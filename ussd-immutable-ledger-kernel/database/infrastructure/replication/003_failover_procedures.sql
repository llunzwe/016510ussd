-- =============================================================================
-- FAILOVER PROCEDURES
-- High availability failover and switchover procedures
-- =============================================================================

-- =============================================================================
-- FAILOVER SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS failover;

COMMENT ON SCHEMA failover IS 'High availability failover and switchover management';

-- =============================================================================
-- NODE REGISTRY
-- =============================================================================
CREATE TABLE IF NOT EXISTS failover.node_registry (
    id SERIAL PRIMARY KEY,
    node_name VARCHAR(100) NOT NULL UNIQUE,
    node_type VARCHAR(20) NOT NULL DEFAULT 'REPLICA', -- PRIMARY, REPLICA, STANDBY, WITNESS
    host VARCHAR(255) NOT NULL,
    port INTEGER DEFAULT 5432,
    datacenter VARCHAR(50),
    priority INTEGER DEFAULT 100, -- Lower = higher priority for promotion
    
    -- Connection info
    conn_string TEXT,
    replication_slot VARCHAR(128),
    
    -- Status
    current_state VARCHAR(20) DEFAULT 'UNKNOWN', -- UNKNOWN, HEALTHY, DEGRADED, UNHEALTHY, OFFLINE
    last_seen_at TIMESTAMPTZ,
    last_check_at TIMESTAMPTZ,
    
    -- Replication info
    is_streaming BOOLEAN DEFAULT FALSE,
    replication_lag_bytes BIGINT,
    replication_lag_seconds INTEGER,
    
    -- Metadata
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE failover.node_registry IS 'Registry of all database nodes in the cluster';

-- =============================================================================
-- FAILOVER LOG
-- =============================================================================
CREATE TABLE IF NOT EXISTS failover.event_log (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL DEFAULT gen_random_uuid(),
    event_type VARCHAR(50) NOT NULL, -- SWITCHOVER, FAILOVER, DEMOTION, PROMOTION, HEALTH_CHECK
    
    -- Nodes involved
    primary_node VARCHAR(100),
    target_node VARCHAR(100),
    
    -- Event details
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status VARCHAR(20) DEFAULT 'RUNNING', -- RUNNING, SUCCESS, FAILED, ROLLED_BACK
    
    -- Trigger reason
    trigger_reason VARCHAR(100), -- MANUAL, AUTOMATIC, HEALTH_CHECK, SCHEDULED
    trigger_details JSONB,
    
    -- Steps executed
    steps_completed INTEGER DEFAULT 0,
    steps_total INTEGER,
    current_step TEXT,
    
    -- Results
    old_primary_lsn pg_lsn,
    new_primary_lsn pg_lsn,
    failover_time_ms INTEGER,
    data_loss_bytes BIGINT,
    
    -- Error info
    error_message TEXT,
    rollback_details JSONB,
    
    -- Audit
    initiated_by VARCHAR(100) DEFAULT current_user
);

CREATE INDEX IF NOT EXISTS idx_failover_event_type 
ON failover.event_log(event_type, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_failover_event_status 
ON failover.event_log(status);

-- =============================================================================
-- FAILOVER CONFIGURATION
-- =============================================================================
CREATE TABLE IF NOT EXISTS failover.configuration (
    id SERIAL PRIMARY KEY,
    config_name VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT NOT NULL,
    config_type VARCHAR(20) DEFAULT 'STRING', -- STRING, INTEGER, BOOLEAN, JSON
    description TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by VARCHAR(100) DEFAULT current_user
);

-- Default configuration
INSERT INTO failover.configuration (config_name, config_value, config_type, description) VALUES
    ('auto_failover_enabled', 'false', 'BOOLEAN', 'Enable automatic failover'),
    ('failover_timeout_seconds', '30', 'INTEGER', 'Maximum time to wait for failover'),
    ('primary_unhealthy_threshold', '3', 'INTEGER', 'Consecutive failed checks before primary considered unhealthy'),
    ('replica_min_lag_bytes', '104857600', 'INTEGER', 'Minimum replication lag in bytes for promotion (100MB)'),
    ('replica_max_lag_seconds', '300', 'INTEGER', 'Maximum replication lag in seconds for promotion'),
    ('health_check_interval_seconds', '10', 'INTEGER', 'Interval between health checks'),
    ('failover_cooldown_minutes', '60', 'INTEGER', 'Cooldown period between failovers'),
    ('require_sync_replica', 'false', 'BOOLEAN', 'Require at least one synchronous replica'),
    ('preferred_primary_dc', 'us-east-1', 'STRING', 'Preferred datacenter for primary'),
    ('maintenance_mode', 'false', 'BOOLEAN', 'Disable auto-failover during maintenance')
ON CONFLICT (config_name) DO UPDATE SET
    config_value = EXCLUDED.config_value,
    config_type = EXCLUDED.config_type;

-- =============================================================================
-- FUNCTION: Register node
-- =============================================================================
CREATE OR REPLACE FUNCTION failover.register_node(
    p_node_name VARCHAR,
    p_node_type VARCHAR,
    p_host VARCHAR,
    p_port INTEGER DEFAULT 5432,
    p_datacenter VARCHAR DEFAULT NULL,
    p_priority INTEGER DEFAULT 100
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_conn_string TEXT;
BEGIN
    v_conn_string := format('host=%s port=%s dbname=postgres', p_host, p_port);
    
    INSERT INTO failover.node_registry (
        node_name, node_type, host, port, datacenter, priority, conn_string
    ) VALUES (
        p_node_name, p_node_type, p_host, p_port, p_datacenter, p_priority, v_conn_string
    )
    ON CONFLICT (node_name) DO UPDATE SET
        node_type = EXCLUDED.node_type,
        host = EXCLUDED.host,
        port = EXCLUDED.port,
        datacenter = EXCLUDED.datacenter,
        priority = EXCLUDED.priority,
        conn_string = EXCLUDED.conn_string,
        updated_at = NOW();
    
    RETURN format('SUCCESS: Registered node %s (%s)', p_node_name, p_node_type);
EXCEPTION WHEN OTHERS THEN
    RETURN format('ERROR: %s', SQLERRM);
END;
$$;

-- =============================================================================
-- FUNCTION: Get primary node
-- =============================================================================
CREATE OR REPLACE FUNCTION failover.get_primary_node()
RETURNS TABLE(node_name VARCHAR, host VARCHAR, port INTEGER, conn_string TEXT)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        nr.node_name::VARCHAR(100),
        nr.host::VARCHAR(255),
        nr.port,
        nr.conn_string::TEXT
    FROM failover.node_registry nr
    WHERE nr.node_type = 'PRIMARY'
      AND nr.is_active = TRUE
      AND nr.current_state = 'HEALTHY'
    ORDER BY nr.priority, nr.node_name
    LIMIT 1;
END;
$$;

-- =============================================================================
-- FUNCTION: Get best replica for promotion
-- =============================================================================
CREATE OR REPLACE FUNCTION failover.get_best_replica()
RETURNS TABLE(node_name VARCHAR, host VARCHAR, replication_lag_bytes BIGINT, priority INTEGER)
LANGUAGE plpgsql
AS $$
DECLARE
    v_max_lag BIGINT;
    v_max_lag_seconds INTEGER;
BEGIN
    -- Get config values
    SELECT config_value::BIGINT INTO v_max_lag
    FROM failover.configuration WHERE config_name = 'replica_min_lag_bytes';
    
    SELECT config_value::INTEGER INTO v_max_lag_seconds
    FROM failover.configuration WHERE config_name = 'replica_max_lag_seconds';
    
    RETURN QUERY
    SELECT 
        nr.node_name::VARCHAR(100),
        nr.host::VARCHAR(255),
        nr.replication_lag_bytes,
        nr.priority
    FROM failover.node_registry nr
    WHERE nr.node_type IN ('REPLICA', 'STANDBY')
      AND nr.is_active = TRUE
      AND nr.current_state = 'HEALTHY'
      AND (nr.replication_lag_bytes IS NULL OR nr.replication_lag_bytes < v_max_lag)
      AND (nr.replication_lag_seconds IS NULL OR nr.replication_lag_seconds < v_max_lag_seconds)
    ORDER BY nr.priority, nr.replication_lag_bytes NULLS LAST, nr.node_name
    LIMIT 1;
END;
$$;

-- =============================================================================
-- FUNCTION: Log failover event
-- =============================================================================
CREATE OR REPLACE FUNCTION failover.log_event(
    p_event_type VARCHAR,
    p_primary_node VARCHAR DEFAULT NULL,
    p_target_node VARCHAR DEFAULT NULL,
    p_trigger_reason VARCHAR DEFAULT 'MANUAL',
    p_trigger_details JSONB DEFAULT '{}'
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_event_id UUID := gen_random_uuid();
BEGIN
    INSERT INTO failover.event_log (
        event_id, event_type, primary_node, target_node, 
        trigger_reason, trigger_details
    ) VALUES (
        v_event_id, p_event_type, p_primary_node, p_target_node,
        p_trigger_reason, p_trigger_details
    );
    
    RETURN v_event_id;
END;
$$;

-- =============================================================================
-- FUNCTION: Update event status
-- =============================================================================
CREATE OR REPLACE FUNCTION failover.update_event_status(
    p_event_id UUID,
    p_status VARCHAR,
    p_step TEXT DEFAULT NULL,
    p_error_message TEXT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE failover.event_log
    SET status = p_status,
        current_step = COALESCE(p_step, current_step),
        error_message = COALESCE(p_error_message, error_message),
        completed_at = CASE WHEN p_status IN ('SUCCESS', 'FAILED', 'ROLLED_BACK') 
                       THEN NOW() ELSE completed_at END
    WHERE event_id = p_event_id;
END;
$$;

-- =============================================================================
-- FUNCTION: Perform switchover (graceful)
-- =============================================================================
CREATE OR REPLACE FUNCTION failover.perform_switchover(
    p_target_node VARCHAR,
    p_force BOOLEAN DEFAULT FALSE
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_current_primary RECORD;
    v_target RECORD;
    v_event_id UUID;
    v_start_time TIMESTAMPTZ;
BEGIN
    v_start_time := clock_timestamp();
    
    -- Get current primary
    SELECT * INTO v_current_primary FROM failover.get_primary_node();
    
    IF NOT FOUND THEN
        RETURN 'ERROR: No primary node found';
    END IF;
    
    -- Get target replica
    SELECT * INTO v_target 
    FROM failover.node_registry 
    WHERE node_name = p_target_node;
    
    IF NOT FOUND THEN
        RETURN format('ERROR: Target node %s not found', p_target_node);
    END IF;
    
    IF v_target.node_type NOT IN ('REPLICA', 'STANDBY') THEN
        RETURN format('ERROR: Target node %s is not a replica', p_target_node);
    END IF;
    
    -- Log event
    v_event_id := failover.log_event(
        'SWITCHOVER',
        v_current_primary.node_name,
        p_target_node,
        'MANUAL',
        jsonb_build_object('force', p_force)
    );
    
    -- Note: Actual switchover steps would be performed by external tooling
    -- (patroni, repmgr, or custom scripts) that calls this for tracking
    
    UPDATE failover.event_log
    SET status = 'RUNNING',
        steps_total = 5,
        current_step = 'Waiting for external switchover...'
    WHERE event_id = v_event_id;
    
    RETURN format('SWITCHOVER_INITIATED: Event %s logged. Current primary: %s, Target: %s',
                  v_event_id, v_current_primary.node_name, p_target_node);
END;
$$;

-- =============================================================================
-- FUNCTION: Perform failover (ungraceful)
-- =============================================================================
CREATE OR REPLACE FUNCTION failover.perform_failover(
    p_failed_node VARCHAR DEFAULT NULL,
    p_target_node VARCHAR DEFAULT NULL
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_failed_node VARCHAR;
    v_target VARCHAR;
    v_event_id UUID;
    v_config RECORD;
BEGIN
    -- Check if auto-failover is enabled
    SELECT * INTO v_config 
    FROM failover.configuration 
    WHERE config_name = 'auto_failover_enabled';
    
    IF v_config.config_value::BOOLEAN = FALSE THEN
        RETURN 'ERROR: Auto-failover is disabled';
    END IF;
    
    -- Check maintenance mode
    SELECT * INTO v_config 
    FROM failover.configuration 
    WHERE config_name = 'maintenance_mode';
    
    IF v_config.config_value::BOOLEAN = TRUE THEN
        RETURN 'ERROR: Maintenance mode is active, failover disabled';
    END IF;
    
    -- Determine failed node
    IF p_failed_node IS NULL THEN
        SELECT node_name INTO v_failed_node
        FROM failover.node_registry
        WHERE node_type = 'PRIMARY' AND current_state != 'HEALTHY'
        ORDER BY last_check_at DESC
        LIMIT 1;
    ELSE
        v_failed_node := p_failed_node;
    END IF;
    
    IF v_failed_node IS NULL THEN
        RETURN 'ERROR: No failed primary detected';
    END IF;
    
    -- Determine target for promotion
    IF p_target_node IS NULL THEN
        SELECT node_name INTO v_target FROM failover.get_best_replica();
    ELSE
        v_target := p_target_node;
    END IF;
    
    IF v_target IS NULL THEN
        RETURN 'ERROR: No suitable replica found for promotion';
    END IF;
    
    -- Log event
    v_event_id := failover.log_event(
        'FAILOVER',
        v_failed_node,
        v_target,
        'AUTOMATIC',
        jsonb_build_object(
            'failed_node_state', (SELECT current_state FROM failover.node_registry WHERE node_name = v_failed_node)
        )
    );
    
    -- Note: Actual failover is performed by external tooling
    UPDATE failover.event_log
    SET status = 'RUNNING',
        steps_total = 8,
        current_step = 'Waiting for external failover...'
    WHERE event_id = v_event_id;
    
    RETURN format('FAILOVER_INITIATED: Event %s. Failed: %s, Promoting: %s',
                  v_event_id, v_failed_node, v_target);
END;
$$;

-- =============================================================================
-- FUNCTION: Update node health status
-- =============================================================================
CREATE OR REPLACE FUNCTION failover.update_node_health(
    p_node_name VARCHAR,
    p_state VARCHAR,
    p_replication_lag_bytes BIGINT DEFAULT NULL,
    p_replication_lag_seconds INTEGER DEFAULT NULL
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE failover.node_registry
    SET current_state = p_state,
        last_seen_at = NOW(),
        last_check_at = NOW(),
        replication_lag_bytes = COALESCE(p_replication_lag_bytes, replication_lag_bytes),
        replication_lag_seconds = COALESCE(p_replication_lag_seconds, replication_lag_seconds),
        is_streaming = (p_state = 'HEALTHY' AND node_type IN ('REPLICA', 'STANDBY'))
    WHERE node_name = p_node_name;
    
    IF FOUND THEN
        RETURN format('SUCCESS: Updated %s to %s', p_node_name, p_state);
    ELSE
        RETURN format('ERROR: Node %s not found', p_node_name);
    END IF;
END;
$$;

-- =============================================================================
-- FUNCTION: Promote replica to primary
-- =============================================================================
CREATE OR REPLACE FUNCTION failover.promote_replica(
    p_node_name VARCHAR
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_old_primary VARCHAR;
BEGIN
    -- Get current primary
    SELECT node_name INTO v_old_primary
    FROM failover.node_registry
    WHERE node_type = 'PRIMARY' AND is_active = TRUE;
    
    -- Demote old primary
    IF v_old_primary IS NOT NULL THEN
        UPDATE failover.node_registry
        SET node_type = 'STANDBY',
            current_state = 'DEGRADED',
            updated_at = NOW()
        WHERE node_name = v_old_primary;
    END IF;
    
    -- Promote new primary
    UPDATE failover.node_registry
    SET node_type = 'PRIMARY',
        current_state = 'HEALTHY',
        is_streaming = FALSE,
        replication_lag_bytes = NULL,
        replication_lag_seconds = NULL,
        updated_at = NOW()
    WHERE node_name = p_node_name;
    
    -- Log promotion
    PERFORM failover.log_event(
        'PROMOTION',
        v_old_primary,
        p_node_name,
        'MANUAL'
    );
    
    RETURN format('SUCCESS: Promoted %s to PRIMARY (demoted %s)',
                  p_node_name, COALESCE(v_old_primary, 'none'));
END;
$$;

-- =============================================================================
-- VIEW: Cluster health status
-- =============================================================================
CREATE OR REPLACE VIEW failover.cluster_health AS
SELECT 
    nr.node_name,
    nr.node_type,
    nr.host,
    nr.datacenter,
    nr.current_state,
    nr.is_streaming,
    nr.replication_lag_bytes,
    nr.replication_lag_seconds,
    CASE 
        WHEN nr.node_type = 'PRIMARY' THEN 0
        WHEN nr.current_state = 'HEALTHY' AND nr.replication_lag_seconds < 10 THEN 1
        WHEN nr.current_state = 'HEALTHY' AND nr.replication_lag_seconds < 60 THEN 2
        WHEN nr.current_state = 'DEGRADED' THEN 3
        ELSE 4
    END as health_rank,
    nr.last_seen_at,
    EXTRACT(EPOCH FROM (NOW() - nr.last_check_at))::INTEGER as seconds_since_check
FROM failover.node_registry nr
WHERE nr.is_active = TRUE
ORDER BY 
    CASE nr.node_type WHEN 'PRIMARY' THEN 0 ELSE 1 END,
    nr.priority,
    nr.node_name;

-- =============================================================================
-- VIEW: Recent failover events
-- =============================================================================
CREATE OR REPLACE VIEW failover.recent_events AS
SELECT 
    event_id,
    event_type,
    primary_node,
    target_node,
    status,
    trigger_reason,
    started_at,
    completed_at,
    EXTRACT(EPOCH FROM (COALESCE(completed_at, NOW()) - started_at))::INTEGER as duration_seconds,
    failover_time_ms,
    data_loss_bytes,
    initiated_by
FROM failover.event_log
WHERE started_at > NOW() - INTERVAL '7 days'
ORDER BY started_at DESC;

-- =============================================================================
-- FUNCTION: Get configuration value
-- =============================================================================
CREATE OR REPLACE FUNCTION failover.get_config(p_config_name VARCHAR)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_value TEXT;
BEGIN
    SELECT config_value INTO v_value
    FROM failover.configuration
    WHERE config_name = p_config_name;
    
    RETURN v_value;
END;
$$;

-- =============================================================================
-- FUNCTION: Set configuration value
-- =============================================================================
CREATE OR REPLACE FUNCTION failover.set_config(
    p_config_name VARCHAR,
    p_config_value TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE failover.configuration
    SET config_value = p_config_value,
        updated_at = NOW(),
        updated_by = current_user
    WHERE config_name = p_config_name;
    
    IF FOUND THEN
        RETURN format('SUCCESS: Set %s = %s', p_config_name, p_config_value);
    ELSE
        RETURN format('ERROR: Config %s not found', p_config_name);
    END IF;
END;
$$;

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA failover TO failover_admin;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA failover TO failover_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA failover TO failover_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA failover TO failover_admin;
