-- =============================================================================
-- SUBSCRIPTION CONFIGURATION
-- Logical replication subscription setup
-- =============================================================================

-- =============================================================================
-- SUBSCRIPTION CONFIGURATION TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS replication.subscription_config (
    id SERIAL PRIMARY KEY,
    subscription_name VARCHAR(128) NOT NULL UNIQUE,
    publication_name VARCHAR(128) NOT NULL,
    
    -- Connection info
    host VARCHAR(255) NOT NULL,
    port INTEGER DEFAULT 5432,
    database VARCHAR(63) NOT NULL,
    username VARCHAR(63) NOT NULL,
    -- Password stored securely via vault integration
    password_reference VARCHAR(255),
    
    -- SSL settings
    ssl_mode VARCHAR(20) DEFAULT 'require', -- disable, allow, prefer, require, verify-ca, verify-full
    ssl_root_cert_path VARCHAR(500),
    ssl_cert_path VARCHAR(500),
    ssl_key_path VARCHAR(500),
    
    -- Subscription options
    slot_name VARCHAR(128),
    copy_data BOOLEAN DEFAULT TRUE,
    create_slot BOOLEAN DEFAULT TRUE,
    enabled BOOLEAN DEFAULT TRUE,
    streaming_mode VARCHAR(20) DEFAULT 'off', -- off, on, parallel
    
    -- Sync settings
    synchronize_structure BOOLEAN DEFAULT FALSE,
    synchronize_data BOOLEAN DEFAULT TRUE,
    
    -- Failover settings
    failover_to_host VARCHAR(255),
    failover_to_port INTEGER DEFAULT 5432,
    
    -- Metadata
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    description TEXT
);

COMMENT ON TABLE replication.subscription_config IS 'Configuration for logical replication subscriptions';

-- =============================================================================
-- SUBSCRIPTION STATUS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS replication.subscription_status (
    id SERIAL PRIMARY KEY,
    subscription_name VARCHAR(128) NOT NULL REFERENCES replication.subscription_config(subscription_name),
    pid INTEGER,
    received_lsn pg_lsn,
    last_msg_send_time TIMESTAMPTZ,
    last_msg_receipt_time TIMESTAMPTZ,
    latest_end_lsn pg_lsn,
    latest_end_time TIMESTAMPTZ,
    total_transactions BIGINT DEFAULT 0,
    total_rows_received BIGINT DEFAULT 0,
    replication_lag_seconds INTEGER,
    current_state VARCHAR(20) DEFAULT 'INITIALIZING', -- INITIALIZING, STREAMING, ERROR, DISABLED
    error_message TEXT,
    checked_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sub_status_name 
ON replication.subscription_status(subscription_name);

CREATE INDEX IF NOT EXISTS idx_sub_status_lag 
ON replication.subscription_status(replication_lag_seconds) 
WHERE replication_lag_seconds > 300;

-- =============================================================================
-- DEFAULT SUBSCRIPTION CONFIGS (templates)
-- =============================================================================
INSERT INTO replication.subscription_config (
    subscription_name, publication_name, host, database, username,
    slot_name, ssl_mode, streaming_mode, description
) VALUES 
(
    'ledger_replica_sub',
    'ledger_transactions_pub',
    'primary.db.internal',
    'ledger_production',
    'replication_user',
    'ledger_replica_slot',
    'verify-full',
    'on',
    'Subscription for ledger replica from primary'
),
(
    'audit_replica_sub',
    'audit_logs_pub',
    'primary.db.internal',
    'ledger_production',
    'replication_user',
    'audit_replica_slot',
    'verify-full',
    'on',
    'Subscription for audit logs replica'
),
(
    'dr_site_sub',
    'ledger_transactions_pub',
    'primary.db.internal',
    'ledger_production',
    'replication_user',
    'dr_site_slot',
    'verify-full',
    'parallel',
    'Disaster recovery site subscription'
)
ON CONFLICT (subscription_name) DO UPDATE SET
    publication_name = EXCLUDED.publication_name,
    host = EXCLUDED.host,
    description = EXCLUDED.description;

-- =============================================================================
-- FUNCTION: Build connection string
-- =============================================================================
CREATE OR REPLACE FUNCTION replication.build_connection_string(
    p_subscription_name VARCHAR,
    p_include_password BOOLEAN DEFAULT FALSE
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
    v_conn_string TEXT;
BEGIN
    SELECT * INTO v_config 
    FROM replication.subscription_config 
    WHERE subscription_name = p_subscription_name;
    
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    
    v_conn_string := format('host=%s port=%s dbname=%s user=%s sslmode=%s',
        v_config.host, v_config.port, v_config.database, 
        v_config.username, v_config.ssl_mode);
    
    -- Add SSL certificates if specified
    IF v_config.ssl_root_cert_path IS NOT NULL THEN
        v_conn_string := v_conn_string || format(' sslrootcert=%s', v_config.ssl_root_cert_path);
    END IF;
    
    IF v_config.ssl_cert_path IS NOT NULL THEN
        v_conn_string := v_conn_string || format(' sslcert=%s', v_config.ssl_cert_path);
    END IF;
    
    IF v_config.ssl_key_path IS NOT NULL THEN
        v_conn_string := v_conn_string || format(' sslkey=%s', v_config.ssl_key_path);
    END IF;
    
    -- Note: Password should be retrieved from vault in production
    IF p_include_password AND v_config.password_reference IS NOT NULL THEN
        v_conn_string := v_conn_string || format(' password=%s', '[REDACTED]');
    END IF;
    
    RETURN v_conn_string;
END;
$$;

-- =============================================================================
-- FUNCTION: Create subscription
-- =============================================================================
CREATE OR REPLACE FUNCTION replication.create_subscription(
    p_subscription_name VARCHAR,
    p_use_password_from_vault BOOLEAN DEFAULT TRUE
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
    v_conn_string TEXT;
    v_sql TEXT;
BEGIN
    SELECT * INTO v_config 
    FROM replication.subscription_config 
    WHERE subscription_name = p_subscription_name;
    
    IF NOT FOUND THEN
        RETURN format('ERROR: Subscription config not found: %s', p_subscription_name);
    END IF;
    
    -- Get connection string (password handling in production would use vault)
    v_conn_string := replication.build_connection_string(p_subscription_name, FALSE);
    
    -- Drop existing subscription if exists
    BEGIN
        EXECUTE format('DROP SUBSCRIPTION IF EXISTS %I', p_subscription_name);
    EXCEPTION WHEN OTHERS THEN
        NULL;
    END;
    
    -- Build create subscription SQL
    v_sql := format(
        'CREATE SUBSCRIPTION %I CONNECTION %L PUBLICATION %I',
        p_subscription_name,
        v_conn_string,
        v_config.publication_name
    );
    
    -- Add options
    v_sql := v_sql || format(
        ' WITH (copy_data = %s, create_slot = %s, enabled = %s, slot_name = %L, streaming = %L)',
        v_config.copy_data,
        v_config.create_slot,
        v_config.enabled,
        COALESCE(v_config.slot_name, p_subscription_name || '_slot'),
        v_config.streaming_mode
    );
    
    -- Note: In production, this would need password handling
    -- v_sql := v_sql || format(', password = %L', vault.get_secret(v_config.password_reference));
    
    EXECUTE v_sql;
    
    -- Initialize status
    INSERT INTO replication.subscription_status (
        subscription_name, current_state
    ) VALUES (
        p_subscription_name, 
        CASE WHEN v_config.enabled THEN 'INITIALIZING' ELSE 'DISABLED' END
    )
    ON CONFLICT (subscription_name) DO UPDATE SET current_state = EXCLUDED.current_state;
    
    RETURN format('SUCCESS: Created subscription %s for publication %s',
                  p_subscription_name, v_config.publication_name);
                  
EXCEPTION WHEN OTHERS THEN
    -- Log error
    INSERT INTO replication.subscription_status (
        subscription_name, current_state, error_message
    ) VALUES (
        p_subscription_name, 'ERROR', SQLERRM
    )
    ON CONFLICT (subscription_name) DO UPDATE SET 
        current_state = 'ERROR',
        error_message = SQLERRM,
        checked_at = NOW();
    
    RETURN format('ERROR: %s', SQLERRM);
END;
$$;

-- =============================================================================
-- FUNCTION: Update subscription status from system views
-- =============================================================================
CREATE OR REPLACE FUNCTION replication.refresh_subscription_status()
RETURNS TABLE(subscription_name TEXT, state TEXT, lag_seconds INTEGER)
LANGUAGE plpgsql
AS $$
DECLARE
    v_sub RECORD;
    v_stat RECORD;
BEGIN
    FOR v_sub IN 
        SELECT s.subname, s.subenabled
        FROM pg_subscription s
    LOOP
        subscription_name := v_sub.subname;
        
        -- Get stats from pg_stat_subscription
        SELECT * INTO v_stat
        FROM pg_stat_subscription
        WHERE subname = v_sub.subname
        ORDER BY pid DESC
        LIMIT 1;
        
        IF FOUND THEN
            state := COALESCE(v_stat.shared_slot_name, 'STREAMING');
            lag_seconds := EXTRACT(EPOCH FROM (NOW() - v_stat.latest_end_time))::INTEGER;
            
            -- Update status table
            UPDATE replication.subscription_status
            SET pid = v_stat.pid,
                received_lsn = v_stat.received_lsn,
                last_msg_send_time = v_stat.last_msg_send_time,
                last_msg_receipt_time = v_stat.last_msg_receipt_time,
                latest_end_lsn = v_stat.latest_end_lsn,
                latest_end_time = v_stat.latest_end_time,
                replication_lag_seconds = lag_seconds,
                current_state = CASE 
                    WHEN lag_seconds > 300 THEN 'LAGGING'
                    ELSE 'STREAMING'
                END,
                checked_at = NOW()
            WHERE subscription_name = v_sub.subname;
        ELSE
            state := CASE WHEN v_sub.subenabled THEN 'INITIALIZING' ELSE 'DISABLED' END;
            lag_seconds := NULL;
        END IF;
        
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Enable subscription
-- =============================================================================
CREATE OR REPLACE FUNCTION replication.enable_subscription(p_subscription_name VARCHAR)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format('ALTER SUBSCRIPTION %I ENABLE', p_subscription_name);
    
    UPDATE replication.subscription_status
    SET current_state = 'STREAMING',
        checked_at = NOW()
    WHERE subscription_name = p_subscription_name;
    
    RETURN format('Subscription %s enabled', p_subscription_name);
EXCEPTION WHEN OTHERS THEN
    RETURN format('ERROR: %s', SQLERRM);
END;
$$;

-- =============================================================================
-- FUNCTION: Disable subscription
-- =============================================================================
CREATE OR REPLACE FUNCTION replication.disable_subscription(p_subscription_name VARCHAR)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format('ALTER SUBSCRIPTION %I DISABLE', p_subscription_name);
    
    UPDATE replication.subscription_status
    SET current_state = 'DISABLED',
        checked_at = NOW()
    WHERE subscription_name = p_subscription_name;
    
    RETURN format('Subscription %s disabled', p_subscription_name);
EXCEPTION WHEN OTHERS THEN
    RETURN format('ERROR: %s', SQLERRM);
END;
$$;

-- =============================================================================
-- FUNCTION: Switch to failover host
-- =============================================================================
CREATE OR REPLACE FUNCTION replication.failover_subscription(
    p_subscription_name VARCHAR
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
    v_old_host VARCHAR;
BEGIN
    SELECT * INTO v_config 
    FROM replication.subscription_config 
    WHERE subscription_name = p_subscription_name;
    
    IF NOT FOUND OR v_config.failover_to_host IS NULL THEN
        RETURN 'ERROR: No failover configuration found';
    END IF;
    
    -- Store old host
    v_old_host := v_config.host;
    
    -- Update config to use failover host
    UPDATE replication.subscription_config
    SET host = failover_to_host,
        port = failover_to_port,
        failover_to_host = host, -- Swap for failback capability
        failover_to_port = port,
        updated_at = NOW()
    WHERE subscription_name = p_subscription_name;
    
    -- Recreate subscription with new host
    PERFORM replication.create_subscription(p_subscription_name);
    
    RETURN format('SUCCESS: Failed over %s from %s to %s',
                  p_subscription_name, v_old_host, v_config.failover_to_host);
EXCEPTION WHEN OTHERS THEN
    RETURN format('ERROR: %s', SQLERRM);
END;
$$;

-- =============================================================================
-- FUNCTION: Initialize all configured subscriptions
-- =============================================================================
CREATE OR REPLACE FUNCTION replication.init_all_subscriptions()
RETURNS TABLE(subscription_name TEXT, result TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
BEGIN
    FOR v_config IN 
        SELECT * FROM replication.subscription_config WHERE is_active = TRUE
    LOOP
        subscription_name := v_config.subscription_name;
        result := replication.create_subscription(v_config.subscription_name);
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- VIEW: Subscription health overview
-- =============================================================================
CREATE OR REPLACE VIEW replication.subscription_health AS
SELECT 
    sc.subscription_name,
    sc.publication_name,
    sc.host,
    sc.port,
    sc.database,
    sc.enabled as config_enabled,
    ss.current_state,
    ss.replication_lag_seconds,
    CASE 
        WHEN ss.replication_lag_seconds IS NULL THEN 'UNKNOWN'
        WHEN ss.replication_lag_seconds < 5 THEN 'HEALTHY'
        WHEN ss.replication_lag_seconds < 60 THEN 'WARNING'
        WHEN ss.replication_lag_seconds < 300 THEN 'CRITICAL'
        ELSE 'EMERGENCY'
    END as health_status,
    ss.received_lsn,
    ss.latest_end_lsn,
    ss.latest_end_time,
    ss.total_transactions,
    ss.total_rows_received,
    ss.checked_at,
    sc.failover_to_host,
    sc.streaming_mode
FROM replication.subscription_config sc
LEFT JOIN replication.subscription_status ss ON ss.subscription_name = sc.subscription_name
WHERE sc.is_active = TRUE;

-- =============================================================================
-- VIEW: Native subscription status
-- =============================================================================
CREATE OR REPLACE VIEW replication.native_subscription_status AS
SELECT 
    s.oid as subid,
    s.subname as subscription_name,
    s.subenabled as enabled,
    s.subbinary as binary_mode,
    s.substream as streaming_mode,
    s.subtwophasestate as two_phase_state,
    d.datname as database_name,
    array_agg(p.pubname) as subscribed_publications
FROM pg_subscription s
JOIN pg_database d ON d.oid = s.subdbid
LEFT JOIN pg_subscription_rel sr ON sr.srsubid = s.oid
LEFT JOIN pg_publication p ON p.oid = sr.srrelid
GROUP BY s.oid, s.subname, s.subenabled, s.subbinary, s.substream, s.subtwophasestate, d.datname;

-- =============================================================================
-- TRIGGER: Update timestamp
-- =============================================================================
CREATE TRIGGER trigger_sub_config_updated
    BEFORE UPDATE ON replication.subscription_config
    FOR EACH ROW EXECUTE FUNCTION replication.update_timestamp();

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT SELECT ON replication.subscription_config TO replication_monitor;
GRANT SELECT ON replication.subscription_status TO replication_monitor;
GRANT SELECT ON replication.subscription_health TO replication_monitor;
