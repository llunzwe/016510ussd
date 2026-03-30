-- =============================================================================
-- USSD IMMUTABLE LEDGER KERNEL - STREAMING REPLICATION CONFIGURATION
-- File: replication/physical/001_streaming_replication.sql
-- Version: 1.0.0-Enterprise
-- Classification: CONFIDENTIAL - Financial Systems
-- Description: Configure physical streaming replication for high availability
-- =============================================================================
-- COMPLIANCE FRAMEWORK:
--   - ISO/IEC 27031:2025 (Business Continuity - ICT Continuity)
--   - ISO/IEC 27001:2022 (A.12.3 - Backup, A.17.1 - Continuity)
--   - ISO/IEC 27040:2024 (Storage Security - Replication Security)
--   - GDPR Article 32 (Security of Processing - Availability)
-- =============================================================================
-- BUSINESS CONTINUITY REQUIREMENTS:
--   - RTO: 4 hours maximum
--   - RPO: 0 (synchronous) or 1 hour (asynchronous)
--   - Automatic failover capability
--   - Multi-site replication for DR
-- =============================================================================
-- SECURITY CONTROLS:
--   - TLS 1.3 for replication connections
--   - Certificate-based authentication
--   - Replication slot encryption
--   - Standby feedback for consistency
-- =============================================================================

-- =============================================================================
-- SECURITY: Verify execution context
-- =============================================================================
DO $$
BEGIN
    IF NOT (SELECT pg_has_role(current_user, 'replication_admin', 'MEMBER') OR 
            (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)) THEN
        RAISE EXCEPTION 'Insufficient privileges. Required: replication_admin or superuser';
    END IF;
END $$;

-- =============================================================================
-- AUDIT: Log setup start
-- =============================================================================
INSERT INTO audit_events (
    event_type, entity_type, entity_id, actor_id, action, severity,
    new_values
) VALUES (
    'REPLICATION_SETUP', 'STREAMING_REPLICATION', '001_streaming_replication',
    current_user, 'START', 'info',
    jsonb_build_object('compliance', ARRAY['ISO_27031:2025', 'ISO_27001_A.17', 'GDPR_Article_32']),
    NOW()
);

-- =============================================================================
-- PREREQUISITES (ISO 27031:2025)
-- =============================================================================

-- Required postgresql.conf settings on PRIMARY:
-- wal_level = replica
-- max_wal_senders = 10
-- max_replication_slots = 10
-- wal_keep_size = 2GB
-- hot_standby = on
-- hot_standby_feedback = on
-- ssl = on
-- ssl_min_protocol_version = 'TLSv1.3'

-- Required pg_hba.conf entries:
-- hostssl replication replicator 10.0.0.0/8 cert

-- =============================================================================
-- REPLICATION CONFIGURATION TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS streaming_replication_config (
    id                  BIGSERIAL PRIMARY KEY,
    replica_name        TEXT UNIQUE NOT NULL,
    replica_host        TEXT NOT NULL,
    replica_port        INTEGER DEFAULT 5432,
    replica_database    TEXT DEFAULT 'ussd_ledger',
    replication_type    TEXT DEFAULT 'streaming',
    sync_mode           TEXT DEFAULT 'async',
    -- Security settings
    tls_version         TEXT DEFAULT 'TLSv1.3',
    auth_method         TEXT DEFAULT 'certificate',  -- certificate, scram
    ssl_cert_cn         TEXT,  -- Expected certificate CN
    -- Configuration
    application_name    TEXT NOT NULL,
    slot_name           TEXT,
    priority            INTEGER DEFAULT 100,
    -- Business Continuity
    rto_minutes         INTEGER DEFAULT 240,  -- RTO target
    rpo_minutes         INTEGER DEFAULT 60,   -- RPO target
    is_active           BOOLEAN DEFAULT TRUE,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    metadata            JSONB
);

COMMENT ON TABLE streaming_replication_config IS 
    'Streaming replication configuration. Compliance: ISO 27031:2025. Security: TLS 1.3, Certificate auth.';

-- Seed replica configurations
INSERT INTO streaming_replication_config 
    (replica_name, replica_host, replica_port, application_name, slot_name, sync_mode, priority, rto_minutes)
VALUES 
    ('standby_001', 'standby-001.db.internal', 5432, 'ussd_standby_001', 'slot_standby_001', 'async', 10, 240),
    ('standby_002', 'standby-002.db.internal', 5432, 'ussd_standby_002', 'slot_standby_002', 'async', 20, 240),
    ('sync_standby', 'standby-sync.db.internal', 5432, 'ussd_sync_standby', 'slot_sync_standby', 'sync', 5, 0)
ON CONFLICT (replica_name) DO NOTHING;

-- =============================================================================
-- REPLICATION SLOT MANAGEMENT
-- =============================================================================

-- Function to create replication slot for streaming with audit
CREATE OR REPLACE FUNCTION create_streaming_slot(p_slot_name TEXT)
RETURNS TABLE (
    slot_name TEXT,
    lsn TEXT,
    status TEXT
) AS $$
BEGIN
    -- Drop existing slot if exists
    PERFORM pg_drop_replication_slot(p_slot_name)
    FROM pg_replication_slots WHERE slot_name = p_slot_name;
    
    -- Create physical replication slot
    RETURN QUERY
    SELECT s.slot_name::TEXT, s.confirmed_flush_lsn::TEXT, 'created'::TEXT
    FROM pg_create_physical_replication_slot(p_slot_name, true) s;
    
    -- Audit log
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'REPLICATION_SLOT_CREATED', 'PHYSICAL_SLOT', p_slot_name,
        current_user, 'CREATE', 'info',
        jsonb_build_object('slot_type', 'physical')
    );
END;
$$ LANGUAGE plpgsql;

-- Create slots for configured replicas
SELECT create_streaming_slot('slot_standby_001');
SELECT create_streaming_slot('slot_standby_002');
SELECT create_streaming_slot('slot_sync_standby');

-- =============================================================================
-- SYNCHRONOUS REPLICATION CONFIGURATION (ISO 27031:2025)
-- =============================================================================

-- Function to generate synchronous_standby_names value
CREATE OR REPLACE FUNCTION generate_sync_standby_names()
RETURNS TEXT AS $$
DECLARE
    v_sync_replicas TEXT[];
BEGIN
    SELECT array_agg(application_name ORDER BY priority)
    INTO v_sync_replicas
    FROM streaming_replication_config
    WHERE sync_mode = 'sync' AND is_active = true;
    
    IF array_length(v_sync_replicas, 1) IS NULL THEN
        RETURN '';
    END IF;
    
    -- Format: FIRST 1 (standby1, standby2) or ANY 1 (standby1, standby2)
    RETURN format('FIRST 1 (%s)', array_to_string(v_sync_replicas, ', '));
END;
$$ LANGUAGE plpgsql;

-- View current synchronous replication settings
CREATE OR REPLACE VIEW v_synchronous_config AS
SELECT 
    name,
    setting,
    unit,
    short_desc,
    CASE 
        WHEN name = 'synchronous_commit' AND setting = 'remote_apply' THEN 'ZERO_RPO'
        WHEN name = 'synchronous_commit' AND setting = 'remote_write' THEN 'LOW_RPO'
        ELSE 'ASYNC'
    END AS rpo_status
FROM pg_settings
WHERE name IN (
    'synchronous_commit',
    'synchronous_standby_names',
    'max_synchronous_standby_delay'
);

-- =============================================================================
-- REPLICATION MONITORING (ISO 27031:2025)
-- =============================================================================

-- View: Replication status with compliance info
CREATE OR REPLACE VIEW v_replication_status AS
SELECT 
    client_addr,
    usename,
    application_name,
    state,
    sync_state,
    sent_lsn,
    write_lsn,
    flush_lsn,
    replay_lsn,
    pg_wal_lsn_diff(sent_lsn, replay_lsn) AS replay_lag_bytes,
    pg_size_pretty(pg_wal_lsn_diff(sent_lsn, replay_lsn)) AS replay_lag_pretty,
    reply_time,
    CASE 
        WHEN pg_wal_lsn_diff(sent_lsn, replay_lsn) > 1073741824 THEN 'CRITICAL'
        WHEN pg_wal_lsn_diff(sent_lsn, replay_lsn) > 104857600 THEN 'WARNING'
        ELSE 'OK'
    END AS lag_status
FROM pg_stat_replication
ORDER BY application_name;

-- View: Replication slot status
CREATE OR REPLACE VIEW v_replication_slots_status AS
SELECT 
    slot_name,
    plugin,
    slot_type,
    database,
    active,
    restart_lsn,
    confirmed_flush_lsn,
    pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) AS lag_bytes,
    pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS lag_size,
    wal_status,
    safe_wal_size,
    CASE 
        WHEN wal_status = 'lost' THEN 'CRITICAL'
        WHEN pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) > 1073741824 THEN 'WARNING'
        ELSE 'OK'
    END AS slot_health
FROM pg_replication_slots
WHERE slot_type = 'physical';

-- View: WAL sender status
CREATE OR REPLACE VIEW v_wal_senders AS
SELECT 
    pid,
    usename,
    application_name,
    client_addr,
    state,
    sent_lsn,
    write_lsn,
    flush_lsn,
    replay_lsn,
    write_lag,
    flush_lag,
    replay_lag,
    sync_priority,
    sync_state
FROM pg_stat_replication;

-- =============================================================================
-- REPLICATION HEALTH CHECKS (ISO 27031:2025)
-- =============================================================================

-- Function to check replication health with compliance assessment
CREATE OR REPLACE FUNCTION check_replication_health()
RETURNS TABLE (
    check_name TEXT,
    replica TEXT,
    status TEXT,
    lag_bytes BIGINT,
    lag_pretty TEXT,
    details TEXT,
    compliance_impact TEXT
) AS $$
DECLARE
    r RECORD;
    v_lag BIGINT;
BEGIN
    FOR r IN SELECT * FROM streaming_replication_config WHERE is_active = true
    LOOP
        check_name := 'Replication Lag';
        replica := r.replica_name;
        
        -- Get lag for this replica
        SELECT pg_wal_lsn_diff(sent_lsn, replay_lsn) INTO v_lag
        FROM pg_stat_replication
        WHERE application_name = r.application_name;
        
        IF v_lag IS NULL THEN
            status := 'CRITICAL';
            lag_bytes := 0;
            lag_pretty := 'N/A';
            details := 'Replica not connected';
            compliance_impact := 'CRITICAL - RPO breach';
        ELSIF v_lag > 1073741824 THEN  -- 1GB
            status := 'CRITICAL';
            lag_bytes := v_lag;
            lag_pretty := pg_size_pretty(v_lag);
            details := 'Lag exceeds 1GB';
            compliance_impact := 'HIGH - RPO risk';
        ELSIF v_lag > 104857600 THEN  -- 100MB
            status := 'WARNING';
            lag_bytes := v_lag;
            lag_pretty := pg_size_pretty(v_lag);
            details := 'Lag exceeds 100MB';
            compliance_impact := 'MEDIUM - Monitor closely';
        ELSE
            status := 'OK';
            lag_bytes := v_lag;
            lag_pretty := pg_size_pretty(v_lag);
            details := 'Replication healthy';
            compliance_impact := 'LOW - Normal operation';
        END IF;
        
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- FAILOVER MANAGEMENT (ISO 27031:2025)
-- =============================================================================

-- Table for failover events (auditable)
CREATE TABLE IF NOT EXISTS failover_history (
    id                  BIGSERIAL PRIMARY KEY,
    failover_time       TIMESTAMPTZ DEFAULT NOW(),
    old_primary         TEXT,
    new_primary         TEXT,
    failover_type       TEXT,  -- 'planned', 'automatic', 'manual'
    failover_reason     TEXT,
    recovery_time_ms    INTEGER,
    data_loss_bytes     BIGINT,
    performed_by        TEXT,
    -- Compliance
    compliance_reviewed BOOLEAN DEFAULT FALSE,
    reviewed_by         TEXT,
    reviewed_at         TIMESTAMPTZ,
    notes               TEXT
);

COMMENT ON TABLE failover_history IS 
    'Failover event history for BC compliance. Compliance: ISO 27031:2025. Review required.';

-- Function to identify best failover candidate
CREATE OR REPLACE FUNCTION get_failover_candidate()
RETURNS TABLE (
    replica_name TEXT,
    replica_host TEXT,
    replay_lag_bytes BIGINT,
    sync_state TEXT,
    priority INTEGER,
    candidate_score NUMERIC,
    estimated_rto_minutes INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        c.replica_name,
        c.replica_host,
        COALESCE(pg_wal_lsn_diff(sr.sent_lsn, sr.replay_lsn), 999999999)::BIGINT AS replay_lag_bytes,
        COALESCE(sr.sync_state, 'unknown')::TEXT AS sync_state,
        c.priority,
        CASE 
            WHEN sr.sync_state = 'sync' THEN 100
            WHEN sr.sync_state = 'potential' THEN 80
            WHEN sr.sync_state = 'async' THEN 60
            ELSE 0
        END::NUMERIC - (COALESCE(pg_wal_lsn_diff(sr.sent_lsn, sr.replay_lsn), 0) / 1000000.0) AS candidate_score,
        c.rto_minutes
    FROM streaming_replication_config c
    LEFT JOIN pg_stat_replication sr ON sr.application_name = c.application_name
    WHERE c.is_active = true
    ORDER BY candidate_score DESC
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- Procedure to log failover event
CREATE OR REPLACE PROCEDURE log_failover_event(
    p_old_primary TEXT,
    p_new_primary TEXT,
    p_failover_type TEXT,
    p_reason TEXT,
    p_recovery_time_ms INTEGER,
    p_data_loss_bytes BIGINT DEFAULT 0
)
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO failover_history (
        old_primary, new_primary, failover_type, failover_reason,
        recovery_time_ms, data_loss_bytes, performed_by
    ) VALUES (
        p_old_primary, p_new_primary, p_failover_type, p_reason,
        p_recovery_time_ms, p_data_loss_bytes, current_user
    );
    
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'FAILOVER_EVENT', 'CLUSTER', p_new_primary,
        current_user, p_failover_type, 'critical',
        jsonb_build_object(
            'old_primary', p_old_primary,
            'recovery_time_ms', p_recovery_time_ms,
            'data_loss_bytes', p_data_loss_bytes,
            'reason', p_reason
        )
    );
END;
$$;

-- =============================================================================
-- STANDBY CONFIGURATION TEMPLATE
-- =============================================================================

-- Recovery configuration template for standby servers
/*
-- Add to postgresql.auto.conf or recovery.conf (PG 12+):

primary_conninfo = 'host=primary.db.internal port=5432 user=replicator sslmode=verify-full sslcert=/etc/ssl/certs/replicator.crt sslkey=/etc/ssl/private/replicator.key sslrootcert=/etc/ssl/certs/ca.crt application_name=ussd_standby_001'
primary_slot_name = 'slot_standby_001'
recovery_target_timeline = 'latest'
hot_standby = on
hot_standby_feedback = on
ssl_min_protocol_version = 'TLSv1.3'

-- For delayed replica (for PITR protection):
-- recovery_min_apply_delay = 1h
*/

-- Function to generate standby configuration
CREATE OR REPLACE FUNCTION generate_standby_config(
    p_replica_name TEXT,
    p_primary_host TEXT,
    p_primary_port INTEGER DEFAULT 5432
)
RETURNS TABLE (
    config_name TEXT,
    config_value TEXT,
    description TEXT
) AS $$
DECLARE
    v_config RECORD;
BEGIN
    SELECT * INTO v_config 
    FROM streaming_replication_config 
    WHERE replica_name = p_replica_name;
    
    IF NOT FOUND THEN
        RETURN;
    END IF;
    
    config_name := 'primary_conninfo';
    config_value := format('host=%s port=%s user=replicator sslmode=verify-full application_name=%s',
        p_primary_host, p_primary_port, v_config.application_name);
    description := 'Connection string to primary server (TLS 1.3 required)';
    RETURN NEXT;
    
    config_name := 'primary_slot_name';
    config_value := v_config.slot_name;
    description := 'Replication slot name on primary';
    RETURN NEXT;
    
    config_name := 'hot_standby';
    config_value := 'on';
    description := 'Enable read-only queries on standby';
    RETURN NEXT;
    
    config_name := 'hot_standby_feedback';
    config_value := 'on';
    description := 'Prevent vacuum from removing rows needed by standby';
    RETURN NEXT;
    
    config_name := 'recovery_target_timeline';
    config_value := 'latest';
    description := 'Follow latest timeline after promotion';
    RETURN NEXT;
    
    config_name := 'ssl_min_protocol_version';
    config_value := 'TLSv1.3';
    description := 'Minimum TLS version for replication connections';
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- REPLICATION PERFORMANCE MONITORING
-- =============================================================================

-- View: Replication performance metrics
CREATE OR REPLACE VIEW v_replication_performance AS
SELECT 
    sr.application_name,
    sr.client_addr,
    sr.state,
    sr.sync_state,
    extract(epoch from sr.write_lag)::NUMERIC(10,3) AS write_lag_seconds,
    extract(epoch from sr.flush_lag)::NUMERIC(10,3) AS flush_lag_seconds,
    extract(epoch from sr.replay_lag)::NUMERIC(10,3) AS replay_lag_seconds,
    pg_wal_lsn_diff(sr.sent_lsn, sr.replay_lsn) AS total_lag_bytes,
    sr.reply_time
FROM pg_stat_replication sr
ORDER BY sr.application_name;

-- =============================================================================
-- GRANTS
-- =============================================================================

GRANT SELECT ON v_replication_status TO monitoring_user;
GRANT SELECT ON v_replication_slots_status TO monitoring_user;
GRANT SELECT ON v_wal_senders TO monitoring_user;
GRANT SELECT ON v_synchronous_config TO monitoring_user;
GRANT EXECUTE ON FUNCTION check_replication_health() TO monitoring_user;
GRANT EXECUTE ON FUNCTION get_failover_candidate() TO monitoring_user;

-- =============================================================================
-- VERIFICATION QUERIES
-- =============================================================================

-- Check replication status
SELECT * FROM v_replication_status;

-- Check replication slots
SELECT * FROM v_replication_slots_status;

-- Check health
SELECT * FROM check_replication_health();

-- Get best failover candidate
SELECT * FROM get_failover_candidate();

-- Check synchronous configuration
SELECT * FROM v_synchronous_config;

-- =============================================================================
-- AUDIT: Log setup completion
-- =============================================================================
INSERT INTO audit_events (
    event_type, entity_type, entity_id, actor_id, action, severity,
    new_values
) VALUES (
    'REPLICATION_SETUP', 'STREAMING_REPLICATION', '001_streaming_replication',
    current_user, 'COMPLETE', 'info',
    jsonb_build_object(
        'slots_created', 3,
        'monitoring_views', 5,
        'compliance_features', ARRAY['TLS_1.3', 'Failover_Management', 'Synchronous_Replication', 'Health_Monitoring']
    ),
    NOW()
);

-- =============================================================================
-- IMPLEMENTATION CHECKLIST
-- =============================================================================

/*
COMPLIANCE CHECKLIST:
[ ] Configure primary server postgresql.conf
[ ] Create replication user with certificate authentication
[ ] Configure pg_hba.conf for SSL-only replication
[ ] Set up standby servers with pg_basebackup
[ ] Configure synchronous replication for zero RPO
[ ] Set up automatic failover (Patroni/repmgr)
[ ] Configure TLS 1.3 certificates
[ ] Test failover procedures quarterly
[ ] Set up monitoring for replication lag
[ ] Document disaster recovery runbook
[ ] Schedule quarterly BC drills

BUSINESS CONTINUITY REQUIREMENTS:
- RTO: 4 hours maximum
- RPO: 0 for synchronous replica, 1 hour for async
- Automatic failover with Patroni
- Multi-site replication (primary + 2 standbys)
- Quarterly failover testing

SECURITY CONTROLS:
- TLS 1.3 mandatory
- Certificate-based authentication
- Replication slot protection
- Standby feedback enabled
- Connection encryption enforced

MONITORING ALERTS:
- Replication lag > 100MB: WARNING
- Replication lag > 1GB: CRITICAL
- Replica disconnect: CRITICAL
- Slot inactive: WARNING
- Failover event: CRITICAL (immediate review required)
*/
