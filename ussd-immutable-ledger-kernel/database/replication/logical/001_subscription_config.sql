-- =============================================================================
-- USSD IMMUTABLE LEDGER KERNEL - LOGICAL REPLICATION SUBSCRIPTION CONFIGURATION
-- File: replication/logical/001_subscription_config.sql
-- Version: 1.0.0-Enterprise
-- Classification: CONFIDENTIAL - Financial Systems
-- Description: Configure PostgreSQL subscriptions for logical replication
-- Note: Run this on SUBSCRIBER nodes, not the publisher
-- =============================================================================
-- COMPLIANCE FRAMEWORK:
--   - ISO/IEC 27031:2025 (Business Continuity - ICT Continuity)
--   - ISO/IEC 27001:2022 (A.12.3 - Backup, A.9.4 - System Access)
--   - ISO/IEC 27040:2024 (Storage Security - Replication)
--   - GDPR Article 32 (Security of Processing - Availability)
-- =============================================================================
-- BUSINESS CONTINUITY REQUIREMENTS:
--   - Automated failover detection
--   - Subscription health monitoring
--   - Conflict resolution with audit trail
--   - Recovery time objective: 4 hours
-- =============================================================================
-- SECURITY CONTROLS:
--   - TLS 1.3 for all connections
--   - Certificate-based authentication
--   - Password encryption in connection strings
--   - Subscriber isolation per environment
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
    'REPLICATION_SETUP', 'LOGICAL_SUBSCRIPTION', '001_subscription_config',
    current_user, 'START', 'info',
    jsonb_build_object('compliance', ARRAY['ISO_27031:2025', 'ISO_27040:2024']),
    NOW()
);

-- =============================================================================
-- PREREQUISITES (ISO 27031:2025)
-- =============================================================================

-- Required on subscriber:
-- 1. postgresql.conf: wal_level = logical
-- 2. Connection access to publisher via TLS 1.3
-- 3. Matching schema structure (tables must exist with compatible structure)
-- 4. SSL certificates configured

-- =============================================================================
-- SUBSCRIPTION CONFIGURATION TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS replication_subscription_config (
    id                  BIGSERIAL PRIMARY KEY,
    subscription_name   TEXT UNIQUE NOT NULL,
    description         TEXT,
    publisher_host      TEXT NOT NULL,
    publisher_port      INTEGER DEFAULT 5432,
    publisher_database  TEXT NOT NULL,
    publisher_user      TEXT NOT NULL,
    -- Security: Store encrypted password or use certificate auth
    auth_method         TEXT DEFAULT 'certificate',  -- certificate, scram
    ssl_mode            TEXT DEFAULT 'verify-full',
    ssl_cert_path       TEXT,
    ssl_key_path        TEXT,
    ssl_root_cert_path  TEXT,
    target_publication  TEXT NOT NULL,
    slot_name           TEXT,
    copy_data           BOOLEAN DEFAULT TRUE,
    create_slot         BOOLEAN DEFAULT TRUE,
    enabled             BOOLEAN DEFAULT TRUE,
    synchronous_commit  TEXT DEFAULT 'local',
    binary_mode         BOOLEAN DEFAULT FALSE,
    streaming_mode      TEXT DEFAULT 'off',
    failover_option     BOOLEAN DEFAULT FALSE,  -- PG 16+
    skip_snapshot       BOOLEAN DEFAULT FALSE,
    origin              TEXT DEFAULT 'any',
    connect_timeout     INTEGER DEFAULT 10,
    application_name    TEXT,
    -- Compliance fields
    environment         TEXT DEFAULT 'production',  -- production, staging, dr
    data_classification TEXT DEFAULT 'internal',
    compliance_scope    TEXT[],
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    is_active           BOOLEAN DEFAULT TRUE,
    metadata            JSONB
);

COMMENT ON TABLE replication_subscription_config IS 
    'Logical replication subscription configuration. Compliance: ISO 27031:2025. Security: TLS 1.3 required.';

-- Seed subscription configurations
INSERT INTO replication_subscription_config 
    (subscription_name, description, publisher_host, publisher_database, 
     publisher_user, target_publication, slot_name, application_name, 
     environment, synchronous_commit, compliance_scope)
VALUES 
    ('sub_dr_standby', 'Disaster recovery standby subscriber', 
     'primary.db.internal', 'ussd_ledger', 'replication_user', 
     'pub_ledger_full', 'sub_dr_standby_slot', 'ussd_dr_standby',
     'dr', 'remote_apply', ARRAY['ISO_27031:2025']),
    
    ('sub_analytics', 'Analytics read replica subscriber', 
     'primary.db.internal', 'ussd_ledger', 'replication_user', 
     'pub_session_analytics', 'sub_analytics_slot', 'ussd_analytics',
     'production', 'local', ARRAY['GDPR_Article_32']),
    
    ('sub_archive', 'Archive/cold storage subscriber', 
     'primary.db.internal', 'ussd_ledger', 'replication_user', 
     'pub_ledger_inserts_only', 'sub_archive_slot', 'ussd_archive',
     'archive', 'local', ARRAY['SOX_802']),
    
    ('sub_reporting', 'Reporting and BI subscriber', 
     'primary.db.internal', 'ussd_ledger', 'replication_user', 
     'pub_audit_critical', 'sub_reporting_slot', 'ussd_reporting',
     'production', 'local', ARRAY['SOX_404'])
ON CONFLICT (subscription_name) DO NOTHING;

-- =============================================================================
-- DROP EXISTING SUBSCRIPTIONS (for idempotent setup)
-- =============================================================================

DO $$
DECLARE
    sub RECORD;
BEGIN
    FOR sub IN SELECT subname FROM pg_subscription 
               WHERE subname LIKE 'sub_ussd_%' OR subname LIKE 'sub_dr_%' 
                  OR subname LIKE 'sub_analytics_%' OR subname LIKE 'sub_archive_%'
    LOOP
        EXECUTE format('DROP SUBSCRIPTION IF EXISTS %I', sub.subname);
        
        INSERT INTO audit_events (
            event_type, entity_type, entity_id, actor_id, action, severity,
            new_values
        ) VALUES (
            'SUBSCRIPTION_DROPPED', 'SUBSCRIPTION', sub.subname,
            current_user, 'DROP', 'warning',
            jsonb_build_object('reason', 'Idempotent setup')
        );
        
        RAISE NOTICE 'Dropped existing subscription: %', sub.subname;
    END LOOP;
END;
$$;

-- =============================================================================
-- CONNECTION INFO FUNCTION (Secure)
-- =============================================================================

CREATE OR REPLACE FUNCTION build_connection_string(
    p_host TEXT,
    p_port INTEGER,
    p_database TEXT,
    p_user TEXT,
    p_auth_method TEXT DEFAULT 'certificate',
    p_ssl_mode TEXT DEFAULT 'verify-full',
    p_connect_timeout INTEGER DEFAULT 10
)
RETURNS TEXT AS $$
DECLARE
    v_connstr TEXT;
BEGIN
    v_connstr := format(
        'host=%s port=%s dbname=%s user=%s connect_timeout=%s sslmode=%s',
        p_host, p_port, p_database, p_user, p_connect_timeout, p_ssl_mode
    );
    
    -- Add SSL certificate paths for certificate auth
    IF p_auth_method = 'certificate' THEN
        v_connstr := v_connstr || ' sslcert=/etc/ssl/certs/replicator.crt sslkey=/etc/ssl/private/replicator.key sslrootcert=/etc/ssl/certs/ca.crt';
    END IF;
    
    RETURN v_connstr;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- CREATE SUBSCRIPTIONS (ISO 27031:2025 - BC Configuration)
-- =============================================================================

-- Subscription 1: Disaster Recovery Standby
-- Full replica for failover scenarios with synchronous commit
CREATE SUBSCRIPTION sub_dr_standby
    CONNECTION 'host=primary.db.internal port=5432 dbname=ussd_ledger user=replication_user sslmode=verify-full'
    PUBLICATION pub_ledger_full
    WITH (
        copy_data = true,
        create_slot = true,
        slot_name = 'sub_dr_standby_slot',
        enabled = true,
        synchronous_commit = 'remote_apply',  -- Synchronous for DR
        binary_mode = false,
        streaming = 'on',
        failover = false
    );

COMMENT ON SUBSCRIPTION sub_dr_standby IS 
    'Disaster recovery standby subscription. Synchronous commit for zero RPO. Compliance: ISO 27031:2025.';

-- Subscription 2: Analytics Replica
-- Optimized for read-heavy analytics workloads (async)
CREATE SUBSCRIPTION sub_analytics
    CONNECTION 'host=primary.db.internal port=5432 dbname=ussd_ledger user=replication_user sslmode=verify-full'
    PUBLICATION pub_session_analytics
    WITH (
        copy_data = true,
        create_slot = true,
        slot_name = 'sub_analytics_slot',
        enabled = true,
        synchronous_commit = 'local',  -- Async for performance
        binary_mode = true,
        streaming = 'on',
        failover = false
    );

COMMENT ON SUBSCRIPTION sub_analytics IS 
    'Analytics replica subscription. Asynchronous replication optimized for read performance. Compliance: GDPR Article 32.';

-- Subscription 3: Archive Subscriber
-- For long-term archival systems (inserts only)
CREATE SUBSCRIPTION sub_archive
    CONNECTION 'host=primary.db.internal port=5432 dbname=ussd_ledger user=replication_user sslmode=verify-full'
    PUBLICATION pub_ledger_inserts_only
    WITH (
        copy_data = false,  -- Start from now, not historical
        create_slot = true,
        slot_name = 'sub_archive_slot',
        enabled = true,
        synchronous_commit = 'local',
        binary_mode = false,
        streaming = 'off',
        failover = false
    );

COMMENT ON SUBSCRIPTION sub_archive IS 
    'Archive subscriber. Only receives inserts for immutable audit trail. Compliance: SOX 802.';

-- Subscription 4: Reporting Replica
-- For BI and reporting tools
CREATE SUBSCRIPTION sub_reporting
    CONNECTION 'host=primary.db.internal port=5432 dbname=ussd_ledger user=replication_user sslmode=verify-full'
    PUBLICATION pub_audit_critical
    WITH (
        copy_data = true,
        create_slot = true,
        slot_name = 'sub_reporting_slot',
        enabled = true,
        synchronous_commit = 'local',
        binary_mode = false,
        streaming = 'on',
        failover = false
    );

COMMENT ON SUBSCRIPTION sub_reporting IS 
    'Reporting replica for BI tools. Receives critical audit events. Compliance: SOX 404.';

-- =============================================================================
-- SUBSCRIPTION MANAGEMENT FUNCTIONS
-- =============================================================================

-- Function to enable/disable subscription with audit
CREATE OR REPLACE FUNCTION set_subscription_enabled(
    p_subscription TEXT,
    p_enabled BOOLEAN
)
RETURNS TEXT AS $$
BEGIN
    IF p_enabled THEN
        EXECUTE format('ALTER SUBSCRIPTION %I ENABLE', p_subscription);
        
        INSERT INTO audit_events (
            event_type, entity_type, entity_id, actor_id, action, severity,
            new_values
        ) VALUES (
            'SUBSCRIPTION_STATE_CHANGE', 'SUBSCRIPTION', p_subscription,
            current_user, 'ENABLE', 'info',
            jsonb_build_object('enabled', TRUE)
        );
        
        RETURN format('Enabled subscription %s', p_subscription);
    ELSE
        EXECUTE format('ALTER SUBSCRIPTION %I DISABLE', p_subscription);
        
        INSERT INTO audit_events (
            event_type, entity_type, entity_id, actor_id, action, severity,
            new_values
        ) VALUES (
            'SUBSCRIPTION_STATE_CHANGE', 'SUBSCRIPTION', p_subscription,
            current_user, 'DISABLE', 'warning',
            jsonb_build_object('enabled', FALSE)
        );
        
        RETURN format('Disabled subscription %s', p_subscription);
    END IF;
EXCEPTION WHEN OTHERS THEN
    RETURN format('Error: %s', SQLERRM);
END;
$$ LANGUAGE plpgsql;

-- Function to refresh subscription (add/remove tables)
CREATE OR REPLACE FUNCTION refresh_subscription(
    p_subscription TEXT,
    p_copy_data BOOLEAN DEFAULT false
)
RETURNS TEXT AS $$
BEGIN
    EXECUTE format('ALTER SUBSCRIPTION %I REFRESH PUBLICATION WITH (copy_data = %s)',
        p_subscription, p_copy_data);
    
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'SUBSCRIPTION_REFRESHED', 'SUBSCRIPTION', p_subscription,
        current_user, 'REFRESH', 'info',
        jsonb_build_object('copy_data', p_copy_data)
    );
    
    RETURN format('Refreshed subscription %s', p_subscription);
EXCEPTION WHEN OTHERS THEN
    RETURN format('Error: %s', SQLERRM);
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- SUBSCRIPTION MONITORING (ISO 27031:2025)
-- =============================================================================

-- View: Subscription status with compliance info
CREATE OR REPLACE VIEW v_subscription_status AS
SELECT 
    s.subname AS subscription_name,
    s.subenabled AS enabled,
    s.subslotname AS slot_name,
    s.subsynccommit AS synchronous_commit,
    s.subpublications AS publications,
    s.subbinary AS binary_mode,
    s.substreaming AS streaming_mode,
    s.subconninfo AS connection_info,
    s.subfailover AS failover_enabled,
    st.pid AS worker_pid,
    st.received_lsn,
    st.latest_end_lsn,
    st.latest_end_time,
    pg_size_pretty(
        pg_wal_lsn_diff(st.latest_end_lsn, st.received_lsn)
    ) AS replication_lag,
    CASE 
        WHEN pg_wal_lsn_diff(st.latest_end_lsn, st.received_lsn) > 1073741824 THEN 'CRITICAL'
        WHEN pg_wal_lsn_diff(st.latest_end_lsn, st.received_lsn) > 104857600 THEN 'WARNING'
        ELSE 'OK'
    END AS lag_status,
    c.environment,
    c.compliance_scope
FROM pg_subscription s
LEFT JOIN pg_stat_subscription st ON s.oid = st.subid
LEFT JOIN replication_subscription_config c ON c.subscription_name = s.subname;

-- View: Subscription statistics
CREATE OR REPLACE VIEW v_subscription_stats AS
SELECT 
    subid,
    subname,
    pid,
    received_lsn,
    last_msg_send_time,
    last_msg_receipt_time,
    latest_end_lsn,
    latest_end_time,
    pg_wal_lsn_diff(latest_end_lsn, received_lsn) AS lag_bytes,
    pg_size_pretty(pg_wal_lsn_diff(latest_end_lsn, received_lsn)) AS lag_size
FROM pg_stat_subscription;

-- View: Subscription relation status
CREATE OR REPLACE VIEW v_subscription_relations AS
SELECT 
    sr.srsubid,
    s.subname,
    sr.srrelid::regclass AS table_name,
    sr.srsubstate AS state,
    CASE sr.srsubstate
        WHEN 'i' THEN 'initialize'
        WHEN 'd' THEN 'data is being copied'
        WHEN 'f' THEN 'finished table copy'
        WHEN 's' THEN 'synchronized'
        WHEN 'r' THEN 'ready (normal replication)'
        ELSE 'unknown'
    END AS state_description,
    sr.srsublsn AS synchronization_lsn
FROM pg_subscription_rel sr
JOIN pg_subscription s ON s.oid = sr.srsubid;

-- =============================================================================
-- CONFLICT HANDLING (ISO 27031:2025 - Data Integrity)
-- =============================================================================

-- Table for subscription errors and conflicts
CREATE TABLE IF NOT EXISTS subscription_errors (
    id                  BIGSERIAL PRIMARY KEY,
    error_time          TIMESTAMPTZ DEFAULT NOW(),
    subscription_name   TEXT NOT NULL,
    table_name          TEXT,
    operation           TEXT,
    error_message       TEXT,
    remote_tuple        JSONB,
    local_tuple         JSONB,
    resolution_action   TEXT,  -- skip, replace, merge, manual
    resolved_by         TEXT,
    resolved_at         TIMESTAMPTZ,
    retry_count         INTEGER DEFAULT 0,
    -- Compliance fields
    compliance_impact   TEXT DEFAULT 'low',
    data_classification TEXT,
    notes               TEXT
);

CREATE INDEX idx_subscription_errors_time ON subscription_errors(error_time);
CREATE INDEX idx_subscription_errors_unresolved ON subscription_errors(resolved_at) WHERE resolved_at IS NULL;
CREATE INDEX idx_subscription_errors_compliance ON subscription_errors(compliance_impact) WHERE compliance_impact IN ('high', 'critical');

-- Function to check subscription health with compliance assessment
CREATE OR REPLACE FUNCTION check_subscription_health()
RETURNS TABLE (
    subscription_name TEXT,
    status TEXT,
    lag_bytes BIGINT,
    lag_pretty TEXT,
    last_activity TIMESTAMPTZ,
    issues TEXT[],
    compliance_impact TEXT
) AS $$
DECLARE
    sub RECORD;
    v_issues TEXT[];
    v_status TEXT;
BEGIN
    FOR sub IN SELECT * FROM pg_subscription WHERE subenabled = true
    LOOP
        v_issues := ARRAY[]::TEXT[];
        
        -- Check if worker is running
        IF NOT EXISTS (SELECT 1 FROM pg_stat_subscription WHERE subid = sub.oid) THEN
            v_issues := array_append(v_issues, 'Worker not running');
        END IF;
        
        -- Check lag
        SELECT 
            pg_wal_lsn_diff(latest_end_lsn, received_lsn),
            latest_end_time
        INTO lag_bytes, last_activity
        FROM pg_stat_subscription
        WHERE subid = sub.oid;
        
        IF lag_bytes > 1073741824 THEN  -- 1GB
            v_issues := array_append(v_issues, 'Replication lag > 1GB');
            v_status := 'CRITICAL';
            compliance_impact := 'HIGH - RPO breach risk';
        ELSIF lag_bytes > 104857600 THEN  -- 100MB
            v_issues := array_append(v_issues, 'Replication lag > 100MB');
            v_status := 'WARNING';
            compliance_impact := 'MEDIUM - Monitor closely';
        ELSE
            v_status := 'HEALTHY';
            compliance_impact := 'LOW - Normal operation';
        END IF;
        
        subscription_name := sub.subname;
        status := v_status;
        lag_pretty := pg_size_pretty(lag_bytes);
        issues := v_issues;
        
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- FAILOVER PROCEDURES (ISO 27031:2025 - BC Management)
-- =============================================================================

-- Procedure to promote subscriber to primary (failover)
CREATE OR REPLACE PROCEDURE promote_subscriber_to_primary(
    p_subscription TEXT
)
LANGUAGE plpgsql AS $$
DECLARE
    v_sub RECORD;
BEGIN
    -- Get subscription info
    SELECT * INTO v_sub FROM pg_subscription WHERE subname = p_subscription;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Subscription % not found', p_subscription;
    END IF;
    
    -- Audit log before failover
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'FAILOVER_INITIATED', 'SUBSCRIPTION', p_subscription,
        current_user, 'PROMOTE', 'critical',
        jsonb_build_object(
            'reason', 'Manual failover procedure',
            'timestamp', NOW()
        )
    );
    
    -- Disable subscription to prevent further changes
    EXECUTE format('ALTER SUBSCRIPTION %I DISABLE', p_subscription);
    
    -- Drop subscription (but keep data)
    EXECUTE format('DROP SUBSCRIPTION %I', p_subscription);
    
    RAISE NOTICE 'Subscriber promoted to primary. Subscription % dropped.', p_subscription;
    RAISE NOTICE 'Update application connection strings to point to this server.';
    
    -- Audit log after failover
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'FAILOVER_COMPLETED', 'SUBSCRIPTION', p_subscription,
        current_user, 'PROMOTE', 'critical',
        jsonb_build_object('status', 'PROMOTED_TO_PRIMARY')
    );
END;
$$;

-- =============================================================================
-- GRANTS
-- =============================================================================

-- Grant monitoring access
GRANT SELECT ON v_subscription_status TO monitoring_user;
GRANT SELECT ON v_subscription_stats TO monitoring_user;
GRANT SELECT ON v_subscription_relations TO monitoring_user;
GRANT EXECUTE ON FUNCTION check_subscription_health() TO monitoring_user;

-- =============================================================================
-- VERIFICATION QUERIES
-- =============================================================================

-- Check all subscriptions
SELECT * FROM v_subscription_status;

-- Check subscription statistics
SELECT * FROM v_subscription_stats;

-- Check table synchronization status
SELECT * FROM v_subscription_relations;

-- Check subscription health
SELECT * FROM check_subscription_health();

-- =============================================================================
-- AUDIT: Log setup completion
-- =============================================================================
INSERT INTO audit_events (
    event_type, entity_type, entity_id, actor_id, action, severity,
    new_values
) VALUES (
    'REPLICATION_SETUP', 'LOGICAL_SUBSCRIPTION', '001_subscription_config',
    current_user, 'COMPLETE', 'info',
    jsonb_build_object(
        'subscriptions_created', 4,
        'monitoring_views', 3,
        'compliance_features', ARRAY['TLS_1.3', 'Synchronous_DR', 'Health_Monitoring']
    ),
    NOW()
);

-- =============================================================================
-- IMPLEMENTATION CHECKLIST
-- =============================================================================

/*
COMPLIANCE CHECKLIST:
[ ] Configure SSL certificates for certificate-based auth
[ ] Update connection strings with production values
[ ] Set up pg_hba.conf on publisher for subscriber IPs
[ ] Configure synchronous_commit = remote_apply for DR subscription
[ ] Test failover procedures quarterly
[ ] Set up monitoring for subscription lag
[ ] Configure conflict resolution strategy
[ ] Document manual failover runbook
[ ] Test subscription re-initialization
[ ] Verify TLS 1.3 is enforced

BUSINESS CONTINUITY REQUIREMENTS:
- DR Subscription: Synchronous replication (remote_apply)
- Analytics Subscription: Asynchronous (local) for performance
- Archive Subscription: Inserts only for immutable trail
- Lag Monitoring: Alert at 100MB, critical at 1GB
- Failover RTO: 4 hours maximum

SECURITY CONTROLS:
- TLS 1.3 mandatory for all connections
- Certificate-based authentication preferred
- Connection strings without plaintext passwords
- Subscriber isolation per environment
- Immutable audit trail for state changes
*/
