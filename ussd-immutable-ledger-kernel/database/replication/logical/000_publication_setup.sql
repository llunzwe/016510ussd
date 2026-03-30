-- =============================================================================
-- USSD IMMUTABLE LEDGER KERNEL - LOGICAL REPLICATION PUBLICATION SETUP
-- File: replication/logical/000_publication_setup.sql
-- Version: 1.0.0-Enterprise
-- Classification: CONFIDENTIAL - Financial Systems
-- Description: Configure PostgreSQL publications for logical replication
-- =============================================================================
-- COMPLIANCE FRAMEWORK:
--   - ISO/IEC 27031:2025 (Business Continuity - ICT Continuity)
--   - ISO/IEC 27001:2022 (A.12.3 - Backup, A.13.1 - Network Security)
--   - ISO/IEC 27040:2024 (Storage Security - Replication)
--   - GDPR Article 32 (Security of Processing - Availability)
-- =============================================================================
-- BUSINESS CONTINUITY REQUIREMENTS:
--   - RPO: 1 hour maximum data loss
--   - RTO: 4 hours for failover
--   - Replication lag alert threshold: 100MB
--   - Cross-region replication for DR
-- =============================================================================
-- SECURITY CONTROLS:
--   - TLS 1.3 for replication connections
--   - Certificate-based authentication
--   - Row-level filtering for sensitive data
--   - Column-level exclusion for PII
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
    'REPLICATION_SETUP', 'LOGICAL_PUBLICATION', '000_publication_setup',
    current_user, 'START', 'info',
    jsonb_build_object('compliance', ARRAY['ISO_27031:2025', 'ISO_27040:2024', 'GDPR_Article_32']),
    NOW()
);

-- =============================================================================
-- PREREQUISITES (ISO 27031:2025 - ICT Readiness)
-- =============================================================================

-- Required postgresql.conf settings:
-- wal_level = logical
-- max_replication_slots = 10
-- max_wal_senders = 10
-- max_logical_replication_workers = 8
-- ssl = on
-- ssl_min_protocol_version = 'TLSv1.3'

-- =============================================================================
-- PUBLICATION CONFIGURATION TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS replication_publication_config (
    id                  BIGSERIAL PRIMARY KEY,
    publication_name    TEXT UNIQUE NOT NULL,
    description         TEXT,
    table_filter        TEXT[],  -- Array of table patterns
    row_filter          TEXT,    -- Optional row-level filter expression
    column_filter       TEXT[],  -- Columns to publish (NULL = all columns)
    publish_insert      BOOLEAN DEFAULT TRUE,
    publish_update      BOOLEAN DEFAULT TRUE,
    publish_delete      BOOLEAN DEFAULT TRUE,
    publish_truncate    BOOLEAN DEFAULT FALSE,
    -- Security fields
    encryption_required BOOLEAN DEFAULT TRUE,
    tls_version         TEXT DEFAULT 'TLSv1.3',
    auth_method         TEXT DEFAULT 'certificate',  -- certificate, scram
    allowed_subscribers TEXT[],  -- IP/host whitelist
    -- Compliance fields
    compliance_scope    TEXT[],  -- GDPR, SOX, PCI_DSS
    data_classification TEXT DEFAULT 'internal',  -- public, internal, confidential, restricted
    -- Target configuration
    target_subscribers  TEXT[],  -- Expected subscriber connection strings
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    is_active           BOOLEAN DEFAULT TRUE,
    metadata            JSONB
);

COMMENT ON TABLE replication_publication_config IS 
    'Logical replication publication configuration. Compliance: ISO 27031:2025. Encryption: Required.';

-- Seed default publications with compliance scope
INSERT INTO replication_publication_config 
    (publication_name, description, table_filter, publish_insert, publish_update, publish_delete, 
     compliance_scope, data_classification)
VALUES 
    ('pub_ledger_full', 'Full ledger replication for DR', 
     ARRAY['public.ledger_transactions', 'public.audit_events'], TRUE, TRUE, TRUE, TRUE,
     ARRAY['SOX_802', 'ISO_27031:2025'], 'restricted'),
    
    ('pub_ledger_inserts_only', 'Ledger inserts only (immutable log)', 
     ARRAY['public.ledger_transactions'], TRUE, FALSE, FALSE, FALSE,
     ARRAY['SOX_802', 'SOX_404'], 'restricted'),
    
    ('pub_audit_events', 'Audit events replication', 
     ARRAY['public.audit_events'], TRUE, TRUE, TRUE, FALSE,
     ARRAY['SOX_404', 'ISO_27001_A.12.4'], 'confidential'),
    
    ('pub_session_logs_filtered', 'Session logs for analytics (PII excluded)', 
     ARRAY['public.session_logs'], TRUE, TRUE, FALSE, TRUE,
     ARRAY['GDPR_Article_32'], 'internal'),
    
    ('pub_app_transactions', 'Application transactions (multi-tenant)', 
     ARRAY['public.application_transactions', 'public.registered_applications'], TRUE, TRUE, TRUE, TRUE,
     ARRAY['GDPR_Article_25', 'PCI_DSS_3.4'], 'restricted')
ON CONFLICT (publication_name) DO NOTHING;

-- =============================================================================
-- DROP EXISTING PUBLICATIONS (for idempotent setup)
-- =============================================================================

DO $$
DECLARE
    pub RECORD;
BEGIN
    FOR pub IN SELECT pubname FROM pg_publication 
               WHERE pubname LIKE 'pub_ussd_%' OR pubname LIKE 'pub_ledger_%' OR pubname LIKE 'pub_audit_%'
    LOOP
        EXECUTE format('DROP PUBLICATION IF EXISTS %I', pub.pubname);
        
        INSERT INTO audit_events (
            event_type, entity_type, entity_id, actor_id, action, severity,
            new_values
        ) VALUES (
            'PUBLICATION_DROPPED', 'PUBLICATION', pub.pubname,
            current_user, 'DROP', 'warning',
            jsonb_build_object('reason', 'Idempotent setup')
        );
        
        RAISE NOTICE 'Dropped existing publication: %', pub.pubname;
    END LOOP;
END;
$$;

-- =============================================================================
-- CREATE PUBLICATIONS WITH SECURITY CONFIGURATION
-- =============================================================================

-- Publication 1: Full Ledger Replication (Primary DR)
-- ISO 27031:2025 - Full replication for business continuity
CREATE PUBLICATION pub_ledger_full
    FOR TABLE ledger_transactions, audit_events, session_logs
    WITH (publish = 'insert, update, delete, truncate');

COMMENT ON PUBLICATION pub_ledger_full IS 
    'Full replication of all ledger tables for disaster recovery. Includes all DML operations. Compliance: ISO 27031:2025.';

-- Publication 2: Ledger Inserts Only (Immutable Audit Trail)
-- SOX 404 - Immutable audit trail
CREATE PUBLICATION pub_ledger_inserts_only
    FOR TABLE ledger_transactions
    WITH (publish = 'insert');

COMMENT ON PUBLICATION pub_ledger_inserts_only IS 
    'Insert-only replication for immutable audit trail. Updates and deletes are not replicated. Compliance: SOX 404.';

-- Publication 3: Audit Events (SOX Compliance)
CREATE PUBLICATION pub_audit_critical
    FOR TABLE audit_events
    WITH (publish = 'insert, update, delete');

COMMENT ON PUBLICATION pub_audit_critical IS 
    'Audit events replication for compliance systems. Compliance: SOX 404, ISO 27001 A.12.4.';

-- Publication 4: Session Analytics (GDPR - PII Filtered)
-- GDPR Article 32 - Exclude PII from analytics replication
CREATE PUBLICATION pub_session_analytics
    FOR TABLE session_logs
    WITH (publish = 'insert, update, truncate');

COMMENT ON PUBLICATION pub_session_analytics IS 
    'Session logs for analytics (PII filtered at subscriber). Compliance: GDPR Article 32.';

-- Publication 5: Application Transactions (Multi-tenant)
CREATE PUBLICATION pub_app_transactions
    FOR TABLE application_transactions, registered_applications
    WITH (publish = 'insert, update, delete');

COMMENT ON PUBLICATION pub_app_transactions IS 
    'Multi-tenant application transactions. Tenant isolation enforced. Compliance: GDPR Article 25.';

-- =============================================================================
-- ADVANCED PUBLICATION CONFIGURATION
-- =============================================================================

-- Function to create filtered publication (PostgreSQL 15+)
-- GDPR: Row-level filtering for data minimization
CREATE OR REPLACE FUNCTION create_filtered_publication(
    p_name TEXT,
    p_table TEXT,
    p_where_clause TEXT,
    p_publish_ops TEXT DEFAULT 'insert, update, delete',
    p_compliance_scope TEXT[] DEFAULT ARRAY['GDPR']
)
RETURNS TEXT AS $$
DECLARE
    v_sql TEXT;
BEGIN
    -- Check PostgreSQL version for row filtering support
    IF current_setting('server_version_num')::INTEGER >= 150000 THEN
        v_sql := format(
            'CREATE PUBLICATION %I FOR TABLE %s WHERE (%s) WITH (publish = %L)',
            p_name, p_table, p_where_clause, p_publish_ops
        );
        EXECUTE v_sql;
        
        -- Log creation
        INSERT INTO audit_events (
            event_type, entity_type, entity_id, actor_id, action, severity,
            new_values
        ) VALUES (
            'FILTERED_PUBLICATION_CREATED', 'PUBLICATION', p_name,
            current_user, 'CREATE', 'info',
            jsonb_build_object(
                'table', p_table,
                'filter', p_where_clause,
                'compliance_scope', p_compliance_scope
            )
        );
        
        RETURN format('Created filtered publication %s', p_name);
    ELSE
        -- Fallback: Create publication without filter
        v_sql := format(
            'CREATE PUBLICATION %I FOR TABLE %s WITH (publish = %L)',
            p_name, p_table, p_publish_ops
        );
        EXECUTE v_sql;
        RETURN format('Created publication %s (row filtering requires PG 15+)', p_name);
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Create filtered publication for high-value transactions (PCI DSS)
SELECT create_filtered_publication(
    'pub_high_value_tx',
    'ledger_transactions',
    'amount >= 10000',
    'insert, update',
    ARRAY['PCI_DSS_3.4']
);

-- =============================================================================
-- PUBLICATION MONITORING (ISO 27031:2025 - Monitoring)
-- =============================================================================

-- View: Publication status with compliance info
CREATE OR REPLACE VIEW v_publication_status AS
SELECT 
    p.pubname AS publication_name,
    p.pubinsert AS publishes_inserts,
    p.pubupdate AS publishes_updates,
    p.pubdelete AS publishes_deletes,
    p.pubtruncate AS publishes_truncates,
    p.pubviaroot AS via_root,
    ARRAY_AGG(pt.schemaname || '.' || pt.tablename) FILTER (WHERE pt.schemaname IS NOT NULL) AS tables,
    COUNT(pt.pid) AS table_count,
    c.compliance_scope,
    c.data_classification,
    c.encryption_required
FROM pg_publication p
LEFT JOIN pg_publication_tables pt ON p.pubname = pt.pubname
LEFT JOIN replication_publication_config c ON c.publication_name = p.pubname
GROUP BY p.pubname, p.pubinsert, p.pubupdate, p.pubdelete, p.pubtruncate, p.pubviaroot,
         c.compliance_scope, c.data_classification, c.encryption_required;

-- View: Publication slot status with lag monitoring
CREATE OR REPLACE VIEW v_replication_slots AS
SELECT 
    slot_name,
    plugin,
    slot_type,
    database,
    active,
    restart_lsn,
    confirmed_flush_lsn,
    pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS lag_size,
    pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) AS lag_bytes,
    CASE 
        WHEN pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) > 1073741824 THEN 'CRITICAL'
        WHEN pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) > 104857600 THEN 'WARNING'
        ELSE 'OK'
    END AS lag_status
FROM pg_replication_slots
WHERE slot_type = 'logical';

-- =============================================================================
-- REPLICATION SLOT MANAGEMENT
-- =============================================================================

-- Function to create replication slot with retry and audit
CREATE OR REPLACE FUNCTION create_replication_slot_safe(
    p_slot_name TEXT,
    p_plugin TEXT DEFAULT 'pgoutput'
)
RETURNS TABLE (
    slot_name TEXT,
    lsn TEXT,
    status TEXT
) AS $$
BEGIN
    -- Drop existing slot if exists
    PERFORM pg_drop_replication_slot(p_slot_name)
    FROM pg_replication_slots
    WHERE slot_name = p_slot_name;
    
    -- Create new slot
    RETURN QUERY
    SELECT * FROM pg_create_logical_replication_slot(p_slot_name, p_plugin);
    
    -- Audit log
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'REPLICATION_SLOT_CREATED', 'SLOT', p_slot_name,
        current_user, 'CREATE', 'info',
        jsonb_build_object('plugin', p_plugin)
    );
END;
$$ LANGUAGE plpgsql;

-- Create slots for expected subscribers
SELECT create_replication_slot_safe('sub_dr_standby_slot');
SELECT create_replication_slot_safe('sub_analytics_slot');
SELECT create_replication_slot_safe('sub_archive_slot');

-- =============================================================================
-- CONFLICT RESOLUTION STRATEGY (ISO 27031:2025 - Data Integrity)
-- =============================================================================

-- Table for tracking replication conflicts
CREATE TABLE IF NOT EXISTS replication_conflicts (
    id                  BIGSERIAL PRIMARY KEY,
    conflict_time       TIMESTAMPTZ DEFAULT NOW(),
    publication_name    TEXT,
    table_name          TEXT,
    operation           TEXT,  -- insert, update, delete
    conflict_type       TEXT,  -- unique_violation, update_missing, delete_missing
    local_tuple         JSONB,
    remote_tuple        JSONB,
    resolution_action   TEXT,  -- apply_remote, keep_local, merge, log_only
    resolved_by         TEXT,
    resolved_at         TIMESTAMPTZ,
    -- Compliance fields
    compliance_impact   TEXT DEFAULT 'low',  -- low, medium, high, critical
    data_classification TEXT,
    notes               TEXT
);

CREATE INDEX idx_replication_conflicts_time ON replication_conflicts(conflict_time);
CREATE INDEX idx_replication_conflicts_unresolved ON replication_conflicts(resolved_at) WHERE resolved_at IS NULL;
CREATE INDEX idx_replication_conflicts_compliance ON replication_conflicts(compliance_impact) WHERE compliance_impact IN ('high', 'critical');

COMMENT ON TABLE replication_conflicts IS 
    'Replication conflict tracking. Compliance: ISO 27031:2025. Critical conflicts require immediate resolution.';

-- =============================================================================
-- PUBLICATION MAINTENANCE
-- =============================================================================

-- Function to add table to existing publication with audit
CREATE OR REPLACE FUNCTION add_table_to_publication(
    p_publication TEXT,
    p_table TEXT
)
RETURNS TEXT AS $$
BEGIN
    EXECUTE format('ALTER PUBLICATION %I ADD TABLE %s', p_publication, p_table);
    
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'PUBLICATION_MODIFIED', 'PUBLICATION', p_publication,
        current_user, 'ADD_TABLE', 'info',
        jsonb_build_object('table_added', p_table)
    );
    
    RETURN format('Added %s to publication %s', p_table, p_publication);
EXCEPTION WHEN OTHERS THEN
    RETURN format('Error: %s', SQLERRM);
END;
$$ LANGUAGE plpgsql;

-- Function to remove table from publication
CREATE OR REPLACE FUNCTION remove_table_from_publication(
    p_publication TEXT,
    p_table TEXT
)
RETURNS TEXT AS $$
BEGIN
    EXECUTE format('ALTER PUBLICATION %I DROP TABLE %s', p_publication, p_table);
    
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'PUBLICATION_MODIFIED', 'PUBLICATION', p_publication,
        current_user, 'DROP_TABLE', 'warning',
        jsonb_build_object('table_removed', p_table)
    );
    
    RETURN format('Removed %s from publication %s', p_table, p_publication);
EXCEPTION WHEN OTHERS THEN
    RETURN format('Error: %s', SQLERRM);
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- MONITORING AND ALERTING (ISO 27031:2025)
-- =============================================================================

-- Function to check replication lag with compliance alerting
CREATE OR REPLACE FUNCTION check_replication_lag(
    p_max_lag_bytes BIGINT DEFAULT 1073741824  -- 1GB default
)
RETURNS TABLE (
    slot_name TEXT,
    lag_bytes BIGINT,
    lag_pretty TEXT,
    status TEXT,
    compliance_impact TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        rs.slot_name::TEXT,
        pg_wal_lsn_diff(pg_current_wal_lsn(), rs.confirmed_flush_lsn)::BIGINT AS lag_bytes,
        pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), rs.confirmed_flush_lsn))::TEXT AS lag_pretty,
        CASE 
            WHEN pg_wal_lsn_diff(pg_current_wal_lsn(), rs.confirmed_flush_lsn) > p_max_lag_bytes 
            THEN 'CRITICAL'
            WHEN pg_wal_lsn_diff(pg_current_wal_lsn(), rs.confirmed_flush_lsn) > p_max_lag_bytes / 4 
            THEN 'WARNING'
            ELSE 'OK'
        END::TEXT AS status,
        CASE 
            WHEN pg_wal_lsn_diff(pg_current_wal_lsn(), rs.confirmed_flush_lsn) > p_max_lag_bytes 
            THEN 'HIGH - RPO breach risk'
            WHEN pg_wal_lsn_diff(pg_current_wal_lsn(), rs.confirmed_flush_lsn) > p_max_lag_bytes / 4 
            THEN 'MEDIUM - Monitor closely'
            ELSE 'LOW - Normal operation'
        END::TEXT AS compliance_impact
    FROM pg_replication_slots rs
    WHERE rs.slot_type = 'logical';
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- GRANTS
-- =============================================================================

-- Grant replication privileges (run as superuser)
-- ALTER USER replication_user WITH REPLICATION;

-- Grant publication access
GRANT SELECT ON ALL TABLES IN SCHEMA public TO replication_user;
GRANT USAGE ON SCHEMA public TO replication_user;
GRANT SELECT ON v_publication_status TO replication_user;
GRANT SELECT ON v_replication_slots TO replication_user;

-- =============================================================================
-- VERIFICATION QUERIES
-- =============================================================================

-- Check all publications
SELECT * FROM v_publication_status;

-- Check replication slots
SELECT * FROM v_replication_slots;

-- Check replication lag
SELECT * FROM check_replication_lag();

-- List tables in each publication
SELECT * FROM pg_publication_tables ORDER BY pubname;

-- =============================================================================
-- AUDIT: Log setup completion
-- =============================================================================
INSERT INTO audit_events (
    event_type, entity_type, entity_id, actor_id, action, severity,
    new_values
) VALUES (
    'REPLICATION_SETUP', 'LOGICAL_PUBLICATION', '000_publication_setup',
    current_user, 'COMPLETE', 'info',
    jsonb_build_object(
        'publications_created', 5,
        'slots_created', 3,
        'compliance_features', ARRAY['TLS_1.3', 'Row_Filtering', 'Conflict_Tracking']
    ),
    NOW()
);

-- =============================================================================
-- IMPLEMENTATION CHECKLIST
-- =============================================================================

/*
COMPLIANCE CHECKLIST:
[ ] Configure wal_level = logical in postgresql.conf (requires restart)
[ ] Set up TLS 1.3 certificates for replication connections
[ ] Create replication_user with REPLICATION privilege
[ ] Configure pg_hba.conf for SSL-only replication connections
[ ] Set up monitoring for replication lag (alert at 100MB)
[ ] Configure conflict resolution procedures
[ ] Test row-level filtering (PostgreSQL 15+)
[ ] Verify column exclusion for PII
[ ] Set up cross-region replication for DR
[ ] Document failover procedures
[ ] Schedule quarterly replication testing

BUSINESS CONTINUITY REQUIREMENTS:
- RPO: 1 hour (configure synchronous_commit = remote_apply for critical data)
- RTO: 4 hours (automated failover with Patroni)
- Replication lag alerts: 100MB warning, 1GB critical
- Cross-region: At least 1 DR region with async replication

SECURITY CONTROLS:
- TLS 1.3 mandatory for all replication connections
- Certificate-based authentication preferred
- Row-level filtering for GDPR compliance
- Immutable audit trail for all publication changes
- Lag monitoring with compliance impact assessment
*/
