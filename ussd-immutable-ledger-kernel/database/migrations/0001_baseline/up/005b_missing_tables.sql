-- =============================================================================
-- MIGRATION: 005b_missing_tables.sql
-- DESCRIPTION: Create missing tables referenced by triggers and processes
-- DEPENDENCIES: 001_create_schemas.sql, 003_core_account_registry.sql
-- MUST RUN BEFORE: 030_core_integrity_triggers.sql, partition maintenance
-- =============================================================================

-- Create ussd.security_alerts table (referenced by fraud detection triggers)
CREATE TABLE IF NOT EXISTS ussd.security_alerts (
    alert_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_type          VARCHAR(50) NOT NULL,
    severity            VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    session_id          UUID REFERENCES ussd.ussd_sessions(session_id),
    account_id          UUID REFERENCES core.accounts(account_id),
    description         TEXT NOT NULL,
    detected_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at         TIMESTAMPTZ,
    resolved_by         UUID REFERENCES core.accounts(account_id),
    metadata            JSONB DEFAULT '{}',
    
    CONSTRAINT chk_security_alerts_severity 
        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
);

CREATE INDEX IF NOT EXISTS idx_security_alerts_session 
    ON ussd.security_alerts(session_id);
CREATE INDEX IF NOT EXISTS idx_security_alerts_account 
    ON ussd.security_alerts(account_id);
CREATE INDEX IF NOT EXISTS idx_security_alerts_detected 
    ON ussd.security_alerts(detected_at);
CREATE INDEX IF NOT EXISTS idx_security_alerts_type 
    ON ussd.security_alerts(alert_type, severity) 
    WHERE severity IN ('HIGH', 'CRITICAL');

COMMENT ON TABLE ussd.security_alerts IS 'Security alerts for fraud detection and monitoring';

-- Create ussd.maintenance_logs table (referenced by session cleanup)
CREATE TABLE IF NOT EXISTS ussd.maintenance_logs (
    log_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    maintenance_type    VARCHAR(50) NOT NULL,
    table_name          VARCHAR(100),
    records_affected    INTEGER,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at        TIMESTAMPTZ,
    status              VARCHAR(20) DEFAULT 'RUNNING',
    details             JSONB DEFAULT '{}',
    
    CONSTRAINT chk_maintenance_logs_status 
        CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED'))
);

CREATE INDEX IF NOT EXISTS idx_maintenance_logs_type 
    ON ussd.maintenance_logs(maintenance_type, started_at);
CREATE INDEX IF NOT EXISTS idx_maintenance_logs_status 
    ON ussd.maintenance_logs(status) 
    WHERE status = 'RUNNING';

COMMENT ON TABLE ussd.maintenance_logs IS 'Maintenance operation logs for audit trail';

-- Create audit.audit_events table (referenced by partition maintenance)
CREATE TABLE IF NOT EXISTS audit.audit_events (
    event_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type          VARCHAR(100) NOT NULL,
    entity_type         VARCHAR(50),
    entity_id           TEXT,
    actor_id            UUID,
    action              VARCHAR(50),
    severity            VARCHAR(20) DEFAULT 'INFO',
    old_values          JSONB,
    new_values          JSONB,
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    CONSTRAINT chk_audit_events_severity 
        CHECK (severity IN ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'))
);

CREATE INDEX IF NOT EXISTS idx_audit_events_type 
    ON audit.audit_events(event_type, occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_entity 
    ON audit.audit_events(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_occurred 
    ON audit.audit_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_severity 
    ON audit.audit_events(severity, occurred_at) 
    WHERE severity IN ('ERROR', 'CRITICAL');

COMMENT ON TABLE audit.audit_events IS 'System audit events for compliance tracking';

-- Create archive.partition_archive_registry table
CREATE TABLE IF NOT EXISTS archive.partition_archive_registry (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    original_table      VARCHAR(100) NOT NULL,
    partition_name      VARCHAR(100) NOT NULL,
    partition_date      DATE,
    row_count           BIGINT,
    original_size_bytes BIGINT,
    compressed_size_bytes BIGINT,
    compression_ratio   NUMERIC(5,2),
    archived_to         VARCHAR(255),
    archive_path        TEXT,
    checksum_sha256     VARCHAR(64),
    encryption_key_id   VARCHAR(100),
    encryption_algorithm VARCHAR(20),
    retention_until     TIMESTAMPTZ,
    compliance_standard VARCHAR(50),
    status              VARCHAR(20) DEFAULT 'PENDING',
    metadata            JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    CONSTRAINT chk_partition_archive_status 
        CHECK (status IN ('PENDING', 'ARCHIVING', 'ARCHIVED', 'FAILED', 'RESTORED'))
);

CREATE INDEX IF NOT EXISTS idx_partition_archive_table 
    ON archive.partition_archive_registry(original_table, partition_date);
CREATE INDEX IF NOT EXISTS idx_partition_archive_status 
    ON archive.partition_archive_registry(status);
CREATE INDEX IF NOT EXISTS idx_partition_archive_retention 
    ON archive.partition_archive_registry(retention_until) 
    WHERE retention_until IS NOT NULL;

COMMENT ON TABLE archive.partition_archive_registry IS 'Registry of archived partitions for compliance';

/*
================================================================================
MIGRATION CHECKLIST:
[x] Create ussd.security_alerts table
[x] Create ussd.maintenance_logs table  
[x] Create audit.audit_events table
[x] Create archive.partition_archive_registry table
[x] Add all indexes for query performance
[x] Add check constraints for data integrity
[ ] Test with partition maintenance procedures
[ ] Verify fraud detection triggers can write to security_alerts
================================================================================
*/
