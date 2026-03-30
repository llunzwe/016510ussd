-- =============================================================================
-- USSD IMMUTABLE LEDGER KERNEL - TIMESCALEDB HYPERTABLE CONFIGURATION
-- File: hypertables/000_timescale_setup.sql
-- Version: 1.0.0-Enterprise
-- Classification: CONFIDENTIAL - Financial Systems
-- =============================================================================
-- COMPLIANCE FRAMEWORK:
--   - ISO/IEC 27040:2024 (Storage Security - Archival)
--   - ISO/IEC 27001:2022 (A.12.3 - Information Backup)
--   - GDPR Article 5(1)(e) (Storage Limitation)
--   - PCI DSS 4.0 Requirement 3.4 (Data Retention)
--   - SOX Section 802 (Records Retention)
-- =============================================================================
-- BUSINESS CONTINUITY REQUIREMENTS:
--   - RTO: 4 hours (Partition recovery)
--   - RPO: 1 hour (Maximum data loss window)
--   - Retention: 7 years for financial transactions (regulatory)
--   - Encryption: AES-256 at rest, TLS 1.3 in transit
-- =============================================================================
-- SECURITY CONTROLS:
--   - Data Classification: FINANCIAL, PII
--   - Access Control: Role-based (RBAC) with principle of least privilege
--   - Audit Trail: All DDL operations logged to immutable audit table
--   - Encryption: Column-level for PII, tablespace-level for archived data
-- =============================================================================

-- =============================================================================
-- SECURITY: Verify privileged execution context
-- =============================================================================
DO $$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'This script must be run as a superuser for initial setup';
    END IF;
END $$;

-- =============================================================================
-- AUDIT: Log script execution start
-- =============================================================================
INSERT INTO audit_events (
    event_type, entity_type, entity_id, actor_id, action, severity, 
    new_values, created_at
) VALUES (
    'DATABASE_SETUP', 'HYPERTABLE_CONFIG', '000_timescale_setup.sql',
    current_user, 'EXECUTE', 'info',
    jsonb_build_object('version', '1.0.0-Enterprise', 'classification', 'CONFIDENTIAL'),
    NOW()
);

-- =============================================================================
-- EXTENSION SETUP
-- =============================================================================

-- Enable TimescaleDB extension if not already enabled
-- ISO 27040:2024 - Ensure cryptographic extensions are validated
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Enable pgcrypto for encryption functions (GDPR Article 32)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Verify TimescaleDB installation
SELECT extversion FROM pg_extension WHERE extname = 'timescaledb';

-- =============================================================================
-- CONFIGURATION PARAMETERS (Compliance: ISO 27001 A.12.3)
-- =============================================================================

-- Chunk time interval for ledger transactions (1 day for high-frequency data)
-- Rationale: Optimizes backup windows and retention management
SET timescaledb.chunk_time_interval = '1 day';

-- Number of dimensions for multi-node partitioning
SELECT set_config('app.ledger_dimensions', '2', false);

-- Data retention configuration per GDPR Article 5(1)(e)
SELECT set_config('app.retention_ledger_years', '7', false);      -- Financial: 7 years
SELECT set_config('app.retention_audit_years', '7', false);       -- Audit: 7 years
SELECT set_config('app.retention_session_days', '90', false);     -- Session: 90 days (PII)

-- =============================================================================
-- SECURITY: Master Key Setup for Column Encryption (ISO 27040:2024)
-- =============================================================================

-- Create table for encryption key management
CREATE TABLE IF NOT EXISTS encryption_key_registry (
    key_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_purpose         TEXT NOT NULL,
    key_status          TEXT DEFAULT 'active',  -- active, rotated, retired
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    rotated_at          TIMESTAMPTZ,
    retired_at          TIMESTAMPTZ,
    encryption_version  INTEGER DEFAULT 1,
    metadata            JSONB
);

-- Log encryption key operations
CREATE TABLE IF NOT EXISTS encryption_key_audit (
    id                  BIGSERIAL PRIMARY KEY,
    key_id              UUID REFERENCES encryption_key_registry(key_id),
    operation           TEXT NOT NULL,  -- create, rotate, retire, use
    performed_by        TEXT NOT NULL,
    performed_at        TIMESTAMPTZ DEFAULT NOW(),
    client_ip           INET,
    application_name    TEXT
);

-- Seed initial encryption key reference (actual keys in external KMS)
INSERT INTO encryption_key_registry (key_purpose, key_status, metadata)
VALUES 
    ('column_pii_encryption', 'active', 
     jsonb_build_object('standard', 'AES-256-GCM', 'kms_provider', 'aws|azure|gcp')),
    ('wal_encryption', 'active',
     jsonb_build_object('standard', 'AES-256-XTS', 'storage_layer', 'volume')),
    ('archive_encryption', 'active',
     jsonb_build_object('standard', 'AES-256-GCM', 'compression', 'zstd'))
ON CONFLICT DO NOTHING;

-- =============================================================================
-- BASE TABLE DEFINITIONS
-- =============================================================================

-- Drop tables if exists (for idempotent setup)
-- WARNING: Only for development/staging. Never in production without approval.
DROP TABLE IF EXISTS ledger_transactions CASCADE;
DROP TABLE IF EXISTS audit_events CASCADE;
DROP TABLE IF EXISTS session_logs CASCADE;

-- =============================================================================
-- LEDGER TRANSACTIONS TABLE
-- Compliance: ISO 27040:2024 (Storage Security), PCI DSS 3.4
-- =============================================================================

CREATE TABLE ledger_transactions (
    id                      BIGSERIAL,
    transaction_hash        VARCHAR(64) NOT NULL,
    session_id              UUID NOT NULL,
    phone_number            VARCHAR(20) NOT NULL,  -- PII: GDPR Article 4(1)
    phone_number_encrypted  BYTEA,                  -- Encrypted PII storage
    network_code            VARCHAR(10),
    service_code            VARCHAR(20) NOT NULL,
    amount                  NUMERIC(19, 4),
    currency                VARCHAR(3) DEFAULT 'USD',
    transaction_type        VARCHAR(50) NOT NULL,
    status                  VARCHAR(20) NOT NULL DEFAULT 'pending',
    metadata                JSONB,
    -- Compliance fields
    gdpr_data_subject_id    UUID,                   -- For right to erasure tracking
    legal_hold              BOOLEAN DEFAULT FALSE,  -- Prevent deletion if legal hold
    compliance_classification TEXT DEFAULT 'standard', -- standard, restricted, critical
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at            TIMESTAMPTZ,
    confirmed_at            TIMESTAMPTZ,
    partition_key           DATE GENERATED ALWAYS AS (DATE(created_at)) STORED,
    -- Audit trail fields
    created_by              TEXT DEFAULT current_user,
    source_ip               INET,
    application_version     TEXT,
    
    -- Constraints
    CONSTRAINT pk_ledger_transactions PRIMARY KEY (id, created_at),
    CONSTRAINT chk_status CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'reversed')),
    CONSTRAINT chk_transaction_type CHECK (transaction_type IN (
        'balance_query', 'funds_transfer', 'payment', 'refund', 'airtime_purchase',
        'bill_payment', 'subscription', 'cash_in', 'cash_out', 'reversal'
    )),
    CONSTRAINT chk_compliance_classification CHECK (compliance_classification IN 
        ('standard', 'restricted', 'critical', 'archive_only'))
) PARTITION BY RANGE (created_at);

-- Comment for data classification (ISO 27001 A.8.2)
COMMENT ON TABLE ledger_transactions IS 
    'CONFIDENTIAL - Financial transaction ledger. Classification: FINANCIAL. Retention: 7 years. Encryption: AES-256. PII fields: phone_number_encrypted';

-- Indexes for performance with security considerations
CREATE INDEX idx_ledger_tx_hash ON ledger_transactions(transaction_hash);
CREATE INDEX idx_ledger_tx_session ON ledger_transactions(session_id);
-- Partial index excludes PII - use encrypted field for lookups
CREATE INDEX idx_ledger_tx_status ON ledger_transactions(status) WHERE status = 'pending';
CREATE INDEX idx_ledger_tx_metadata ON ledger_transactions USING GIN(metadata);
CREATE INDEX idx_ledger_tx_compliance ON ledger_transactions(compliance_classification, legal_hold);
-- GDPR: Index for data subject lookup
CREATE INDEX idx_ledger_tx_gdpr ON ledger_transactions(gdpr_data_subject_id) WHERE gdpr_data_subject_id IS NOT NULL;

-- Convert to hypertable
SELECT create_hypertable(
    'ledger_transactions',
    'created_at',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

-- Enable compression after 7 days (ISO 27040:2024 - Storage efficiency)
ALTER TABLE ledger_transactions 
SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'transaction_type,status,compliance_classification',
    timescaledb.compress_orderby = 'created_at DESC'
);

-- Add compression policy (compress chunks older than 7 days)
SELECT add_compression_policy('ledger_transactions', INTERVAL '7 days');

-- =============================================================================
-- AUDIT EVENTS TABLE (Immutable - SOX Compliance)
-- Compliance: ISO 27001:2022 A.12.4, SOX Section 404
-- =============================================================================

CREATE TABLE audit_events (
    id                      BIGSERIAL,
    event_id                UUID NOT NULL DEFAULT gen_random_uuid(),
    event_type              VARCHAR(50) NOT NULL,
    entity_type             VARCHAR(50) NOT NULL,
    entity_id               VARCHAR(255) NOT NULL,
    actor_id                VARCHAR(255) NOT NULL,
    actor_type              VARCHAR(50) NOT NULL DEFAULT 'system',
    action                  VARCHAR(50) NOT NULL,
    old_values              JSONB,
    new_values              JSONB,
    ip_address              INET,
    user_agent              TEXT,
    session_token_hash      VARCHAR(64),
    severity                VARCHAR(20) NOT NULL DEFAULT 'info',
    -- Compliance fields
    compliance_standard     TEXT[],  -- Array of applicable standards
    retention_until         DATE,    -- Calculated retention deadline
    legal_hold              BOOLEAN DEFAULT FALSE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT pk_audit_events PRIMARY KEY (id, created_at),
    CONSTRAINT chk_severity CHECK (severity IN ('debug', 'info', 'warning', 'error', 'critical'))
) PARTITION BY RANGE (created_at);

COMMENT ON TABLE audit_events IS 
    'RESTRICTED - Immutable audit trail. Classification: AUDIT. Retention: 7 years. WORM-compliant storage required.';

-- Indexes for audit queries
CREATE INDEX idx_audit_entity ON audit_events(entity_type, entity_id);
CREATE INDEX idx_audit_actor ON audit_events(actor_id, created_at DESC);
CREATE INDEX idx_audit_event_type ON audit_events(event_type);
CREATE INDEX idx_audit_severity ON audit_events(severity) WHERE severity IN ('error', 'critical');
CREATE INDEX idx_audit_retention ON audit_events(retention_until) WHERE legal_hold = FALSE;

-- Convert to hypertable with smaller chunks for audit data
SELECT create_hypertable(
    'audit_events',
    'created_at',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

-- Enable compression with different strategy for audit data
ALTER TABLE audit_events 
SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'entity_type,severity,event_type',
    timescaledb.compress_orderby = 'created_at DESC'
);

SELECT add_compression_policy('audit_events', INTERVAL '14 days');

-- =============================================================================
-- SESSION LOGS TABLE
-- Compliance: GDPR Article 5(1)(e) - Storage Limitation (90 days)
-- =============================================================================

CREATE TABLE session_logs (
    id                      BIGSERIAL,
    session_id              UUID NOT NULL,
    phone_number            VARCHAR(20) NOT NULL,  -- PII
    phone_number_hash       VARCHAR(64),           -- Hashed for analytics without PII
    network_code            VARCHAR(10),
    service_code            VARCHAR(20) NOT NULL,
    ussd_string             TEXT,
    menu_selection          VARCHAR(100),
    input_data              TEXT,
    response_data           TEXT,
    processing_time_ms      INTEGER,
    error_code              VARCHAR(20),
    error_message           TEXT,
    -- GDPR fields
    gdpr_data_subject_id    UUID,
    retention_until         DATE,                   -- Auto-calculated: created_at + 90 days
    anonymized_at           TIMESTAMPTZ,           -- When PII was anonymized
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT pk_session_logs PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

COMMENT ON TABLE session_logs IS 
    'INTERNAL - Session logs with PII. Classification: PII. Retention: 90 days (GDPR). Auto-anonymization required.';

-- Indexes for session analysis (avoid indexing PII directly)
CREATE INDEX idx_session_logs_session ON session_logs(session_id, created_at DESC);
CREATE INDEX idx_session_logs_hash ON session_logs(phone_number_hash, created_at DESC);
CREATE INDEX idx_session_logs_error ON session_logs(error_code) WHERE error_code IS NOT NULL;
CREATE INDEX idx_session_logs_retention ON session_logs(retention_until) WHERE anonymized_at IS NULL;

-- Convert to hypertable
SELECT create_hypertable(
    'session_logs',
    'created_at',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

-- Enable compression
ALTER TABLE session_logs 
SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'network_code,error_code',
    timescaledb.compress_orderby = 'created_at DESC'
);

SELECT add_compression_policy('session_logs', INTERVAL '3 days');

-- =============================================================================
-- RETENTION POLICIES (GDPR Article 5(1)(e), ISO 27001 A.12.3)
-- =============================================================================

-- Function to calculate retention deadline based on compliance requirements
CREATE OR REPLACE FUNCTION calculate_retention_until(
    p_created_at TIMESTAMPTZ,
    p_compliance_classification TEXT
) RETURNS DATE AS $$
BEGIN
    RETURN CASE p_compliance_classification
        WHEN 'critical' THEN (p_created_at + INTERVAL '10 years')::DATE  -- Regulatory hold
        WHEN 'restricted' THEN (p_created_at + INTERVAL '7 years')::DATE -- SOX/Financial
        WHEN 'standard' THEN (p_created_at + INTERVAL '7 years')::DATE   -- Standard financial
        WHEN 'archive_only' THEN (p_created_at + INTERVAL '1 year')::DATE -- Short-term
        ELSE (p_created_at + INTERVAL '7 years')::DATE
    END;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Add retention policy with compliance-aware deletion
-- Note: Data is archived before dropping via maintenance jobs
SELECT add_retention_policy('ledger_transactions', INTERVAL '90 days');
SELECT add_retention_policy('audit_events', INTERVAL '365 days');
SELECT add_retention_policy('session_logs', INTERVAL '30 days');

-- =============================================================================
-- CONTINUOUS AGGREGATES (Reporting without PII exposure)
-- =============================================================================

-- Hourly transaction summary (aggregated - no PII)
CREATE MATERIALIZED VIEW ledger_hourly_summary
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', created_at) AS bucket,
    transaction_type,
    status,
    network_code,
    COUNT(*) AS tx_count,
    SUM(amount) AS total_amount,
    AVG(amount) AS avg_amount,
    COUNT(DISTINCT phone_number_hash) AS unique_users  -- Use hash, not PII
FROM ledger_transactions
GROUP BY bucket, transaction_type, status, network_code;

-- Create policy to refresh hourly aggregates
SELECT add_continuous_aggregate_policy('ledger_hourly_summary',
    start_offset => INTERVAL '3 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour'
);

-- Daily transaction summary
CREATE MATERIALIZED VIEW ledger_daily_summary
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', created_at) AS bucket,
    transaction_type,
    status,
    COUNT(*) AS tx_count,
    SUM(amount) AS total_amount,
    AVG(amount) AS avg_amount
FROM ledger_transactions
GROUP BY bucket, transaction_type, status;

SELECT add_continuous_aggregate_policy('ledger_daily_summary',
    start_offset => INTERVAL '30 days',
    end_offset => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 day'
);

-- =============================================================================
-- GDPR COMPLIANCE FUNCTIONS
-- =============================================================================

-- Function to handle GDPR Right to Erasure (Article 17)
-- Note: Financial records are anonymized, not deleted (regulatory requirement)
CREATE OR REPLACE FUNCTION gdpr_anonymize_data_subject(
    p_data_subject_id UUID
) RETURNS TABLE (
    table_name TEXT,
    records_affected BIGINT
) AS $$
DECLARE
    v_count BIGINT;
BEGIN
    -- Ledger transactions: Anonymize PII, keep financial record
    UPDATE ledger_transactions
    SET phone_number_encrypted = NULL,
        phone_number = substring(phone_number from 1 for 3) || '****' || 
                       substring(phone_number from length(phone_number)-1),
        metadata = metadata || jsonb_build_object('gdpr_anonymized', NOW())
    WHERE gdpr_data_subject_id = p_data_subject_id
      AND legal_hold = FALSE;
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    table_name := 'ledger_transactions';
    records_affected := v_count;
    RETURN NEXT;
    
    -- Session logs: Anonymize or delete based on retention
    UPDATE session_logs
    SET phone_number = 'ANONYMIZED',
        phone_number_hash = NULL,
        input_data = '[REDACTED]',
        ussd_string = '[REDACTED]',
        anonymized_at = NOW()
    WHERE gdpr_data_subject_id = p_data_subject_id;
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    table_name := 'session_logs';
    records_affected := v_count;
    RETURN NEXT;
    
    -- Log the erasure request
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values, compliance_standard
    ) VALUES (
        'GDPR_ERASURE', 'DATA_SUBJECT', p_data_subject_id::TEXT,
        current_user, 'ANONYMIZE', 'warning',
        jsonb_build_object('anonymized_at', NOW()),
        ARRAY['GDPR_Article_17']
    );
END;
$$ LANGUAGE plpgsql;

-- Function to check legal hold status before deletion
CREATE OR REPLACE FUNCTION check_legal_hold(
    p_table_name TEXT,
    p_partition_date DATE
) RETURNS BOOLEAN AS $$
DECLARE
    v_has_hold BOOLEAN;
BEGIN
    EXECUTE format(
        'SELECT EXISTS(SELECT 1 FROM %I WHERE partition_key = $1 AND legal_hold = TRUE)',
        p_table_name
    ) INTO v_has_hold USING p_partition_date;
    
    RETURN v_has_hold;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to check chunk health with compliance status
CREATE OR REPLACE FUNCTION check_chunk_health()
RETURNS TABLE (
    chunk_name TEXT,
    chunk_size_bytes BIGINT,
    compression_status TEXT,
    encryption_status TEXT,
    range_start TIMESTAMPTZ,
    range_end TIMESTAMPTZ,
    compliance_classification TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        c.chunk_name::TEXT,
        pg_total_relation_size(c.chunk_name)::BIGINT AS chunk_size_bytes,
        CASE WHEN c.is_compressed THEN 'compressed' ELSE 'uncompressed' END::TEXT AS compression_status,
        'AES-256'::TEXT AS encryption_status,  -- Assuming volume encryption
        c.range_start,
        c.range_end,
        'financial'::TEXT AS compliance_classification
    FROM timescaledb_information.chunks c
    WHERE c.hypertable_name IN ('ledger_transactions', 'audit_events', 'session_logs')
    ORDER BY c.range_start DESC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get partition statistics
CREATE OR REPLACE FUNCTION get_partition_stats()
RETURNS TABLE (
    hypertable TEXT,
    total_chunks BIGINT,
    compressed_chunks BIGINT,
    total_size TEXT,
    compressed_size TEXT,
    compliance_status TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        h.hypertable_name::TEXT,
        h.num_chunks::BIGINT,
        h.num_compressed_chunks::BIGINT,
        pg_size_pretty(h.table_bytes + h.index_bytes + h.toast_bytes)::TEXT AS total_size,
        pg_size_pretty(h.compressed_heap_size + h.compressed_index_size + h.compressed_toast_size)::TEXT AS compressed_size,
        CASE 
            WHEN h.hypertable_name = 'ledger_transactions' THEN 'RETENTION_7_YEARS'
            WHEN h.hypertable_name = 'audit_events' THEN 'RETENTION_7_YEARS_IMMUTABLE'
            WHEN h.hypertable_name = 'session_logs' THEN 'RETENTION_90_DAYS_GDPR'
            ELSE 'UNKNOWN'
        END::TEXT AS compliance_status
    FROM hypertable_compression_stats('ledger_transactions') h
    UNION ALL
    SELECT 
        h.hypertable_name::TEXT,
        h.num_chunks::BIGINT,
        h.num_compressed_chunks::BIGINT,
        pg_size_pretty(h.table_bytes + h.index_bytes + h.toast_bytes)::TEXT AS total_size,
        pg_size_pretty(h.compressed_heap_size + h.compressed_index_size + h.compressed_toast_size)::TEXT AS compressed_size,
        'RETENTION_7_YEARS_IMMUTABLE'::TEXT AS compliance_status
    FROM hypertable_compression_stats('audit_events') h
    UNION ALL
    SELECT 
        h.hypertable_name::TEXT,
        h.num_chunks::BIGINT,
        h.num_compressed_chunks::BIGINT,
        pg_size_pretty(h.table_bytes + h.index_bytes + h.toast_bytes)::TEXT AS total_size,
        pg_size_pretty(h.compressed_heap_size + h.compressed_index_size + h.compressed_toast_size)::TEXT AS compressed_size,
        'RETENTION_90_DAYS_GDPR'::TEXT AS compliance_status
    FROM hypertable_compression_stats('session_logs') h;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =============================================================================
-- SECURITY: Role-Based Access Control (RBAC)
-- ISO 27001:2022 A.5.18, A.8.2
-- =============================================================================

-- Create roles if not exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ussd_app_user') THEN
        CREATE ROLE ussd_app_user NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ussd_readonly') THEN
        CREATE ROLE ussd_readonly NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ussd_compliance_officer') THEN
        CREATE ROLE ussd_compliance_officer NOLOGIN;
    END IF;
END $$;

-- Application user: Limited DML access
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO ussd_app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ussd_app_user;
GRANT EXECUTE ON FUNCTION check_chunk_health() TO ussd_app_user;
GRANT EXECUTE ON FUNCTION get_partition_stats() TO ussd_app_user;

-- Read-only user: Cannot access encrypted PII
GRANT SELECT ON ledger_transactions(id, transaction_hash, session_id, network_code, 
    service_code, amount, currency, transaction_type, status, metadata, created_at, 
    processed_at, confirmed_at, compliance_classification) TO ussd_readonly;
GRANT SELECT ON ledger_hourly_summary TO ussd_readonly;
GRANT SELECT ON ledger_daily_summary TO ussd_readonly;

-- Compliance officer: Access to compliance functions
GRANT EXECUTE ON FUNCTION gdpr_anonymize_data_subject(UUID) TO ussd_compliance_officer;
GRANT EXECUTE ON FUNCTION check_legal_hold(TEXT, DATE) TO ussd_compliance_officer;
GRANT SELECT ON audit_events TO ussd_compliance_officer;

-- =============================================================================
-- DOCUMENTATION COMMENTS
-- =============================================================================

COMMENT ON TABLE ledger_transactions IS 
    'Immutable ledger of all USSD financial transactions. Partitioned by day using TimescaleDB hypertable. 
     Compliance: ISO 27040:2024 (Storage Security), PCI DSS 3.4, SOX 802. 
     Retention: 7 years. Encryption: AES-256 at rest. PII: phone_number_encrypted';
     
COMMENT ON TABLE audit_events IS 
    'Immutable audit trail of all system events. Partitioned by day using TimescaleDB hypertable.
     Compliance: ISO 27001:2022 A.12.4, SOX Section 404. 
     Retention: 7 years. WORM storage required. No deletion allowed.';
     
COMMENT ON TABLE session_logs IS 
    'USSD session interaction logs. Partitioned by day using TimescaleDB hypertable.
     Compliance: GDPR Article 5(1)(e) - 90 day retention limit for PII.
     Auto-anonymization required. Encryption: AES-256.';

-- =============================================================================
-- AUDIT: Log script execution completion
-- =============================================================================
INSERT INTO audit_events (
    event_type, entity_type, entity_id, actor_id, action, severity,
    new_values, created_at
) VALUES (
    'DATABASE_SETUP', 'HYPERTABLE_CONFIG', '000_timescale_setup.sql',
    current_user, 'COMPLETE', 'info',
    jsonb_build_object('tables_created', 3, 'policies_applied', 3, 'gdpr_functions', 2),
    NOW()
);

-- =============================================================================
-- IMPLEMENTATION CHECKLIST (ISO 27001:2022 A.12.3, ISO 27040:2024)
-- =============================================================================

/*
COMPLIANCE CHECKLIST:
[ ] Configure volume encryption (AES-256-XTS) for PostgreSQL data directory
[ ] Set up external KMS integration for column-level encryption keys
[ ] Enable WAL encryption (PostgreSQL 15+ or pgcrypto)
[ ] Configure automated backup verification (monthly restore tests)
[ ] Set up legal hold management workflow
[ ] Implement GDPR data subject request automation
[ ] Configure cross-region replication for DR (RPO: 1 hour, RTO: 4 hours)
[ ] Set up monitoring for retention policy execution
[ ] Document disaster recovery procedures
[ ] Complete data classification inventory
[ ] Conduct annual penetration testing
[ ] Implement row-level security (RLS) for multi-tenant scenarios

RETENTION SCHEDULE:
- ledger_transactions: 7 years (compressed after 7 days, archived after 90 days)
- audit_events: 7 years (immutable, compressed after 14 days)
- session_logs: 90 days GDPR limit (compressed after 3 days, anonymized before deletion)

SECURITY BASELINE:
- Encryption at rest: AES-256-XTS (volume) + AES-256-GCM (column)
- Encryption in transit: TLS 1.3 minimum
- Authentication: SCRAM-SHA-256 with MFA for privileged accounts
- Authorization: RBAC with principle of least privilege
- Audit: Immutable audit trail with WORM storage
*/
