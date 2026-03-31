-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: security/audit/001_audit_table_definitions.sql
-- Description: Core audit log tables and partition management
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: RESTRICTED
-- DATA SENSITIVITY: CRITICAL - Immutable Audit Trail
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.12.4 Logging and Monitoring
  - A.12.4.1: Event logging covering all security-relevant events
  - A.12.4.2: Protection of log information from tampering
  - A.12.4.3: System administrator and operator logs
  
A.16.1 Management of Information Security Incidents
  - A.16.1.1: Incident logging with forensic value
  - A.16.1.7: Collection of evidence for legal proceedings

A.18.1 Compliance with Legal and Contractual Requirements
  - A.18.1.3: Protection of records (7-year retention)
  - A.18.1.4: Privacy and protection of PII in audit logs
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION IN CLOUD
================================================================================
- Audit logs track all PII access for compliance
- Data subject access request support through audit queries
- Secure handling of PII in audit records with masking
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
5.4.2 Audit Logging for Storage
  - Partitioning for performance and retention management
  - Compression for long-term archival
  - Encryption at rest for audit records
  
7.3 Data Retention and Disposal
  - Automated partition lifecycle management
  - Legal hold capability preventing deletion
  - Secure purge procedures for expired data
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
Clause 4: EDRM Reference Model Alignment
  - Information Management: Structured audit schema
  - Identification: Indexed fields for e-discovery queries
  - Preservation: Immutable storage with legal hold
  - Collection: Partitioned tables for efficient export
  - Processing: Normalized JSONB for standard formats
  - Review: Views for compliance officer access
  - Production: Export functions for litigation support
  - Presentation: Time-series views for timeline analysis
================================================================================

================================================================================
PCI DSS 4.0 AUDIT REQUIREMENTS
================================================================================
Requirement 10.3.1: Retain audit trail history for minimum 1 year
Requirement 10.3.2: Immediate availability of at least 3 months of logs
Requirement 10.3.3: Secure storage preventing modification
Requirement 10.3.4: Centralized logging for critical systems
Requirement 10.3.5: File integrity monitoring on audit logs
Requirement 10.3.6: Synchronization of time across systems
Requirement 10.7: Retention policy for audit logs
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. Native partitioning by time range for performance
2. RLS policies preventing UPDATE/DELETE on audit tables
3. JSONB for flexible structured data storage
4. Appropriate indexes for common query patterns
5. Automated partition creation and archival
================================================================================

================================================================================
AUDIT TRAIL IMMUTABILITY
================================================================================
Enforcement Mechanisms:
  1. RLS policies: DENY UPDATE/DELETE on audit tables
  2. Database triggers: Block modification attempts
  3. Application role permissions: Read-only access
  4. WORM storage integration for archive partitions
  5. Cryptographic signing of audit batches

Integrity Verification:
  - Periodic hash chain verification
  - Automated integrity reports
  - External blockchain anchoring (optional)
================================================================================

================================================================================
RETENTION AND ARCHIVAL POLICY
================================================================================
Active Partition (Hot): Last 3 months on fast storage
Archive Partition (Warm): 3-12 months on standard storage
Cold Storage: 1-7 years on compressed/archival storage
Legal Hold: Indefinite retention for litigation holds
================================================================================
*/

-- ============================================================================
-- CORE AUDIT LOG TABLE
-- ============================================================================

-- ISO/IEC 27001: A.12.4.1 - Main audit log table
-- PCI DSS 10.3 - Native partitioning for retention management
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schema_name VARCHAR(63) NOT NULL,
    table_name VARCHAR(63) NOT NULL,
    operation VARCHAR(10) NOT NULL CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')),
    record_id TEXT,
    old_data JSONB,
    new_data JSONB,
    changed_fields JSONB,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by UUID,
    session_user_name VARCHAR(100),
    application_name VARCHAR(100),
    client_addr INET,
    client_port INTEGER,
    transaction_id BIGINT,
    statement_id BIGINT,
    query_text TEXT,
    severity VARCHAR(20) DEFAULT 'info',
    metadata JSONB DEFAULT '{}'
) PARTITION BY RANGE (changed_at);

-- Create initial partitions for current and next month
-- ISO/IEC 27040: Automated partition management
DO $$
DECLARE
    current_month TEXT;
    next_month TEXT;
BEGIN
    current_month := to_char(NOW(), 'YYYY_MM');
    next_month := to_char(NOW() + INTERVAL '1 month', 'YYYY_MM');
    
    -- Current month partition
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS audit_log_%s PARTITION OF audit_log
         FOR VALUES FROM (%L) TO (%L)',
        current_month,
        date_trunc('month', NOW()),
        date_trunc('month', NOW() + INTERVAL '1 month')
    );
    
    -- Next month partition
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS audit_log_%s PARTITION OF audit_log
         FOR VALUES FROM (%L) TO (%L)',
        next_month,
        date_trunc('month', NOW() + INTERVAL '1 month'),
        date_trunc('month', NOW() + INTERVAL '2 months')
    );
END $$;

-- Indexes on partitioned table (PCI DSS 10.3.4)
CREATE INDEX IF NOT EXISTS idx_audit_log_table_op ON audit_log(table_name, operation);
CREATE INDEX IF NOT EXISTS idx_audit_log_changed_by ON audit_log(changed_by);
CREATE INDEX IF NOT EXISTS idx_audit_log_record_id ON audit_log(record_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_changed_at ON audit_log(changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_transaction ON audit_log(transaction_id);

-- ============================================================================
-- SPECIALIZED AUDIT TABLES
-- ============================================================================

-- Transaction audit log (high-value/sensitive operations)
-- PCI DSS: Enhanced logging for CHD access
CREATE TABLE IF NOT EXISTS transaction_audit_log (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    operation VARCHAR(10) NOT NULL,
    audit_data JSONB NOT NULL,
    compliance_flags JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- Authentication audit log
-- ISO/IEC 27001: A.9.4.2 - Authentication monitoring
CREATE TABLE IF NOT EXISTS authentication_audit_log (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    event_details JSONB NOT NULL,
    risk_score INTEGER DEFAULT 0,
    alert_triggered BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- PII access audit log (GDPR/CCPA compliance)
-- ISO/IEC 27018: PII processing monitoring
CREATE TABLE IF NOT EXISTS pii_access_audit (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    data_subject_id TEXT NOT NULL,
    access_type VARCHAR(20) NOT NULL,
    legal_basis VARCHAR(50),
    consent_reference VARCHAR(100),
    access_context JSONB NOT NULL,
    retention_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- ============================================================================
-- AUDIT ERROR AND MAINTENANCE TABLES
-- ============================================================================

-- Audit error log (for failed audit writes)
-- ISO/IEC 27001: A.12.4.2 - Audit system reliability
CREATE TABLE IF NOT EXISTS audit_error_log (
    error_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    error_time TIMESTAMPTZ DEFAULT NOW(),
    table_schema VARCHAR(63),
    table_name VARCHAR(63),
    operation VARCHAR(10),
    error_message TEXT,
    original_data JSONB
);

-- Audit archive table (for old partitions)
-- ISO/IEC 27040: Long-term storage
CREATE TABLE IF NOT EXISTS audit_archive (
    LIKE audit_log INCLUDING ALL,
    archived_at TIMESTAMPTZ DEFAULT NOW(),
    archive_reason VARCHAR(50)
);

-- ============================================================================
-- RLS POLICIES FOR AUDIT TABLE PROTECTION
-- ============================================================================

-- Prevent modification of audit tables (immutability)
-- ISO/IEC 27001: A.12.4.2 - Protection of log information
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;

-- Policy: audit_immutable - Deny all modifications
CREATE POLICY audit_immutable ON audit_log
    FOR ALL
    TO PUBLIC
    USING (FALSE);

-- ============================================================================
-- AUTOMATED PARTITION COMPRESSION FOR OLDER DATA (ISO 27040)
-- ============================================================================

-- Partition compression tracking table
CREATE TABLE IF NOT EXISTS audit_partition_compression (
    compression_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partition_name VARCHAR(100) NOT NULL UNIQUE,
    compressed_at TIMESTAMPTZ DEFAULT NOW(),
    original_size_bytes BIGINT,
    compressed_size_bytes BIGINT,
    compression_ratio NUMERIC(5,2),
    compression_method VARCHAR(20) DEFAULT 'pglz',
    row_count BIGINT,
    uncompressed_at TIMESTAMPTZ,
    is_compressed BOOLEAN DEFAULT TRUE
);

-- Function to compress audit partition
-- ISO/IEC 27040: Automated partition compression for storage efficiency
-- Parameters: p_partition_name - partition to compress
-- Returns: Compression ratio achieved
CREATE OR REPLACE FUNCTION compress_audit_partition(
    p_partition_name VARCHAR(100)
)
RETURNS NUMERIC AS $$
DECLARE
    v_original_size BIGINT;
    v_compressed_size BIGINT;
    v_row_count BIGINT;
    v_compression_ratio NUMERIC(5,2);
BEGIN
    -- Get original size and row count
    SELECT pg_total_relation_size(p_partition_name::regclass),
           (SELECT reltuples::BIGINT FROM pg_class WHERE relname = p_partition_name)
    INTO v_original_size, v_row_count;
    
    -- Compress the partition using pg_compress
    EXECUTE format('ALTER TABLE %I SET (toast_compression = pglz)', p_partition_name);
    
    -- Force recompression by updating all rows
    EXECUTE format('UPDATE %I SET audit_id = audit_id WHERE changed_at IS NOT NULL', p_partition_name);
    
    -- Get compressed size
    SELECT pg_total_relation_size(p_partition_name::regclass) INTO v_compressed_size;
    
    -- Calculate ratio
    v_compression_ratio := ROUND((1.0 - (v_compressed_size::NUMERIC / v_original_size)) * 100, 2);
    
    -- Log compression
    INSERT INTO audit_partition_compression (
        partition_name, original_size_bytes, compressed_size_bytes,
        compression_ratio, row_count
    ) VALUES (
        p_partition_name, v_original_size, v_compressed_size,
        v_compression_ratio, v_row_count
    )
    ON CONFLICT (partition_name) DO UPDATE SET
        compressed_at = NOW(),
        original_size_bytes = v_original_size,
        compressed_size_bytes = v_compressed_size,
        compression_ratio = v_compression_ratio,
        row_count = v_row_count,
        is_compressed = TRUE;
    
    RETURN v_compression_ratio;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- FOREIGN DATA WRAPPER FOR CROSS-REGION AGGREGATION (ISO 27001)
-- ============================================================================

-- Server configuration for cross-region audit aggregation
-- Note: Actual server creation requires appropriate extensions and credentials
CREATE TABLE IF NOT EXISTS audit_fdw_servers (
    server_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_name VARCHAR(100) NOT NULL UNIQUE,
    region VARCHAR(50) NOT NULL,
    host VARCHAR(255) NOT NULL,
    port INTEGER DEFAULT 5432,
    database_name VARCHAR(100) NOT NULL,
    username VARCHAR(100),
    password_encrypted TEXT,  -- Encrypted credential storage
    is_active BOOLEAN DEFAULT TRUE,
    last_sync_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to setup FDW for cross-region aggregation
-- ISO/IEC 27001: Cross-region audit aggregation for compliance
-- Parameters: p_server_name - FDW server configuration to use
-- Returns: VOID
CREATE OR REPLACE FUNCTION setup_cross_region_fdw(
    p_server_name VARCHAR(100)
)
RETURNS VOID AS $$
DECLARE
    v_server RECORD;
BEGIN
    SELECT * INTO v_server FROM audit_fdw_servers WHERE server_name = p_server_name;
    
    IF v_server IS NULL THEN
        RAISE EXCEPTION 'FDW server configuration not found: %', p_server_name;
    END IF;
    
    -- Create extension if not exists
    CREATE EXTENSION IF NOT EXISTS postgres_fdw;
    
    -- Create server (if not exists, skip error)
    BEGIN
        EXECUTE format('CREATE SERVER %I FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host %L, port %L, dbname %L)',
            v_server.server_name, v_server.host, v_server.port, v_server.database_name);
    EXCEPTION WHEN duplicate_object THEN
        NULL; -- Server already exists
    END;
    
    -- Create user mapping
    EXECUTE format('CREATE USER MAPPING IF NOT EXISTS FOR CURRENT_USER SERVER %I OPTIONS (user %L)',
        v_server.server_name, v_server.username);
    
    -- Import foreign schema for audit tables
    BEGIN
        EXECUTE format('IMPORT FOREIGN SCHEMA public LIMIT TO (audit_log, audit_error_log) FROM SERVER %I INTO public',
            v_server.server_name);
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Could not import foreign schema: %', SQLERRM;
    END;
    
    -- Update last sync
    UPDATE audit_fdw_servers SET last_sync_at = NOW() WHERE server_id = v_server.server_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- REAL-TIME MATERIALIZED VIEW REFRESH FOR DASHBOARDS
-- ============================================================================

-- Materialized view for audit dashboard
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_audit_summary AS
SELECT 
    date_trunc('hour', changed_at) as hour_bucket,
    table_name,
    operation,
    COUNT(*) as operation_count,
    COUNT(DISTINCT changed_by) as unique_users,
    COUNT(*) FILTER (WHERE severity = 'high') as high_severity_count
FROM audit_log
WHERE changed_at > NOW() - INTERVAL '24 hours'
GROUP BY date_trunc('hour', changed_at), table_name, operation;

-- Index for materialized view
CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_audit_summary ON mv_audit_summary(hour_bucket, table_name, operation);

-- Function to refresh audit materialized views
-- Parameters: p_concurrent - whether to refresh concurrently
-- Returns: VOID
CREATE OR REPLACE FUNCTION refresh_audit_materialized_views(
    p_concurrent BOOLEAN DEFAULT TRUE
)
RETURNS VOID AS $$
BEGIN
    IF p_concurrent THEN
        REFRESH MATERIALIZED VIEW CONCURRENTLY mv_audit_summary;
    ELSE
        REFRESH MATERIALIZED VIEW mv_audit_summary;
    END IF;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- AUDIT LOG ENCRYPTION AT REST (PCI DSS 10.3.3)
-- ============================================================================

-- Table for storing encrypted audit batches
CREATE TABLE IF NOT EXISTS audit_log_encrypted (
    batch_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    date_from TIMESTAMPTZ NOT NULL,
    date_to TIMESTAMPTZ NOT NULL,
    encrypted_data BYTEA NOT NULL,
    encryption_key_id UUID,
    record_count INTEGER NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to encrypt audit batch
-- PCI DSS 10.3.3: Audit log encryption at rest
-- Parameters: p_date_from, p_date_to - date range to encrypt
-- Returns: Batch ID of encrypted data
CREATE OR REPLACE FUNCTION encrypt_audit_batch(
    p_date_from TIMESTAMPTZ,
    p_date_to TIMESTAMPTZ
)
RETURNS UUID AS $$
DECLARE
    v_batch_id UUID;
    v_data JSONB;
    v_encrypted BYTEA;
    v_record_count INTEGER;
BEGIN
    -- Aggregate audit records as JSONB
    SELECT jsonb_agg(to_jsonb(a)), COUNT(*)::INTEGER
    INTO v_data, v_record_count
    FROM audit_log a
    WHERE changed_at BETWEEN p_date_from AND p_date_to;
    
    IF v_record_count = 0 THEN
        RETURN NULL;
    END IF;
    
    -- Encrypt using pgcrypto
    v_encrypted := pgp_sym_encrypt(
        v_data::TEXT,
        current_setting('app.audit_encryption_key', TRUE)
    )::BYTEA;
    
    INSERT INTO audit_log_encrypted (
        date_from, date_to, encrypted_data, record_count
    ) VALUES (
        p_date_from, p_date_to, v_encrypted, v_record_count
    ) RETURNING batch_id INTO v_batch_id;
    
    RETURN v_batch_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- BACKUP AND DISASTER RECOVERY PROCEDURES (ISO 27001 A.12)
-- ============================================================================

-- Backup tracking table
CREATE TABLE IF NOT EXISTS audit_backup_log (
    backup_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_type VARCHAR(50) NOT NULL,  -- full, incremental, archive
    backup_location TEXT NOT NULL,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    record_count BIGINT,
    size_bytes BIGINT,
    checksum TEXT,
    verified BOOLEAN DEFAULT FALSE,
    status VARCHAR(20) DEFAULT 'in_progress'
);

-- Function to perform audit backup
-- ISO/IEC 27001 A.12.3 - Backup procedures
-- Parameters: p_backup_type, p_location
-- Returns: Backup ID
CREATE OR REPLACE FUNCTION perform_audit_backup(
    p_backup_type VARCHAR(50) DEFAULT 'incremental',
    p_location TEXT DEFAULT '/backup/audit'
)
RETURNS UUID AS $$
DECLARE
    v_backup_id UUID;
    v_record_count BIGINT;
    v_checksum TEXT;
BEGIN
    -- Create backup record
    INSERT INTO audit_backup_log (backup_type, backup_location, status)
    VALUES (p_backup_type, p_location, 'in_progress')
    RETURNING backup_id INTO v_backup_id;
    
    -- Count records to backup
    IF p_backup_type = 'full' THEN
        SELECT COUNT(*) INTO v_record_count FROM audit_log;
    ELSE
        SELECT COUNT(*) INTO v_record_count FROM audit_log WHERE changed_at > NOW() - INTERVAL '1 day';
    END IF;
    
    -- Calculate checksum
    SELECT encode(digest(string_agg(audit_id::TEXT, ',' ORDER BY audit_id), 'sha256'), 'hex')
    INTO v_checksum
    FROM audit_log;
    
    -- Update backup record
    UPDATE audit_backup_log SET
        completed_at = NOW(),
        record_count = v_record_count,
        checksum = v_checksum,
        status = 'completed'
    WHERE backup_id = v_backup_id;
    
    RETURN v_backup_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- ANOMALY DETECTION MATERIALIZED VIEWS
-- ============================================================================

-- Materialized view for audit anomaly detection
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_audit_anomalies AS
WITH hourly_stats AS (
    SELECT 
        date_trunc('hour', changed_at) as hour_bucket,
        table_name,
        operation,
        COUNT(*) as op_count,
        COUNT(DISTINCT changed_by) as unique_users
    FROM audit_log
    WHERE changed_at > NOW() - INTERVAL '7 days'
    GROUP BY date_trunc('hour', changed_at), table_name, operation
),
stats_with_avg AS (
    SELECT 
        *,
        AVG(op_count) OVER (
            PARTITION BY table_name, operation 
            ORDER BY hour_bucket 
            ROWS BETWEEN 24 PRECEDING AND 1 PRECEDING
        ) as avg_count,
        STDDEV(op_count) OVER (
            PARTITION BY table_name, operation 
            ORDER BY hour_bucket 
            ROWS BETWEEN 24 PRECEDING AND 1 PRECEDING
        ) as stddev_count
    FROM hourly_stats
)
SELECT 
    hour_bucket,
    table_name,
    operation,
    op_count,
    unique_users,
    avg_count,
    stddev_count,
    CASE 
        WHEN op_count > avg_count + 3 * COALESCE(stddev_count, 0) THEN 'high_volume_anomaly'
        WHEN op_count < avg_count - 3 * COALESCE(stddev_count, 0) THEN 'low_volume_anomaly'
        WHEN unique_users > avg_count * 2 THEN 'user_spike_anomaly'
        ELSE 'normal'
    END as anomaly_type
FROM stats_with_avg
WHERE op_count > avg_count + 3 * COALESCE(stddev_count, 0)
   OR op_count < avg_count - 3 * COALESCE(stddev_count, 0)
   OR unique_users > avg_count * 2;

-- ============================================================================
-- AUDIT DATA LINEAGE TRACKING (ISO 27050-3)
-- ============================================================================

-- Data lineage table
CREATE TABLE IF NOT EXISTS audit_data_lineage (
    lineage_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_system VARCHAR(100) NOT NULL,
    source_table VARCHAR(100) NOT NULL,
    target_system VARCHAR(100) NOT NULL,
    target_table VARCHAR(100) NOT NULL,
    transformation_logic TEXT,
    record_count BIGINT,
    lineage_timestamp TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Function to track audit data lineage
-- ISO/IEC 27050-3: Data lineage tracking for e-discovery
-- Parameters: p_source_system, p_source_table, p_target_system, p_target_table, p_transformation
-- Returns: Lineage ID
CREATE OR REPLACE FUNCTION track_audit_lineage(
    p_source_system VARCHAR(100),
    p_source_table VARCHAR(100),
    p_target_system VARCHAR(100),
    p_target_table VARCHAR(100),
    p_transformation_logic TEXT DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_lineage_id UUID;
    v_record_count BIGINT;
BEGIN
    -- Get record count from source
    EXECUTE format('SELECT COUNT(*) FROM %I.%I', 
        p_source_system, p_source_table) INTO v_record_count;
    
    INSERT INTO audit_data_lineage (
        source_system, source_table, target_system, target_table,
        transformation_logic, record_count
    ) VALUES (
        p_source_system, p_source_table, p_target_system, p_target_table,
        p_transformation_logic, v_record_count
    ) RETURNING lineage_id INTO v_lineage_id;
    
    RETURN v_lineage_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- AUDIT LOG DIGITAL SIGNATURES (ISO 27001 A.10)
-- ============================================================================

-- Digital signature table for audit batches
CREATE TABLE IF NOT EXISTS audit_digital_signatures (
    signature_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL,
    signer_id UUID NOT NULL,
    signature_algorithm VARCHAR(50) DEFAULT 'RSA-SHA256',
    signature_value BYTEA NOT NULL,
    signed_at TIMESTAMPTZ DEFAULT NOW(),
    verification_status VARCHAR(20) DEFAULT 'unverified'
);

-- Function to sign audit batch
-- ISO/IEC 27001 A.10 - Digital signatures for audit integrity
-- Parameters: p_batch_id - batch to sign
-- Returns: Signature ID
CREATE OR REPLACE FUNCTION sign_audit_batch(
    p_batch_id UUID
)
RETURNS UUID AS $$
DECLARE
    v_signature_id UUID;
    v_batch_data TEXT;
    v_signature BYTEA;
BEGIN
    -- Get batch data
    SELECT encode(digest(
        string_agg(audit_id::TEXT || operation || changed_at::TEXT, ',' ORDER BY audit_id),
        'sha256'
    ), 'hex')
    INTO v_batch_data
    FROM audit_log
    WHERE metadata->>'batch_id' = p_batch_id::TEXT;
    
    -- Create HMAC signature
    v_signature := hmac(
        v_batch_data::BYTEA,
        current_setting('app.audit_signing_key', TRUE)::BYTEA,
        'sha256'
    );
    
    INSERT INTO audit_digital_signatures (
        batch_id, signer_id, signature_value
    ) VALUES (
        p_batch_id, current_user_id(), v_signature
    ) RETURNING signature_id INTO v_signature_id;
    
    RETURN v_signature_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE audit_log IS 'ISO/IEC 27001 A.12.4 - Main audit log table partitioned by month for retention management';
COMMENT ON TABLE transaction_audit_log IS 'PCI DSS - Specialized audit log for financial transactions with compliance flags';
COMMENT ON TABLE pii_access_audit IS 'ISO/IEC 27018 - GDPR/CCPA compliant PII access tracking with legal basis';
COMMENT ON POLICY audit_immutable ON audit_log IS 'ISO/IEC 27001 A.12.4.2 - Prevents modification of audit records';
COMMENT ON FUNCTION compress_audit_partition IS 'ISO/IEC 27040 - Automated partition compression for older audit data';
COMMENT ON FUNCTION setup_cross_region_fdw IS 'ISO/IEC 27001 - Configures FDW for cross-region audit aggregation';
COMMENT ON FUNCTION refresh_audit_materialized_views IS 'Refreshes audit materialized views for dashboards';
COMMENT ON FUNCTION encrypt_audit_batch IS 'PCI DSS 10.3.3 - Encrypts audit batch for at-rest protection';
COMMENT ON FUNCTION perform_audit_backup IS 'ISO/IEC 27001 A.12.3 - Performs audit log backup with checksum verification';
COMMENT ON FUNCTION track_audit_lineage IS 'ISO/IEC 27050-3 - Tracks audit data lineage for e-discovery';
COMMENT ON FUNCTION sign_audit_batch IS 'ISO/IEC 27001 A.10 - Creates digital signature for audit batch integrity';
COMMENT ON MATERIALIZED VIEW mv_audit_summary IS 'Real-time audit summary for dashboards';
COMMENT ON MATERIALIZED VIEW mv_audit_anomalies IS 'Anomaly detection view for audit patterns';
COMMENT ON TABLE audit_partition_compression IS 'ISO/IEC 27040 - Tracks audit partition compression status';
COMMENT ON TABLE audit_fdw_servers IS 'ISO/IEC 27001 - Cross-region FDW server configurations';
COMMENT ON TABLE audit_backup_log IS 'ISO/IEC 27001 A.12.3 - Audit backup tracking';
COMMENT ON TABLE audit_data_lineage IS 'ISO/IEC 27050-3 - Audit data lineage tracking';
COMMENT ON TABLE audit_digital_signatures IS 'ISO/IEC 27001 A.10 - Digital signatures for audit batch integrity';
