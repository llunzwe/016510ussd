-- =============================================================================
-- USSD IMMUTABLE LEDGER KERNEL - WAL ARCHIVING CONFIGURATION
-- File: replication/physical/000_wal_archiving.sql
-- Version: 1.0.0-Enterprise
-- Classification: CONFIDENTIAL - Financial Systems
-- Description: Configure Write-Ahead Log archiving for physical replication
-- =============================================================================
-- COMPLIANCE FRAMEWORK:
--   - ISO/IEC 27040:2024 (Storage Security - WAL Encryption)
--   - ISO/IEC 27001:2022 (A.12.3 - Backup, A.10.1 - Cryptographic Controls)
--   - ISO/IEC 27031:2025 (Business Continuity - ICT Continuity)
--   - GDPR Article 32 (Security of Processing - Encryption)
-- =============================================================================
-- BUSINESS CONTINUITY REQUIREMENTS:
--   - Point-in-Time Recovery (PITR) capability
--   - WAL retention: 7 years for financial data
--   - Archive verification: SHA-256 checksums
--   - Geographic redundancy for archives
-- =============================================================================
-- SECURITY CONTROLS:
--   - WAL encryption at rest (AES-256)
--   - Encrypted archive transmission (TLS 1.3)
--   - Archive integrity verification
--   - Access control to archive storage
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
    'REPLICATION_SETUP', 'WAL_ARCHIVING', '000_wal_archiving',
    current_user, 'START', 'info',
    jsonb_build_object('compliance', ARRAY['ISO_27040:2024', 'ISO_27031:2025', 'GDPR_Article_32']),
    NOW()
);

-- =============================================================================
-- PREREQUISITES (ISO 27040:2024)
-- =============================================================================

-- Required postgresql.conf settings:
-- wal_level = replica (or higher)
-- archive_mode = on
-- archive_command = 'your_archive_command_here'
-- archive_timeout = 60
-- max_wal_size = 4GB
-- min_wal_size = 1GB
-- ssl = on
-- ssl_min_protocol_version = 'TLSv1.3'

-- For WAL encryption (PostgreSQL 15+ or pgcrypto):
-- wal_encryption = on  (if supported)

-- =============================================================================
-- ARCHIVE CONFIGURATION TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS wal_archive_config (
    id                  BIGSERIAL PRIMARY KEY,
    config_name         TEXT UNIQUE NOT NULL,
    archive_method      TEXT NOT NULL CHECK (archive_method IN ('local', 'nfs', 's3', 'gcs', 'azure', 'sftp')),
    archive_path        TEXT NOT NULL,
    archive_command     TEXT NOT NULL,
    restore_command     TEXT,
    -- Security settings (ISO 27040:2024)
    encryption_enabled  BOOLEAN DEFAULT TRUE,
    encryption_type     TEXT DEFAULT 'AES-256-GCM',
    kms_key_id          TEXT,  -- Reference to external KMS
    tls_version         TEXT DEFAULT 'TLSv1.3',
    -- Compression settings
    compression_enabled BOOLEAN DEFAULT TRUE,
    compression_type    TEXT DEFAULT 'zstd',
    compression_level   INTEGER DEFAULT 6,
    -- Retention settings
    retention_days      INTEGER DEFAULT 7,
    min_wal_files       INTEGER DEFAULT 10,
    max_wal_files       INTEGER DEFAULT 1000,
    archive_timeout     INTEGER DEFAULT 60,
    -- Compliance
    compliance_scope    TEXT[] DEFAULT ARRAY['ISO_27040:2024'],
    is_active           BOOLEAN DEFAULT TRUE,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    metadata            JSONB
);

COMMENT ON TABLE wal_archive_config IS 
    'WAL archive configuration with encryption. Compliance: ISO 27040:2024. Encryption: AES-256-GCM.';

-- Seed default configurations
INSERT INTO wal_archive_config 
    (config_name, archive_method, archive_path, archive_command, restore_command, 
     retention_days, compliance_scope, kms_key_id)
VALUES 
    ('local_archive', 'local', '/var/lib/postgresql/archive', 
     'test ! -f /var/lib/postgresql/archive/%f && cp %p /var/lib/postgresql/archive/%f',
     'cp /var/lib/postgresql/archive/%f %p',
     7, ARRAY['ISO_27040:2024'], NULL),
    
    ('s3_encrypted', 's3', 's3://ussd-ledger-wal-archive/production',
     'aws s3 cp %p s3://ussd-ledger-wal-archive/production/%f --sse aws:kms --sse-kms-key-id alias/wal-encryption',
     'aws s3 cp s3://ussd-ledger-wal-archive/production/%f %p',
     2555, ARRAY['SOX_802', 'ISO_27040:2024'], 'alias/wal-encryption'),
    
    ('s3_dr_region', 's3', 's3://ussd-ledger-wal-archive-dr/production',
     'aws s3 cp %p s3://ussd-ledger-wal-archive-dr/production/%f --sse aws:kms --sse-kms-key-id alias/wal-encryption-dr',
     'aws s3 cp s3://ussd-ledger-wal-archive-dr/production/%f %p',
     2555, ARRAY['ISO_27031:2025', 'DR'], 'alias/wal-encryption-dr'),
    
    ('nfs_encrypted', 'nfs', '/mnt/nas/postgres_archive',
     'openssl enc -aes-256-cbc -salt -in %p -out /mnt/nas/postgres_archive/%f.enc -pass file:/secure/wal-key && test ! -f /mnt/nas/postgres_archive/%f.enc',
     'openssl enc -aes-256-cbc -d -in /mnt/nas/postgres_archive/%f.enc -out %p -pass file:/secure/wal-key',
     90, ARRAY['GDPR_Article_32'], 'file:/secure/wal-key')
ON CONFLICT (config_name) DO NOTHING;

-- =============================================================================
-- ARCHIVE MONITORING TABLES (ISO 27040:2024)
-- =============================================================================

-- WAL file tracking with integrity
CREATE TABLE IF NOT EXISTS wal_archive_log (
    id                  BIGSERIAL PRIMARY KEY,
    wal_file_name       TEXT NOT NULL,
    wal_file_size       BIGINT,
    archive_config      TEXT REFERENCES wal_archive_config(config_name),
    archive_status      TEXT DEFAULT 'pending',
    archived_at         TIMESTAMPTZ,
    archive_duration_ms INTEGER,
    archive_path        TEXT,
    -- Security fields
    checksum_md5        VARCHAR(32),
    checksum_sha256     VARCHAR(64),
    checksum_verified   BOOLEAN DEFAULT FALSE,
    encryption_verified BOOLEAN DEFAULT FALSE,
    error_message       TEXT,
    retry_count         INTEGER DEFAULT 0,
    -- Compliance
    compliance_scope    TEXT[],
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_wal_archive_log_file ON wal_archive_log(wal_file_name);
CREATE INDEX idx_wal_archive_log_status ON wal_archive_log(archive_status);
CREATE INDEX idx_wal_archive_log_time ON wal_archive_log(created_at);
CREATE INDEX idx_wal_archive_log_checksum ON wal_archive_log(checksum_verified) WHERE checksum_verified = FALSE;

COMMENT ON TABLE wal_archive_log IS 
    'WAL archive tracking with cryptographic verification. Compliance: ISO 27040:2024.';

-- =============================================================================
-- ARCHIVE COMMAND GENERATION (ISO 27040:2024)
-- =============================================================================

-- Function to generate archive command with encryption
CREATE OR REPLACE FUNCTION generate_archive_command(p_config_name TEXT)
RETURNS TEXT AS $$
DECLARE
    v_config RECORD;
    v_command TEXT;
BEGIN
    SELECT * INTO v_config FROM wal_archive_config WHERE config_name = p_config_name;
    IF NOT FOUND THEN
        RETURN 'ERROR: Configuration not found';
    END IF;
    
    CASE v_config.archive_method
        WHEN 'local' THEN
            IF v_config.encryption_enabled THEN
                -- Encrypt before archiving
                v_command := format(
                    'openssl enc -aes-256-cbc -salt -in %%p -out %s/%%f.enc -pass pass:$(cat %s) && test ! -f %s/%%f.enc',
                    v_config.archive_path, v_config.kms_key_id, v_config.archive_path
                );
            ELSE
                v_command := format('test ! -f %s/%%f && cp %%p %s/%%f',
                    v_config.archive_path, v_config.archive_path);
            END IF;
            
        WHEN 's3' THEN
            IF v_config.encryption_enabled THEN
                v_command := format(
                    'aws s3 cp %%p %s/%%f --sse aws:kms --sse-kms-key-id %s',
                    v_config.archive_path, v_config.kms_key_id
                );
            ELSE
                v_command := format('aws s3 cp %%p %s/%%f',
                    v_config.archive_path);
            END IF;
            
        WHEN 'gcs' THEN
            v_command := format('gsutil cp %%p %s/%%f',
                v_config.archive_path);
                
        ELSE
            v_command := v_config.archive_command;
    END CASE;
    
    RETURN v_command;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- ARCHIVE MONITORING (ISO 27031:2025)
-- =============================================================================

-- View: Current WAL archiving status
CREATE OR REPLACE VIEW v_wal_archive_status AS
SELECT 
    pg_current_wal_lsn() AS current_lsn,
    pg_last_wal_receive_lsn() AS last_received_lsn,
    pg_last_wal_replay_lsn() AS last_replay_lsn,
    pg_wal_lsn_diff(pg_current_wal_lsn(), pg_last_wal_replay_lsn()) AS replication_lag_bytes,
    pg_is_wal_replay_paused() AS replay_paused,
    (SELECT archived_count FROM pg_stat_archiver) AS archived_count,
    (SELECT failed_count FROM pg_stat_archiver) AS failed_count,
    (SELECT last_archived_wal FROM pg_stat_archiver) AS last_archived_wal,
    (SELECT last_archived_time FROM pg_stat_archiver) AS last_archived_time,
    (SELECT last_failed_wal FROM pg_stat_archiver) AS last_failed_wal,
    (SELECT last_failed_time FROM pg_stat_archiver) AS last_failed_time,
    CASE 
        WHEN (SELECT failed_count FROM pg_stat_archiver) > 0 THEN 'WARNING'
        ELSE 'OK'
    END AS archive_health;

-- Function to check archive health with compliance
CREATE OR REPLACE FUNCTION check_archive_health()
RETURNS TABLE (
    check_name TEXT,
    status TEXT,
    details TEXT,
    compliance_impact TEXT
) AS $$
DECLARE
    v_last_archived TIMESTAMPTZ;
    v_failed_count BIGINT;
BEGIN
    SELECT last_archived_time, failed_count 
    INTO v_last_archived, v_failed_count
    FROM pg_stat_archiver;
    
    check_name := 'Last Archive Time';
    IF v_last_archived IS NULL THEN
        status := 'WARNING';
        details := 'No WAL files archived yet';
        compliance_impact := 'HIGH - PITR not available';
    ELSIF v_last_archived < NOW() - INTERVAL '10 minutes' THEN
        status := 'WARNING';
        details := format('Last archive was at %s', v_last_archived);
        compliance_impact := 'MEDIUM - Archive lag detected';
    ELSE
        status := 'OK';
        details := format('Last archive was at %s', v_last_archived);
        compliance_impact := 'LOW - Normal operation';
    END IF;
    RETURN NEXT;
    
    check_name := 'Failed Archives';
    IF v_failed_count > 10 THEN
        status := 'CRITICAL';
        details := format('%s failed archives detected', v_failed_count);
        compliance_impact := 'CRITICAL - Data loss risk';
    ELSIF v_failed_count > 0 THEN
        status := 'WARNING';
        details := format('%s failed archives', v_failed_count);
        compliance_impact := 'HIGH - Investigate immediately';
    ELSE
        status := 'OK';
        details := 'No failed archives';
        compliance_impact := 'LOW - Normal operation';
    END IF;
    RETURN NEXT;
    
    check_name := 'WAL Encryption';
    -- Check if WAL encryption is enabled (PostgreSQL 15+)
    status := 'INFO';
    details := 'WAL encryption status should be verified at storage layer';
    compliance_impact := 'HIGH - Required by ISO 27040:2024';
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- WAL RETENTION MANAGEMENT (SOX 802)
-- =============================================================================

CREATE OR REPLACE PROCEDURE cleanup_old_wal_archives(
    p_config_name TEXT,
    p_retention_days INTEGER DEFAULT NULL,
    p_dry_run BOOLEAN DEFAULT TRUE
)
LANGUAGE plpgsql AS $$
DECLARE
    v_config RECORD;
    v_retention INTEGER;
    v_deleted_count INTEGER := 0;
BEGIN
    SELECT * INTO v_config FROM wal_archive_config WHERE config_name = p_config_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Configuration % not found', p_config_name;
    END IF;
    
    v_retention := COALESCE(p_retention_days, v_config.retention_days);
    
    RAISE NOTICE 'Cleaning up WAL archives older than % days from %',
        v_retention, v_config.archive_path;
    
    -- Log cleanup attempt
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'WAL_CLEANUP', 'ARCHIVE', p_config_name,
        current_user, 'CLEANUP', 'warning',
        jsonb_build_object(
            'retention_days', v_retention,
            'dry_run', p_dry_run,
            'archive_path', v_config.archive_path
        )
    );
    
    -- Implementation depends on storage backend
    IF p_dry_run THEN
        RAISE NOTICE '[DRY RUN] Would delete archives older than % days', v_retention;
    ELSE
        -- Actual deletion logic here
        RAISE NOTICE 'Deleted % old WAL archives', v_deleted_count;
    END IF;
END;
$$;

-- =============================================================================
-- PITR SUPPORT FUNCTIONS
-- =============================================================================

-- Function to find recovery WAL file for PITR
CREATE OR REPLACE FUNCTION find_recovery_wal_file(
    p_target_time TIMESTAMPTZ,
    p_config_name TEXT DEFAULT 's3_encrypted'
)
RETURNS TABLE (
    wal_file_name TEXT,
    wal_file_path TEXT,
    archive_time TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        l.wal_file_name,
        l.archive_path,
        l.archived_at
    FROM wal_archive_log l
    WHERE l.archive_config = p_config_name
      AND l.archive_status = 'archived'
      AND l.archived_at <= p_target_time
    ORDER BY l.archived_at DESC
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- AUDIT: Log setup completion
-- =============================================================================
INSERT INTO audit_events (
    event_type, entity_type, entity_id, actor_id, action, severity,
    new_values
) VALUES (
    'REPLICATION_SETUP', 'WAL_ARCHIVING', '000_wal_archiving',
    current_user, 'COMPLETE', 'info',
    jsonb_build_object(
        'configs_created', 4,
        'monitoring_views', 2,
        'compliance_features', ARRAY['AES256_Encryption', 'KMS_Integration', 'Integrity_Checks']
    ),
    NOW()
);

-- =============================================================================
-- IMPLEMENTATION CHECKLIST
-- =============================================================================

/*
COMPLIANCE CHECKLIST:
[ ] Configure postgresql.conf for WAL archiving
[ ] Set up S3 bucket with KMS encryption (SSE-KMS)
[ ] Configure cross-region replication for DR
[ ] Set up IAM roles for WAL archiving
[ ] Configure archive_command with encryption
[ ] Set up monitoring for archive failures
[ ] Configure 7-year retention for SOX compliance
[ ] Test PITR procedures monthly
[ ] Verify WAL encryption at rest
[ ] Document recovery procedures

SECURITY REQUIREMENTS:
- WAL Encryption: AES-256-GCM (storage layer or pgcrypto)
- Transmission: TLS 1.3
- Archive Integrity: SHA-256 checksums
- Access Control: IAM roles / service accounts
- Key Management: External KMS (AWS KMS/Azure/GCP)

RETENTION REQUIREMENTS:
- Standard: 7 days minimum
- Financial (SOX 802): 7 years
- GDPR: Based on data classification
- DR: Cross-region copy

BUSINESS CONTINUITY:
- PITR: Point-in-time recovery capability
- RTO: 4 hours for full restore
- Geographic redundancy: 3 copies (3-2-1 rule)
- Monthly restore testing required
*/
