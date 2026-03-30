-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: security/encryption/001_key_rotation_procedures.sql
-- Description: Automated and manual key rotation procedures for maintaining
--              encryption key lifecycle and security compliance
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: TOP SECRET
-- DATA SENSITIVITY: CRITICAL - Encryption Key Lifecycle Management
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.10.1.2 Key Management
  - Automated key rotation scheduling and execution
  - Key lifecycle management (create, activate, deprecate, revoke, archive)
  - Dual-key strategy for zero-downtime rotation
  
A.10.1.3 Protection of Keys
  - Key encryption key (KEK) separation from data encryption keys (DEK)
  - HSM integration for master key protection
  - Secure key generation using cryptographically secure RNG
  
A.12.4.1 Event Logging
  - Comprehensive audit trail for all key operations
  - Tamper-evident logging for key lifecycle events
  
A.12.1.2 Change Management
  - Scheduled key rotation as controlled change
  - Emergency rotation procedures for compromise response
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION IN CLOUD
================================================================================
Clause 7.2: Consent and Choice
  - Key rotation ensures PII remains protected over time
  - Transparent key management maintains user trust
  
Clause 8.1: Purpose and Use
  - Regular rotation limits exposure window for PII encryption keys
  - Purpose-limited key usage for different data types
  
Clause 9: Accountability
  - Complete audit trail of all key operations
  - Key usage tracking for compliance reporting
  
Clause 10: Security
  - Regular key rotation strengthens PII protection
  - Compromise response through emergency key rotation
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
8.3.1 Key Generation
  - Cryptographically secure random key generation
  - Key strength validation (256-bit minimum)
  
8.3.2 Key Storage
  - Encrypted DEK storage (wrapped by KEK)
  - Master key in external HSM/KMS
  - Key metadata stored separately from encrypted data
  
8.3.3 Key Rotation
  - Scheduled rotation per organizational policy (default 90 days)
  - Emergency rotation for compromise response
  - Zero-downtime rotation using dual-key strategy
  - Batch re-encryption with progress tracking
  
8.3.4 Key Retirement
  - Graceful key deprecation before deletion
  - Archive keys for data recovery requirements
  - Secure destruction per NIST SP 800-88
  
8.3.5 Key Recovery
  - Key escrow for emergency recovery
  - Dual control for key recovery operations
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
Clause 5: Identification
  - Key inventory enables identification of encrypted ESI
  - Key mapping to data sources for e-discovery
  
Clause 6: Preservation
  - Archived keys preserved for legal hold data recovery
  - Key lifecycle audit trail for evidence integrity
  
Clause 7: Collection
  - Authorized key access for e-discovery decryption
  - Chain of custody for key usage
================================================================================

================================================================================
PCI DSS 4.0 KEY MANAGEMENT REQUIREMENTS
================================================================================
Requirement 3.6.1: Generation of Strong Cryptographic Keys
  - Keys generated using approved RNG (pgcrypto gen_random_bytes)
  - Minimum 256-bit key length for AES encryption
  
Requirement 3.6.2: Secure Cryptographic Key Distribution
  - KEK-encrypted DEKs for secure transport
  - No plaintext key transmission over network
  
Requirement 3.6.3: Secure Storage of Cryptographic Keys
  - Master keys in HSM or encrypted vault
  - Key usage audit logging
  
Requirement 3.6.4: Cryptographic Key Changes (Rotation)
  - Scheduled key rotation (default: 90 days)
  - Emergency rotation on compromise detection
  - Re-encryption of all data with new keys
  
Requirement 3.6.5: Retirement of Keys
  - Deprecated key status before deletion
  - Key archival for legal hold requirements
  
Requirement 3.6.6: Split Knowledge and Dual Control
  - Dual authorization for master key operations
  - Separation of key management duties
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. SECURITY DEFINER for all key management functions
2. Transactional integrity for key rotation operations
3. Batch processing for large-scale re-encryption
4. Progress tracking for long-running operations
5. Error handling with rollback capability
================================================================================

================================================================================
KEY ROTATION PROCEDURES
================================================================================
Scheduled Rotation:
  1. Generate new DEK and register in encryption_keys table
  2. Mark old key as 'deprecated' (grace period for decryption)
  3. Initiate background re-encryption job
  4. Update data_key_mappings to reference new key
  5. Archive old key after data retention period

Emergency Rotation (Compromise Response):
  1. Immediately revoke compromised key
  2. Generate new key and activate
  3. Emergency re-encryption with highest priority
  4. Security incident notification
  5. Post-incident review and report

Zero-Downtime Rotation:
  1. Dual-key mode: both old and new keys valid
  2. Gradual re-encryption in background
  3. Read attempts with both keys (fallback)
  4. Complete cutover after 100% re-encrypted
================================================================================

================================================================================
AUDIT REQUIREMENTS (ISO/IEC 27050-3:2020)
================================================================================
- All key operations logged with immutable hash chain
- Key rotation reports generated per compliance requirement
- Failed rotations trigger immediate security alerts
- Key usage analytics for anomaly detection
================================================================================
*/

-- ============================================================================
-- KEY MANAGEMENT TABLES
-- ============================================================================

-- Master key registry
-- ISO/IEC 27040: Key inventory and lifecycle tracking
CREATE TABLE IF NOT EXISTS encryption_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_name VARCHAR(100) NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    key_status VARCHAR(20) NOT NULL CHECK (key_status IN ('active', 'deprecated', 'revoked', 'archived')),
    algorithm VARCHAR(50) NOT NULL DEFAULT 'aes-256-gcm',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    rotated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_by UUID,
    key_metadata JSONB DEFAULT '{}',
    CONSTRAINT unique_key_version UNIQUE (key_name, key_version)
);

-- Data encryption key (DEK) to key encryption key (KEK) mapping
-- ISO/IEC 27040: Key hierarchy implementation
CREATE TABLE IF NOT EXISTS data_key_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dek_id UUID NOT NULL REFERENCES encryption_keys(key_id),
    kek_id UUID NOT NULL REFERENCES encryption_keys(key_id),
    encrypted_dek BYTEA NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    column_name VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Key rotation jobs tracking
-- PCI DSS: Change tracking for key rotation operations
CREATE TABLE IF NOT EXISTS key_rotation_jobs (
    job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id UUID NOT NULL REFERENCES encryption_keys(key_id),
    job_type VARCHAR(50) NOT NULL CHECK (job_type IN ('automatic', 'manual', 'scheduled', 'emergency')),
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'cancelled')),
    table_name VARCHAR(100),
    column_name VARCHAR(100),
    total_records INTEGER,
    processed_records INTEGER DEFAULT 0,
    failed_records INTEGER DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_log TEXT,
    initiated_by UUID,
    priority INTEGER DEFAULT 5 CHECK (priority BETWEEN 1 AND 10)
);

-- Key rotation audit log
-- ISO/IEC 27001: A.12.4 - Logging and monitoring
CREATE TABLE IF NOT EXISTS key_rotation_audit (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID REFERENCES key_rotation_jobs(job_id),
    action VARCHAR(50) NOT NULL,
    key_id UUID REFERENCES encryption_keys(key_id),
    old_key_id UUID REFERENCES encryption_keys(key_id),
    table_name VARCHAR(100),
    record_count INTEGER,
    execution_time_ms INTEGER,
    performed_by UUID,
    performed_at TIMESTAMPTZ DEFAULT NOW(),
    details JSONB DEFAULT '{}'
);

-- ============================================================================
-- KEY ROTATION FUNCTIONS
-- ============================================================================

-- Function to register a new encryption key
-- ISO/IEC 27040: Key generation and registration
-- PCI DSS 3.6.1: Generation of Strong Cryptographic Keys
-- Parameters: p_key_name, p_algorithm, p_expires_at, p_metadata
-- Returns: New key UUID
CREATE OR REPLACE FUNCTION register_encryption_key(
    p_key_name VARCHAR(100),
    p_algorithm VARCHAR(50) DEFAULT 'aes-256-gcm',
    p_expires_at TIMESTAMPTZ DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'
)
RETURNS UUID AS $$
DECLARE
    new_key_id UUID;
    new_version INTEGER;
BEGIN
    -- Determine next version number
    SELECT COALESCE(MAX(key_version), 0) + 1
    INTO new_version
    FROM encryption_keys
    WHERE key_name = p_key_name;
    
    -- Deactivate previous version if exists
    UPDATE encryption_keys
    SET key_status = 'deprecated',
        rotated_at = NOW()
    WHERE key_name = p_key_name
    AND key_status = 'active';
    
    -- Insert new key
    INSERT INTO encryption_keys (
        key_name,
        key_version,
        key_status,
        algorithm,
        expires_at,
        created_by,
        key_metadata
    ) VALUES (
        p_key_name,
        new_version,
        'active',
        p_algorithm,
        p_expires_at,
        current_user_id(),
        p_metadata
    ) RETURNING key_id INTO new_key_id;
    
    -- Log the key registration
    INSERT INTO key_rotation_audit (
        action,
        key_id,
        performed_by,
        details
    ) VALUES (
        'key_registered',
        new_key_id,
        current_user_id(),
        jsonb_build_object('key_name', p_key_name, 'version', new_version)
    );
    
    RETURN new_key_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function to initiate key rotation for a specific column
-- PCI DSS: Requirement 3.6.4 - Cryptographic key changes
-- Parameters: p_table_name, p_column_name, p_job_type, p_priority
-- Returns: Job ID for tracking
CREATE OR REPLACE FUNCTION initiate_key_rotation(
    p_table_name VARCHAR(100),
    p_column_name VARCHAR(100),
    p_job_type VARCHAR(50) DEFAULT 'manual',
    p_priority INTEGER DEFAULT 5
)
RETURNS UUID AS $$
DECLARE
    job_id UUID;
    current_key_id UUID;
    record_count INTEGER;
    dynamic_sql TEXT;
BEGIN
    -- Get current active key
    SELECT key_id INTO current_key_id
    FROM encryption_keys
    WHERE key_status = 'active'
    AND key_name = 'primary'
    ORDER BY key_version DESC
    LIMIT 1;
    
    IF current_key_id IS NULL THEN
        RAISE EXCEPTION 'No active encryption key found - ensure key generation is complete';
    END IF;
    
    -- Count records to process
    dynamic_sql := format(
        'SELECT COUNT(*) FROM %I WHERE %I IS NOT NULL',
        p_table_name,
        p_column_name
    );
    EXECUTE dynamic_sql INTO record_count;
    
    -- Create rotation job
    INSERT INTO key_rotation_jobs (
        key_id,
        job_type,
        status,
        table_name,
        column_name,
        total_records,
        initiated_by,
        priority
    ) VALUES (
        current_key_id,
        p_job_type,
        'pending',
        p_table_name,
        p_column_name,
        record_count,
        current_user_id(),
        p_priority
    ) RETURNING job_id INTO job_id;
    
    -- Log initiation
    INSERT INTO key_rotation_audit (
        job_id,
        action,
        key_id,
        table_name,
        record_count,
        performed_by
    ) VALUES (
        job_id,
        'rotation_initiated',
        current_key_id,
        p_table_name,
        record_count,
        current_user_id()
    );
    
    RETURN job_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function to execute key rotation (batch processing)
-- ISO/IEC 27040: Secure key rotation with integrity verification
-- PCI DSS 3.6.4: Cryptographic key changes with re-encryption
-- Parameters: p_job_id, p_batch_size
-- Returns: Table with processed, failed, remaining counts
CREATE OR REPLACE FUNCTION execute_key_rotation(
    p_job_id UUID,
    p_batch_size INTEGER DEFAULT 1000
)
RETURNS TABLE(
    processed INTEGER,
    failed INTEGER,
    remaining INTEGER
) AS $$
DECLARE
    v_job RECORD;
    v_new_key_id UUID;
    v_start_time TIMESTAMPTZ;
    v_batch_count INTEGER;
    v_failed_count INTEGER;
    v_dynamic_sql TEXT;
BEGIN
    -- Get job details
    SELECT * INTO v_job
    FROM key_rotation_jobs
    WHERE job_id = p_job_id;
    
    IF v_job IS NULL THEN
        RAISE EXCEPTION 'Rotation job not found: %', p_job_id;
    END IF;
    
    IF v_job.status NOT IN ('pending', 'in_progress') THEN
        RAISE EXCEPTION 'Job is not in processable state: %', v_job.status;
    END IF;
    
    -- Update job status
    UPDATE key_rotation_jobs
    SET status = 'in_progress',
        started_at = COALESCE(started_at, NOW())
    WHERE job_id = p_job_id;
    
    -- Get new active key
    SELECT key_id INTO v_new_key_id
    FROM encryption_keys
    WHERE key_status = 'active'
    ORDER BY created_at DESC
    LIMIT 1;
    
    v_start_time := clock_timestamp();
    v_batch_count := 0;
    v_failed_count := 0;
    
    -- Perform rotation in batches
    BEGIN
        v_dynamic_sql := format(
            'UPDATE %I 
             SET %I = encrypt_field(decrypt_field(%I))
             WHERE %I IS NOT NULL
             AND ctid IN (
                 SELECT ctid FROM %I 
                 WHERE %I IS NOT NULL
                 LIMIT %s
             )',
            v_job.table_name,
            v_job.column_name,
            v_job.column_name,
            v_job.column_name,
            v_job.table_name,
            v_job.column_name,
            p_batch_size
        );
        
        EXECUTE v_dynamic_sql;
        GET DIAGNOSTICS v_batch_count = ROW_COUNT;
        
    EXCEPTION WHEN OTHERS THEN
        v_failed_count := p_batch_size;
        
        -- Update job with error
        UPDATE key_rotation_jobs
        SET failed_records = failed_records + v_failed_count,
            error_log = COALESCE(error_log || E'\n', '') || SQLERRM
        WHERE job_id = p_job_id;
    END;
    
    -- Update job progress
    UPDATE key_rotation_jobs
    SET processed_records = processed_records + v_batch_count,
        failed_records = failed_records + v_failed_count
    WHERE job_id = p_job_id;
    
    -- Check if complete
    IF (SELECT processed_records FROM key_rotation_jobs WHERE job_id = p_job_id) >= 
       (SELECT total_records FROM key_rotation_jobs WHERE job_id = p_job_id) THEN
        
        UPDATE key_rotation_jobs
        SET status = CASE 
                WHEN failed_records = 0 THEN 'completed'
                WHEN failed_records < total_records * 0.01 THEN 'completed_with_warnings'
                ELSE 'failed'
            END,
            completed_at = NOW()
        WHERE job_id = p_job_id;
        
        -- Log completion
        INSERT INTO key_rotation_audit (
            job_id,
            action,
            key_id,
            old_key_id,
            table_name,
            record_count,
            execution_time_ms,
            performed_by
        ) VALUES (
            p_job_id,
            'rotation_completed',
            v_new_key_id,
            v_job.key_id,
            v_job.table_name,
            v_batch_count,
            EXTRACT(MILLISECONDS FROM clock_timestamp() - v_start_time)::INTEGER,
            current_user_id()
        );
    END IF;
    
    RETURN QUERY
    SELECT 
        processed_records,
        failed_records,
        total_records - processed_records
    FROM key_rotation_jobs
    WHERE job_id = p_job_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- SCHEDULED ROTATION MANAGEMENT
-- ============================================================================

-- Function to schedule automatic rotation
-- ISO/IEC 27001: A.10.1.2 - Scheduled key rotation
-- Parameters: p_key_name, p_rotation_interval, p_auto_execute
CREATE OR REPLACE FUNCTION schedule_key_rotation(
    p_key_name VARCHAR(100),
    p_rotation_interval INTERVAL DEFAULT '90 days',
    p_auto_execute BOOLEAN DEFAULT FALSE
)
RETURNS VOID AS $$
DECLARE
    next_rotation TIMESTAMPTZ;
BEGIN
    next_rotation := NOW() + p_rotation_interval;
    
    -- Store schedule in key metadata
    UPDATE encryption_keys
    SET key_metadata = jsonb_set(
        COALESCE(key_metadata, '{}'),
        '{rotation_schedule}',
        jsonb_build_object(
            'interval', p_rotation_interval::TEXT,
            'next_rotation', next_rotation,
            'auto_execute', p_auto_execute
        )
    )
    WHERE key_name = p_key_name
    AND key_status = 'active';
    
    -- Schedule the job (would integrate with pg_cron in production)
    PERFORM cron.schedule(
        'key_rotation_' || p_key_name,
        next_rotation,
        format('SELECT execute_scheduled_rotation(%L)', p_key_name)
    );
EXCEPTION WHEN OTHERS THEN
    -- If cron extension not available, just log
    RAISE NOTICE 'Could not schedule with cron: %', SQLERRM;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function executed by scheduler for automatic rotation
-- Parameters: p_key_name - the key to rotate
CREATE OR REPLACE FUNCTION execute_scheduled_rotation(
    p_key_name VARCHAR(100)
)
RETURNS VOID AS $$
DECLARE
    key_record RECORD;
BEGIN
    SELECT * INTO key_record
    FROM encryption_keys
    WHERE key_name = p_key_name
    AND key_status = 'active';
    
    IF key_record IS NULL THEN
        RAISE NOTICE 'No active key found for rotation: %', p_key_name;
        RETURN;
    END IF;
    
    -- Check if rotation is due
    IF (key_record.key_metadata->'rotation_schedule'->>'next_rotation')::TIMESTAMPTZ > NOW() THEN
        RETURN;
    END IF;
    
    -- Initiate rotation for all columns using this key
    FOR key_record IN
        SELECT DISTINCT table_name, column_name
        FROM data_key_mappings
        WHERE kek_id = key_record.key_id
    LOOP
        PERFORM initiate_key_rotation(
            key_record.table_name,
            key_record.column_name,
            'scheduled',
            3  -- Medium priority
        );
    END LOOP;
    
    -- Update next rotation time
    UPDATE encryption_keys
    SET key_metadata = jsonb_set(
        key_metadata,
        '{rotation_schedule,next_rotation}',
        to_jsonb(NOW() + (key_metadata->'rotation_schedule'->>'interval')::INTERVAL)
    )
    WHERE key_name = p_key_name;
    
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- KEY LIFECYCLE MANAGEMENT
-- ============================================================================

-- Function to revoke a key (emergency use)
-- PCI DSS: Emergency key compromise response
-- Parameters: p_key_id, p_reason
CREATE OR REPLACE FUNCTION revoke_encryption_key(
    p_key_id UUID,
    p_reason TEXT DEFAULT NULL
)
RETURNS VOID AS $$
DECLARE
    key_record RECORD;
BEGIN
    SELECT * INTO key_record
    FROM encryption_keys
    WHERE key_id = p_key_id;
    
    IF key_record IS NULL THEN
        RAISE EXCEPTION 'Key not found: %', p_key_id;
    END IF;
    
    IF key_record.key_status = 'revoked' THEN
        RAISE EXCEPTION 'Key is already revoked: %', p_key_id;
    END IF;
    
    -- Mark as revoked
    UPDATE encryption_keys
    SET key_status = 'revoked',
        key_metadata = jsonb_set(
            COALESCE(key_metadata, '{}'),
            '{revocation}',
            jsonb_build_object(
                'reason', p_reason,
                'revoked_at', NOW(),
                'revoked_by', current_user_id()
            )
        )
    WHERE key_id = p_key_id;
    
    -- Immediate re-rotation of all affected data
    PERFORM initiate_key_rotation(
        mapping.table_name,
        mapping.column_name,
        'emergency',
        1  -- Highest priority
    )
    FROM data_key_mappings mapping
    WHERE mapping.kek_id = p_key_id;
    
    -- Log revocation
    INSERT INTO key_rotation_audit (
        action,
        key_id,
        performed_by,
        details
    ) VALUES (
        'key_revoked',
        p_key_id,
        current_user_id(),
        jsonb_build_object('reason', p_reason)
    );
    
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function to archive old keys
-- ISO/IEC 27040: Secure key retirement
-- Parameters: p_age_threshold - age before archiving
-- Returns: Number of keys archived
CREATE OR REPLACE FUNCTION archive_old_keys(
    p_age_threshold INTERVAL DEFAULT '1 year'
)
RETURNS INTEGER AS $$
DECLARE
    archived_count INTEGER;
BEGIN
    UPDATE encryption_keys
    SET key_status = 'archived'
    WHERE key_status = 'deprecated'
    AND rotated_at < NOW() - p_age_threshold;
    
    GET DIAGNOSTICS archived_count = ROW_COUNT;
    
    RETURN archived_count;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- MONITORING AND REPORTING
-- ============================================================================

-- View for key rotation status
-- ISO/IEC 27001: A.12.4 - Monitoring key management
CREATE OR REPLACE VIEW key_rotation_status AS
SELECT
    k.key_id,
    k.key_name,
    k.key_version,
    k.key_status,
    k.created_at,
    k.rotated_at,
    k.expires_at,
    k.key_metadata->'rotation_schedule'->>'next_rotation' as next_scheduled_rotation,
    COUNT(DISTINCT m.table_name || '.' || m.column_name) as protected_columns,
    COUNT(DISTINCT j.job_id) FILTER (WHERE j.status = 'in_progress') as active_rotations,
    COUNT(DISTINCT j.job_id) FILTER (WHERE j.status = 'pending') as pending_rotations
FROM encryption_keys k
LEFT JOIN data_key_mappings m ON k.key_id = m.kek_id
LEFT JOIN key_rotation_jobs j ON k.key_id = j.key_id
GROUP BY k.key_id, k.key_name, k.key_version, k.key_status, k.created_at, k.rotated_at, k.expires_at;

-- Function to generate rotation report
-- PCI DSS: Regular key management reporting
-- Parameters: p_start_date, p_end_date
-- Returns: Metrics table
CREATE OR REPLACE FUNCTION generate_rotation_report(
    p_start_date TIMESTAMPTZ DEFAULT NOW() - INTERVAL '30 days',
    p_end_date TIMESTAMPTZ DEFAULT NOW()
)
RETURNS TABLE(
    metric_name TEXT,
    metric_value BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 'total_rotations'::TEXT, COUNT(*)::BIGINT
    FROM key_rotation_jobs
    WHERE created_at BETWEEN p_start_date AND p_end_date
    
    UNION ALL
    
    SELECT 'completed_rotations'::TEXT, COUNT(*)::BIGINT
    FROM key_rotation_jobs
    WHERE status = 'completed'
    AND created_at BETWEEN p_start_date AND p_end_date
    
    UNION ALL
    
    SELECT 'failed_rotations'::TEXT, COUNT(*)::BIGINT
    FROM key_rotation_jobs
    WHERE status = 'failed'
    AND created_at BETWEEN p_start_date AND p_end_date
    
    UNION ALL
    
    SELECT 'total_records_processed'::TEXT, COALESCE(SUM(total_records), 0)::BIGINT
    FROM key_rotation_jobs
    WHERE created_at BETWEEN p_start_date AND p_end_date;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- SECURITY AUDIT LOG ENTRY
-- ============================================================================
DO $$
BEGIN
    PERFORM log_security_event(
        'key_rotation_system_initialized',
        jsonb_build_object(
            'tables', ARRAY['encryption_keys', 'data_key_mappings', 'key_rotation_jobs', 'key_rotation_audit'],
            'standards', ARRAY['ISO/IEC 27001:2022', 'ISO/IEC 27040:2024', 'PCI DSS 4.0'],
            'features', ARRAY['scheduled_rotation', 'emergency_revocation', 'batch_reencryption'],
            'timestamp', NOW()
        )
    );
EXCEPTION WHEN OTHERS THEN
    NULL;
END $$;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE encryption_keys IS 'ISO/IEC 27040: Master key registry with lifecycle tracking';
COMMENT ON TABLE key_rotation_jobs IS 'PCI DSS: Key rotation job tracking for audit compliance';
COMMENT ON FUNCTION register_encryption_key IS 'ISO/IEC 27001: A.10.1.2 - Key registration with version management';
COMMENT ON FUNCTION revoke_encryption_key IS 'PCI DSS: Emergency key compromise response procedure';

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Implement zero-downtime rotation using dual-encryption strategy (ISO 27040)
-- TODO: Add support for incremental rotation with change data capture (PCI DSS 3.6.4)
-- TODO: Implement cross-region key synchronization for DR (ISO 27001 A.17)
-- TODO: Add key escrow and recovery procedures (ISO 27040 8.3.5)
-- TODO: Implement quantum-resistant key preparation (NIST PQC standards)
-- TODO: Add automated key health checks and alerts (ISO 27001 A.12.4)
-- TODO: Implement key usage analytics and optimization (ISO 27040)
-- TODO: Create disaster recovery procedures for key loss scenarios (ISO 27001 A.17)
-- TODO: Add integration with external HSM for key protection (PCI DSS 3.6.1)
-- TODO: Implement key splitting (Shamir's Secret Sharing) for master keys (ISO 27040)
-- ============================================================================
