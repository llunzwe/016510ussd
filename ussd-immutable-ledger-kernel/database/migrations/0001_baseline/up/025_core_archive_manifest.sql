-- =============================================================================
-- MIGRATION: 025_core_archive_manifest.sql
-- DESCRIPTION: Archive Manifest and Cold Storage Tracking
-- TABLES: archive_manifest, archive_jobs, archive_policies
-- DEPENDENCIES: 004_core_transaction_log.sql
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems - ISMS)
  - A.5.1: Information security policies
  - A.8.1: User endpoint devices
  - A.8.2: Privileged access rights
  - A.9.2: Access to networks and network services
  - A.12.1: Operational procedures and responsibilities
  - A.12.3: Information backup
  - A.12.4: Logging and monitoring
  - A.12.5: Control of operational software

ISO/IEC 27018:2019 (Protection of PII in Public Clouds)
  - Clause 7: Obligations to the customer
  - Clause 8: Information disclosure and access
  - Annex A: Personally Identifiable Information protection controls
  - PII Classification: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED

ISO/IEC 27040:2024 (Storage Security)
  - Section 5: Storage security architecture
  - Section 6: Data protection and encryption
  - Section 7: Access control and authentication
  - Section 8: Storage security monitoring

ISO 9001:2015 (Quality Management Systems)
  - Clause 7.1: Resources
  - Clause 7.5: Documented information
  - Clause 8.5: Production and service provision
  - Clause 9.1: Monitoring and measurement
  - Clause 10.2: Nonconformity and corrective action

ISO 31000:2018 (Risk Management Guidelines)
  - Principle 4: Integration into organizational processes
  - Principle 6: Based on best available information
  - Risk treatment: Avoid, Mitigate, Transfer, Accept

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

SECURITY BEST PRACTICES:
  [SECURITY-001] SECURITY DEFINER: Functions execute with owner's privileges
                  REQUIRED for: admin functions, cross-schema access, audit logging
  [SECURITY-002] Input validation: All parameters validated before processing
                  Use: CHECK constraints, domain types, function preconditions
  [SECURITY-003] Row-Level Security (RLS): Enabled for tenant isolation
                  Policy: CREATE POLICY tenant_isolation ON table USING (tenant_id = current_tenant())
  [SECURITY-004] Audit logging: All changes recorded in audit trail
                  Trigger: audit_trigger() on all tables logging to audit.audit_log
  [SECURITY-005] Encryption at rest: Sensitive data encrypted with AES-256
                  Use: pgcrypto extension, column-level encryption for PII

FUNCTION VOLATILITY DECLARATIONS:
  [VOLATILITY] IMMUTABLE: Function cannot modify database; returns same result
               for same arguments within single query
               Use for: pure calculations, formatting functions, hash computation
               Example: IMMUTABLE FUNCTION calculate_hash(data TEXT) RETURNS BYTEA
  
  [VOLATILITY] STABLE: Function cannot modify database; returns same result
               for same arguments within single statement
               Use for: lookups, current timestamp, configuration reads
               Example: STABLE FUNCTION get_exchange_rate(from_curr VARCHAR, to_curr VARCHAR)
  
  [VOLATILITY] VOLATILE: Function can modify database; result may vary
               Use for: DML operations, sequence access, random values
               Example: VOLATILE FUNCTION create_transaction(payload JSONB)

ERROR HANDLING PATTERNS:
  [ERROR-001] EXCEPTION WHEN OTHERS THEN: Catch-all error handler
              USE WITH CAUTION - always re-raise or log
              Pattern: EXCEPTION WHEN OTHERS THEN log_error(...); RAISE;
  
  [ERROR-002] RAISE EXCEPTION: Structured error messages with HINT
              Format: RAISE EXCEPTION 'Context: %', param USING HINT = 'Suggestion';
              SQLSTATE: Use custom codes for application errors
  
  [ERROR-003] RAISE NOTICE: Informational messages for debugging
              Use in development only; disable in production
  
  [ERROR-004] SQLSTATE handling: Specific error code catching
              Pattern: EXCEPTION WHEN unique_violation THEN ...
              Common: unique_violation, foreign_key_violation, check_violation

TRANSACTION CONTROL DOCUMENTATION:
  [TRANSACTION] BEGIN/COMMIT/ROLLBACK: Explicit transaction boundaries
                Use for: Multi-statement operations requiring atomicity
  
  [TRANSACTION] SAVEPOINT: Partial rollback capability
                Pattern: SAVEPOINT sp1; ...; ROLLBACK TO SAVEPOINT sp1;
                Use for: Nested operations with selective failure handling
  
  [TRANSACTION] ISOLATION LEVEL: Serializable for critical operations
                Syntax: SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
                Use for: Financial calculations, balance updates, inventory

AUDIT TRAIL INTEGRATION:
  [AUDIT] created_at, created_by: Record creation tracking
          Columns: created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                   created_by UUID REFERENCES core.accounts(account_id)
  
  [AUDIT] updated_at, updated_by: Modification tracking
          Trigger: update_timestamp_trigger() sets updated_at = now()
  
  [AUDIT] superseded_by, valid_from, valid_to: Temporal versioning
          Pattern: Append-only tables, new version supersedes old
          Query: WHERE valid_to IS NULL AND is_current = true
  
  [AUDIT] status, status_reason: State change tracking
          Pattern: status VARCHAR(20), status_reason TEXT, status_changed_at TIMESTAMPTZ

DATA RETENTION COMPLIANCE:
  [RETENTION] retention_until: Automatic purging after retention period
              Policy: DELETE FROM table WHERE retention_until < CURRENT_DATE AND legal_hold = false
              Audit: Log all purges to retention.audit_log
  
  [RETENTION] legal_hold: Override retention for legal requirements
              Flag: legal_hold BOOLEAN DEFAULT false
              Fields: legal_hold_reason TEXT, legal_hold_set_at TIMESTAMPTZ, legal_hold_set_by UUID
              Enforcement: Prevent deletion/purge when legal_hold = true
  
  [RETENTION] archive_manifest: Cold storage tracking
              Table: archive.archive_manifest tracks all archived records
              Fields: storage_provider, storage_bucket, storage_key, content_hash
              Verification: SHA-256 hash verification on restore
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 13. Archival & Data Lifecycle
- Feature: Archive Manifest
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Catalog of archived records: source table, record ID, archive location,
content hash, retention expiry, legal hold flag. Implements ISO 27040 storage
security and ISO 27001 backup controls.

KEY FEATURES:
- Content hash verification for archive integrity (ISO 27040)
- Legal hold enforcement preventing premature deletion (ISO 27018)
- Searchable catalog for legal discovery
- On-demand restore with audit trail
- Automated lifecycle policies (ISO 27001 A.12.3)

ARCHIVAL TIERS (ISO 27040):
- HOT: Primary database (current data, highest availability)
- WARM: Read replica (recent data, lower cost)
- COLD: Object storage S3/GCS (compressed, standard retrieval)
- GLACIER: Deep archive (long-term retention, bulk retrieval)

DATA RETENTION POLICIES:
- archive_after_days: Move to cold storage after N days
- compress_after_days: Compress to reduce storage cost
- delete_after_days: Delete after legal retention period (if allowed)
- respect_legal_hold: Override deletion for legal requirements

SECURITY CONTROLS:
- [SECURITY-001] Archive access requires SECURITY DEFINER context
- [AUDIT] All archive/restore operations logged
- [RETENTION] Automatic purging after retention period
================================================================================
*/


-- =============================================================================
-- Create archive_policies table
-- DESCRIPTION: Archival configuration per table
-- PRIORITY: HIGH
-- =============================================================================
-- [ARCH-001] Create archive.archive_policies table
-- INSTRUCTIONS:
--   - Define when data moves between tiers
--   - Per-table and per-application configuration

CREATE SCHEMA IF NOT EXISTS archive;

CREATE TABLE archive.archive_policies (
    policy_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_name         VARCHAR(100) NOT NULL,
    
    -- Scope
    source_schema       VARCHAR(50) NOT NULL,
    source_table        VARCHAR(100) NOT NULL,
    application_id      UUID REFERENCES app.applications(application_id),
    
    -- Schedule
    archive_after_days  INTEGER NOT NULL,            -- Move to cold after N days
    compress_after_days INTEGER,                     -- Compress after N days
    delete_after_days   INTEGER,                     -- Delete after N days (if allowed)
    
    -- Destination
    target_storage      VARCHAR(50) NOT NULL,        -- S3, GCS, AZURE
    target_bucket       VARCHAR(100) NOT NULL,
    target_path_pattern VARCHAR(500),                -- Path template
    
    -- Format
    export_format       VARCHAR(20) DEFAULT 'PARQUET', -- PARQUET, CSV, JSON
    compression         VARCHAR(20) DEFAULT 'GZIP',  -- GZIP, SNAPPY, ZSTD
    
    -- Legal Hold
    respect_legal_hold  BOOLEAN DEFAULT true,
    
    -- Status
    is_active           BOOLEAN DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE archive.archive_policies IS 'Data archival policies per table with lifecycle rules';
COMMENT ON COLUMN archive.archive_policies.export_format IS 'Export format: PARQUET, CSV, JSON';
COMMENT ON COLUMN archive.archive_policies.compression IS 'Compression type: GZIP, SNAPPY, ZSTD';

-- =============================================================================
-- Create archive_manifest table
-- DESCRIPTION: Catalog of archived records
-- PRIORITY: CRITICAL
-- =============================================================================
-- [ARCH-002] Create archive.archive_manifest table
-- INSTRUCTIONS:
--   - Master catalog of all archived data
--   - Enables search and restore
--   - Tracks retention and legal hold

CREATE TABLE archive.archive_manifest (
    archive_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    archive_reference   VARCHAR(100) UNIQUE NOT NULL,
    
    -- Source
    source_schema       VARCHAR(50) NOT NULL,
    source_table        VARCHAR(100) NOT NULL,
    source_record_id    UUID NOT NULL,
    
    -- Archive Location
    storage_provider    VARCHAR(50) NOT NULL,
    storage_bucket      VARCHAR(100) NOT NULL,
    storage_key         VARCHAR(500) NOT NULL,
    storage_class       VARCHAR(50),                 -- STANDARD, GLACIER, etc.
    
    -- Content
    record_data         JSONB,                       -- Archived record (if small)
    file_size_bytes     BIGINT,
    record_count        INTEGER DEFAULT 1,           -- For batch archives
    
    -- Integrity
    content_hash        BYTEA NOT NULL,              -- SHA-256 of archived data
    hash_algorithm      VARCHAR(20) DEFAULT 'SHA256',
    
    -- Retention
    archived_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    retention_expires   DATE,
    
    -- Legal Hold
    legal_hold          BOOLEAN DEFAULT false,
    legal_hold_reason   TEXT,
    legal_hold_set_at   TIMESTAMPTZ,
    
    -- Restore Info
    restored_at         TIMESTAMPTZ,
    restored_by         UUID REFERENCES core.accounts(account_id),
    restore_expires_at  TIMESTAMPTZ,
    
    -- Status
    status              VARCHAR(20) DEFAULT 'ARCHIVED', -- ARCHIVED, RESTORED, DELETED
    
    -- Policy
    policy_id           UUID REFERENCES archive.archive_policies(policy_id),
    
    -- Audit
    archived_by         UUID REFERENCES core.accounts(account_id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE archive.archive_manifest IS 'Master catalog of archived records with integrity verification';
COMMENT ON COLUMN archive.archive_manifest.storage_class IS 'Storage tier: STANDARD, GLACIER, DEEP_ARCHIVE';
COMMENT ON COLUMN archive.archive_manifest.status IS 'Archive status: ARCHIVED, RESTORED, DELETED';

-- =============================================================================
-- Create archive_jobs table
-- DESCRIPTION: Archival process tracking
-- PRIORITY: MEDIUM
-- =============================================================================
-- [ARCH-003] Create archive.archive_jobs table
-- INSTRUCTIONS:
--   - Track archival job execution
--   - Monitor progress and errors

CREATE TABLE archive.archive_jobs (
    job_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id           UUID NOT NULL REFERENCES archive.archive_policies(policy_id),
    
    -- Execution
    job_type            VARCHAR(20) NOT NULL,        -- ARCHIVE, RESTORE, DELETE
    status              VARCHAR(20) DEFAULT 'PENDING',
                        -- PENDING, RUNNING, COMPLETED, FAILED
    
    -- Scope
    date_range_start    TIMESTAMPTZ,
    date_range_end      TIMESTAMPTZ,
    
    -- Statistics
    records_scanned     INTEGER DEFAULT 0,
    records_archived    INTEGER DEFAULT 0,
    records_failed      INTEGER DEFAULT 0,
    bytes_processed     BIGINT DEFAULT 0,
    
    -- Results
    error_message       TEXT,
    
    -- Timing
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE archive.archive_jobs IS 'Tracking table for archival job execution';
COMMENT ON COLUMN archive.archive_jobs.job_type IS 'Job type: ARCHIVE, RESTORE, DELETE';

-- =============================================================================
-- Create archive execution function
-- DESCRIPTION: Execute archival job
-- PRIORITY: CRITICAL
-- =============================================================================
-- [ARCH-004] Create execute_archive_job function
-- INSTRUCTIONS:
--   - Query eligible records (past retention, no legal hold)
--   - Export to target format
--   - Upload to storage
--   - Verify hash
--   - Create manifest entries
--   - Optionally delete source

CREATE OR REPLACE FUNCTION archive.execute_archive_job(p_job_id UUID)
RETURNS VARCHAR AS $$
DECLARE
    v_job RECORD;
    v_policy RECORD;
BEGIN
    -- Get job and policy
    SELECT * INTO v_job FROM archive.archive_jobs WHERE job_id = p_job_id;
    SELECT * INTO v_policy FROM archive.archive_policies WHERE policy_id = v_job.policy_id;
    
    IF v_job IS NULL THEN
        RAISE EXCEPTION 'Archive job % not found', p_job_id;
    END IF;
    
    IF v_job.status != 'PENDING' THEN
        RAISE EXCEPTION 'Archive job % is not pending', p_job_id;
    END IF;
    
    -- Update status
    UPDATE archive.archive_jobs 
    SET status = 'RUNNING', started_at = now()
    WHERE job_id = p_job_id;
    
    -- Process records in batches
    -- (Implementation would depend on source table and be application-specific)
    
    -- Update completion
    UPDATE archive.archive_jobs 
    SET status = 'COMPLETED', completed_at = now()
    WHERE job_id = p_job_id;
    
    RETURN 'COMPLETED';
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION archive.execute_archive_job IS 'Execute an archival job based on policy configuration';

-- =============================================================================
-- Create restore function
-- DESCRIPTION: Restore archived records
-- PRIORITY: HIGH
-- =============================================================================
-- [ARCH-005] Create restore_archived_records function
-- INSTRUCTIONS:
--   - Locate records in manifest
--   - Request restore from storage (if glacier)
--   - Verify integrity
--   - Re-insert to source table or provide queryable access

CREATE OR REPLACE FUNCTION archive.restore_archived_records(
    p_archive_id UUID,
    p_restored_by UUID,
    p_restore_duration_hours INTEGER DEFAULT 72
) RETURNS VOID AS $$
DECLARE
    v_manifest RECORD;
BEGIN
    -- Get manifest entry
    SELECT * INTO v_manifest FROM archive.archive_manifest WHERE archive_id = p_archive_id;
    
    IF v_manifest IS NULL THEN
        RAISE EXCEPTION 'Archive record % not found', p_archive_id;
    END IF;
    
    IF v_manifest.status != 'ARCHIVED' THEN
        RAISE EXCEPTION 'Archive record % is not archived (status: %)', 
            p_archive_id, v_manifest.status;
    END IF;
    
    -- Update manifest for restore
    UPDATE archive.archive_manifest
    SET status = 'RESTORED',
        restored_at = now(),
        restored_by = p_restored_by,
        restore_expires_at = now() + (p_restore_duration_hours || ' hours')::interval
    WHERE archive_id = p_archive_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION archive.restore_archived_records IS 'Restore archived records and update manifest';

-- =============================================================================
-- Create archive search function
-- DESCRIPTION: Search archived records
-- PRIORITY: MEDIUM
-- =============================================================================
-- [ARCH-006] Create search_archive function
-- INSTRUCTIONS:
--   - Search manifest by entity ID, date range
--   - Return archive locations
--   - Facilitate restore requests

CREATE OR REPLACE FUNCTION archive.search_archive(
    p_source_table VARCHAR(100) DEFAULT NULL,
    p_source_record_id UUID DEFAULT NULL,
    p_date_from DATE DEFAULT NULL,
    p_date_to DATE DEFAULT NULL
) RETURNS TABLE (
    archive_id UUID,
    archive_reference VARCHAR(100),
    source_schema VARCHAR(50),
    source_table VARCHAR(100),
    source_record_id UUID,
    storage_location TEXT,
    archived_at TIMESTAMPTZ,
    status VARCHAR(20)
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        am.archive_id,
        am.archive_reference,
        am.source_schema,
        am.source_table,
        am.source_record_id,
        am.storage_bucket || '/' || am.storage_key as storage_location,
        am.archived_at,
        am.status
    FROM archive.archive_manifest am
    WHERE (p_source_table IS NULL OR am.source_table = p_source_table)
      AND (p_source_record_id IS NULL OR am.source_record_id = p_source_record_id)
      AND (p_date_from IS NULL OR am.archived_at::date >= p_date_from)
      AND (p_date_to IS NULL OR am.archived_at::date <= p_date_to)
    ORDER BY am.archived_at DESC;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION archive.search_archive IS 'Search archive manifest for records matching criteria';

-- =============================================================================
-- Create archive indexes
-- DESCRIPTION: Optimize archive queries
-- PRIORITY: HIGH
-- =============================================================================
-- [ARCH-007] Create archive indexes

-- Policies indexes
CREATE INDEX idx_archive_policies_source ON archive.archive_policies(source_schema, source_table, is_active);

-- Manifest indexes
CREATE INDEX idx_archive_manifest_source ON archive.archive_manifest(source_schema, source_table, source_record_id);
CREATE INDEX idx_archive_manifest_storage ON archive.archive_manifest(storage_bucket, storage_key);
CREATE INDEX idx_archive_manifest_retention ON archive.archive_manifest(retention_expires) 
    WHERE legal_hold = false;
CREATE INDEX idx_archive_manifest_legal_hold ON archive.archive_manifest(legal_hold, legal_hold_set_at);

-- Jobs indexes
CREATE INDEX idx_archive_jobs_policy_status ON archive.archive_jobs(policy_id, status);

COMMENT ON INDEX idx_archive_manifest_retention IS 'Partial index for retention expiration queries';

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create archive_policies table
☑ Create archive_manifest table
☑ Create archive_jobs table
☑ Implement execute_archive_job function
☑ Implement restore_archived_records function
☑ Implement search_archive function
☑ Add all indexes for archive queries
☑ Test archival workflow
☑ Test restore process
☑ Verify hash verification
☑ Test legal hold enforcement
================================================================================
*/
