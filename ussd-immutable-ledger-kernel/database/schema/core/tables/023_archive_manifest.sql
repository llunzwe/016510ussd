-- =============================================================================
-- USSD KERNEL CORE SCHEMA - ARCHIVE MANIFEST
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    023_archive_manifest.sql
-- SCHEMA:      ussd_core
-- TABLE:       archive_manifest
-- DESCRIPTION: Manifest of all archived data including cold storage
--              references, retention metadata, and retrieval procedures.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Archive access control
├── A.12.3 Information backup - Archive verification
└── A.18.1 Compliance - Retention policy enforcement

ISO/IEC 27040:2024 (Storage Security)
├── Cold storage encryption: AES-256 at rest
├── Archive integrity: Hash verification
├── Geographic redundancy: Multi-region storage
└── Retrieval auditing: Complete access log

Financial Regulations
├── Retention periods: 7+ years for financial data
├── Retrievability: Guaranteed retrieval within SLA
├── Chain of custody: Archive access tracking
└── Destruction certification: Secure deletion proof

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. ARCHIVE TYPES
   - TRANSACTION_LOG: Historical transactions
   - AUDIT_LOG: Audit records
   - DOCUMENT: Archived documents
   - BACKUP: System backups

2. STORAGE TIERS
   - HOT: Online, immediate access
   - WARM: Nearline, minutes to access
   - COLD: Offline, hours to access
   - GLACIER: Deep archive, days to access

3. VERIFICATION
   - Pre-archive hash verification
   - Post-archive integrity check
   - Periodic integrity audits

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

ARCHIVE SECURITY:
- Encryption at rest
- Access logging
- Retrieval authorization
- Secure deletion

CHAIN OF CUSTODY:
- Archive creation audit
- Access audit trail
- Retrieval authorization chain
- Destruction certification

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: archive_id
- TYPE: archive_type + created_at
- RETRIEVAL: last_accessed_at
- EXPIRY: destruction_due_date

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- ARCHIVE_CREATED
- ARCHIVE_ACCESSED
- ARCHIVE_RESTORED
- ARCHIVE_DESTROYED

RETENTION: Permanent (manifest records)
================================================================================
*/

-- -----------------------------------------------------------------------------
-- CREATE TABLE: archive_manifest
-- -----------------------------------------------------------------------------
CREATE TABLE core.archive_manifest (
    -- Primary identifier
    archive_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    archive_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Archive classification
    archive_type VARCHAR(50) NOT NULL
        CHECK (archive_type IN ('TRANSACTION_LOG', 'AUDIT_LOG', 'DOCUMENT', 'BACKUP', 'LEDGER_SNAPSHOT', 'CONFIGURATION')),
    archive_subtype VARCHAR(50),
    
    -- Date range covered
    data_start_date DATE NOT NULL,
    data_end_date DATE NOT NULL,
    
    -- Source information
    source_table VARCHAR(100),
    source_partition VARCHAR(100),
    record_count BIGINT,
    
    -- Storage
    storage_tier VARCHAR(20) NOT NULL
        CHECK (storage_tier IN ('HOT', 'WARM', 'COLD', 'GLACIER', 'DEEP_ARCHIVE')),
    storage_provider VARCHAR(50) NOT NULL,
    storage_location VARCHAR(500) NOT NULL,
    storage_bucket VARCHAR(100),
    storage_key VARCHAR(500),
    storage_region VARCHAR(50),
    storage_replicas TEXT[],  -- Array of replica locations
    
    -- Content metadata
    total_size_bytes BIGINT NOT NULL CHECK (total_size_bytes > 0),
    compression_algorithm VARCHAR(20),
    compressed_size_bytes BIGINT,
    compression_ratio NUMERIC(5, 2),
    
    -- Integrity
    content_hash VARCHAR(64) NOT NULL,  -- SHA-256 of archive
    hash_algorithm VARCHAR(20) DEFAULT 'SHA-256',
    manifest_hash VARCHAR(64),  -- Hash of manifest file within archive
    
    -- Encryption
    encrypted BOOLEAN DEFAULT TRUE,
    encryption_algorithm VARCHAR(20) DEFAULT 'AES-256-GCM',
    encryption_key_id VARCHAR(100),
    
    -- Retention
    retention_years INTEGER NOT NULL CHECK (retention_years > 0),
    destruction_due_date DATE,
    destroyed_at TIMESTAMPTZ,
    destruction_certificate_id VARCHAR(100),
    destruction_method VARCHAR(50),
    
    -- Access tracking
    access_count INTEGER DEFAULT 0,
    last_accessed_at TIMESTAMPTZ,
    last_accessed_by UUID,
    estimated_retrieval_time_minutes INTEGER,
    
    -- Status
    status VARCHAR(20) DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'RESTORING', 'VERIFIED', 'CORRUPTED', 'DESTROYED')),
    verification_status VARCHAR(20) DEFAULT 'PENDING'
        CHECK (verification_status IN ('PENDING', 'VERIFIED', 'FAILED')),
    last_verified_at TIMESTAMPTZ,
    
    -- Restoration tracking
    restored_count INTEGER DEFAULT 0,
    last_restored_at TIMESTAMPTZ,
    restoration_location VARCHAR(500),
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- -----------------------------------------------------------------------------
-- INDEXES
-- -----------------------------------------------------------------------------
-- Archive type queries
CREATE INDEX idx_archive_manifest_type 
    ON core.archive_manifest(archive_type, created_at);

-- Date range queries
CREATE INDEX idx_archive_manifest_date_range 
    ON core.archive_manifest(data_start_date, data_end_date);

-- Storage tier queries
CREATE INDEX idx_archive_manifest_tier 
    ON core.archive_manifest(storage_tier, status);

-- Destruction scheduling
CREATE INDEX idx_archive_manifest_destruction 
    ON core.archive_manifest(destruction_due_date) 
    WHERE status = 'ACTIVE' AND destruction_due_date IS NOT NULL;

-- Access tracking
CREATE INDEX idx_archive_manifest_access 
    ON core.archive_manifest(last_accessed_at) 
    WHERE last_accessed_at IS NOT NULL;

-- Verification status
CREATE INDEX idx_archive_manifest_verification 
    ON core.archive_manifest(verification_status, last_verified_at);

-- Status monitoring
CREATE INDEX idx_archive_manifest_status 
    ON core.archive_manifest(status, created_at);

-- Source table tracking
CREATE INDEX idx_archive_manifest_source 
    ON core.archive_manifest(source_table, data_start_date);

-- -----------------------------------------------------------------------------
-- IMMUTABILITY TRIGGERS
-- -----------------------------------------------------------------------------
CREATE TRIGGER trg_archive_manifest_prevent_update
    BEFORE UPDATE ON core.archive_manifest
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_archive_manifest_prevent_delete
    BEFORE DELETE ON core.archive_manifest
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- -----------------------------------------------------------------------------
-- HASH COMPUTATION TRIGGER
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION core.compute_archive_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.archive_id::TEXT || 
        NEW.archive_reference || 
        NEW.archive_type ||
        NEW.data_start_date::TEXT ||
        NEW.data_end_date::TEXT ||
        NEW.storage_location ||
        NEW.content_hash ||
        NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_archive_manifest_compute_hash
    BEFORE INSERT ON core.archive_manifest
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_archive_hash();

-- -----------------------------------------------------------------------------
-- HELPER FUNCTIONS
-- -----------------------------------------------------------------------------

-- Function to register a new archive
CREATE OR REPLACE FUNCTION core.register_archive(
    p_archive_type VARCHAR(50),
    p_data_start_date DATE,
    p_data_end_date DATE,
    p_storage_tier VARCHAR(20),
    p_storage_provider VARCHAR(50),
    p_storage_location VARCHAR(500),
    p_total_size_bytes BIGINT,
    p_content_hash VARCHAR(64),
    p_retention_years INTEGER,
    p_created_by UUID,
    p_source_table VARCHAR(100) DEFAULT NULL,
    p_record_count BIGINT DEFAULT NULL,
    p_compression_algorithm VARCHAR(20) DEFAULT NULL,
    p_compressed_size_bytes BIGINT DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_archive_id UUID;
    v_reference VARCHAR(100);
    v_compression_ratio NUMERIC(5, 2);
BEGIN
    -- Calculate compression ratio
    IF p_compressed_size_bytes IS NOT NULL AND p_compressed_size_bytes > 0 THEN
        v_compression_ratio := (1 - (p_compressed_size_bytes::NUMERIC / p_total_size_bytes)) * 100;
    END IF;
    
    -- Generate reference
    v_reference := 'ARC-' || UPPER(p_archive_type) || '-' || TO_CHAR(NOW(), 'YYYYMMDD') || '-' || SUBSTRING(MD5(RANDOM()::TEXT), 1, 6);
    
    INSERT INTO core.archive_manifest (
        archive_reference,
        archive_type,
        source_table,
        data_start_date,
        data_end_date,
        record_count,
        storage_tier,
        storage_provider,
        storage_location,
        total_size_bytes,
        compression_algorithm,
        compressed_size_bytes,
        compression_ratio,
        content_hash,
        retention_years,
        destruction_due_date,
        created_by
    ) VALUES (
        v_reference,
        p_archive_type,
        p_source_table,
        p_data_start_date,
        p_data_end_date,
        p_record_count,
        p_storage_tier,
        p_storage_provider,
        p_storage_location,
        p_total_size_bytes,
        p_compression_algorithm,
        p_compressed_size_bytes,
        v_compression_ratio,
        p_content_hash,
        p_retention_years,
        CURRENT_DATE + INTERVAL '1 year' * p_retention_years,
        p_created_by
    ) RETURNING archive_id INTO v_archive_id;
    
    RETURN v_archive_id;
END;
$$;

-- Function to get archives for destruction
CREATE OR REPLACE FUNCTION core.get_archives_for_destruction(
    p_batch_size INTEGER DEFAULT 100
)
RETURNS TABLE (
    archive_id UUID,
    archive_reference VARCHAR(100),
    archive_type VARCHAR(50),
    destruction_due_date DATE,
    retention_years INTEGER
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        am.archive_id,
        am.archive_reference,
        am.archive_type,
        am.destruction_due_date,
        am.retention_years
    FROM core.archive_manifest am
    WHERE am.status = 'ACTIVE'
      AND am.destruction_due_date IS NOT NULL
      AND am.destruction_due_date <= CURRENT_DATE
    ORDER BY am.destruction_due_date
    LIMIT p_batch_size;
END;
$$;

-- Function to get archive statistics
CREATE OR REPLACE FUNCTION core.get_archive_statistics(
    p_archive_type VARCHAR(50) DEFAULT NULL
)
RETURNS TABLE (
    storage_tier VARCHAR(20),
    archive_count BIGINT,
    total_records BIGINT,
    total_size_bytes BIGINT,
    avg_compression_ratio NUMERIC
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        am.storage_tier,
        COUNT(*) as archive_count,
        COALESCE(SUM(am.record_count), 0) as total_records,
        SUM(am.total_size_bytes) as total_size_bytes,
        AVG(am.compression_ratio)::NUMERIC as avg_compression_ratio
    FROM core.archive_manifest am
    WHERE am.status = 'ACTIVE'
      AND (p_archive_type IS NULL OR am.archive_type = p_archive_type)
    GROUP BY am.storage_tier
    ORDER BY total_size_bytes DESC;
END;
$$;

-- Function to find archives by date range
CREATE OR REPLACE FUNCTION core.find_archives_by_date_range(
    p_start_date DATE,
    p_end_date DATE,
    p_archive_type VARCHAR(50) DEFAULT NULL
)
RETURNS TABLE (
    archive_id UUID,
    archive_reference VARCHAR(100),
    archive_type VARCHAR(50),
    data_start_date DATE,
    data_end_date DATE,
    storage_tier VARCHAR(20),
    record_count BIGINT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        am.archive_id,
        am.archive_reference,
        am.archive_type,
        am.data_start_date,
        am.data_end_date,
        am.storage_tier,
        am.record_count
    FROM core.archive_manifest am
    WHERE am.status = 'ACTIVE'
      AND am.data_start_date <= p_end_date
      AND am.data_end_date >= p_start_date
      AND (p_archive_type IS NULL OR am.archive_type = p_archive_type)
    ORDER BY am.data_start_date;
END;
$$;

-- Function to get storage utilization
CREATE OR REPLACE FUNCTION core.get_storage_utilization()
RETURNS TABLE (
    archive_type VARCHAR(50),
    storage_tier VARCHAR(20),
    archive_count BIGINT,
    total_size_gb NUMERIC,
    compressed_size_gb NUMERIC,
    storage_savings_gb NUMERIC
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        am.archive_type,
        am.storage_tier,
        COUNT(*) as archive_count,
        ROUND(SUM(am.total_size_bytes) / (1024.0 * 1024 * 1024), 2) as total_size_gb,
        ROUND(SUM(COALESCE(am.compressed_size_bytes, am.total_size_bytes)) / (1024.0 * 1024 * 1024), 2) as compressed_size_gb,
        ROUND((SUM(am.total_size_bytes) - SUM(COALESCE(am.compressed_size_bytes, am.total_size_bytes))) / (1024.0 * 1024 * 1024), 2) as storage_savings_gb
    FROM core.archive_manifest am
    WHERE am.status = 'ACTIVE'
    GROUP BY am.archive_type, am.storage_tier
    ORDER BY total_size_gb DESC;
END;
$$;

-- -----------------------------------------------------------------------------
-- COMMENTS
-- -----------------------------------------------------------------------------
COMMENT ON TABLE core.archive_manifest IS 'Manifest of all archived data with cold storage references';
COMMENT ON COLUMN core.archive_manifest.archive_id IS 'Unique identifier for the archive';
COMMENT ON COLUMN core.archive_manifest.storage_tier IS 'Storage tier: HOT, WARM, COLD, GLACIER, DEEP_ARCHIVE';
COMMENT ON COLUMN core.archive_manifest.content_hash IS 'SHA-256 hash of archive content for integrity';
COMMENT ON COLUMN core.archive_manifest.destruction_due_date IS 'Date when archive should be destroyed per retention policy';

-- =============================================================================
-- END OF FILE
-- =============================================================================
