-- =============================================================================
-- USSD KERNEL CORE SCHEMA - DOCUMENT REGISTRY
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    020_document_registry.sql
-- SCHEMA:      ussd_core
-- TABLE:       document_registry
-- DESCRIPTION: Registry of all documents including KYC documents, contracts,
--              and regulatory filings with metadata and storage references.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.5.9 Information and other associated assets - Document inventory
├── A.8.1 User endpoint devices - Document upload verification
└── A.8.11 Data masking - Sensitive document handling

ISO/IEC 27040:2024 (Storage Security)
├── Document encryption: At-rest encryption
├── Hash verification: Content integrity
├── Immutable storage: WORM for regulatory documents
└── Retention: Automated retention management

GDPR Compliance
├── Data minimization: Document collection limits
├── Retention limits: Automatic purging
├── Subject access: Document retrieval for data subjects
└── Right to erasure: Document deletion workflows

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. DOCUMENT TYPES
   - KYC_ID: Identity document
   - KYC_ADDRESS: Address proof
   - CONTRACT: Legal contract
   - STATEMENT: Account statement
   - REPORT: Regulatory report
   - CORRESPONDENCE: Customer communication

2. STORAGE
   - External object storage (S3, MinIO, etc.)
   - Encrypted at rest
   - Hash verification on retrieval
   - Geo-redundant storage

3. VERSIONING
   - Document versions tracked
   - Immutable version history
   - Latest version default

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

DOCUMENT SECURITY:
- Encryption at rest (AES-256)
- Encryption in transit (TLS 1.3)
- Access logging
- Watermarking for sensitive docs

ACCESS CONTROL:
- Role-based document access
- Document classification levels
- Time-limited access grants

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: document_id
- OWNER: owner_account_id + document_type
- TYPE: document_type + created_at
- EXPIRY: retention_until (for purging)

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- DOCUMENT_REGISTERED
- DOCUMENT_ACCESSED
- DOCUMENT_DOWNLOADED
- DOCUMENT_PURGED

RETENTION: Per document type (7 years for regulatory, 5 years for KYC)
================================================================================
*/

-- -----------------------------------------------------------------------------
-- CREATE TABLE: document_registry
-- -----------------------------------------------------------------------------
CREATE TABLE core.document_registry (
    -- Primary identifier
    document_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Document classification
    document_type VARCHAR(50) NOT NULL
        CHECK (document_type IN ('KYC_ID', 'KYC_ADDRESS', 'KYC_INCOME', 'CONTRACT', 'STATEMENT', 'REPORT', 'CORRESPONDENCE', 'RECEIPT', 'OTHER')),
    document_subtype VARCHAR(50),
    
    -- Owner
    owner_account_id UUID REFERENCES core.account_registry(account_id) ON DELETE RESTRICT,
    application_id UUID,
    
    -- Storage
    storage_provider VARCHAR(50) NOT NULL,
    storage_bucket VARCHAR(100) NOT NULL,
    storage_key VARCHAR(500) NOT NULL,
    storage_region VARCHAR(50),
    storage_version_id VARCHAR(100),
    
    -- Content metadata
    file_name VARCHAR(255) NOT NULL,
    file_extension VARCHAR(20),
    file_size_bytes BIGINT NOT NULL CHECK (file_size_bytes > 0),
    mime_type VARCHAR(100) NOT NULL,
    content_hash VARCHAR(64) NOT NULL,  -- SHA-256 of content
    
    -- Encryption
    encryption_algorithm VARCHAR(20) DEFAULT 'AES-256-GCM',
    encryption_key_id VARCHAR(100),  -- KMS key reference
    
    -- Versioning
    version_number INTEGER DEFAULT 1 CHECK (version_number > 0),
    previous_version_id UUID,
    is_latest_version BOOLEAN DEFAULT TRUE,
    
    -- Status
    status VARCHAR(20) DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'ARCHIVED', 'PENDING_REVIEW', 'REJECTED', 'PURGED')),
    
    -- Classification
    classification VARCHAR(20) DEFAULT 'INTERNAL'
        CHECK (classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED')),
    
    -- Retention
    retention_period_months INTEGER,
    retention_until DATE,
    legal_hold BOOLEAN DEFAULT FALSE,
    legal_hold_reason TEXT,
    purged_at TIMESTAMPTZ,
    purged_by UUID,
    
    -- Access tracking
    access_count INTEGER DEFAULT 0,
    last_accessed_at TIMESTAMPTZ,
    last_accessed_by UUID,
    
    -- Verification
    verified_at TIMESTAMPTZ,
    verified_by UUID,
    verification_status VARCHAR(20)
        CHECK (verification_status IN ('PENDING', 'VERIFIED', 'FAILED')),
    
    -- Audit
    uploaded_by UUID,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- -----------------------------------------------------------------------------
-- INDEXES
-- -----------------------------------------------------------------------------
-- Owner document lookups
CREATE INDEX idx_document_registry_owner_type 
    ON core.document_registry(owner_account_id, document_type) 
    WHERE status = 'ACTIVE';

-- Document type queries
CREATE INDEX idx_document_registry_type_date 
    ON core.document_registry(document_type, uploaded_at);

-- Status monitoring
CREATE INDEX idx_document_registry_status 
    ON core.document_registry(status, uploaded_at);

-- Retention management
CREATE INDEX idx_document_registry_retention 
    ON core.document_registry(retention_until) 
    WHERE retention_until IS NOT NULL AND status != 'PURGED' AND legal_hold = FALSE;

-- Latest version queries
CREATE INDEX idx_document_registry_latest 
    ON core.document_registry(owner_account_id, document_type, version_number) 
    WHERE is_latest_version = TRUE;

-- Content hash lookups (deduplication)
CREATE INDEX idx_document_registry_content_hash 
    ON core.document_registry(content_hash);

-- Application-scoped queries
CREATE INDEX idx_document_registry_application 
    ON core.document_registry(application_id, document_type);

-- -----------------------------------------------------------------------------
-- IMMUTABILITY TRIGGERS
-- -----------------------------------------------------------------------------
CREATE TRIGGER trg_document_registry_prevent_update
    BEFORE UPDATE ON core.document_registry
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_document_registry_prevent_delete
    BEFORE DELETE ON core.document_registry
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- -----------------------------------------------------------------------------
-- HASH COMPUTATION TRIGGER
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION core.compute_document_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.document_id::TEXT || 
        NEW.document_reference || 
        NEW.document_type ||
        COALESCE(NEW.owner_account_id::TEXT, '') ||
        NEW.storage_bucket ||
        NEW.storage_key ||
        NEW.content_hash ||
        NEW.file_name ||
        NEW.uploaded_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_document_registry_compute_hash
    BEFORE INSERT ON core.document_registry
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_document_hash();

-- -----------------------------------------------------------------------------
-- HELPER FUNCTIONS
-- -----------------------------------------------------------------------------

-- Function to register a new document
CREATE OR REPLACE FUNCTION core.register_document(
    p_document_type VARCHAR(50),
    p_owner_account_id UUID,
    p_storage_provider VARCHAR(50),
    p_storage_bucket VARCHAR(100),
    p_storage_key VARCHAR(500),
    p_file_name VARCHAR(255),
    p_file_size_bytes BIGINT,
    p_mime_type VARCHAR(100),
    p_content_hash VARCHAR(64),
    p_uploaded_by UUID,
    p_application_id UUID DEFAULT NULL,
    p_retention_months INTEGER DEFAULT NULL,
    p_classification VARCHAR(20) DEFAULT 'INTERNAL'
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_document_id UUID;
    v_reference VARCHAR(100);
    v_version INTEGER := 1;
    v_previous_version UUID;
BEGIN
    -- Generate reference
    v_reference := 'DOC-' || UPPER(p_document_type) || '-' || TO_CHAR(NOW(), 'YYYYMMDD') || '-' || SUBSTRING(MD5(RANDOM()::TEXT), 1, 6);
    
    -- Check for previous version
    SELECT document_id, version_number 
    INTO v_previous_version, v_version
    FROM core.document_registry
    WHERE owner_account_id = p_owner_account_id 
      AND document_type = p_document_type
      AND is_latest_version = TRUE
      AND status = 'ACTIVE'
    ORDER BY version_number DESC
    LIMIT 1;
    
    IF FOUND THEN
        v_version := v_version + 1;
    END IF;
    
    INSERT INTO core.document_registry (
        document_reference,
        document_type,
        owner_account_id,
        application_id,
        storage_provider,
        storage_bucket,
        storage_key,
        file_name,
        file_size_bytes,
        mime_type,
        content_hash,
        uploaded_by,
        retention_period_months,
        retention_until,
        version_number,
        previous_version_id,
        classification
    ) VALUES (
        v_reference,
        p_document_type,
        p_owner_account_id,
        p_application_id,
        p_storage_provider,
        p_storage_bucket,
        p_storage_key,
        p_file_name,
        p_file_size_bytes,
        p_mime_type,
        p_content_hash,
        p_uploaded_by,
        p_retention_months,
        CASE WHEN p_retention_months IS NOT NULL 
             THEN CURRENT_DATE + INTERVAL '1 month' * p_retention_months 
             ELSE NULL END,
        v_version,
        v_previous_version,
        p_classification
    ) RETURNING document_id INTO v_document_id;
    
    RETURN v_document_id;
END;
$$;

-- Function to get documents for purging
CREATE OR REPLACE FUNCTION core.get_documents_for_purging(
    p_batch_size INTEGER DEFAULT 1000
)
RETURNS TABLE (
    document_id UUID,
    document_reference VARCHAR(100),
    owner_account_id UUID,
    document_type VARCHAR(50),
    retention_until DATE
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        dr.document_id,
        dr.document_reference,
        dr.owner_account_id,
        dr.document_type,
        dr.retention_until
    FROM core.document_registry dr
    WHERE dr.status != 'PURGED'
      AND dr.retention_until IS NOT NULL
      AND dr.retention_until <= CURRENT_DATE
      AND dr.legal_hold = FALSE
    ORDER BY dr.retention_until
    LIMIT p_batch_size;
END;
$$;

-- Function to find duplicate documents by content hash
CREATE OR REPLACE FUNCTION core.find_duplicate_documents()
RETURNS TABLE (
    content_hash VARCHAR(64),
    duplicate_count BIGINT,
    document_ids UUID[]
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        dr.content_hash,
        COUNT(*) as duplicate_count,
        ARRAY_AGG(dr.document_id) as document_ids
    FROM core.document_registry dr
    WHERE dr.status = 'ACTIVE'
    GROUP BY dr.content_hash
    HAVING COUNT(*) > 1;
END;
$$;

-- Function to get document statistics
CREATE OR REPLACE FUNCTION core.get_document_statistics(
    p_application_id UUID DEFAULT NULL
)
RETURNS TABLE (
    document_type VARCHAR(50),
    document_count BIGINT,
    total_size_bytes BIGINT,
    avg_size_bytes NUMERIC
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        dr.document_type,
        COUNT(*) as document_count,
        SUM(dr.file_size_bytes) as total_size_bytes,
        AVG(dr.file_size_bytes)::NUMERIC as avg_size_bytes
    FROM core.document_registry dr
    WHERE dr.status = 'ACTIVE'
      AND (p_application_id IS NULL OR dr.application_id = p_application_id)
    GROUP BY dr.document_type
    ORDER BY document_count DESC;
END;
$$;

-- -----------------------------------------------------------------------------
-- COMMENTS
-- -----------------------------------------------------------------------------
COMMENT ON TABLE core.document_registry IS 'Registry of all documents with metadata and storage references';
COMMENT ON COLUMN core.document_registry.document_id IS 'Unique identifier for the document';
COMMENT ON COLUMN core.document_registry.content_hash IS 'SHA-256 hash of document content for integrity verification';
COMMENT ON COLUMN core.document_registry.storage_key IS 'Object storage key/path';
COMMENT ON COLUMN core.document_registry.legal_hold IS 'Prevents purging when TRUE';

-- =============================================================================
-- END OF FILE
-- =============================================================================
