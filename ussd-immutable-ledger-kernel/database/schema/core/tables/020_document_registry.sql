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
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.document_registry (
    -- Primary identifier
    document_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    document_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Document classification
    document_type VARCHAR(50) NOT NULL
        CHECK (document_type IN ('KYC_ID', 'KYC_ADDRESS', 'CONTRACT', 'STATEMENT', 'REPORT', 'CORRESPONDENCE')),
    document_subtype VARCHAR(50),
    
    -- Owner
    owner_account_id UUID REFERENCES ussd_core.account_registry(account_id),
    application_id UUID,
    
    -- Storage
    storage_provider VARCHAR(50) NOT NULL,
    storage_bucket VARCHAR(100) NOT NULL,
    storage_key VARCHAR(500) NOT NULL,
    storage_region VARCHAR(50),
    
    -- Content metadata
    file_name VARCHAR(255) NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    content_hash VARCHAR(64) NOT NULL,  -- SHA-256 of content
    
    -- Encryption
    encryption_algorithm VARCHAR(20) DEFAULT 'AES-256-GCM',
    encryption_key_id VARCHAR(100),  -- KMS key reference
    
    -- Versioning
    version_number INTEGER DEFAULT 1,
    previous_version_id UUID,
    is_latest_version BOOLEAN DEFAULT TRUE,
    
    -- Status
    status VARCHAR(20) DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'ARCHIVED', 'PURGED')),
    
    -- Retention
    retention_period_months INTEGER,
    retention_until DATE,
    purged_at TIMESTAMPTZ,
    
    -- Audit
    uploaded_by UUID,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    record_hash VARCHAR(64) NOT NULL
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
