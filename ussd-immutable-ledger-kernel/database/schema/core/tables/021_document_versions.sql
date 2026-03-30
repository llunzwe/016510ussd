-- =============================================================================
-- USSD KERNEL CORE SCHEMA - DOCUMENT VERSIONS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    021_document_versions.sql
-- SCHEMA:      ussd_core
-- TABLE:       document_versions
-- DESCRIPTION: Version history for documents tracking all revisions
--              and maintaining complete audit trail of changes.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.3 Information backup - Version history preservation
├── A.12.4 Logging and monitoring - Version change tracking
└── A.16.1 Management of information security incidents - Version recovery

ISO/IEC 27040:2024 (Storage Security)
├── Immutable version history
├── Version integrity verification
└── Point-in-time recovery support

Regulatory Compliance
├── Document history: Complete version trail
├── Change tracking: Who changed what when
└── Audit trail: Immutable version log

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. VERSION TRACKING
   - Sequential version numbers
   - Change reason documentation
   - Previous version reference
   - Change summary

2. RETRIEVAL
   - Latest version default
   - Specific version access
   - Version comparison support

3. PURGING
   - Version-specific purging
   - Complete document purging
   - Retention policy enforcement

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

VERSION SECURITY:
- Immutable version records
- Content hash verification
- Access audit logging

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: version_id
- DOCUMENT: document_id + version_number

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- VERSION_CREATED
- VERSION_ACCESSED
- VERSION_PURGED

RETENTION: Aligned with document_registry
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.document_versions (
    -- Primary identifier
    version_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Parent document
    document_id UUID NOT NULL REFERENCES ussd_core.document_registry(document_id),
    version_number INTEGER NOT NULL,
    
    -- Change information
    change_reason TEXT NOT NULL,
    change_summary VARCHAR(500),
    changed_by UUID,
    
    -- Storage (may differ per version)
    storage_bucket VARCHAR(100) NOT NULL,
    storage_key VARCHAR(500) NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    content_hash VARCHAR(64) NOT NULL,
    
    -- Status
    is_current BOOLEAN DEFAULT FALSE,
    is_purged BOOLEAN DEFAULT FALSE,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    purged_at TIMESTAMPTZ,
    
    -- Audit
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    UNIQUE (document_id, version_number)
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
