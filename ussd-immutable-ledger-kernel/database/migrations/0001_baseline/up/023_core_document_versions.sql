-- =============================================================================
-- MIGRATION: 023_core_document_versions.sql
-- DESCRIPTION: Document Version History with Audit Trail
-- TABLES: document_versions, version_diffs
-- DEPENDENCIES: 022_core_document_registry.sql
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
- Section: 10. Document & Evidence Management
- Feature: Document Versions
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Version history of documents (e.g., updated loan contract, revised bylaws).
Tracks changes and allows retrieval of previous versions. Implements ISO 9001
documented information control and ISO 27018 access logging.

KEY FEATURES:
- Version numbering (major.minor) with semantic meaning
- Complete change tracking for audit (ISO 9001 7.5)
- Previous version retrieval with access control
- Version comparison for legal discovery
- Approval workflow for new versions (ISO 31000 risk control)

VERSIONING CONTROLS:
- [AUDIT] created_by, created_at: Version creation tracking
- [AUDIT] approved_by, approved_at: Approval workflow audit
- [RETENTION] version retention tied to document retention policy

APPROVAL WORKFLOW:
- DRAFT -> PENDING -> APPROVED/REJECTED
- Approval requires authorized role (ISO 27001 A.8.2)
- Rejection reason recorded for audit
================================================================================
*/


-- =============================================================================
-- TODO: Create document_versions table
-- DESCRIPTION: Version records for documents
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [VER-001] Create core.document_versions table
-- INSTRUCTIONS:
--   - Stores each version of a document
--   - Links versions in sequence
--   - Tracks approval status
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.document_versions (
--       version_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       document_id         UUID NOT NULL REFERENCES core.document_registry(document_id),
--       
--       -- Version Info
--       version_number      VARCHAR(20) NOT NULL,        -- "1.0", "2.1"
--       version_label       VARCHAR(100),                -- "Initial", "Amended"
--       
--       -- Previous Version
--       previous_version_id UUID REFERENCES core.document_versions(version_id),
--       is_major_version    BOOLEAN DEFAULT false,
--       
--       -- Change Description
--       change_summary      TEXT NOT NULL,
--       change_details      JSONB,                       -- Detailed change log
--       
--       -- Content
--       storage_key         VARCHAR(500) NOT NULL,       -- New version location
--       file_size_bytes     BIGINT,
--       checksum_sha256     BYTEA,
--       
--       -- Approval
--       approval_status     VARCHAR(20) DEFAULT 'DRAFT', -- DRAFT, PENDING, APPROVED, REJECTED
--       approved_by         UUID REFERENCES core.accounts(account_id),
--       approved_at         TIMESTAMPTZ,
--       
--       -- Status
--       is_current          BOOLEAN DEFAULT false,
--       effective_date      DATE,
--       
--       -- Audit
--       created_by          UUID NOT NULL REFERENCES core.accounts(account_id),
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );
--
-- CONSTRAINTS:
--   - UNIQUE (document_id, version_number)
--   - Only one current version per document

-- =============================================================================
-- TODO: Create version current constraint trigger
-- DESCRIPTION: Ensure only one current version
-- PRIORITY: MEDIUM
-- =============================================================================
-- TODO: [VER-002] Create ensure_single_current_version trigger
-- INSTRUCTIONS:
--   - When version marked as current
--   - Unmark previous current version
--   - Update document_registry to point to current

-- =============================================================================
-- TODO: Create version approval function
-- DESCRIPTION: Approve document version
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [VER-003] Create approve_document_version function
-- INSTRUCTIONS:
--   - Update approval status
--   - Set approved_by/approved_at
--   - Optionally mark as current
--   - Validate approver has permission

-- =============================================================================
-- TODO: Create version retrieval function
-- DESCRIPTION: Get document content by version
-- PRIORITY: MEDIUM
-- =============================================================================
-- TODO: [VER-004] Create get_document_version function
-- INSTRUCTIONS:
--   - Return version metadata
--   - Generate download URL
--   - Support "current" or specific version

-- =============================================================================
-- TODO: Create version comparison function
-- DESCRIPTION: Compare two versions
-- PRIORITY: LOW
-- =============================================================================
-- TODO: [VER-005] Create compare_document_versions function
-- INSTRUCTIONS:
--   - Retrieve both versions
--   - Generate diff summary
--   - Return changed sections

-- =============================================================================
-- TODO: Create version indexes
-- DESCRIPTION: Optimize version queries
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [VER-006] Create version indexes
-- INDEX LIST:
--   - PRIMARY KEY (version_id)
--   - UNIQUE (document_id, version_number)
--   - INDEX on (document_id, is_current) WHERE is_current = true
--   - INDEX on (document_id, created_at)
--   - INDEX on (previous_version_id)
--   - INDEX on (approval_status)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create document_versions table
□ Implement single current version constraint
□ Implement approve_document_version function
□ Implement get_document_version function
□ Implement compare_document_versions function
□ Add all indexes for version queries
□ Test version creation
□ Test approval workflow
□ Test current version enforcement
□ Verify version chain integrity
================================================================================
*/
