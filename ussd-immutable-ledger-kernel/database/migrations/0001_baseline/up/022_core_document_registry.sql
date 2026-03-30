-- =============================================================================
-- MIGRATION: 022_core_document_registry.sql
-- DESCRIPTION: Document Registry with Content Integrity Verification
-- TABLES: document_registry, document_categories, document_tags
-- DEPENDENCIES: 003_core_account_registry.sql
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
- Feature: Document Registry
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Stores references to external documents (PDF, images) with content hash for
integrity. Links documents to any entity (user, group, transaction). Implements
ISO 27040 storage security and ISO 27018 PII protection.

KEY FEATURES:
- Content hash (SHA-256) for integrity verification (ISO 27040 Section 7)
- Encryption metadata with external KMS integration (ISO 27040 Section 6)
- Retention period tracking for compliance (ISO 27001 A.12.3)
- Legal hold support for litigation (ISO 27018 Clause 8)
- PII classification and tagging (ISO 27018 Annex A)

DOCUMENT TYPES:
- KYC_DOCUMENT: ID, proof of address (PII classification: RESTRICTED)
- CONTRACT: Loan agreements, terms (retention: 7+ years)
- RECEIPT: Transaction receipts (retention: per fiscal policy)
- STATEMENT: Account statements (encryption: REQUIRED per ISO 27040)
- REPORT: Generated reports (access: ROLE_BASED)

SECURITY CLASSIFICATIONS (ISO 27018):
- PUBLIC: No restrictions
- INTERNAL: Organization only
- CONFIDENTIAL: Restricted access
- RESTRICTED: PII - requires encryption and audit trail
================================================================================
*/


-- =============================================================================
-- TODO: Create document_categories table
-- DESCRIPTION: Document classification
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [DOC-001] Create core.document_categories table
-- INSTRUCTIONS:
--   - Define document types and retention policies
--   - Configure encryption requirements
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.document_categories (
--       category_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       category_code       VARCHAR(50) UNIQUE NOT NULL,
--       category_name       VARCHAR(100) NOT NULL,
--       description         TEXT,
--       
--       -- Security
--       requires_encryption BOOLEAN DEFAULT true,
--       pii_classification  VARCHAR(20),                 -- PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
--       
--       -- Retention
--       retention_years     INTEGER NOT NULL,            -- Retention period
--       retention_basis     VARCHAR(50) DEFAULT 'CREATION', -- CREATION, EVENT, TRANSACTION
--       
--       -- Workflow
--       requires_approval   BOOLEAN DEFAULT false,
--       allowed_formats     VARCHAR(20)[],               -- PDF, JPG, PNG
--       max_file_size_mb    INTEGER DEFAULT 10,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create document_registry table
-- DESCRIPTION: Document metadata and references
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [DOC-002] Create core.document_registry table
-- INSTRUCTIONS:
--   - Metadata for stored documents
--   - Links to external storage (S3, etc.)
--   - Content hash for integrity
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.document_registry (
--       document_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       document_reference  VARCHAR(100) UNIQUE NOT NULL,
--       
--       -- Classification
--       category_id         UUID NOT NULL REFERENCES core.document_categories(category_id),
--       document_type       VARCHAR(50) NOT NULL,
--       
--       -- Ownership
--       owner_account_id    UUID REFERENCES core.accounts(account_id),
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Storage
--       storage_provider    VARCHAR(50) NOT NULL,        -- S3, GCS, AZURE
--       storage_bucket      VARCHAR(100) NOT NULL,
--       storage_key         VARCHAR(500) NOT NULL,       -- Path within bucket
--       storage_region      VARCHAR(50),
--       
--       -- File Metadata
--       original_filename   VARCHAR(255),
--       file_size_bytes     BIGINT NOT NULL,
--       mime_type           VARCHAR(100),
--       checksum_sha256     BYTEA NOT NULL,              -- Content hash
--       
--       -- Encryption
--       is_encrypted        BOOLEAN DEFAULT false,
--       encryption_key_id   VARCHAR(255),                -- Reference to KMS
--       encrypted_at        TIMESTAMPTZ,
--       
--       -- Entity Link
--       linked_entity_type  VARCHAR(50),                 -- ACCOUNT, TRANSACTION, etc.
--       linked_entity_id    UUID,
--       
--       -- Retention
--       uploaded_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
--       retention_until     DATE NOT NULL,
--       
--       -- Legal Hold
--       legal_hold          BOOLEAN DEFAULT false,
--       legal_hold_reason   TEXT,
--       legal_hold_set_at   TIMESTAMPTZ,
--       legal_hold_set_by   UUID REFERENCES core.accounts(account_id),
--       
--       -- Status
--       status              VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, ARCHIVED, DELETED
--       
--       -- Audit
--       uploaded_by         UUID REFERENCES core.accounts(account_id),
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create document_tags table
-- DESCRIPTION: Tagging for documents
-- PRIORITY: MEDIUM
-- =============================================================================
-- TODO: [DOC-003] Create core.document_tags table
-- INSTRUCTIONS:
--   - Many-to-many tags for documents
--   - Supports search and filtering
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.document_tags (
--       document_id         UUID NOT NULL REFERENCES core.document_registry(document_id),
--       tag                 VARCHAR(50) NOT NULL,
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       PRIMARY KEY (document_id, tag)
--   );

-- =============================================================================
-- TODO: Create document upload function
-- DESCRIPTION: Register new document
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [DOC-004] Create register_document function
-- INSTRUCTIONS:
--   - Validate file format
--   - Calculate retention date
--   - Generate storage key
--   - Compute checksum
--   - Return upload URL
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.register_document(
--       p_category_id UUID,
--       p_owner_account_id UUID,
--       p_filename VARCHAR(255),
--       p_file_size BIGINT,
--       p_mime_type VARCHAR(100),
--       p_linked_entity_type VARCHAR(50),
--       p_linked_entity_id UUID
--   ) RETURNS TABLE (document_id UUID, upload_url TEXT) AS $$
--   DECLARE
--       v_doc_id UUID;
--       v_category RECORD;
--       v_retention_years INTEGER;
--   BEGIN
--       -- Get category
--       SELECT * INTO v_category FROM core.document_categories WHERE category_id = p_category_id;
--       
--       -- Generate document ID and reference
--       v_doc_id := gen_random_uuid();
--       
--       -- Calculate retention
--       v_retention_years := v_category.retention_years;
--       
--       -- Insert record
--       INSERT INTO core.document_registry (
--           document_id, document_reference, category_id, document_type,
--           owner_account_id, storage_provider, storage_bucket, storage_key,
--           original_filename, file_size_bytes, mime_type,
--           retention_until, linked_entity_type, linked_entity_id
--       ) VALUES (
--           v_doc_id,
--           'DOC-' || to_char(now(), 'YYYYMMDD') || '-' || substr(v_doc_id::text, 1, 8),
--           p_category_id,
--           v_category.category_code,
--           p_owner_account_id,
--           'S3',  -- From config
--           'ledger-documents',
--           to_char(now(), 'YYYY/MM/') || v_doc_id::text || '/' || p_filename,
--           p_filename,
--           p_file_size,
--           p_mime_type,
--           CURRENT_DATE + (v_retention_years || ' years')::interval,
--           p_linked_entity_type,
--           p_linked_entity_id
--       );
--       
--       -- Return presigned URL (pseudo-code)
--       RETURN QUERY SELECT v_doc_id, 'https://presigned-url...'::TEXT;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create document verification function
-- DESCRIPTION: Verify document integrity
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [DOC-005] Create verify_document function
-- INSTRUCTIONS:
--   - Retrieve document from storage
--   - Recompute SHA-256 hash
--   - Compare with stored checksum
--   - Return verification result

-- =============================================================================
-- TODO: Create legal hold function
-- DESCRIPTION: Set/remove legal hold
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [DOC-006] Create set_legal_hold function
-- INSTRUCTIONS:
--   - Toggle legal_hold flag
--   - Record reason and operator
--   - Prevent deletion while on hold

-- =============================================================================
-- TODO: Create document indexes
-- DESCRIPTION: Optimize document queries
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [DOC-007] Create document indexes
-- INDEX LIST:
--   -- Registry:
--   - PRIMARY KEY (document_id)
--   - UNIQUE (document_reference)
--   - INDEX on (owner_account_id, category_id)
--   - INDEX on (linked_entity_type, linked_entity_id)
--   - INDEX on (retention_until) WHERE legal_hold = false
--   - INDEX on (status, uploaded_at)
--   -- Tags:
--   - PRIMARY KEY (document_id, tag)
--   - INDEX on (tag)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create document_categories table
□ Create document_registry table
□ Create document_tags table
□ Implement register_document function
□ Implement verify_document function
□ Implement set_legal_hold function
□ Add all indexes for document queries
□ Test document registration
□ Test integrity verification
□ Test legal hold enforcement
================================================================================
*/
