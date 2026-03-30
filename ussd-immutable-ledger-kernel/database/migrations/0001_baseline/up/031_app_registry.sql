-- =============================================================================
-- MIGRATION: 031_app_registry.sql
-- DESCRIPTION: Application (Tenant) Registry with Versioning
-- TABLES: applications, application_versions
-- DEPENDENCIES: 001_create_schemas.sql
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
- Section: 1. Application Registry, 2. Account-Application Membership
- Feature: Application (Tenant) Registry
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Stores metadata for each USSD application (transport, health, e-commerce,
savings group, micro-loan) with unique ID, name, owner, status. Implements
multi-tenancy isolation per ISO 27001 access control.

KEY FEATURES:
- Append-only with versioning (ISO 27001 A.12.4)
- Status lifecycle: active, suspended, archived
- Multi-tenancy isolation with RLS
- Configuration versioning for audit
- Application-specific settings

STATUS LIFECYCLE:
- PENDING: New application, awaiting activation
- ACTIVE: Fully operational (ISO 27001 monitoring applies)
- SUSPENDED: Temporarily disabled (risk mitigation per ISO 31000)
- ARCHIVED: Retired application (retention per ISO 27040)

TENANCY ISOLATION:
- [SECURITY-003] Row-Level Security for application data isolation
- [AUDIT] version, valid_from, valid_to: Temporal versioning
- [AUDIT] superseded_by: Version chain tracking
- Each application's data logically separated
================================================================================
*/


-- =============================================================================
-- TODO: Create applications table
-- DESCRIPTION: Application registry
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [APP-001] Create app.applications table
-- INSTRUCTIONS:
--   - Append-only table
--   - Status changes create new version rows
--   - Links to owner account
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE app.applications (
--       application_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       application_code    VARCHAR(50) UNIQUE NOT NULL,
--       
--       -- Identity
--       application_name    VARCHAR(100) NOT NULL,
--       description         TEXT,
--       
--       -- Ownership
--       owner_account_id    UUID REFERENCES core.accounts(account_id),
--       owner_name          VARCHAR(200),
--       
--       -- Configuration
--       base_currency       VARCHAR(3) DEFAULT 'USD',
--       timezone            VARCHAR(50) DEFAULT 'UTC',
--       default_language    VARCHAR(10) DEFAULT 'en',
--       
--       -- Settings JSON
--       settings            JSONB DEFAULT '{}',
--       
--       -- Status
--       status              VARCHAR(20) NOT NULL DEFAULT 'PENDING',
--                           -- PENDING, ACTIVE, SUSPENDED, ARCHIVED
--       status_reason       TEXT,
--       
--       -- Versioning
--       version             INTEGER NOT NULL DEFAULT 1,
--       previous_version_id UUID REFERENCES app.applications(application_id),
--       is_current          BOOLEAN DEFAULT true,
--       
--       -- Validity
--       valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       valid_to            TIMESTAMPTZ,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id),
--       superseded_by       UUID REFERENCES app.applications(application_id)
--   );
--
-- CONSTRAINTS:
--   - UNIQUE (application_code) WHERE is_current = true
--   - CHECK (status IN ('PENDING', 'ACTIVE', 'SUSPENDED', 'ARCHIVED'))

-- =============================================================================
-- TODO: Create application_versions view
-- DESCRIPTION: Convenience view for current applications
-- PRIORITY: MEDIUM
-- =============================================================================
-- TODO: [APP-002] Create current_applications view
-- INSTRUCTIONS:
--   - Show only current (non-superseded) applications
--
-- VIEW DEFINITION:
--   CREATE VIEW app.current_applications AS
--   SELECT * FROM app.applications
--   WHERE is_current = true AND valid_to IS NULL;

-- =============================================================================
-- TODO: Create application lifecycle function
-- DESCRIPTION: Change application status
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [APP-003] Create change_application_status function
-- INSTRUCTIONS:
--   - Create new version row on status change
--   - Link previous version
--   - Update is_current flags
--   - Record audit
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION app.change_application_status(
--       p_application_id UUID,
--       p_new_status VARCHAR(20),
--       p_reason TEXT,
--       p_changed_by UUID
--   ) RETURNS UUID AS $$
--   DECLARE
--       v_old_app RECORD;
--       v_new_id UUID;
--   BEGIN
--       -- Get current version
--       SELECT * INTO v_old_app 
--       FROM app.applications 
--       WHERE application_id = p_application_id AND is_current = true;
--       
--       -- Create new version
--       INSERT INTO app.applications (
--           application_code, application_name, description,
--           owner_account_id, base_currency, timezone, settings,
--           status, status_reason, version, previous_version_id,
--           is_current, valid_from, created_by
--       ) VALUES (
--           v_old_app.application_code, v_old_app.application_name, v_old_app.description,
--           v_old_app.owner_account_id, v_old_app.base_currency, v_old_app.timezone,
--           v_old_app.settings, p_new_status, p_reason, v_old_app.version + 1,
--           p_application_id, true, now(), p_changed_by
--       )
--       RETURNING application_id INTO v_new_id;
--       
--       -- Mark old version as superseded
--       UPDATE app.applications
--       SET is_current = false, valid_to = now(), superseded_by = v_new_id
--       WHERE application_id = p_application_id;
--       
--       RETURN v_new_id;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create application indexes
-- DESCRIPTION: Optimize application queries
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [APP-004] Create application indexes
-- INDEX LIST:
--   - PRIMARY KEY (application_id)
--   - UNIQUE (application_code) WHERE is_current = true
--   - INDEX on (owner_account_id, is_current)
--   - INDEX on (status, is_current)
--   - INDEX on (valid_from, valid_to)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create app.applications table with versioning
□ Create current_applications view
□ Implement change_application_status function
□ Add all indexes for application queries
□ Test status change workflow
□ Test versioning behavior
□ Verify current application uniqueness
□ Add seed applications
================================================================================
*/
