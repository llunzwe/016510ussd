-- =============================================================================
-- MIGRATION: 034_app_user_role_assignments.sql
-- DESCRIPTION: User Role Assignments within Applications
-- TABLES: user_role_assignments, role_assignment_history
-- DEPENDENCIES: 033_app_roles_permissions.sql, 032_app_account_membership.sql
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
- Section: 3. Role & Permission Management
- Feature: User Role Assignments
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Assigns a role to an account within a specific application, with temporal
validity. Current effective roles are derived from latest assignment.
All changes are audited per ISO 27001 A.8.2.

KEY FEATURES:
- Temporal validity (valid_from/valid_to) for audit
- Multiple roles per account supported
- Role expiration with automatic revocation
- Assignment audit trail
- Permission checking with context

ASSIGNMENT VALIDATION:
- [SECURITY-002] Verify membership before role assignment
- [SECURITY-003] EXCLUDE USING gist: Prevent overlapping same-role assignments
- [AUDIT] assigned_by, assigned_at: Assignment tracking
- [AUDIT] revoked_by, revoked_at: Revocation tracking

TEMPORAL CONTROL:
- valid_from: When assignment becomes active
- valid_to: When assignment expires (NULL = indefinite)
- [ERROR-002] CHECK constraint: valid_to > valid_from

PERMISSION CHECKING:
- [VOLATILITY] STABLE: user_has_permission() - role-based check
- Context-aware: amount limits, time restrictions, etc.
================================================================================
*/


-- =============================================================================
-- TODO: Create user_role_assignments table
-- DESCRIPTION: Role assignments with temporal validity
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [RA-001] Create app.user_role_assignments table
-- INSTRUCTIONS:
--   - Versioned role assignments
--   - Supports multiple concurrent roles
--   - Automatic expiration handling
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE app.user_role_assignments (
--       assignment_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Links
--       account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       role_id             UUID NOT NULL REFERENCES app.roles(role_id),
--       membership_id       UUID REFERENCES app.account_memberships(membership_id),
--       
--       -- Validity
--       valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       valid_to            TIMESTAMPTZ,                 -- NULL = indefinite
--       
--       -- Assignment Context
--       assigned_by         UUID NOT NULL REFERENCES core.accounts(account_id),
--       assigned_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
--       assignment_reason   TEXT,
--       assignment_source   VARCHAR(50),                 -- USSD, WEB, ADMIN, API
--       
--       -- Revocation
--       revoked_by          UUID REFERENCES core.accounts(account_id),
--       revoked_at          TIMESTAMPTZ,
--       revocation_reason   TEXT,
--       
--       -- Status
--       is_active           BOOLEAN DEFAULT true,
--       
--       -- Constraints
--       CONSTRAINT valid_time_range CHECK (valid_to IS NULL OR valid_to > valid_from)
--   );
--
-- CONSTRAINTS:
--   - EXCLUDE USING gist (account_id WITH =, application_id WITH =, 
--                         role_id WITH =, valid_during WITH &&)
--   -- Prevents overlapping same-role assignments

-- =============================================================================
-- TODO: Create effective_roles view
-- DESCRIPTION: Currently active role assignments
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [RA-002] Create effective_roles view
-- INSTRUCTIONS:
--   - Filter to currently valid assignments
--   - Join with role details
--
-- VIEW DEFINITION:
--   CREATE VIEW app.effective_roles AS
--   SELECT 
--       ra.*,
--       r.role_code,
--       r.role_name,
--       a.application_code,
--       a.application_name
--   FROM app.user_role_assignments ra
--   JOIN app.roles r ON ra.role_id = r.role_id
--   JOIN app.applications a ON ra.application_id = a.application_id
--   WHERE ra.is_active = true
--     AND ra.valid_from <= now()
--     AND (ra.valid_to IS NULL OR ra.valid_to > now())
--     AND ra.revoked_at IS NULL;

-- =============================================================================
-- TODO: Create assign_role function
-- DESCRIPTION: Assign role to user
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [RA-003] Create assign_role function
-- INSTRUCTIONS:
--   - Validate account has membership in application
--   - Check for conflicting assignments
--   - Create assignment record
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION app.assign_role(
--       p_account_id UUID,
--       p_application_id UUID,
--       p_role_id UUID,
--       p_valid_from TIMESTAMPTZ DEFAULT now(),
--       p_valid_to TIMESTAMPTZ DEFAULT NULL,
--       p_assigned_by UUID DEFAULT NULL,
--       p_reason TEXT DEFAULT NULL
--   ) RETURNS UUID AS $$
--   DECLARE
--       v_assignment_id UUID;
--   BEGIN
--       -- Verify membership
--       IF NOT EXISTS (
--           SELECT 1 FROM app.current_memberships
--           WHERE account_id = p_account_id 
--             AND application_id = p_application_id
--       ) THEN
--           RAISE EXCEPTION 'Account must have active membership in application';
--       END IF;
--       
--       -- Check for conflicting assignment
--       IF EXISTS (
--           SELECT 1 FROM app.user_role_assignments
--           WHERE account_id = p_account_id
--             AND application_id = p_application_id
--             AND role_id = p_role_id
--             AND is_active = true
--             AND (valid_to IS NULL OR valid_to > p_valid_from)
--       ) THEN
--           RAISE EXCEPTION 'Conflicting role assignment exists';
--       END IF;
--       
--       -- Create assignment
--       INSERT INTO app.user_role_assignments (
--           account_id, application_id, role_id,
--           valid_from, valid_to, assigned_by, assignment_reason
--       ) VALUES (
--           p_account_id, p_application_id, p_role_id,
--           p_valid_from, p_valid_to, p_assigned_by, p_reason
--       )
--       RETURNING assignment_id INTO v_assignment_id;
--       
--       RETURN v_assignment_id;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create revoke_role function
-- DESCRIPTION: Revoke role from user
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [RA-004] Create revoke_role function
-- INSTRUCTIONS:
--   - Mark assignment as revoked
--   - Record revocation reason
--   - Update valid_to

-- =============================================================================
-- TODO: Create check_permission function
-- DESCRIPTION: Check user permission in context
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [RA-005] Create user_has_permission function
-- INSTRUCTIONS:
--   - Get all effective roles for user in application
--   - Check if any role grants permission
--   - Consider conditions
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION app.user_has_permission(
--       p_account_id UUID,
--       p_application_id UUID,
--       p_permission_code VARCHAR(100),
--       p_context JSONB DEFAULT '{}'
--   ) RETURNS BOOLEAN AS $$
--   DECLARE
--       v_has_permission BOOLEAN := false;
--       v_role RECORD;
--   BEGIN
--       -- Check each effective role
--       FOR v_role IN 
--           SELECT role_id FROM app.effective_roles
--           WHERE account_id = p_account_id 
--             AND application_id = p_application_id
--       LOOP
--           IF app.has_permission(v_role.role_id, p_permission_code, p_context) THEN
--               RETURN true;
--           END IF;
--       END LOOP;
--       
--       RETURN false;
--   END;
--   $$ LANGUAGE plpgsql STABLE;

-- =============================================================================
-- TODO: Create assignment indexes
-- DESCRIPTION: Optimize assignment queries
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [RA-006] Create assignment indexes
-- INDEX LIST:
--   - PRIMARY KEY (assignment_id)
--   - INDEX on (account_id, application_id, is_active)
--   - INDEX on (role_id, is_active)
--   - INDEX on (valid_from, valid_to)
--   - INDEX on (account_id, application_id, role_id, valid_to)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create user_role_assignments table
□ Create effective_roles view
□ Implement assign_role function
□ Implement revoke_role function
□ Implement user_has_permission function
□ Add all indexes for assignment queries
□ Test role assignment workflow
□ Test permission checking
□ Test temporal validity
□ Verify exclusion constraints
================================================================================
*/
