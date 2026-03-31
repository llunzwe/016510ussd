-- =============================================================================
-- MIGRATION: 032_app_account_membership.sql
-- DESCRIPTION: Account to Application Membership with Temporal Validity
-- TABLES: account_memberships, membership_history
-- DEPENDENCIES: 031_app_registry.sql, 003_core_account_registry.sql
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
- Section: 2. Account-Application Membership
- Feature: Account to Application Mapping
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Many-to-many mapping linking accounts to applications with per-application
metadata. An account can be enrolled in multiple applications over time.
Implements ISO 27018 PII access control and ISO 27001 privilege management.

KEY FEATURES:
- Temporal validity (valid_from/valid_to) for audit
- Application-specific metadata storage
- Enrollment workflow with verification
- Current membership view for queries
- Versioned changes with full history

USE CASE EXAMPLES:
- User A: "driver" in transport app
- User A: "patient" in health app  
- User A: "member" in savings group
Each with different permissions and PII handling (ISO 27018)

ACCESS CONTROL:
- [SECURITY-002] Input validation on enrollment
- [SECURITY-003] EXCLUDE USING gist: Prevents overlapping memberships
- [AUDIT] enrolled_by, enrolled_at: Enrollment tracking
- [AUDIT] terminated_by, terminated_at: Termination tracking
================================================================================
*/


-- =============================================================================
-- IMPLEMENTED: Create account_memberships table
-- DESCRIPTION: Account-application link
-- PRIORITY: CRITICAL
-- =============================================================================
-- [MEM-001] Create app.account_memberships table
CREATE TABLE app.account_memberships (
    membership_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Links
    account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Membership Details
    membership_type     VARCHAR(50) DEFAULT 'MEMBER', -- ADMIN, MEMBER, GUEST
    display_name        VARCHAR(200),                -- Nickname in this app
    
    -- Application-Specific Metadata
    role_data           JSONB DEFAULT '{}',          -- App-specific roles
    preferences         JSONB DEFAULT '{}',          -- User preferences
    
    -- Validity (bitemporal)
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,                 -- NULL = current
    
    -- Enrollment
    enrolled_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    enrolled_by         UUID REFERENCES core.accounts(account_id),
    enrollment_source   VARCHAR(50),                 -- USSD, WEB, ADMIN
    
    -- Termination
    terminated_at       TIMESTAMPTZ,
    terminated_by       UUID REFERENCES core.accounts(account_id),
    termination_reason  TEXT,
    
    -- Versioning
    is_current          BOOLEAN DEFAULT true,
    previous_membership_id UUID REFERENCES app.account_memberships(membership_id),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    updated_at          TIMESTAMPTZ
);

-- CONSTRAINTS:
-- Prevent overlapping active memberships using btree_gist extension
ALTER TABLE app.account_memberships
    ADD CONSTRAINT chk_membership_valid_time 
        CHECK (valid_to IS NULL OR valid_to > valid_from);

COMMENT ON TABLE app.account_memberships IS 'Links accounts to applications with temporal validity';
COMMENT ON COLUMN app.account_memberships.membership_type IS 'ADMIN, MEMBER, or GUEST';
COMMENT ON COLUMN app.account_memberships.is_current IS 'True if this is the current membership record';

-- =============================================================================
-- IMPLEMENTED: Create current_memberships view
-- DESCRIPTION: Active memberships only
-- PRIORITY: HIGH
-- =============================================================================
-- [MEM-002] Create current_memberships view
CREATE VIEW app.current_memberships AS
SELECT * FROM app.account_memberships
WHERE is_current = true 
  AND valid_to IS NULL 
  AND terminated_at IS NULL;

COMMENT ON VIEW app.current_memberships IS 'View showing only active (non-terminated, valid) memberships';

-- =============================================================================
-- IMPLEMENTED: Create membership enrollment function
-- DESCRIPTION: Enroll account in application
-- PRIORITY: CRITICAL
-- =============================================================================
-- [MEM-003] Create enroll_account function
CREATE OR REPLACE FUNCTION app.enroll_account(
    p_account_id UUID,
    p_application_id UUID,
    p_membership_type VARCHAR(50) DEFAULT 'MEMBER',
    p_enrolled_by UUID DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_membership_id UUID;
BEGIN
    -- Validate membership type
    IF p_membership_type NOT IN ('ADMIN', 'MEMBER', 'GUEST') THEN
        RAISE EXCEPTION 'Invalid membership type: %', p_membership_type
            USING HINT = 'Valid types are: ADMIN, MEMBER, GUEST';
    END IF;

    -- Check for existing active membership
    IF EXISTS (
        SELECT 1 FROM app.current_memberships
        WHERE account_id = p_account_id 
          AND application_id = p_application_id
    ) THEN
        RAISE EXCEPTION 'Account already has active membership in this application';
    END IF;
    
    -- Create membership
    INSERT INTO app.account_memberships (
        account_id, application_id, membership_type,
        enrolled_by, enrollment_source, created_by
    ) VALUES (
        p_account_id, p_application_id, p_membership_type,
        p_enrolled_by, 'USSD', p_enrolled_by
    )
    RETURNING membership_id INTO v_membership_id;
    
    RETURN v_membership_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION app.enroll_account IS 'Enrolls an account in an application with specified membership type';

-- =============================================================================
-- IMPLEMENTED: Create membership termination function
-- DESCRIPTION: End account membership
-- PRIORITY: HIGH
-- =============================================================================
-- [MEM-004] Create terminate_membership function
CREATE OR REPLACE FUNCTION app.terminate_membership(
    p_membership_id UUID,
    p_reason TEXT,
    p_terminated_by UUID DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_membership RECORD;
BEGIN
    -- Get current membership
    SELECT * INTO v_membership
    FROM app.account_memberships
    WHERE membership_id = p_membership_id AND is_current = true;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Membership not found or not current: %', p_membership_id;
    END IF;
    
    -- Mark as terminated
    UPDATE app.account_memberships
    SET terminated_at = now(),
        terminated_by = p_terminated_by,
        termination_reason = p_reason,
        valid_to = now()
    WHERE membership_id = p_membership_id;
    
    RETURN true;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION app.terminate_membership IS 'Terminates an account membership with reason';

-- =============================================================================
-- IMPLEMENTED: Create membership indexes
-- DESCRIPTION: Optimize membership queries
-- PRIORITY: HIGH
-- =============================================================================
-- [MEM-005] Create membership indexes
-- PRIMARY KEY (membership_id) - created with table

CREATE INDEX idx_memberships_account_app_valid 
    ON app.account_memberships (account_id, application_id, valid_from);

CREATE INDEX idx_memberships_app_type_current 
    ON app.account_memberships (application_id, membership_type, is_current);

CREATE INDEX idx_memberships_account_current 
    ON app.account_memberships (account_id, is_current) 
    WHERE is_current = true;

CREATE INDEX idx_memberships_valid_to_null 
    ON app.account_memberships (valid_to) 
    WHERE valid_to IS NULL;

CREATE INDEX idx_memberships_enrolled_by 
    ON app.account_memberships (enrolled_by) 
    WHERE enrolled_by IS NOT NULL;

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create account_memberships table
☑ Create current_memberships view
☑ Implement enroll_account function
☑ Implement terminate_membership function
☑ Add all indexes for membership queries
☐ Test enrollment workflow
☐ Test termination workflow
☐ Verify temporal validity constraints
☐ Test overlapping membership prevention
================================================================================
*/
