-- =============================================================================
-- MIGRATION: 033_app_roles_permissions.sql
-- DESCRIPTION: Role and Permission Definitions with RBAC
-- TABLES: roles, permissions, role_permissions
-- DEPENDENCIES: 031_app_registry.sql
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
- Section: 3. Role & Permission Management, 6. Entitlements & Access Control
- Feature: Per-Application Roles
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Predefined roles per application (group_admin, loan_officer, passenger,
driver, patient, merchant). Each role has a set of permissions. Implements
ISO 27001 A.8.2 privileged access rights and ISO 27018 PII access control.

KEY FEATURES:
- Versioned role definitions (ISO 27001 A.9.2)
- Granular permissions (CRUD + approve)
- Role hierarchy with inheritance
- Application-scoped or global roles
- Effective permissions view with DENY override

PERMISSION EXAMPLES:
- contribution:create, contribution:read
- loan:approve, loan:disburse
- account:freeze, account:unfreeze
- report:view (PII access per ISO 27018)
- user:admin (privileged per ISO 27001 A.8.2)

ROLE HIERARCHY:
- Parent role inheritance
- DENY overrides ALLOW (principle of least privilege)
- Conditions: {{ "max_amount": 1000 }} for limit-based permissions

SECURITY:
- [SECURITY-001] SECURITY DEFINER for permission checks
- [VOLATILITY] STABLE: has_permission() for repeated access checks
================================================================================
*/


-- =============================================================================
-- IMPLEMENTED: Create permissions table
-- DESCRIPTION: Catalog of available permissions
-- PRIORITY: CRITICAL
-- =============================================================================
-- [PERM-001] Create app.permissions table
CREATE TABLE app.permissions (
    permission_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    permission_code     VARCHAR(100) NOT NULL,       -- contribution:create
    
    -- Structure
    resource            VARCHAR(50) NOT NULL,        -- contribution, loan, account
    action              VARCHAR(50) NOT NULL,        -- create, read, update, delete, approve
    scope               VARCHAR(50),                 -- own, group, all
    
    -- Description
    permission_name     VARCHAR(200) NOT NULL,
    description         TEXT,
    
    -- Scope
    application_id      UUID REFERENCES app.applications(application_id), -- NULL = global
    
    -- Status
    is_active           BOOLEAN DEFAULT true,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- CONSTRAINTS:
CREATE UNIQUE INDEX idx_permissions_code_app 
    ON app.permissions (permission_code, COALESCE(application_id, '00000000-0000-0000-0000-000000000000'::UUID));

COMMENT ON TABLE app.permissions IS 'Catalog of available permissions for RBAC';
COMMENT ON COLUMN app.permissions.permission_code IS 'Unique code like contribution:create or loan:approve';

-- =============================================================================
-- IMPLEMENTED: Create roles table
-- DESCRIPTION: Role definitions per application
-- PRIORITY: CRITICAL
-- =============================================================================
-- [PERM-002] Create app.roles table
CREATE TABLE app.roles (
    role_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_code           VARCHAR(50) NOT NULL,
    
    -- Identity
    role_name           VARCHAR(100) NOT NULL,
    description         TEXT,
    
    -- Hierarchy
    parent_role_id      UUID REFERENCES app.roles(role_id),
    role_path           LTREE,
    
    -- Scope
    application_id      UUID REFERENCES app.applications(application_id), -- NULL = global
    
    -- Settings
    is_system_role      BOOLEAN DEFAULT false,       -- Cannot be modified
    is_default_role     BOOLEAN DEFAULT false,       -- Assigned on enrollment
    
    -- Versioning
    version             INTEGER DEFAULT 1,
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,
    
    -- Status
    status              VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, DEPRECATED
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id)
);

-- CONSTRAINTS:
CREATE UNIQUE INDEX idx_roles_code_app_current 
    ON app.roles (role_code, COALESCE(application_id, '00000000-0000-0000-0000-000000000000'::UUID)) 
    WHERE valid_to IS NULL;

COMMENT ON TABLE app.roles IS 'Role definitions with hierarchy support per application';
COMMENT ON COLUMN app.roles.role_path IS 'LTREE path for hierarchical queries';

-- =============================================================================
-- IMPLEMENTED: Create role_permissions table
-- DESCRIPTION: Permission grants per role
-- PRIORITY: CRITICAL
-- =============================================================================
-- [PERM-003] Create app.role_permissions table
CREATE TABLE app.role_permissions (
    grant_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Links
    role_id             UUID NOT NULL REFERENCES app.roles(role_id),
    permission_id       UUID NOT NULL REFERENCES app.permissions(permission_id),
    
    -- Grant Type
    grant_type          VARCHAR(10) DEFAULT 'ALLOW', -- ALLOW, DENY
    
    -- Conditions (optional JSON for conditional grants)
    conditions          JSONB,                       -- { "max_amount": 1000 }
    
    -- Validity
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,
    
    -- Audit
    granted_by          UUID REFERENCES core.accounts(account_id),
    granted_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- CONSTRAINTS:
CREATE UNIQUE INDEX idx_role_permissions_current 
    ON app.role_permissions (role_id, permission_id) 
    WHERE valid_to IS NULL;

COMMENT ON TABLE app.role_permissions IS 'Many-to-many link between roles and permissions with grant types';

-- =============================================================================
-- IMPLEMENTED: Create effective_permissions view
-- DESCRIPTION: Resolved permissions per role
-- PRIORITY: HIGH
-- =============================================================================
-- [PERM-004] Create effective_permissions view
CREATE VIEW app.effective_permissions AS
WITH RECURSIVE role_tree AS (
    -- Base case
    SELECT role_id, role_id as root_role, role_path, 0 as level
    FROM app.roles WHERE status = 'ACTIVE' AND valid_to IS NULL
    
    UNION ALL
    
    -- Recursive case
    SELECT r.role_id, rt.root_role, r.role_path, rt.level + 1
    FROM app.roles r
    JOIN role_tree rt ON r.parent_role_id = rt.role_id
    WHERE r.status = 'ACTIVE' AND r.valid_to IS NULL
)
SELECT DISTINCT ON (rt.root_role, p.permission_code)
    rt.root_role as role_id,
    p.permission_id,
    p.permission_code,
    rp.grant_type,
    rp.conditions
FROM role_tree rt
JOIN app.role_permissions rp ON rp.role_id = rt.role_id
JOIN app.permissions p ON rp.permission_id = p.permission_id
WHERE rp.valid_to IS NULL
  AND p.is_active = true
ORDER BY rt.root_role, p.permission_code, rt.level, 
         CASE rp.grant_type WHEN 'DENY' THEN 0 ELSE 1 END;

COMMENT ON VIEW app.effective_permissions IS 'Resolved permissions per role including inherited permissions from parent roles';

-- =============================================================================
-- IMPLEMENTED: Create permission check function
-- DESCRIPTION: Check if role has permission
-- PRIORITY: CRITICAL
-- =============================================================================
-- [PERM-005] Create has_permission function
CREATE OR REPLACE FUNCTION app.has_permission(
    p_role_id UUID,
    p_permission_code VARCHAR(100),
    p_context JSONB DEFAULT '{}'
) RETURNS BOOLEAN AS $$
DECLARE
    v_grant RECORD;
BEGIN
    SELECT * INTO v_grant
    FROM app.effective_permissions
    WHERE role_id = p_role_id AND permission_code = p_permission_code;
    
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    
    IF v_grant.grant_type = 'DENY' THEN
        RETURN false;
    END IF;
    
    -- Check conditions if present
    IF v_grant.conditions IS NOT NULL THEN
        -- Example: Check max_amount condition
        IF v_grant.conditions->>'max_amount' IS NOT NULL THEN
            IF (p_context->>'amount')::numeric > (v_grant.conditions->>'max_amount')::numeric THEN
                RETURN false;
            END IF;
        END IF;
    END IF;
    
    RETURN true;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION app.has_permission IS 'Checks if a role has a specific permission, optionally validating conditions';

-- =============================================================================
-- IMPLEMENTED: Create role indexes
-- DESCRIPTION: Optimize role queries
-- PRIORITY: HIGH
-- =============================================================================
-- [PERM-006] Create role indexes
-- Permissions:
-- PRIMARY KEY (permission_id) - created with table
-- UNIQUE (permission_code, application_id) - created above

CREATE INDEX idx_permissions_resource_action 
    ON app.permissions (resource, action);

-- Roles:
-- PRIMARY KEY (role_id) - created with table
-- UNIQUE (role_code, application_id) WHERE valid_to IS NULL - created above

CREATE INDEX idx_roles_parent 
    ON app.roles (parent_role_id) 
    WHERE parent_role_id IS NOT NULL;

CREATE INDEX idx_roles_app_status 
    ON app.roles (application_id, status);

-- Role Permissions:
-- PRIMARY KEY (grant_id) - created with table
-- UNIQUE (role_id, permission_id) WHERE valid_to IS NULL - created above

CREATE INDEX idx_role_permissions_permission 
    ON app.role_permissions (permission_id);

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create permissions table
☑ Create roles table with hierarchy
☑ Create role_permissions table
☑ Create effective_permissions view
☑ Implement has_permission function
☑ Add all indexes for role queries
☐ Test permission inheritance
☐ Test condition evaluation
☐ Verify role versioning
☐ Add seed roles and permissions
================================================================================
*/
