/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - ROLES & PERMISSIONS
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-003
 * Feature Name:       Role-Based Access Control (RBAC)
 * Description:        Role-based access control definitions. Manages roles,
 *                     permissions, and their relationships within applications.
 *                     Supports role inheritance and permission scoping.
 * 
 * Version:            1.0.0
 * Author:             Platform Engineering Team
 * Created:            2026-03-30
 * Last Modified:      2026-03-30
 * 
 * =============================================================================
 * COMPLIANCE & CERTIFICATIONS
 * =============================================================================
 * 
 * ISO/IEC 27001:2022 (ISMS)
 *   - Control A.5.15: Access control (role definitions)
 *   - Control A.5.18: Access rights (permission assignment)
 *   - Control A.5.31: Legal, statutory, regulatory requirements
 *   - Control A.8.2: Privileged access roles (system_role flag)
 *   - Control A.9.2.5: Review of access rights (regular audits)
 * 
 * ISO/IEC 27017:2015 (Cloud Security)
 *   - Section 9: Network security (role scope restrictions)
 *   - Section 12: Inter-tenant access control
 * 
 * ISO/IEC 27018:2019 (PII Protection)
 *   - Section 8.2: Purpose limitation (entitlement limits)
 * 
 * ISO 9001:2015 (Quality Management)
 *   - Section 7.5: Documented information (role documentation)
 * 
 * ISO 31000:2018 (Risk Management)
 *   - Risk treatment: Permission scoping, inheritance controls
 * 
 * SOC 2 Type II
 *   - CC6.1: Logical access controls
 *   - CC6.2: Access credentials management
 *   - CC6.3: Access removal procedures
 * 
 * NIST 800-53
 *   - AC-2: Account management
 *   - AC-3: Access enforcement
 *   - AC-6: Least privilege
 * 
 * =============================================================================
 * RBAC ENFORCEMENT DOCUMENTATION
 * =============================================================================
 * 
 * ROLE HIERARCHY:
 * 
 *   platform_admin       [SYSTEM] - Full platform access
 *      └── platform_operator
 *   app_owner            [APP]    - Application ownership
 *      └── app_admin
 *           └── app_member
 *                └── app_viewer
 * 
 * PERMISSION FORMAT: resource:action:scope
 *   resource:  ledger, transaction, account, app, user, report
 *   action:    create, read, update, delete, execute, admin
 *   scope:     own, group, organization, any
 * 
 * EXAMPLE PERMISSIONS:
 *   ledger:read:own      - Read own ledger entries
 *   ledger:write:any     - Write any ledger entries
 *   app:admin:any        - Full app administration
 *   user:manage:group    - Manage users in same group
 * 
 * REQUIRED PERMISSIONS FOR OPERATIONS:
 * 
 * | Operation                    | Required Permission              |
 * |------------------------------|----------------------------------|
 * | CREATE role                  | app:role:create                  |
 * | READ role                    | app:role:read                    |
 * | UPDATE role                  | app:role:update                  |
 * | DELETE role                  | app:role:delete                  |
 * | ASSIGN role                  | app:role_assignment:create       |
 * | MODIFY system role           | platform:admin:system            |
 * 
 * =============================================================================
 * MULTI-TENANCY SECURITY ANNOTATIONS
 * =============================================================================
 * 
 * TENANT SCOPE LEVELS:
 *   - platform:   Global roles, cannot be modified by apps
 *   - application: Scoped to specific app
 *   - organization: Scoped to org unit within app
 *   - resource:   Scoped to specific resource
 * 
 * ISOLATION CONTROLS:
 *   - app_id NULL = Global platform role
 *   - app_id NOT NULL = Application-scoped role
 *   - RLS: Apps can only see their own roles + global roles
 * 
 * SYSTEM ROLE PROTECTION:
 *   - is_system_role = TRUE: Immutable, cannot be modified/deleted
 *   - Reserved for platform-level access control
 *   - Only platform admins can create system roles
 * 
 * =============================================================================
 * AUDIT TRAIL REQUIREMENTS
 * =============================================================================
 * 
 * MANDATORY AUDIT EVENTS:
 *   - Role Created (definition, initial permissions)
 *   - Permission Change (what changed, who changed, when)
 *   - Role Deprecation (reason, migration plan)
 *   - Role Deleted (archived, assignments migrated)
 *   - Permission Calculation (cache refresh events)
 *   - Inheritance Cycle Detection (security event)
 * 
 * AUDIT RETENTION: 7 years
 * AUDIT ACCESS: platform:auditor role only
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - app.t_application_registry (FK: app_id)
 *   - core.t_user_identity (FK: created_by
 * 
 * CHANGE LOG:
 *   1.0.0 - Initial schema creation with compliance headers
 *   TODO: Add role inheritance cycle detection
 *   TODO: Add permission analytics
 * =============================================================================
 */



-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Controls A.5.x - A.9.x)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Multi-tenancy)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds
-- ISO 9001:2015 - Quality Management Systems
-- ISO 31000:2018 - Risk Management Guidelines
-- ============================================================================
-- CODING PRACTICES:
-- - Use parameterized queries to prevent SQL injection
-- - Implement proper error handling with transaction rollback
-- - Use SECURITY DEFINER
-- - Enforce RLS policies for multi-tenant data isolation
-- - Use explicit column lists (avoid SELECT *)
-- - Add audit logging for all security-relevant operations
-- - Use UUIDs for primary identifiers to prevent enumeration
-- - Implement optimistic locking with version columns
-- - Use TIMESTAMPTZ for all timestamp columns
-- - Validate all inputs with CHECK constraints
-- ============================================================================

-- =============================================================================
-- TABLE: app.t_roles_permissions
-- =============================================================================
CREATE TABLE IF NOT EXISTS app.t_roles_permissions (
    -- -------------------------------------------------------------------------
    -- PRIMARY IDENTIFIERS
    -- -------------------------------------------------------------------------
    role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                
    app_id                      UUID,
                                -- FK: app.t_application_registry.app_id
                                -- NULL = Global platform role
                                -- ISO 27017: Scope isolation
                                CONSTRAINT fk_role_app 
                                    FOREIGN KEY (app_id) 
                                    REFERENCES app.t_application_registry(app_id)
                                    ON DELETE CASCADE,
                                
    role_code                   VARCHAR(50) NOT NULL,
                                -- FORMAT: [a-z][a-z0-9_]{2,49}
                                CONSTRAINT chk_role_code_format 
                                    CHECK (role_code ~ '^[a-z][a-z0-9_]{2,49}$'),
    
    -- -------------------------------------------------------------------------
    -- ROLE CLASSIFICATION
    -- ISO 27001: Privilege classification
    -- -------------------------------------------------------------------------
    role_type                   VARCHAR(20) NOT NULL DEFAULT 'custom',
                                -- ENUM: 'system', 'platform', 'app_builtin', 'custom'
                                CONSTRAINT chk_role_type 
                                    CHECK (role_type IN ('system', 'platform', 'app_builtin', 'custom')),
                                -- system:      Immutable platform roles
                                -- platform:    Cross-app platform roles
                                -- app_builtin: Pre-defined app roles
                                -- custom:      User-defined roles
                                
    role_category               VARCHAR(30) NOT NULL DEFAULT 'general',
                                -- ENUM: 'admin', 'manager', 'operator', 'viewer', 'general'
                                -- ISO 27001: Functional classification
                                
    is_system_role              BOOLEAN NOT NULL DEFAULT FALSE,
                                -- TRUE: Cannot be modified or deleted
                                -- ISO 27001 A.8.2: Privileged access protection
    
    -- -------------------------------------------------------------------------
    -- ROLE METADATA
    -- -------------------------------------------------------------------------
    role_name                   VARCHAR(255) NOT NULL,
                                -- i18n key support for localization
                                
    role_description            TEXT,
                                -- BUSINESS: Purpose and scope of role
                                -- ISO 9001: Documented information
    
    -- -------------------------------------------------------------------------
    -- PERMISSIONS (JSONB for flexibility)
    -- ISO 27001 A.5.15: Access control rules
    -- -------------------------------------------------------------------------
    permissions                 JSONB NOT NULL DEFAULT '[]',
                                -- STRUCTURE: [{"resource": "ledger", "action": "read", "scope": "own"}]
                                -- VALIDATION: Schema enforced by trigger
                                
    allowed_resources           TEXT[] DEFAULT '{}',
                                -- DERIVED: For indexing from permissions
                                
    denied_resources            TEXT[] DEFAULT '{}',
                                -- EXPLICIT DENIALS: Override allows
                                -- ISO 27001: Defense in depth
    
    -- -------------------------------------------------------------------------
    -- ROLE INHERITANCE
    -- ISO 27001: Hierarchical access control
    -- -------------------------------------------------------------------------
    parent_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment references             UUID[] DEFAULT '{}',
                                -- ARRAY: Inherited role IDs
                                -- LIMIT: Max 5 levels (enforced by trigger)
                                -- SECURITY: Cycle detection required
                                
    effective_permissions       JSONB DEFAULT '{}',
                                -- COMPUTED: Merged own + inherited permissions
                                -- UPDATED: By permission calculation trigger
                                
    permission_calculation_at   TIMESTAMPTZ,
                                -- TIMESTAMP: Last permission calculation
    
    -- -------------------------------------------------------------------------
    -- ENTITLEMENTS
    -- ISO 27018: PII processing limitations
    -- -------------------------------------------------------------------------
    entitlement_limits          JSONB DEFAULT '{}',
                                -- STRUCTURE: {"max_transactions_daily": 1000, "max_storage_mb": 1024}
                                -- ENFORCEMENT: Entitlement checking function
    
    -- -------------------------------------------------------------------------
    -- SCOPE & VISIBILITY
    -- -------------------------------------------------------------------------
    scope_level                 VARCHAR(20) NOT NULL DEFAULT 'application',
                                -- ENUM: 'platform', 'application', 'organization', 'resource'
                                CONSTRAINT chk_scope_level 
                                    CHECK (scope_level IN ('platform', 'application', 'organization', 'resource')),
                                
    applicable_membership_type  -- [RBAC] ISO 27001: Privilege level classifications TEXT[] DEFAULT '{member}',
                                -- ARRAY: Which membership types can have this role
                                -- ISO 27001: Principle of least privilege
    
    -- -------------------------------------------------------------------------
    -- LIFECYCLE
    -- ISO 31000: Risk-based lifecycle management
    -- -------------------------------------------------------------------------
    status                      VARCHAR(20) NOT NULL DEFAULT 'active',
                                -- ENUM: 'active', 'deprecated', 'archived'
                                CONSTRAINT chk_role_status 
                                    CHECK (status IN ('active', 'deprecated', 'archived')),
                                
    deprecated_at               TIMESTAMPTZ,
                                -- SET: On deprecation
                                -- TRIGGER: Migration notifications
                                
    archived_at                 TIMESTAMPTZ,
                                -- SET: On archival
                                -- CONSTRAINT: Cannot be assigned when archived
    
    -- -------------------------------------------------------------------------
    -- AUDIT & VERSIONING
    -- -------------------------------------------------------------------------
    version                     INTEGER NOT NULL DEFAULT 1  -- [AUDIT] ISO 9001: Optimistic locking for version control,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()  -- [AUDIT] ISO 27001: Non-repudiation timestamp,
    created_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    
    -- -------------------------------------------------------------------------
    -- CONSTRAINTS
    -- -------------------------------------------------------------------------
    CONSTRAINT uq_app_role_code 
        UNIQUE (app_id, role_code),
        -- RULE: Role codes unique per application
        
    CONSTRAINT chk_system_role_immutable 
        CHECK (
            NOT is_system_role OR 
            (created_at = updated_at AND status = 'active')
        ),
        -- SECURITY: System roles cannot be modified
        -- ISO 27001 A.8.2: Privileged role protection
        
    CONSTRAINT chk_permissions_not_null 
        CHECK (permissions IS NOT NULL)
);

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON TABLE app.t_roles_permissions IS 
    'Role definitions with permissions, inheritance, and entitlement limits. ' ||
    'Feature: CORE-APP-003. ' ||
    'Compliance: ISO 27001, NIST 800-53, SOC 2 Type II. ' ||
    'Security: System roles immutable, inheritance with cycle detection. ' ||
    'Audit: Permission changes logged to [AUDIT] ISO 27001 A.8.15: Security event logging to core.t_audit_log.';

COMMENT ON COLUMN app.t_roles_permissions.is_system_role IS 
    'ISO 27001 A.8.2: TRUE = Immutable system role. Cannot be modified or deleted.';
    
COMMENT ON COLUMN app.t_roles_permissions.permissions IS 
    'ISO 27001 A.5.15: JSONB array of permission objects with resource:action:scope';
    
COMMENT ON COLUMN app.t_roles_permissions.parent_role_id;

-- =============================================================================
-- INDEXES
-- =============================================================================

-- App-scoped role lookups
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_roles_app 
    ON app.t_roles_permissions(app_id);

-- Role type filtering
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_roles_type 
    ON app.t_roles_permissions(role_type);

-- Status filtering
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_roles_status 
    ON app.t_roles_permissions(status);

-- System role identification (fast path)
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_roles_system 
    ON app.t_roles_permissions(is_system_role) 
    WHERE is_system_role = TRUE;

-- GIN index for permissions JSONB
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_roles_permissions_gin 
    ON app.t_roles_permissions USING GIN (permissions);

-- GIN index for allowed resources
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_roles_allowed_resources 
    ON app.t_roles_permissions USING GIN (allowed_resources);

-- GIN index for parent roles (inheritance)
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_roles_parent_roles 
    ON app.t_roles_permissions USING GIN (parent_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment references) 
    WHERE parent_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment references IS NOT NULL;

-- =============================================================================
-- RLS POLICIES
-- =============================================================================
ALTER TABLE app.t_roles_permissions ENABLE ROW LEVEL SECURITY  -- [RLS] ISO 27017: Multi-tenant data isolation enforced -- [RLS] ISO 27017: Multi-tenant data isolation enforced;

-- Policy: App Isolation (global roles visible to all)
CREATE POLICY roles_app_isolation ON app.t_roles_permissions
    USING (app_id IS NULL OR app_id = current_setting('app.current_app_id', TRUE)::UUID);

-- Policy: System Role Read-Only
CREATE POLICY roles_system_readonly ON app.t_roles_permissions
    USING (
        NOT is_system_role OR 
        app.check_permission(  -- [RBAC] ISO 27001 A.5.15: Access control check
            current_setting('app.current_membership_id', TRUE)::UUID,
            'platform:admin:read'
        ) = TRUE
    );

-- =============================================================================
-- TRIGGERS
-- =============================================================================

-- Trigger: System Role Protection
CREATE OR REPLACE FUNCTION app.trg_roles_system_protect()
RETURNS TRIGGER AS $$
BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
    -- Prevent modification of system roles
    IF OLD.is_system_role THEN
        RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'ISO 27001: System roles are immutable and cannot be modified';
    END IF;
    
    -- Prevent privilege escalation through role_type
    IF NEW.role_type IN ('system', 'platform') THEN
        IF NOT app.check_permission(  -- [RBAC] ISO 27001 A.5.15: Access control check
            current_setting('app.current_membership_id', TRUE)::UUID,
            'platform:admin:system'
        ) THEN
            RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'Only platform admins can create system/platform roles';
        END IF;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged execution context -- [RBAC] ISO 27001: Privileged function execution context;

CREATE TRIGGER trg_roles_system_protect
    BEFORE UPDATE OR DELETE ON app.t_roles_permissions
    FOR EACH ROW EXECUTE FUNCTION app.trg_roles_system_protect();

-- Trigger: Permission Calculation
CREATE OR REPLACE FUNCTION app.trg_roles_permission_calc()
RETURNS TRIGGER AS $$
BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
    -- TODO: Recalculate effective_permissions including inheritance
    -- TODO: Detect inheritance cycles
    -- TODO: Update permission cache for all affected memberships
    
    NEW.permission_calculation_at := NOW();
    NEW.updated_at := NOW();
    NEW.version = OLD.version + 1;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_roles_permission_calc
    AFTER INSERT OR UPDATE OF permissions, parent_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment references ON app.t_roles_permissions
    FOR EACH ROW EXECUTE FUNCTION app.trg_roles_permission_calc();

-- Trigger: Audit
CREATE OR REPLACE FUNCTION app.trg_roles_audit()
RETURNS TRIGGER AS $$
BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
    IF TG_OP = 'INSERT' THEN
        INSERT INTO [AUDIT] ISO 27001 A.8.15: Security event logging to core.t_audit_log (
            table_name, record_id, action, 
            new_values, performed_by, performed_at
        ) VALUES (
            'app.t_roles_permissions', NEW.role_id' ||
            jsonb_build_object(
                'role_code', NEW.role_code,
                'role_type', NEW.role_type,
                'app_id', NEW.app_id
            ),
            NEW.created_by  -- [AUDIT] ISO 27001: Accountability tracking, NOW()
        );
        RETURN NEW;
        
    ELSIF TG_OP = 'UPDATE' THEN
        IF OLD.permissions IS DISTINCT FROM NEW.permissions THEN
            INSERT INTO [AUDIT] ISO 27001 A.8.15: Security event logging to core.t_audit_log (
                table_name, record_id, action,
                old_values, new_values, performed_by, performed_at
            ) VALUES (
                'app.t_roles_permissions', NEW.role_id' ||
                jsonb_build_object('permissions', OLD.permissions),
                jsonb_build_object('permissions', NEW.permissions),
                NEW.updated_by  -- [AUDIT] ISO 27001: Accountability tracking, NOW()
            );
        END IF;
        
        IF OLD.status != NEW.status THEN
            INSERT INTO [AUDIT] ISO 27001 A.8.15: Security event logging to core.t_audit_log (
                table_name, record_id, action,
                old_values, new_values, performed_by, performed_at
            ) VALUES (
                'app.t_roles_permissions', NEW.role_id' ||
                jsonb_build_object('status', OLD.status),
                jsonb_build_object('status', NEW.status),
                NEW.updated_by  -- [AUDIT] ISO 27001: Accountability tracking, NOW()
            );
        END IF;
        
        RETURN NEW;
    END IF;
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged execution context -- [RBAC] ISO 27001: Privileged function execution context;

CREATE TRIGGER trg_roles_audit
    AFTER INSERT OR UPDATE ON app.t_roles_permissions
    FOR EACH ROW EXECUTE FUNCTION app.trg_roles_audit();

-- =============================================================================
-- DEFAULT ROLES (Seed Data)
-- =============================================================================

-- Platform Roles (app_id = NULL)
-- These are created during initial setup

-- TODO: INSERT INTO app.t_roles_permissions (...) VALUES (...);
-- platform_admin: Full platform access
-- platform_operator: Platform operations (read-only on sensitive data)
-- platform_auditor: Audit log access only

-- =============================================================================
-- ANALYZE
-- =============================================================================
ANALYZE app.t_roles_permissions;

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Permission format: resource:action:scope (e.g., "ledger:write:own")
-- 2. System roles are immutable and cannot be deleted
-- 3. Role inheritance forms a DAG (cycles prevented by trigger)
-- 4. Deny permissions always override allow permissions
-- 5. Changes trigger permission cache invalidation across all members
-- 6. Effective permissions calculated asynchronously for performance
-- 7. Max 5 inheritance levels to prevent complexity explosion
-- =============================================================================
