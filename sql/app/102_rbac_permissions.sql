-- ============================================================================
-- USSD KERNEL APP SCHEMA - RBAC AND PERMISSIONS
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Role-based access control with permission definitions, role
--              hierarchies, and user role assignments. All changes versioned.
-- Immutability: Permissions, roles, and assignments are versioned
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. PERMISSIONS CATALOG
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.permissions (
    permission_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Permission code (unique identifier)
    permission_code VARCHAR(100) NOT NULL,  -- e.g., 'transaction:submit', 'account:read'
    
    -- Scope
    application_id UUID,  -- NULL = global permission
    
    -- Classification
    resource_type VARCHAR(50) NOT NULL,  -- e.g., 'transaction', 'account', 'report'
    action ussd_app.permission_action NOT NULL,
    
    -- Description
    name VARCHAR(100) NOT NULL,
    description TEXT,
    
    -- Conditions (optional RBAC conditions)
    conditions JSONB DEFAULT '{}',  -- e.g., {"amount_max": 1000, "own_data_only": true}
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Immutable versioning
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    superseded_by UUID REFERENCES ussd_app.permissions(permission_id),
    valid_from TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    valid_to TIMESTAMPTZ,
    
    record_hash VARCHAR(64) NOT NULL
);

-- ----------------------------------------------------------------------------
-- 2. ROLES TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.roles (
    role_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Role identification
    role_code VARCHAR(50) NOT NULL,  -- e.g., 'passenger', 'driver', 'admin'
    role_name VARCHAR(100) NOT NULL,
    description TEXT,
    
    -- Scope
    application_id UUID,  -- NULL = system-wide role
    
    -- Classification
    role_type VARCHAR(20) DEFAULT 'custom' CHECK (role_type IN ('system', 'builtin', 'custom')),
    
    -- Hierarchy (for role inheritance)
    parent_role_id UUID REFERENCES ussd_app.roles(role_id),
    
    -- Default for new enrollments
    is_default BOOLEAN DEFAULT FALSE,
    
    -- Status
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'deprecated')),
    deprecated_at TIMESTAMPTZ,
    
    -- Immutable versioning
    version INTEGER DEFAULT 1,
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    created_by UUID,
    superseded_by UUID REFERENCES ussd_app.roles(role_id),
    valid_from TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    valid_to TIMESTAMPTZ,
    
    record_hash VARCHAR(64) NOT NULL
);

-- ----------------------------------------------------------------------------
-- 3. ROLE-PERMISSION MAPPING
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.role_permissions (
    mapping_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    role_id UUID NOT NULL REFERENCES ussd_app.roles(role_id),
    permission_id UUID NOT NULL REFERENCES ussd_app.permissions(permission_id),
    
    -- Grant conditions (optional)
    grant_conditions JSONB DEFAULT '{}',  -- e.g., {"max_amount": 500}
    
    -- Immutable versioning
    granted_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    granted_by UUID,
    valid_from TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    valid_to TIMESTAMPTZ,
    
    UNIQUE(role_id, permission_id, valid_from)
);

-- ----------------------------------------------------------------------------
-- 4. USER ROLE ASSIGNMENTS
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.user_roles (
    assignment_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    role_id UUID NOT NULL REFERENCES ussd_app.roles(role_id),
    
    -- Scope (optional - for scoped permissions)
    application_id UUID,  -- NULL = system-wide
    scope_conditions JSONB DEFAULT '{}',  -- e.g., {"department": "sales"}
    
    -- Assignment metadata
    assigned_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    assigned_by UUID,
    assignment_reason TEXT,
    
    -- Expiration
    expires_at TIMESTAMPTZ,  -- NULL = never expires
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Immutable versioning
    valid_from TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    valid_to TIMESTAMPTZ,
    superseded_by UUID REFERENCES ussd_app.user_roles(assignment_id),
    
    UNIQUE(account_id, role_id, application_id, valid_from)
);

-- ----------------------------------------------------------------------------
-- 5. ROLE ASSIGNMENT HISTORY
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.role_assignment_history (
    history_id BIGSERIAL PRIMARY KEY,
    
    account_id UUID NOT NULL,
    role_id UUID NOT NULL,
    application_id UUID,
    
    action VARCHAR(20) NOT NULL,  -- 'assigned', 'revoked', 'expired'
    
    previous_assignment_id UUID,
    new_assignment_id UUID,
    
    reason TEXT,
    performed_by UUID,
    performed_at TIMESTAMPTZ DEFAULT ussd_core.precise_now()
);

-- ----------------------------------------------------------------------------
-- 6. INDEXES
-- ----------------------------------------------------------------------------
CREATE UNIQUE INDEX idx_permissions_active_code 
    ON ussd_app.permissions(permission_code, COALESCE(application_id, '00000000-0000-0000-0000-000000000000'::UUID))
    WHERE valid_to IS NULL;

CREATE INDEX idx_permissions_app ON ussd_app.permissions(application_id);
CREATE INDEX idx_permissions_resource ON ussd_app.permissions(resource_type);

CREATE UNIQUE INDEX idx_roles_active_code 
    ON ussd_app.roles(role_code, COALESCE(application_id, '00000000-0000-0000-0000-000000000000'::UUID))
    WHERE valid_to IS NULL;

CREATE INDEX idx_roles_app ON ussd_app.roles(application_id);
CREATE INDEX idx_roles_parent ON ussd_app.roles(parent_role_id);

CREATE INDEX idx_role_permissions_role ON ussd_app.role_permissions(role_id);
CREATE INDEX idx_role_permissions_perm ON ussd_app.role_permissions(permission_id);
CREATE INDEX idx_role_permissions_valid ON ussd_app.role_permissions(valid_from, valid_to);

CREATE INDEX idx_user_roles_account ON ussd_app.user_roles(account_id);
CREATE INDEX idx_user_roles_role ON ussd_app.user_roles(role_id);
CREATE INDEX idx_user_roles_app ON ussd_app.user_roles(application_id);
CREATE INDEX idx_user_roles_valid ON ussd_app.user_roles(valid_from, valid_to);

CREATE INDEX idx_role_history_account ON ussd_app.role_assignment_history(account_id);

-- ----------------------------------------------------------------------------
-- 7. IMMUTABILITY TRIGGERS
-- ----------------------------------------------------------------------------
CREATE TRIGGER trg_permissions_prevent_update
    BEFORE UPDATE ON ussd_app.permissions
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_update();

CREATE TRIGGER trg_roles_prevent_update
    BEFORE UPDATE ON ussd_app.roles
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_update();

CREATE TRIGGER trg_role_permissions_prevent_update
    BEFORE UPDATE ON ussd_app.role_permissions
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_update();

CREATE TRIGGER trg_user_roles_prevent_update
    BEFORE UPDATE ON ussd_app.user_roles
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_update();

-- ----------------------------------------------------------------------------
-- 8. HASH COMPUTATION
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd_app.compute_permission_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := ussd_core.generate_hash(
        NEW.permission_id::TEXT || NEW.permission_code || NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION ussd_app.compute_role_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := ussd_core.generate_hash(
        NEW.role_id::TEXT || NEW.role_code || NEW.version::TEXT || NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_permissions_compute_hash
    BEFORE INSERT ON ussd_app.permissions
    FOR EACH ROW
    EXECUTE FUNCTION ussd_app.compute_permission_hash();

CREATE TRIGGER trg_roles_compute_hash
    BEFORE INSERT ON ussd_app.roles
    FOR EACH ROW
    EXECUTE FUNCTION ussd_app.compute_role_hash();

-- ----------------------------------------------------------------------------
-- 9. RBAC MANAGEMENT FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to create a permission
CREATE OR REPLACE FUNCTION ussd_app.create_permission(
    p_permission_code VARCHAR,
    p_resource_type VARCHAR,
    p_action ussd_app.permission_action,
    p_name VARCHAR,
    p_description TEXT DEFAULT NULL,
    p_application_id UUID DEFAULT NULL,
    p_conditions JSONB DEFAULT '{}'
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_permission_id UUID;
BEGIN
    INSERT INTO ussd_app.permissions (
        permission_code,
        resource_type,
        action,
        name,
        description,
        application_id,
        conditions
    ) VALUES (
        p_permission_code,
        p_resource_type,
        p_action,
        p_name,
        p_description,
        p_application_id,
        p_conditions
    )
    RETURNING permission_id INTO v_permission_id;
    
    RETURN v_permission_id;
END;
$$;

-- Function to create a role
CREATE OR REPLACE FUNCTION ussd_app.create_role(
    p_role_code VARCHAR,
    p_role_name VARCHAR,
    p_description TEXT DEFAULT NULL,
    p_application_id UUID DEFAULT NULL,
    p_parent_role_id UUID DEFAULT NULL,
    p_created_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_role_id UUID;
BEGIN
    INSERT INTO ussd_app.roles (
        role_code,
        role_name,
        description,
        application_id,
        parent_role_id,
        created_by
    ) VALUES (
        p_role_code,
        p_role_name,
        p_description,
        p_application_id,
        p_parent_role_id,
        p_created_by
    )
    RETURNING role_id INTO v_role_id;
    
    RETURN v_role_id;
END;
$$;

-- Function to grant permission to role
CREATE OR REPLACE FUNCTION ussd_app.grant_permission(
    p_role_id UUID,
    p_permission_id UUID,
    p_granted_by UUID DEFAULT NULL,
    p_conditions JSONB DEFAULT '{}'
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    -- Check if already granted
    IF EXISTS (
        SELECT 1 FROM ussd_app.role_permissions
        WHERE role_id = p_role_id AND permission_id = p_permission_id AND valid_to IS NULL
    ) THEN
        RAISE EXCEPTION 'Permission already granted to role';
    END IF;
    
    INSERT INTO ussd_app.role_permissions (
        role_id,
        permission_id,
        grant_conditions,
        granted_by
    ) VALUES (
        p_role_id,
        p_permission_id,
        p_conditions,
        p_granted_by
    );
END;
$$;

-- Function to revoke permission from role
CREATE OR REPLACE FUNCTION ussd_app.revoke_permission(
    p_role_id UUID,
    p_permission_id UUID,
    p_revoked_by UUID DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE ussd_app.role_permissions
    SET valid_to = ussd_core.precise_now()
    WHERE role_id = p_role_id 
      AND permission_id = p_permission_id 
      AND valid_to IS NULL;
END;
$$;

-- Function to assign role to user
CREATE OR REPLACE FUNCTION ussd_app.assign_role(
    p_account_id UUID,
    p_role_id UUID,
    p_application_id UUID DEFAULT NULL,
    p_assigned_by UUID DEFAULT NULL,
    p_expires_at TIMESTAMPTZ DEFAULT NULL,
    p_reason TEXT DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_assignment_id UUID;
BEGIN
    -- Check if already has this role
    IF EXISTS (
        SELECT 1 FROM ussd_app.user_roles
        WHERE account_id = p_account_id 
          AND role_id = p_role_id 
          AND COALESCE(application_id, '00000000-0000-0000-0000-000000000000'::UUID) = 
              COALESCE(p_application_id, '00000000-0000-0000-0000-000000000000'::UUID)
          AND valid_to IS NULL
    ) THEN
        RAISE EXCEPTION 'Role already assigned to user';
    END IF;
    
    INSERT INTO ussd_app.user_roles (
        account_id,
        role_id,
        application_id,
        assigned_by,
        assignment_reason,
        expires_at
    ) VALUES (
        p_account_id,
        p_role_id,
        p_application_id,
        p_assigned_by,
        p_reason,
        p_expires_at
    )
    RETURNING assignment_id INTO v_assignment_id;
    
    -- Log history
    INSERT INTO ussd_app.role_assignment_history (
        account_id,
        role_id,
        application_id,
        action,
        new_assignment_id,
        reason,
        performed_by
    ) VALUES (
        p_account_id,
        p_role_id,
        p_application_id,
        'assigned',
        v_assignment_id,
        p_reason,
        p_assigned_by
    );
    
    RETURN v_assignment_id;
END;
$$;

-- Function to revoke role from user
CREATE OR REPLACE FUNCTION ussd_app.revoke_role(
    p_assignment_id UUID,
    p_revoked_by UUID DEFAULT NULL,
    p_reason TEXT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_record ussd_app.user_roles%ROWTYPE;
BEGIN
    SELECT * INTO v_record
    FROM ussd_app.user_roles
    WHERE assignment_id = p_assignment_id AND valid_to IS NULL;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Assignment not found: %', p_assignment_id;
    END IF;
    
    UPDATE ussd_app.user_roles
    SET valid_to = ussd_core.precise_now()
    WHERE assignment_id = p_assignment_id;
    
    -- Log history
    INSERT INTO ussd_app.role_assignment_history (
        account_id,
        role_id,
        application_id,
        action,
        previous_assignment_id,
        reason,
        performed_by
    ) VALUES (
        v_record.account_id,
        v_record.role_id,
        v_record.application_id,
        'revoked',
        p_assignment_id,
        p_reason,
        p_revoked_by
    );
END;
$$;

-- Function to check if user has permission
CREATE OR REPLACE FUNCTION ussd_app.user_has_permission(
    p_account_id UUID,
    p_permission_code VARCHAR,
    p_application_id UUID DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM ussd_app.user_roles ur
        JOIN ussd_app.roles r ON ur.role_id = r.role_id
        JOIN ussd_app.role_permissions rp ON r.role_id = rp.role_id
        JOIN ussd_app.permissions p ON rp.permission_id = p.permission_id
        WHERE ur.account_id = p_account_id
          AND ur.valid_to IS NULL
          AND ur.is_active = TRUE
          AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
          AND r.valid_to IS NULL
          AND rp.valid_to IS NULL
          AND p.valid_to IS NULL
          AND p.permission_code = p_permission_code
          AND (p.application_id IS NULL OR p.application_id = p_application_id)
          AND (ur.application_id IS NULL OR ur.application_id = p_application_id)
    );
END;
$$;

-- Function to get all permissions for a user
CREATE OR REPLACE FUNCTION ussd_app.get_user_permissions(
    p_account_id UUID,
    p_application_id UUID DEFAULT NULL
)
RETURNS TABLE (
    permission_code VARCHAR,
    permission_name VARCHAR,
    resource_type VARCHAR,
    action ussd_app.permission_action,
    role_code VARCHAR,
    conditions JSONB
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        p.permission_code,
        p.name as permission_name,
        p.resource_type,
        p.action,
        r.role_code,
        COALESCE(rp.grant_conditions, '{}'::JSONB) || COALESCE(ur.scope_conditions, '{}'::JSONB) as conditions
    FROM ussd_app.user_roles ur
    JOIN ussd_app.roles r ON ur.role_id = r.role_id
    JOIN ussd_app.role_permissions rp ON r.role_id = rp.role_id
    JOIN ussd_app.permissions p ON rp.permission_id = p.permission_id
    WHERE ur.account_id = p_account_id
      AND ur.valid_to IS NULL
      AND ur.is_active = TRUE
      AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
      AND r.valid_to IS NULL
      AND rp.valid_to IS NULL
      AND p.valid_to IS NULL
      AND p.is_active = TRUE
      AND (p.application_id IS NULL OR p.application_id = p_application_id)
      AND (ur.application_id IS NULL OR ur.application_id = p_application_id)
    GROUP BY p.permission_code, p.name, p.resource_type, p.action, r.role_code, rp.grant_conditions, ur.scope_conditions;
END;
$$;

-- ----------------------------------------------------------------------------
-- 10. VIEWS
-- ----------------------------------------------------------------------------

-- Active permissions
CREATE VIEW ussd_app.active_permissions AS
SELECT *
FROM ussd_app.permissions
WHERE valid_to IS NULL AND is_active = TRUE;

-- Active roles
CREATE VIEW ussd_app.active_roles AS
SELECT *
FROM ussd_app.roles
WHERE valid_to IS NULL AND status = 'active';

-- Role permission matrix
CREATE VIEW ussd_app.role_permission_matrix AS
SELECT 
    r.role_id,
    r.role_code,
    r.role_name,
    r.application_id as role_application_id,
    p.permission_id,
    p.permission_code,
    p.resource_type,
    p.action,
    p.application_id as permission_application_id,
    rp.grant_conditions
FROM ussd_app.roles r
JOIN ussd_app.role_permissions rp ON r.role_id = rp.role_id
JOIN ussd_app.permissions p ON rp.permission_id = p.permission_id
WHERE r.valid_to IS NULL
  AND p.valid_to IS NULL
  AND rp.valid_to IS NULL;

-- User role assignments with details
CREATE VIEW ussd_app.user_role_assignments AS
SELECT 
    ur.*,
    r.role_code,
    r.role_name,
    a.app_code,
    a.name as application_name
FROM ussd_app.user_roles ur
JOIN ussd_app.roles r ON ur.role_id = r.role_id
LEFT JOIN ussd_app.applications a ON ur.application_id = a.application_id
WHERE ur.valid_to IS NULL;

-- My permissions (current user)
CREATE VIEW ussd_app.my_permissions AS
SELECT * FROM ussd_app.get_user_permissions(
    NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID
);

-- ----------------------------------------------------------------------------
-- 11. INITIAL PERMISSIONS AND ROLES (Kernel-Only)
-- ----------------------------------------------------------------------------
-- Applications define their own business-specific permissions

-- Kernel-level permissions only
INSERT INTO ussd_app.permissions (permission_code, resource_type, action, name, description) VALUES
    ('kernel:account:create', 'account', 'create', 'Create Account', 'Create kernel accounts'),
    ('kernel:account:read', 'account', 'read', 'Read Account', 'View account details'),
    ('kernel:account:read:all', 'account', 'read', 'Read All Accounts', 'View any account'),
    ('kernel:transaction:read', 'transaction', 'read', 'Read Transaction', 'View transactions'),
    ('kernel:transaction:read:all', 'transaction', 'read', 'Read All Transactions', 'View any transaction'),
    ('kernel:admin', 'admin', 'admin', 'Kernel Administration', 'Full kernel administration'),
    ('kernel:audit:read', 'admin', 'read', 'View Audit Logs', 'Access kernel audit trails'),
    ('kernel:config:manage', 'admin', 'update', 'Manage Configuration', 'Modify kernel configuration');

-- Kernel roles only
INSERT INTO ussd_app.roles (role_code, role_name, description, role_type, is_default) VALUES
    ('kernel_admin', 'Kernel Administrator', 'Full kernel access', 'system', FALSE),
    ('kernel_operator', 'Kernel Operator', 'Basic kernel operations', 'builtin', TRUE),
    ('kernel_auditor', 'Kernel Auditor', 'Read-only audit access', 'builtin', FALSE);

-- Assign kernel permissions to kernel_admin
INSERT INTO ussd_app.role_permissions (role_id, permission_id)
SELECT 
    (SELECT role_id FROM ussd_app.roles WHERE role_code = 'kernel_admin'),
    permission_id
FROM ussd_app.permissions
WHERE valid_to IS NULL;  -- All kernel permissions

-- ----------------------------------------------------------------------------
-- 12. ROW LEVEL SECURITY
-- ----------------------------------------------------------------------------
ALTER TABLE ussd_app.permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd_app.roles ENABLE ROW LEVEL SECURITY;

-- Permissions are readable by all authenticated users
CREATE POLICY permissions_read ON ussd_app.permissions
    FOR SELECT USING (TRUE);

-- Roles are readable by all
CREATE POLICY roles_read ON ussd_app.roles
    FOR SELECT USING (TRUE);

-- ----------------------------------------------------------------------------
-- 13. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_app.permissions IS 
    'Permission catalog with immutable versioning';
COMMENT ON TABLE ussd_app.roles IS 
    'Role definitions with hierarchy support';
COMMENT ON TABLE ussd_app.role_permissions IS 
    'Many-to-many mapping of roles to permissions, versioned';
COMMENT ON TABLE ussd_app.user_roles IS 
    'User role assignments with expiration support';
COMMENT ON FUNCTION ussd_app.user_has_permission IS 
    'Checks if user has specific permission (with inheritance)';
