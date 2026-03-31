-- ============================================================================
-- App Schema - Permission and Role Operations
-- ============================================================================

-- Function: Create role
CREATE OR REPLACE FUNCTION app.create_role(
    p_application_id UUID,
    p_role_name VARCHAR(50),
    p_role_description TEXT DEFAULT NULL,
    p_parent_role_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, public
AS $$
DECLARE
    v_role_id UUID;
BEGIN
    v_role_id := gen_random_uuid();

    INSERT INTO app.roles_permissions (
        role_id,
        application_id,
        role_name,
        role_description,
        parent_role_id,
        is_system_role,
        valid_from,
        valid_to,
        superseded_by,
        is_current,
        created_at,
        created_by
    ) VALUES (
        v_role_id,
        p_application_id,
        p_role_name,
        p_role_description,
        p_parent_role_id,
        FALSE,
        now(),
        'infinity'::timestamptz,
        NULL,
        TRUE,
        now(),
        current_user
    );

    RETURN v_role_id;
END;
$$;

COMMENT ON FUNCTION app.create_role IS 'Creates a new role in application';

-- Function: Assign permission to role
CREATE OR REPLACE FUNCTION app.grant_permission(
    p_role_id UUID,
    p_resource VARCHAR(64),
    p_action VARCHAR(32),
    p_conditions JSONB DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, public
AS $$
DECLARE
    v_permission_id UUID;
BEGIN
    v_permission_id := gen_random_uuid();

    INSERT INTO app.roles_permissions (
        role_id,
        resource,
        action,
        conditions,
        granted_at,
        granted_by
    ) VALUES (
        v_role_id,
        p_resource,
        p_action,
        p_conditions,
        now(),
        current_user
    );

    RETURN v_permission_id;
END;
$$;

COMMENT ON FUNCTION app.grant_permission IS 'Grants permission to role';

-- Function: Assign role to user
CREATE OR REPLACE FUNCTION app.assign_role(
    p_membership_id UUID,
    p_role_id UUID,
    p_scope_account_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, public
AS $$
DECLARE
    v_assignment_id UUID;
BEGIN
    v_assignment_id := gen_random_uuid();

    INSERT INTO app.user_role_assignments (
        assignment_id,
        membership_id,
        role_id,
        scope_account_id,
        valid_from,
        valid_to,
        superseded_by,
        is_current,
        assigned_at,
        assigned_by
    ) VALUES (
        v_assignment_id,
        p_membership_id,
        p_role_id,
        p_scope_account_id,
        now(),
        'infinity'::timestamptz,
        NULL,
        TRUE,
        now(),
        current_user
    );

    RETURN v_assignment_id;
END;
$$;

COMMENT ON FUNCTION app.assign_role IS 'Assigns role to user membership';

-- Function: Check permission
CREATE OR REPLACE FUNCTION app.check_permission(
    p_membership_id UUID,
    p_resource VARCHAR(64),
    p_action VARCHAR(32)
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SET search_path = app, public
AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM app.user_role_assignments ura
        JOIN app.roles_permissions rp ON ura.role_id = rp.role_id
        WHERE ura.membership_id = p_membership_id
        AND ura.is_current = TRUE
        AND rp.resource = p_resource
        AND rp.action = p_action
        AND ura.valid_from <= now()
        AND ura.valid_to > now()
    );
END;
$$;

COMMENT ON FUNCTION app.check_permission IS 'Checks if user has permission';
