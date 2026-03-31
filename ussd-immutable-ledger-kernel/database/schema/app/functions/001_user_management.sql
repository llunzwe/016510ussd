/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - USER MANAGEMENT FUNCTIONS
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-FUNC-006
 * Feature Name:       User Management Functions
 * Description:        Functions for user authentication, role assignment,
 *                     and membership management. Provides security definer
 *                     functions for RLS bypass with proper audit logging.
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
 *   - Control A.5.18: Access rights management
 *   - Control A.9.2.1: User registration
 *   - Control A.9.2.2: Access provisioning
 *   - Control A.9.2.4: Secret authentication info management
 *   - Control A.9.2.6: Removal of access rights
 * 
 * ISO/IEC 27017:2015 (Cloud Security)
 *   - Section 9: Access control in multi-tenant environments
 * 
 * GDPR (General Data Protection Regulation)
 *   - Article 17: Right to erasure
 *   - Article 25: Data protection by design
 * 
 * SOC 2 Type II
 *   - CC6.1: Logical access controls
 *   - CC6.2: Access provisioning and revocation
 * 
 * =============================================================================
 * AUDIT TRAIL REQUIREMENTS
 * =============================================================================
 * 
 * MANDATORY AUDIT EVENTS:
 *   - User invited (inviter, invitee, role)
 *   - Invitation accepted/rejected
 *   - Role assigned/removed
 *   - Membership status changes
 *   - Permission denials
 *   - Session events
 * 
 * AUDIT RETENTION: 7 years
 * =============================================================================
 */

-- =============================================================================
-- COMPLIANCE STANDARDS
-- =============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework
-- ISO/IEC 27017:2015 - Cloud Security Controls
-- GDPR - Data Protection
-- SOC 2 Type II - Security Controls
-- =============================================================================

-- =============================================================================
-- FUNCTION: Create Membership Invitation
-- ISO 27001 A.9.2.1: Secure user registration
-- =============================================================================

CREATE OR REPLACE FUNCTION app.invite_user(
    p_app_id UUID,
    p_user_identity_id UUID,
    p_membership_type VARCHAR(30) DEFAULT 'member',
    p_primary_role_id UUID DEFAULT NULL,
    p_org_unit_id UUID DEFAULT NULL,
    p_custom_message TEXT DEFAULT NULL
)
RETURNS TABLE (
    membership_id UUID,
    invitation_token TEXT,
    expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_membership_id UUID;
    v_invitation_token TEXT;
    v_token_hash TEXT;
    v_expires_at TIMESTAMPTZ;
    v_current_membership UUID;
    v_current_user UUID;
    v_app_exists BOOLEAN;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_membership := current_setting('app.current_membership_id', TRUE)::UUID;
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Verify application exists and is active
    SELECT EXISTS(
        SELECT 1 FROM app.t_application_registry 
        WHERE app_id = p_app_id AND status = 'active'
    ) INTO v_app_exists;
    
    IF NOT v_app_exists THEN
        RAISE EXCEPTION '[NOT_FOUND] Application % not found or not active', p_app_id;
    END IF;
    
    -- Authorization check
    IF NOT app.check_permission(v_current_membership, 'app:membership:invite') THEN
        RAISE EXCEPTION '[RBAC] Insufficient privileges to invite users';
    END IF;
    
    -- Validate membership type
    IF p_membership_type NOT IN ('admin', 'member', 'guest', 'service') THEN
        -- Note: 'owner' cannot be invited, must use transfer_ownership
        RAISE EXCEPTION '[VALIDATION] Invalid membership type. Owner must be transferred.';
    END IF;
    
    -- Check if user already has membership in this app
    IF EXISTS (
        SELECT 1 FROM app.t_account_membership
        WHERE app_id = p_app_id 
          AND user_identity_id = p_user_identity_id
          AND status IN ('active', 'pending', 'suspended')
    ) THEN
        RAISE EXCEPTION '[CONFLICT] User already has a membership in this application';
    END IF;
    
    -- Generate invitation token (plaintext returned, hash stored)
    v_invitation_token := encode(gen_random_bytes(32), 'hex');
    v_token_hash := crypt(v_invitation_token, gen_salt('bf', 10));
    v_expires_at := NOW() + INTERVAL '7 days';
    
    -- Create membership record
    INSERT INTO app.t_account_membership (
        app_id,
        user_identity_id,
        membership_type,
        membership_scope,
        org_unit_id,
        primary_role_id,
        status,
        invitation_token_hash,
        invited_by,
        invited_at,
        invitation_expires_at,
        created_by,
        updated_by
    ) VALUES (
        p_app_id,
        p_user_identity_id,
        p_membership_type,
        'organization',
        p_org_unit_id,
        p_primary_role_id,
        'pending',
        v_token_hash,
        v_current_user,
        NOW(),
        v_expires_at,
        v_current_user,
        v_current_user
    )
    RETURNING app.t_account_membership.membership_id INTO v_membership_id;
    
    -- [AUDIT] ISO 27001: Log invitation
    INSERT INTO core.t_audit_trail (
        table_name,
        record_id,
        action,
        new_values,
        performed_by,
        performed_at
    ) VALUES (
        'app.t_account_membership',
        v_membership_id,
        'INVITE',
        jsonb_build_object(
            'app_id', p_app_id,
            'user_identity_id', p_user_identity_id,
            'membership_type', p_membership_type,
            'invited_by', v_current_user,
            'expires_at', v_expires_at
        ),
        v_current_user,
        NOW()
    );
    
    -- Return membership details (token only shown once)
    RETURN QUERY SELECT v_membership_id, v_invitation_token, v_expires_at;
END;
$$;

COMMENT ON FUNCTION app.invite_user IS 
    'Invite a user to join an application. ISO 27001 A.9.2.1. ' ||
    'Returns invitation token (deliver securely to user).';

-- =============================================================================
-- FUNCTION: Accept Invitation
-- ISO 27001 A.9.2.1: Registration completion
-- =============================================================================

CREATE OR REPLACE FUNCTION app.accept_invitation(
    p_invitation_token TEXT,
    p_user_agent TEXT DEFAULT NULL,
    p_ip_address INET DEFAULT NULL
)
RETURNS TABLE (
    success BOOLEAN,
    membership_id UUID,
    app_id UUID,
    message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_membership_record RECORD;
    v_token_hash TEXT;
    v_current_user UUID;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    v_token_hash := crypt(p_invitation_token, gen_salt('bf', 10));
    
    -- Find membership by token hash verification
    SELECT 
        m.membership_id,
        m.app_id,
        m.user_identity_id,
        m.invitation_token_hash,
        m.invitation_expires_at,
        m.status
    INTO v_membership_record
    FROM app.t_account_membership m
    WHERE m.status = 'pending'
      AND m.invitation_expires_at > NOW();
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::UUID, NULL::UUID, 'Invalid or expired invitation'::TEXT;
        RETURN;
    END IF;
    
    -- Verify token hash matches
    IF v_membership_record.invitation_token_hash != crypt(p_invitation_token, v_membership_record.invitation_token_hash) THEN
        RETURN QUERY SELECT FALSE, NULL::UUID, NULL::UUID, 'Invalid invitation token'::TEXT;
        RETURN;
    END IF;
    
    -- Verify current user matches invited user
    IF v_membership_record.user_identity_id != v_current_user THEN
        RETURN QUERY SELECT FALSE, NULL::UUID, NULL::UUID, 'Invitation not for current user'::TEXT;
        RETURN;
    END IF;
    
    -- Activate membership
    UPDATE app.t_account_membership
    SET status = 'active',
        invitation_token_hash = NULL,  -- Clear token
        joined_at = NOW(),
        updated_at = NOW(),
        updated_by = v_current_user
    WHERE membership_id = v_membership_record.membership_id;
    
    -- [AUDIT] ISO 27001: Log acceptance
    INSERT INTO core.t_audit_trail (
        table_name,
        record_id,
        action,
        new_values,
        performed_by,
        performed_at
    ) VALUES (
        'app.t_account_membership',
        v_membership_record.membership_id,
        'INVITATION_ACCEPT',
        jsonb_build_object(
            'user_agent', p_user_agent,
            'ip_address', p_ip_address::TEXT
        ),
        v_current_user,
        NOW()
    );
    
    RETURN QUERY SELECT 
        TRUE, 
        v_membership_record.membership_id, 
        v_membership_record.app_id,
        'Invitation accepted successfully'::TEXT;
END;
$$;

COMMENT ON FUNCTION app.accept_invitation IS 
    'Accept a membership invitation. ISO 27001 A.9.2.1.';

-- =============================================================================
-- FUNCTION: Assign Role to Membership
-- ISO 27001 A.9.2.2: Access provisioning
-- =============================================================================

CREATE OR REPLACE FUNCTION app.assign_role(
    p_membership_id UUID,
    p_role_id UUID,
    p_assignment_type VARCHAR(20) DEFAULT 'direct',
    p_valid_from TIMESTAMPTZ DEFAULT NOW(),
    p_valid_until TIMESTAMPTZ DEFAULT NULL,
    p_justification TEXT DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_assignment_id UUID;
    v_current_membership UUID;
    v_current_user UUID;
    v_role_exists BOOLEAN;
    v_target_app_id UUID;
    v_target_membership RECORD;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_membership := current_setting('app.current_membership_id', TRUE)::UUID;
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Get target membership details
    SELECT app_id, user_identity_id, status INTO v_target_membership
    FROM app.t_account_membership
    WHERE membership_id = p_membership_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION '[NOT_FOUND] Membership % not found', p_membership_id;
    END IF;
    
    v_target_app_id := v_target_membership.app_id;
    
    -- Authorization check
    IF NOT app.check_permission(v_current_membership, 'app:role_assignment:create') THEN
        RAISE EXCEPTION '[RBAC] Insufficient privileges to assign roles';
    END IF;
    
    -- Verify role exists and is active
    SELECT EXISTS(
        SELECT 1 FROM app.t_roles_permissions 
        WHERE role_id = p_role_id 
          AND status = 'active'
          AND (app_id IS NULL OR app_id = v_target_app_id)
    ) INTO v_role_exists;
    
    IF NOT v_role_exists THEN
        RAISE EXCEPTION '[NOT_FOUND] Role % not found or not active', p_role_id;
    END IF;
    
    -- Check for existing active assignment
    IF EXISTS (
        SELECT 1 FROM app.t_user_role_assignments
        WHERE membership_id = p_membership_id
          AND role_id = p_role_id
          AND is_revoked = FALSE
          AND approval_status = 'approved'
    ) THEN
        RAISE EXCEPTION '[CONFLICT] Role already assigned to this membership';
    END IF;
    
    -- Validate assignment type
    IF p_assignment_type NOT IN ('direct', 'inherited', 'delegated', 'temporary') THEN
        RAISE EXCEPTION '[VALIDATION] Invalid assignment type: %', p_assignment_type;
    END IF;
    
    -- Validate temporal bounds
    IF p_valid_until IS NOT NULL AND p_valid_until <= p_valid_from THEN
        RAISE EXCEPTION '[VALIDATION] valid_until must be after valid_from';
    END IF;
    
    -- Create assignment
    INSERT INTO app.t_user_role_assignments (
        membership_id,
        role_id,
        assignment_type,
        assignment_source,
        valid_from,
        valid_until,
        justification,
        approval_status,
        approved_at,
        approved_by,
        created_by,
        updated_by
    ) VALUES (
        p_membership_id,
        p_role_id,
        p_assignment_type,
        'manual',
        p_valid_from,
        p_valid_until,
        p_justification,
        'approved',  -- Auto-approved for now; workflow can be added
        NOW(),
        v_current_user,
        v_current_user,
        v_current_user
    )
    RETURNING app.t_user_role_assignments.assignment_id INTO v_assignment_id;
    
    -- [AUDIT] ISO 27001: Log role assignment
    INSERT INTO core.t_audit_trail (
        table_name,
        record_id,
        action,
        new_values,
        performed_by,
        performed_at
    ) VALUES (
        'app.t_user_role_assignments',
        v_assignment_id,
        'CREATE',
        jsonb_build_object(
            'membership_id', p_membership_id,
            'role_id', p_role_id,
            'assignment_type', p_assignment_type,
            'valid_from', p_valid_from,
            'valid_until', p_valid_until
        ),
        v_current_user,
        NOW()
    );
    
    -- Invalidate permission cache
    PERFORM pg_notify('permission_cache_invalidate', p_membership_id::TEXT);
    
    RETURN v_assignment_id;
END;
$$;

COMMENT ON FUNCTION app.assign_role IS 
    'Assign a role to a membership. ISO 27001 A.9.2.2: Access provisioning.';

-- =============================================================================
-- FUNCTION: Revoke Role Assignment
-- ISO 27001 A.9.2.6: Removal of access rights
-- =============================================================================

CREATE OR REPLACE FUNCTION app.revoke_role(
    p_assignment_id UUID,
    p_reason TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_current_membership UUID;
    v_current_user UUID;
    v_assignment RECORD;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_membership := current_setting('app.current_membership_id', TRUE)::UUID;
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Require reason
    IF p_reason IS NULL OR trim(p_reason) = '' THEN
        RAISE EXCEPTION '[VALIDATION] Revocation reason is required';
    END IF;
    
    -- Get assignment details
    SELECT * INTO v_assignment
    FROM app.t_user_role_assignments
    WHERE assignment_id = p_assignment_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION '[NOT_FOUND] Assignment % not found', p_assignment_id;
    END IF;
    
    -- Check if already revoked
    IF v_assignment.is_revoked THEN
        RAISE EXCEPTION '[STATE] Assignment is already revoked';
    END IF;
    
    -- Authorization check
    IF NOT app.check_permission(v_current_membership, 'app:role_assignment:delete') THEN
        RAISE EXCEPTION '[RBAC] Insufficient privileges to revoke roles';
    END IF;
    
    -- Revoke assignment (soft delete)
    UPDATE app.t_user_role_assignments
    SET is_revoked = TRUE,
        revoked_at = NOW(),
        revoked_by = v_current_user,
        revocation_reason = p_reason,
        updated_at = NOW(),
        updated_by = v_current_user
    WHERE assignment_id = p_assignment_id;
    
    -- [AUDIT] ISO 27001: Log revocation
    INSERT INTO core.t_audit_trail (
        table_name,
        record_id,
        action,
        old_values,
        new_values,
        performed_by,
        performed_at
    ) VALUES (
        'app.t_user_role_assignments',
        p_assignment_id,
        'REVOKE',
        jsonb_build_object('is_revoked', FALSE),
        jsonb_build_object(
            'is_revoked', TRUE,
            'reason', p_reason
        ),
        v_current_user,
        NOW()
    );
    
    -- Invalidate permission cache
    PERFORM pg_notify('permission_cache_invalidate', v_assignment.membership_id::TEXT);
    
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION app.revoke_role IS 
    'Revoke a role assignment. ISO 27001 A.9.2.6: Access removal.';

-- =============================================================================
-- FUNCTION: Transfer Ownership
-- ISO 27001: Privileged access transfer
-- =============================================================================

CREATE OR REPLACE FUNCTION app.transfer_ownership(
    p_app_id UUID,
    p_new_owner_membership_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_current_membership UUID;
    v_current_user UUID;
    v_current_owner_membership UUID;
    v_new_owner_app_id UUID;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_membership := current_setting('app.current_membership_id', TRUE)::UUID;
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Get current owner
    SELECT membership_id INTO v_current_owner_membership
    FROM app.t_account_membership
    WHERE app_id = p_app_id AND membership_type = 'owner' AND status = 'active';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION '[STATE] No active owner found for application';
    END IF;
    
    -- Get new owner's app
    SELECT app_id INTO v_new_owner_app_id
    FROM app.t_account_membership
    WHERE membership_id = p_new_owner_membership_id AND status = 'active';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION '[NOT_FOUND] New owner membership not found or not active';
    END IF;
    
    -- Verify new owner is in same app
    IF v_new_owner_app_id != p_app_id THEN
        RAISE EXCEPTION '[VALIDATION] New owner must be a member of the same application';
    END IF;
    
    -- Authorization: Must be current owner or platform admin
    IF v_current_membership != v_current_owner_membership THEN
        IF NOT app.check_permission(v_current_membership, 'platform:admin:manage') THEN
            RAISE EXCEPTION '[RBAC] Only current owner or platform admin can transfer ownership';
        END IF;
    END IF;
    
    -- Demote current owner to admin
    UPDATE app.t_account_membership
    SET membership_type = 'admin',
        updated_at = NOW(),
        updated_by = v_current_user
    WHERE membership_id = v_current_owner_membership;
    
    -- Promote new owner
    UPDATE app.t_account_membership
    SET membership_type = 'owner',
        updated_at = NOW(),
        updated_by = v_current_user
    WHERE membership_id = p_new_owner_membership_id;
    
    -- Update application owner reference
    UPDATE app.t_application_registry
    SET default_owner_account_id = p_new_owner_membership_id,
        updated_at = NOW(),
        updated_by = v_current_user
    WHERE app_id = p_app_id;
    
    -- [AUDIT] ISO 27001: Log ownership transfer
    INSERT INTO core.t_audit_trail (
        table_name,
        record_id,
        action,
        old_values,
        new_values,
        performed_by,
        performed_at,
        severity
    ) VALUES (
        'app.t_application_registry',
        p_app_id,
        'OWNERSHIP_TRANSFER',
        jsonb_build_object('previous_owner', v_current_owner_membership),
        jsonb_build_object('new_owner', p_new_owner_membership_id),
        v_current_user,
        NOW(),
        'high'
    );
    
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION app.transfer_ownership IS 
    'Transfer application ownership. ISO 27001: Privileged access transfer.';

-- =============================================================================
-- FUNCTION: Suspend Membership
-- ISO 27001: Access suspension
-- =============================================================================

CREATE OR REPLACE FUNCTION app.suspend_membership(
    p_membership_id UUID,
    p_reason TEXT,
    p_duration_hours INTEGER DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_current_membership UUID;
    v_current_user UUID;
    v_old_status VARCHAR(20);
    v_target_app_id UUID;
    v_suspended_until TIMESTAMPTZ;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_membership := current_setting('app.current_membership_id', TRUE)::UUID;
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Require reason
    IF p_reason IS NULL OR trim(p_reason) = '' THEN
        RAISE EXCEPTION '[VALIDATION] Suspension reason is required';
    END IF;
    
    -- Get current status
    SELECT status, app_id INTO v_old_status, v_target_app_id
    FROM app.t_account_membership
    WHERE membership_id = p_membership_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION '[NOT_FOUND] Membership % not found', p_membership_id;
    END IF;
    
    IF v_old_status != 'active' THEN
        RAISE EXCEPTION '[STATE] Can only suspend active memberships';
    END IF;
    
    -- Authorization check
    IF NOT app.check_permission(v_current_membership, 'app:membership:manage') THEN
        RAISE EXCEPTION '[RBAC] Insufficient privileges to suspend memberships';
    END IF;
    
    -- Calculate suspension end
    IF p_duration_hours IS NOT NULL THEN
        v_suspended_until := NOW() + (p_duration_hours || ' hours')::INTERVAL;
    END IF;
    
    -- Suspend membership
    UPDATE app.t_account_membership
    SET status = 'suspended',
        status_reason = p_reason || COALESCE(' (until ' || v_suspended_until::TEXT || ')', ''),
        suspended_at = NOW(),
        updated_at = NOW(),
        updated_by = v_current_user
    WHERE membership_id = p_membership_id;
    
    -- Revoke all role assignments
    UPDATE app.t_user_role_assignments
    SET is_revoked = TRUE,
        revoked_at = NOW(),
        revoked_by = v_current_user,
        revocation_reason = 'Membership suspended: ' || p_reason
    WHERE membership_id = p_membership_id
      AND is_revoked = FALSE;
    
    -- [AUDIT] ISO 27001: Log suspension
    INSERT INTO core.t_audit_trail (
        table_name,
        record_id,
        action,
        old_values,
        new_values,
        performed_by,
        performed_at,
        severity
    ) VALUES (
        'app.t_account_membership',
        p_membership_id,
        'SUSPEND',
        jsonb_build_object('status', v_old_status),
        jsonb_build_object(
            'status', 'suspended',
            'reason', p_reason
        ),
        v_current_user,
        NOW(),
        'high'
    );
    
    -- Invalidate permission cache
    PERFORM pg_notify('permission_cache_invalidate', p_membership_id::TEXT);
    
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION app.suspend_membership IS 
    'Suspend a membership and revoke all roles. ISO 27001: Access control.';

-- =============================================================================
-- FUNCTION: Get User Effective Permissions
-- Helper for permission retrieval
-- =============================================================================

CREATE OR REPLACE FUNCTION app.get_user_permissions(p_membership_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = app, core, public
AS $$
DECLARE
    v_permissions JSONB;
BEGIN
    SELECT permissions INTO v_permissions
    FROM app.v_effective_permissions
    WHERE membership_id = p_membership_id;
    
    RETURN COALESCE(v_permissions, '[]'::JSONB);
END;
$$;

COMMENT ON FUNCTION app.get_user_permissions IS 
    'Get effective permissions for a membership.';

-- =============================================================================
-- FUNCTION: List User Memberships
-- Helper for user dashboard
-- =============================================================================

CREATE OR REPLACE FUNCTION app.list_user_memberships(p_user_identity_id UUID)
RETURNS TABLE (
    membership_id UUID,
    app_id UUID,
    app_code VARCHAR(50),
    app_name VARCHAR(255),
    membership_type VARCHAR(30),
    status VARCHAR(20),
    primary_role_name VARCHAR(255)
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = app, core, public
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        am.membership_id,
        am.app_id,
        ar.app_code,
        ar.app_name,
        am.membership_type,
        am.status,
        rp.role_name as primary_role_name
    FROM app.t_account_membership am
    INNER JOIN app.t_application_registry ar ON am.app_id = ar.app_id
    LEFT JOIN app.t_roles_permissions rp ON am.primary_role_id = rp.role_id
    WHERE am.user_identity_id = p_user_identity_id
    ORDER BY 
        CASE am.status 
            WHEN 'active' THEN 1 
            WHEN 'pending' THEN 2 
            ELSE 3 
        END,
        ar.app_name;
END;
$$;

COMMENT ON FUNCTION app.list_user_memberships IS 
    'List all memberships for a user across applications.';

-- =============================================================================
-- ANALYZE for query optimizer
-- =============================================================================
ANALYZE app.t_account_membership;
ANALYZE app.t_user_role_assignments;
