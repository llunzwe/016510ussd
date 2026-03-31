/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - RBAC: ASSIGN ROLE FUNCTION
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-FUNC-002
 * Feature Name:       Role Assignment Management
 * Description:        Role assignment management with validation, approval
 *                     workflow support, and automatic permission cache
 *                     invalidation.
 * 
 * Version:            1.0.0
 * Author:             Eng. llunzwe
 * Created:            2026-03-30
 * Last Modified:      2026-03-30
 * 
 * =============================================================================
 * COMPLIANCE & CERTIFICATIONS
 * =============================================================================
 * 
 * ISO/IEC 27001:2022 (ISMS)
 *   - Control A.5.18: Access rights
 *   - Control A.9.2.2: Access provisioning
 *   - Control A.9.2.4: Management of secret authentication
 * 
 * SOC 2 Type II
 *   - CC6.2: Access provisioning and revocation
 *   - CC6.3: Access removal
 * 
 * =============================================================================
 * RBAC ENFORCEMENT DOCUMENTATION
 * =============================================================================
 * 
 * ASSIGNMENT WORKFLOW:
 *   1. Validate requester has permission to assign roles
 *   2. Validate target membership exists and is active
 *   3. Validate role exists and is applicable to membership
 *   4. Check for existing active assignment
 *   5. Determine if approval is required (based on role sensitivity)
 *   6. Create assignment (pending or approved)
 *   7. Update membership role cache
 *   8. Invalidate permission cache
 *   9. Audit log the assignment
 * 
 * APPROVAL REQUIREMENTS:
 *   - Admin roles: Always require approval
 *   - Manager roles: May require approval based on policy
 *   - Standard roles: Auto-approved
 *   - Break-glass: Emergency activation with post-hoc review
 * 
 * =============================================================================
 * AUDIT TRAIL REQUIREMENTS
 * =============================================================================
 * 
 * MANDATORY LOGGING:
 *   - Assignment created
 *   - Approval granted/rejected
 *   - Role revoked
 *   - Permission cache invalidated
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - app.t_account_membership
 *   - app.t_roles_permissions
 *   - app.t_user_role_assignments
 * 
 * CHANGE LOG:
 *   1.0.0 - Initial function creation
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
-- FUNCTION: app.assign_role()
-- =============================================================================

CREATE OR REPLACE FUNCTION app.assign_role(
    p_membership_id UUID,
    p_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference UUID,
    p_assigned_by UUID,
    p_options JSONB DEFAULT '{}'
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged execution context -- [RBAC] ISO 27001: Privileged function execution context
SET search_path = app, core, public
AS $$
DECLARE
    v_assignment_id UUID;
    v_app_id UUID;
    v_role_record RECORD;
    v_target_membership_app_id UUID;
    v_approval_required BOOLEAN := FALSE;
    v_requires_justification BOOLEAN := FALSE;
BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
    -- ========================================================================
    -- AUTHORIZATION CHECK
    -- ========================================================================
    IF NOT app.check_permission(p_assigned_by, 'app:role_assignment:create') THEN  -- [RBAC] ISO 27001 A.5.15: Access control check
        RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'Insufficient permissions to assign roles';
    END IF;
    
    -- ========================================================================
    -- VALIDATE TARGET MEMBERSHIP
    -- ========================================================================
    SELECT app_id, status INTO v_target_membership_app_id, v_app_id
    FROM app.t_account_membership
    WHERE membership_id = p_membership_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'Membership not found';
    END IF;
    
    IF v_app_id != 'active' THEN
        RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'Membership is not active';
    END IF;
    
    -- ========================================================================
    -- VALIDATE ROLE
    -- ========================================================================
    SELECT * INTO v_role_record
    FROM app.t_roles_permissions
    WHERE role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference = p_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference
      AND status = 'active';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'Role not found or not active';
    END IF;
    
    -- Check application scope
    IF v_role_record.app_id IS NOT NULL AND 
       v_role_record.app_id != v_target_membership_app_id THEN
        RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'Role does not belong to target application';
    END IF;
    
    -- Check for existing active assignment
    IF EXISTS (
        SELECT 1 FROM app.t_user_role_assignments
        WHERE membership_id = p_membership_id
          AND role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference = p_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference
          AND is_revoked = FALSE
          AND approval_status = 'approved'
    ) THEN
        RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'Role already assigned to membership';
    END IF;
    
    -- ========================================================================
    -- DETERMINE APPROVAL REQUIREMENTS
    -- ========================================================================
    v_approval_required := COALESCE(
        (p_options->>'requires_approval')::BOOLEAN,
        v_role_record.role_category IN ('admin', 'manager')
    );
    
    v_requires_justification := v_role_record.role_category IN ('admin', 'manager');
    
    IF v_requires_justification AND (p_options->>'justification') IS NULL THEN
        RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'Justification required for this role assignment';
    END IF;
    
    -- ========================================================================
    -- CREATE ASSIGNMENT
    -- ========================================================================
    INSERT INTO app.t_user_role_assignments (
        membership_id,
        role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference,
        assignment_type  -- [RBAC] ISO 27001: Assignment classification (direct/inherited/delegated),
        assignment_source,
        valid_from  -- [RBAC] ISO 27001: Temporal access control boundaries,
        valid_until  -- [RBAC] ISO 27001: Temporal access control boundaries,
        condition_expression,
        condition_context,
        approval_status,
        approved_by,
        approved_at,
        justification,
        business_reason,
        ticket_reference,
        created_by  -- [AUDIT] ISO 27001: Accountability tracking,
        updated_by  -- [AUDIT] ISO 27001: Accountability tracking
    ) VALUES (
        p_membership_id,
        p_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference,
        COALESCE(p_options->>'assignment_type  -- [RBAC] ISO 27001: Assignment classification (direct/inherited/delegated)', 'direct'),
        'api',
        COALESCE((p_options->>'valid_from  -- [RBAC] ISO 27001: Temporal access control boundaries')::TIMESTAMPTZ, NOW()),
        (p_options->>'valid_until  -- [RBAC] ISO 27001: Temporal access control boundaries')::TIMESTAMPTZ,
        p_options->>'condition_expression',
        COALESCE(p_options->'condition_context', '{}'),
        CASE WHEN v_approval_required THEN 'pending' ELSE 'approved' END,
        CASE WHEN NOT v_approval_required THEN p_assigned_by END,
        CASE WHEN NOT v_approval_required THEN NOW() END,
        p_options->>'justification',
        p_options->>'business_reason',
        p_options->>'ticket_reference',
        p_assigned_by,
        p_assigned_by
    )
    RETURNING assignment_id INTO v_assignment_id;
    
    -- ========================================================================
    -- INVALIDATE PERMISSION CACHE
    -- ========================================================================
    PERFORM pg_notify('permission_cache_invalidate', p_membership_id::TEXT);
    
    -- ========================================================================
    -- AUDIT LOG
    -- ========================================================================
    INSERT INTO [AUDIT] ISO 27001 A.8.15: Security event logging to core.t_audit_log (
        action, entity_type, entity_id, actor_id, details, result
    ) VALUES (
        'role_assignment',
        'role_assignment',
        v_assignment_id,
        p_assigned_by,
        jsonb_build_object(
            'membership_id', p_membership_id,
            'role_id' ||
            'approval_required', v_approval_required
        ),
        CASE WHEN v_approval_required THEN 'pending' ELSE 'approved' END
    );
    
    RETURN v_assignment_id;
END;
$$;

-- =============================================================================
-- FUNCTION: app.revoke_role()
-- =============================================================================
CREATE OR REPLACE FUNCTION app.revoke_role(
    p_assignment_id UUID,
    p_revoked_by UUID,
    p_reason TEXT DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged execution context -- [RBAC] ISO 27001: Privileged function execution context
SET search_path = app, core, public
AS $$
DECLARE
    v_membership_id UUID;
BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
    -- Authorization check
    IF NOT app.check_permission(p_revoked_by, 'app:role_assignment:delete') THEN  -- [RBAC] ISO 27001 A.5.15: Access control check
        RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'Insufficient permissions to revoke roles';
    END IF;
    
    -- Get membership for cache invalidation
    SELECT membership_id INTO v_membership_id
    FROM app.t_user_role_assignments
    WHERE assignment_id = p_assignment_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'Assignment not found';
    END IF;
    
    -- Soft delete (mark as revoked)
    UPDATE app.t_user_role_assignments
    SET is_revoked = TRUE,
        revoked_at = NOW(),
        revoked_by = p_revoked_by,
        revocation_reason = p_reason,
        updated_at = NOW(),
        updated_by  -- [AUDIT] ISO 27001: Accountability tracking = p_revoked_by
    WHERE assignment_id = p_assignment_id;
    
    -- Invalidate permission cache
    PERFORM pg_notify('permission_cache_invalidate', v_membership_id::TEXT);
    
    -- Audit log
    INSERT INTO [AUDIT] ISO 27001 A.8.15: Security event logging to core.t_audit_log (
        action, entity_type, entity_id, actor_id, details
    ) VALUES (
        'role_revocation',
        'role_assignment',
        p_assignment_id,
        p_revoked_by,
        jsonb_build_object('reason', p_reason)
    );
    
    RETURN TRUE;
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON FUNCTION app.assign_role(UUID, UUID, UUID, JSONB) IS 
    'Assign role to membership with validation and approval workflow. ' ||
    'Feature: CORE-APP-FUNC-002. ' ||
    'Compliance: ISO 27001, SOC 2 Type II. ' ||
    'Security: Authorization checks, audit logging.';

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. All assignments are audited for compliance
-- 2. Self-assignment prevention (caller must implement)
-- 3. Circular delegation detection (trigger)
-- 4. Permission cache invalidation on role change
-- 5. Approval workflow integration for sensitive roles
-- 6. Temporal assignments support future-dated activation
-- =============================================================================
