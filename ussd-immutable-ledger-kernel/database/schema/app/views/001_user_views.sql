/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - VIEW: USER VIEWS
 * =============================================================================
 * 
 * Feature:      CORE-APP-VIEW-005
 * Description:  User-centric views for membership, role assignments, and
 *               permission management. Supports user dashboards and
 *               self-service access reviews.
 * 
 * Version:      1.0.0
 * Author:       Eng. llunzwe
 * Created:      2026-03-30
 * Last Modified: 2026-03-30
 * 
 * =============================================================================
 * COMPLIANCE & CERTIFICATIONS
 * =============================================================================
 * 
 * ISO/IEC 27001:2022 (ISMS)
 *   - Control A.5.18: Access rights
 *   - Control A.9.2.1: User registration
 *   - Control A.9.2.5: Review of access rights
 * 
 * GDPR (General Data Protection Regulation)
 *   - Article 15: Right of access
 *   - Article 17: Right to erasure
 * 
 * SOC 2 Type II
 *   - CC6.1: Logical access controls
 *   - CC6.2: Access provisioning
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - app.t_account_membership
 *   - app.t_user_role_assignments
 *   - app.t_roles_permissions
 *   - app.t_application_registry
 *   - core.t_user_identity
 * 
 * =============================================================================
 */

-- =============================================================================
-- COMPLIANCE STANDARDS
-- =============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework
-- GDPR - Data Protection
-- SOC 2 Type II - Security Controls
-- =============================================================================

-- =============================================================================
-- VIEW: User Membership Details
-- ISO 27001: User access overview
-- =============================================================================

CREATE OR REPLACE VIEW app.v_user_memberships AS
SELECT 
    -- Membership identifiers
    am.membership_id,
    am.user_identity_id,
    
    -- Application context
    am.app_id,
    ar.app_code,
    ar.app_name,
    ar.ledger_tenant_id,
    
    -- Membership details
    am.membership_type,
    am.membership_scope,
    am.org_unit_id,
    
    -- Hierarchy
    am.parent_membership_id,
    am.hierarchy_level,
    
    -- Roles
    am.primary_role_id,
    pr.role_name as primary_role_name,
    pr.role_code as primary_role_code,
    am.secondary_role_ids,
    
    -- Status
    am.status,
    am.status_reason,
    
    -- Lifecycle dates
    am.invited_at,
    am.joined_at,
    am.suspended_at,
    am.revoked_at,
    am.onboarding_completed_at,
    
    -- Invitation
    am.invited_by,
    inviter.email as invited_by_email,
    am.invitation_expires_at,
    
    -- Permissions override
    am.custom_permissions,
    am.entitlement_overrides,
    
    -- Audit
    am.version,
    am.created_at,
    am.created_by,
    am.updated_at,
    am.updated_by,
    
    -- Computed fields
    CASE 
        WHEN am.status = 'active' THEN TRUE
        ELSE FALSE
    END as is_active,
    
    CASE 
        WHEN am.status = 'pending' AND am.invitation_expires_at < NOW() THEN TRUE
        ELSE FALSE
    END as invitation_expired,
    
    CASE 
        WHEN am.joined_at IS NOT NULL THEN
            EXTRACT(EPOCH FROM (NOW() - am.joined_at)) / 86400
        ELSE NULL
    END::INTEGER as days_as_member

FROM app.t_account_membership am
INNER JOIN app.t_application_registry ar ON am.app_id = ar.app_id
LEFT JOIN app.t_roles_permissions pr ON am.primary_role_id = pr.role_id
LEFT JOIN core.t_user_identity inviter ON am.invited_by = inviter.user_identity_id
WHERE am.deleted_at IS NULL
  AND ar.deleted_at IS NULL;

COMMENT ON VIEW app.v_user_memberships IS 
    'User membership details across applications. ' ||
    'ISO 27001: Access rights overview. Feature: CORE-APP-VIEW-005';

-- =============================================================================
-- VIEW: Active Role Assignments with Details
-- ISO 27001 A.9.2.2: Access provisioning visibility
-- =============================================================================

CREATE OR REPLACE VIEW app.v_role_assignments_detail AS
SELECT 
    -- Assignment identifiers
    ra.assignment_id,
    ra.membership_id,
    
    -- User context
    am.user_identity_id,
    ui.email as user_email,
    ui.display_name as user_display_name,
    
    -- Application context
    am.app_id,
    ar.app_code,
    ar.app_name,
    
    -- Role details
    ra.role_id,
    rp.role_name,
    rp.role_code,
    rp.role_type,
    rp.role_category,
    rp.permissions as role_permissions,
    
    -- Assignment details
    ra.assignment_type,
    ra.assignment_source,
    
    -- Temporal validity
    ra.valid_from,
    ra.valid_until,
    CASE 
        WHEN ra.valid_from <= NOW() 
         AND (ra.valid_until IS NULL OR ra.valid_until > NOW())
        THEN TRUE
        ELSE FALSE
    END as is_temporally_valid,
    
    -- Delegation
    ra.delegated_from_assignment_id,
    ra.delegation_depth,
    ra.delegation_constraints,
    
    -- Approval
    ra.approval_status,
    ra.approved_by,
    approver.email as approved_by_email,
    ra.approved_at,
    
    -- Resource scope
    ra.resource_scope,
    
    -- Justification
    ra.justification,
    ra.business_reason,
    ra.ticket_reference,
    
    -- Revocation
    ra.is_revoked,
    ra.revoked_at,
    ra.revoked_by,
    ra.revocation_reason,
    
    -- Break-glass
    ra.is_break_glass,
    ra.break_glass_expires_at,
    CASE 
        WHEN ra.is_break_glass AND ra.break_glass_expires_at > NOW() 
        THEN TRUE 
        ELSE FALSE 
    END as break_glass_active,
    
    -- Audit
    ra.version,
    ra.created_at,
    ra.created_by,
    ra.updated_at,
    ra.updated_by,
    
    -- Computed status
    CASE 
        WHEN ra.is_revoked THEN 'revoked'
        WHEN ra.approval_status != 'approved' THEN ra.approval_status
        WHEN NOT (ra.valid_from <= NOW() AND (ra.valid_until IS NULL OR ra.valid_until > NOW())) 
            THEN 'expired'
        WHEN ra.is_break_glass AND ra.break_glass_expires_at <= NOW() 
            THEN 'break_glass_expired'
        ELSE 'active'
    END as effective_status,
    
    NOW() as calculated_at

FROM app.t_user_role_assignments ra
INNER JOIN app.t_account_membership am ON ra.membership_id = am.membership_id
INNER JOIN app.t_roles_permissions rp ON ra.role_id = rp.role_id
INNER JOIN app.t_application_registry ar ON am.app_id = ar.app_id
LEFT JOIN core.t_user_identity ui ON am.user_identity_id = ui.user_identity_id
LEFT JOIN core.t_user_identity approver ON ra.approved_by = approver.user_identity_id
WHERE ra.deleted_at IS NULL
  AND am.deleted_at IS NULL
  AND rp.deleted_at IS NULL;

COMMENT ON VIEW app.v_role_assignments_detail IS 
    'Detailed role assignments with user and role context. ' ||
    'ISO 27001 A.9.2.2: Access provisioning visibility.';

-- =============================================================================
-- VIEW: Effective User Permissions (Aggregated)
-- ISO 27001: Permission review support
-- =============================================================================

CREATE OR REPLACE VIEW app.v_user_permissions AS
WITH active_assignments AS (
    SELECT 
        ra.membership_id,
        ra.role_id,
        rp.permissions as role_permissions,
        ra.is_break_glass,
        ra.resource_scope,
        -- Priority: break-glass > direct > delegated > inherited
        CASE ra.assignment_type
            WHEN 'break_glass' THEN 1
            WHEN 'direct' THEN 2
            WHEN 'delegated' THEN 3
            WHEN 'inherited' THEN 4
            ELSE 5
        END as assignment_priority
    FROM app.t_user_role_assignments ra
    INNER JOIN app.t_roles_permissions rp ON ra.role_id = rp.role_id
    WHERE ra.is_revoked = FALSE
      AND ra.approval_status = 'approved'
      AND ra.valid_from <= NOW()
      AND (ra.valid_until IS NULL OR ra.valid_until > NOW())
      AND (ra.is_break_glass = FALSE OR ra.break_glass_expires_at > NOW())
)
SELECT 
    am.membership_id,
    am.user_identity_id,
    ui.email as user_email,
    ui.display_name as user_name,
    
    am.app_id,
    ar.app_code,
    ar.app_name,
    
    -- Aggregate permissions from all roles
    jsonb_agg(
        DISTINCT jsonb_build_object(
            'role_id', aa.role_id,
            'is_break_glass', aa.is_break_glass,
            'resource_scope', aa.resource_scope,
            'priority', aa.assignment_priority
        )
    ) as role_assignments,
    
    -- Count of active roles
    COUNT(DISTINCT aa.role_id) as active_role_count,
    
    -- Break-glass indicator
    BOOL_OR(aa.is_break_glass) as has_break_glass_access,
    
    -- Calculated at
    NOW() as calculated_at

FROM app.t_account_membership am
INNER JOIN app.t_application_registry ar ON am.app_id = ar.app_id
LEFT JOIN core.t_user_identity ui ON am.user_identity_id = ui.user_identity_id
LEFT JOIN active_assignments aa ON am.membership_id = aa.membership_id
WHERE am.status = 'active'
  AND am.deleted_at IS NULL
GROUP BY am.membership_id, am.user_identity_id, ui.email, ui.display_name,
         am.app_id, ar.app_code, ar.app_name;

COMMENT ON VIEW app.v_user_permissions IS 
    'Aggregated user permissions across all active roles. ' ||
    'ISO 27001: Permission review support.';

-- =============================================================================
-- VIEW: Pending Invitations
-- Invitation management dashboard
-- =============================================================================

CREATE OR REPLACE VIEW app.v_pending_invitations AS
SELECT 
    am.membership_id,
    am.user_identity_id,
    ui.email as user_email,
    ui.display_name as user_name,
    
    am.app_id,
    ar.app_code,
    ar.app_name,
    
    am.membership_type,
    am.primary_role_id,
    rp.role_name as primary_role_name,
    
    am.invited_at,
    am.invitation_expires_at,
    
    -- Days until expiry
    CASE 
        WHEN am.invitation_expires_at > NOW() 
        THEN EXTRACT(EPOCH FROM (am.invitation_expires_at - NOW())) / 86400
        ELSE -1  -- Expired
    END::INTEGER as days_until_expiry,
    
    -- Expiry status
    CASE 
        WHEN am.invitation_expires_at < NOW() THEN 'expired'
        WHEN am.invitation_expires_at < NOW() + INTERVAL '1 day' THEN 'expires_soon'
        ELSE 'valid'
    END as expiry_status,
    
    am.invited_by,
    inviter.email as invited_by_email,
    
    am.custom_message,
    
    -- Actions available
    jsonb_build_object(
        'can_resend', am.invitation_expires_at > NOW(),
        'can_cancel', TRUE,
        'can_extend', am.invitation_expires_at > NOW()
    ) as available_actions

FROM app.t_account_membership am
INNER JOIN app.t_application_registry ar ON am.app_id = ar.app_id
LEFT JOIN core.t_user_identity ui ON am.user_identity_id = ui.user_identity_id
LEFT JOIN core.t_user_identity inviter ON am.invited_by = inviter.user_identity_id
LEFT JOIN app.t_roles_permissions rp ON am.primary_role_id = rp.role_id
WHERE am.status = 'pending'
  AND am.deleted_at IS NULL
  AND am.invitation_token_hash IS NOT NULL
ORDER BY am.invitation_expires_at ASC;

COMMENT ON VIEW app.v_pending_invitations IS 
    'Pending membership invitations with expiry tracking.';

-- =============================================================================
-- VIEW: Membership Hierarchy
-- Organizational structure visualization
-- =============================================================================

CREATE OR REPLACE VIEW app.v_membership_hierarchy AS
WITH RECURSIVE hierarchy AS (
    -- Base: Top-level memberships (no parent)
    SELECT 
        membership_id,
        app_id,
        user_identity_id,
        parent_membership_id,
        hierarchy_level,
        membership_type,
        ARRAY[membership_id] as path
    FROM app.t_account_membership
    WHERE parent_membership_id IS NULL
      AND status = 'active'
      AND deleted_at IS NULL
    
    UNION ALL
    
    -- Recursive: Child memberships
    SELECT 
        am.membership_id,
        am.app_id,
        am.user_identity_id,
        am.parent_membership_id,
        am.hierarchy_level,
        am.membership_type,
        h.path || am.membership_id
    FROM app.t_account_membership am
    INNER JOIN hierarchy h ON am.parent_membership_id = h.membership_id
    WHERE am.status = 'active'
      AND am.deleted_at IS NULL
      AND NOT am.membership_id = ANY(h.path)  -- Prevent cycles
)

SELECT 
    h.membership_id,
    h.app_id,
    ar.app_code,
    h.user_identity_id,
    ui.email as user_email,
    ui.display_name as user_name,
    
    h.parent_membership_id,
    parent_ui.display_name as parent_user_name,
    
    h.hierarchy_level,
    h.path as hierarchy_path,
    
    h.membership_type,
    
    -- Tree depth
    array_length(h.path, 1) - 1 as tree_depth,
    
    -- Is root
    CASE WHEN h.parent_membership_id IS NULL THEN TRUE ELSE FALSE END as is_root,
    
    -- Has children
    EXISTS (
        SELECT 1 FROM app.t_account_membership child 
        WHERE child.parent_membership_id = h.membership_id
          AND child.status = 'active'
          AND child.deleted_at IS NULL
    ) as has_children

FROM hierarchy h
INNER JOIN app.t_application_registry ar ON h.app_id = ar.app_id
LEFT JOIN core.t_user_identity ui ON h.user_identity_id = ui.user_identity_id
LEFT JOIN app.t_account_membership parent ON h.parent_membership_id = parent.membership_id
LEFT JOIN core.t_user_identity parent_ui ON parent.user_identity_id = parent_ui.user_identity_id
ORDER BY h.path;

COMMENT ON VIEW app.v_membership_hierarchy IS 
    'Hierarchical view of membership delegation chains.';

-- =============================================================================
-- VIEW: Access Review Report
-- ISO 27001 A.9.2.5: Review of access rights
-- =============================================================================

CREATE OR REPLACE VIEW app.v_access_review AS
SELECT 
    am.membership_id,
    am.user_identity_id,
    ui.email as user_email,
    ui.display_name as user_name,
    
    am.app_id,
    ar.app_code,
    ar.app_name,
    
    am.membership_type,
    am.status as membership_status,
    
    -- Role summary
    am.primary_role_id,
    pr.role_name as primary_role_name,
    am.secondary_role_ids,
    
    -- Active role count
    COALESCE(role_counts.active_roles, 0) as active_role_count,
    
    -- Last activity (placeholder - would need session/audit data)
    am.updated_at as last_modified,
    
    -- Risk indicators
    CASE 
        WHEN am.membership_type = 'owner' THEN 'high'
        WHEN am.membership_type = 'admin' THEN 'medium'
        ELSE 'low'
    END as access_risk_level,
    
    -- Review recommendations
    CASE 
        WHEN am.status = 'suspended' AND am.suspended_at < NOW() - INTERVAL '90 days' 
            THEN 'recommend_revoke'
        WHEN am.joined_at IS NULL AND am.invited_at < NOW() - INTERVAL '30 days'
            THEN 'recommend_cancel_invitation'
        WHEN am.updated_at < NOW() - INTERVAL '180 days' AND am.membership_type IN ('owner', 'admin')
            THEN 'recommend_review'
        ELSE 'no_action'
    END as review_recommendation,
    
    -- Review metadata
    NOW() as review_date,
    'automated' as review_type

FROM app.t_account_membership am
INNER JOIN app.t_application_registry ar ON am.app_id = ar.app_id
LEFT JOIN core.t_user_identity ui ON am.user_identity_id = ui.user_identity_id
LEFT JOIN app.t_roles_permissions pr ON am.primary_role_id = pr.role_id
LEFT JOIN (
    SELECT 
        membership_id,
        COUNT(*) as active_roles
    FROM app.t_user_role_assignments
    WHERE is_revoked = FALSE
      AND approval_status = 'approved'
    GROUP BY membership_id
) role_counts ON am.membership_id = role_counts.membership_id
WHERE am.deleted_at IS NULL
  AND am.status IN ('active', 'suspended', 'pending');

COMMENT ON VIEW app.v_access_review IS 
    'Access review report for periodic access rights review. ' ||
    'ISO 27001 A.9.2.5: Review of access rights.';

-- =============================================================================
-- VIEW: User Activity Summary
-- User dashboard support
-- =============================================================================

CREATE OR REPLACE VIEW app.v_user_activity_summary AS
SELECT 
    ui.user_identity_id,
    ui.email,
    ui.display_name,
    
    -- Membership counts
    COUNT(DISTINCT am.membership_id) FILTER (WHERE am.status = 'active') as active_memberships,
    COUNT(DISTINCT am.membership_id) FILTER (WHERE am.status = 'pending') as pending_invitations,
    
    -- Application access
    COUNT(DISTINCT am.app_id) FILTER (WHERE am.status = 'active') as accessible_apps,
    
    -- Role summary
    COUNT(DISTINCT ra.role_id) FILTER (WHERE ra.is_revoked = FALSE) as total_roles,
    BOOL_OR(ra.is_break_glass) FILTER (WHERE ra.is_revoked = FALSE) as has_break_glass,
    
    -- Ownership
    BOOL_OR(am.membership_type = 'owner') FILTER (WHERE am.status = 'active') as is_app_owner,
    BOOL_OR(am.membership_type = 'admin') FILTER (WHERE am.status = 'active') as is_app_admin,
    
    -- Last activity
    MAX(am.updated_at) as last_activity,
    
    -- Account status
    CASE 
        WHEN NOT EXISTS (
            SELECT 1 FROM app.t_account_membership m 
            WHERE m.user_identity_id = ui.user_identity_id 
              AND m.status = 'active'
        ) THEN 'no_active_memberships'
        ELSE 'active'
    END as account_status

FROM core.t_user_identity ui
LEFT JOIN app.t_account_membership am ON ui.user_identity_id = am.user_identity_id
LEFT JOIN app.t_user_role_assignments ra ON am.membership_id = ra.membership_id
WHERE ui.deleted_at IS NULL
GROUP BY ui.user_identity_id, ui.email, ui.display_name;

COMMENT ON VIEW app.v_user_activity_summary IS 
    'User activity summary for dashboard and user management.';

-- =============================================================================
-- GRANTS
-- =============================================================================
-- Note: Actual grants depend on role setup
-- GRANT SELECT ON app.v_user_memberships TO app_readonly;
-- GRANT SELECT ON app.v_role_assignments_detail TO app_readonly;

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. All views join to user identity table for user details
-- 2. Soft-deleted records filtered at each level
-- 3. Recursive CTE for hierarchy handles up to 100 levels (PostgreSQL default)
-- 4. Permission aggregation uses JSONB for flexibility
-- 5. Review recommendations based on organizational policy thresholds
-- =============================================================================
