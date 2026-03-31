/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - VIEW: EFFECTIVE PERMISSIONS
 * =============================================================================
 * 
 * Feature:      CORE-APP-VIEW-002
 * Description:  Aggregated effective permissions for each membership,
 *               combining all active roles with proper handling of
 *               permission conflicts, scoping, and inheritance.
 * 
 * Version:      1.0.0
 * Author:       Platform Engineering Team
 * Created:      2026-03-30
 * 
 * DEPENDENCIES:
 *   - app.v_current_active_roles
 *   - app.t_roles_permissions
 *   - app.t_account_membership
 * 
 * CHANGE LOG:
 *   1.0.0 - Initial view creation
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
-- VIEW: app.v_effective_permissions
-- =============================================================================

DROP VIEW IF EXISTS app.v_effective_permissions CASCADE;

CREATE OR REPLACE VIEW app.v_effective_permissions AS

WITH active_roles AS (
    -- Get all active roles per membership from base view
    SELECT 
        membership_id,
        role_id,  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference
        role_code,
        inheritance_level,
        direct_permissions,
        resource_scope,
        assignment_type,  -- [RBAC] ISO 27001: Assignment classification (direct/inherited/delegated)
        is_break_glass,  -- [RBAC] ISO 27001: Emergency access indicator
        -- Priority: break_glass > direct > inherited
        CASE 
            WHEN is_break_glass THEN 0  -- [RBAC] ISO 27001: Emergency access indicator
            WHEN assignment_type = 'direct' THEN 1  -- [RBAC] ISO 27001: Assignment classification (direct/inherited/delegated)
            ELSE 2 + inheritance_level
        END as permission_priority
    FROM app.v_current_active_roles
    WHERE is_temporally_valid = TRUE
),

expanded_permissions AS (
    -- Expand JSON permission arrays into rows
    SELECT 
        ar.membership_id,
        ar.role_id,  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference
        ar.role_code,
        ar.permission_priority,
        ar.resource_scope,
        jsonb_array_elements(ar.direct_permissions) as permission,
        ar.is_break_glass,  -- [RBAC] ISO 27001: Emergency access indicator
        ar.assignment_type  -- [RBAC] ISO 27001: Assignment classification (direct/inherited/delegated)
    FROM active_roles ar
    WHERE ar.direct_permissions IS NOT NULL
      AND jsonb_array_length(ar.direct_permissions) > 0
),

permission_details AS (
    -- Extract permission details
    SELECT 
        ep.membership_id,
        ep.role_id,  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference
        ep.role_code,
        ep.permission_priority,
        ep.resource_scope,
        COALESCE(ep.permission->>'resource', '*') as resource,
        COALESCE(ep.permission->>'action', '*') as action,
        ep.permission->>'scope' as permission_scope,
        ep.permission->>'condition' as condition,
        COALESCE((ep.permission->>'deny')::BOOLEAN, FALSE) as is_deny,
        ep.is_break_glass,  -- [RBAC] ISO 27001: Emergency access indicator
        ep.assignment_type  -- [RBAC] ISO 27001: Assignment classification (direct/inherited/delegated)
    FROM expanded_permissions ep
),

aggregated_permissions AS (
    -- Aggregate permissions per membership, handling conflicts
    SELECT 
        pd.membership_id,
        pd.resource,
        pd.action,
        -- Deny overrides allow at same priority level
        BOOL_OR(pd.is_deny) as has_deny,
        BOOL_OR(NOT pd.is_deny) as has_allow,
        -- Collect all scopes
        ARRAY_AGG(DISTINCT pd.permission_scope) FILTER (WHERE pd.permission_scope IS NOT NULL AND NOT pd.is_deny) as allowed_scopes,
        -- Min priority wins
        MIN(pd.permission_priority) as effective_priority,
        -- Collect source roles
        ARRAY_AGG(DISTINCT pd.role_code) as source_roles,
        -- Check if any from break-glass
        BOOL_OR(pd.is_break_glass) as includes_break_glass,  -- [RBAC] ISO 27001: Emergency access indicator
        -- Collect conditions
        ARRAY_AGG(DISTINCT pd.condition) FILTER (WHERE pd.condition IS NOT NULL AND NOT pd.is_deny) as conditions
    FROM permission_details pd
    GROUP BY pd.membership_id, pd.resource, pd.action
)

SELECT 
    ap.membership_id,
    am.user_identity_id,
    am.app_id,
    am.app_code,
    
    -- Aggregated permissions as JSONB array
    jsonb_agg(
        jsonb_build_object(
            'resource', ap.resource,
            'action', ap.action,
            'granted', CASE 
                WHEN ap.has_deny AND ap.effective_priority > 0 THEN FALSE  -- Deny at low priority
                WHEN ap.has_deny AND NOT ap.has_allow THEN FALSE  -- Only deny
                ELSE ap.has_allow  -- Allow wins or no deny
            END,
            'scopes', COALESCE(ap.allowed_scopes, ARRAY[]::TEXT[]),
            'sources', ap.source_roles,
            'via_break_glass', ap.includes_break_glass,
            'priority', ap.effective_priority,
            'conditions', COALESCE(ap.conditions, ARRAY[]::TEXT[])
        )
    ) as permissions,
    
    -- Permission summary
    COUNT(DISTINCT ap.resource || ':' || ap.action) as total_permissions,
    COUNT(DISTINCT CASE WHEN ap.has_allow AND (NOT ap.has_deny OR ap.effective_priority = 0) THEN ap.resource || ':' || ap.action END) as allowed_count,
    COUNT(DISTINCT CASE WHEN ap.has_deny AND (NOT ap.has_allow OR ap.effective_priority > 0) THEN ap.resource || ':' || ap.action END) as denied_count,
    
    -- Metadata
    NOW() as calculated_at,
    MIN(ap.effective_priority) as max_role_priority  -- Lower number = higher priority

FROM aggregated_permissions ap
INNER JOIN app.t_account_membership am ON ap.membership_id = am.membership_id
INNER JOIN app.t_application_registry ar ON am.app_id = ar.app_id
GROUP BY ap.membership_id, am.user_identity_id, am.app_id, ar.app_code;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON VIEW app.v_effective_permissions IS 
    'Aggregated effective permissions per membership. Feature: CORE-APP-VIEW-002';

-- =============================================================================
-- HELPER FUNCTION: Check specific permission
-- =============================================================================

CREATE OR REPLACE FUNCTION app.has_effective_permission(
    p_membership_id UUID,
    p_resource TEXT,
    p_action TEXT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged function execution context
AS $$
    SELECT EXISTS (
        SELECT 1 
        FROM app.v_effective_permissions ep,
             jsonb_array_elements(ep.permissions) as perm
        WHERE ep.membership_id = p_membership_id
          AND perm->>'resource' = p_resource
          AND perm->>'action' = p_action
          AND (perm->>'granted')::BOOLEAN = TRUE
    );
$$;

-- =============================================================================
-- HELPER FUNCTION: Get membership permissions
-- =============================================================================

CREATE OR REPLACE FUNCTION app.get_membership_permissions(
    p_membership_id UUID
)
RETURNS JSONB
LANGUAGE SQL
STABLE
SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged function execution context
AS $$
    SELECT COALESCE(
        (SELECT permissions 
         FROM app.v_effective_permissions 
         WHERE membership_id = p_membership_id),
        '[]'::JSONB
    );
$$;

-- =============================================================================
-- HELPER FUNCTION: Check permission with wildcards
-- =============================================================================

CREATE OR REPLACE FUNCTION app.check_permission(
    p_membership_id UUID,
    p_resource TEXT,
    p_action TEXT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged function execution context
AS $$
    SELECT EXISTS (
        SELECT 1 
        FROM app.v_effective_permissions ep,
             jsonb_array_elements(ep.permissions) as perm
        WHERE ep.membership_id = p_membership_id
          AND (perm->>'granted')::BOOLEAN = TRUE
          AND (
              -- Exact match
              (perm->>'resource' = p_resource AND perm->>'action' = p_action)
              -- Wildcard resource
              OR (perm->>'resource' = '*' AND perm->>'action' = p_action)
              -- Wildcard action
              OR (perm->>'resource' = p_resource AND perm->>'action' = '*')
              -- Both wildcards
              OR (perm->>'resource' = '*' AND perm->>'action' = '*')
          )
    );
$$;

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Deny permissions override allows at same priority
-- 2. Break-glass permissions have highest priority (0)
-- 3. Direct assignments higher priority than inherited
-- 4. Lower inheritance_level = higher priority
-- 5. Resource scoping applied after permission calculation
-- 6. Results should be cached at application layer
-- =============================================================================
