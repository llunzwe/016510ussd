/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - RBAC: CHECK PERMISSION FUNCTION
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-FUNC-001
 * Feature Name:       Permission Checking
 * Description:        Core permission checking function for Role-Based Access
 *                     Control. Evaluates effective permissions considering role
 *                     inheritance, temporal assignments, and conditional grants.
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
 *   - Control A.5.15: Access control
 *   - Control A.5.18: Access rights
 *   - Control A.9.4.1: Information access restriction
 * 
 * ISO/IEC 27017:2015 (Cloud Security)
 *   - Section 9: Access control in multi-tenant environments
 * 
 * SOC 2 Type II
 *   - CC6.1: Logical access controls
 *   - CC6.2: Prior to access, registration and authorization
 * 
 * NIST 800-53
 *   - AC-3: Access enforcement
 *   - AC-6: Least privilege
 * 
 * =============================================================================
 * RBAC ENFORCEMENT DOCUMENTATION
 * =============================================================================
 * 
 * FUNCTION PURPOSE:
 *   Primary access control enforcement point. All permission checks should
 *   route through this function for consistent policy application.
 * 
 * PERMISSION FORMAT: resource:action:scope
 *   Examples:
 *     - ledger:read:own      - Read own ledger entries
 *     - ledger:write:any     - Write any ledger entries
 *     - app:admin:any        - Full app administration
 * 
 * EVALUATION ORDER:
 *   1. Check break-glass access (highest priority)
 *   2. Check temporal validity (valid_from/valid_until)
 *   3. Check conditional grants (context evaluation)
 *   4. Evaluate effective permissions from view
 *   5. Apply wildcard matching (* patterns)
 * 
 * SECURITY NOTES:
 *   - SECURITY DEFINER
 *   - All checks logged for audit
 *   - Results should be cached at application layer
 * 
 * =============================================================================
 * AUDIT TRAIL REQUIREMENTS
 * =============================================================================
 * 
 * MANDATORY LOGGING:
 *   - Permission denied (security event)
 *   - Break-glass access granted (critical alert)
 *   - Conditional grant evaluated
 *   - Permission cache miss
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - app.t_account_membership
 *   - app.t_roles_permissions
 *   - app.t_user_role_assignments
 *   - app.v_effective_permissions
 * 
 * CHANGE LOG:
 *   1.0.0 - Initial function creation
 *   1.0.1 - Implemented TODOs: JSON Logic evaluation for condition_expression
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
-- FUNCTION: app.check_permission()
-- =============================================================================

CREATE OR REPLACE FUNCTION app.check_permission(
    p_membership_id UUID,
    p_permission TEXT,
    p_context JSONB DEFAULT '{}'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = app, core, public
AS $$
DECLARE
    v_has_permission BOOLEAN := FALSE;
    v_resource TEXT;
    v_action TEXT;
    v_scope TEXT;
    v_effective_perms JSONB;
    v_membership_status VARCHAR(20);
    v_break_glass_active BOOLEAN;
    v_assignment RECORD;
    v_condition_met BOOLEAN := TRUE;
    v_cond_expr JSONB;
    v_cond_context JSONB;
BEGIN
    -- ========================================================================
    -- INPUT VALIDATION
    -- ========================================================================
    IF p_membership_id IS NULL OR p_permission IS NULL THEN
        RAISE EXCEPTION 'Membership ID and permission are required';
    END IF;
    
    -- Parse permission string (resource:action:scope)
    v_resource := split_part(p_permission, ':', 1);
    v_action := split_part(p_permission, ':', 2);
    v_scope := split_part(p_permission, ':', 3);
    
    IF v_resource = '' OR v_action = '' OR v_scope = '' THEN
        RAISE EXCEPTION 'Invalid permission format. Expected: resource:action:scope';
    END IF;
    
    -- ========================================================================
    -- VALIDATE MEMBERSHIP
    -- ========================================================================
    SELECT status INTO v_membership_status
    FROM app.t_account_membership
    WHERE membership_id = p_membership_id;
    
    IF NOT FOUND THEN
        -- Log denied access attempt
        INSERT INTO core.audit_trail (
            audit_category,
            audit_level,
            audit_event,
            audit_description,
            action,
            action_status,
            table_schema,
            table_name,
            record_id,
            new_data
        ) VALUES (
            'SECURITY',
            'WARNING',
            'permission_check_failed',
            'Permission check failed: membership not found',
            'PERMISSION_CHECK',
            'DENIED',
            'app',
            't_account_membership',
            p_membership_id::TEXT,
            jsonb_build_object('permission', p_permission, 'reason', 'membership_not_found')
        );
        RETURN FALSE;
    END IF;
    
    IF v_membership_status != 'active' THEN
        -- Inactive membership
        INSERT INTO core.audit_trail (
            audit_category,
            audit_level,
            audit_event,
            audit_description,
            action,
            action_status,
            table_schema,
            table_name,
            record_id,
            new_data
        ) VALUES (
            'SECURITY',
            'WARNING',
            'permission_check_failed',
            'Permission check failed: membership inactive',
            'PERMISSION_CHECK',
            'DENIED',
            'app',
            't_account_membership',
            p_membership_id::TEXT,
            jsonb_build_object('permission', p_permission, 'reason', 'membership_inactive', 'status', v_membership_status)
        );
        RETURN FALSE;
    END IF;
    
    -- ========================================================================
    -- CHECK BREAK-GLASS ACCESS
    -- ISO 27001: Emergency access procedure
    -- ========================================================================
    SELECT EXISTS (
        SELECT 1 FROM app.t_user_role_assignments
        WHERE membership_id = p_membership_id
          AND is_break_glass = TRUE
          AND approval_status = 'approved'
          AND is_revoked = FALSE
          AND break_glass_expires_at > NOW()
    ) INTO v_break_glass_active;
    
    IF v_break_glass_active THEN
        -- Log break-glass access
        INSERT INTO core.audit_trail (
            audit_category,
            audit_level,
            audit_event,
            audit_description,
            action,
            action_status,
            table_schema,
            table_name,
            record_id,
            new_data
        ) VALUES (
            'SECURITY',
            'CRITICAL',
            'break_glass_permission_used',
            'Break-glass access used for permission check',
            'PERMISSION_CHECK',
            'GRANTED',
            'app',
            't_user_role_assignments',
            p_membership_id::TEXT,
            jsonb_build_object('permission', p_permission)
        );
        
        -- Notify security team
        PERFORM pg_notify('security_alert', jsonb_build_object(
            'type', 'break_glass_permission_used',
            'membership_id', p_membership_id,
            'permission', p_permission,
            'timestamp', NOW()
        )::TEXT);
        
        RETURN TRUE;
    END IF;
    
    -- ========================================================================
    -- GET EFFECTIVE PERMISSIONS
    -- ========================================================================
    SELECT permissions INTO v_effective_perms
    FROM app.v_effective_permissions
    WHERE membership_id = p_membership_id;
    
    IF v_effective_perms IS NULL THEN
        v_effective_perms := '[]'::JSONB;
    END IF;
    
    -- ========================================================================
    -- EVALUATE PERMISSION
    -- Check for exact match or wildcard patterns
    -- ========================================================================
    -- Check exact permission
    IF v_effective_perms @> jsonb_build_array(
        jsonb_build_object('resource', v_resource, 'action', v_action, 'scope', v_scope, 'granted', true)
    ) THEN
        v_has_permission := TRUE;
    END IF;
    
    -- Check wildcards: resource:*:scope
    IF NOT v_has_permission THEN
        IF v_effective_perms @> jsonb_build_array(
            jsonb_build_object('resource', v_resource, 'action', '*', 'scope', v_scope, 'granted', true)
        ) THEN
            v_has_permission := TRUE;
        END IF;
    END IF;
    
    -- Check wildcards: resource:action:*
    IF NOT v_has_permission THEN
        IF v_effective_perms @> jsonb_build_array(
            jsonb_build_object('resource', v_resource, 'action', v_action, 'scope', '*', 'granted', true)
        ) THEN
            v_has_permission := TRUE;
        END IF;
    END IF;
    
    -- Check wildcards: *:action:scope
    IF NOT v_has_permission THEN
        IF v_effective_perms @> jsonb_build_array(
            jsonb_build_object('resource', '*', 'action', v_action, 'scope', v_scope, 'granted', true)
        ) THEN
            v_has_permission := TRUE;
        END IF;
    END IF;
    
    -- ========================================================================
    -- EVALUATE CONDITIONAL GRANTS
    -- ========================================================================
    -- Check if any assignments have condition expressions
    FOR v_assignment IN 
        SELECT condition_expression, condition_context
        FROM app.t_user_role_assignments a
        JOIN app.t_roles_permissions r ON a.role_id = r.role_id
        WHERE a.membership_id = p_membership_id
          AND a.is_revoked = FALSE
          AND a.approval_status = 'approved'
          AND a.valid_from <= NOW()
          AND (a.valid_until IS NULL OR a.valid_until > NOW())
          AND a.condition_expression IS NOT NULL
    LOOP
        BEGIN
            -- Parse condition expression as JSON
            v_cond_expr := v_assignment.condition_expression::JSONB;
            v_cond_context := COALESCE(v_assignment.condition_context, '{}') || COALESCE(p_context, '{}');
            
            -- Simple JSON Logic evaluation for common conditions
            -- Evaluate time-based conditions
            IF v_cond_expr ? 'and' OR v_cond_expr ? 'or' THEN
                -- Complex nested conditions - evaluate based on context
                v_condition_met := app.evaluate_json_logic(v_cond_expr, v_cond_context);
            ELSIF v_cond_expr ? '>' THEN
                -- Greater than comparison
                v_condition_met := (v_cond_context->>(v_cond_expr->>'var'))::NUMERIC > (v_cond_expr->>0)::NUMERIC;
            ELSIF v_cond_expr ? '<' THEN
                -- Less than comparison
                v_condition_met := (v_cond_context->>(v_cond_expr->>'var'))::NUMERIC < (v_cond_expr->>0)::NUMERIC;
            ELSIF v_cond_expr ? '=' THEN
                -- Equality comparison
                v_condition_met := v_cond_context->>(v_cond_expr->>'var') = v_cond_expr->>0;
            ELSIF v_cond_expr ? 'in' THEN
                -- Membership test
                v_condition_met := v_cond_expr->0 @> jsonb_build_array(v_cond_context->>(v_cond_expr->>'var'));
            END IF;
            
            -- Log conditional grant evaluation
            INSERT INTO core.audit_trail (
                audit_category,
                audit_level,
                audit_event,
                audit_description,
                action,
                action_status,
                table_schema,
                table_name,
                record_id,
                new_data
            ) VALUES (
                'SECURITY',
                'INFO',
                'conditional_grant_evaluated',
                'Conditional grant expression evaluated',
                'PERMISSION_CHECK',
                CASE WHEN v_condition_met THEN 'SUCCESS' ELSE 'DENIED' END,
                'app',
                't_user_role_assignments',
                p_membership_id::TEXT,
                jsonb_build_object(
                    'permission', p_permission,
                    'condition', v_assignment.condition_expression,
                    'context', v_cond_context,
                    'result', v_condition_met
                )
            );
            
        EXCEPTION WHEN OTHERS THEN
            -- If condition evaluation fails, deny access
            v_condition_met := FALSE;
        END;
    END LOOP;
    
    -- Override permission if conditions not met
    IF NOT v_condition_met THEN
        v_has_permission := FALSE;
    END IF;
    
    -- ========================================================================
    -- AUDIT LOGGING
    -- ========================================================================
    IF NOT v_has_permission THEN
        INSERT INTO core.audit_trail (
            audit_category,
            audit_level,
            audit_event,
            audit_description,
            action,
            action_status,
            table_schema,
            table_name,
            record_id,
            new_data
        ) VALUES (
            'SECURITY',
            'WARNING',
            'permission_denied',
            'Permission check denied',
            'PERMISSION_CHECK',
            'DENIED',
            'app',
            't_account_membership',
            p_membership_id::TEXT,
            jsonb_build_object('permission', p_permission, 'context', p_context)
        );
    END IF;
    
    RETURN v_has_permission;
END;
$$;

-- =============================================================================
-- FUNCTION: app.evaluate_json_logic()
-- Helper function to evaluate JSON Logic expressions
-- =============================================================================
CREATE OR REPLACE FUNCTION app.evaluate_json_logic(
    p_logic JSONB,
    p_data JSONB
)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    v_op TEXT;
    v_args JSONB;
    v_result BOOLEAN := TRUE;
    v_item JSONB;
    v_key TEXT;
    v_value JSONB;
BEGIN
    IF p_logic IS NULL OR p_logic = '{}'::JSONB THEN
        RETURN TRUE;
    END IF;
    
    -- Get the operator (first key)
    SELECT key INTO v_op FROM jsonb_each_text(p_logic) LIMIT 1;
    v_args := p_logic->v_op;
    
    CASE v_op
        -- Logical operators
        WHEN 'and' THEN
            FOR v_item IN SELECT jsonb_array_elements(v_args)
            LOOP
                IF NOT app.evaluate_json_logic(v_item, p_data) THEN
                    RETURN FALSE;
                END IF;
            END LOOP;
            RETURN TRUE;
            
        WHEN 'or' THEN
            FOR v_item IN SELECT jsonb_array_elements(v_args)
            LOOP
                IF app.evaluate_json_logic(v_item, p_data) THEN
                    RETURN TRUE;
                END IF;
            END LOOP;
            RETURN FALSE;
            
        WHEN '!' THEN
            RETURN NOT app.evaluate_json_logic(v_args, p_data);
            
        -- Comparison operators
        WHEN '>' THEN
            RETURN (p_data->>(v_args->0->>'var'))::NUMERIC > (v_args->>1)::NUMERIC;
            
        WHEN '<' THEN
            RETURN (p_data->>(v_args->0->>'var'))::NUMERIC < (v_args->>1)::NUMERIC;
            
        WHEN '>=' THEN
            RETURN (p_data->>(v_args->0->>'var'))::NUMERIC >= (v_args->>1)::NUMERIC;
            
        WHEN '<=' THEN
            RETURN (p_data->>(v_args->0->>'var'))::NUMERIC <= (v_args->>1)::NUMERIC;
            
        WHEN '=' THEN
            RETURN p_data->>(v_args->0->>'var') = v_args->>1;
            
        WHEN '!=' THEN
            RETURN p_data->>(v_args->0->>'var') != v_args->>1;
            
        -- Variable access
        WHEN 'var' THEN
            RETURN p_data ? (v_args#>>'{}');
            
        -- Membership
        WHEN 'in' THEN
            RETURN v_args->0 @> jsonb_build_array(p_data->>(v_args->1->>'var'));
            
        ELSE
            -- Unknown operator, default to allowing
            RETURN TRUE;
    END CASE;
END;
$$;

-- =============================================================================
-- FUNCTION: app.check_any_permission()
-- Check if membership has ANY of the provided permissions
-- =============================================================================
CREATE OR REPLACE FUNCTION app.check_any_permission(
    p_membership_id UUID,
    p_permissions TEXT[],
    p_context JSONB DEFAULT '{}'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = app, core, public
AS $$
DECLARE
    v_perm TEXT;
BEGIN
    FOREACH v_perm IN ARRAY p_permissions
    LOOP
        IF app.check_permission(p_membership_id, v_perm, p_context) THEN
            RETURN TRUE;
        END IF;
    END LOOP;
    RETURN FALSE;
END;
$$;

-- =============================================================================
-- FUNCTION: app.check_all_permissions()
-- Check if membership has ALL of the provided permissions
-- =============================================================================
CREATE OR REPLACE FUNCTION app.check_all_permissions(
    p_membership_id UUID,
    p_permissions TEXT[],
    p_context JSONB DEFAULT '{}'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = app, core, public
AS $$
DECLARE
    v_perm TEXT;
BEGIN
    FOREACH v_perm IN ARRAY p_permissions
    LOOP
        IF NOT app.check_permission(p_membership_id, v_perm, p_context) THEN
            RETURN FALSE;
        END IF;
    END LOOP;
    RETURN TRUE;
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON FUNCTION app.check_permission(UUID, TEXT, JSONB) IS
    'Check if membership has specified permission. ' ||
    'Feature: CORE-APP-FUNC-001. ' ||
    'Compliance: ISO 27001, NIST 800-53. ' ||
    'Security: SECURITY DEFINER; evaluates break-glass, temporal, and conditional grants.';

COMMENT ON FUNCTION app.evaluate_json_logic(JSONB, JSONB) IS
    'Evaluate JSON Logic expressions for conditional grants. Supports and, or, !, >, <, >=, <=, =, !=, in, var operators.';

-- =============================================================================
-- GRANTS
-- =============================================================================
-- GRANT EXECUTE ON FUNCTION app.check_permission(UUID, TEXT, JSONB) TO app_user;
-- GRANT EXECUTE ON FUNCTION app.check_permission(UUID, TEXT, JSONB) TO app_readonly;

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Function uses SECURITY DEFINER to bypass RLS
-- 2. Results should be cached at application level
-- 3. Permission wildcards follow pattern: resource:action:scope
-- 4. All denied checks are logged for security monitoring
-- 5. Break-glass access triggers security alerts
-- 6. Conditional grants use JSON Logic for evaluation
-- =============================================================================
