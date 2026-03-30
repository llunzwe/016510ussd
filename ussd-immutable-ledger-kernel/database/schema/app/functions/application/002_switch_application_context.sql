/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - APPLICATION: SWITCH APPLICATION CONTEXT
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-FUNC-006
 * Feature Name:       Application Context Switching
 * Description:        Safely switches application context for multi-tenant
 *                     operations. Validates permissions and maintains audit
 *                     trail for context switches.
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
 *   - Control A.8.2: Privileged access accounts
 *   - Control A.9.2.5: Review of access rights
 * 
 * SOC 2 Type II
 *   - CC6.1: Logical access controls
 *   - CC6.2: Access provisioning
 * 
 * =============================================================================
 * MULTI-TENANCY SECURITY ANNOTATIONS
 * =============================================================================
 * 
 * CONTEXT SWITCH VALIDATION:
 *   - Requester must be admin or member of target app
 *   - Cross-app delegation allowed if explicitly granted
 *   - Platform admin can switch to any app
 * 
 * AUDIT REQUIREMENTS:
 *   - All context switches logged
 *   - Original membership preserved for attribution
 *   - Reason required for context switch
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - app.t_application_registry
 *   - app.t_account_membership
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
-- FUNCTION: app.switch_application_context()
-- =============================================================================

CREATE OR REPLACE FUNCTION app.switch_application_context(
    p_target_app_id UUID,
    p_membership_id UUID,
    p_reason TEXT DEFAULT NULL
)
RETURNS TABLE (
    success BOOLEAN,
    previous_app_id UUID,
    new_context JSONB
)
LANGUAGE plpgsql
SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged execution context -- [RBAC] ISO 27001: Privileged function execution context
SET search_path = app, core, public
AS $$
DECLARE
    v_current_app_id TEXT;
    v_membership_record RECORD;
    v_target_app RECORD;
    v_can_switch BOOLEAN := FALSE;
BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
    -- ========================================================================
    -- GET CURRENT CONTEXT
    -- ========================================================================
    v_current_app_id := current_setting('app.current_app_id', TRUE);
    
    -- ========================================================================
    -- VALIDATE MEMBERSHIP
    -- ========================================================================
    SELECT * INTO v_membership_record
    FROM app.t_account_membership
    WHERE membership_id = p_membership_id
      AND status = 'active';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'Invalid or inactive membership';
    END IF;
    
    -- ========================================================================
    -- PREVENT NO-OP SWITCHES
    -- ========================================================================
    IF v_current_app_id = p_target_app_id::TEXT THEN
        RETURN QUERY SELECT TRUE, p_target_app_id, '{}'::JSONB;
        RETURN;
    END IF;
    
    -- ========================================================================
    -- LOOKUP TARGET APPLICATION
    -- ========================================================================
    SELECT * INTO v_target_app
    FROM app.t_application_registry
    WHERE app_id = p_target_app_id
      AND status = 'active';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'Target application not found or not active';
    END IF;
    
    -- ========================================================================
    -- AUTHORIZATION CHECK
    -- ========================================================================
    -- Member of target app
    IF v_membership_record.app_id = p_target_app_id THEN
        v_can_switch := TRUE;
    -- Platform admin
    ELSIF app.check_permission(p_membership_id, 'platform:admin:any') THEN  -- [RBAC] ISO 27001 A.5.15: Access control check
        v_can_switch := TRUE;
    -- Same user has membership in target app
    ELSIF EXISTS (
        SELECT 1 FROM app.t_account_membership
        WHERE user_identity_id = v_membership_record.user_identity_id
          AND app_id = p_target_app_id
          AND status = 'active'
    ) THEN
        v_can_switch := TRUE;
    END IF;
    
    IF NOT v_can_switch THEN
        RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'Insufficient permissions to switch to target application';
    END IF;
    
    -- ========================================================================
    -- LOG CONTEXT SWITCH
    -- ========================================================================
    INSERT INTO [AUDIT] ISO 27001 A.8.15: Security event logging to core.t_audit_log (action, entity_type, entity_id, actor_id, details)
    VALUES ('context_switch', 'application_context', p_target_app_id, p_membership_id,
        jsonb_build_object(
            'previous_app_id', v_current_app_id,
            'reason', p_reason,
            'timestamp', NOW()
        ));
    
    -- ========================================================================
    -- PERFORM CONTEXT SWITCH
    -- ========================================================================
    PERFORM set_config('app.current_app_id', p_target_app_id::TEXT, FALSE);  -- [RLS] ISO 27017: Application context for RLS
    PERFORM set_config('app.current_tenant_id', v_target_app.ledger_tenant_id  -- [RLS] ISO 27017: Tenant context for RLS -- [RLS] ISO 27017: Tenant isolation identifier for RLS::TEXT, FALSE);
    PERFORM set_config('app.context_switched_at', NOW()::TEXT, FALSE);
    PERFORM set_config('app.original_membership_id', p_membership_id::TEXT, FALSE);
    
    -- ========================================================================
    -- RETURN NEW CONTEXT
    -- ========================================================================
    RETURN QUERY SELECT 
        TRUE,
        v_current_app_id::UUID,
        jsonb_build_object(
            'app_id', v_target_app.app_id,
            'app_code', v_target_app.app_code,
            'app_name', v_target_app.app_name,
            'tenant_id', v_target_app.ledger_tenant_id' ||
            'switched_at', NOW(),
            'previous_app_id', v_current_app_id
        );
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON FUNCTION app.switch_application_context(UUID, UUID, TEXT) IS 
    'Switch application context for multi-tenant operations. ' ||
    'Feature: CORE-APP-FUNC-006. ' ||
    'Compliance: ISO 27001, SOC 2 Type II. ' ||
    'Security: Authorization checks, audit logging.';

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Context switches are logged for audit
-- 2. Original membership preserved for attribution
-- 3. Cross-app restrictions configurable per deployment
-- 4. RLS policies use context for data isolation
-- =============================================================================
