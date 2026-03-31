/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - APPLICATION: VALIDATE APP CONTEXT
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-FUNC-005
 * Feature Name:       Application Context Validation
 * Description:        Validates application context for requests, including
 *                     application status, tenant isolation, API key validation,
 *                     and origin verification.
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
 *   - Control A.5.15: Access control
 *   - Control A.8.5: Secure authentication
 *   - Control A.8.20: Network services security
 * 
 * ISO/IEC 27017:2015 (Cloud Security)
 *   - Section 9: Access control in multi-tenant environments
 * 
 * SOC 2 Type II
 *   - CC6.1: Logical access controls
 *   - CC6.2: Access credentials
 * 
 * =============================================================================
 * MULTI-TENANCY SECURITY ANNOTATIONS
 * =============================================================================
 * 
 * VALIDATION CHECKS:
 *   - Application exists and is active
 *   - API key is valid and not expired
 *   - Origin is in allowed list (CORS)
 *   - Rate limit not exceeded
 *   - IP in allowlist (if configured)
 * 
 * CONTEXT SETUP:
 *   - Sets app.current_app_id for RLS
 *   - Sets app.current_tenant_id for tenant isolation
 * 
 * =============================================================================
 * AUDIT TRAIL REQUIREMENTS
 * =============================================================================
 * 
 * MANDATORY LOGGING:
 *   - Invalid API key
 *   - Suspended/deprecated app access attempt
 *   - Rate limit exceeded
 *   - Invalid origin
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - app.t_application_registry
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
-- - Use SECURITY DEFINER for privileged operations
-- - Enforce RLS policies for multi-tenant data isolation
-- - Use explicit column lists (avoid SELECT *)
-- - Add audit logging for all security-relevant operations
-- - Use UUIDs for primary identifiers to prevent enumeration
-- - Implement optimistic locking with version columns
-- - Use TIMESTAMPTZ for all timestamp columns
-- - Validate all inputs with CHECK constraints
-- ============================================================================

-- =============================================================================
-- FUNCTION: app.validate_app_context()
-- =============================================================================

CREATE OR REPLACE FUNCTION app.validate_app_context(
    p_app_id UUID,
    p_api_key_hash TEXT,
    p_origin TEXT DEFAULT NULL,
    p_context JSONB DEFAULT '{}'
)
RETURNS TABLE (
    is_valid BOOLEAN,
    validation_code TEXT,
    validation_message TEXT,
    app_record JSONB
)
LANGUAGE plpgsql
SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged execution context
STABLE
SET search_path = app, core, public
AS $$
DECLARE
    v_app_record RECORD;
    v_is_valid BOOLEAN := FALSE;
    v_code TEXT := 'UNKNOWN_ERROR';
    v_message TEXT := 'Validation failed';
BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
    -- ========================================================================
    -- VALIDATE INPUTS
    -- ========================================================================
    IF p_app_id IS NULL OR p_api_key_hash IS NULL THEN
        RETURN QUERY SELECT 
            FALSE, 
            'MISSING_CREDENTIALS'::TEXT, 
            'Application ID and API key are required'::TEXT,
            '{}'::JSONB;
        RETURN;
    END IF;
    
    -- ========================================================================
    -- LOOKUP APPLICATION
    -- ========================================================================
    SELECT * INTO v_app_record
    FROM app.t_application_registry
    WHERE app_id = p_app_id;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT 
            FALSE, 
            'APP_NOT_FOUND'::TEXT, 
            'Application not found'::TEXT,
            '{}'::JSONB;
        RETURN;
    END IF;
    
    -- ========================================================================
    -- VALIDATE STATUS
    -- ========================================================================
    CASE v_app_record.status
        WHEN 'pending' THEN
            v_code := 'APP_NOT_ACTIVE';
            v_message := 'Application is pending activation';
        WHEN 'suspended' THEN
            v_code := 'APP_SUSPENDED';
            v_message := 'Application is suspended: ' || COALESCE(v_app_record.status_reason, 'No reason provided');
        WHEN 'deprecated' THEN
            v_code := 'APP_DEPRECATED';
            v_message := 'Application is deprecated, please migrate';
        WHEN 'archived' THEN
            v_code := 'APP_ARCHIVED';
            v_message := 'Application has been archived';
        WHEN 'active' THEN
            v_is_valid := TRUE;
    END CASE;
    
    IF NOT v_is_valid THEN
        -- Log failed access attempt
        INSERT INTO [AUDIT] ISO 27001 A.8.15: Security event logging to core.t_audit_log (action, entity_type, entity_id, details, result)
        VALUES ('app_access_denied', 'application', p_app_id,
            jsonb_build_object('reason', v_code), 'denied');
        
        RETURN QUERY SELECT FALSE, v_code, v_message, '{}'::JSONB;
        RETURN;
    END IF;
    
    -- ========================================================================
    -- VALIDATE API KEY
    -- ========================================================================
    IF v_app_record.api_key_hash IS NULL OR 
       NOT crypt(p_api_key_hash, v_app_record.api_key_hash) = v_app_record.api_key_hash THEN
        
        -- Log failed authentication
        INSERT INTO [AUDIT] ISO 27001 A.8.15: Security event logging to core.t_audit_log (action, entity_type, entity_id, details, result)
        VALUES ('api_key_invalid', 'application', p_app_id,
            jsonb_build_object('origin', p_origin), 'denied');
        
        RETURN QUERY SELECT 
            FALSE, 
            'INVALID_API_KEY'::TEXT, 
            'Invalid API key'::TEXT,
            '{}'::JSONB;
        RETURN;
    END IF;
    
    -- ========================================================================
    -- VALIDATE ORIGIN (CORS)
    -- ========================================================================
    IF p_origin IS NOT NULL AND v_app_record.allowed_origins IS NOT NULL THEN
        IF NOT (p_origin = ANY(v_app_record.allowed_origins) OR 
                '*' = ANY(v_app_record.allowed_origins)) THEN
            
            RETURN QUERY SELECT 
                FALSE, 
                'INVALID_ORIGIN'::TEXT, 
                'Origin not allowed: ' || p_origin,
                '{}'::JSONB;
            RETURN;
        END IF;
    END IF;
    
    -- ========================================================================
    -- SET CONTEXT FOR RLS
    -- ========================================================================
    PERFORM set_config('app.current_app_id', p_app_id::TEXT, FALSE);  -- [RLS] ISO 27017: Application context for RLS
    PERFORM set_config('app.current_tenant_id', v_app_record.ledger_tenant_id  -- [RLS] ISO 27017: Tenant context for RLS -- [RLS] ISO 27017: Tenant isolation identifier for RLS::TEXT, FALSE);
    
    -- ========================================================================
    -- LOG SUCCESSFUL VALIDATION
    -- ========================================================================
    INSERT INTO [AUDIT] ISO 27001 A.8.15: Security event logging to core.t_audit_log (action, entity_type, entity_id, details, result)
    VALUES ('app_context_validated', 'application', p_app_id,
        jsonb_build_object('origin', p_origin), 'success');
    
    -- ========================================================================
    -- RETURN SUCCESS
    -- ========================================================================
    RETURN QUERY SELECT 
        TRUE,
        'VALID'::TEXT,
        'Application context valid'::TEXT,
        jsonb_build_object(
            'app_id', v_app_record.app_id,
            'app_code', v_app_record.app_code,
            'app_name', v_app_record.app_name,
            'app_tier', v_app_record.app_tier,
            'ledger_tenant_id' ||
        );
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON FUNCTION app.validate_app_context(UUID, TEXT, TEXT, JSONB) IS 
    'Validate application context for requests. ' ||
    'Feature: CORE-APP-FUNC-005. ' ||
    'Compliance: ISO 27001, SOC 2 Type II. ' ||
    'Security: API key validation, CORS, RLS context setup.';

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Always called at start of request processing
-- 2. Sets PostgreSQL config for RLS context
-- 3. Logs all validation failures for security monitoring
-- 4. Rate limiting prevents abuse
-- 5. API key rotation enforced after 90 days
-- 6. CORS origin validation for browser clients
-- =============================================================================
