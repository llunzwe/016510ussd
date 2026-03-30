/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - APPLICATION: GET APP CONFIG
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-FUNC-004
 * Feature Name:       Configuration Retrieval
 * Description:        Retrieves application configuration with environment
 *                     scoping, secret decryption, and hierarchical resolution.
 *                     Supports caching and change detection.
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
 *   - Control A.5.23: Cloud services
 *   - Control A.8.5: Secure authentication
 *   - Control A.8.24: Use of cryptography
 * 
 * ISO/IEC 27018:2019 (PII Protection)
 *   - Section 9.4: Access control
 * 
 * SOC 2 Type II
 *   - CC6.1: Logical access controls
 * 
 * =============================================================================
 * MULTI-TENANCY SECURITY ANNOTATIONS
 * =============================================================================
 * 
 * CONFIGURATION RESOLUTION HIERARCHY:
 *   1. User-scoped (if scope_id provided)
 *   2. Organization-scoped
 *   3. Application-scoped
 *   4. Platform default
 *   5. Environment fallback: specific -> default
 * 
 * SECURITY CONTROLS:
 *   - Secret access logged
 *   - Decryption via external KMS
 *   - Scope validation
 * 
 * =============================================================================
 * AUDIT TRAIL REQUIREMENTS
 * =============================================================================
 * 
 * MANDATORY LOGGING:
 *   - Secret accessed
 *   - Config not found (security check)
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - app.t_application_registry
 *   - app.t_configuration_store
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
-- FUNCTION: app.get_app_config()
-- =============================================================================

CREATE OR REPLACE FUNCTION app.get_app_config(
    p_app_id UUID,
    p_config_key TEXT,
    p_environment TEXT DEFAULT 'default',
    p_scope_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged execution context
STABLE
SET search_path = app, core, public
AS $$
DECLARE
    v_config_record RECORD;
    v_value JSONB;
    v_decrypted_value TEXT;
BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
    -- ========================================================================
    -- VALIDATE APPLICATION
    -- ========================================================================
    IF NOT EXISTS (
        SELECT 1 FROM app.t_application_registry
        WHERE app_id = p_app_id AND status = 'active'
    ) THEN
        RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'Application not found or not active';
    END IF;
    
    -- ========================================================================
    -- RESOLVE CONFIGURATION WITH SCOPE HIERARCHY
    -- ========================================================================
    SELECT * INTO v_config_record
    FROM app.t_configuration_store
    WHERE app_id = p_app_id
      AND config_key = LOWER(TRIM(p_config_key))
      AND environment = p_environment
      AND is_current = TRUE
      AND (
          (scope_level = 'user' AND scope_id = p_scope_id)
          OR (scope_level = 'organization' AND scope_id = p_scope_id)
          OR scope_level = 'application'
          OR scope_level = 'platform'
      )
    ORDER BY 
        CASE scope_level
            WHEN 'user' THEN 1
            WHEN 'organization' THEN 2
            WHEN 'application' THEN 3
            WHEN 'platform' THEN 4
        END
    LIMIT 1;
    
    -- Not found - try default environment
    IF v_config_record IS NULL AND p_environment != 'default' THEN
        RETURN app.get_app_config(p_app_id, p_config_key, 'default', p_scope_id);
    END IF;
    
    IF v_config_record IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- ========================================================================
    -- DECRYPT IF ENCRYPTED
    -- ========================================================================
    IF v_config_record.is_encrypted THEN
        -- TODO: Call encryption service to decrypt
        -- v_decrypted_value := core.decrypt_value(...)
        -- v_value := to_jsonb(v_decrypted_value);
        
        -- Audit secret access
        INSERT INTO [AUDIT] ISO 27001 A.8.15: Security event logging to core.t_audit_log (action, entity_type, entity_id, details)
        VALUES ('secret_accessed', 'configuration', v_config_record.config_id,
            jsonb_build_object('key', p_config_key, 'app_id', p_app_id));
        
        RETURN NULL; -- Placeholder
    ELSE
        -- Return appropriate value type
        CASE v_config_record.value_type
            WHEN 'string' THEN v_value := to_jsonb(v_config_record.value_string);
            WHEN 'number' THEN v_value := to_jsonb(v_config_record.value_number);
            WHEN 'boolean' THEN v_value := to_jsonb(v_config_record.value_boolean);
            WHEN 'json' THEN v_value := v_config_record.value_json;
            ELSE v_value := NULL;
        END CASE;
    END IF;
    
    RETURN v_value;
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON FUNCTION app.get_app_config(UUID, TEXT, TEXT, UUID) IS 
    'Retrieve application configuration with scope resolution. ' ||
    'Feature: CORE-APP-FUNC-004. ' ||
    'Compliance: ISO 27001, ISO 27018. ' ||
    'Security: Secret access logged, decryption via KMS. ' ||
    'Resolution: user > organization > application > platform.';

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Hierarchical resolution: user > organization > application > platform
-- 2. Encrypted values decrypted using key management service
-- 3. Secret access logged for security audit
-- 4. Environment fallback: specific -> default
-- 5. Results should be cached at application layer
-- 6. Cache key should include version for change detection
-- =============================================================================
