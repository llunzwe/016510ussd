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
 *   1.0.1 - Implemented TODOs: Secret decryption via KMS integration
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
 * - Implement proper error handling with transaction rollback
 * - Use SECURITY DEFINER for privileged operations
 * - Enforce RLS policies for multi-tenant data isolation
 * - Use explicit column lists (avoid SELECT *)
 * - Add audit logging for all security-relevant operations
 * - Use UUIDs for primary identifiers to prevent enumeration
 * - Implement optimistic locking with version columns
 * - Use TIMESTAMPTZ for all timestamp columns
 * - Validate all inputs with CHECK constraints
 * ============================================================================

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
SECURITY DEFINER
STABLE
SET search_path = app, core, public
AS $$
DECLARE
    v_config_record RECORD;
    v_value JSONB;
    v_decrypted_value TEXT;
    v_encryption_key_id UUID;
    v_kms_response RECORD;
BEGIN
    -- ========================================================================
    -- VALIDATE APPLICATION
    -- ========================================================================
    IF NOT EXISTS (
        SELECT 1 FROM app.t_application_registry
        WHERE app_id = p_app_id AND status = 'active'
    ) THEN
        RAISE EXCEPTION 'Application not found or not active';
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
        -- Log config not found for security monitoring
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
            'DEBUG',
            'config_not_found',
            'Configuration key not found',
            'CONFIG_LOOKUP',
            'FAILURE',
            'app',
            't_configuration_store',
            p_app_id::TEXT,
            jsonb_build_object(
                'config_key', p_config_key,
                'environment', p_environment,
                'scope_id', p_scope_id
            )
        );
        RETURN NULL;
    END IF;
    
    -- ========================================================================
    -- DECRYPT IF ENCRYPTED
    -- ========================================================================
    IF v_config_record.is_encrypted THEN
        -- Get the encryption key ID from config or app registry
        v_encryption_key_id := COALESCE(
            v_config_record.encryption_key_id,
            (SELECT encryption_key_id FROM app.t_application_registry WHERE app_id = p_app_id)
        );
        
        IF v_encryption_key_id IS NULL THEN
            RAISE EXCEPTION 'Encrypted configuration value but no encryption key configured';
        END IF;
        
        -- Call KMS decryption function (core schema)
        BEGIN
            -- Attempt decryption via external KMS
            SELECT decrypted_value INTO v_decrypted_value
            FROM core.decrypt_value(
                encrypted_data => v_config_record.value_encrypted,
                key_id => v_encryption_key_id,
                key_context => jsonb_build_object(
                    'app_id', p_app_id,
                    'config_key', p_config_key,
                    'purpose', 'config_retrieval'
                )
            );
            
            -- Parse decrypted value based on value_type
            CASE v_config_record.value_type
                WHEN 'string' THEN v_value := to_jsonb(v_decrypted_value);
                WHEN 'json' THEN v_value := v_decrypted_value::JSONB;
                WHEN 'number' THEN v_value := to_jsonb(v_decrypted_value::NUMERIC);
                WHEN 'boolean' THEN v_value := to_jsonb(v_decrypted_value::BOOLEAN);
                ELSE v_value := to_jsonb(v_decrypted_value);
            END CASE;
            
        EXCEPTION WHEN OTHERS THEN
            -- Log decryption failure
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
                new_data,
                error_message
            ) VALUES (
                'SECURITY',
                'ERROR',
                'config_decryption_failed',
                'Failed to decrypt configuration value',
                'CONFIG_DECRYPTION',
                'FAILURE',
                'app',
                't_configuration_store',
                v_config_record.config_id::TEXT,
                jsonb_build_object(
                    'config_key', p_config_key,
                    'encryption_key_id', v_encryption_key_id
                ),
                SQLERRM
            );
            RAISE EXCEPTION 'Failed to decrypt configuration: %', SQLERRM;
        END;
        
        -- Audit secret access
        INSERT INTO core.audit_trail (
            audit_category,
            audit_level,
            audit_event,
            audit_description,
            actor_account_id,
            actor_type,
            action,
            action_status,
            table_schema,
            table_name,
            record_id,
            application_id,
            new_data
        ) VALUES (
            'SECURITY',
            'INFO',
            'secret_accessed',
            'Encrypted configuration value accessed',
            COALESCE(current_setting('app.current_user_id', TRUE)::UUID, v_config_record.created_by),
            'USER',
            'SECRET_ACCESS',
            'SUCCESS',
            'app',
            't_configuration_store',
            v_config_record.config_id::TEXT,
            p_app_id,
            jsonb_build_object(
                'key', p_config_key,
                'app_id', p_app_id,
                'encryption_key_id', v_encryption_key_id,
                'scope_level', v_config_record.scope_level
            )
        );
        
        RETURN v_value;
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
-- FUNCTION: app.get_app_config_with_fallback()
-- Extended version with multiple fallback keys
-- =============================================================================
CREATE OR REPLACE FUNCTION app.get_app_config_with_fallback(
    p_app_id UUID,
    p_config_keys TEXT[],
    p_environment TEXT DEFAULT 'default',
    p_scope_id UUID DEFAULT NULL
)
RETURNS TABLE (
    config_key TEXT,
    config_value JSONB,
    found BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
AS $$
DECLARE
    v_key TEXT;
    v_value JSONB;
BEGIN
    FOREACH v_key IN ARRAY p_config_keys
    LOOP
        v_value := app.get_app_config(p_app_id, v_key, p_environment, p_scope_id);
        config_key := v_key;
        config_value := v_value;
        found := (v_value IS NOT NULL);
        RETURN NEXT;
    END LOOP;
END;
$$;

-- =============================================================================
-- FUNCTION: app.refresh_config_cache()
-- Trigger cache refresh notification
-- =============================================================================
CREATE OR REPLACE FUNCTION app.refresh_config_cache(
    p_app_id UUID,
    p_config_key TEXT DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    PERFORM pg_notify('config_cache_refresh', jsonb_build_object(
        'app_id', p_app_id,
        'config_key', p_config_key,
        'timestamp', NOW()
    )::TEXT);
    
    RETURN TRUE;
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

COMMENT ON FUNCTION app.get_app_config_with_fallback(UUID, TEXT[], TEXT, UUID) IS
    'Retrieve multiple configuration values with fallback support. Returns table of key/value/found status.';

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Hierarchical resolution: user > organization > application > platform
-- 2. Encrypted values decrypted using key management service (core.decrypt_value)
-- 3. Secret access logged for security audit
-- 4. Environment fallback: specific -> default
-- 5. Results should be cached at application layer
-- 6. Cache key should include version for change detection
-- =============================================================================
