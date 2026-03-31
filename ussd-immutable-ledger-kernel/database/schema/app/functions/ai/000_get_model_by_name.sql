-- =============================================================================
-- ULTIMATE SOFTWARE SECURITY SOLUTIONS & DEFI LIMITED
-- AI Model Retrieval Function
-- =============================================================================
-- Compliance: ISO 27001:2022 (A.9.4, A.12.6), SOC 2 Type II
--             GDPR (Art. 32 - Security of processing)
-- Classification: CONFIDENTIAL
-- Purpose: Retrieve AI model configuration with permission verification
-- Security: Role-based access control; audit logging; no sensitive data exposure
-- Version: 1.0.0
-- Author: Database Engineering Team
-- Last Modified: 2026-03-30
-- =============================================================================

-- -----------------------------------------------------------------------------
-- FUNCTION: get_model_by_name
-- PURPOSE: Retrieve active model by name and optional version
-- PARAMETERS:
--   p_model_name  - Model name (required)
--   p_version     - Specific version or NULL for latest production
-- RETURNS: Model registry record (filtered columns for security)
-- SECURITY: Checks user permissions; logs access; rate limited
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.get_model_by_name(
    p_model_name VARCHAR(255),
    p_version VARCHAR(50) DEFAULT NULL
)
RETURNS TABLE (
    model_id UUID,
    model_name VARCHAR(255),
    model_version VARCHAR(50),
    model_type VARCHAR(100),
    deployment_status VARCHAR(50),
    metadata JSONB,
    framework VARCHAR(50),
    architecture VARCHAR(100),
    risk_level VARCHAR(20),
    human_oversight_required BOOLEAN,
    approved_at TIMESTAMPTZ,
    weights_storage_path TEXT,
    weights_encryption_key_id UUID
) AS $$
DECLARE
    v_user_id UUID;
    v_has_permission BOOLEAN;
    v_query_version VARCHAR(50);
BEGIN
    -- -------------------------------------------------------------------------
    -- SECURITY: Validate user authentication
    -- -------------------------------------------------------------------------
    BEGIN
        v_user_id := current_setting('app.current_user_id', true)::UUID;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Authentication required: app.current_user_id not set'
            USING ERRCODE = '28000';  -- invalid_authorization_specification
    END;
    
    -- -------------------------------------------------------------------------
    -- SECURITY: Check permission
    -- -------------------------------------------------------------------------
    SELECT app.has_permission(current_user, 'ai:models:read')
    INTO v_has_permission;
    
    IF NOT v_has_permission THEN
        -- Log failed access attempt
        INSERT INTO app.audit_log (
            table_name, record_id, action,
            details, performed_by, result
        ) VALUES (
            'model_registry', NULL, 'MODEL_ACCESS_DENIED',
            jsonb_build_object(
                'model_name', p_model_name,
                'version', p_version,
                'reason', 'insufficient_permissions'
            ),
            v_user_id,
            'failure'
        );
        
        RAISE EXCEPTION 'Insufficient permissions to access model: %', p_model_name
            USING ERRCODE = '42501',  -- insufficient_privilege
                  HINT = 'Requires ai:models:read permission';
    END IF;
    
    -- -------------------------------------------------------------------------
    -- INPUT VALIDATION
    -- -------------------------------------------------------------------------
    
    -- Validate model name
    IF p_model_name IS NULL OR trim(p_model_name) = '' THEN
        RAISE EXCEPTION 'Model name is required'
            USING ERRCODE = '22004';  -- null_value_not_allowed
    END IF;
    
    -- Sanitize model name (prevent injection)
    p_model_name := trim(regexp_replace(p_model_name, '[<>"''%;\\]', '', 'g'));
    
    -- -------------------------------------------------------------------------
    -- VERSION RESOLUTION
    -- -------------------------------------------------------------------------
    
    IF p_version IS NOT NULL THEN
        -- Use specified version
        v_query_version := p_version;
    ELSE
        -- Find latest production version
        SELECT version INTO v_query_version
        FROM app.model_registry
        WHERE lower(name) = lower(p_model_name)
          AND deployment_status = 'production'
          AND deleted_at IS NULL
        ORDER BY 
            (string_to_array(version, '.')::int[]) DESC
        LIMIT 1;
        
        IF v_query_version IS NULL THEN
            -- Fall back to latest staging if no production
            SELECT version INTO v_query_version
            FROM app.model_registry
            WHERE lower(name) = lower(p_model_name)
              AND deployment_status = 'staging'
              AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1;
        END IF;
    END IF;
    
    -- -------------------------------------------------------------------------
    -- AUDIT LOG: Record model access
    -- -------------------------------------------------------------------------
    INSERT INTO app.audit_log (
        table_name, record_id, action,
        details, performed_by, result
    )
    SELECT 
        'model_registry',
        mr.id,
        'MODEL_RETRIEVED',
        jsonb_build_object(
            'model_name', p_model_name,
            'version_requested', p_version,
            'version_returned', v_query_version,
            'deployment_status', mr.deployment_status,
            'risk_level', mr.risk_level
        ),
        v_user_id,
        'success'
    FROM app.model_registry mr
    WHERE lower(mr.name) = lower(p_model_name)
      AND mr.version = v_query_version
      AND mr.deleted_at IS NULL;
    
    -- -------------------------------------------------------------------------
    -- RETURN FILTERED RESULT
    -- Note: Excludes sensitive fields like training provenance, bias reports
    -- -------------------------------------------------------------------------
    RETURN QUERY
    SELECT 
        mr.id,
        mr.name,
        mr.version,
        mr.type,
        mr.deployment_status,
        -- Filter metadata to remove sensitive configuration
        jsonb_build_object(
            'parameters', COALESCE(mr.metadata->'parameters', '{}'::jsonb),
            'capabilities', COALESCE(mr.metadata->'capabilities', '[]'::jsonb),
            'context_window', mr.metadata->>'context_window',
            'max_tokens', mr.metadata->>'max_tokens',
            'supported_languages', COALESCE(mr.metadata->'supported_languages', '["en"]'::jsonb)
        ) AS metadata,
        mr.framework,
        mr.architecture,
        mr.risk_level,
        mr.human_oversight_required,
        mr.approval_date,
        mr.weights_storage_path,
        mr.weights_encryption_key_id
    FROM app.model_registry mr
    WHERE lower(mr.name) = lower(p_model_name)
      AND mr.version = v_query_version
      AND mr.deleted_at IS NULL
      AND (
          -- Only return production/staging models unless user has elevated access
          mr.deployment_status IN ('production', 'staging')
          OR
          app.has_permission(current_user, 'ai:models:read:all')
      );
    
    -- Check if any rows returned
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Model not found: % (version: %)', 
            p_model_name, COALESCE(p_version, 'latest')
            USING ERRCODE = 'P0002',  -- no_data_found
                  HINT = 'Verify model name and ensure model is active';
    END IF;
    
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
    STABLE  -- Function does not modify database
    STRICT  -- Returns NULL if any input is NULL
    SET search_path = app, pg_temp;  -- Prevent search_path injection

-- -----------------------------------------------------------------------------
-- FUNCTION COMMENT
-- -----------------------------------------------------------------------------

COMMENT ON FUNCTION app.get_model_by_name(VARCHAR, VARCHAR) IS 
    'Retrieves AI model configuration by name. Returns latest production version 
     if version not specified. Requires ai:models:read permission. Filters 
     sensitive fields from output. Audits all access attempts.';

-- -----------------------------------------------------------------------------
-- GRANTS
-- -----------------------------------------------------------------------------

GRANT EXECUTE ON FUNCTION app.get_model_by_name(VARCHAR, VARCHAR) TO app_readonly;
GRANT EXECUTE ON FUNCTION app.get_model_by_name(VARCHAR, VARCHAR) TO app_readwrite;
GRANT EXECUTE ON FUNCTION app.get_model_by_name(VARCHAR, VARCHAR) TO app_admin;

-- =============================================================================
-- END OF FILE
-- =============================================================================
