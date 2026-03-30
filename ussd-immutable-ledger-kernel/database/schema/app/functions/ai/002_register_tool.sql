-- =============================================================================
-- ULTIMATE SOFTWARE SECURITY SOLUTIONS & DEFI LIMITED
-- AI Tool Registration Function
-- =============================================================================
-- Compliance: ISO 27001:2022 (A.12.1, A.14.2), SOC 2 Type II (Change Management)
--             NIST AI RMF (Governance, Mapping)
-- Classification: CONFIDENTIAL - Tool Configuration Registration
-- Purpose: Register new MCP tools with governance controls
-- Security: Schema validation; permission checks; versioning enforcement
-- Version: 1.0.0
-- Author: Database Engineering Team
-- Last Modified: 2026-03-30
-- =============================================================================

-- -----------------------------------------------------------------------------
-- FUNCTION: register_tool
-- PURPOSE: Register a new AI tool in the catalog with full governance
-- PARAMETERS:
--   p_name              - Tool identifier (kebab-case)
--   p_display_name      - Human-readable name
--   p_description       - Tool description
--   p_category          - Tool classification
--   p_input_schema      - JSON Schema for input validation
--   p_output_schema     - Expected output structure (optional)
--   p_kernel_function   - Function name to invoke
--   p_kernel_module     - Module path (optional)
--   p_execution_config  - Execution parameters (optional)
--   p_required_permissions - Array of required permissions
--   p_dependencies      - Other tool dependencies (optional)
--   p_version           - Semantic version (default: 1.0.0)
-- RETURNS: UUID of registered tool
-- SECURITY: Validates schemas; checks permissions; creates audit trail
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.register_tool(
    p_name VARCHAR(255),
    p_display_name VARCHAR(255),
    p_description TEXT,
    p_category VARCHAR(100),
    p_input_schema JSONB,
    p_output_schema JSONB DEFAULT NULL,
    p_kernel_function VARCHAR(255) DEFAULT NULL,
    p_kernel_module VARCHAR(255) DEFAULT NULL,
    p_execution_config JSONB DEFAULT '{}'::jsonb,
    p_required_permissions TEXT[] DEFAULT '{}',
    p_dependencies TEXT[] DEFAULT '{}',
    p_version VARCHAR(50) DEFAULT '1.0.0'
)
RETURNS UUID AS $$
DECLARE
    v_tool_id UUID;
    v_user_id UUID;
    v_existing_id UUID;
    v_existing_status VARCHAR(20);
    v_normalized_name VARCHAR(255);
BEGIN
    -- -------------------------------------------------------------------------
    -- SECURITY: Validate authentication
    -- -------------------------------------------------------------------------
    BEGIN
        v_user_id := current_setting('app.current_user_id')::UUID;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Authentication required: app.current_user_id not set'
            USING ERRCODE = '28000';
    END;
    
    -- -------------------------------------------------------------------------
    -- PERMISSION CHECK
    -- -------------------------------------------------------------------------
    IF NOT app.has_permission(current_user, 'ai:tools:create') THEN
        INSERT INTO app.audit_log (
            table_name, action, details, performed_by, result
        ) VALUES (
            'tool_catalog', 'TOOL_REGISTRATION_DENIED',
            jsonb_build_object(
                'tool_name', p_name,
                'reason', 'insufficient_permissions'
            ),
            v_user_id,
            'failure'
        );
        
        RAISE EXCEPTION 'Insufficient permissions to register tools'
            USING ERRCODE = '42501',
                  HINT = 'Requires ai:tools:create permission';
    END IF;
    
    -- -------------------------------------------------------------------------
    -- INPUT VALIDATION
    -- -------------------------------------------------------------------------
    
    -- Validate tool name
    IF p_name IS NULL OR trim(p_name) = '' THEN
        RAISE EXCEPTION 'Tool name is required'
            USING ERRCODE = '22004';
    END IF;
    
    -- Normalize name (kebab-case, lowercase)
    v_normalized_name := lower(regexp_replace(
        trim(p_name), 
        '[\s_]+', '-', 'g'
    ));
    
    -- Validate name format (alphanumeric, hyphens only)
    IF v_normalized_name !~ '^[a-z0-9]+(-[a-z0-9]+)*$' THEN
        RAISE EXCEPTION 'Invalid tool name format: %', p_name
            USING ERRCODE = '22023',
                  HINT = 'Tool names must be kebab-case (e.g., my-tool-name)';
    END IF;
    
    -- Validate display name
    IF p_display_name IS NULL OR trim(p_display_name) = '' THEN
        RAISE EXCEPTION 'Display name is required'
            USING ERRCODE = '22004';
    END IF;
    
    -- Validate description
    IF p_description IS NULL OR length(trim(p_description)) < 10 THEN
        RAISE EXCEPTION 'Description must be at least 10 characters'
            USING ERRCODE = '22023';
    END IF;
    
    -- Validate category
    IF p_category NOT IN (
        'data_access', 'computation', 'communication', 
        'integration', 'security', 'analytics', 'automation',
        'filesystem', 'database', 'api', 'messaging', 'custom'
    ) THEN
        RAISE EXCEPTION 'Invalid tool category: %', p_category
            USING ERRCODE = '22023',
                  HINT = 'See tool_catalog.category check constraint for valid values';
    END IF;
    
    -- Validate input schema
    IF p_input_schema IS NULL OR jsonb_typeof(p_input_schema) != 'object' THEN
        RAISE EXCEPTION 'Input schema must be a valid JSON object'
            USING ERRCODE = '22023';
    END IF;
    
    IF NOT (p_input_schema ? 'type') THEN
        RAISE EXCEPTION 'Input schema must specify a "type" field'
            USING ERRCODE = '22023';
    END IF;
    
    -- Derive kernel function from name if not provided
    IF p_kernel_function IS NULL THEN
        p_kernel_function := replace(v_normalized_name, '-', '_');
    END IF;
    
    -- -------------------------------------------------------------------------
    -- VERSION CONFLICT CHECK
    -- -------------------------------------------------------------------------
    
    SELECT id, status INTO v_existing_id, v_existing_status
    FROM app.tool_catalog
    WHERE name = v_normalized_name AND version = p_version
      AND deleted_at IS NULL;
    
    IF v_existing_id IS NOT NULL THEN
        -- If existing is deprecated, allow new registration
        IF v_existing_status != 'deprecated' THEN
            RAISE EXCEPTION 'Tool % version % already exists (status: %)', 
                v_normalized_name, p_version, v_existing_status
                USING ERRCODE = '23505',
                      HINT = 'Use a different version or deprecate existing tool';
        END IF;
    END IF;
    
    -- -------------------------------------------------------------------------
    -- INSERT TOOL RECORD
    -- -------------------------------------------------------------------------
    
    INSERT INTO app.tool_catalog (
        name,
        display_name,
        description,
        category,
        version,
        input_schema,
        output_schema,
        kernel_function,
        kernel_module,
        execution_config,
        required_permissions,
        dependencies,
        status,
        maintained_by,
        previous_version_id,
        created_by
    ) VALUES (
        v_normalized_name,
        p_display_name,
        p_description,
        p_category,
        p_version,
        p_input_schema,
        p_output_schema,
        p_kernel_function,
        p_kernel_module,
        COALESCE(p_execution_config, '{}'::jsonb),
        COALESCE(p_required_permissions, ARRAY[]::TEXT[]),
        COALESCE(p_dependencies, ARRAY[]::TEXT[]),
        'development',  -- New tools start in development
        v_user_id,
        v_existing_id,  -- Link to previous version if exists
        v_user_id
    )
    RETURNING id INTO v_tool_id;
    
    -- -------------------------------------------------------------------------
    -- AUDIT LOGGING
    -- -------------------------------------------------------------------------
    
    INSERT INTO app.audit_log (
        table_name, record_id, action,
        details, performed_by, result
    ) VALUES (
        'tool_catalog', v_tool_id, 'TOOL_REGISTERED',
        jsonb_build_object(
            'name', v_normalized_name,
            'display_name', p_display_name,
            'category', p_category,
            'version', p_version,
            'kernel_function', p_kernel_function,
            'required_permissions', p_required_permissions,
            'dependencies', p_dependencies,
            'previous_version', v_existing_id
        ),
        v_user_id,
        'success'
    );
    
    RETURN v_tool_id;
    
EXCEPTION
    WHEN unique_violation THEN
        RAISE EXCEPTION 'Tool registration conflict: % v%', 
            v_normalized_name, p_version
            USING ERRCODE = '23505';
    WHEN OTHERS THEN
        -- Log error for debugging
        INSERT INTO app.audit_log (
            table_name, action, details, performed_by, result, severity
        ) VALUES (
            'tool_catalog', 'TOOL_REGISTRATION_ERROR',
            jsonb_build_object(
                'tool_name', v_normalized_name,
                'error_code', SQLSTATE
            ),
            v_user_id,
            'failure',
            'error'
        );
        RAISE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
    VOLATILE
    SET search_path = app, pg_temp;

-- -----------------------------------------------------------------------------
-- FUNCTION: update_tool_status
-- PURPOSE: Change tool status with governance controls
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.update_tool_status(
    p_tool_id UUID,
    p_new_status VARCHAR(20),
    p_reason TEXT DEFAULT NULL
)
RETURNS BOOLEAN AS $$
DECLARE
    v_user_id UUID;
    v_old_status VARCHAR(20);
    v_tool_name VARCHAR(255);
    v_approved BOOLEAN := FALSE;
BEGIN
    -- -------------------------------------------------------------------------
    -- SECURITY
    -- -------------------------------------------------------------------------
    BEGIN
        v_user_id := current_setting('app.current_user_id')::UUID;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Authentication required' USING ERRCODE = '28000';
    END;
    
    -- -------------------------------------------------------------------------
    -- GET CURRENT STATUS
    -- -------------------------------------------------------------------------
    SELECT status, name INTO v_old_status, v_tool_name
    FROM app.tool_catalog
    WHERE id = p_tool_id AND deleted_at IS NULL;
    
    IF v_old_status IS NULL THEN
        RAISE EXCEPTION 'Tool not found: %', p_tool_id USING ERRCODE = 'P0002';
    END IF;
    
    -- -------------------------------------------------------------------------
    -- STATUS TRANSITION VALIDATION
    -- -------------------------------------------------------------------------
    
    -- Define valid transitions
    CASE v_old_status
        WHEN 'development' THEN
            IF p_new_status NOT IN ('staging', 'deprecated') THEN
                RAISE EXCEPTION 'Invalid transition: development -> %', p_new_status;
            END IF;
        WHEN 'staging' THEN
            IF p_new_status NOT IN ('production', 'development', 'deprecated') THEN
                RAISE EXCEPTION 'Invalid transition: staging -> %', p_new_status;
            END IF;
            -- Production requires approval
            IF p_new_status = 'production' THEN
                IF NOT app.has_permission(current_user, 'ai:tools:approve') THEN
                    RAISE EXCEPTION 'Production deployment requires approval permission'
                        USING ERRCODE = '42501';
                END IF;
                v_approved := TRUE;
            END IF;
        WHEN 'production' THEN
            IF p_new_status NOT IN ('deprecated') THEN
                RAISE EXCEPTION 'Production tools can only be deprecated';
            END IF;
        WHEN 'deprecated' THEN
            IF p_new_status NOT IN ('retired') THEN
                RAISE EXCEPTION 'Deprecated tools can only be retired';
            END IF;
        WHEN 'retired' THEN
            RAISE EXCEPTION 'Retired tools cannot change status';
    END CASE;
    
    -- -------------------------------------------------------------------------
    -- UPDATE STATUS
    -- -------------------------------------------------------------------------
    
    UPDATE app.tool_catalog
    SET 
        status = p_new_status,
        approved_by = CASE WHEN v_approved THEN v_user_id ELSE approved_by END,
        approval_date = CASE WHEN v_approved THEN CURRENT_TIMESTAMP ELSE approval_date END,
        updated_by = v_user_id
    WHERE id = p_tool_id;
    
    -- -------------------------------------------------------------------------
    -- AUDIT LOG
    -- -------------------------------------------------------------------------
    
    INSERT INTO app.audit_log (
        table_name, record_id, action,
        old_data, new_data, details, performed_by, result
    ) VALUES (
        'tool_catalog', p_tool_id, 'STATUS_CHANGE',
        jsonb_build_object('status', v_old_status),
        jsonb_build_object('status', p_new_status),
        jsonb_build_object(
            'tool_name', v_tool_name,
            'reason', p_reason,
            'approved', v_approved
        ),
        v_user_id,
        'success'
    );
    
    RETURN TRUE;
    
EXCEPTION
    WHEN OTHERS THEN
        INSERT INTO app.audit_log (
            table_name, record_id, action,
            details, performed_by, result, severity
        ) VALUES (
            'tool_catalog', p_tool_id, 'STATUS_CHANGE_FAILED',
            jsonb_build_object(
                'attempted_status', p_new_status,
                'error', SQLERRM
            ),
            v_user_id,
            'failure',
            'error'
        );
        RAISE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
    VOLATILE
    SET search_path = app, pg_temp;

-- -----------------------------------------------------------------------------
-- FUNCTION COMMENTS
-- -----------------------------------------------------------------------------

COMMENT ON FUNCTION app.register_tool(VARCHAR, VARCHAR, TEXT, VARCHAR, JSONB, JSONB, VARCHAR, VARCHAR, JSONB, TEXT[], TEXT[], VARCHAR) IS 
    'Registers a new MCP tool in the catalog. Validates JSON schemas, checks 
     permissions, creates audit trail. Tools start in development status.';

COMMENT ON FUNCTION app.update_tool_status(UUID, VARCHAR, TEXT) IS 
    'Updates tool status with state machine enforcement. Production deployment 
     requires approval permission. Logs all transitions for audit.';

-- -----------------------------------------------------------------------------
-- GRANTS
-- -----------------------------------------------------------------------------

GRANT EXECUTE ON FUNCTION app.register_tool(VARCHAR, VARCHAR, TEXT, VARCHAR, JSONB, JSONB, VARCHAR, VARCHAR, JSONB, TEXT[], TEXT[], VARCHAR) 
    TO app_readwrite;
GRANT EXECUTE ON FUNCTION app.register_tool(VARCHAR, VARCHAR, TEXT, VARCHAR, JSONB, JSONB, VARCHAR, VARCHAR, JSONB, TEXT[], TEXT[], VARCHAR) 
    TO app_admin;
    
GRANT EXECUTE ON FUNCTION app.update_tool_status(UUID, VARCHAR, TEXT) 
    TO app_readwrite;
GRANT EXECUTE ON FUNCTION app.update_tool_status(UUID, VARCHAR, TEXT) 
    TO app_admin;

-- =============================================================================
-- END OF FILE
-- =============================================================================
