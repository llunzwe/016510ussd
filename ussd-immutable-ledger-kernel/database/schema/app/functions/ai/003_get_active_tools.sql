-- =============================================================================
-- ULTIMATE SOFTWARE SECURITY SOLUTIONS & DEFI LIMITED
-- Active Tools Discovery Function
-- =============================================================================
-- Compliance: ISO 27001:2022 (A.9.4), SOC 2 Type II
--             Least Privilege Principle (tools filtered by user permissions)
-- Classification: INTERNAL - Tool Discovery Interface
-- Purpose: Discover available AI tools based on user permissions
-- Security: Permission-based filtering; no sensitive config exposure
-- Version: 1.0.0
-- Author: Database Engineering Team
-- Last Modified: 2026-03-30
-- =============================================================================

-- -----------------------------------------------------------------------------
-- FUNCTION: get_active_tools
-- PURPOSE: Retrieve list of active tools user has permission to use
-- PARAMETERS:
--   p_category      - Filter by category (optional)
--   p_include_dev   - Include development tools (default: false)
-- RETURNS: Table of tool information (filtered for security)
-- SECURITY: Checks user permissions against tool requirements
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.get_active_tools(
    p_category VARCHAR(100) DEFAULT NULL,
    p_include_dev BOOLEAN DEFAULT FALSE
)
RETURNS TABLE (
    tool_id UUID,
    tool_name VARCHAR(255),
    display_name VARCHAR(255),
    description TEXT,
    category VARCHAR(100),
    version VARCHAR(50),
    status VARCHAR(20),
    input_schema JSONB,
    required_permissions TEXT[],
    dependencies TEXT[],
    timeout_seconds INTEGER,
    rate_limit_requests INTEGER
) AS $$
DECLARE
    v_user_id UUID;
    v_user_permissions TEXT[];
    v_user_roles TEXT[];
BEGIN
    -- -------------------------------------------------------------------------
    -- SECURITY: Validate authentication
    -- -------------------------------------------------------------------------
    BEGIN
        v_user_id := current_setting('app.current_user_id', true)::UUID;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Authentication required: app.current_user_id not set'
            USING ERRCODE = '28000';
    END;
    
    -- -------------------------------------------------------------------------
    -- INPUT VALIDATION
    -- -------------------------------------------------------------------------
    
    -- Validate category filter if provided
    IF p_category IS NOT NULL THEN
        IF p_category NOT IN (
            'data_access', 'computation', 'communication', 
            'integration', 'security', 'analytics', 'automation',
            'filesystem', 'database', 'api', 'messaging', 'custom'
        ) THEN
            RAISE EXCEPTION 'Invalid category filter: %', p_category
                USING ERRCODE = '22023',
                      HINT = 'See tool_catalog.category for valid values';
        END IF;
    END IF;
    
    -- -------------------------------------------------------------------------
    -- GET USER PERMISSIONS
    -- -------------------------------------------------------------------------
    
    -- Collect all user permissions
    SELECT array_agg(DISTINCT rp.permission_code)
    INTO v_user_permissions
    FROM app.user_roles ur
    JOIN app.role_permissions rp ON ur.role_id = rp.role_id
    WHERE ur.user_id = v_user_id
      AND ur.is_active = TRUE;
    
    -- Add implicit permissions based on roles
    v_user_permissions := COALESCE(v_user_permissions, ARRAY[]::TEXT[]);
    
    -- Always add basic tool discovery permission if user is authenticated
    IF app.has_permission(current_user, 'ai:tools:discover') THEN
        v_user_permissions := array_append(v_user_permissions, 'ai:tools:discover');
    END IF;
    
    -- -------------------------------------------------------------------------
    -- AUDIT LOG: Tool discovery
    -- -------------------------------------------------------------------------
    
    INSERT INTO app.audit_log (
        table_name, action, details, performed_by, result
    ) VALUES (
        'tool_catalog', 'TOOLS_DISCOVERED',
        jsonb_build_object(
            'category_filter', p_category,
            'include_dev', p_include_dev,
            'user_permissions', v_user_permissions
        ),
        v_user_id,
        'success'
    );
    
    -- -------------------------------------------------------------------------
    -- RETURN FILTERED TOOLS
    -- -------------------------------------------------------------------------
    
    RETURN QUERY
    SELECT 
        tc.id,
        tc.name,
        tc.display_name,
        tc.description,
        tc.category,
        tc.version,
        tc.status,
        -- Return schema but sanitize any sensitive examples
        jsonb_build_object(
            'type', tc.input_schema->>'type',
            'properties', tc.input_schema->'properties',
            'required', COALESCE(tc.input_schema->'required', '[]'::jsonb),
            'description', tc.input_schema->>'description'
        ) AS input_schema,
        tc.required_permissions,
        tc.dependencies,
        tc.timeout_seconds,
        tc.rate_limit_requests
    FROM app.tool_catalog tc
    WHERE tc.deleted_at IS NULL
      -- Status filtering
      AND (
          tc.status = 'production'
          OR (p_include_dev AND tc.status IN ('development', 'staging'))
          OR app.has_permission(current_user, 'ai:tools:read:all')
      )
      -- Category filtering
      AND (p_category IS NULL OR tc.category = p_category)
      -- Permission filtering: user must have ALL required permissions
      AND (
          tc.required_permissions = ARRAY[]::TEXT[]
          OR tc.required_permissions <@ v_user_permissions
          OR app.has_permission(current_user, 'ai:tools:use:any')
      )
    ORDER BY 
        tc.category,
        tc.display_name;
    
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
    STABLE  -- Read-only function
    SET search_path = app, pg_temp;

-- -----------------------------------------------------------------------------
-- FUNCTION: get_tool_by_name
-- PURPOSE: Retrieve specific tool details with permission check
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.get_tool_by_name(
    p_tool_name VARCHAR(255),
    p_version VARCHAR(50) DEFAULT NULL
)
RETURNS TABLE (
    tool_id UUID,
    tool_name VARCHAR(255),
    display_name VARCHAR(255),
    description TEXT,
    category VARCHAR(100),
    version VARCHAR(50),
    status VARCHAR(20),
    input_schema JSONB,
    output_schema JSONB,
    kernel_function VARCHAR(255),
    execution_config JSONB,
    required_permissions TEXT[],
    dependencies TEXT[],
    timeout_seconds INTEGER,
    max_retries INTEGER,
    rate_limit_requests INTEGER,
    data_access_level VARCHAR(20),
    pii_handling VARCHAR(50)
) AS $$
DECLARE
    v_user_id UUID;
    v_user_permissions TEXT[];
    v_tool_record RECORD;
    v_has_access BOOLEAN := FALSE;
BEGIN
    -- -------------------------------------------------------------------------
    -- SECURITY
    -- -------------------------------------------------------------------------
    BEGIN
        v_user_id := current_setting('app.current_user_id', true)::UUID;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Authentication required' USING ERRCODE = '28000';
    END;
    
    -- -------------------------------------------------------------------------
    -- INPUT VALIDATION
    -- -------------------------------------------------------------------------
    IF p_tool_name IS NULL OR trim(p_tool_name) = '' THEN
        RAISE EXCEPTION 'Tool name is required' USING ERRCODE = '22004';
    END IF;
    
    -- Normalize name
    p_tool_name := lower(trim(p_tool_name));
    
    -- -------------------------------------------------------------------------
    -- GET USER PERMISSIONS
    -- -------------------------------------------------------------------------
    SELECT array_agg(DISTINCT rp.permission_code)
    INTO v_user_permissions
    FROM app.user_roles ur
    JOIN app.role_permissions rp ON ur.role_id = rp.role_id
    WHERE ur.user_id = v_user_id
      AND ur.is_active = TRUE;
    
    v_user_permissions := COALESCE(v_user_permissions, ARRAY[]::TEXT[]);
    
    -- -------------------------------------------------------------------------
    -- FETCH TOOL RECORD
    -- -------------------------------------------------------------------------
    
    SELECT * INTO v_tool_record
    FROM app.tool_catalog tc
    WHERE lower(tc.name) = p_tool_name
      AND tc.deleted_at IS NULL
      AND (
          p_version IS NULL OR tc.version = p_version
      )
    ORDER BY 
        CASE tc.status 
            WHEN 'production' THEN 1 
            WHEN 'staging' THEN 2 
            ELSE 3 
        END,
        string_to_array(tc.version, '.')::int[] DESC
    LIMIT 1;
    
    IF v_tool_record IS NULL THEN
        RAISE EXCEPTION 'Tool not found: %', p_tool_name
            USING ERRCODE = 'P0002',
                  HINT = 'Verify tool name and version';
    END IF;
    
    -- -------------------------------------------------------------------------
    -- PERMISSION CHECK
    -- -------------------------------------------------------------------------
    
    -- Check if user has required permissions
    IF v_tool_record.required_permissions = ARRAY[]::TEXT[] 
       OR v_tool_record.required_permissions <@ v_user_permissions
       OR app.has_permission(current_user, 'ai:tools:use:any')
       OR app.has_permission(current_user, 'system:admin') THEN
        v_has_access := TRUE;
    END IF;
    
    IF NOT v_has_access THEN
        -- Log denied access
        INSERT INTO app.audit_log (
            table_name, record_id, action, details, performed_by, result
        ) VALUES (
            'tool_catalog', v_tool_record.id, 'TOOL_ACCESS_DENIED',
            jsonb_build_object(
                'tool_name', p_tool_name,
                'required_permissions', v_tool_record.required_permissions,
                'user_permissions', v_user_permissions
            ),
            v_user_id,
            'failure'
        );
        
        RAISE EXCEPTION 'Insufficient permissions for tool: %', p_tool_name
            USING ERRCODE = '42501',
                  HINT = 'Required permissions: ' || array_to_string(v_tool_record.required_permissions, ', ');
    END IF;
    
    -- -------------------------------------------------------------------------
    -- AUDIT LOG
    -- -------------------------------------------------------------------------
    
    INSERT INTO app.audit_log (
        table_name, record_id, action, details, performed_by, result
    ) VALUES (
        'tool_catalog', v_tool_record.id, 'TOOL_RETRIEVED',
        jsonb_build_object(
            'tool_name', p_tool_name,
            'version', v_tool_record.version,
            'category', v_tool_record.category
        ),
        v_user_id,
        'success'
    );
    
    -- -------------------------------------------------------------------------
    -- RETURN TOOL DETAILS
    -- -------------------------------------------------------------------------
    
    RETURN QUERY
    SELECT 
        v_tool_record.id,
        v_tool_record.name,
        v_tool_record.display_name,
        v_tool_record.description,
        v_tool_record.category,
        v_tool_record.version,
        v_tool_record.status,
        v_tool_record.input_schema,
        v_tool_record.output_schema,
        v_tool_record.kernel_function,
        -- Filter execution config to remove sensitive values
        jsonb_build_object(
            'timeout_seconds', v_tool_record.execution_config->>'timeout_seconds',
            'max_memory_mb', v_tool_record.execution_config->>'max_memory_mb'
        ),
        v_tool_record.required_permissions,
        v_tool_record.dependencies,
        v_tool_record.timeout_seconds,
        v_tool_record.max_retries,
        v_tool_record.rate_limit_requests,
        v_tool_record.data_access_level,
        v_tool_record.pii_handling;
    
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
    STABLE
    SET search_path = app, pg_temp;

-- -----------------------------------------------------------------------------
-- FUNCTION: search_tools
-- PURPOSE: Search tools by keyword with permission filtering
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.search_tools(
    p_query VARCHAR(255),
    p_category VARCHAR(100) DEFAULT NULL
)
RETURNS TABLE (
    tool_id UUID,
    tool_name VARCHAR(255),
    display_name VARCHAR(255),
    description TEXT,
    category VARCHAR(100),
    relevance_score NUMERIC
) AS $$
DECLARE
    v_user_id UUID;
    v_search_pattern VARCHAR(512);
BEGIN
    -- -------------------------------------------------------------------------
    -- SECURITY
    -- -------------------------------------------------------------------------
    BEGIN
        v_user_id := current_setting('app.current_user_id', true)::UUID;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Authentication required' USING ERRCODE = '28000';
    END;
    
    -- -------------------------------------------------------------------------
    -- INPUT VALIDATION
    -- -------------------------------------------------------------------------
    IF p_query IS NULL OR trim(p_query) = '' THEN
        RAISE EXCEPTION 'Search query is required' USING ERRCODE = '22004';
    END IF;
    
    -- Sanitize search pattern
    v_search_pattern := '%' || lower(regexp_replace(p_query, '[%_]', '', 'g')) || '%';
    
    -- -------------------------------------------------------------------------
    -- SEARCH AND RETURN
    -- -------------------------------------------------------------------------
    
    RETURN QUERY
    SELECT 
        tc.id,
        tc.name,
        tc.display_name,
        tc.description,
        tc.category,
        -- Simple relevance scoring
        CASE 
            WHEN lower(tc.name) = lower(p_query) THEN 1.0
            WHEN lower(tc.display_name) = lower(p_query) THEN 0.9
            WHEN lower(tc.name) LIKE v_search_pattern THEN 0.8
            WHEN lower(tc.display_name) LIKE v_search_pattern THEN 0.7
            WHEN lower(tc.description) LIKE v_search_pattern THEN 0.5
            ELSE 0.1
        END::NUMERIC(3,2) AS relevance_score
    FROM app.tool_catalog tc
    WHERE tc.deleted_at IS NULL
      AND tc.status = 'production'
      AND (
          lower(tc.name) LIKE v_search_pattern
          OR lower(tc.display_name) LIKE v_search_pattern
          OR lower(tc.description) LIKE v_search_pattern
      )
      AND (p_category IS NULL OR tc.category = p_category)
      -- Permission check
      AND (
          tc.required_permissions = ARRAY[]::TEXT[]
          OR app.has_permission(current_user, 'ai:tools:use:any')
          OR app.has_permission(current_user, 'system:admin')
      )
    ORDER BY relevance_score DESC, tc.display_name
    LIMIT 50;
    
    -- -------------------------------------------------------------------------
    -- AUDIT LOG
    -- -------------------------------------------------------------------------
    
    INSERT INTO app.audit_log (
        table_name, action, details, performed_by, result
    ) VALUES (
        'tool_catalog', 'TOOLS_SEARCHED',
        jsonb_build_object(
            'query', p_query,
            'category_filter', p_category
        ),
        v_user_id,
        'success'
    );
    
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
    STABLE
    SET search_path = app, pg_temp;

-- -----------------------------------------------------------------------------
-- FUNCTION COMMENTS
-- -----------------------------------------------------------------------------

COMMENT ON FUNCTION app.get_active_tools(VARCHAR, BOOLEAN) IS 
    'Returns list of active tools filtered by user permissions. 
     Only shows tools where user has all required permissions.
     Set include_dev=true to see development tools.';

COMMENT ON FUNCTION app.get_tool_by_name(VARCHAR, VARCHAR) IS 
    'Retrieves detailed information for a specific tool.
     Performs permission check against tool requirements.
     Returns latest version if version not specified.';

COMMENT ON FUNCTION app.search_tools(VARCHAR, VARCHAR) IS 
    'Searches tools by keyword with relevance scoring.
     Only searches production tools user has access to.';

-- -----------------------------------------------------------------------------
-- GRANTS
-- -----------------------------------------------------------------------------

GRANT EXECUTE ON FUNCTION app.get_active_tools(VARCHAR, BOOLEAN) TO app_readonly;
GRANT EXECUTE ON FUNCTION app.get_active_tools(VARCHAR, BOOLEAN) TO app_readwrite;
GRANT EXECUTE ON FUNCTION app.get_active_tools(VARCHAR, BOOLEAN) TO app_admin;

GRANT EXECUTE ON FUNCTION app.get_tool_by_name(VARCHAR, VARCHAR) TO app_readonly;
GRANT EXECUTE ON FUNCTION app.get_tool_by_name(VARCHAR, VARCHAR) TO app_readwrite;
GRANT EXECUTE ON FUNCTION app.get_tool_by_name(VARCHAR, VARCHAR) TO app_admin;

GRANT EXECUTE ON FUNCTION app.search_tools(VARCHAR, VARCHAR) TO app_readonly;
GRANT EXECUTE ON FUNCTION app.search_tools(VARCHAR, VARCHAR) TO app_readwrite;
GRANT EXECUTE ON FUNCTION app.search_tools(VARCHAR, VARCHAR) TO app_admin;

-- =============================================================================
-- END OF FILE
-- =============================================================================
