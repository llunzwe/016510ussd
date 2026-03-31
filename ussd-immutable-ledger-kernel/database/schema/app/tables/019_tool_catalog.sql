-- =============================================================================
-- ULTIMATE SOFTWARE SECURITY SOLUTIONS & DEFI LIMITED
-- AI Tool Catalog Table (MCP Tool Definitions)
-- =============================================================================
-- Compliance: ISO 27001:2022 (A.9.4, A.12.6), ISO 27018:2019
--             SOC 2 Type II (Change Management), NIST AI RMF
-- Classification: CONFIDENTIAL - Tool Definitions and Security Schemas
-- Version: 1.0.0
-- Author: Database Engineering Team
-- Last Modified: 2026-03-30
-- =============================================================================

-- -----------------------------------------------------------------------------
-- TABLE: tool_catalog
-- PURPOSE: MCP (Model Context Protocol) tool definitions for AI agents
-- SECURITY: Schema validation required; permission enforcement at call time
-- NOTES: Tools are versioned; changes require new version
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS app.tool_catalog (
    -- Primary Identifier
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Tool Identification
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50) NOT NULL DEFAULT '1.0.0',
    
    -- Unique constraint: Tool name + version
    CONSTRAINT uq_tool_catalog_name_version UNIQUE (name, version),
    
    -- Human-readable Information
    display_name VARCHAR(255),
    description TEXT NOT NULL,
    documentation_url TEXT,
    
    -- Tool Classification
    category VARCHAR(100) NOT NULL CHECK (
        category IN ('data_access', 'computation', 'communication', 
                    'integration', 'security', 'analytics', 'automation',
                    'filesystem', 'database', 'api', 'messaging', 'custom')
    ),
    
    -- MCP Protocol Version
    mcp_protocol_version VARCHAR(20) DEFAULT '2024-11-05' CHECK (
        mcp_protocol_version IN ('2024-11-05')
    ),
    
    -- Tool Schema (JSON Schema for input validation)
    input_schema JSONB NOT NULL,
    output_schema JSONB,                -- Expected output structure
    
    -- Schema validation
    CONSTRAINT chk_input_schema_valid CHECK (
        jsonb_typeof(input_schema) = 'object' AND
        input_schema ? 'type'
    ),
    
    -- Kernel Function Reference
    kernel_function VARCHAR(255) NOT NULL,  -- Function/method name to invoke
    kernel_module VARCHAR(255),             -- Module/package path
    
    -- Execution Configuration
    execution_config JSONB DEFAULT '{}'::jsonb,
    
    -- Timeout and Resource Limits
    timeout_seconds INTEGER DEFAULT 30 CHECK (timeout_seconds > 0),
    max_memory_mb INTEGER DEFAULT 512 CHECK (max_memory_mb > 0),
    max_retries INTEGER DEFAULT 3 CHECK (max_retries >= 0),
    
    -- Rate Limiting
    rate_limit_requests INTEGER DEFAULT 100,    -- Per minute
    rate_limit_window_seconds INTEGER DEFAULT 60,
    
    -- Permission Requirements
    required_permissions TEXT[] DEFAULT '{}',
    required_roles TEXT[] DEFAULT '{}',
    
    -- Data Access Classification
    data_access_level VARCHAR(20) DEFAULT 'none' CHECK (
        data_access_level IN ('none', 'read_own', 'read_all', 'write_own', 'write_all', 'admin')
    ),
    sensitive_data_access BOOLEAN DEFAULT FALSE,
    
    -- Security Configuration
    security_config JSONB DEFAULT '{}'::jsonb,
    
    -- PII Handling
    pii_handling VARCHAR(50) DEFAULT 'none' CHECK (
        pii_handling IN ('none', 'detect_only', 'redact', 'reject', 'audit', 'encrypt')
    ),
    
    -- Content Filtering
    input_filtering_enabled BOOLEAN DEFAULT TRUE,
    output_filtering_enabled BOOLEAN DEFAULT TRUE,
    
    -- Deployment Status
    status VARCHAR(20) NOT NULL DEFAULT 'development' CHECK (
        status IN ('development', 'staging', 'production', 'deprecated', 'retired')
    ),
    
    -- Tool Dependencies
    dependencies TEXT[],                -- Other tool names required
    required_integrations TEXT[],       -- External system integrations needed
    
    -- Cost Tracking
    cost_estimate_per_call NUMERIC(10,6),
    billing_category VARCHAR(100),
    
    -- Observability
    observability_config JSONB DEFAULT '{}'::jsonb,
    
    -- Examples and Testing
    example_inputs JSONB,               -- Example valid inputs
    test_cases JSONB,                   -- Automated test definitions
    
    -- Ownership and Governance
    owner_team VARCHAR(100),
    maintained_by UUID REFERENCES app.users(id),
    approved_by UUID REFERENCES app.users(id),
    approval_date TIMESTAMPTZ,
    
    -- Version Control
    previous_version_id UUID REFERENCES app.tool_catalog(id),
    changelog TEXT,
    
    -- Immutable Ledger Integration
    ledger_hash VARCHAR(64),
    ledger_sequence BIGINT,
    
    -- Audit Columns
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES app.users(id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID REFERENCES app.users(id),
    
    -- Soft Delete
    deleted_at TIMESTAMPTZ,
    deleted_by UUID REFERENCES app.users(id),
    
    -- Constraints
    CONSTRAINT chk_production_requires_approval CHECK (
        (status != 'production') OR 
        (approved_by IS NOT NULL AND approval_date IS NOT NULL)
    ),
    CONSTRAINT chk_sensitive_requires_pii_handling CHECK (
        (sensitive_data_access = FALSE) OR 
        (pii_handling IN ('redact', 'reject', 'audit', 'encrypt'))
    )
);

-- -----------------------------------------------------------------------------
-- INDEXES: Optimized for tool discovery and permission checks
-- -----------------------------------------------------------------------------

-- Tool lookup by name (case-insensitive)
CREATE INDEX IF NOT EXISTS idx_tool_catalog_name 
    ON app.tool_catalog USING btree (lower(name));

-- Active production tools
CREATE INDEX IF NOT EXISTS idx_tool_catalog_active 
    ON app.tool_catalog USING btree (name) 
    WHERE status = 'production' AND deleted_at IS NULL;

-- Category filtering
CREATE INDEX IF NOT EXISTS idx_tool_catalog_category 
    ON app.tool_catalog USING btree (category, status);

-- Permission-based filtering
CREATE INDEX IF NOT EXISTS idx_tool_catalog_permissions 
    ON app.tool_catalog USING gin (required_permissions);

-- Data access level queries
CREATE INDEX IF NOT EXISTS idx_tool_catalog_data_access 
    ON app.tool_catalog USING btree (data_access_level, sensitive_data_access);

-- Owner/maintainer queries
CREATE INDEX IF NOT EXISTS idx_tool_catalog_maintainer 
    ON app.tool_catalog USING btree (maintained_by, status);

-- JSONB index for execution config
CREATE INDEX IF NOT EXISTS idx_tool_catalog_exec_config 
    ON app.tool_catalog USING gin (execution_config jsonb_path_ops);

-- Soft delete filtering
CREATE INDEX IF NOT EXISTS idx_tool_catalog_active_flag 
    ON app.tool_catalog USING btree (deleted_at) 
    WHERE deleted_at IS NULL;

-- Version chain lookup
CREATE INDEX IF NOT EXISTS idx_tool_catalog_version_chain 
    ON app.tool_catalog USING btree (previous_version_id) 
    WHERE previous_version_id IS NOT NULL;

-- -----------------------------------------------------------------------------
-- ROW LEVEL SECURITY (RLS): Tool access control
-- -----------------------------------------------------------------------------

ALTER TABLE app.tool_catalog ENABLE ROW LEVEL SECURITY;

-- Policy: Tool discovery based on permissions
CREATE POLICY tool_catalog_select_policy ON app.tool_catalog
    FOR SELECT
    USING (
        deleted_at IS NULL AND
        (
            -- Public tools visible to all authenticated users
            (status = 'production' AND 
             app.has_permission(current_user, 'ai:tools:discover'))
            OR
            -- Development tools visible to developers
            (status IN ('development', 'staging') AND 
             app.has_permission(current_user, 'ai:tools:develop'))
            OR
            -- Maintainer can view their tools
            maintained_by = current_setting('app.current_user_id', true)::UUID
            OR
            -- Admin override
            app.has_permission(current_user, 'system:admin')
        )
    );

-- Policy: Tool creation requires developer permission
CREATE POLICY tool_catalog_insert_policy ON app.tool_catalog
    FOR INSERT
    WITH CHECK (
        app.has_permission(current_user, 'ai:tools:create')
    );

-- Policy: Tool updates restricted to maintainers and admins
CREATE POLICY tool_catalog_update_policy ON app.tool_catalog
    FOR UPDATE
    USING (
        deleted_at IS NULL AND
        (
            maintained_by = current_setting('app.current_user_id', true)::UUID
            OR
            created_by = current_setting('app.current_user_id', true)::UUID
            OR
            app.has_permission(current_user, 'ai:tools:update')
            OR
            app.has_permission(current_user, 'system:admin')
        )
    );

-- Policy: Soft delete only
CREATE POLICY tool_catalog_delete_policy ON app.tool_catalog
    FOR DELETE
    USING (FALSE);

-- -----------------------------------------------------------------------------
-- TRIGGERS: Automated governance and validation
-- -----------------------------------------------------------------------------

-- Trigger: Validate JSON schema on insert/update
CREATE OR REPLACE FUNCTION app.trigger_tool_catalog_validate()
RETURNS TRIGGER AS $$
DECLARE
    schema_valid BOOLEAN;
BEGIN
    -- Basic JSON Schema validation (check required fields exist)
    IF NOT (NEW.input_schema ? 'type') THEN
        RAISE EXCEPTION 'Input schema must have a "type" field'
            USING HINT = 'JSON Schema must specify root type (object, array, etc.)';
    END IF;
    
    -- Validate schema type is valid
    IF NOT (NEW.input_schema->>'type' IN ('object', 'array', 'string', 
                                           'number', 'integer', 'boolean', 'null')) THEN
        RAISE EXCEPTION 'Invalid JSON Schema type: %', NEW.input_schema->>'type';
    END IF;
    
    -- For object types, check if properties or additionalProperties is defined
    IF NEW.input_schema->>'type' = 'object' AND 
       NOT (NEW.input_schema ? 'properties' OR NEW.input_schema ? 'additionalProperties') THEN
        RAISE WARNING 'Object schema should define properties or additionalProperties';
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER tool_catalog_validate
    BEFORE INSERT OR UPDATE ON app.tool_catalog
    FOR EACH ROW
    EXECUTE FUNCTION app.trigger_tool_catalog_validate();

-- Trigger: Set audit fields and compute ledger hash
CREATE OR REPLACE FUNCTION app.trigger_tool_catalog_inserted()
RETURNS TRIGGER AS $$
BEGIN
    -- Set audit fields
    IF NEW.created_by IS NULL THEN
        NEW.created_by := current_setting('app.current_user_id', true)::UUID;
    END IF;
    
    -- Compute ledger hash
    NEW.ledger_hash := encode(
        digest(
            NEW.id::text || NEW.name || NEW.version || NEW.kernel_function || NEW.created_at::text,
            'sha256'
        ),
        'hex'
    );
    
    -- Get ledger sequence
    SELECT COALESCE(MAX(ledger_sequence), 0) + 1 
    INTO NEW.ledger_sequence
    FROM app.tool_catalog;
    
    -- Log to audit
    INSERT INTO app.audit_log (
        table_name, record_id, action,
        new_data, performed_by
    ) VALUES (
        'tool_catalog', NEW.id, 'INSERT',
        jsonb_build_object(
            'name', NEW.name,
            'version', NEW.version,
            'category', NEW.category,
            'status', NEW.status
        ),
        NEW.created_by
    );
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER tool_catalog_inserted
    BEFORE INSERT ON app.tool_catalog
    FOR EACH ROW
    EXECUTE FUNCTION app.trigger_tool_catalog_inserted();

-- Trigger: Update timestamp and log changes
CREATE OR REPLACE FUNCTION app.trigger_tool_catalog_updated()
RETURNS TRIGGER AS $$
BEGIN
    -- Prevent modification of immutable fields
    IF OLD.ledger_hash IS DISTINCT FROM NEW.ledger_hash OR
       OLD.ledger_sequence IS DISTINCT FROM NEW.ledger_sequence THEN
        RAISE EXCEPTION 'Ledger fields are immutable'
            USING HINT = 'ledger_hash and ledger_sequence cannot be modified';
    END IF;
    
    -- Update timestamp
    NEW.updated_at := CURRENT_TIMESTAMP;
    NEW.updated_by := current_setting('app.current_user_id', true)::UUID;
    
    -- Log to audit
    INSERT INTO app.audit_log (
        table_name, record_id, action,
        old_data, new_data, performed_by
    ) VALUES (
        'tool_catalog', NEW.id, 'UPDATE',
        jsonb_build_object('status', OLD.status, 'version', OLD.version),
        jsonb_build_object('status', NEW.status, 'version', NEW.version),
        NEW.updated_by
    );
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER tool_catalog_updated
    BEFORE UPDATE ON app.tool_catalog
    FOR EACH ROW
    EXECUTE FUNCTION app.trigger_tool_catalog_updated();

-- Trigger: Soft delete enforcement
CREATE OR REPLACE FUNCTION app.trigger_tool_catalog_soft_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.deleted_at IS NOT NULL AND OLD.deleted_at IS NULL THEN
        NEW.deleted_by := current_setting('app.current_user_id', true)::UUID;
        
        INSERT INTO app.audit_log (
            table_name, record_id, action,
            old_data, performed_by
        ) VALUES (
            'tool_catalog', NEW.id, 'SOFT_DELETE',
            jsonb_build_object(
                'name', OLD.name,
                'version', OLD.version,
                'status', OLD.status
            ),
            NEW.deleted_by
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER tool_catalog_soft_delete
    BEFORE UPDATE OF deleted_at ON app.tool_catalog
    FOR EACH ROW
    EXECUTE FUNCTION app.trigger_tool_catalog_soft_delete();

-- Trigger: Prevent hard delete
CREATE OR REPLACE FUNCTION app.trigger_tool_catalog_prevent_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Hard delete prohibited. Use soft delete via UPDATE.'
        USING HINT = 'Set deleted_at timestamp to deprecate a tool';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER tool_catalog_prevent_delete
    BEFORE DELETE ON app.tool_catalog
    FOR EACH ROW
    EXECUTE FUNCTION app.trigger_tool_catalog_prevent_delete();

-- -----------------------------------------------------------------------------
-- TABLE COMMENTS
-- -----------------------------------------------------------------------------

COMMENT ON TABLE app.tool_catalog IS 
    'MCP (Model Context Protocol) tool definitions for AI agents. 
     Stores tool schemas, execution configuration, and security policies.';

COMMENT ON COLUMN app.tool_catalog.name IS 'Unique tool identifier (kebab-case)';
COMMENT ON COLUMN app.tool_catalog.input_schema IS 'JSON Schema for input validation';
COMMENT ON COLUMN app.tool_catalog.kernel_function IS 'Function name to invoke in kernel';
COMMENT ON COLUMN app.tool_catalog.required_permissions IS 'Permissions needed to execute';
COMMENT ON COLUMN app.tool_catalog.data_access_level IS 'Data access classification';
COMMENT ON COLUMN app.tool_catalog.pii_handling IS 'PII processing policy';
COMMENT ON COLUMN app.tool_catalog.status IS 'Tool lifecycle status';

-- -----------------------------------------------------------------------------
-- GRANTS
-- -----------------------------------------------------------------------------

GRANT SELECT ON app.tool_catalog TO app_readonly;
GRANT SELECT, INSERT, UPDATE ON app.tool_catalog TO app_readwrite;
GRANT ALL ON app.tool_catalog TO app_admin;

-- =============================================================================
-- END OF FILE
-- =============================================================================
