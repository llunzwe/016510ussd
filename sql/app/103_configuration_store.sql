-- ============================================================================
-- USSD KERNEL APP SCHEMA - CONFIGURATION STORE
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Mutable configuration with immutable audit trail. Supports
--              feature flags, runtime settings, and schema extensions.
-- Immutability: Config is mutable, but every change is logged immutably
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. CONFIGURATION STORE TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.configuration_store (
    config_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Scope
    application_id UUID,  -- NULL = global config
    environment VARCHAR(20) DEFAULT 'production' CHECK (environment IN ('development', 'staging', 'production')),
    
    -- Config identification
    config_key VARCHAR(100) NOT NULL,
    config_namespace VARCHAR(50) DEFAULT 'default',  -- For grouping
    
    -- Value
    config_value JSONB NOT NULL,
    config_type VARCHAR(20) DEFAULT 'json' CHECK (config_type IN ('string', 'integer', 'boolean', 'json', 'encrypted', 'secret')),
    
    -- Validation
    schema_validation JSONB,  -- JSON schema for validation
    
    -- Metadata
    description TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,  -- Mask in logs
    
    -- Mutable fields (with audit)
    updated_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    updated_by UUID,
    update_reason TEXT,
    
    -- Versioning
    version INTEGER DEFAULT 1,
    
    -- Created (immutable)
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    created_by UUID,
    
    UNIQUE(application_id, environment, config_namespace, config_key)
);

-- ----------------------------------------------------------------------------
-- 2. CONFIG AUDIT LOG
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.configuration_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    config_id UUID NOT NULL,
    
    -- Change details
    previous_value JSONB,
    new_value JSONB,
    change_type VARCHAR(20) NOT NULL,  -- 'create', 'update', 'delete'
    
    -- Context
    changed_by UUID,
    changed_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    change_reason TEXT,
    
    -- Session info
    client_ip INET,
    session_id TEXT
);

-- ----------------------------------------------------------------------------
-- 3. FEATURE FLAGS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.feature_flags (
    flag_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Scope (hierarchical)
    flag_name VARCHAR(100) NOT NULL,
    application_id UUID,  -- NULL = global
    account_id UUID,      -- NULL = not account-specific
    
    -- Flag value
    is_enabled BOOLEAN DEFAULT FALSE,
    
    -- Rollout configuration
    rollout_percentage INTEGER DEFAULT 100 CHECK (rollout_percentage BETWEEN 0 AND 100),
    rollout_strategy VARCHAR(20) DEFAULT 'all' CHECK (rollout_strategy IN ('all', 'percentage', 'whitelist', 'blacklist')),
    rollout_rules JSONB DEFAULT '{}',  -- e.g., {"regions": ["US", "UK"], "account_types": ["premium"]}
    
    -- Metadata
    description TEXT,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    
    -- Mutable with audit
    updated_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    updated_by UUID,
    
    -- Soft delete
    is_deleted BOOLEAN DEFAULT FALSE,
    deleted_at TIMESTAMPTZ,
    deleted_by UUID,
    
    UNIQUE(flag_name, application_id, account_id)
);

-- ----------------------------------------------------------------------------
-- 4. TRANSACTION TYPE SCOPING
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.transaction_type_scoping (
    scoping_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    application_id UUID NOT NULL,
    transaction_type_id UUID NOT NULL REFERENCES ussd_core.transaction_types(type_id),
    
    -- Status in this application
    is_enabled BOOLEAN DEFAULT TRUE,
    
    -- Customization
    custom_name VARCHAR(100),
    custom_description TEXT,
    custom_payload_schema JSONB,  -- Merges with base schema
    
    -- Limits override
    custom_limits JSONB,  -- Override type limits for this app
    
    -- Validation rules
    validation_rules JSONB DEFAULT '[]',  -- Array of rule definitions
    rule_execution_order INTEGER[] DEFAULT '{}',
    
    -- Immutable
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    superseded_by UUID REFERENCES ussd_app.transaction_type_scoping(scoping_id),
    valid_from TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    valid_to TIMESTAMPTZ,
    
    UNIQUE(application_id, transaction_type_id, valid_from)
);

-- ----------------------------------------------------------------------------
-- 5. INDEXES
-- ----------------------------------------------------------------------------
CREATE INDEX idx_config_store_app ON ussd_app.configuration_store(application_id);
CREATE INDEX idx_config_store_key ON ussd_app.configuration_store(config_key);
CREATE INDEX idx_config_store_env ON ussd_app.configuration_store(environment);
CREATE INDEX idx_config_store_namespace ON ussd_app.configuration_store(config_namespace);

CREATE INDEX idx_config_audit_config ON ussd_app.configuration_audit(config_id);
CREATE INDEX idx_config_audit_time ON ussd_app.configuration_audit(changed_at DESC);

CREATE INDEX idx_feature_flags_app ON ussd_app.feature_flags(application_id);
CREATE INDEX idx_feature_flags_name ON ussd_app.feature_flags(flag_name);
CREATE INDEX idx_feature_flags_account ON ussd_app.feature_flags(account_id);

CREATE INDEX idx_tx_scoping_app ON ussd_app.transaction_type_scoping(application_id);
CREATE INDEX idx_tx_scoping_type ON ussd_app.transaction_type_scoping(transaction_type_id);
CREATE INDEX idx_tx_scoping_valid ON ussd_app.transaction_type_scoping(valid_from, valid_to);

-- ----------------------------------------------------------------------------
-- 6. CONFIG CHANGE AUDIT TRIGGER
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd_app.audit_config_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO ussd_app.configuration_audit (
            config_id, previous_value, new_value, change_type,
            changed_by, change_reason, client_ip, session_id
        ) VALUES (
            NEW.config_id, NULL, NEW.config_value, 'create',
            NEW.created_by, 'Initial creation',
            NULLIF(current_setting('app.client_ip', TRUE), '')::INET,
            current_setting('app.session_id', TRUE)
        );
        RETURN NEW;
        
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO ussd_app.configuration_audit (
            config_id, previous_value, new_value, change_type,
            changed_by, change_reason, client_ip, session_id
        ) VALUES (
            NEW.config_id, OLD.config_value, NEW.config_value, 'update',
            NEW.updated_by, NEW.update_reason,
            NULLIF(current_setting('app.client_ip', TRUE), '')::INET,
            current_setting('app.session_id', TRUE)
        );
        
        -- Increment version
        NEW.version = OLD.version + 1;
        NEW.updated_at = ussd_core.precise_now();
        
        RETURN NEW;
        
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO ussd_app.configuration_audit (
            config_id, previous_value, new_value, change_type,
            changed_by, change_reason, client_ip, session_id
        ) VALUES (
            OLD.config_id, OLD.config_value, NULL, 'delete',
            NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID,
            'Configuration deleted',
            NULLIF(current_setting('app.client_ip', TRUE), '')::INET,
            current_setting('app.session_id', TRUE)
        );
        RETURN OLD;
    END IF;
    
    RETURN NULL;
END;
$$;

CREATE TRIGGER trg_config_audit
    AFTER INSERT OR UPDATE OR DELETE ON ussd_app.configuration_store
    FOR EACH ROW
    EXECUTE FUNCTION ussd_app.audit_config_change();

-- ----------------------------------------------------------------------------
-- 7. CONFIGURATION MANAGEMENT FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to get configuration value
CREATE OR REPLACE FUNCTION ussd_app.get_config(
    p_key VARCHAR,
    p_application_id UUID DEFAULT NULL,
    p_namespace VARCHAR DEFAULT 'default',
    p_environment VARCHAR DEFAULT 'production'
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_value JSONB;
BEGIN
    SELECT config_value INTO v_value
    FROM ussd_app.configuration_store
    WHERE config_key = p_key
      AND config_namespace = p_namespace
      AND environment = p_environment
      AND (application_id = p_application_id OR (application_id IS NULL AND p_application_id IS NULL))
    ORDER BY application_id NULLS LAST  -- App-specific overrides global
    LIMIT 1;
    
    RETURN v_value;
END;
$$;

-- Function to set configuration value
CREATE OR REPLACE FUNCTION ussd_app.set_config(
    p_key VARCHAR,
    p_value JSONB,
    p_application_id UUID DEFAULT NULL,
    p_namespace VARCHAR DEFAULT 'default',
    p_environment VARCHAR DEFAULT 'production',
    p_config_type VARCHAR DEFAULT 'json',
    p_reason TEXT DEFAULT NULL,
    p_set_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_config_id UUID;
    v_existing_id UUID;
BEGIN
    -- Check if exists
    SELECT config_id INTO v_existing_id
    FROM ussd_app.configuration_store
    WHERE config_key = p_key
      AND config_namespace = p_namespace
      AND environment = p_environment
      AND (application_id IS NOT DISTINCT FROM p_application_id);
    
    IF v_existing_id IS NOT NULL THEN
        -- Update
        UPDATE ussd_app.configuration_store
        SET config_value = p_value,
            config_type = p_config_type,
            updated_by = COALESCE(p_set_by, NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID),
            update_reason = p_reason
        WHERE config_id = v_existing_id
        RETURNING config_id INTO v_config_id;
    ELSE
        -- Insert
        INSERT INTO ussd_app.configuration_store (
            config_key, config_namespace, config_value, config_type,
            application_id, environment, created_by, update_reason
        ) VALUES (
            p_key, p_namespace, p_value, p_config_type,
            p_application_id, p_environment,
            COALESCE(p_set_by, NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID),
            p_reason
        )
        RETURNING config_id INTO v_config_id;
    END IF;
    
    RETURN v_config_id;
END;
$$;

-- Function to validate config against schema
CREATE OR REPLACE FUNCTION ussd_app.validate_config(
    p_config_id UUID
)
RETURNS TABLE (
    is_valid BOOLEAN,
    errors TEXT[]
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_config ussd_app.configuration_store%ROWTYPE;
BEGIN
    SELECT * INTO v_config
    FROM ussd_app.configuration_store
    WHERE config_id = p_config_id;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, ARRAY['Configuration not found']::TEXT[];
        RETURN;
    END IF;
    
    IF v_config.schema_validation IS NULL THEN
        RETURN QUERY SELECT TRUE, NULL::TEXT[];
        RETURN;
    END IF;
    
    -- Basic type checking (full JSON Schema validation would require extension)
    IF v_config.schema_validation->>'type' IS NOT NULL THEN
        IF jsonb_typeof(v_config.config_value) != v_config.schema_validation->>'type' THEN
            RETURN QUERY SELECT FALSE, ARRAY[format('Type mismatch: expected %s, got %s', 
                v_config.schema_validation->>'type', jsonb_typeof(v_config.config_value))]::TEXT[];
            RETURN;
        END IF;
    END IF;
    
    RETURN QUERY SELECT TRUE, NULL::TEXT[];
END;
$$;

-- ----------------------------------------------------------------------------
-- 8. FEATURE FLAG FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to check if feature is enabled for account
CREATE OR REPLACE FUNCTION ussd_app.is_feature_enabled(
    p_flag_name VARCHAR,
    p_application_id UUID DEFAULT NULL,
    p_account_id UUID DEFAULT NULL,
    p_account_context JSONB DEFAULT '{}'  -- e.g., {"region": "US", "tier": "premium"}
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_flag ussd_app.feature_flags%ROWTYPE;
    v_account_hash INTEGER;
BEGIN
    -- Check account-specific flag first
    IF p_account_id IS NOT NULL THEN
        SELECT * INTO v_flag
        FROM ussd_app.feature_flags
        WHERE flag_name = p_flag_name
          AND account_id = p_account_id
          AND is_deleted = FALSE
          AND (application_id IS NULL OR application_id = p_application_id);
        
        IF FOUND THEN
            RETURN v_flag.is_enabled AND 
                   ussd_app.check_rollout_rules(v_flag, p_account_id, p_account_context);
        END IF;
    END IF;
    
    -- Check app-level flag
    IF p_application_id IS NOT NULL THEN
        SELECT * INTO v_flag
        FROM ussd_app.feature_flags
        WHERE flag_name = p_flag_name
          AND application_id = p_application_id
          AND account_id IS NULL
          AND is_deleted = FALSE;
        
        IF FOUND THEN
            RETURN v_flag.is_enabled AND 
                   ussd_app.check_rollout_rules(v_flag, p_account_id, p_account_context);
        END IF;
    END IF;
    
    -- Check global flag
    SELECT * INTO v_flag
    FROM ussd_app.feature_flags
    WHERE flag_name = p_flag_name
      AND application_id IS NULL
      AND account_id IS NULL
      AND is_deleted = FALSE;
    
    IF FOUND THEN
        RETURN v_flag.is_enabled AND 
               ussd_app.check_rollout_rules(v_flag, p_account_id, p_account_context);
    END IF;
    
    -- Default: disabled
    RETURN FALSE;
END;
$$;

-- Helper function for rollout rules
CREATE OR REPLACE FUNCTION ussd_app.check_rollout_rules(
    p_flag ussd_app.feature_flags,
    p_account_id UUID,
    p_context JSONB
)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    v_account_hash INTEGER;
BEGIN
    CASE p_flag.rollout_strategy
        WHEN 'all' THEN
            RETURN TRUE;
            
        WHEN 'percentage' THEN
            IF p_account_id IS NULL THEN
                RETURN FALSE;  -- Can't do percentage without account
            END IF;
            -- Simple hash-based percentage
            v_account_hash := abs(('x' || substr(md5(p_account_id::TEXT), 1, 8))::bit(32)::INTEGER);
            RETURN (v_account_hash % 100) < p_flag.rollout_percentage;
            
        WHEN 'whitelist' THEN
            -- Check if account is in whitelist
            RETURN p_context->>'account_id' = ANY(
                ARRAY(SELECT jsonb_array_elements_text(p_flag.rollout_rules->'whitelist'))
            );
            
        WHEN 'blacklist' THEN
            -- Check if account is NOT in blacklist
            RETURN NOT (p_context->>'account_id' = ANY(
                ARRAY(SELECT jsonb_array_elements_text(p_flag.rollout_rules->'blacklist'))
            ));
            
        ELSE
            RETURN TRUE;
    END CASE;
END;
$$;

-- Function to toggle feature flag
CREATE OR REPLACE FUNCTION ussd_app.toggle_feature(
    p_flag_name VARCHAR,
    p_enabled BOOLEAN,
    p_application_id UUID DEFAULT NULL,
    p_account_id UUID DEFAULT NULL,
    p_changed_by UUID DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_flag_id UUID;
BEGIN
    SELECT flag_id INTO v_flag_id
    FROM ussd_app.feature_flags
    WHERE flag_name = p_flag_name
      AND application_id IS NOT DISTINCT FROM p_application_id
      AND account_id IS NOT DISTINCT FROM p_account_id
      AND is_deleted = FALSE;
    
    IF v_flag_id IS NOT NULL THEN
        UPDATE ussd_app.feature_flags
        SET is_enabled = p_enabled,
            updated_at = ussd_core.precise_now(),
            updated_by = COALESCE(p_changed_by, NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID)
        WHERE flag_id = v_flag_id;
    ELSE
        RAISE EXCEPTION 'Feature flag not found: %', p_flag_name;
    END IF;
END;
$$;

-- ----------------------------------------------------------------------------
-- 9. TRANSACTION TYPE SCOPING FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to enable transaction type for application
CREATE OR REPLACE FUNCTION ussd_app.enable_transaction_type(
    p_application_id UUID,
    p_transaction_type_code VARCHAR,
    p_custom_config JSONB DEFAULT '{}'
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_type_id UUID;
    v_scoping_id UUID;
BEGIN
    -- Get type ID
    SELECT type_id INTO v_type_id
    FROM ussd_core.transaction_types
    WHERE type_code = p_transaction_type_code AND valid_to IS NULL;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction type not found: %', p_transaction_type_code;
    END IF;
    
    INSERT INTO ussd_app.transaction_type_scoping (
        application_id,
        transaction_type_id,
        custom_name,
        custom_description,
        custom_payload_schema,
        custom_limits,
        validation_rules
    ) VALUES (
        p_application_id,
        v_type_id,
        p_custom_config->>'custom_name',
        p_custom_config->>'custom_description',
        p_custom_config->'custom_payload_schema',
        p_custom_config->'custom_limits',
        p_custom_config->'validation_rules'
    )
    RETURNING scoping_id INTO v_scoping_id;
    
    RETURN v_scoping_id;
END;
$$;

-- ----------------------------------------------------------------------------
-- 10. VIEWS
-- ----------------------------------------------------------------------------

-- Configuration with history
CREATE VIEW ussd_app.configuration_with_history AS
SELECT 
    cs.*,
    (SELECT jsonb_agg(
        jsonb_build_object(
            'changed_at', ca.changed_at,
            'changed_by', ca.changed_by,
            'previous', ca.previous_value,
            'reason', ca.change_reason
        ) ORDER BY ca.changed_at DESC
    ) FROM ussd_app.configuration_audit ca 
    WHERE ca.config_id = cs.config_id 
    LIMIT 10) as recent_history
FROM ussd_app.configuration_store cs;

-- Active feature flags
CREATE VIEW ussd_app.active_feature_flags AS
SELECT 
    ff.*,
    COALESCE(a.name, 'Global') as application_name
FROM ussd_app.feature_flags ff
LEFT JOIN ussd_app.applications a ON ff.application_id = a.application_id
WHERE ff.is_deleted = FALSE;

-- Application transaction types
CREATE VIEW ussd_app.application_transaction_types AS
SELECT 
    ts.*,
    tt.type_code,
    tt.name as base_name,
    tt.description as base_description,
    tt.category,
    tt.amount_min as base_min,
    tt.amount_max as base_max
FROM ussd_app.transaction_type_scoping ts
JOIN ussd_core.transaction_types tt ON ts.transaction_type_id = tt.type_id
WHERE ts.valid_to IS NULL
  AND tt.valid_to IS NULL;

-- ----------------------------------------------------------------------------
-- 11. INITIAL CONFIGURATION
-- ----------------------------------------------------------------------------

-- Global configuration
INSERT INTO ussd_app.configuration_store (config_key, config_value, config_type, description) VALUES
    ('system.maintenance_mode', 'false', 'boolean', 'Global maintenance mode flag'),
    ('system.max_transaction_amount', '1000000', 'integer', 'Maximum transaction amount'),
    ('system.default_currency', '"USD"', 'string', 'Default currency code'),
    ('ussd.session_timeout_seconds', '300', 'integer', 'USSD session timeout'),
    ('ussd.max_menu_depth', '10', 'integer', 'Maximum menu nesting depth'),
    ('notifications.enabled', 'true', 'boolean', 'Enable notifications');

-- Initial feature flags
INSERT INTO ussd_app.feature_flags (flag_name, is_enabled, description) VALUES
    ('beta_features', FALSE, 'Enable beta features globally'),
    ('new_ui', TRUE, 'New user interface rollout'),
    ('advanced_analytics', FALSE, 'Advanced analytics features'),
    ('multi_currency', FALSE, 'Multi-currency support');

-- ----------------------------------------------------------------------------
-- 12. ROW LEVEL SECURITY
-- ----------------------------------------------------------------------------
ALTER TABLE ussd_app.configuration_store ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd_app.feature_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd_app.transaction_type_scoping ENABLE ROW LEVEL SECURITY;

CREATE POLICY config_store_read ON ussd_app.configuration_store
    FOR SELECT USING (TRUE);

CREATE POLICY feature_flags_read ON ussd_app.feature_flags
    FOR SELECT USING (is_deleted = FALSE);

-- ----------------------------------------------------------------------------
-- 13. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_app.configuration_store IS 
    'Mutable configuration with immutable audit trail';
COMMENT ON TABLE ussd_app.configuration_audit IS 
    'Immutable log of all configuration changes';
COMMENT ON TABLE ussd_app.feature_flags IS 
    'Feature flags with hierarchical scoping (global/app/account)';
COMMENT ON FUNCTION ussd_app.is_feature_enabled IS 
    'Checks if feature flag is enabled with rollout rules support';
