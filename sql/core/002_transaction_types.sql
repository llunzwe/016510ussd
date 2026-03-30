-- ============================================================================
-- USSD KERNEL CORE SCHEMA - TRANSACTION TYPES REGISTRY
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Global catalogue of allowed transaction types with JSON schema
--              validation rules, required approvals, and validation hooks.
-- Immutability: 100% - New versions created for modifications
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. TRANSACTION TYPES REGISTRY TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_core.transaction_types (
    -- Primary identifier
    type_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Human-readable unique code (e.g., 'TRANSFER', 'RIDE_BOOKING')
    type_code VARCHAR(50) NOT NULL,
    
    -- Versioning for the type definition itself
    version INTEGER NOT NULL DEFAULT 1,
    
    -- Scope: NULL means global, otherwise specific application
    application_id UUID,  -- NULL = global, UUID = app-specific
    
    -- Classification
    category VARCHAR(50) NOT NULL,  -- e.g., 'payment', 'booking', 'loan', 'admin'
    
    -- Descriptive information
    name VARCHAR(100) NOT NULL,
    description TEXT,
    
    -- JSON Schema for payload validation (RFC 7159 compliant)
    -- Uses JSON Schema Draft 7 or later
    payload_schema JSONB NOT NULL DEFAULT '{"type": "object"}',
    
    -- Schema for the response payload
    response_schema JSONB DEFAULT NULL,
    
    -- Approval requirements
    requires_approval BOOLEAN DEFAULT FALSE,
    approver_role_codes TEXT[] DEFAULT '{}',  -- Array of role codes that can approve
    min_approvers INTEGER DEFAULT 1,
    approval_timeout_hours INTEGER DEFAULT 24,
    
    -- Limits and constraints
    amount_min NUMERIC(20, 8),  -- NULL means no minimum
    amount_max NUMERIC(20, 8),  -- NULL means no maximum
    amount_currency VARCHAR(3) DEFAULT 'USD',
    
    -- Daily/transaction limits per account type
    limits_config JSONB DEFAULT '{}',  -- { "daily_max": 1000, "per_tx_max": 500 }
    
    -- Fee configuration reference
    fee_type_id UUID,  -- References fee_types table if applicable
    
    -- Validation hooks (ordered list of hook references)
    pre_validation_hooks UUID[] DEFAULT '{}',
    post_commit_hooks UUID[] DEFAULT '{}',
    
    -- Business logic reference
    processor_module VARCHAR(100),  -- e.g., 'payments.transfer_processor'
    processor_config JSONB DEFAULT '{}',
    
    -- Lifecycle
    status VARCHAR(20) DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'deprecated', 'retired')),
    
    -- Documentation
    documentation_url TEXT,
    example_payload JSONB,
    
    -- Immutable versioning
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    created_by UUID,
    superseded_by UUID REFERENCES ussd_core.transaction_types(type_id),
    valid_from TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    valid_to TIMESTAMPTZ,
    
    -- Audit
    record_hash VARCHAR(64) NOT NULL
);

-- ----------------------------------------------------------------------------
-- 2. CONSTRAINTS AND INDEXES
-- ----------------------------------------------------------------------------

-- Unique constraint: Only one active version per type_code per scope
CREATE UNIQUE INDEX idx_transaction_type_active 
    ON ussd_core.transaction_types(type_code, COALESCE(application_id, '00000000-0000-0000-0000-000000000000'::UUID))
    WHERE valid_to IS NULL;

-- Lookup indexes
CREATE INDEX idx_transaction_type_code ON ussd_core.transaction_types(type_code);
CREATE INDEX idx_transaction_type_app ON ussd_core.transaction_types(application_id) WHERE application_id IS NOT NULL;
CREATE INDEX idx_transaction_type_category ON ussd_core.transaction_types(category);
CREATE INDEX idx_transaction_type_status ON ussd_core.transaction_types(status) WHERE valid_to IS NULL;

-- JSONB indexes for schema queries
CREATE INDEX idx_transaction_type_payload_schema ON ussd_core.transaction_types USING gin(payload_schema);
CREATE INDEX idx_transaction_type_limits ON ussd_core.transaction_types USING gin(limits_config);

-- Validity window
CREATE INDEX idx_transaction_type_valid_range ON ussd_core.transaction_types(valid_from, valid_to);

-- ----------------------------------------------------------------------------
-- 3. IMMUTABILITY TRIGGERS
-- ----------------------------------------------------------------------------
CREATE TRIGGER trg_transaction_types_prevent_update
    BEFORE UPDATE ON ussd_core.transaction_types
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_update();

CREATE TRIGGER trg_transaction_types_prevent_delete
    BEFORE DELETE ON ussd_core.transaction_types
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_delete();

-- ----------------------------------------------------------------------------
-- 4. HASH COMPUTATION TRIGGER
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd_core.compute_type_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_data TEXT;
BEGIN
    v_data := NEW.type_id::TEXT || 
              NEW.type_code || 
              NEW.version::TEXT ||
              COALESCE(NEW.application_id::TEXT, '') ||
              NEW.payload_schema::TEXT ||
              NEW.created_at::TEXT;
    NEW.record_hash := ussd_core.generate_hash(v_data);
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_transaction_types_compute_hash
    BEFORE INSERT ON ussd_core.transaction_types
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.compute_type_hash();

-- ----------------------------------------------------------------------------
-- 5. VALIDATION FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to validate payload against JSON schema
-- Note: This is a placeholder. For production, use pg_jsonschema extension
-- or implement validation in application layer
CREATE OR REPLACE FUNCTION ussd_core.validate_payload(
    p_payload JSONB,
    p_type_id UUID
)
RETURNS TABLE (
    is_valid BOOLEAN,
    errors TEXT[]
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_schema JSONB;
    v_errors TEXT[] := '{}';
BEGIN
    SELECT payload_schema INTO v_schema
    FROM ussd_core.transaction_types
    WHERE type_id = p_type_id AND valid_to IS NULL;
    
    IF v_schema IS NULL THEN
        RETURN QUERY SELECT FALSE, ARRAY['Transaction type not found or inactive']::TEXT[];
        RETURN;
    END IF;
    
    -- Basic validation: check if payload is an object
    IF jsonb_typeof(p_payload) != 'object' THEN
        v_errors := array_append(v_errors, 'Payload must be an object');
    END IF;
    
    -- Check required fields from schema
    IF v_schema ? 'required' THEN
        -- Simple required field check
        -- Full JSON Schema validation would require pg_jsonschema extension
        NULL;  -- Placeholder
    END IF;
    
    IF array_length(v_errors, 1) IS NULL THEN
        is_valid := TRUE;
    ELSE
        is_valid := FALSE;
    END IF;
    
    RETURN QUERY SELECT is_valid, v_errors;
END;
$$;

-- Function to check if account can execute transaction type
CREATE OR REPLACE FUNCTION ussd_core.can_execute_type(
    p_account_id UUID,
    p_type_id UUID
)
RETURNS TABLE (
    allowed BOOLEAN,
    reason TEXT
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_type_record ussd_core.transaction_types%ROWTYPE;
    v_account_record ussd_core.account_registry%ROWTYPE;
BEGIN
    -- Get transaction type
    SELECT * INTO v_type_record
    FROM ussd_core.transaction_types
    WHERE type_id = p_type_id AND valid_to IS NULL;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, 'Transaction type not found or inactive'::TEXT;
        RETURN;
    END IF;
    
    -- Get account
    SELECT * INTO v_account_record
    FROM ussd_core.account_registry
    WHERE account_id = p_account_id AND valid_to IS NULL;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, 'Account not found or inactive'::TEXT;
        RETURN;
    END IF;
    
    -- Check if type is application-scoped and account has membership
    IF v_type_record.application_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM ussd_app.account_memberships am
            WHERE am.account_id = p_account_id
              AND am.application_id = v_type_record.application_id
              AND am.valid_to IS NULL
        ) THEN
            RETURN QUERY SELECT FALSE, 'Account not enrolled in application'::TEXT;
            RETURN;
        END IF;
    END IF;
    
    RETURN QUERY SELECT TRUE, NULL::TEXT;
END;
$$;

-- ----------------------------------------------------------------------------
-- 6. VERSIONING FUNCTION
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ussd_core.create_transaction_type_version(
    p_type_id UUID,
    p_new_payload_schema JSONB DEFAULT NULL,
    p_new_limits_config JSONB DEFAULT NULL,
    p_new_status VARCHAR(20) DEFAULT NULL,
    p_reason TEXT DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_old_record ussd_core.transaction_types%ROWTYPE;
    v_new_type_id UUID;
BEGIN
    SELECT * INTO v_old_record
    FROM ussd_core.transaction_types
    WHERE type_id = p_type_id AND valid_to IS NULL;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction type not found: %', p_type_id;
    END IF;
    
    INSERT INTO ussd_core.transaction_types (
        type_code,
        version,
        application_id,
        category,
        name,
        description,
        payload_schema,
        response_schema,
        requires_approval,
        approver_role_codes,
        min_approvers,
        approval_timeout_hours,
        amount_min,
        amount_max,
        amount_currency,
        limits_config,
        fee_type_id,
        pre_validation_hooks,
        post_commit_hooks,
        processor_module,
        processor_config,
        status,
        documentation_url,
        example_payload,
        created_by,
        valid_from
    ) VALUES (
        v_old_record.type_code,
        v_old_record.version + 1,
        v_old_record.application_id,
        v_old_record.category,
        v_old_record.name,
        v_old_record.description,
        COALESCE(p_new_payload_schema, v_old_record.payload_schema),
        v_old_record.response_schema,
        v_old_record.requires_approval,
        v_old_record.approver_role_codes,
        v_old_record.min_approvers,
        v_old_record.approval_timeout_hours,
        v_old_record.amount_min,
        v_old_record.amount_max,
        v_old_record.amount_currency,
        COALESCE(p_new_limits_config, v_old_record.limits_config),
        v_old_record.fee_type_id,
        v_old_record.pre_validation_hooks,
        v_old_record.post_commit_hooks,
        v_old_record.processor_module,
        v_old_record.processor_config,
        COALESCE(p_new_status, v_old_record.status),
        v_old_record.documentation_url,
        v_old_record.example_payload,
        v_old_record.created_by,
        ussd_core.precise_now()
    )
    RETURNING type_id INTO v_new_type_id;
    
    -- Log audit
    PERFORM ussd_audit.log_audit_event(
        'ussd_core', 'transaction_types',
        v_new_type_id::TEXT,
        'UPDATE',
        to_jsonb(v_old_record),
        NULL,
        p_reason
    );
    
    RETURN v_new_type_id;
END;
$$;

-- ----------------------------------------------------------------------------
-- 7. ROW LEVEL SECURITY
-- ----------------------------------------------------------------------------
ALTER TABLE ussd_core.transaction_types ENABLE ROW LEVEL SECURITY;

CREATE POLICY transaction_types_read ON ussd_core.transaction_types
    FOR SELECT
    USING (status = 'active' OR status = 'deprecated' OR 
           NULLIF(current_setting('app.is_admin', TRUE), '')::BOOLEAN = TRUE);

-- ----------------------------------------------------------------------------
-- 8. VIEWS
-- ----------------------------------------------------------------------------

-- Active transaction types
CREATE VIEW ussd_core.active_transaction_types AS
SELECT *
FROM ussd_core.transaction_types
WHERE valid_to IS NULL
  AND status IN ('active', 'deprecated');

-- Global transaction types
CREATE VIEW ussd_core.global_transaction_types AS
SELECT *
FROM ussd_core.active_transaction_types
WHERE application_id IS NULL;

-- ----------------------------------------------------------------------------
-- 9. INITIAL TRANSACTION TYPES (Kernel-Only, Business-Agnostic)
-- ----------------------------------------------------------------------------
-- Note: Business-specific transaction types should be registered by applications
-- using the ussd_app.enable_transaction_type_for_app() function

INSERT INTO ussd_core.transaction_types (
    type_id,
    type_code,
    category,
    name,
    description,
    payload_schema,
    status,
    created_by
) VALUES
-- Kernel system types (generic, no business logic)
(
    '10000000-0000-0000-0000-000000000001'::UUID,
    'SYSTEM_ACCOUNT_CREATE',
    'system',
    'System Account Creation',
    'Kernel-level account initialization',
    '{"type": "object", "required": ["account_type"], 
      "properties": {"account_type": {"type": "string"}, 
                     "metadata": {"type": "object"}}}',
    'active',
    '00000000-0000-0000-0000-000000000001'::UUID
),
(
    '10000000-0000-0000-0000-000000000002'::UUID,
    'SYSTEM_CONFIG_UPDATE',
    'system',
    'System Configuration Update',
    'Kernel configuration change',
    '{"type": "object", "required": ["config_key", "config_value"], 
      "properties": {"config_key": {"type": "string"}, 
                     "config_value": {},
                     "reason": {"type": "string"}}}',
    'active',
    '00000000-0000-0000-0000-000000000001'::UUID
);

-- ----------------------------------------------------------------------------
-- 10. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_core.transaction_types IS 
    'Immutable registry of transaction type definitions with JSON schema validation';
COMMENT ON COLUMN ussd_core.transaction_types.payload_schema IS 
    'JSON Schema (Draft 7+) for validating transaction payloads';
COMMENT ON COLUMN ussd_core.transaction_types.pre_validation_hooks IS 
    'Ordered array of hook IDs to execute before validation';
COMMENT ON COLUMN ussd_core.transaction_types.processor_module IS 
    'Reference to business logic processor for this transaction type';
