/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - AI GOVERNANCE FUNCTIONS
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-FUNC-008
 * Feature Name:       AI Governance Functions
 * Description:        Functions for AI model validation, inference tracking,
 *                     and governance compliance. Supports EU AI Act, GDPR
 *                     Article 22 (automated decision-making), and model
 *                     lifecycle management.
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
 * EU AI Act (Regulation 2024/1689)
 *   - Article 10: Data and data governance
 *   - Article 12: Record-keeping
 *   - Article 14: Human oversight
 *   - Article 15: Accuracy, robustness, cybersecurity
 *   - Risk-based classification (minimal, limited, high, unacceptable)
 * 
 * GDPR (General Data Protection Regulation)
 *   - Article 22: Automated individual decision-making
 *   - Article 35: Data protection impact assessment
 *   - Article 44: International transfers
 * 
 * ISO/IEC 27001:2022 (ISMS)
 *   - Control A.8.9: Configuration management
 *   - Control A.8.10: Deletion of information
 *   - Control A.12.4: Logging and monitoring
 * 
 * ISO/IEC 27018:2019 (PII Protection)
 *   - PII in AI training data
 *   - Automated processing safeguards
 * 
 * SOC 2 Type II
 *   - AI model governance controls
 *   - Inference logging and audit
 * 
 * =============================================================================
 * AUDIT TRAIL REQUIREMENTS
 * =============================================================================
 * 
 * MANDATORY AUDIT EVENTS:
 *   - Model registered/versioned
 *   - Model deployment status changes
 *   - Inference execution (all inputs/outputs)
 *   - High-risk AI system usage
 *   - Human oversight activation
 *   - Tool execution
 *   - PII detected in AI processing
 * 
 * AUDIT RETENTION: 7 years (configurable per compliance framework)
 * =============================================================================
 */

-- =============================================================================
-- COMPLIANCE STANDARDS
-- =============================================================================
-- EU AI Act - Risk-based AI governance
-- GDPR - Automated decision-making
-- ISO/IEC 27001:2022 - ISMS Framework
-- ISO/IEC 27018:2019 - PII Protection
-- SOC 2 Type II - AI Model Governance
-- =============================================================================

-- =============================================================================
-- FUNCTION: Register AI Model
-- EU AI Act Article 12: Record-keeping for AI systems
-- =============================================================================

CREATE OR REPLACE FUNCTION app.register_ai_model(
    p_name VARCHAR(255),
    p_version VARCHAR(50),
    p_type VARCHAR(100) DEFAULT 'custom',
    p_framework VARCHAR(50) DEFAULT 'custom',
    p_architecture VARCHAR(100) DEFAULT NULL,
    p_risk_level VARCHAR(20) DEFAULT 'limited',
    p_deployment_status VARCHAR(50) DEFAULT 'development',
    p_metadata JSONB DEFAULT '{}',
    p_performance_metrics JSONB DEFAULT '{}',
    p_training_dataset_hash VARCHAR(64) DEFAULT NULL,
    p_training_data_provenance JSONB DEFAULT NULL,
    p_human_oversight_required BOOLEAN DEFAULT FALSE
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_model_id UUID;
    v_current_user UUID;
    v_validated_risk_level VARCHAR(20);
BEGIN
    -- [TXN] EU AI Act: ACID transaction boundary
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Authorization check
    IF NOT app.check_permission(
        current_setting('app.current_membership_id', TRUE)::UUID, 
        'ai:models:create'
    ) THEN
        RAISE EXCEPTION '[RBAC] Insufficient privileges to register AI model';
    END IF;
    
    -- Validate risk level per EU AI Act
    IF p_risk_level NOT IN ('minimal', 'limited', 'high', 'unacceptable') THEN
        RAISE EXCEPTION '[VALIDATION] Invalid risk level. Must be: minimal, limited, high, or unacceptable';
    END IF;
    
    -- High-risk AI requires human oversight per EU AI Act Article 14
    IF p_risk_level = 'high' AND NOT COALESCE(p_human_oversight_required, FALSE) THEN
        v_validated_risk_level := p_risk_level;
        -- Force oversight requirement
        NULL;
    ELSE
        v_validated_risk_level := p_risk_level;
    END IF;
    
    -- Validate model type
    IF p_type NOT IN (
        'classification', 'regression', 'generation', 
        'embedding', 'multimodal', 'reinforcement',
        'time_series', 'anomaly_detection', 'nlp',
        'computer_vision', 'speech_recognition', 'custom'
    ) THEN
        RAISE EXCEPTION '[VALIDATION] Invalid model type: %', p_type;
    END IF;
    
    -- Check for duplicate name+version
    IF EXISTS (
        SELECT 1 FROM app.model_registry 
        WHERE name = p_name AND version = p_version AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION '[CONFLICT] Model % version % already exists', p_name, p_version;
    END IF;
    
    -- Insert model record
    INSERT INTO app.model_registry (
        name,
        version,
        type,
        framework,
        architecture,
        risk_level,
        deployment_status,
        metadata,
        performance_metrics,
        training_dataset_hash,
        training_data_provenance,
        human_oversight_required,
        created_by,
        updated_by
    ) VALUES (
        p_name,
        p_version,
        p_type,
        p_framework,
        p_architecture,
        v_validated_risk_level,
        p_deployment_status,
        p_metadata,
        p_performance_metrics,
        p_training_dataset_hash,
        p_training_data_provenance,
        CASE WHEN v_validated_risk_level = 'high' THEN TRUE ELSE p_human_oversight_required END,
        v_current_user,
        v_current_user
    )
    RETURNING id INTO v_model_id;
    
    -- [AUDIT] EU AI Act Article 12: Log model registration
    INSERT INTO core.t_audit_trail (
        table_name,
        record_id,
        action,
        new_values,
        performed_by,
        performed_at,
        severity
    ) VALUES (
        'app.model_registry',
        v_model_id,
        'MODEL_REGISTERED',
        jsonb_build_object(
            'name', p_name,
            'version', p_version,
            'type', p_type,
            'risk_level', v_validated_risk_level,
            'human_oversight_required', CASE WHEN v_validated_risk_level = 'high' THEN TRUE ELSE p_human_oversight_required END
        ),
        v_current_user,
        NOW(),
        CASE WHEN v_validated_risk_level IN ('high', 'unacceptable') THEN 'high' ELSE 'normal' END
    );
    
    -- Alert if high-risk
    IF v_validated_risk_level = 'high' THEN
        PERFORM pg_notify('ai_governance_alert', jsonb_build_object(
            'type', 'high_risk_model_registered',
            'model_id', v_model_id,
            'model_name', p_name,
            'risk_level', v_validated_risk_level
        )::TEXT);
    END IF;
    
    RETURN v_model_id;
END;
$$;

COMMENT ON FUNCTION app.register_ai_model IS 
    'Register AI model with EU AI Act compliance. Article 12: Record-keeping. ' ||
    'Auto-enforces human oversight for high-risk systems.';

-- =============================================================================
-- FUNCTION: Approve Model for Production
-- EU AI Act: Human oversight for high-risk AI deployment
-- =============================================================================

CREATE OR REPLACE FUNCTION app.approve_model_for_production(
    p_model_id UUID,
    p_governance_review_id UUID DEFAULT NULL,
    p_approval_notes TEXT DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_current_membership UUID;
    v_current_user UUID;
    v_model_record RECORD;
BEGIN
    -- [TXN] EU AI Act: ACID transaction boundary
    v_current_membership := current_setting('app.current_membership_id', TRUE)::UUID;
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Get model details
    SELECT * INTO v_model_record
    FROM app.model_registry
    WHERE id = p_model_id AND deleted_at IS NULL;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION '[NOT_FOUND] Model % not found', p_model_id;
    END IF;
    
    -- Check authorization based on risk level
    IF v_model_record.risk_level = 'high' THEN
        -- High-risk requires platform admin approval
        IF NOT app.check_permission(v_current_membership, 'platform:admin:ai:governance') THEN
            RAISE EXCEPTION '[RBAC] High-risk models require platform admin approval';
        END IF;
        
        -- Must have governance review for high-risk
        IF p_governance_review_id IS NULL THEN
            RAISE EXCEPTION '[GOVERNANCE] High-risk models require governance review ID';
        END IF;
    ELSE
        -- Lower risk levels can be approved by AI admin
        IF NOT app.check_permission(v_current_membership, 'ai:models:approve') THEN
            RAISE EXCEPTION '[RBAC] Insufficient privileges to approve models';
        END IF;
    END IF;
    
    -- Update model status
    UPDATE app.model_registry
    SET deployment_status = 'production',
        approved_by = v_current_user,
        approval_date = NOW(),
        governance_review_id = p_governance_review_id,
        updated_at = NOW(),
        updated_by = v_current_user,
        is_immutable = TRUE  -- Production models become immutable
    WHERE id = p_model_id;
    
    -- [AUDIT] EU AI Act: Log production approval
    INSERT INTO core.t_audit_trail (
        table_name,
        record_id,
        action,
        old_values,
        new_values,
        performed_by,
        performed_at,
        severity
    ) VALUES (
        'app.model_registry',
        p_model_id,
        'MODEL_APPROVED_PRODUCTION',
        jsonb_build_object('deployment_status', v_model_record.deployment_status),
        jsonb_build_object(
            'deployment_status', 'production',
            'governance_review_id', p_governance_review_id,
            'approval_notes', p_approval_notes
        ),
        v_current_user,
        NOW(),
        CASE WHEN v_model_record.risk_level = 'high' THEN 'high' ELSE 'normal' END
    );
    
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION app.approve_model_for_production IS 
    'Approve model for production deployment. EU AI Act: Human oversight required.';

-- =============================================================================
-- FUNCTION: Log AI Inference
-- EU AI Act Article 12: Automatic logging of AI system activity
-- GDPR Article 22: Automated decision-making records
-- =============================================================================

CREATE OR REPLACE FUNCTION app.log_inference(
    p_model_id UUID,
    p_input_data JSONB,
    p_output_data JSONB,
    p_confidence_score NUMERIC DEFAULT NULL,
    p_inference_type VARCHAR(50) DEFAULT 'realtime',
    p_user_id UUID DEFAULT NULL,
    p_session_id UUID DEFAULT NULL,
    p_correlation_id VARCHAR(255) DEFAULT NULL,
    p_latency_ms INTEGER DEFAULT NULL,
    p_tokens_input INTEGER DEFAULT NULL,
    p_tokens_output INTEGER DEFAULT NULL,
    p_billing_tag VARCHAR(100) DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_inference_id UUID;
    v_current_user UUID;
    v_model_risk_level VARCHAR(20);
    v_contains_pii BOOLEAN;
    v_pii_types TEXT[];
    v_data_classification VARCHAR(20);
    v_retention_until DATE;
    v_input_hash VARCHAR(64);
    v_output_hash VARCHAR(64);
BEGIN
    -- [TXN] EU AI Act: ACID transaction boundary
    v_current_user := COALESCE(p_user_id, current_setting('app.current_user_id', TRUE)::UUID);
    
    -- Verify model exists
    SELECT risk_level INTO v_model_risk_level
    FROM app.model_registry
    WHERE id = p_model_id AND deleted_at IS NULL;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION '[NOT_FOUND] Model % not found', p_model_id;
    END IF;
    
    -- Calculate hashes for integrity
    v_input_hash := encode(digest(p_input_data::TEXT, 'sha256'), 'hex');
    v_output_hash := encode(digest(p_output_data::TEXT, 'sha256'), 'hex');
    
    -- PII Detection (basic pattern matching)
    v_contains_pii := FALSE;
    v_pii_types := ARRAY[]::TEXT[];
    v_data_classification := 'internal';
    
    -- Check for common PII patterns in input
    IF p_input_data::TEXT ~* '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b' THEN
        v_contains_pii := TRUE;
        v_pii_types := array_append(v_pii_types, 'email');
    END IF;
    
    IF p_input_data::TEXT ~* '\b\d{3}-\d{2}-\d{4}\b' OR p_input_data::TEXT ~* '\b\d{9}\b' THEN
        v_contains_pii := TRUE;
        v_pii_types := array_append(v_pii_types, 'ssn');
    END IF;
    
    IF p_input_data::TEXT ~* '\b\d{3}-\d{3}-\d{4}\b' THEN
        v_contains_pii := TRUE;
        v_pii_types := array_append(v_pii_types, 'phone');
    END IF;
    
    IF p_input_data::TEXT ~* '(?i)(credit.?card|card.?number).*\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}' THEN
        v_contains_pii := TRUE;
        v_pii_types := array_append(v_pii_types, 'credit_card');
        v_data_classification := 'restricted';
    END IF;
    
    -- Adjust classification if PII detected
    IF v_contains_pii THEN
        v_data_classification := 'confidential';
    END IF;
    
    -- Set retention (7 years default per compliance)
    v_retention_until := CURRENT_DATE + INTERVAL '7 years';
    
    -- Insert inference log
    INSERT INTO app.inference_log (
        model_id,
        request_id,
        correlation_id,
        input_data,
        input_hash,
        input_size_bytes,
        output_data,
        output_hash,
        output_size_bytes,
        confidence_score,
        confidence_threshold,
        latency_ms,
        tokens_input,
        tokens_output,
        inference_type,
        user_id,
        session_id,
        contains_pii,
        pii_types_detected,
        pii_redaction_applied,
        data_classification,
        status,
        compliance_frameworks,
        retention_until,
        billing_tag,
        created_by,
        partition_date
    ) VALUES (
        p_model_id,
        gen_random_uuid(),
        p_correlation_id,
        p_input_data,
        v_input_hash,
        length(p_input_data::TEXT),
        p_output_data,
        v_output_hash,
        length(p_output_data::TEXT),
        p_confidence_score,
        CASE WHEN p_confidence_score IS NOT NULL THEN 0.5 ELSE NULL END,
        COALESCE(p_latency_ms, 0),
        p_tokens_input,
        p_tokens_output,
        p_inference_type,
        v_current_user,
        p_session_id,
        v_contains_pii,
        v_pii_types,
        FALSE,  -- redaction would be applied at ingestion
        v_data_classification,
        'success',
        CASE WHEN v_model_risk_level = 'high' THEN ARRAY['EU_AI_ACT', 'GDPR']::TEXT[] ELSE ARRAY['GDPR']::TEXT[] END,
        v_retention_until,
        p_billing_tag,
        v_current_user,
        CURRENT_DATE
    )
    RETURNING id INTO v_inference_id;
    
    -- [AUDIT] EU AI Act Article 12: Log inference (for high-risk only in main audit trail)
    IF v_model_risk_level = 'high' THEN
        INSERT INTO core.t_audit_trail (
            table_name,
            record_id,
            action,
            new_values,
            performed_by,
            performed_at,
            severity
        ) VALUES (
            'app.inference_log',
            v_inference_id,
            'HIGH_RISK_INFERENCE',
            jsonb_build_object(
                'model_id', p_model_id,
                'inference_type', p_inference_type,
                'contains_pii', v_contains_pii,
                'confidence_score', p_confidence_score
            ),
            v_current_user,
            NOW(),
            'high'
        );
        
        -- Alert for high-risk AI usage
        PERFORM pg_notify('ai_governance_alert', jsonb_build_object(
            'type', 'high_risk_inference',
            'inference_id', v_inference_id,
            'model_id', p_model_id,
            'user_id', v_current_user
        )::TEXT);
    END IF;
    
    RETURN v_inference_id;
END;
$$;

COMMENT ON FUNCTION app.log_inference IS 
    'Log AI inference with EU AI Act compliance. Article 12: Record-keeping. ' ||
    'Auto-detects PII, calculates hashes, sets retention.';

-- =============================================================================
-- FUNCTION: Register MCP Tool
-- ISO 27001: Tool catalog management
-- =============================================================================

CREATE OR REPLACE FUNCTION app.register_tool(
    p_name VARCHAR(255),
    p_description TEXT,
    p_category VARCHAR(100),
    p_kernel_function VARCHAR(255),
    p_input_schema JSONB,
    p_output_schema JSONB DEFAULT NULL,
    p_required_permissions TEXT[] DEFAULT '{}',
    p_data_access_level VARCHAR(20) DEFAULT 'none',
    p_sensitive_data_access BOOLEAN DEFAULT FALSE,
    p_timeout_seconds INTEGER DEFAULT 30,
    p_max_memory_mb INTEGER DEFAULT 512,
    p_rate_limit_requests INTEGER DEFAULT 100,
    p_pii_handling VARCHAR(50) DEFAULT 'none',
    p_status VARCHAR(20) DEFAULT 'development'
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_tool_id UUID;
    v_current_user UUID;
    v_version VARCHAR(50) := '1.0.0';
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Authorization check
    IF NOT app.check_permission(
        current_setting('app.current_membership_id', TRUE)::UUID,
        'ai:tools:create'
    ) THEN
        RAISE EXCEPTION '[RBAC] Insufficient privileges to register tools';
    END IF;
    
    -- Validate category
    IF p_category NOT IN (
        'data_access', 'computation', 'communication', 
        'integration', 'security', 'analytics', 'automation',
        'filesystem', 'database', 'api', 'messaging', 'custom'
    ) THEN
        RAISE EXCEPTION '[VALIDATION] Invalid tool category: %', p_category;
    END IF;
    
    -- Validate input schema
    IF NOT (p_input_schema ? 'type') THEN
        RAISE EXCEPTION '[VALIDATION] Input schema must have a "type" field';
    END IF;
    
    -- Check for duplicate name
    IF EXISTS (
        SELECT 1 FROM app.tool_catalog 
        WHERE name = p_name AND deleted_at IS NULL
    ) THEN
        -- Increment version if tool exists
        SELECT version INTO v_version
        FROM app.tool_catalog
        WHERE name = p_name AND deleted_at IS NULL
        ORDER BY created_at DESC
        LIMIT 1;
        
        -- Simple version increment (in production, use semantic versioning)
        v_version := split_part(v_version, '.', 1) || '.' || 
                    (split_part(v_version, '.', 2)::INTEGER + 1)::TEXT || '.0';
    END IF;
    
    -- Insert tool record
    INSERT INTO app.tool_catalog (
        name,
        version,
        display_name,
        description,
        category,
        kernel_function,
        input_schema,
        output_schema,
        required_permissions,
        data_access_level,
        sensitive_data_access,
        timeout_seconds,
        max_memory_mb,
        rate_limit_requests,
        pii_handling,
        status,
        created_by,
        updated_by
    ) VALUES (
        p_name,
        v_version,
        p_name,  -- display_name defaults to name
        p_description,
        p_category,
        p_kernel_function,
        p_input_schema,
        p_output_schema,
        p_required_permissions,
        p_data_access_level,
        p_sensitive_data_access,
        p_timeout_seconds,
        p_max_memory_mb,
        p_rate_limit_requests,
        p_pii_handling,
        p_status,
        v_current_user,
        v_current_user
    )
    RETURNING id INTO v_tool_id;
    
    -- [AUDIT] Log tool registration
    INSERT INTO core.t_audit_trail (
        table_name,
        record_id,
        action,
        new_values,
        performed_by,
        performed_at
    ) VALUES (
        'app.tool_catalog',
        v_tool_id,
        'TOOL_REGISTERED',
        jsonb_build_object(
            'name', p_name,
            'version', v_version,
            'category', p_category,
            'data_access_level', p_data_access_level,
            'sensitive_data_access', p_sensitive_data_access
        ),
        v_current_user,
        NOW()
    );
    
    RETURN v_tool_id;
END;
$$;

COMMENT ON FUNCTION app.register_tool IS 
    'Register MCP tool with governance controls. ISO 27001: Tool management.';

-- =============================================================================
-- FUNCTION: Validate Tool Access
-- ISO 27001: Access control for tool execution
-- =============================================================================

CREATE OR REPLACE FUNCTION app.validate_tool_access(
    p_tool_id UUID,
    p_membership_id UUID
)
RETURNS TABLE (
    allowed BOOLEAN,
    tool_name VARCHAR(255),
    data_access_level VARCHAR(20),
    requires_pii_handling VARCHAR(50),
    message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = app, core, public
AS $$
DECLARE
    v_tool_record RECORD;
    v_has_permission BOOLEAN := FALSE;
    v_required_perm TEXT;
BEGIN
    -- Get tool details
    SELECT * INTO v_tool_record
    FROM app.tool_catalog
    WHERE id = p_tool_id AND deleted_at IS NULL;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT 
            FALSE, 
            NULL::VARCHAR(255), 
            NULL::VARCHAR(20), 
            NULL::VARCHAR(50),
            'Tool not found'::TEXT;
        RETURN;
    END IF;
    
    -- Check if tool is production ready
    IF v_tool_record.status != 'production' THEN
        -- Allow developers to access non-production tools
        IF NOT app.check_permission(p_membership_id, 'ai:tools:develop') THEN
            RETURN QUERY SELECT 
                FALSE, 
                v_tool_record.name::VARCHAR(255), 
                NULL::VARCHAR(20), 
                NULL::VARCHAR(50),
                'Tool not in production status'::TEXT;
            RETURN;
        END IF;
    END IF;
    
    -- Check required permissions
    IF array_length(v_tool_record.required_permissions, 1) > 0 THEN
        FOREACH v_required_perm IN ARRAY v_tool_record.required_permissions
        LOOP
            IF app.check_permission(p_membership_id, v_required_perm) THEN
                v_has_permission := TRUE;
                EXIT;
            END IF;
        END LOOP;
        
        IF NOT v_has_permission THEN
            RETURN QUERY SELECT 
                FALSE, 
                v_tool_record.name::VARCHAR(255), 
                NULL::VARCHAR(20), 
                NULL::VARCHAR(50),
                'Insufficient permissions for tool execution'::TEXT;
            RETURN;
        END IF;
    ELSE
        v_has_permission := TRUE;
    END IF;
    
    -- All checks passed
    RETURN QUERY SELECT 
        TRUE,
        v_tool_record.name::VARCHAR(255),
        v_tool_record.data_access_level::VARCHAR(20),
        v_tool_record.pii_handling::VARCHAR(50),
        'Access granted'::TEXT;
END;
$$;

COMMENT ON FUNCTION app.validate_tool_access IS 
    'Validate if membership can access tool. ISO 27001: Access control.';

-- =============================================================================
-- FUNCTION: Get Model by Name
-- Helper for model lookup
-- =============================================================================

CREATE OR REPLACE FUNCTION app.get_model_by_name(
    p_model_name VARCHAR(255),
    p_version VARCHAR(50) DEFAULT NULL
)
RETURNS TABLE (
    model_id UUID,
    name VARCHAR(255),
    version VARCHAR(50),
    type VARCHAR(100),
    deployment_status VARCHAR(50),
    risk_level VARCHAR(20),
    human_oversight_required BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = app, core, public
AS $$
BEGIN
    IF p_version IS NOT NULL THEN
        -- Exact version lookup
        RETURN QUERY
        SELECT 
            mr.id,
            mr.name,
            mr.version,
            mr.type,
            mr.deployment_status,
            mr.risk_level,
            mr.human_oversight_required
        FROM app.model_registry mr
        WHERE mr.name = p_model_name
          AND mr.version = p_version
          AND mr.deleted_at IS NULL;
    ELSE
        -- Latest production version
        RETURN QUERY
        SELECT 
            mr.id,
            mr.name,
            mr.version,
            mr.type,
            mr.deployment_status,
            mr.risk_level,
            mr.human_oversight_required
        FROM app.model_registry mr
        WHERE mr.name = p_model_name
          AND mr.deployment_status = 'production'
          AND mr.deleted_at IS NULL
        ORDER BY mr.created_at DESC
        LIMIT 1;
    END IF;
END;
$$;

COMMENT ON FUNCTION app.get_model_by_name IS 
    'Get model details by name and optional version.';

-- =============================================================================
-- FUNCTION: Get Active Tools
-- List production-ready tools
-- =============================================================================

CREATE OR REPLACE FUNCTION app.get_active_tools(p_category VARCHAR(100) DEFAULT NULL)
RETURNS TABLE (
    tool_id UUID,
    name VARCHAR(255),
    version VARCHAR(50),
    display_name VARCHAR(255),
    category VARCHAR(100),
    description TEXT,
    required_permissions TEXT[]
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = app, core, public
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        tc.id,
        tc.name,
        tc.version,
        tc.display_name,
        tc.category,
        tc.description,
        tc.required_permissions
    FROM app.tool_catalog tc
    WHERE tc.status = 'production'
      AND tc.deleted_at IS NULL
      AND (p_category IS NULL OR tc.category = p_category)
    ORDER BY tc.category, tc.name;
END;
$$;

COMMENT ON FUNCTION app.get_active_tools IS 
    'List all production-ready tools, optionally filtered by category.';

-- =============================================================================
-- FUNCTION: Get Inference Audit Trail
-- GDPR Article 30: Records of processing
-- =============================================================================

CREATE OR REPLACE FUNCTION app.get_inference_audit_trail(
    p_model_id UUID DEFAULT NULL,
    p_user_id UUID DEFAULT NULL,
    p_start_date DATE DEFAULT NULL,
    p_end_date DATE DEFAULT NULL,
    p_limit INTEGER DEFAULT 100
)
RETURNS TABLE (
    inference_id UUID,
    model_name VARCHAR(255),
    model_version VARCHAR(50),
    inference_type VARCHAR(50),
    confidence_score NUMERIC,
    contains_pii BOOLEAN,
    data_classification VARCHAR(20),
    status VARCHAR(20),
    created_at TIMESTAMPTZ,
    request_id UUID
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = app, core, public
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        il.id,
        mr.name,
        mr.version,
        il.inference_type,
        il.confidence_score,
        il.contains_pii,
        il.data_classification,
        il.status,
        il.created_at,
        il.request_id
    FROM app.inference_log il
    INNER JOIN app.model_registry mr ON il.model_id = mr.id
    WHERE (p_model_id IS NULL OR il.model_id = p_model_id)
      AND (p_user_id IS NULL OR il.user_id = p_user_id)
      AND (p_start_date IS NULL OR il.partition_date >= p_start_date)
      AND (p_end_date IS NULL OR il.partition_date <= p_end_date)
    ORDER BY il.created_at DESC
    LIMIT p_limit;
END;
$$;

COMMENT ON FUNCTION app.get_inference_audit_trail IS 
    'Get inference audit trail. GDPR Article 30: Processing records.';

-- =============================================================================
-- ANALYZE for query optimizer
-- =============================================================================
ANALYZE app.model_registry;
ANALYZE app.inference_log;
ANALYZE app.tool_catalog;
ANALYZE app.agent_sessions;
