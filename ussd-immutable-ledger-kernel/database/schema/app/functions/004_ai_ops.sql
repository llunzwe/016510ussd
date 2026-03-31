-- ============================================================================
-- App Schema - AI Operations
-- ============================================================================

-- Function: Register AI model
CREATE OR REPLACE FUNCTION app.register_model(
    p_application_id UUID,
    p_model_name VARCHAR(128),
    p_model_version VARCHAR(32),
    p_model_type VARCHAR(32),
    p_risk_level VARCHAR(16) DEFAULT 'minimal'
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, public
AS $$
DECLARE
    v_model_id UUID;
BEGIN
    v_model_id := gen_random_uuid();

    INSERT INTO app.model_registry (
        model_id,
        model_name,
        model_version,
        model_type,
        risk_level,
        training_data_hash,
        bias_audit_completed,
        deployment_status,
        application_id,
        created_at,
        created_by
    ) VALUES (
        v_model_id,
        p_model_name,
        p_model_version,
        p_model_type,
        p_risk_level,
        NULL,
        FALSE,
        'staging',
        p_application_id,
        now(),
        current_user
    );

    RETURN v_model_id;
END;
$$;

COMMENT ON FUNCTION app.register_model IS 'Registers new AI model in registry';

-- Function: Log inference
CREATE OR REPLACE FUNCTION app.log_inference(
    p_application_id UUID,
    p_model_id UUID,
    p_input_data JSONB,
    p_output_data JSONB,
    p_latency_ms INTEGER,
    p_success BOOLEAN DEFAULT TRUE
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, public
AS $$
DECLARE
    v_inference_id UUID;
BEGIN
    v_inference_id := gen_random_uuid();

    INSERT INTO app.inference_log (
        inference_id,
        model_id,
        input_hash,
        output_hash,
        input_data_encrypted,
        output_data_encrypted,
        feature_importance,
        confidence_score,
        latency_ms,
        cache_hit,
        success,
        error_message,
        human_reviewed,
        review_outcome,
        reviewed_by,
        session_id,
        application_id,
        created_at
    ) VALUES (
        v_inference_id,
        p_model_id,
        encode(digest(p_input_data::text, 'sha256'), 'hex'),
        encode(digest(p_output_data::text, 'sha256'), 'hex'),
        pgp_sym_encrypt(p_input_data::text, current_setting('app.encryption_key', true)),
        pgp_sym_encrypt(p_output_data::text, current_setting('app.encryption_key', true)),
        NULL,
        (p_output_data->>'confidence')::decimal,
        p_latency_ms,
        FALSE,
        p_success,
        CASE WHEN p_success THEN NULL ELSE p_output_data->>'error' END,
        FALSE,
        NULL,
        NULL,
        NULL,
        p_application_id,
        now()
    );

    RETURN v_inference_id;
END;
$$;

COMMENT ON FUNCTION app.log_inference IS 'Logs AI model inference with encrypted data';

-- Function: Check model safety
CREATE OR REPLACE FUNCTION app.check_model_safety(
    p_model_id UUID
)
RETURNS TABLE (
    safe BOOLEAN,
    issues TEXT[]
)
LANGUAGE plpgsql
STABLE
SET search_path = app, public
AS $$
DECLARE
    v_model RECORD;
    v_issues TEXT[] := ARRAY[]::TEXT[];
BEGIN
    SELECT * INTO v_model
    FROM app.model_registry
    WHERE model_id = p_model_id;

    IF v_model IS NULL THEN
        safe := FALSE;
        issues := ARRAY['Model not found'];
        RETURN NEXT;
        RETURN;
    END IF;

    -- Check risk level
    IF v_model.risk_level = 'prohibited' THEN
        v_issues := array_append(v_issues, 'Prohibited risk level');
    END IF;

    -- Check bias audit
    IF v_model.risk_level = 'high' AND NOT v_model.bias_audit_completed THEN
        v_issues := array_append(v_issues, 'High-risk model without bias audit');
    END IF;

    -- Check EU AI Act compliance
    IF v_model.eu_ai_act_compliant = FALSE THEN
        v_issues := array_append(v_issues, 'Not EU AI Act compliant');
    END IF;

    safe := array_length(v_issues, 1) IS NULL;
    issues := v_issues;
    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION app.check_model_safety IS 'Validates AI model safety before inference';
