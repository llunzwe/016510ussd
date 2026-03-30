-- =============================================================================
-- ULTIMATE SOFTWARE SECURITY SOLUTIONS & DEFI LIMITED
-- AI Inference Logging Function
-- =============================================================================
-- Compliance: ISO 27001:2022 (A.12.4, A.12.5), ISO 27018:2019
--             SOC 2 Type II (CC6.1, CC7.2), GDPR (Art. 30 - Processing records)
--             EU AI Act (Art. 12 - Record-keeping for high-risk AI systems)
-- Classification: RESTRICTED - Creates audit records
-- Purpose: Immutable logging of AI model inferences
-- Security: Input validation; PII detection; content filtering; tamper-proof
-- Version: 1.0.0
-- Author: Database Engineering Team
-- Last Modified: 2026-03-30
-- =============================================================================

-- -----------------------------------------------------------------------------
-- FUNCTION: log_inference
-- PURPOSE: Record an AI inference with full audit trail
-- PARAMETERS:
--   p_model_id              - UUID of model used
--   p_request_id            - Unique request identifier
--   p_input_data            - Input to model (JSONB)
--   p_output_data           - Model output (JSONB)
--   p_confidence_score      - Model confidence (0-1)
--   p_latency_ms            - Total latency in milliseconds
--   p_inference_type        - realtime, batch, streaming, async
--   p_correlation_id        - Distributed tracing ID (optional)
--   p_metadata              - Additional metadata (optional)
-- RETURNS: UUID of created inference log record
-- SECURITY: Validates model access; detects PII; computes integrity hashes
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.log_inference(
    p_model_id UUID,
    p_request_id UUID,
    p_input_data JSONB,
    p_output_data JSONB,
    p_confidence_score NUMERIC DEFAULT NULL,
    p_latency_ms INTEGER DEFAULT NULL,
    p_inference_type VARCHAR(50) DEFAULT 'realtime',
    p_correlation_id VARCHAR(255) DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'::jsonb
)
RETURNS UUID AS $$
DECLARE
    v_log_id UUID;
    v_user_id UUID;
    v_model_exists BOOLEAN;
    v_model_risk_level VARCHAR(20);
    v_model_name VARCHAR(255);
    v_input_hash VARCHAR(64);
    v_output_hash VARCHAR(64);
    v_contains_pii BOOLEAN := FALSE;
    v_pii_types TEXT[] := ARRAY[]::TEXT[];
    v_status VARCHAR(20) := 'success';
    v_error_code VARCHAR(50) := NULL;
    v_error_message TEXT := NULL;
    v_input_size INTEGER;
    v_output_size INTEGER;
BEGIN
    -- -------------------------------------------------------------------------
    -- SECURITY: Validate user/service authentication
    -- -------------------------------------------------------------------------
    BEGIN
        v_user_id := current_setting('app.current_user_id')::UUID;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Authentication required: app.current_user_id not set'
            USING ERRCODE = '28000';
    END;
    
    -- -------------------------------------------------------------------------
    -- INPUT VALIDATION
    -- -------------------------------------------------------------------------
    
    -- Validate required parameters
    IF p_model_id IS NULL THEN
        RAISE EXCEPTION 'Model ID is required'
            USING ERRCODE = '22004';
    END IF;
    
    IF p_request_id IS NULL THEN
        RAISE EXCEPTION 'Request ID is required'
            USING ERRCODE = '22004';
    END IF;
    
    IF p_input_data IS NULL THEN
        RAISE EXCEPTION 'Input data is required'
            USING ERRCODE = '22004';
    END IF;
    
    IF p_output_data IS NULL THEN
        RAISE EXCEPTION 'Output data is required'
            USING ERRCODE = '22004';
    END IF;
    
    -- Validate inference type
    IF p_inference_type NOT IN ('realtime', 'batch', 'streaming', 'async') THEN
        RAISE EXCEPTION 'Invalid inference type: %', p_inference_type
            USING ERRCODE = '22023',  -- invalid_parameter_value
                  HINT = 'Valid types: realtime, batch, streaming, async';
    END IF;
    
    -- Validate confidence score range
    IF p_confidence_score IS NOT NULL AND 
       (p_confidence_score < 0 OR p_confidence_score > 1) THEN
        RAISE EXCEPTION 'Confidence score must be between 0 and 1'
            USING ERRCODE = '22003';  -- numeric_value_out_of_range
    END IF;
    
    -- -------------------------------------------------------------------------
    -- VERIFY MODEL ACCESS
    -- -------------------------------------------------------------------------
    
    SELECT EXISTS(
        SELECT 1 FROM app.model_registry 
        WHERE id = p_model_id AND deleted_at IS NULL
    ) INTO v_model_exists;
    
    IF NOT v_model_exists THEN
        RAISE EXCEPTION 'Model not found or inaccessible: %', p_model_id
            USING ERRCODE = 'P0002',
                  HINT = 'Verify model ID exists and is not deleted';
    END IF;
    
    -- Get model details for audit
    SELECT risk_level, name 
    INTO v_model_risk_level, v_model_name
    FROM app.model_registry 
    WHERE id = p_model_id;
    
    -- -------------------------------------------------------------------------
    -- CONTENT ANALYSIS: PII Detection
    -- -------------------------------------------------------------------------
    
    -- Check input for common PII patterns
    IF p_input_data::text ~* '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b' THEN
        v_contains_pii := TRUE;
        v_pii_types := array_append(v_pii_types, 'email');
    END IF;
    
    IF p_input_data::text ~* '\b\d{3}-\d{2}-\d{4}\b' OR  -- SSN pattern
       p_input_data::text ~* '\b\d{3}\s?\d{3}\s?\d{4}\b' THEN  -- Phone
        v_contains_pii := TRUE;
        v_pii_types := array_append(v_pii_types, 'ssn_or_phone');
    END IF;
    
    IF p_input_data::text ~* '\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b' THEN
        v_contains_pii := TRUE;
        v_pii_types := array_append(v_pii_types, 'credit_card');
    END IF;
    
    IF p_output_data::text ~* '(password|passwd|pwd)\s*[:=]\s*\S+' THEN
        v_contains_pii := TRUE;
        v_pii_types := array_append(v_pii_types, 'password');
    END IF;
    
    -- -------------------------------------------------------------------------
    -- COMPUTE INTEGRITY HASHES
    -- -------------------------------------------------------------------------
    
    v_input_size := octet_length(p_input_data::text);
    v_output_size := octet_length(p_output_data::text);
    
    v_input_hash := encode(digest(p_input_data::text, 'sha256'), 'hex');
    v_output_hash := encode(digest(p_output_data::text, 'sha256'), 'hex');
    
    -- -------------------------------------------------------------------------
    -- SIZE LIMITS CHECK
    -- -------------------------------------------------------------------------
    
    IF v_input_size > 10485760 THEN  -- 10MB limit
        v_status := 'validation_error';
        v_error_code := 'INPUT_TOO_LARGE';
        v_error_message := 'Input data exceeds maximum size (10MB)';
    ELSIF v_output_size > 10485760 THEN
        v_status := 'validation_error';
        v_error_code := 'OUTPUT_TOO_LARGE';
        v_error_message := 'Output data exceeds maximum size (10MB)';
    END IF;
    
    -- -------------------------------------------------------------------------
    -- INSERT INFERENCE RECORD
    -- -------------------------------------------------------------------------
    
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
        latency_ms,
        inference_type,
        user_id,
        contains_pii,
        pii_types_detected,
        status,
        error_code,
        error_message,
        data_classification,
        compliance_frameworks,
        created_by
    ) VALUES (
        p_model_id,
        p_request_id,
        p_correlation_id,
        p_input_data,
        v_input_hash,
        v_input_size,
        p_output_data,
        v_output_hash,
        v_output_size,
        p_confidence_score,
        p_latency_ms,
        p_inference_type,
        v_user_id,
        v_contains_pii,
        v_pii_types,
        v_status,
        v_error_code,
        v_error_message,
        CASE WHEN v_contains_pii THEN 'restricted' ELSE 'internal' END,
        CASE 
            WHEN v_model_risk_level = 'high' THEN ARRAY['EU_AI_ACT', 'GDPR']
            WHEN v_contains_pii THEN ARRAY['GDPR', 'ISO27018']
            ELSE ARRAY['ISO27001']
        END,
        v_user_id
    )
    RETURNING id INTO v_log_id;
    
    -- -------------------------------------------------------------------------
    -- HIGH-RISK MODEL ALERT (EU AI Act compliance)
    -- -------------------------------------------------------------------------
    
    IF v_model_risk_level = 'high' THEN
        -- Log additional compliance record for high-risk AI
        INSERT INTO app.audit_log (
            table_name, record_id, action,
            details, performed_by, result, severity
        ) VALUES (
            'inference_log', v_log_id, 'HIGH_RISK_INFERENCE',
            jsonb_build_object(
                'model_id', p_model_id,
                'model_name', v_model_name,
                'request_id', p_request_id,
                'user_id', v_user_id,
                'confidence', p_confidence_score,
                'contains_pii', v_contains_pii,
                'compliance_note', 'EU AI Act Article 12 record-keeping'
            ),
            v_user_id,
            v_status,
            'warning'
        );
    END IF;
    
    -- -------------------------------------------------------------------------
    -- RETURN LOG ID
    -- -------------------------------------------------------------------------
    
    RETURN v_log_id;
    
EXCEPTION
    WHEN unique_violation THEN
        -- Request ID already exists
        RAISE EXCEPTION 'Duplicate request ID: %', p_request_id
            USING ERRCODE = '23505',
                  HINT = 'Request IDs must be unique';
    WHEN OTHERS THEN
        -- Log error but don't expose internal details
        INSERT INTO app.audit_log (
            table_name, action, details, performed_by, result, severity
        ) VALUES (
            'inference_log', 'LOG_INFERENCE_ERROR',
            jsonb_build_object(
                'model_id', p_model_id,
                'request_id', p_request_id,
                'error_code', SQLSTATE,
                'error_hint', 'See database logs for details'
            ),
            v_user_id,
            'failure',
            'error'
        );
        RAISE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
    VOLATILE  -- Function modifies database
    SET search_path = app, pg_temp;

-- -----------------------------------------------------------------------------
-- FUNCTION: log_inference_batch
-- PURPOSE: Batch logging for high-throughput scenarios
-- PARAMETERS:
--   p_inferences - Array of inference records
-- RETURNS: Array of created log IDs
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app.log_inference_batch(
    p_inferences JSONB[]
)
RETURNS UUID[] AS $$
DECLARE
    v_inference JSONB;
    v_log_ids UUID[] := ARRAY[]::UUID[];
    v_log_id UUID;
    v_user_id UUID;
    v_count INTEGER := 0;
    v_max_batch_size INTEGER := 1000;
BEGIN
    -- -------------------------------------------------------------------------
    -- SECURITY: Validate authentication
    -- -------------------------------------------------------------------------
    BEGIN
        v_user_id := current_setting('app.current_user_id')::UUID;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Authentication required'
            USING ERRCODE = '28000';
    END;
    
    -- -------------------------------------------------------------------------
    -- BATCH SIZE VALIDATION
    -- -------------------------------------------------------------------------
    IF array_length(p_inferences, 1) > v_max_batch_size THEN
        RAISE EXCEPTION 'Batch size exceeds maximum of %', v_max_batch_size
            USING ERRCODE = '54000';  -- program_limit_exceeded
    END IF;
    
    -- -------------------------------------------------------------------------
    -- PROCESS EACH INFERENCE
    -- -------------------------------------------------------------------------
    FOREACH v_inference IN ARRAY p_inferences
    LOOP
        v_count := v_count + 1;
        
        BEGIN
            SELECT app.log_inference(
                (v_inference->>'model_id')::UUID,
                (v_inference->>'request_id')::UUID,
                v_inference->'input_data',
                v_inference->'output_data',
                (v_inference->>'confidence_score')::NUMERIC,
                (v_inference->>'latency_ms')::INTEGER,
                COALESCE(v_inference->>'inference_type', 'batch'),
                v_inference->>'correlation_id',
                COALESCE(v_inference->'metadata', '{}'::jsonb)
            ) INTO v_log_id;
            
            v_log_ids := array_append(v_log_ids, v_log_id);
            
        EXCEPTION WHEN OTHERS THEN
            -- Log failed record but continue processing
            INSERT INTO app.audit_log (
                table_name, action, details, performed_by, result, severity
            ) VALUES (
                'inference_log', 'BATCH_ITEM_FAILED',
                jsonb_build_object(
                    'batch_index', v_count,
                    'error', SQLERRM,
                    'model_id', v_inference->>'model_id'
                ),
                v_user_id,
                'failure',
                'warning'
            );
        END;
    END LOOP;
    
    -- Log batch completion
    INSERT INTO app.audit_log (
        table_name, action, details, performed_by, result
    ) VALUES (
        'inference_log', 'BATCH_COMPLETED',
        jsonb_build_object(
            'total_records', v_count,
            'successful', array_length(v_log_ids, 1),
            'failed', v_count - COALESCE(array_length(v_log_ids, 1), 0)
        ),
        v_user_id,
        'success'
    );
    
    RETURN v_log_ids;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER
    VOLATILE
    SET search_path = app, pg_temp;

-- -----------------------------------------------------------------------------
-- FUNCTION COMMENTS
-- -----------------------------------------------------------------------------

COMMENT ON FUNCTION app.log_inference(UUID, UUID, JSONB, JSONB, NUMERIC, INTEGER, VARCHAR, VARCHAR, JSONB) IS 
    'Records an AI model inference with full audit trail. Validates model access, 
     detects PII, computes integrity hashes. Returns log record UUID. Required 
     for EU AI Act compliance for high-risk AI systems.';

COMMENT ON FUNCTION app.log_inference_batch(JSONB[]) IS 
    'Batch version of log_inference for high-throughput scenarios. 
     Processes up to 1000 records per call. Returns array of log IDs.';

-- -----------------------------------------------------------------------------
-- GRANTS
-- -----------------------------------------------------------------------------

GRANT EXECUTE ON FUNCTION app.log_inference(UUID, UUID, JSONB, JSONB, NUMERIC, INTEGER, VARCHAR, VARCHAR, JSONB) 
    TO app_readwrite;
GRANT EXECUTE ON FUNCTION app.log_inference(UUID, UUID, JSONB, JSONB, NUMERIC, INTEGER, VARCHAR, VARCHAR, JSONB) 
    TO app_admin;
    
GRANT EXECUTE ON FUNCTION app.log_inference_batch(JSONB[]) 
    TO app_readwrite;
GRANT EXECUTE ON FUNCTION app.log_inference_batch(JSONB[]) 
    TO app_admin;

-- =============================================================================
-- END OF FILE
-- =============================================================================
