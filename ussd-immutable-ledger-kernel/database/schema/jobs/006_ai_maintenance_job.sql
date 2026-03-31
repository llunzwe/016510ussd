-- ============================================================================
-- AI Maintenance Job
-- ============================================================================

-- Function: Run AI maintenance
CREATE OR REPLACE FUNCTION app.run_ai_maintenance()
RETURNS TABLE (
    models_checked INTEGER,
    models_flagged INTEGER,
    cache_cleaned INTEGER
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, public
AS $$
DECLARE
    v_checked INTEGER := 0;
    v_flagged INTEGER := 0;
    v_cache INTEGER := 0;
    v_model RECORD;
    v_safety RECORD;
BEGIN
    -- Check model safety
    FOR v_model IN
        SELECT model_id FROM app.model_registry
        WHERE deployment_status = 'production'
    LOOP
        v_checked := v_checked + 1;
        
        SELECT * INTO v_safety FROM app.check_model_safety(v_model.model_id);
        
        IF NOT v_safety.safe THEN
            v_flagged := v_flagged + 1;
        END IF;
    END LOOP;

    -- Clean old inference cache
    DELETE FROM app.inference_log
    WHERE created_at < now() - interval '30 days'
    AND human_reviewed = FALSE;

    GET DIAGNOSTICS v_cache = ROW_COUNT;

    models_checked := v_checked;
    models_flagged := v_flagged;
    cache_cleaned := v_cache;
    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION app.run_ai_maintenance IS 'Runs AI model safety checks and cache cleanup';
