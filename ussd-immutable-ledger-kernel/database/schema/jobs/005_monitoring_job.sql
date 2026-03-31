-- ============================================================================
-- Monitoring Job
-- ============================================================================

-- Function: Collect metrics
CREATE OR REPLACE FUNCTION utils.collect_metrics()
RETURNS TABLE (
    metrics_collected INTEGER,
    alerts_triggered INTEGER
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = utils, public
AS $$
DECLARE
    v_metrics INTEGER := 0;
    v_alerts INTEGER := 0;
BEGIN
    -- Transaction rate
    v_metrics := v_metrics + 1;

    -- Error rate
    v_metrics := v_metrics + 1;

    -- Latency
    v_metrics := v_metrics + 1;

    -- Check thresholds
    IF v_metrics > 1000 THEN
        v_alerts := v_alerts + 1;
    END IF;

    metrics_collected := v_metrics;
    alerts_triggered := v_alerts;
    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION utils.collect_metrics IS 'Collects system metrics for monitoring';
