-- ============================================================================
-- App Schema - Entitlement Operations
-- ============================================================================

-- Function: Set entitlement limit
CREATE OR REPLACE FUNCTION app.set_entitlement(
    p_application_id UUID,
    p_limit_type VARCHAR(32),
    p_limit_value DECIMAL(19,4),
    p_period VARCHAR(16) DEFAULT 'MONTHLY'
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, public
AS $$
DECLARE
    v_entitlement_id UUID;
BEGIN
    v_entitlement_id := gen_random_uuid();

    INSERT INTO app.entitlement_limits (
        entitlement_id,
        application_id,
        limit_type,
        limit_value,
        limit_period,
        current_usage,
        warning_threshold,
        hard_limit,
        period_start,
        period_end,
        created_at
    ) VALUES (
        v_entitlement_id,
        p_application_id,
        p_limit_type,
        p_limit_value,
        p_period,
        0,
        p_limit_value * 0.8, -- 80% warning
        p_limit_value,
        date_trunc(p_period::text, now()),
        date_trunc(p_period::text, now()) + 
            CASE p_period 
                WHEN 'DAILY' THEN interval '1 day'
                WHEN 'WEEKLY' THEN interval '1 week'
                WHEN 'MONTHLY' THEN interval '1 month'
                ELSE interval '1 month'
            END,
        now()
    );

    RETURN v_entitlement_id;
END;
$$;

COMMENT ON FUNCTION app.set_entitlement IS 'Sets usage entitlement limit';

-- Function: Check and consume entitlement
CREATE OR REPLACE FUNCTION app.consume_entitlement(
    p_application_id UUID,
    p_limit_type VARCHAR(32),
    p_amount DECIMAL(19,4)
)
RETURNS TABLE (
    allowed BOOLEAN,
    remaining DECIMAL(19,4),
    message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, public
AS $$
DECLARE
    v_entitlement RECORD;
BEGIN
    SELECT * INTO v_entitlement
    FROM app.entitlement_limits
    WHERE application_id = p_application_id
    AND limit_type = p_limit_type
    AND period_end > now()
    ORDER BY period_start DESC
    LIMIT 1;

    IF v_entitlement IS NULL THEN
        allowed := TRUE;
        remaining := NULL;
        message := 'No limit configured';
        RETURN NEXT;
        RETURN;
    END IF;

    IF v_entitlement.hard_limit AND (v_entitlement.current_usage + p_amount) > v_entitlement.limit_value THEN
        allowed := FALSE;
        remaining := v_entitlement.limit_value - v_entitlement.current_usage;
        message := 'Hard limit exceeded';
        RETURN NEXT;
        RETURN;
    END IF;

    -- Update usage
    UPDATE app.entitlement_limits
    SET current_usage = current_usage + p_amount
    WHERE entitlement_id = v_entitlement.entitlement_id;

    allowed := TRUE;
    remaining := v_entitlement.limit_value - (v_entitlement.current_usage + p_amount);
    message := CASE 
        WHEN (v_entitlement.current_usage + p_amount) > v_entitlement.warning_threshold 
        THEN 'Warning: approaching limit'
        ELSE 'OK'
    END;
    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION app.consume_entitlement IS 'Checks and consumes entitlement quota';
