-- ============================================================================
-- USSD Routing Operations
-- ============================================================================

-- Function: Resolve shortcode
CREATE OR REPLACE FUNCTION ussd.resolve_shortcode(
    p_shortcode VARCHAR(20),
    p_network_code VARCHAR(20),
    p_country_code CHAR(2) DEFAULT NULL
)
RETURNS TABLE (
    application_id UUID,
    handler_endpoint VARCHAR(255),
    rate_limit_requests INTEGER,
    rate_limit_window INTEGER
)
LANGUAGE plpgsql
STABLE
SET search_path = ussd_gateway, public
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        sr.application_id,
        sr.handler_endpoint,
        sr.rate_limit_requests,
        sr.rate_limit_window_seconds
    FROM ussd.shortcode_routing sr
    WHERE sr.shortcode = p_shortcode
    AND (sr.network_code IS NULL OR sr.network_code = p_network_code)
    AND (sr.country_code IS NULL OR sr.country_code = p_country_code)
    AND sr.is_active = TRUE
    AND sr.valid_from <= now()
    AND sr.valid_to > now()
    ORDER BY 
        CASE WHEN sr.network_code = p_network_code THEN 0 ELSE 1 END,
        CASE WHEN sr.country_code = p_country_code THEN 0 ELSE 1 END
    LIMIT 1;
END;
$$;

COMMENT ON FUNCTION ussd.resolve_shortcode IS 'Resolves shortcode to application endpoint';

-- Function: Check rate limit
CREATE OR REPLACE FUNCTION ussd.check_rate_limit(
    p_routing_id UUID,
    p_msisdn_hash VARCHAR(64)
)
RETURNS TABLE (
    allowed BOOLEAN,
    remaining INTEGER,
    reset_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ussd_gateway, public
AS $$
DECLARE
    v_limit INTEGER;
    v_window INTEGER;
    v_count INTEGER;
BEGIN
    SELECT rate_limit_requests, rate_limit_window_seconds 
    INTO v_limit, v_window
    FROM ussd.shortcode_routing
    WHERE routing_id = p_routing_id;

    -- Count requests in window
    SELECT COUNT(*) INTO v_count
    FROM ussd.session_state
    WHERE routing_id = p_routing_id
    AND msisdn_hash = p_msisdn_hash
    AND created_at > now() - (v_window || ' seconds')::interval;

    allowed := v_count < v_limit;
    remaining := GREATEST(0, v_limit - v_count);
    reset_at := now() + (v_window || ' seconds')::interval;
    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION ussd.check_rate_limit IS 'Checks rate limit for shortcode';
