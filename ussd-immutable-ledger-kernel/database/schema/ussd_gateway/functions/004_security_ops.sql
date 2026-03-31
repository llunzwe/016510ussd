-- ============================================================================
-- USSD Security Operations
-- ============================================================================

-- Function: Generate device fingerprint
CREATE OR REPLACE FUNCTION ussd.generate_device_fingerprint(
    p_msisdn VARCHAR(20),
    p_imsi VARCHAR(64),
    p_imei VARCHAR(64),
    p_network_code VARCHAR(20)
)
RETURNS VARCHAR(64)
LANGUAGE plpgsql
IMMUTABLE
SET search_path = ussd_gateway, public
AS $$
BEGIN
    RETURN encode(
        digest(
            COALESCE(p_msisdn, '') || 
            COALESCE(p_imsi, '') || 
            COALESCE(p_imei, '') || 
            COALESCE(p_network_code, ''),
            'sha256'
        ),
        'hex'
    );
END;
$$;

COMMENT ON FUNCTION ussd.generate_device_fingerprint IS 'Generates privacy-preserving device hash';

-- Function: Check SIM swap
CREATE OR REPLACE FUNCTION ussd.check_sim_swap(
    p_msisdn VARCHAR(20),
    p_imsi VARCHAR(64)
)
RETURNS TABLE (
    swap_detected BOOLEAN,
    risk_level VARCHAR(16),
    hours_since_change INTEGER,
    requires_verification BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ussd_gateway, public
AS $$
DECLARE
    v_last_fingerprint RECORD;
    v_msisdn_hash VARCHAR(64);
BEGIN
    v_msisdn_hash := encode(digest(p_msisdn, 'sha256'), 'hex');

    SELECT * INTO v_last_fingerprint
    FROM ussd.device_fingerprints
    WHERE msisdn_hash = v_msisdn_hash
    ORDER BY last_seen_at DESC
    LIMIT 1;

    IF v_last_fingerprint IS NULL THEN
        swap_detected := FALSE;
        risk_level := 'LOW';
        hours_since_change := NULL;
        requires_verification := FALSE;
        RETURN NEXT;
        RETURN;
    END IF;

    IF v_last_fingerprint.imsi_hash != encode(digest(p_imsi, 'sha256'), 'hex') THEN
        swap_detected := TRUE;
        hours_since_change := EXTRACT(EPOCH FROM (now() - v_last_fingerprint.last_seen_at)) / 3600;
        
        -- GSMA IR.71 recommendations
        IF hours_since_change < 24 THEN
            risk_level := 'CRITICAL';
            requires_verification := TRUE;
        ELSIF hours_since_change < 72 THEN
            risk_level := 'HIGH';
            requires_verification := TRUE;
        ELSE
            risk_level := 'MEDIUM';
            requires_verification := FALSE;
        END IF;
    ELSE
        swap_detected := FALSE;
        risk_level := 'LOW';
        hours_since_change := NULL;
        requires_verification := FALSE;
    END IF;

    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION ussd.check_sim_swap IS 'Detects potential SIM swap fraud';

-- Function: Update risk score
CREATE OR REPLACE FUNCTION ussd.update_risk_score(
    p_device_fingerprint_id UUID,
    p_event_type VARCHAR(32),
    p_risk_delta INTEGER
)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ussd_gateway, public
AS $$
DECLARE
    v_new_score INTEGER;
BEGIN
    UPDATE ussd.device_fingerprints
    SET risk_score = GREATEST(0, LEAST(100, risk_score + p_risk_delta)),
        risk_factors = array_append(risk_factors, p_event_type || ':' || p_risk_delta::text),
        last_risk_update = now()
    WHERE device_fingerprint_id = p_device_fingerprint_id
    RETURNING risk_score INTO v_new_score;

    RETURN v_new_score;
END;
$$;

COMMENT ON FUNCTION ussd.update_risk_score IS 'Updates device risk score';

-- Function: Validate PIN attempt
CREATE OR REPLACE FUNCTION ussd.validate_pin_attempt(
    p_session_id UUID,
    p_attempt_successful BOOLEAN
)
RETURNS TABLE (
    allowed BOOLEAN,
    remaining_attempts INTEGER,
    locked BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ussd_gateway, public
AS $$
DECLARE
    v_session RECORD;
BEGIN
    SELECT * INTO v_session
    FROM ussd.session_state
    WHERE internal_session_id = p_session_id;

    IF v_session.pin_attempts >= 3 AND NOT p_attempt_successful THEN
        allowed := FALSE;
        remaining_attempts := 0;
        locked := TRUE;
        RETURN NEXT;
        RETURN;
    END IF;

    IF p_attempt_successful THEN
        UPDATE ussd.session_state
        SET pin_attempts = 0,
            pin_locked = FALSE
        WHERE internal_session_id = p_session_id;
        
        allowed := TRUE;
        remaining_attempts := 3;
        locked := FALSE;
    ELSE
        UPDATE ussd.session_state
        SET pin_attempts = pin_attempts + 1,
            pin_locked = pin_attempts + 1 >= 3
        WHERE internal_session_id = p_session_id;
        
        allowed := pin_attempts + 1 < 3;
        remaining_attempts := GREATEST(0, 3 - (pin_attempts + 1));
        locked := pin_attempts + 1 >= 3;
    END IF;

    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION ussd.validate_pin_attempt IS 'Validates PIN and tracks attempts';
