-- ============================================================================
-- USSD Session Operations
-- ============================================================================

-- Function: Create new USSD session
CREATE OR REPLACE FUNCTION ussd.create_session(
    p_session_id VARCHAR(64),
    p_msisdn VARCHAR(20),
    p_imsi VARCHAR(64),
    p_imei VARCHAR(64),
    p_network_code VARCHAR(20),
    p_shortcode VARCHAR(20),
    p_application_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ussd_gateway, public
AS $$
DECLARE
    v_internal_id UUID;
    v_msisdn_hash VARCHAR(64);
    v_msisdn_encrypted BYTEA;
    v_sim_fingerprint VARCHAR(64);
BEGIN
    v_internal_id := gen_random_uuid();
    v_msisdn_hash := encode(digest(p_msisdn, 'sha256'), 'hex');
    v_msisdn_encrypted := pgp_sym_encrypt(p_msisdn, current_setting('app.encryption_key', true));
    v_sim_fingerprint := encode(digest(p_imsi || p_imei, 'sha256'), 'hex');

    INSERT INTO ussd.session_state (
        internal_session_id,
        external_session_id,
        msisdn_hash,
        msisdn_encrypted,
        imsi_hash,
        imei_hash,
        sim_swap_fingerprint,
        network_code,
        shortcode,
        application_id,
        menu_state,
        input_history,
        context_data,
        security_level,
        session_hash,
        session_started_at,
        last_activity_at,
        network_timeout_at,
        absolute_timeout_at,
        timeout_duration_minutes,
        created_at
    ) VALUES (
        v_internal_id,
        p_session_id,
        v_msisdn_hash,
        v_msisdn_encrypted,
        encode(digest(p_imsi, 'sha256'), 'hex'),
        encode(digest(p_imei, 'sha256'), 'hex'),
        v_sim_fingerprint,
        p_network_code,
        p_shortcode,
        COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID),
        'main',
        ARRAY[]::TEXT[],
        '{}',
        'STANDARD',
        encode(digest(v_internal_id::text || now()::text, 'sha256'), 'hex'),
        now(),
        now(),
        now() + interval '2 minutes',
        now() + interval '15 minutes',
        15,
        now()
    );

    RETURN v_internal_id;
END;
$$;

COMMENT ON FUNCTION ussd.create_session IS 'Creates new USSD session with encrypted MSISDN';

-- Function: Update session activity
CREATE OR REPLACE FUNCTION ussd.update_session(
    p_internal_session_id UUID,
    p_menu_state VARCHAR(64),
    p_user_input TEXT DEFAULT NULL,
    p_context_update JSONB DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ussd_gateway, public
AS $$
BEGIN
    UPDATE ussd.session_state
    SET menu_state = p_menu_state,
        input_history = CASE 
            WHEN p_user_input IS NOT NULL THEN 
                array_append(input_history, p_user_input)
            ELSE input_history
        END,
        context_data = COALESCE(context_data, '{}'::jsonb) || COALESCE(p_context_update, '{}'::jsonb),
        last_activity_at = now(),
        network_timeout_at = now() + interval '2 minutes',
        session_hash = encode(
            digest(
                internal_session_id::text || 
                p_menu_state || 
                COALESCE(p_user_input, '') || 
                now()::text,
                'sha256'
            ),
            'hex'
        )
    WHERE internal_session_id = p_internal_session_id;

    RETURN FOUND;
END;
$$;

COMMENT ON FUNCTION ussd.update_session IS 'Updates session state and extends timeout';

-- Function: End session
CREATE OR REPLACE FUNCTION ussd.end_session(
    p_internal_session_id UUID,
    p_completion_status VARCHAR(16) DEFAULT 'COMPLETED'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ussd_gateway, public
AS $$
BEGIN
    UPDATE ussd.session_state
    SET is_active = FALSE,
        session_ended_at = now(),
        completion_status = p_completion_status,
        termination_reason = 'USER_END'
    WHERE internal_session_id = p_internal_session_id;

    RETURN FOUND;
END;
$$;

COMMENT ON FUNCTION ussd.end_session IS 'Terminates USSD session';

-- Function: Cleanup expired sessions
CREATE OR REPLACE FUNCTION ussd.cleanup_expired_sessions()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ussd_gateway, public
AS $$
DECLARE
    v_count INTEGER;
BEGIN
    UPDATE ussd.session_state
    SET is_active = FALSE,
        session_ended_at = now(),
        completion_status = 'TIMEOUT',
        termination_reason = CASE 
            WHEN absolute_timeout_at < now() THEN 'ABSOLUTE_TIMEOUT'
            ELSE 'NETWORK_TIMEOUT'
        END
    WHERE is_active = TRUE
    AND (network_timeout_at < now() OR absolute_timeout_at < now());

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

COMMENT ON FUNCTION ussd.cleanup_expired_sessions IS 'Cleans up timed-out sessions';
