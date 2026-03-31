-- ============================================================================
-- USSD Gateway - Session Management Functions
-- Implements session lifecycle, timeout handling, and state persistence
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Function: ussd.create_session
-- Description: Creates a new USSD session with encrypted MSISDN and initial state
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.create_session(
    p_msisdn VARCHAR(20),
    p_session_id VARCHAR(100),
    p_network_operator VARCHAR(50) DEFAULT NULL,
    p_imsi VARCHAR(50) DEFAULT NULL,
    p_imei VARCHAR(50) DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_session_uuid UUID;
    v_msisdn_hash VARCHAR(64);
    v_encrypted_msisdn BYTEA;
BEGIN
    -- Generate hash of MSISDN for quick lookups
    v_msisdn_hash := encode(digest(p_msisdn, 'sha256'), 'hex');
    
    -- Encrypt MSISDN using pgcrypto
    v_encrypted_msisdn := pgp_sym_encrypt(
        p_msisdn, 
        current_setting('app.encryption_key', true),
        'cipher-algo=aes256, compress-algo=0'
    );
    
    -- Insert new session
    INSERT INTO ussd.sessions (
        session_id,
        msisdn_encrypted,
        msisdn_hash,
        network_operator,
        imsi,
        imei,
        state,
        menu_path,
        created_at,
        last_activity_at,
        expires_at,
        is_active
    ) VALUES (
        p_session_id,
        v_encrypted_msisdn,
        v_msisdn_hash,
        p_network_operator,
        p_imsi,
        p_imei,
        'INIT',
        'root',
        NOW(),
        NOW(),
        NOW() + INTERVAL '5 minutes',
        TRUE
    )
    RETURNING id INTO v_session_uuid;
    
    -- Log session creation for audit
    INSERT INTO ussd.audit_logs (
        session_id,
        msisdn_hash,
        action,
        details,
        created_at
    ) VALUES (
        v_session_uuid,
        v_msisdn_hash,
        'SESSION_CREATED',
        jsonb_build_object(
            'session_id', p_session_id,
            'network_operator', p_network_operator,
            'client_ip', inet_client_addr()
        ),
        NOW()
    );
    
    RETURN v_session_uuid;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.create_session IS 'Creates a new USSD session with encrypted MSISDN storage';

-- ----------------------------------------------------------------------------
-- Function: ussd.get_session
-- Description: Retrieves active session by session_id, handles timeout checks
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.get_session(
    p_session_id VARCHAR(100)
) RETURNS TABLE (
    id UUID,
    session_id VARCHAR(100),
    msisdn VARCHAR(20),
    state VARCHAR(50),
    menu_path VARCHAR(500),
    session_data JSONB,
    transaction_id UUID,
    created_at TIMESTAMPTZ,
    last_activity_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN
) AS $$
DECLARE
    v_session RECORD;
    v_decrypted_msisdn VARCHAR(20);
BEGIN
    -- Find active non-expired session
    SELECT s.* INTO v_session
    FROM ussd.sessions s
    WHERE s.session_id = p_session_id
      AND s.is_active = TRUE
      AND s.expires_at > NOW();
    
    IF NOT FOUND THEN
        RETURN;
    END IF;
    
    -- Decrypt MSISDN
    v_decrypted_msisdn := pgp_sym_decrypt(
        v_session.msisdn_encrypted,
        current_setting('app.encryption_key', true)
    );
    
    -- Update last activity
    UPDATE ussd.sessions 
    SET last_activity_at = NOW(),
        expires_at = NOW() + INTERVAL '5 minutes'
    WHERE id = v_session.id;
    
    RETURN QUERY SELECT
        v_session.id,
        v_session.session_id,
        v_decrypted_msisdn,
        v_session.state,
        v_session.menu_path,
        v_session.session_data,
        v_session.transaction_id,
        v_session.created_at,
        NOW(), -- Updated last_activity_at
        v_session.expires_at,
        v_session.is_active;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.get_session IS 'Retrieves active session with automatic timeout handling';

-- ----------------------------------------------------------------------------
-- Function: ussd.update_session_state
-- Description: Updates session state, menu path, and session data atomically
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.update_session_state(
    p_session_id VARCHAR(100),
    p_new_state VARCHAR(50) DEFAULT NULL,
    p_menu_path VARCHAR(500) DEFAULT NULL,
    p_session_data JSONB DEFAULT NULL,
    p_transaction_id UUID DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_updated BOOLEAN := FALSE;
BEGIN
    UPDATE ussd.sessions 
    SET 
        state = COALESCE(p_new_state, state),
        menu_path = COALESCE(p_menu_path, menu_path),
        session_data = COALESCE(p_session_data, session_data),
        transaction_id = COALESCE(p_transaction_id, transaction_id),
        last_activity_at = NOW(),
        expires_at = NOW() + INTERVAL '5 minutes'
    WHERE session_id = p_session_id
      AND is_active = TRUE
      AND expires_at > NOW();
    
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    
    RETURN v_updated > 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.update_session_state IS 'Atomically updates session state and metadata';

-- ----------------------------------------------------------------------------
-- Function: ussd.close_session
-- Description: Gracefully closes a USSD session with completion status
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.close_session(
    p_session_id VARCHAR(100),
    p_completion_status VARCHAR(20) DEFAULT 'COMPLETED',
    p_final_data JSONB DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_session RECORD;
    v_updated BOOLEAN := FALSE;
BEGIN
    -- Get session for audit logging
    SELECT * INTO v_session
    FROM ussd.sessions
    WHERE session_id = p_session_id AND is_active = TRUE;
    
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    
    -- Update session as closed
    UPDATE ussd.sessions 
    SET 
        is_active = FALSE,
        state = 'CLOSED',
        session_data = COALESCE(p_final_data, session_data) || 
            jsonb_build_object('completion_status', p_completion_status),
        closed_at = NOW()
    WHERE session_id = p_session_id;
    
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    
    -- Log session closure
    IF v_updated > 0 THEN
        INSERT INTO ussd.audit_logs (
            session_id,
            msisdn_hash,
            action,
            details,
            created_at
        ) VALUES (
            v_session.id,
            v_session.msisdn_hash,
            'SESSION_CLOSED',
            jsonb_build_object(
                'completion_status', p_completion_status,
                'duration_seconds', EXTRACT(EPOCH FROM (NOW() - v_session.created_at)),
                'final_menu_path', v_session.menu_path
            ),
            NOW()
        );
    END IF;
    
    RETURN v_updated > 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.close_session IS 'Gracefully closes a USSD session with audit logging';

-- ----------------------------------------------------------------------------
-- Function: ussd.cleanup_expired_sessions
-- Description: Batch cleanup of expired sessions (called by cron/trigger)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.cleanup_expired_sessions(
    p_batch_size INTEGER DEFAULT 1000
) RETURNS INTEGER AS $$
DECLARE
    v_cleaned_count INTEGER := 0;
    v_expired RECORD;
BEGIN
    -- Mark expired sessions as closed with timeout status
    WITH expired_sessions AS (
        UPDATE ussd.sessions 
        SET 
            is_active = FALSE,
            state = 'TIMEOUT',
            closed_at = NOW(),
            session_data = session_data || jsonb_build_object(
                'timeout_reason', 'Session expired after inactivity',
                'timeout_at', NOW()
            )
        WHERE is_active = TRUE
          AND expires_at <= NOW()
        RETURNING id, session_id, msisdn_hash, created_at
    )
    SELECT COUNT(*) INTO v_cleaned_count FROM expired_sessions;
    
    -- Log cleanup operation if any sessions were cleaned
    IF v_cleaned_count > 0 THEN
        INSERT INTO ussd.audit_logs (
            session_id,
            msisdn_hash,
            action,
            details,
            created_at
        ) VALUES (
            NULL,
            'SYSTEM',
            'SESSIONS_CLEANED',
            jsonb_build_object(
                'count', v_cleaned_count,
                'batch_size', p_batch_size
            ),
            NOW()
        );
    END IF;
    
    RETURN v_cleaned_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.cleanup_expired_sessions IS 'Batch cleanup of expired USSD sessions';

-- ----------------------------------------------------------------------------
-- Function: ussd.get_session_stats
-- Description: Returns session statistics for monitoring
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.get_session_stats(
    p_time_range INTERVAL DEFAULT INTERVAL '1 hour'
) RETURNS TABLE (
    metric_name VARCHAR(50),
    metric_value BIGINT,
    metric_details JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        'active_sessions'::VARCHAR(50) as metric_name,
        COUNT(*)::BIGINT as metric_value,
        jsonb_build_object(
            'avg_session_duration_sec', 
            COALESCE(AVG(EXTRACT(EPOCH FROM (last_activity_at - created_at))), 0)
        ) as metric_details
    FROM ussd.sessions 
    WHERE is_active = TRUE;
    
    RETURN QUERY
    SELECT 
        'expired_sessions'::VARCHAR(50),
        COUNT(*)::BIGINT,
        jsonb_build_object('time_range', p_time_range::TEXT)
    FROM ussd.sessions 
    WHERE is_active = FALSE 
      AND closed_at >= NOW() - p_time_range;
    
    RETURN QUERY
    SELECT 
        'sessions_by_state'::VARCHAR(50),
        COUNT(*)::BIGINT,
        jsonb_build_object('state', state)
    FROM ussd.sessions 
    WHERE is_active = TRUE
    GROUP BY state;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.get_session_stats IS 'Returns USSD session statistics for monitoring dashboards';
