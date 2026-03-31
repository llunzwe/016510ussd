-- ============================================================================
-- USSD Gateway - Security Engine Functions
-- Fraud detection, risk scoring, and security monitoring
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Function: ussd.check_fraud_rules
-- Description: Evaluates transaction against fraud detection rules
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.check_fraud_rules(
    p_session_id VARCHAR(100),
    p_transaction_type VARCHAR(50),
    p_amount DECIMAL(18,2),
    p_destination_account VARCHAR(100) DEFAULT NULL
) RETURNS TABLE (
    risk_score INTEGER,
    risk_level VARCHAR(20),
    triggered_rules JSONB,
    action_required VARCHAR(20),
    block_transaction BOOLEAN
) AS $$
DECLARE
    v_session RECORD;
    v_msisdn VARCHAR(20);
    v_msisdn_hash VARCHAR(64);
    v_score INTEGER := 0;
    v_rules JSONB := '[]'::JSONB;
    v_level VARCHAR(20) := 'LOW';
    v_action VARCHAR(20) := 'ALLOW';
    v_block BOOLEAN := FALSE;
    v_hourly_count INTEGER;
    v_unique_destinations INTEGER;
    v_failed_attempts INTEGER;
    v_avg_amount DECIMAL(18,2);
BEGIN
    -- Get session details
    SELECT * INTO v_session FROM ussd.get_session(p_session_id);
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT 
            100, 'HIGH'::VARCHAR(20), '[{"rule": "INVALID_SESSION"}]'::JSONB, 
            'BLOCK'::VARCHAR(20), TRUE;
        RETURN;
    END IF;
    
    v_msisdn := v_session.msisdn;
    v_msisdn_hash := encode(digest(v_msisdn, 'sha256'), 'hex');
    
    -- Rule 1: Velocity check - transactions per hour
    SELECT COUNT(*) INTO v_hourly_count
    FROM ussd.transactions t
    JOIN ussd.sessions s ON t.session_id = s.id
    WHERE s.msisdn_hash = v_msisdn_hash
      AND t.created_at >= NOW() - INTERVAL '1 hour'
      AND t.status IN ('COMPLETED', 'PENDING');
    
    IF v_hourly_count > 10 THEN
        v_score := v_score + 30;
        v_rules := v_rules || jsonb_build_object(
            'rule', 'HIGH_VELOCITY',
            'description', 'More than 10 transactions in last hour',
            'count', v_hourly_count,
            'score', 30
        );
    ELSIF v_hourly_count > 5 THEN
        v_score := v_score + 15;
        v_rules := v_rules || jsonb_build_object(
            'rule', 'ELEVATED_VELOCITY',
            'description', 'More than 5 transactions in last hour',
            'count', v_hourly_count,
            'score', 15
        );
    END IF;
    
    -- Rule 2: Amount anomaly - significantly higher than average
    SELECT COALESCE(AVG(amount), 0) INTO v_avg_amount
    FROM ussd.transactions t
    JOIN ussd.sessions s ON t.session_id = s.id
    WHERE s.msisdn_hash = v_msisdn_hash
      AND t.status = 'COMPLETED'
      AND t.created_at >= NOW() - INTERVAL '30 days';
    
    IF v_avg_amount > 0 AND p_amount > v_avg_amount * 3 THEN
        v_score := v_score + 25;
        v_rules := v_rules || jsonb_build_object(
            'rule', 'AMOUNT_ANOMALY',
            'description', 'Amount significantly higher than average',
            'amount', p_amount,
            'average', v_avg_amount,
            'multiplier', ROUND(p_amount / NULLIF(v_avg_amount, 0), 2),
            'score', 25
        );
    END IF;
    
    -- Rule 3: New destination account
    IF p_destination_account IS NOT NULL THEN
        SELECT COUNT(DISTINCT destination_account) INTO v_unique_destinations
        FROM ussd.transactions t
        JOIN ussd.sessions s ON t.session_id = s.id
        WHERE s.msisdn_hash = v_msisdn_hash
          AND t.destination_account = p_destination_account
          AND t.status = 'COMPLETED';
        
        IF v_unique_destinations = 0 THEN
            v_score := v_score + 15;
            v_rules := v_rules || jsonb_build_object(
                'rule', 'NEW_DESTINATION',
                'description', 'First-time transfer to this destination',
                'destination', encode(digest(p_destination_account, 'sha256'), 'hex'),
                'score', 15
            );
        END IF;
    END IF;
    
    -- Rule 4: Failed authentication attempts
    SELECT COALESCE(pin_attempts, 0) INTO v_failed_attempts
    FROM ussd.user_profiles
    WHERE msisdn_hash = v_msisdn_hash;
    
    IF v_failed_attempts > 0 THEN
        v_score := v_score + (v_failed_attempts * 10);
        v_rules := v_rules || jsonb_build_object(
            'rule', 'RECENT_FAILED_ATTEMPTS',
            'description', 'Recent failed authentication attempts',
            'failed_attempts', v_failed_attempts,
            'score', v_failed_attempts * 10
        );
    END IF;
    
    -- Rule 5: Time-based risk (unusual hours)
    IF EXTRACT(HOUR FROM NOW()) BETWEEN 0 AND 5 THEN
        v_score := v_score + 10;
        v_rules := v_rules || jsonb_build_object(
            'rule', 'UNUSUAL_HOURS',
            'description', 'Transaction during unusual hours (00:00-05:00)',
            'hour', EXTRACT(HOUR FROM NOW())::INTEGER,
            'score', 10
        );
    END IF;
    
    -- Rule 6: Session anomaly (rapid state changes)
    IF EXISTS (
        SELECT 1 FROM ussd.audit_logs
        WHERE session_id = v_session.id
          AND created_at >= NOW() - INTERVAL '1 minute'
          AND action LIKE 'NAV%'
        HAVING COUNT(*) > 10
    ) THEN
        v_score := v_score + 20;
        v_rules := v_rules || jsonb_build_object(
            'rule', 'RAPID_NAVIGATION',
            'description', 'Unusually rapid menu navigation',
            'score', 20
        );
    END IF;
    
    -- Determine risk level and action
    IF v_score >= 70 THEN
        v_level := 'CRITICAL';
        v_action := 'BLOCK';
        v_block := TRUE;
    ELSIF v_score >= 50 THEN
        v_level := 'HIGH';
        v_action := 'CHALLENGE';
        v_block := FALSE;
    ELSIF v_score >= 30 THEN
        v_level := 'MEDIUM';
        v_action := 'STEP_UP_AUTH';
        v_block := FALSE;
    ELSE
        v_level := 'LOW';
        v_action := 'ALLOW';
        v_block := FALSE;
    END IF;
    
    -- Log fraud check
    INSERT INTO ussd.fraud_checks (
        session_id,
        transaction_type,
        amount,
        risk_score,
        risk_level,
        triggered_rules,
        action_taken,
        created_at
    ) VALUES (
        v_session.id,
        p_transaction_type,
        p_amount,
        v_score,
        v_level,
        v_rules,
        v_action,
        NOW()
    );
    
    RETURN QUERY SELECT v_score, v_level, v_rules, v_action, v_block;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.check_fraud_rules IS 'Evaluates transaction against fraud detection rules';

-- ----------------------------------------------------------------------------
-- Function: ussd.update_risk_profile
-- Description: Updates user risk profile based on behavior patterns
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.update_risk_profile(
    p_msisdn VARCHAR(20)
) RETURNS VOID AS $$
DECLARE
    v_msisdn_hash VARCHAR(64);
    v_daily_volume DECIMAL(18,2);
    v_daily_count INTEGER;
    v_hourly_pattern INTEGER[];
    v_avg_transaction DECIMAL(18,2);
    v_risk_category VARCHAR(20) := 'STANDARD';
BEGIN
    v_msisdn_hash := encode(digest(p_msisdn, 'sha256'), 'hex');
    
    -- Calculate daily metrics
    SELECT 
        COALESCE(SUM(amount), 0),
        COUNT(*)
    INTO v_daily_volume, v_daily_count
    FROM ussd.transactions t
    JOIN ussd.sessions s ON t.session_id = s.id
    WHERE s.msisdn_hash = v_msisdn_hash
      AND t.status = 'COMPLETED'
      AND t.created_at >= CURRENT_DATE;
    
    -- Calculate average transaction
    SELECT COALESCE(AVG(amount), 0) INTO v_avg_transaction
    FROM ussd.transactions t
    JOIN ussd.sessions s ON t.session_id = s.id
    WHERE s.msisdn_hash = v_msisdn_hash
      AND t.status = 'COMPLETED'
      AND t.created_at >= NOW() - INTERVAL '30 days';
    
    -- Determine risk category based on behavior
    IF v_daily_volume > 50000 OR v_daily_count > 50 THEN
        v_risk_category := 'HIGH_VOLUME';
    ELSIF v_avg_transaction > 10000 THEN
        v_risk_category := 'HIGH_VALUE';
    ELSIF v_daily_count > 0 THEN
        v_risk_category := 'STANDARD';
    ELSE
        v_risk_category := 'NEW_USER';
    END IF;
    
    -- Upsert risk profile
    INSERT INTO ussd.user_risk_profiles (
        msisdn_hash,
        risk_category,
        daily_volume,
        daily_count,
        avg_transaction_amount,
        last_updated
    ) VALUES (
        v_msisdn_hash,
        v_risk_category,
        v_daily_volume,
        v_daily_count,
        v_avg_transaction,
        NOW()
    )
    ON CONFLICT (msisdn_hash) 
    DO UPDATE SET
        risk_category = v_risk_category,
        daily_volume = v_daily_volume,
        daily_count = v_daily_count,
        avg_transaction_amount = v_avg_transaction,
        last_updated = NOW();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.update_risk_profile IS 'Updates user risk profile based on transaction patterns';

-- ----------------------------------------------------------------------------
-- Function: ussd.block_device
-- Description: Blocks a device/MSISDN due to suspicious activity
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.block_device(
    p_msisdn VARCHAR(20),
    p_reason TEXT,
    p_blocked_by VARCHAR(100) DEFAULT 'SYSTEM',
    p_duration_hours INTEGER DEFAULT NULL
) RETURNS TABLE (
    success BOOLEAN,
    block_id UUID,
    expires_at TIMESTAMPTZ,
    message TEXT
) AS $$
DECLARE
    v_msisdn_hash VARCHAR(64);
    v_block_id UUID;
    v_expiry TIMESTAMPTZ;
BEGIN
    v_msisdn_hash := encode(digest(p_msisdn, 'sha256'), 'hex');
    v_expiry := CASE 
        WHEN p_duration_hours IS NULL THEN NULL
        ELSE NOW() + (p_duration_hours || ' hours')::INTERVAL
    END;
    
    -- Insert block record
    INSERT INTO ussd.blocked_devices (
        msisdn_hash,
        imei_hash,
        reason,
        blocked_by,
        blocked_at,
        expires_at,
        is_active
    ) VALUES (
        v_msisdn_hash,
        NULL, -- Could be populated if IMEI available
        p_reason,
        p_blocked_by,
        NOW(),
        v_expiry,
        TRUE
    )
    RETURNING id INTO v_block_id;
    
    -- Close any active sessions
    UPDATE ussd.sessions 
    SET is_active = FALSE,
        state = 'BLOCKED',
        closed_at = NOW()
    WHERE msisdn_hash = v_msisdn_hash
      AND is_active = TRUE;
    
    -- Log the block
    INSERT INTO ussd.audit_logs (
        session_id,
        msisdn_hash,
        action,
        details,
        created_at
    ) VALUES (
        NULL,
        v_msisdn_hash,
        'DEVICE_BLOCKED',
        jsonb_build_object(
            'reason', p_reason,
            'blocked_by', p_blocked_by,
            'expires_at', v_expiry
        ),
        NOW()
    );
    
    RETURN QUERY SELECT 
        TRUE,
        v_block_id,
        v_expiry,
        'Device blocked successfully'::TEXT;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.block_device IS 'Blocks a device due to suspicious activity';

-- ----------------------------------------------------------------------------
-- Function: ussd.unblock_device
-- Description: Removes a device block
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.unblock_device(
    p_block_id UUID,
    p_unblocked_by VARCHAR(100) DEFAULT 'ADMIN'
) RETURNS BOOLEAN AS $$
BEGIN
    UPDATE ussd.blocked_devices 
    SET 
        is_active = FALSE,
        unblocked_at = NOW(),
        unblocked_by = p_unblocked_by
    WHERE id = p_block_id
      AND is_active = TRUE;
    
    RETURN FOUND;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.unblock_device IS 'Removes a device block';

-- ----------------------------------------------------------------------------
-- Function: ussd.is_device_blocked
-- Description: Checks if a device/MSISDN is blocked
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.is_device_blocked(
    p_msisdn VARCHAR(20),
    p_imei VARCHAR(50) DEFAULT NULL
) RETURNS TABLE (
    is_blocked BOOLEAN,
    block_reason TEXT,
    blocked_until TIMESTAMPTZ
) AS $$
DECLARE
    v_msisdn_hash VARCHAR(64);
    v_block RECORD;
BEGIN
    v_msisdn_hash := encode(digest(p_msisdn, 'sha256'), 'hex');
    
    -- Check for active block
    SELECT * INTO v_block
    FROM ussd.blocked_devices
    WHERE (msisdn_hash = v_msisdn_hash OR imei_hash = encode(digest(p_imei, 'sha256'), 'hex'))
      AND is_active = TRUE
      AND (expires_at IS NULL OR expires_at > NOW())
    ORDER BY blocked_at DESC
    LIMIT 1;
    
    IF FOUND THEN
        RETURN QUERY SELECT 
            TRUE,
            v_block.reason::TEXT,
            v_block.expires_at;
    ELSE
        RETURN QUERY SELECT 
            FALSE,
            NULL::TEXT,
            NULL::TIMESTAMPTZ;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.is_device_blocked IS 'Checks if a device is blocked';

-- ----------------------------------------------------------------------------
-- Function: ussd.log_security_event
-- Description: Logs security-related events for audit and analysis
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.log_security_event(
    p_event_type VARCHAR(50),
    p_severity VARCHAR(20),
    p_msisdn VARCHAR(20) DEFAULT NULL,
    p_session_id VARCHAR(100) DEFAULT NULL,
    p_details JSONB DEFAULT '{}',
    p_source_ip INET DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_event_id UUID;
    v_msisdn_hash VARCHAR(64);
BEGIN
    IF p_msisdn IS NOT NULL THEN
        v_msisdn_hash := encode(digest(p_msisdn, 'sha256'), 'hex');
    END IF;
    
    INSERT INTO ussd.security_events (
        event_type,
        severity,
        msisdn_hash,
        session_id,
        details,
        source_ip,
        created_at
    ) VALUES (
        p_event_type,
        p_severity,
        v_msisdn_hash,
        p_session_id,
        p_details,
        COALESCE(p_source_ip, inet_client_addr()),
        NOW()
    )
    RETURNING id INTO v_event_id;
    
    -- Alert if critical severity
    IF p_severity = 'CRITICAL' THEN
        -- Could trigger external notification here
        INSERT INTO ussd.security_alerts (
            event_id,
            alert_type,
            status,
            created_at
        ) VALUES (
            v_event_id,
            p_event_type,
            'NEW',
            NOW()
        );
    END IF;
    
    RETURN v_event_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.log_security_event IS 'Logs security events with optional alerting';

-- ----------------------------------------------------------------------------
-- Function: ussd.get_security_alerts
-- Description: Retrieves pending security alerts for review
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.get_security_alerts(
    p_status VARCHAR(20) DEFAULT 'NEW',
    p_limit INTEGER DEFAULT 50
) RETURNS TABLE (
    alert_id UUID,
    event_type VARCHAR(50),
    severity VARCHAR(20),
    msisdn_hash VARCHAR(64),
    details JSONB,
    created_at TIMESTAMPTZ,
    event_created_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        sa.id as alert_id,
        se.event_type,
        se.severity,
        se.msisdn_hash,
        se.details,
        sa.created_at,
        se.created_at as event_created_at
    FROM ussd.security_alerts sa
    JOIN ussd.security_events se ON sa.event_id = se.id
    WHERE sa.status = p_status
    ORDER BY se.severity = 'CRITICAL' DESC, sa.created_at DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.get_security_alerts IS 'Retrieves pending security alerts';

-- ----------------------------------------------------------------------------
-- Function: ussd.resolve_security_alert
-- Description: Marks a security alert as resolved
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.resolve_security_alert(
    p_alert_id UUID,
    p_resolution TEXT,
    p_resolved_by VARCHAR(100)
) RETURNS BOOLEAN AS $$
BEGIN
    UPDATE ussd.security_alerts 
    SET 
        status = 'RESOLVED',
        resolution = p_resolution,
        resolved_by = p_resolved_by,
        resolved_at = NOW()
    WHERE id = p_alert_id
      AND status = 'NEW';
    
    RETURN FOUND;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.resolve_security_alert IS 'Resolves a security alert';
