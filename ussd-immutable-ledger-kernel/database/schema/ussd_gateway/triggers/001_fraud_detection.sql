-- ============================================================================
-- USSD Gateway - Fraud Detection Triggers
-- Real-time fraud monitoring and automated response triggers
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Trigger Function: ussd.tf_fraud_check_transaction
-- Description: Performs real-time fraud check on new transactions
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.tf_fraud_check_transaction()
RETURNS TRIGGER AS $$
DECLARE
    v_fraud_result RECORD;
    v_msisdn VARCHAR(20);
    v_session RECORD;
BEGIN
    -- Get session details
    SELECT s.* INTO v_session
    FROM ussd.sessions s
    WHERE s.id = NEW.session_id;
    
    IF NOT FOUND THEN
        -- No session found, high risk
        NEW.status := 'BLOCKED';
        NEW.metadata := NEW.metadata || jsonb_build_object(
            'fraud_block_reason', 'No valid session found'
        );
        RETURN NEW;
    END IF;
    
    -- Decrypt MSISDN for fraud check
    v_msisdn := pgp_sym_decrypt(v_session.msisdn_encrypted, current_setting('app.encryption_key', true));
    
    -- Run fraud detection rules
    SELECT * INTO v_fraud_result
    FROM ussd.check_fraud_rules(
        v_session.session_id,
        NEW.transaction_type,
        NEW.amount,
        NEW.destination_account
    );
    
    -- Update transaction with fraud check results
    NEW.risk_score := v_fraud_result.risk_score;
    NEW.risk_level := v_fraud_result.risk_level;
    NEW.metadata := NEW.metadata || jsonb_build_object(
        'fraud_check_at', NOW(),
        'fraud_rules_triggered', v_fraud_result.triggered_rules,
        'fraud_action', v_fraud_result.action_required
    );
    
    -- Apply fraud action
    CASE v_fraud_result.action_required
        WHEN 'BLOCK' THEN
            NEW.status := 'BLOCKED';
            NEW.metadata := NEW.metadata || jsonb_build_object(
                'blocked_by_fraud_check', TRUE,
                'block_reason', 'High risk score: ' || v_fraud_result.risk_score
            );
            
            -- Log security event
            PERFORM ussd.log_security_event(
                'TRANSACTION_BLOCKED',
                'HIGH',
                v_msisdn,
                v_session.session_id,
                jsonb_build_object(
                    'transaction_id', NEW.id,
                    'risk_score', v_fraud_result.risk_score,
                    'rules', v_fraud_result.triggered_rules
                )
            );
            
        WHEN 'CHALLENGE' THEN
            -- Force OTP requirement
            NEW.requires_otp := TRUE;
            NEW.requires_pin := TRUE;
            
        WHEN 'STEP_UP_AUTH' THEN
            -- Force at least PIN verification
            NEW.requires_pin := TRUE;
    END CASE;
    
    -- Update user risk profile asynchronously
    PERFORM pg_notify('update_risk_profile', jsonb_build_object(
        'msisdn', v_msisdn,
        'transaction_id', NEW.id
    )::TEXT);
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.tf_fraud_check_transaction IS 
'Performs real-time fraud detection on new transactions';

-- ----------------------------------------------------------------------------
-- Trigger: transaction_fraud_check
-- Description: Fraud check before inserting new transactions
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS transaction_fraud_check ON ussd.transactions;
CREATE TRIGGER transaction_fraud_check
    BEFORE INSERT ON ussd.transactions
    FOR EACH ROW
    EXECUTE FUNCTION ussd.tf_fraud_check_transaction();

COMMENT ON TRIGGER transaction_fraud_check ON ussd.transactions IS 
'Fraud detection trigger for new transactions';

-- ----------------------------------------------------------------------------
-- Trigger Function: ussd.tf_fraud_velocity_check
-- Description: Monitors transaction velocity and triggers alerts
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.tf_fraud_velocity_check()
RETURNS TRIGGER AS $$
DECLARE
    v_session RECORD;
    v_msisdn VARCHAR(20);
    v_msisdn_hash VARCHAR(64);
    v_recent_count INTEGER;
    v_recent_amount DECIMAL(18,2);
BEGIN
    -- Only check on status change to completed
    IF NEW.status != 'COMPLETED' OR OLD.status = 'COMPLETED' THEN
        RETURN NEW;
    END IF;
    
    -- Get session details
    SELECT s.* INTO v_session
    FROM ussd.sessions s
    WHERE s.id = NEW.session_id;
    
    IF NOT FOUND THEN
        RETURN NEW;
    END IF;
    
    v_msisdn := pgp_sym_decrypt(v_session.msisdn_encrypted, current_setting('app.encryption_key', true));
    v_msisdn_hash := encode(digest(v_msisdn, 'sha256'), 'hex');
    
    -- Check 5-minute velocity
    SELECT 
        COUNT(*),
        COALESCE(SUM(amount), 0)
    INTO v_recent_count, v_recent_amount
    FROM ussd.transactions t
    JOIN ussd.sessions s ON t.session_id = s.id
    WHERE s.msisdn_hash = v_msisdn_hash
      AND t.status = 'COMPLETED'
      AND t.completed_at >= NOW() - INTERVAL '5 minutes';
    
    -- Alert on suspicious velocity
    IF v_recent_count >= 3 OR v_recent_amount >= 5000 THEN
        PERFORM ussd.log_security_event(
            'VELOCITY_ALERT',
            CASE WHEN v_recent_count >= 5 OR v_recent_amount >= 10000 
                 THEN 'HIGH' ELSE 'MEDIUM' END,
            v_msisdn,
            v_session.session_id,
            jsonb_build_object(
                'recent_count', v_recent_count,
                'recent_amount', v_recent_amount,
                'new_transaction_id', NEW.id,
                'new_amount', NEW.amount
            )
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.tf_fraud_velocity_check IS 
'Monitors transaction velocity patterns';

-- ----------------------------------------------------------------------------
-- Trigger: transaction_velocity_check
-- Description: Velocity monitoring on transaction completion
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS transaction_velocity_check ON ussd.transactions;
CREATE TRIGGER transaction_velocity_check
    AFTER UPDATE ON ussd.transactions
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status)
    EXECUTE FUNCTION ussd.tf_fraud_velocity_check();

COMMENT ON TRIGGER transaction_velocity_check ON ussd.transactions IS 
'Velocity check trigger for completed transactions';

-- ----------------------------------------------------------------------------
-- Trigger Function: ussd.tf_fraud_failed_auth_monitor
-- Description: Monitors failed authentication attempts for fraud patterns
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.tf_fraud_failed_auth_monitor()
RETURNS TRIGGER AS $$
DECLARE
    v_failed_count INTEGER;
    v_msisdn_hash VARCHAR(64);
    v_session RECORD;
BEGIN
    -- Only check on PIN attempt increment
    IF NEW.pin_attempts <= OLD.pin_attempts THEN
        RETURN NEW;
    END IF;
    
    -- Check if threshold reached
    IF NEW.pin_attempts >= 3 THEN
        -- Get session for logging
        SELECT s.* INTO v_session
        FROM ussd.sessions s
        WHERE s.msisdn_hash = NEW.msisdn_hash
          AND s.is_active = TRUE
        ORDER BY s.created_at DESC
        LIMIT 1;
        
        -- Log security event
        PERFORM ussd.log_security_event(
            'MULTIPLE_FAILED_AUTH',
            'HIGH',
            NULL,  -- Don't expose MSISDN in logs
            v_session.session_id,
            jsonb_build_object(
                'failed_attempts', NEW.pin_attempts,
                'msisdn_hash_prefix', LEFT(NEW.msisdn_hash, 16)
            )
        );
        
        -- Create security alert
        INSERT INTO ussd.security_alerts (
            alert_type,
            status,
            details,
            created_at
        ) VALUES (
            'ACCOUNT_LOCKOUT',
            'NEW',
            jsonb_build_object(
                'msisdn_hash', NEW.msisdn_hash,
                'failed_attempts', NEW.pin_attempts,
                'last_attempt_at', NEW.last_pin_attempt_at
            ),
            NOW()
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.tf_fraud_failed_auth_monitor IS 
'Monitors failed authentication attempts for suspicious patterns';

-- ----------------------------------------------------------------------------
-- Trigger: profile_failed_auth_monitor
-- Description: Monitor for repeated authentication failures
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS profile_failed_auth_monitor ON ussd.user_profiles;
CREATE TRIGGER profile_failed_auth_monitor
    AFTER UPDATE ON ussd.user_profiles
    FOR EACH ROW
    WHEN (NEW.pin_attempts > OLD.pin_attempts)
    EXECUTE FUNCTION ussd.tf_fraud_failed_auth_monitor();

COMMENT ON TRIGGER profile_failed_auth_monitor ON ussd.user_profiles IS 
'Fraud monitoring for authentication failures';

-- ----------------------------------------------------------------------------
-- Trigger Function: ussd.tf_fraud_session_anomaly
-- Description: Detects anomalous session patterns
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.tf_fraud_session_anomaly()
RETURNS TRIGGER AS $$
DECLARE
    v_session_count INTEGER;
    v_unique_operators INTEGER;
    v_msisdn VARCHAR(20);
BEGIN
    -- Only check on new session creation
    IF TG_OP != 'INSERT' THEN
        RETURN NEW;
    END IF;
    
    -- Count recent sessions from same MSISDN
    SELECT 
        COUNT(*),
        COUNT(DISTINCT network_operator)
    INTO v_session_count, v_unique_operators
    FROM ussd.sessions
    WHERE msisdn_hash = NEW.msisdn_hash
      AND created_at >= NOW() - INTERVAL '1 hour';
    
    -- Alert on multiple sessions
    IF v_session_count > 5 THEN
        PERFORM ussd.log_security_event(
            'MULTIPLE_SESSIONS',
            'MEDIUM',
            pgp_sym_decrypt(NEW.msisdn_encrypted, current_setting('app.encryption_key', true)),
            NEW.session_id,
            jsonb_build_object(
                'session_count_1h', v_session_count,
                'unique_operators', v_unique_operators,
                'new_session_id', NEW.id
            )
        );
    END IF;
    
    -- Alert on operator switching
    IF v_unique_operators > 2 THEN
        PERFORM ussd.log_security_event(
            'OPERATOR_SWITCHING',
            'HIGH',
            pgp_sym_decrypt(NEW.msisdn_encrypted, current_setting('app.encryption_key', true)),
            NEW.session_id,
            jsonb_build_object(
                'unique_operators', v_unique_operators,
                'suspicious', TRUE
            )
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.tf_fraud_session_anomaly IS 
'Detects anomalous session patterns like rapid reconnection';

-- ----------------------------------------------------------------------------
-- Trigger: session_anomaly_detection
-- Description: Anomaly detection on new sessions
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS session_anomaly_detection ON ussd.sessions;
CREATE TRIGGER session_anomaly_detection
    AFTER INSERT ON ussd.sessions
    FOR EACH ROW
    EXECUTE FUNCTION ussd.tf_fraud_session_anomaly();

COMMENT ON TRIGGER session_anomaly_detection ON ussd.sessions IS 
'Anomaly detection for new USSD sessions';

-- ----------------------------------------------------------------------------
-- Trigger Function: ussd.tf_fraud_geolocation_check
-- Description: Monitors for suspicious location changes
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.tf_fraud_geolocation_check()
RETURNS TRIGGER AS $$
DECLARE
    v_last_location VARCHAR(100);
    v_last_time TIMESTAMPTZ;
    v_time_diff INTERVAL;
BEGIN
    -- Skip if no location data
    IF NEW.location_data IS NULL THEN
        RETURN NEW;
    END IF;
    
    -- Get last known location from session data
    SELECT 
        (session_data->>'last_location')::VARCHAR(100),
        (session_data->>'last_location_at')::TIMESTAMPTZ
    INTO v_last_location, v_last_time
    FROM ussd.sessions
    WHERE id = NEW.session_id;
    
    -- Check for impossible travel (simplified - real implementation would use geo distance)
    IF v_last_location IS NOT NULL AND v_last_time IS NOT NULL THEN
        v_time_diff := NEW.created_at - v_last_time;
        
        -- If location changed significantly in short time
        IF NEW.location_data->>'country' != v_last_location 
           AND v_time_diff < INTERVAL '1 hour' THEN
            
            PERFORM ussd.log_security_event(
                'IMPOSSIBLE_TRAVEL',
                'CRITICAL',
                NULL,
                NEW.session_id::VARCHAR(100),
                jsonb_build_object(
                    'last_location', v_last_location,
                    'current_location', NEW.location_data->>'country',
                    'time_difference_minutes', EXTRACT(EPOCH FROM v_time_diff) / 60
                )
            );
        END IF;
    END IF;
    
    -- Update session with location
    UPDATE ussd.sessions
    SET session_data = session_data || jsonb_build_object(
        'last_location', NEW.location_data->>'country',
        'last_location_at', NEW.created_at
    )
    WHERE id = NEW.session_id;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.tf_fraud_geolocation_check IS 
'Monitors for suspicious location changes';

-- ----------------------------------------------------------------------------
-- Function: ussd.create_fraud_rules
-- Description: Creates or updates fraud detection rules
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.create_fraud_rule(
    p_rule_name VARCHAR(100),
    p_rule_type VARCHAR(50),
    p_condition JSONB,
    p_risk_score INTEGER,
    p_action VARCHAR(20),
    p_is_active BOOLEAN DEFAULT TRUE
) RETURNS UUID AS $$
DECLARE
    v_rule_id UUID;
BEGIN
    INSERT INTO ussd.fraud_rules (
        rule_name,
        rule_type,
        condition,
        risk_score,
        action,
        is_active,
        created_at
    ) VALUES (
        p_rule_name,
        p_rule_type,
        p_condition,
        p_risk_score,
        p_action,
        p_is_active,
        NOW()
    )
    ON CONFLICT (rule_name) 
    DO UPDATE SET
        rule_type = p_rule_type,
        condition = p_condition,
        risk_score = p_risk_score,
        action = p_action,
        is_active = p_is_active,
        updated_at = NOW()
    RETURNING id INTO v_rule_id;
    
    RETURN v_rule_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.create_fraud_rule IS 
'Creates or updates a fraud detection rule';
