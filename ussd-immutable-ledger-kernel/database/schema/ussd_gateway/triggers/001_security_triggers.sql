-- ============================================================================
-- USSD Security Triggers
-- ============================================================================

-- Trigger: Check for suspicious activity
CREATE OR REPLACE FUNCTION ussd.check_suspicious_activity()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ussd_gateway, public
AS $$
DECLARE
    v_recent_attempts INTEGER;
BEGIN
    -- Count recent PIN attempts
    SELECT COUNT(*) INTO v_recent_attempts
    FROM ussd.session_state
    WHERE msisdn_hash = NEW.msisdn_hash
    AND created_at > now() - interval '1 hour';

    IF v_recent_attempts > 10 THEN
        -- Flag for review
        NEW.metadata := COALESCE(NEW.metadata, '{}'::jsonb) || 
            jsonb_build_object('suspicious_activity', TRUE);
        
        -- Log security event
        INSERT INTO core.audit_trail (
            table_name, record_id, action, old_values, new_values,
            changed_by, changed_at, transaction_id, severity
        ) VALUES (
            'session_state', NEW.internal_session_id, 'SECURITY_ALERT',
            '{}',
            jsonb_build_object(
                'reason', 'High volume of sessions',
                'count', v_recent_attempts
            ),
            current_user, now(), txid_current(), 'WARNING'
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_security_check
    BEFORE INSERT ON ussd.session_state
    FOR EACH ROW
    EXECUTE FUNCTION ussd.check_suspicious_activity();

-- Trigger: Update device fingerprint on session
CREATE OR REPLACE FUNCTION ussd.update_device_fingerprint()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ussd_gateway, public
AS $$
BEGIN
    -- Check for SIM swap
    IF NEW.sim_swap_fingerprint IS DISTINCT FROM OLD.sim_swap_fingerprint THEN
        NEW.metadata := COALESCE(NEW.metadata, '{}'::jsonb) || 
            jsonb_build_object('sim_swap_detected', TRUE);
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_device_fingerprint
    BEFORE UPDATE ON ussd.session_state
    FOR EACH ROW
    EXECUTE FUNCTION ussd.update_device_fingerprint();
