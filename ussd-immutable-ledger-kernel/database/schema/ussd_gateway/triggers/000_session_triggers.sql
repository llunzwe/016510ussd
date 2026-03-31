-- ============================================================================
-- USSD Session Triggers
-- ============================================================================

-- Trigger: Update session hash on change
CREATE OR REPLACE FUNCTION ussd.update_session_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ussd_gateway, public
AS $$
BEGIN
    NEW.session_hash := encode(
        digest(
            NEW.internal_session_id::text || 
            NEW.menu_state || 
            NEW.last_activity_at::text,
            'sha256'
        ),
        'hex'
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_session_hash
    BEFORE UPDATE ON ussd.session_state
    FOR EACH ROW
    EXECUTE FUNCTION ussd.update_session_hash();

-- Trigger: Audit session creation
CREATE OR REPLACE FUNCTION ussd.audit_session()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ussd_gateway, public
AS $$
BEGIN
    INSERT INTO core.audit_trail (
        table_name, record_id, action, old_values, new_values,
        changed_by, changed_at, transaction_id, severity
    ) VALUES (
        'session_state', NEW.internal_session_id, 
        CASE TG_OP WHEN 'INSERT' THEN 'CREATE' ELSE 'UPDATE' END,
        '{}',
        jsonb_build_object(
            'session_id', NEW.external_session_id,
            'shortcode', NEW.shortcode,
            'application_id', NEW.application_id
        ),
        current_user, now(), txid_current(), 'INFO'
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_session_audit
    AFTER INSERT OR UPDATE ON ussd.session_state
    FOR EACH ROW
    EXECUTE FUNCTION ussd.audit_session();
