-- ============================================================================
-- USSD Gateway - Session Cleanup Triggers
-- Automated cleanup of expired sessions and resource management
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Trigger Function: ussd.tf_session_cleanup_expired
-- Description: Marks expired sessions as closed on any session table access
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.tf_session_cleanup_expired()
RETURNS TRIGGER AS $$
BEGIN
    -- Efficient batch update of expired sessions
    -- Uses SKIP LOCKED to avoid contention with active sessions
    WITH expired AS (
        SELECT id 
        FROM ussd.sessions
        WHERE is_active = TRUE
          AND expires_at <= NOW()
        LIMIT 100
        FOR UPDATE SKIP LOCKED
    )
    UPDATE ussd.sessions s
    SET 
        is_active = FALSE,
        state = 'TIMEOUT',
        closed_at = NOW(),
        session_data = session_data || jsonb_build_object(
            'timeout_reason', 'Automatic cleanup - session expired',
            'cleanup_trigger', TG_NAME,
            'cleaned_at', NOW()
        )
    FROM expired e
    WHERE s.id = e.id;
    
    -- Log cleanup if any sessions were affected
    IF FOUND THEN
        INSERT INTO ussd.maintenance_logs (
            operation,
            table_name,
            records_affected,
            details,
            created_at
        ) VALUES (
            'SESSION_CLEANUP',
            'ussd.sessions',
            (SELECT COUNT(*) FROM ussd.sessions 
             WHERE state = 'TIMEOUT' 
             AND session_data->>'cleanup_trigger' = TG_NAME
             AND closed_at >= NOW() - INTERVAL '1 second'),
            jsonb_build_object(
                'trigger_event', TG_OP,
                'trigger_table', TG_TABLE_NAME
            ),
            NOW()
        );
    END IF;
    
    -- Continue with original operation
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION ussd.tf_session_cleanup_expired IS 
'Automatically marks expired sessions as closed during table operations';

-- ----------------------------------------------------------------------------
-- Trigger: session_cleanup_on_insert
-- Description: Cleanup expired sessions when new sessions are created
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS session_cleanup_on_insert ON ussd.sessions;
CREATE TRIGGER session_cleanup_on_insert
    AFTER INSERT ON ussd.sessions
    FOR EACH STATEMENT
    EXECUTE FUNCTION ussd.tf_session_cleanup_expired();

COMMENT ON TRIGGER session_cleanup_on_insert ON ussd.sessions IS 
'Triggers cleanup of expired sessions when new sessions are created';

-- ----------------------------------------------------------------------------
-- Trigger: session_cleanup_on_select
-- Description: Cleanup expired sessions during reads (periodic maintenance)
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS session_cleanup_on_select ON ussd.sessions;
CREATE TRIGGER session_cleanup_on_select
    BEFORE SELECT ON ussd.sessions
    FOR EACH STATEMENT
    WHEN (random() < 0.01)  -- Only run ~1% of the time to reduce overhead
    EXECUTE FUNCTION ussd.tf_session_cleanup_expired();

COMMENT ON TRIGGER session_cleanup_on_select ON ussd.sessions IS 
'Periodic cleanup trigger that runs occasionally during SELECT operations';

-- ----------------------------------------------------------------------------
-- Trigger Function: ussd.tf_session_audit_log
-- Description: Logs all session state changes for audit trail
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.tf_session_audit_log()
RETURNS TRIGGER AS $$
DECLARE
    v_changes JSONB;
BEGIN
    -- Track state changes
    IF TG_OP = 'INSERT' THEN
        v_changes := jsonb_build_object(
            'operation', 'CREATE',
            'new_state', NEW.state,
            'new_menu_path', NEW.menu_path
        );
    ELSIF TG_OP = 'UPDATE' THEN
        -- Only log if state or path changed
        IF OLD.state IS DISTINCT FROM NEW.state 
           OR OLD.menu_path IS DISTINCT FROM NEW.menu_path THEN
            v_changes := jsonb_build_object(
                'operation', 'UPDATE',
                'old_state', OLD.state,
                'new_state', NEW.state,
                'old_path', OLD.menu_path,
                'new_path', NEW.menu_path,
                'old_active', OLD.is_active,
                'new_active', NEW.is_active
            );
        ELSE
            RETURN NEW;  -- No significant change, skip logging
        END IF;
    ELSIF TG_OP = 'DELETE' THEN
        v_changes := jsonb_build_object(
            'operation', 'DELETE',
            'deleted_state', OLD.state,
            'deleted_at', NOW()
        );
    END IF;
    
    -- Insert audit record
    IF v_changes IS NOT NULL THEN
        INSERT INTO ussd.session_audit_logs (
            session_id,
            operation,
            changes,
            performed_at
        ) VALUES (
            COALESCE(NEW.id, OLD.id),
            TG_OP,
            v_changes,
            NOW()
        );
    END IF;
    
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION ussd.tf_session_audit_log IS 
'Logs all session state changes to audit trail';

-- ----------------------------------------------------------------------------
-- Trigger: session_state_audit
-- Description: Audit logging for session state changes
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS session_state_audit ON ussd.sessions;
CREATE TRIGGER session_state_audit
    AFTER INSERT OR UPDATE OR DELETE ON ussd.sessions
    FOR EACH ROW
    EXECUTE FUNCTION ussd.tf_session_audit_log();

COMMENT ON TRIGGER session_state_audit ON ussd.sessions IS 
'Audit trail for all session modifications';

-- ----------------------------------------------------------------------------
-- Trigger Function: ussd.tf_auto_extend_session
-- Description: Automatically extends session expiry on activity
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.tf_auto_extend_session()
RETURNS TRIGGER AS $$
BEGIN
    -- Extend session expiry on activity
    IF NEW.is_active = TRUE AND OLD.is_active = TRUE THEN
        -- Only extend if significant time has passed (avoid excessive updates)
        IF NEW.last_activity_at > OLD.last_activity_at + INTERVAL '30 seconds' THEN
            NEW.expires_at := NEW.last_activity_at + INTERVAL '5 minutes';
        END IF;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION ussd.tf_auto_extend_session IS 
'Automatically extends session timeout on user activity';

-- ----------------------------------------------------------------------------
-- Trigger: session_auto_extend
-- Description: Extends session lifetime on activity updates
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS session_auto_extend ON ussd.sessions;
CREATE TRIGGER session_auto_extend
    BEFORE UPDATE ON ussd.sessions
    FOR EACH ROW
    WHEN (OLD.last_activity_at IS DISTINCT FROM NEW.last_activity_at)
    EXECUTE FUNCTION ussd.tf_auto_extend_session();

COMMENT ON TRIGGER session_auto_extend ON ussd.sessions IS 
'Extends session expiry time when activity timestamp is updated';

-- ----------------------------------------------------------------------------
-- Trigger Function: ussd.tf_cleanup_orphaned_transactions
-- Description: Cleans up orphaned transactions when session closes
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.tf_cleanup_orphaned_transactions()
RETURNS TRIGGER AS $$
BEGIN
    -- Cancel any pending transactions when session closes
    IF OLD.is_active = TRUE AND NEW.is_active = FALSE THEN
        UPDATE ussd.transactions 
        SET 
            status = 'CANCELLED',
            cancelled_at = NOW(),
            cancellation_reason = 'Session closed: ' || COALESCE(NEW.state, 'Unknown')
        WHERE session_id = NEW.id
          AND status IN ('PENDING', 'PENDING_AUTH');
        
        -- Expire any pending OTPs
        UPDATE ussd.otp_records 
        SET expires_at = LEAST(expires_at, NOW())
        WHERE transaction_id IN (
            SELECT id FROM ussd.transactions 
            WHERE session_id = NEW.id
        )
        AND verified = FALSE;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION ussd.tf_cleanup_orphaned_transactions IS 
'Cancels pending transactions when session is closed';

-- ----------------------------------------------------------------------------
-- Trigger: session_close_cleanup
-- Description: Cleanup operations when session closes
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS session_close_cleanup ON ussd.sessions;
CREATE TRIGGER session_close_cleanup
    BEFORE UPDATE ON ussd.sessions
    FOR EACH ROW
    WHEN (OLD.is_active = TRUE AND NEW.is_active = FALSE)
    EXECUTE FUNCTION ussd.tf_cleanup_orphaned_transactions();

COMMENT ON TRIGGER session_close_cleanup ON ussd.sessions IS 
'Cleans up associated resources when session closes';

-- ----------------------------------------------------------------------------
-- Function: ussd.schedule_session_cleanup
-- Description: Can be called by pg_cron for periodic cleanup
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.schedule_session_cleanup(
    p_max_age_hours INTEGER DEFAULT 24
) RETURNS INTEGER AS $$
DECLARE
    v_cleaned_sessions INTEGER;
    v_cleaned_audit INTEGER;
    v_cleaned_otp INTEGER;
BEGIN
    -- Clean up old closed sessions (archival)
    WITH archived AS (
        DELETE FROM ussd.sessions
        WHERE is_active = FALSE
          AND closed_at < NOW() - (p_max_age_hours || ' hours')::INTERVAL
        RETURNING id
    )
    SELECT COUNT(*) INTO v_cleaned_sessions FROM archived;
    
    -- Clean up old audit logs (keep 90 days)
    DELETE FROM ussd.session_audit_logs
    WHERE performed_at < NOW() - INTERVAL '90 days';
    GET DIAGNOSTICS v_cleaned_audit = ROW_COUNT;
    
    -- Clean up expired OTP records (keep 7 days for analysis)
    DELETE FROM ussd.otp_records
    WHERE expires_at < NOW() - INTERVAL '7 days';
    GET DIAGNOSTICS v_cleaned_otp = ROW_COUNT;
    
    -- Log maintenance operation
    INSERT INTO ussd.maintenance_logs (
        operation,
        table_name,
        records_affected,
        details,
        created_at
    ) VALUES 
        ('ARCHIVE_CLEANUP', 'ussd.sessions', v_cleaned_sessions, 
         jsonb_build_object('max_age_hours', p_max_age_hours), NOW()),
        ('ARCHIVE_CLEANUP', 'ussd.session_audit_logs', v_cleaned_audit,
         jsonb_build_object('retention_days', 90), NOW()),
        ('ARCHIVE_CLEANUP', 'ussd.otp_records', v_cleaned_otp,
         jsonb_build_object('retention_days', 7), NOW());
    
    RETURN v_cleaned_sessions + v_cleaned_audit + v_cleaned_otp;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION ussd.schedule_session_cleanup IS 
'Periodic maintenance function for cleaning up old session data';
