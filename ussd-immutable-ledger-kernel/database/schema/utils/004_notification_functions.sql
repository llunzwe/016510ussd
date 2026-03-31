-- ============================================================================
-- Notification Functions
-- ============================================================================

-- Function: Queue notification
CREATE OR REPLACE FUNCTION utils.queue_notification(
    p_channel VARCHAR(50),
    p_recipient TEXT,
    p_subject TEXT,
    p_body TEXT,
    p_priority VARCHAR(16) DEFAULT 'NORMAL'
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = utils, public
AS $$
DECLARE
    v_notification_id UUID;
BEGIN
    v_notification_id := gen_random_uuid();
    
    -- In production, would insert into notification queue table
    -- For now, use PostgreSQL LISTEN/NOTIFY
    PERFORM pg_notify(
        p_channel,
        json_build_object(
            'id', v_notification_id,
            'recipient', p_recipient,
            'subject', p_subject,
            'priority', p_priority
        )::text
    );
    
    RETURN v_notification_id;
END;
$$;

COMMENT ON FUNCTION utils.queue_notification IS 'Queues notification for delivery';

-- Function: Send audit alert
CREATE OR REPLACE FUNCTION utils.send_audit_alert(
    p_severity VARCHAR(16),
    p_event_type VARCHAR(50),
    p_description TEXT
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = utils, public
AS $$
BEGIN
    PERFORM pg_notify(
        'audit_alerts',
        json_build_object(
            'severity', p_severity,
            'event_type', p_event_type,
            'description', p_description,
            'timestamp', now()
        )::text
    );
END;
$$;

COMMENT ON FUNCTION utils.send_audit_alert IS 'Sends real-time audit alert';
