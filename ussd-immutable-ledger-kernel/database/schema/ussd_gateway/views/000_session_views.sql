-- ============================================================================
-- USSD Gateway - Session Views
-- Active session monitoring and operational views
-- ============================================================================

-- ----------------------------------------------------------------------------
-- View: ussd.v_active_sessions
-- Description: Real-time view of active sessions with decrypted MSISDN
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW ussd.v_active_sessions AS
SELECT 
    s.id,
    s.session_id,
    s.network_operator,
    s.state,
    s.menu_path::TEXT as current_menu_path,
    s.session_data,
    s.created_at,
    s.last_activity_at,
    s.expires_at,
    EXTRACT(EPOCH FROM (s.expires_at - NOW()))::INTEGER as seconds_until_timeout,
    CASE 
        WHEN s.expires_at <= NOW() + INTERVAL '1 minute' THEN 'CRITICAL'
        WHEN s.expires_at <= NOW() + INTERVAL '2 minutes' THEN 'WARNING'
        ELSE 'HEALTHY'
    END as session_health,
    t.id as pending_transaction_id,
    t.transaction_type as pending_transaction_type,
    t.amount as pending_amount,
    t.status as transaction_status
FROM ussd.sessions s
LEFT JOIN ussd.transactions t ON s.transaction_id = t.id AND t.status IN ('PENDING', 'PENDING_AUTH')
WHERE s.is_active = TRUE
  AND s.expires_at > NOW()
ORDER BY s.last_activity_at DESC;

COMMENT ON VIEW ussd.v_active_sessions IS 
'Real-time view of active USSD sessions with health status';

-- ----------------------------------------------------------------------------
-- View: ussd.v_session_summary
-- Description: Aggregated session statistics
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW ussd.v_session_summary AS
WITH session_stats AS (
    SELECT 
        COUNT(*) FILTER (WHERE is_active = TRUE AND expires_at > NOW()) as active_count,
        COUNT(*) FILTER (WHERE is_active = FALSE AND closed_at >= CURRENT_DATE) as closed_today,
        COUNT(*) FILTER (WHERE state = 'TIMEOUT' AND closed_at >= CURRENT_DATE) as timeouts_today,
        AVG(EXTRACT(EPOCH FROM (COALESCE(closed_at, last_activity_at) - created_at)))::INTEGER 
            as avg_session_duration_sec,
        MAX(EXTRACT(EPOCH FROM (COALESCE(closed_at, last_activity_at) - created_at)))::INTEGER 
            as max_session_duration_sec,
        network_operator,
        DATE_TRUNC('hour', created_at) as hour_bucket
    FROM ussd.sessions
    WHERE created_at >= NOW() - INTERVAL '24 hours'
    GROUP BY network_operator, DATE_TRUNC('hour', created_at)
)
SELECT 
    hour_bucket,
    network_operator,
    active_count,
    closed_today,
    timeouts_today,
    avg_session_duration_sec,
    max_session_duration_sec
FROM session_stats
ORDER BY hour_bucket DESC, network_operator;

COMMENT ON VIEW ussd.v_session_summary IS 
'Aggregated session statistics by hour and operator';

-- ----------------------------------------------------------------------------
-- View: ussd.v_expired_sessions
-- Description: Recently expired sessions requiring cleanup
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW ussd.v_expired_sessions AS
SELECT 
    s.id,
    s.session_id,
    s.state,
    s.menu_path::TEXT as final_menu_path,
    s.session_data,
    s.created_at,
    s.expires_at,
    s.closed_at,
    EXTRACT(EPOCH FROM (s.expires_at - s.last_activity_at))::INTEGER as idle_seconds,
    CASE 
        WHEN s.session_data ? 'completion_status' THEN s.session_data->>'completion_status'
        WHEN s.state = 'TIMEOUT' THEN 'TIMEOUT'
        ELSE 'UNKNOWN'
    END as completion_reason
FROM ussd.sessions s
WHERE s.is_active = FALSE
  AND s.closed_at >= NOW() - INTERVAL '24 hours'
ORDER BY s.closed_at DESC;

COMMENT ON VIEW ussd.v_expired_sessions IS 
'Recently expired sessions for analysis and cleanup verification';

-- ----------------------------------------------------------------------------
-- View: ussd.v_transaction_queue
-- Description: Pending transactions awaiting authentication
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW ussd.v_transaction_queue AS
SELECT 
    t.id as transaction_id,
    t.transaction_type,
    t.amount,
    t.currency_code,
    t.status,
    t.requires_pin,
    t.requires_otp,
    t.pin_verified,
    t.otp_verified,
    t.created_at,
    t.expires_at,
    EXTRACT(EPOCH FROM (t.expires_at - NOW()))::INTEGER as seconds_until_expiry,
    s.session_id,
    s.network_operator,
    t.risk_score,
    t.risk_level,
    CASE 
        WHEN t.expires_at <= NOW() THEN 'EXPIRED'
        WHEN t.expires_at <= NOW() + INTERVAL '2 minutes' THEN 'CRITICAL'
        WHEN t.expires_at <= NOW() + INTERVAL '5 minutes' THEN 'URGENT'
        ELSE 'NORMAL'
    END as priority
FROM ussd.transactions t
JOIN ussd.sessions s ON t.session_id = s.id
WHERE t.status IN ('PENDING', 'PENDING_AUTH')
ORDER BY 
    CASE 
        WHEN t.expires_at <= NOW() THEN 0
        WHEN t.expires_at <= NOW() + INTERVAL '2 minutes' THEN 1
        WHEN t.expires_at <= NOW() + INTERVAL '5 minutes' THEN 2
        ELSE 3
    END,
    t.created_at ASC;

COMMENT ON VIEW ussd.v_transaction_queue IS 
'Pending transactions awaiting authentication with priority levels';

-- ----------------------------------------------------------------------------
-- View: ussd.v_user_session_history
-- Description: Session history for user support (hash-based lookup)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW ussd.v_user_session_history AS
SELECT 
    s.id as session_id,
    s.msisdn_hash,
    LEFT(s.msisdn_hash, 16) || '...' as msisdn_masked,
    s.network_operator,
    s.state,
    s.menu_path::TEXT as menu_path,
    s.session_data,
    s.is_active,
    s.created_at,
    s.last_activity_at,
    s.closed_at,
    EXTRACT(EPOCH FROM (COALESCE(s.closed_at, s.last_activity_at) - s.created_at))::INTEGER 
        as duration_seconds,
    COUNT(t.id) as transaction_count,
    COALESCE(SUM(t.amount) FILTER (WHERE t.status = 'COMPLETED'), 0) as total_completed_amount,
    COALESCE(SUM(t.amount) FILTER (WHERE t.status = 'FAILED'), 0) as total_failed_amount
FROM ussd.sessions s
LEFT JOIN ussd.transactions t ON s.id = t.session_id
GROUP BY s.id, s.msisdn_hash, s.network_operator, s.state, s.menu_path,
         s.session_data, s.is_active, s.created_at, s.last_activity_at, s.closed_at
ORDER BY s.created_at DESC;

COMMENT ON VIEW ussd.v_user_session_history IS 
'Session history view for user support (PII masked)';

-- ----------------------------------------------------------------------------
-- View: ussd.v_session_audit_trail
-- Description: Complete audit trail for sessions
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW ussd.v_session_audit_trail AS
SELECT 
    sal.id as audit_id,
    sal.session_id,
    s.session_id as external_session_id,
    sal.operation,
    sal.changes,
    sal.performed_at,
    LAG(sal.changes) OVER (PARTITION BY sal.session_id ORDER BY sal.performed_at) 
        as previous_changes,
    sal.changes ->> 'new_state' as state_after,
    sal.changes ->> 'old_state' as state_before
FROM ussd.session_audit_logs sal
LEFT JOIN ussd.sessions s ON sal.session_id = s.id
ORDER BY sal.performed_at DESC;

COMMENT ON VIEW ussd.v_session_audit_trail IS 
'Complete audit trail of all session state changes';

-- ----------------------------------------------------------------------------
-- View: ussd.v_menu_navigation_stats
-- Description: Menu navigation analytics
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW ussd.v_menu_navigation_stats AS
WITH menu_visits AS (
    SELECT 
        (changes ->> 'new_path')::LTREE as menu_path,
        COUNT(*) as visit_count,
        COUNT(DISTINCT session_id) as unique_sessions,
        AVG(EXTRACT(EPOCH FROM (performed_at - LAG(performed_at) OVER (
            PARTITION BY session_id ORDER BY performed_at
        ))))::INTEGER as avg_time_spent_seconds
    FROM ussd.session_audit_logs
    WHERE operation = 'UPDATE'
      AND changes ? 'new_path'
      AND performed_at >= NOW() - INTERVAL '7 days'
    GROUP BY changes ->> 'new_path'
)
SELECT 
    mv.menu_path::TEXT,
    m.display_text as menu_title,
    m.menu_type,
    mv.visit_count,
    mv.unique_sessions,
    mv.avg_time_spent_seconds,
    ROUND(mv.visit_count::NUMERIC / NULLIF(mv.unique_sessions, 0), 2) as avg_visits_per_session
FROM menu_visits mv
LEFT JOIN ussd.menus m ON mv.menu_path = m.full_path
ORDER BY mv.visit_count DESC;

COMMENT ON VIEW ussd.v_menu_navigation_stats IS 
'Menu navigation analytics for UX optimization';

-- ----------------------------------------------------------------------------
-- View: ussd.v_system_health
-- Description: Overall system health dashboard
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW ussd.v_system_health AS
WITH metrics AS (
    SELECT 
        -- Session metrics
        COUNT(*) FILTER (WHERE s.is_active = TRUE AND s.expires_at > NOW()) 
            as active_sessions,
        COUNT(*) FILTER (WHERE s.is_active = TRUE AND s.expires_at <= NOW() + INTERVAL '1 minute') 
            as critical_sessions,
        
        -- Transaction metrics
        COUNT(t.id) FILTER (WHERE t.status = 'PENDING_AUTH') 
            as pending_transactions,
        COUNT(t.id) FILTER (WHERE t.status = 'COMPLETED' AND t.completed_at >= NOW() - INTERVAL '1 hour') 
            as completed_last_hour,
        AVG(t.amount) FILTER (WHERE t.status = 'COMPLETED' AND t.completed_at >= NOW() - INTERVAL '1 hour')
            as avg_transaction_last_hour,
        
        -- Security metrics
        COUNT(se.id) FILTER (WHERE se.created_at >= NOW() - INTERVAL '1 hour' AND se.severity = 'CRITICAL')
            as critical_security_events,
        COUNT(se.id) FILTER (WHERE se.created_at >= NOW() - INTERVAL '1 hour' AND se.severity = 'HIGH')
            as high_security_events,
            
        -- Fraud metrics
        COUNT(fc.id) FILTER (WHERE fc.created_at >= NOW() - INTERVAL '1 hour' AND fc.risk_level = 'CRITICAL')
            as critical_fraud_checks
            
    FROM ussd.sessions s
    LEFT JOIN ussd.transactions t ON s.id = t.session_id
    LEFT JOIN ussd.security_events se ON TRUE
    LEFT JOIN ussd.fraud_checks fc ON TRUE
)
SELECT 
    active_sessions,
    critical_sessions,
    pending_transactions,
    completed_last_hour,
    COALESCE(avg_transaction_last_hour, 0)::DECIMAL(18,2) as avg_transaction_last_hour,
    critical_security_events,
    high_security_events,
    critical_fraud_checks,
    CASE 
        WHEN critical_security_events > 0 OR critical_fraud_checks > 10 THEN 'CRITICAL'
        WHEN high_security_events > 5 OR critical_sessions > 100 THEN 'WARNING'
        WHEN active_sessions > 10000 THEN 'BUSY'
        ELSE 'HEALTHY'
    END as system_status,
    NOW() as reported_at
FROM metrics;

COMMENT ON VIEW ussd.v_system_health IS 
'Real-time system health dashboard view';

-- ----------------------------------------------------------------------------
-- View: ussd.v_session_errors
-- Description: Session errors and failures for troubleshooting
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW ussd.v_session_errors AS
SELECT 
    s.id as session_id,
    s.session_id as external_session_id,
    s.state,
    s.session_data ->> 'error' as error_message,
    s.session_data ->> 'completion_status' as completion_status,
    s.created_at,
    s.closed_at,
    t.id as failed_transaction_id,
    t.transaction_type as failed_transaction_type,
    t.amount as failed_amount,
    t.status as transaction_status,
    t.metadata ->> 'fraud_block_reason' as block_reason,
    t.risk_score,
    t.risk_level
FROM ussd.sessions s
LEFT JOIN ussd.transactions t ON s.id = t.session_id AND t.status IN ('FAILED', 'BLOCKED', 'CANCELLED')
WHERE s.session_data ? 'error'
   OR s.state = 'ERROR'
   OR t.status IN ('FAILED', 'BLOCKED')
   OR s.session_data ->> 'completion_status' = 'ERROR'
ORDER BY s.created_at DESC;

COMMENT ON VIEW ussd.v_session_errors IS 
'Session errors and failures for troubleshooting';

-- ----------------------------------------------------------------------------
-- Materialized View: ussd.mv_daily_session_stats
-- Description: Pre-aggregated daily statistics for reporting
-- ----------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS ussd.mv_daily_session_stats AS
SELECT 
    DATE(s.created_at) as session_date,
    s.network_operator,
    COUNT(*) as total_sessions,
    COUNT(*) FILTER (WHERE s.state = 'TIMEOUT') as timeout_count,
    COUNT(*) FILTER (WHERE s.session_data ->> 'completion_status' = 'COMPLETED') as completed_count,
    COUNT(*) FILTER (WHERE s.session_data ->> 'completion_status' = 'CANCELLED') as cancelled_count,
    AVG(EXTRACT(EPOCH FROM (COALESCE(s.closed_at, s.last_activity_at) - s.created_at)))::INTEGER 
        as avg_duration_seconds,
    COUNT(DISTINCT t.id) as total_transactions,
    COUNT(DISTINCT t.id) FILTER (WHERE t.status = 'COMPLETED') as completed_transactions,
    COALESCE(SUM(t.amount) FILTER (WHERE t.status = 'COMPLETED'), 0) as total_transaction_volume,
    AVG(t.risk_score) FILTER (WHERE t.risk_score IS NOT NULL)::INTEGER as avg_risk_score
FROM ussd.sessions s
LEFT JOIN ussd.transactions t ON s.id = t.session_id
WHERE s.created_at >= CURRENT_DATE - INTERVAL '90 days'
GROUP BY DATE(s.created_at), s.network_operator
ORDER BY session_date DESC, network_operator;

CREATE UNIQUE INDEX idx_mv_daily_session_stats 
ON ussd.mv_daily_session_stats (session_date, network_operator);

COMMENT ON MATERIALIZED VIEW ussd.mv_daily_session_stats IS 
'Daily session statistics for reporting (refresh nightly)';

-- ----------------------------------------------------------------------------
-- Function to refresh materialized view
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.refresh_daily_stats()
RETURNS VOID AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY ussd.mv_daily_session_stats;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION ussd.refresh_daily_stats IS 
'Refreshes the daily session statistics materialized view';
