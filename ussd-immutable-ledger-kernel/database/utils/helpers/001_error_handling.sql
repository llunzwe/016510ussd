-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: utils/helpers/001_error_handling.sql
-- Description: Standardized error handling functions, custom exceptions,
--              and error logging utilities
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: INTERNAL
-- DATA SENSITIVITY: MEDIUM - Error Diagnostics
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.16.1: Management of Information Security Incidents
  - Structured error logging for incident detection
  - Error categorization for priority response
  
A.12.4: Logging and Monitoring
  - Error logging with user context
  - Retry tracking for availability monitoring

A.14.2.5: Secure System Engineering Principles
  - Error messages without information disclosure
  - Standardized error codes for security
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION
================================================================================
- Error logging without PII exposure
- Sanitized error messages for external display
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
- Error logging for storage operation failures
- Data integrity error detection
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
- Error logs as ESI for litigation
- Immutable error audit trail
================================================================================

================================================================================
PCI DSS 4.0 ERROR HANDLING REQUIREMENTS
================================================================================
Requirement 6.5: Secure error handling
Requirement 10.7: Error log retention
Requirement 11.4.5: Intrusion detection through error monitoring
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. Standardized error codes for all error types
2. Error logging without blocking operations
3. Retry logic for transient failures
4. Severity classification for alerts
5. Partitioned error logs for retention management
================================================================================

================================================================================
ERROR CATEGORIES
================================================================================
- AUTH: Authentication errors
- FORB: Authorization errors  
- VAL: Validation errors
- DB: Database errors
- BIZ: Business logic errors
- EXT: External service errors
================================================================================
*/

-- ============================================================================
-- ERROR CODES AND DEFINITIONS
-- ============================================================================

-- Table for error code definitions
CREATE TABLE IF NOT EXISTS error_code_definitions (
    error_code VARCHAR(20) PRIMARY KEY,
    error_category VARCHAR(50) NOT NULL,
    error_title VARCHAR(100) NOT NULL,
    error_description TEXT,
    http_status_code INTEGER,
    is_retryable BOOLEAN DEFAULT FALSE,
    default_severity VARCHAR(20) DEFAULT 'ERROR',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert standard error codes
INSERT INTO error_code_definitions (
    error_code, error_category, error_title, error_description, 
    http_status_code, is_retryable, default_severity
) VALUES
    -- Authentication Errors (AUTH)
    ('AUTH-001', 'authentication', 'Unauthorized', 'Authentication is required', 401, FALSE, 'WARNING'),
    ('AUTH-002', 'authentication', 'Invalid Credentials', 'The provided credentials are invalid', 401, FALSE, 'WARNING'),
    ('AUTH-003', 'authentication', 'Token Expired', 'The authentication token has expired', 401, FALSE, 'WARNING'),
    ('AUTH-004', 'authentication', 'MFA Required', 'Multi-factor authentication required', 401, FALSE, 'WARNING'),
    ('AUTH-005', 'authentication', 'Account Locked', 'Account temporarily locked due to failed attempts', 423, FALSE, 'WARNING'),
    ('AUTH-006', 'authentication', 'Session Invalid', 'Session has been invalidated', 401, FALSE, 'INFO'),
    
    -- Authorization Errors (FORB)
    ('FORB-001', 'authorization', 'Forbidden', 'Access to this resource is forbidden', 403, FALSE, 'WARNING'),
    ('FORB-002', 'authorization', 'Insufficient Permissions', 'The user lacks required permissions', 403, FALSE, 'WARNING'),
    ('FORB-003', 'authorization', 'Resource Ownership', 'User does not own the requested resource', 403, FALSE, 'WARNING'),
    ('FORB-004', 'authorization', 'IP Restricted', 'Access from this IP address is not allowed', 403, FALSE, 'WARNING'),
    
    -- Validation Errors (VAL)
    ('VAL-001', 'validation', 'Invalid Input', 'The provided input is invalid', 400, FALSE, 'WARNING'),
    ('VAL-002', 'validation', 'Missing Required Field', 'A required field is missing', 400, FALSE, 'WARNING'),
    ('VAL-003', 'validation', 'Invalid Format', 'Input format does not match expected pattern', 400, FALSE, 'WARNING'),
    ('VAL-004', 'validation', 'Value Out of Range', 'Input value is outside acceptable range', 400, FALSE, 'WARNING'),
    ('VAL-005', 'validation', 'Duplicate Entry', 'A record with this value already exists', 409, FALSE, 'WARNING'),
    ('VAL-006', 'validation', 'Invalid Reference', 'Referenced record does not exist', 400, FALSE, 'WARNING'),
    ('VAL-007', 'validation', 'Business Rule Violation', 'Operation violates business rules', 422, FALSE, 'WARNING'),
    
    -- Database Errors (DB)
    ('DB-001', 'database', 'Connection Error', 'Failed to connect to the database', 500, TRUE, 'CRITICAL'),
    ('DB-002', 'database', 'Query Error', 'Database query execution failed', 500, FALSE, 'ERROR'),
    ('DB-003', 'database', 'Timeout', 'Database operation timed out', 504, TRUE, 'ERROR'),
    ('DB-004', 'database', 'Deadlock', 'Transaction deadlock detected', 503, TRUE, 'WARNING'),
    ('DB-005', 'database', 'Constraint Violation', 'Database constraint violation', 409, FALSE, 'WARNING'),
    ('DB-006', 'database', 'Serialization Failure', 'Transaction serialization failure', 503, TRUE, 'WARNING'),
    
    -- Business Logic Errors (BIZ)
    ('BIZ-001', 'business', 'Insufficient Funds', 'Account has insufficient funds', 422, FALSE, 'WARNING'),
    ('BIZ-002', 'business', 'Limit Exceeded', 'Transaction limit has been exceeded', 422, FALSE, 'WARNING'),
    ('BIZ-003', 'business', 'Invalid State', 'Object is in an invalid state for this operation', 409, FALSE, 'WARNING'),
    ('BIZ-004', 'business', 'Dependency Error', 'Operation depends on incomplete prerequisite', 422, FALSE, 'WARNING'),
    ('BIZ-005', 'business', 'Rate Limit Exceeded', 'Rate limit has been exceeded', 429, TRUE, 'WARNING'),
    ('BIZ-006', 'business', 'Service Unavailable', 'Service temporarily unavailable', 503, TRUE, 'ERROR'),
    
    -- External Service Errors (EXT)
    ('EXT-001', 'external', 'Service Timeout', 'External service request timed out', 504, TRUE, 'ERROR'),
    ('EXT-002', 'external', 'Service Unavailable', 'External service is unavailable', 503, TRUE, 'ERROR'),
    ('EXT-003', 'external', 'Invalid Response', 'External service returned invalid response', 502, FALSE, 'ERROR'),
    ('EXT-004', 'external', 'Authentication Failed', 'External service authentication failed', 502, FALSE, 'ERROR'),
    ('EXT-005', 'external', 'Rate Limited', 'External service rate limit reached', 429, TRUE, 'WARNING'),
    
    -- System Errors (SYS)
    ('SYS-001', 'system', 'Internal Error', 'An internal system error occurred', 500, FALSE, 'CRITICAL'),
    ('SYS-002', 'system', 'Configuration Error', 'System configuration error', 500, FALSE, 'CRITICAL'),
    ('SYS-003', 'system', 'Resource Exhausted', 'System resources exhausted', 503, TRUE, 'CRITICAL'),
    ('SYS-004', 'system', 'Unexpected Error', 'An unexpected error occurred', 500, FALSE, 'ALERT')
    
ON CONFLICT (error_code) DO UPDATE SET
    error_title = EXCLUDED.error_title,
    error_description = EXCLUDED.error_description,
    http_status_code = EXCLUDED.http_status_code,
    is_retryable = EXCLUDED.is_retryable;

-- ============================================================================
-- ERROR LOGGING
-- ============================================================================

-- Create error log partitions
DO $$
BEGIN
    -- Create error log table with partitioning if not exists
    CREATE TABLE IF NOT EXISTS error_log (
        error_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        error_code VARCHAR(20) REFERENCES error_code_definitions(error_code),
        error_message TEXT,
        error_details JSONB,
        user_id UUID,
        session_id UUID,
        request_id UUID,
        ip_address INET,
        function_name TEXT,
        severity VARCHAR(20) DEFAULT 'ERROR',
        status VARCHAR(20) DEFAULT 'open',
        retry_count INTEGER DEFAULT 0,
        last_retry_at TIMESTAMPTZ,
        resolved_at TIMESTAMPTZ,
        resolved_by UUID,
        resolution_notes TEXT,
        correlation_id UUID,
        created_at TIMESTAMPTZ DEFAULT NOW()
    ) PARTITION BY RANGE (created_at);
    
    -- Create initial partitions
    IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'error_log_2026_01') THEN
        CREATE TABLE error_log_2026_01 PARTITION OF error_log
            FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'error_log_2026_02') THEN
        CREATE TABLE error_log_2026_02 PARTITION OF error_log
            FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'error_log_2026_03') THEN
        CREATE TABLE error_log_2026_03 PARTITION OF error_log
            FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
    END IF;
END $$;

-- Index for error log queries
CREATE INDEX IF NOT EXISTS idx_error_log_code ON error_log(error_code, created_at);
CREATE INDEX IF NOT EXISTS idx_error_log_status ON error_log(status, severity);
CREATE INDEX IF NOT EXISTS idx_error_log_user ON error_log(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_error_log_request ON error_log(request_id);
CREATE INDEX IF NOT EXISTS idx_error_log_correlation ON error_log(correlation_id);

-- ============================================================================
-- ERROR AGGREGATION AND ALERTING
-- ============================================================================

-- Error aggregation table for trend analysis
CREATE TABLE IF NOT EXISTS error_aggregations (
    aggregation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregation_window TIMESTAMPTZ NOT NULL,
    window_size_minutes INTEGER NOT NULL DEFAULT 5,
    error_code VARCHAR(20) REFERENCES error_code_definitions(error_code),
    error_category VARCHAR(50),
    severity VARCHAR(20),
    error_count INTEGER NOT NULL DEFAULT 0,
    unique_users INTEGER DEFAULT 0,
    unique_requests INTEGER DEFAULT 0,
    avg_retry_count NUMERIC(10, 2),
    resolution_time_seconds NUMERIC(10, 2),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_error_agg_window ON error_aggregations(aggregation_window, error_code);

-- Alert thresholds configuration
CREATE TABLE IF NOT EXISTS error_alert_thresholds (
    threshold_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    threshold_name VARCHAR(100) NOT NULL,
    error_code VARCHAR(20) REFERENCES error_code_definitions(error_code),
    error_category VARCHAR(50),
    severity VARCHAR(20),
    window_minutes INTEGER NOT NULL DEFAULT 5,
    count_threshold INTEGER NOT NULL,
    rate_threshold_percent NUMERIC(5, 2), -- Percentage of total requests
    consecutive_windows INTEGER DEFAULT 1,
    alert_severity VARCHAR(20) DEFAULT 'WARNING',
    notification_channels TEXT[] DEFAULT ARRAY['email'],
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default alert thresholds
INSERT INTO error_alert_thresholds (threshold_name, error_code, error_category, severity, window_minutes, count_threshold, alert_severity)
VALUES
    ('Critical DB Errors', NULL, 'database', 'CRITICAL', 5, 10, 'CRITICAL'),
    ('Auth Failures Spike', 'AUTH-002', NULL, NULL, 5, 50, 'WARNING'),
    ('Rate Limit Breaches', 'BIZ-005', NULL, NULL, 1, 100, 'WARNING'),
    ('External Service Failures', NULL, 'external', NULL, 5, 20, 'ERROR'),
    ('System Resource Exhaustion', 'SYS-003', NULL, NULL, 1, 5, 'CRITICAL')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- ERROR LOGGING FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION log_error(
    p_error_code VARCHAR(20),
    p_error_message TEXT,
    p_error_details JSONB DEFAULT NULL,
    p_user_id UUID DEFAULT NULL,
    p_session_id UUID DEFAULT NULL,
    p_request_id UUID DEFAULT NULL,
    p_ip_address INET DEFAULT NULL,
    p_function_name TEXT DEFAULT NULL,
    p_severity VARCHAR(20) DEFAULT NULL,
    p_correlation_id UUID DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_error_id UUID;
    v_default_severity VARCHAR(20);
BEGIN
    -- Get default severity if not provided
    IF p_severity IS NULL THEN
        SELECT default_severity INTO v_default_severity
        FROM error_code_definitions
        WHERE error_code = p_error_code;
        v_default_severity := COALESCE(v_default_severity, 'ERROR');
    ELSE
        v_default_severity := p_severity;
    END IF;
    
    INSERT INTO error_log (
        error_code, error_message, error_details, user_id, session_id,
        request_id, ip_address, function_name, severity, correlation_id
    ) VALUES (
        p_error_code, p_error_message, p_error_details, p_user_id, p_session_id,
        p_request_id, p_ip_address, p_function_name, v_default_severity, p_correlation_id
    )
    RETURNING error_id INTO v_error_id;
    
    RETURN v_error_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- ERROR CORRELATION ANALYSIS
-- ============================================================================

CREATE OR REPLACE FUNCTION analyze_error_correlation(
    p_start_time TIMESTAMPTZ,
    p_end_time TIMESTAMPTZ,
    p_min_occurrences INTEGER DEFAULT 5
)
RETURNS TABLE (
    error_code_1 VARCHAR(20),
    error_code_2 VARCHAR(20),
    co_occurrence_count INTEGER,
    correlation_score NUMERIC(5, 4),
    avg_time_difference_seconds NUMERIC(10, 2),
    suggestion TEXT
) AS $$
BEGIN
    RETURN QUERY
    WITH error_pairs AS (
        SELECT 
            e1.error_code as code1,
            e2.error_code as code2,
            COUNT(*) as pair_count,
            AVG(EXTRACT(EPOCH FROM (e2.created_at - e1.created_at))) as avg_time_diff
        FROM error_log e1
        JOIN error_log e2 ON e1.request_id = e2.request_id 
            AND e1.error_id != e2.error_id
            AND e2.created_at >= e1.created_at
            AND e2.created_at <= e1.created_at + INTERVAL '1 minute'
        WHERE e1.created_at BETWEEN p_start_time AND p_end_time
          AND e2.created_at BETWEEN p_start_time AND p_end_time
        GROUP BY e1.error_code, e2.error_code
        HAVING COUNT(*) >= p_min_occurrences
    )
    SELECT 
        ep.code1,
        ep.code2,
        ep.pair_count::INTEGER,
        LEAST(1.0, ep.pair_count::NUMERIC / (
            SELECT COUNT(*) FROM error_log WHERE error_code = ep.code1 AND created_at BETWEEN p_start_time AND p_end_time
        ))::NUMERIC(5, 4) as correlation,
        ep.avg_time_diff::NUMERIC(10, 2),
        CASE 
            WHEN ep.code1 LIKE 'DB-%' AND ep.code2 LIKE 'EXT-%' THEN 'Database errors causing external service failures - check connection pooling'
            WHEN ep.code1 LIKE 'AUTH-%' AND ep.code2 LIKE 'FORB-%' THEN 'Auth failures followed by permission errors - review token refresh logic'
            WHEN ep.code1 LIKE 'EXT-%' AND ep.code2 LIKE 'BIZ-%' THEN 'External service failures affecting business operations - implement circuit breaker'
            ELSE 'Review error sequence for systemic issues'
        END as suggestion
    FROM error_pairs ep
    ORDER BY ep.pair_count DESC;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- AUTOMATED ERROR RESOLUTION SUGGESTIONS
-- ============================================================================

CREATE TABLE IF NOT EXISTS error_resolution_suggestions (
    suggestion_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    error_code VARCHAR(20) REFERENCES error_code_definitions(error_code),
    error_pattern TEXT,
    suggestion_text TEXT NOT NULL,
    auto_resolution_possible BOOLEAN DEFAULT FALSE,
    auto_resolution_function TEXT,
    success_rate_percent NUMERIC(5, 2),
    avg_resolution_time_seconds INTEGER,
    requires_approval BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO error_resolution_suggestions (error_code, error_pattern, suggestion_text, auto_resolution_possible)
VALUES
    ('DB-004', 'deadlock detected', 'Retry the transaction after a brief delay with exponential backoff', TRUE),
    ('DB-006', 'could not serialize', 'Retry the transaction with a longer delay', TRUE),
    ('AUTH-003', 'token expired', 'Refresh the authentication token using the refresh token', TRUE),
    ('BIZ-005', 'rate limit', 'Implement exponential backoff and retry after the rate limit window', TRUE),
    ('EXT-001', 'timeout', 'Check external service health and retry with increased timeout', FALSE),
    ('DB-001', 'connection refused', 'Verify database connectivity and connection pool configuration', FALSE),
    ('SYS-003', 'resource exhausted', 'Scale up system resources or implement load shedding', FALSE)
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION get_error_resolution_suggestion(
    p_error_id UUID
)
RETURNS TABLE (
    error_code VARCHAR(20),
    error_message TEXT,
    suggestion_text TEXT,
    auto_resolution_possible BOOLEAN,
    resolution_steps TEXT[]
) AS $$
DECLARE
    v_error_record RECORD;
    v_suggestion RECORD;
BEGIN
    SELECT * INTO v_error_record FROM error_log WHERE error_id = p_error_id;
    
    IF v_error_record IS NULL THEN
        RETURN;
    END IF;
    
    SELECT * INTO v_suggestion
    FROM error_resolution_suggestions
    WHERE error_code = v_error_record.error_code
      AND (error_pattern IS NULL OR v_error_record.error_message LIKE '%' || error_pattern || '%')
    ORDER BY success_rate_percent DESC NULLS LAST
    LIMIT 1;
    
    IF v_suggestion IS NULL THEN
        RETURN QUERY SELECT 
            v_error_record.error_code,
            v_error_record.error_message,
            'No automated suggestion available. Manual investigation required.'::TEXT,
            FALSE,
            ARRAY['Review error logs', 'Check related system metrics', 'Escalate to on-call if critical']::TEXT[];
    ELSE
        RETURN QUERY SELECT 
            v_error_record.error_code,
            v_error_record.error_message,
            v_suggestion.suggestion_text,
            v_suggestion.auto_resolution_possible,
            CASE v_suggestion.auto_resolution_possible
                WHEN TRUE THEN ARRAY['Apply automated fix', 'Verify resolution', 'Monitor for recurrence']
                ELSE ARRAY['Manual review required', 'Check system logs', 'Apply suggested fix', 'Verify resolution']
            END;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- RATE LIMITING AND CIRCUIT BREAKER
-- ============================================================================

CREATE TABLE IF NOT EXISTS error_rate_limits (
    limit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    error_code VARCHAR(20) REFERENCES error_code_definitions(error_code),
    error_category VARCHAR(50),
    source_identifier TEXT, -- IP, user_id, or service name
    window_start TIMESTAMPTZ DEFAULT NOW(),
    window_minutes INTEGER DEFAULT 1,
    error_count INTEGER DEFAULT 0,
    circuit_open BOOLEAN DEFAULT FALSE,
    circuit_opened_at TIMESTAMPTZ,
    circuit_reset_after_minutes INTEGER DEFAULT 5,
    blocked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_error_rate_limits_lookup ON error_rate_limits(error_code, source_identifier, window_start);

CREATE OR REPLACE FUNCTION check_error_rate_limit(
    p_error_code VARCHAR(20),
    p_source_identifier TEXT,
    p_max_errors INTEGER DEFAULT 10,
    p_window_minutes INTEGER DEFAULT 1
)
RETURNS TABLE (
    allowed BOOLEAN,
    circuit_open BOOLEAN,
    retry_after_seconds INTEGER,
    current_count INTEGER
) AS $$
DECLARE
    v_record RECORD;
    v_count INTEGER;
    v_circuit_open BOOLEAN := FALSE;
    v_retry_after INTEGER := 0;
BEGIN
    -- Check existing rate limit record
    SELECT * INTO v_record
    FROM error_rate_limits
    WHERE (error_code = p_error_code OR error_code IS NULL)
      AND source_identifier = p_source_identifier
      AND window_start > NOW() - (p_window_minutes || ' minutes')::INTERVAL
    ORDER BY window_start DESC
    LIMIT 1;
    
    IF v_record IS NULL THEN
        -- Create new rate limit record
        INSERT INTO error_rate_limits (error_code, source_identifier, window_minutes, error_count)
        VALUES (p_error_code, p_source_identifier, p_window_minutes, 1)
        RETURNING * INTO v_record;
        v_count := 1;
    ELSE
        -- Check if circuit is open
        IF v_record.circuit_open THEN
            IF v_record.blocked_until > NOW() THEN
                v_circuit_open := TRUE;
                v_retry_after := EXTRACT(EPOCH FROM (v_record.blocked_until - NOW()))::INTEGER;
                v_count := v_record.error_count;
            ELSE
                -- Reset circuit
                UPDATE error_rate_limits 
                SET circuit_open = FALSE, error_count = 1, window_start = NOW()
                WHERE limit_id = v_record.limit_id;
                v_count := 1;
            END IF;
        ELSE
            -- Increment count
            UPDATE error_rate_limits 
            SET error_count = error_count + 1
            WHERE limit_id = v_record.limit_id
            RETURNING error_count INTO v_count;
            
            -- Check if threshold exceeded
            IF v_count >= p_max_errors THEN
                UPDATE error_rate_limits 
                SET circuit_open = TRUE,
                    circuit_opened_at = NOW(),
                    blocked_until = NOW() + (v_record.circuit_reset_after_minutes || ' minutes')::INTERVAL
                WHERE limit_id = v_record.limit_id;
                
                v_circuit_open := TRUE;
                v_retry_after := v_record.circuit_reset_after_minutes * 60;
            END IF;
        END IF;
    END IF;
    
    RETURN QUERY SELECT NOT v_circuit_open, v_circuit_open, v_retry_after, v_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- ERROR SIMULATION FOR TESTING
-- ============================================================================

CREATE OR REPLACE FUNCTION simulate_error(
    p_error_code VARCHAR(20),
    p_delay_seconds INTEGER DEFAULT 0,
    p_should_retry BOOLEAN DEFAULT FALSE
)
RETURNS TABLE (
    simulated BOOLEAN,
    error_id UUID,
    message TEXT
) AS $$
DECLARE
    v_error_def RECORD;
    v_error_id UUID;
BEGIN
    SELECT * INTO v_error_def FROM error_code_definitions WHERE error_code = p_error_code;
    
    IF v_error_def IS NULL THEN
        RETURN QUERY SELECT FALSE, NULL::UUID, format('Unknown error code: %s', p_error_code);
        RETURN;
    END IF;
    
    -- Add delay if specified
    IF p_delay_seconds > 0 THEN
        PERFORM pg_sleep(p_delay_seconds);
    END IF;
    
    -- Log the simulated error
    SELECT log_error(
        p_error_code,
        format('[SIMULATION] %s', v_error_def.error_description),
        jsonb_build_object('simulated', TRUE, 'should_retry', p_should_retry),
        NULL, NULL, gen_random_uuid(), NULL, 'simulate_error',
        v_error_def.default_severity
    ) INTO v_error_id;
    
    -- Simulate retry behavior
    IF p_should_retry AND v_error_def.is_retryable THEN
        PERFORM pg_sleep(0.1); -- Simulate retry delay
        PERFORM log_error(
            'SYS-001',
            '[SIMULATION] Retry attempt completed',
            jsonb_build_object('original_error', p_error_code, 'retry_successful', TRUE),
            NULL, NULL, gen_random_uuid(), NULL, 'simulate_error',
            'INFO'
        );
    END IF;
    
    RETURN QUERY SELECT TRUE, v_error_id, format('Simulated %s: %s', p_error_code, v_error_def.error_title);
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- ERROR IMPACT ASSESSMENT
-- ============================================================================

CREATE OR REPLACE FUNCTION assess_error_impact(
    p_error_id UUID
)
RETURNS TABLE (
    error_id UUID,
    impact_score INTEGER, -- 1-10
    severity_level TEXT,
    affected_users INTEGER,
    affected_transactions INTEGER,
    estimated_financial_impact NUMERIC(18, 4),
    recommendations TEXT[]
) AS $$
DECLARE
    v_error_record RECORD;
    v_user_count INTEGER;
    v_tx_count INTEGER;
    v_impact_score INTEGER;
    v_recommendations TEXT[];
BEGIN
    SELECT * INTO v_error_record FROM error_log WHERE error_id = p_error_id;
    
    IF v_error_record IS NULL THEN
        RETURN;
    END IF;
    
    -- Count affected users (same user in last hour)
    SELECT COUNT(DISTINCT user_id) INTO v_user_count
    FROM error_log
    WHERE error_code = v_error_record.error_code
      AND created_at > v_error_record.created_at - INTERVAL '1 hour'
      AND user_id IS NOT NULL;
    
    -- Count affected transactions (same request pattern)
    SELECT COUNT(*) INTO v_tx_count
    FROM error_log
    WHERE correlation_id = v_error_record.correlation_id
       OR (request_id = v_error_record.request_id AND request_id IS NOT NULL);
    
    -- Calculate impact score
    v_impact_score := CASE v_error_record.severity
        WHEN 'CRITICAL' THEN 9
        WHEN 'ALERT' THEN 10
        WHEN 'ERROR' THEN 7
        WHEN 'WARNING' THEN 5
        ELSE 3
    END;
    
    IF v_user_count > 10 THEN v_impact_score := v_impact_score + 1; END IF;
    IF v_tx_count > 5 THEN v_impact_score := v_impact_score + 1; END IF;
    
    v_impact_score := LEAST(10, v_impact_score);
    
    -- Generate recommendations
    v_recommendations := CASE v_error_record.error_category
        WHEN 'database' THEN ARRAY['Check database connection pool', 'Review query performance', 'Verify replication lag']
        WHEN 'authentication' THEN ARRAY['Check identity provider status', 'Review token expiration settings', 'Verify MFA service']
        WHEN 'external' THEN ARRAY['Check external service health', 'Review timeout configurations', 'Verify API rate limits']
        ELSE ARRAY['Review application logs', 'Check system resources', 'Monitor error trends']
    END;
    
    RETURN QUERY SELECT 
        p_error_id,
        v_impact_score,
        CASE 
            WHEN v_impact_score >= 9 THEN 'CRITICAL'
            WHEN v_impact_score >= 7 THEN 'HIGH'
            WHEN v_impact_score >= 5 THEN 'MEDIUM'
            ELSE 'LOW'
        END,
        v_user_count,
        v_tx_count,
        0::NUMERIC(18, 4), -- Would require business logic to calculate
        v_recommendations;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- ERROR DASHBOARD DATA VIEWS
-- ============================================================================

CREATE OR REPLACE VIEW error_dashboard_summary AS
SELECT 
    date_trunc('hour', created_at) as hour,
    error_code,
    severity,
    status,
    COUNT(*) as error_count,
    COUNT(DISTINCT user_id) as unique_users,
    COUNT(DISTINCT request_id) as unique_requests,
    AVG(retry_count) as avg_retries,
    COUNT(CASE WHEN resolved_at IS NOT NULL THEN 1 END) as resolved_count
FROM error_log
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY date_trunc('hour', created_at), error_code, severity, status;

CREATE OR REPLACE VIEW error_trend_analysis AS
WITH hourly_stats AS (
    SELECT 
        date_trunc('hour', created_at) as hour,
        error_category,
        COUNT(*) as error_count
    FROM error_log e
    JOIN error_code_definitions d ON e.error_code = d.error_code
    WHERE created_at > NOW() - INTERVAL '7 days'
    GROUP BY date_trunc('hour', created_at), error_category
)
SELECT 
    hour,
    error_category,
    error_count,
    AVG(error_count) OVER (
        PARTITION BY error_category 
        ORDER BY hour 
        ROWS BETWEEN 23 PRECEDING AND CURRENT ROW
    ) as rolling_24h_avg,
    error_count - LAG(error_count, 24) OVER (PARTITION BY error_category ORDER BY hour) as delta_24h
FROM hourly_stats;

-- ============================================================================
-- ERROR RECOVERY WORKFLOW
-- ============================================================================

CREATE TABLE IF NOT EXISTS error_recovery_workflows (
    workflow_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    error_id UUID NOT NULL REFERENCES error_log(error_id),
    workflow_type VARCHAR(50) NOT NULL, -- 'auto_retry', 'manual_review', 'escalation', 'notification'
    status VARCHAR(20) DEFAULT 'pending',
    current_step INTEGER DEFAULT 1,
    total_steps INTEGER DEFAULT 1,
    workflow_data JSONB,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION create_recovery_workflow(
    p_error_id UUID,
    p_workflow_type VARCHAR(50) DEFAULT 'auto_retry'
)
RETURNS UUID AS $$
DECLARE
    v_workflow_id UUID;
    v_error_record RECORD;
    v_steps INTEGER;
BEGIN
    SELECT * INTO v_error_record FROM error_log WHERE error_id = p_error_id;
    
    IF v_error_record IS NULL THEN
        RETURN NULL;
    END IF;
    
    v_steps := CASE p_workflow_type
        WHEN 'auto_retry' THEN 3
        WHEN 'manual_review' THEN 2
        WHEN 'escalation' THEN 4
        ELSE 1
    END;
    
    INSERT INTO error_recovery_workflows (
        error_id, workflow_type, total_steps, workflow_data
    ) VALUES (
        p_error_id, p_workflow_type, v_steps,
        jsonb_build_object(
            'error_code', v_error_record.error_code,
            'severity', v_error_record.severity,
            'retryable', (SELECT is_retryable FROM error_code_definitions WHERE error_code = v_error_record.error_code)
        )
    )
    RETURNING workflow_id INTO v_workflow_id;
    
    RETURN v_workflow_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE error_code_definitions IS 'ISO/IEC 27001: Standardized error code definitions for security incident tracking';
COMMENT ON TABLE error_log IS 'PCI DSS 10.7: Error log with partitioning for retention management';
COMMENT ON TABLE error_aggregations IS 'Error aggregation for trend analysis and monitoring';
COMMENT ON TABLE error_alert_thresholds IS 'Alert threshold configuration for error monitoring';
COMMENT ON TABLE error_resolution_suggestions IS 'Automated error resolution suggestions';
COMMENT ON TABLE error_rate_limits IS 'Circuit breaker pattern implementation for error rate limiting';
COMMENT ON VIEW error_dashboard_summary IS 'Dashboard view for error monitoring';
COMMENT ON VIEW error_trend_analysis IS 'Error trend analysis for capacity planning';
COMMENT ON FUNCTION log_error IS 'Standardized error logging function';
COMMENT ON FUNCTION analyze_error_correlation IS 'Error correlation analysis for root cause detection';
COMMENT ON FUNCTION check_error_rate_limit IS 'Circuit breaker pattern for error rate limiting';
COMMENT ON FUNCTION simulate_error IS 'Error simulation for testing and validation';
COMMENT ON FUNCTION assess_error_impact IS 'Error impact assessment scoring';

-- ============================================================================
-- IMPLEMENTATION COMPLETE
-- ============================================================================
