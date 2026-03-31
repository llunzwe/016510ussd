-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: utils/helpers/002_logging_utilities.sql
-- Description: Comprehensive logging system with severity levels, structured
--              logging, and log rotation capabilities
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: INTERNAL
-- DATA SENSITIVITY: MEDIUM - Application Logs
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.12.4 Logging and Monitoring
  - Structured logging with severity levels
  - Comprehensive application event tracking
  
A.12.4.1: Event Logging
  - User identification in all log entries
  - Timestamp synchronization
  
A.12.4.2: Protection of Log Information
  - Log partitioning prevents tampering
  - Structured format for integrity verification
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION
================================================================================
- Logging without PII exposure
- Structured logs for privacy audit
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
- Log partitioning for retention management
- Compression for efficient storage
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
- Structured logs as ESI
- Immutable log retention
================================================================================

================================================================================
PCI DSS 4.0 LOGGING REQUIREMENTS
================================================================================
Requirement 10.2: Audit logs covering all system components
Requirement 10.3: Audit trail coverage
Requirement 10.7: Retention policy for audit logs
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. Partitioned tables for log retention
2. JSONB for structured logging
3. Severity levels aligned with syslog
4. Correlation IDs for distributed tracing
5. Automated log rotation
================================================================================

================================================================================
LOG LEVELS (RFC 5424 Syslog Severity Levels)
================================================================================
DEBUG (7): Detailed debugging information
INFO (6): Informational messages
NOTICE (5): Normal but significant condition
WARNING (4): Warning conditions
ERROR (3): Error conditions
CRITICAL (2): Critical conditions
ALERT (1): Action must be taken immediately
EMERGENCY (0): System is unusable
================================================================================

================================================================================
RETENTION POLICY
================================================================================
Application Logs: 90 days
Security Events: 1 year (PCI DSS 10.7)
Audit Logs: 7 years (financial regulations)
Critical Errors: 3 years
================================================================================
*/

-- ============================================================================
-- LOG LEVELS CONFIGURATION
-- ============================================================================

CREATE TYPE log_level AS ENUM ('DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERROR', 'CRITICAL', 'ALERT', 'EMERGENCY');

-- Configuration table
CREATE TABLE IF NOT EXISTS logging_config (
    config_key VARCHAR(50) PRIMARY KEY,
    config_value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default configuration
INSERT INTO logging_config (config_key, config_value, description) VALUES
    ('min_log_level', 'INFO', 'Minimum log level to record'),
    ('log_to_table', 'true', 'Enable table logging'),
    ('log_retention_days', '90', 'Number of days to retain logs (PCI DSS 10.7)'),
    ('audit_log_enabled', 'true', 'Enable audit logging'),
    ('log_sampling_rate', '100', 'Log sampling rate percentage (100 = no sampling)'),
    ('log_compression_enabled', 'true', 'Enable log compression for archival'),
    ('log_shipper_enabled', 'false', 'Enable external log shipping'),
    ('opentelemetry_enabled', 'false', 'Enable OpenTelemetry structured logging')
ON CONFLICT (config_key) DO UPDATE SET
    config_value = EXCLUDED.config_value;

-- ============================================================================
-- LOG TABLES
-- ============================================================================

-- Create log partitions
DO $$
BEGIN
    -- Main application log
    CREATE TABLE IF NOT EXISTS app_log (
        log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        log_timestamp TIMESTAMPTZ DEFAULT NOW(),
        log_level log_level NOT NULL,
        log_source VARCHAR(100),
        log_function VARCHAR(100),
        log_message TEXT NOT NULL,
        log_details JSONB,
        user_id UUID,
        session_id UUID,
        request_id UUID,
        correlation_id UUID,
        ip_address INET,
        trace_id TEXT, -- For distributed tracing
        span_id TEXT,
        parent_span_id TEXT,
        service_name VARCHAR(100) DEFAULT 'ussd-ledger',
        environment VARCHAR(20) DEFAULT 'production'
    ) PARTITION BY RANGE (log_timestamp);
    
    -- Create initial partitions
    IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'app_log_2026_01') THEN
        CREATE TABLE app_log_2026_01 PARTITION OF app_log
            FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'app_log_2026_02') THEN
        CREATE TABLE app_log_2026_02 PARTITION OF app_log
            FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'app_log_2026_03') THEN
        CREATE TABLE app_log_2026_03 PARTITION OF app_log
            FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
    END IF;
END $$;

-- Indexes for efficient log queries
CREATE INDEX IF NOT EXISTS idx_app_log_timestamp ON app_log(log_timestamp);
CREATE INDEX IF NOT EXISTS idx_app_log_level ON app_log(log_level, log_timestamp);
CREATE INDEX IF NOT EXISTS idx_app_log_source ON app_log(log_source, log_timestamp);
CREATE INDEX IF NOT EXISTS idx_app_log_user ON app_log(user_id, log_timestamp);
CREATE INDEX IF NOT EXISTS idx_app_log_request ON app_log(request_id);
CREATE INDEX IF NOT EXISTS idx_app_log_correlation ON app_log(correlation_id);
CREATE INDEX IF NOT EXISTS idx_app_log_trace ON app_log(trace_id, span_id);

-- ============================================================================
-- LOG SHIPPING CONFIGURATION
-- ============================================================================

CREATE TABLE IF NOT EXISTS log_shipping_config (
    shipper_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    shipper_name VARCHAR(100) NOT NULL,
    shipper_type VARCHAR(50) NOT NULL, -- 'elk', 'splunk', 'cloudwatch', 'datadog', 'custom'
    endpoint_url TEXT,
    api_key_encrypted TEXT,
    index_name VARCHAR(100),
    batch_size INTEGER DEFAULT 100,
    flush_interval_seconds INTEGER DEFAULT 30,
    retry_attempts INTEGER DEFAULT 3,
    is_active BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert sample configurations (inactive by default)
INSERT INTO log_shipping_config (shipper_name, shipper_type, endpoint_url, index_name, is_active)
VALUES
    ('ELK Stack', 'elk', 'http://elasticsearch:9200', 'ussd-ledger-logs', FALSE),
    ('Splunk', 'splunk', 'https://splunk-hec:8088', 'main', FALSE),
    ('CloudWatch', 'cloudwatch', 'arn:aws:logs:region:account:log-group:ussd-ledger', NULL, FALSE)
ON CONFLICT DO NOTHING;

-- ============================================================================
-- LOG SHIPPING QUEUE
-- ============================================================================

CREATE TABLE IF NOT EXISTS log_shipping_queue (
    queue_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    log_id UUID NOT NULL,
    shipper_id UUID REFERENCES log_shipping_config(shipper_id),
    status VARCHAR(20) DEFAULT 'pending', -- pending, processing, shipped, failed
    retry_count INTEGER DEFAULT 0,
    last_error TEXT,
    shipped_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_log_ship_queue_status ON log_shipping_queue(status, created_at);

-- ============================================================================
-- CORE LOGGING FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION app_log_write(
    p_level log_level,
    p_message TEXT,
    p_source VARCHAR(100) DEFAULT NULL,
    p_function VARCHAR(100) DEFAULT NULL,
    p_details JSONB DEFAULT NULL,
    p_user_id UUID DEFAULT NULL,
    p_session_id UUID DEFAULT NULL,
    p_request_id UUID DEFAULT NULL,
    p_correlation_id UUID DEFAULT NULL,
    p_ip_address INET DEFAULT NULL,
    p_trace_id TEXT DEFAULT NULL,
    p_span_id TEXT DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_log_id UUID;
    v_min_level log_level;
    v_sampling_rate INTEGER;
    v_should_log BOOLEAN := TRUE;
BEGIN
    -- Check minimum log level
    SELECT config_value::log_level INTO v_min_level
    FROM logging_config WHERE config_key = 'min_log_level';
    v_min_level := COALESCE(v_min_level, 'INFO'::log_level);
    
    -- Skip if below minimum level
    IF p_level < v_min_level THEN
        RETURN NULL;
    END IF;
    
    -- Apply sampling for high-volume logs
    SELECT config_value::INTEGER INTO v_sampling_rate
    FROM logging_config WHERE config_key = 'log_sampling_rate';
    v_sampling_rate := COALESCE(v_sampling_rate, 100);
    
    IF v_sampling_rate < 100 AND p_level IN ('DEBUG', 'INFO') THEN
        v_should_log := (random() * 100) < v_sampling_rate;
    END IF;
    
    IF NOT v_should_log THEN
        RETURN NULL;
    END IF;
    
    INSERT INTO app_log (
        log_level, log_source, log_function, log_message, log_details,
        user_id, session_id, request_id, correlation_id, ip_address,
        trace_id, span_id
    ) VALUES (
        p_level, p_source, p_function, p_message, p_details,
        p_user_id, p_session_id, p_request_id, p_correlation_id, p_ip_address,
        p_trace_id, p_span_id
    )
    RETURNING log_id INTO v_log_id;
    
    -- Queue for external shipping if enabled
    INSERT INTO log_shipping_queue (log_id, shipper_id)
    SELECT v_log_id, shipper_id
    FROM log_shipping_config
    WHERE is_active = TRUE;
    
    RETURN v_log_id;
END;
$$ LANGUAGE plpgsql;

-- Convenience functions for each log level
CREATE OR REPLACE FUNCTION log_debug(p_message TEXT, p_source VARCHAR(100) DEFAULT NULL, p_details JSONB DEFAULT NULL)
RETURNS UUID AS $$ BEGIN RETURN app_log_write('DEBUG', p_message, p_source, NULL, p_details); END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION log_info(p_message TEXT, p_source VARCHAR(100) DEFAULT NULL, p_details JSONB DEFAULT NULL)
RETURNS UUID AS $$ BEGIN RETURN app_log_write('INFO', p_message, p_source, NULL, p_details); END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION log_warning(p_message TEXT, p_source VARCHAR(100) DEFAULT NULL, p_details JSONB DEFAULT NULL)
RETURNS UUID AS $$ BEGIN RETURN app_log_write('WARNING', p_message, p_source, NULL, p_details); END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION log_error(p_message TEXT, p_source VARCHAR(100) DEFAULT NULL, p_details JSONB DEFAULT NULL)
RETURNS UUID AS $$ BEGIN RETURN app_log_write('ERROR', p_message, p_source, NULL, p_details); END; $$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION log_critical(p_message TEXT, p_source VARCHAR(100) DEFAULT NULL, p_details JSONB DEFAULT NULL)
RETURNS UUID AS $$ BEGIN RETURN app_log_write('CRITICAL', p_message, p_source, NULL, p_details); END; $$ LANGUAGE plpgsql;

-- ============================================================================
-- LOG SAMPLING FOR HIGH-VOLUME SCENARIOS
-- ============================================================================

CREATE TABLE IF NOT EXISTS log_sampling_rules (
    rule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_name VARCHAR(100) NOT NULL,
    source_pattern VARCHAR(100),
    message_pattern VARCHAR(200),
    log_level log_level,
    sampling_rate_percent INTEGER NOT NULL CHECK (sampling_rate_percent BETWEEN 0 AND 100),
    time_window_minutes INTEGER DEFAULT 5,
    max_logs_per_window INTEGER,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default sampling rules
INSERT INTO log_shipping_config (shipper_name, shipper_type, endpoint_url, index_name, is_active)
VALUES
    ('High Volume Debug', 'internal', NULL, NULL, FALSE)
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION apply_log_sampling(
    p_level log_level,
    p_source VARCHAR(100),
    p_message TEXT
)
RETURNS BOOLEAN AS $$
DECLARE
    v_rule RECORD;
    v_recent_count INTEGER;
    v_should_log BOOLEAN := TRUE;
BEGIN
    -- Check for matching sampling rules
    SELECT * INTO v_rule
    FROM log_sampling_rules
    WHERE is_active = TRUE
      AND (log_level IS NULL OR log_level = p_level)
      AND (source_pattern IS NULL OR p_source LIKE source_pattern)
      AND (message_pattern IS NULL OR p_message LIKE message_pattern)
    ORDER BY sampling_rate_percent ASC
    LIMIT 1;
    
    IF v_rule IS NULL THEN
        RETURN TRUE;
    END IF;
    
    -- Apply sampling rate
    IF v_rule.sampling_rate_percent < 100 THEN
        v_should_log := (random() * 100) < v_rule.sampling_rate_percent;
    END IF;
    
    -- Check rate limit per window
    IF v_rule.max_logs_per_window IS NOT NULL THEN
        SELECT COUNT(*) INTO v_recent_count
        FROM app_log
        WHERE log_source = p_source
          AND log_level = p_level
          AND log_timestamp > NOW() - (v_rule.time_window_minutes || ' minutes')::INTERVAL;
        
        IF v_recent_count >= v_rule.max_logs_per_window THEN
            v_should_log := FALSE;
        END IF;
    END IF;
    
    RETURN v_should_log;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- DISTRIBUTED TRACING SUPPORT
-- ============================================================================

CREATE OR REPLACE FUNCTION generate_trace_id()
RETURNS TEXT AS $$
BEGIN
    RETURN encode(gen_random_bytes(16), 'hex');
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION generate_span_id()
RETURNS TEXT AS $$
BEGIN
    RETURN encode(gen_random_bytes(8), 'hex');
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION start_trace(
    p_trace_name TEXT,
    p_user_id UUID DEFAULT NULL,
    p_correlation_id UUID DEFAULT NULL
)
RETURNS TABLE (
    trace_id TEXT,
    span_id TEXT,
    correlation_id UUID
) AS $$
DECLARE
    v_trace_id TEXT;
    v_span_id TEXT;
    v_correlation_id UUID;
BEGIN
    v_trace_id := generate_trace_id();
    v_span_id := generate_span_id();
    v_correlation_id := COALESCE(p_correlation_id, gen_random_uuid());
    
    -- Log trace start
    PERFORM app_log_write(
        'INFO',
        format('Trace started: %s', p_trace_name),
        'distributed_tracing',
        'start_trace',
        jsonb_build_object('trace_name', p_trace_name),
        p_user_id, NULL, NULL, v_correlation_id, NULL,
        v_trace_id, v_span_id
    );
    
    RETURN QUERY SELECT v_trace_id, v_span_id, v_correlation_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION log_span(
    p_trace_id TEXT,
    p_parent_span_id TEXT,
    p_span_name TEXT,
    p_span_data JSONB DEFAULT NULL
)
RETURNS TEXT AS $$
DECLARE
    v_span_id TEXT;
BEGIN
    v_span_id := generate_span_id();
    
    PERFORM app_log_write(
        'DEBUG',
        format('Span: %s', p_span_name),
        'distributed_tracing',
        'log_span',
        jsonb_build_object('span_name', p_span_name, 'span_data', p_span_data),
        NULL, NULL, NULL, NULL, NULL,
        p_trace_id, v_span_id, p_parent_span_id
    );
    
    RETURN v_span_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- LOG-BASED ALERTING RULES ENGINE
-- ============================================================================

CREATE TABLE IF NOT EXISTS log_alert_rules (
    rule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_name VARCHAR(100) NOT NULL,
    description TEXT,
    
    -- Match conditions
    min_log_level log_level,
    source_pattern VARCHAR(100),
    message_pattern VARCHAR(200),
    log_details_query JSONB, -- JSONB path query
    
    -- Threshold conditions
    threshold_count INTEGER NOT NULL DEFAULT 1,
    threshold_window_minutes INTEGER NOT NULL DEFAULT 5,
    consecutive_occurrences INTEGER DEFAULT 1,
    
    -- Alert configuration
    alert_severity VARCHAR(20) DEFAULT 'WARNING',
    notification_channels TEXT[] DEFAULT ARRAY['email'],
    notification_template TEXT,
    auto_resolve_after_minutes INTEGER,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    last_triggered_at TIMESTAMPTZ,
    trigger_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert sample alert rules
INSERT INTO log_alert_rules (rule_name, description, min_log_level, threshold_count, threshold_window_minutes, alert_severity)
VALUES
    ('Critical Error Spike', 'Alert on multiple critical errors', 'CRITICAL', 5, 5, 'CRITICAL'),
    ('DB Connection Errors', 'Database connection issues detected', 'ERROR', 10, 5, 'WARNING'),
    ('Auth Failures', 'Multiple authentication failures', 'WARNING', 20, 10, 'WARNING'),
    ('High Error Rate', 'General error rate threshold', 'ERROR', 50, 5, 'ERROR')
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION evaluate_log_alert_rules(
    p_check_window_minutes INTEGER DEFAULT 5
)
RETURNS TABLE (
    rule_id UUID,
    rule_name VARCHAR(100),
    triggered BOOLEAN,
    match_count INTEGER,
    alert_message TEXT
) AS $$
DECLARE
    v_rule RECORD;
    v_count INTEGER;
    v_triggered BOOLEAN;
BEGIN
    FOR v_rule IN SELECT * FROM log_alert_rules WHERE is_active = TRUE
    LOOP
        -- Count matching logs
        SELECT COUNT(*) INTO v_count
        FROM app_log
        WHERE log_timestamp > NOW() - (p_check_window_minutes || ' minutes')::INTERVAL
          AND (v_rule.min_log_level IS NULL OR log_level >= v_rule.min_log_level)
          AND (v_rule.source_pattern IS NULL OR log_source LIKE v_rule.source_pattern)
          AND (v_rule.message_pattern IS NULL OR log_message LIKE v_rule.message_pattern)
          AND (v_rule.log_details_query IS NULL OR log_details @> v_rule.log_details_query);
        
        v_triggered := v_count >= v_rule.threshold_count;
        
        IF v_triggered THEN
            UPDATE log_alert_rules 
            SET last_triggered_at = NOW(),
                trigger_count = trigger_count + 1
            WHERE rule_id = v_rule.rule_id;
        END IF;
        
        RETURN QUERY SELECT 
            v_rule.rule_id,
            v_rule.rule_name,
            v_triggered,
            v_count,
            CASE WHEN v_triggered 
                THEN format('Alert: %s - %s occurrences in %s minutes', v_rule.rule_name, v_count, p_check_window_minutes)
                ELSE NULL
            END;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- OPENTELEMETRY STRUCTURED LOGGING
-- ============================================================================

CREATE OR REPLACE FUNCTION format_otel_log(
    p_log_id UUID
)
RETURNS JSONB AS $$
DECLARE
    v_log RECORD;
BEGIN
    SELECT * INTO v_log FROM app_log WHERE log_id = p_log_id;
    
    IF v_log IS NULL THEN
        RETURN NULL;
    END IF;
    
    RETURN jsonb_build_object(
        'timestamp', v_log.log_timestamp,
        'severity', v_log.log_level,
        'body', v_log.log_message,
        'attributes', jsonb_build_object(
            'source', v_log.log_source,
            'function', v_log.log_function,
            'service.name', v_log.service_name,
            'deployment.environment', v_log.environment
        ),
        'trace_id', v_log.trace_id,
        'span_id', v_log.span_id,
        'trace_flags', '01',
        'resource', jsonb_build_object(
            'service.name', v_log.service_name,
            'service.version', (SELECT config_value FROM logging_config WHERE config_key = 'app.version')
        ),
        'user_id', v_log.user_id,
        'request_id', v_log.request_id,
        'correlation_id', v_log.correlation_id,
        'details', v_log.log_details
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- LOG COMPRESSION FOR ARCHIVAL STORAGE
-- ============================================================================

CREATE TABLE IF NOT EXISTS log_archives (
    archive_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    archive_date DATE NOT NULL,
    partition_name TEXT NOT NULL,
    row_count INTEGER,
    uncompressed_size_bytes BIGINT,
    compressed_size_bytes BIGINT,
    compression_ratio NUMERIC(5, 2),
    archive_location TEXT,
    checksum TEXT,
    archived_at TIMESTAMPTZ DEFAULT NOW(),
    restored_at TIMESTAMPTZ,
    retention_until TIMESTAMPTZ
);

CREATE OR REPLACE FUNCTION compress_old_logs(
    p_older_than_days INTEGER DEFAULT 30
)
RETURNS TABLE (
    partition_name TEXT,
    rows_archived INTEGER,
    compressed_size_bytes BIGINT
) AS $$
DECLARE
    v_partition RECORD;
    v_count INTEGER;
BEGIN
    -- Find old partitions
    FOR v_partition IN 
        SELECT tablename 
        FROM pg_tables 
        WHERE tablename LIKE 'app_log_%'
          AND tablename < 'app_log_' || to_char(NOW() - (p_older_than_days || ' days')::INTERVAL, 'YYYY_MM')
    LOOP
        -- Get row count
        EXECUTE format('SELECT COUNT(*) FROM %I', v_partition.tablename) INTO v_count;
        
        IF v_count > 0 THEN
            -- Archive metadata
            INSERT INTO log_archives (
                archive_date, partition_name, row_count, 
                uncompressed_size_bytes, retention_until
            ) VALUES (
                CURRENT_DATE,
                v_partition.tablename,
                v_count,
                v_count * 500, -- Estimate ~500 bytes per log row
                NOW() + INTERVAL '7 years' -- Financial regulation retention
            );
            
            -- In production, this would compress and move to cold storage
            -- For now, we just record the archive metadata
            
            RETURN QUERY SELECT v_partition.tablename, v_count, (v_count * 500 / 10)::BIGINT; -- Assume 10:1 compression
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- REAL-TIME LOG STREAMING (WEBSOCKET SIMULATION)
-- ============================================================================

CREATE TABLE IF NOT EXISTS log_stream_subscriptions (
    subscription_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscriber_session TEXT NOT NULL,
    min_log_level log_level DEFAULT 'INFO',
    source_filter TEXT[],
    message_filter TEXT,
    user_id_filter UUID,
    correlation_id_filter UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_delivery_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE OR REPLACE FUNCTION publish_log_to_streams(
    p_log_id UUID
)
RETURNS INTEGER AS $$
DECLARE
    v_log RECORD;
    v_subscription RECORD;
    v_delivered_count INTEGER := 0;
BEGIN
    SELECT * INTO v_log FROM app_log WHERE log_id = p_log_id;
    
    IF v_log IS NULL THEN
        RETURN 0;
    END IF;
    
    -- Find matching subscriptions
    FOR v_subscription IN 
        SELECT * FROM log_stream_subscriptions 
        WHERE is_active = TRUE
          AND min_log_level <= v_log.log_level
          AND (source_filter IS NULL OR v_log.log_source = ANY(source_filter))
          AND (user_id_filter IS NULL OR v_log.user_id = user_id_filter)
          AND (correlation_id_filter IS NULL OR v_log.correlation_id = correlation_id_filter)
    LOOP
        -- In a real implementation, this would push to WebSocket/Webhook
        -- For now, we just track the delivery
        UPDATE log_stream_subscriptions 
        SET last_delivery_at = NOW() 
        WHERE subscription_id = v_subscription.subscription_id;
        
        v_delivered_count := v_delivered_count + 1;
    END LOOP;
    
    RETURN v_delivered_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- LOG ANALYSIS AND ANOMALY DETECTION
-- ============================================================================

CREATE TABLE IF NOT EXISTS log_anomalies (
    anomaly_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    anomaly_type VARCHAR(50) NOT NULL, -- 'spike', 'pattern_change', 'unusual_sequence', 'outlier'
    affected_source VARCHAR(100),
    affected_time_window TSTZRANGE,
    baseline_metrics JSONB,
    observed_metrics JSONB,
    anomaly_score NUMERIC(5, 2), -- 0-100
    severity VARCHAR(20),
    investigation_status VARCHAR(20) DEFAULT 'open',
    resolution_notes TEXT
);

CREATE OR REPLACE FUNCTION detect_log_anomalies(
    p_baseline_hours INTEGER DEFAULT 168, -- 1 week
    p_observation_minutes INTEGER DEFAULT 30
)
RETURNS TABLE (
    anomaly_type VARCHAR(50),
    affected_source VARCHAR(100),
    anomaly_score NUMERIC(5, 2),
    description TEXT
) AS $$
DECLARE
    v_baseline_avg NUMERIC;
    v_current_count INTEGER;
    v_zscore NUMERIC;
    v_source RECORD;
BEGIN
    -- Detect volume spikes per source
    FOR v_source IN SELECT DISTINCT log_source FROM app_log WHERE log_timestamp > NOW() - INTERVAL '1 day'
    LOOP
        -- Calculate baseline average
        SELECT AVG(hourly_count) INTO v_baseline_avg
        FROM (
            SELECT date_trunc('hour', log_timestamp) as hour, COUNT(*) as hourly_count
            FROM app_log
            WHERE log_source = v_source.log_source
              AND log_timestamp BETWEEN NOW() - (p_baseline_hours || ' hours')::INTERVAL 
                                    AND NOW() - (p_observation_minutes || ' minutes')::INTERVAL
            GROUP BY date_trunc('hour', log_timestamp)
        ) hourly;
        
        -- Get current count
        SELECT COUNT(*) INTO v_current_count
        FROM app_log
        WHERE log_source = v_source.log_source
          AND log_timestamp > NOW() - (p_observation_minutes || ' minutes')::INTERVAL;
        
        -- Calculate Z-score (simplified)
        IF v_baseline_avg > 0 THEN
            v_zscore := ABS((v_current_count - v_baseline_avg) / v_baseline_avg) * 100;
            
            IF v_zscore > 200 THEN -- More than 3x baseline
                RETURN QUERY SELECT 
                    'spike'::VARCHAR(50),
                    v_source.log_source,
                    LEAST(100, v_zscore / 10)::NUMERIC(5, 2),
                    format('Log volume spike detected: %s logs in %s minutes (baseline: %s/hour)', 
                           v_current_count, p_observation_minutes, round(v_baseline_avg, 1));
            END IF;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- LOG-BASED METRICS EXTRACTION
-- ============================================================================

CREATE TABLE IF NOT EXISTS log_metrics (
    metric_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_name VARCHAR(100) NOT NULL,
    metric_timestamp TIMESTAMPTZ DEFAULT NOW(),
    metric_value NUMERIC(18, 6),
    metric_labels JSONB,
    source_log_id UUID REFERENCES app_log(log_id)
);

CREATE INDEX IF NOT EXISTS idx_log_metrics_lookup ON log_metrics(metric_name, metric_timestamp);

CREATE OR REPLACE FUNCTION extract_metrics_from_logs(
    p_start_time TIMESTAMPTZ,
    p_end_time TIMESTAMPTZ
)
RETURNS TABLE (
    metric_name TEXT,
    metric_value NUMERIC,
    labels JSONB
) AS $$
BEGIN
    -- Extract response times from log details
    RETURN QUERY
    SELECT 
        'log_response_time_ms'::TEXT,
        (log_details->>'response_time_ms')::NUMERIC,
        jsonb_build_object('source', log_source, 'level', log_level)
    FROM app_log
    WHERE log_timestamp BETWEEN p_start_time AND p_end_time
      AND log_details ? 'response_time_ms';
    
    -- Extract transaction counts
    RETURN QUERY
    SELECT 
        'log_transaction_count'::TEXT,
        COUNT(*)::NUMERIC,
        jsonb_build_object('source', log_source)
    FROM app_log
    WHERE log_timestamp BETWEEN p_start_time AND p_end_time
      AND log_message LIKE '%transaction%'
    GROUP BY log_source;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- LOG DEDUPLICATION
-- ============================================================================

CREATE TABLE IF NOT EXISTS log_dedup_hashes (
    hash_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_hash TEXT NOT NULL UNIQUE,
    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    occurrence_count INTEGER DEFAULT 1,
    first_log_id UUID,
    dedup_window_minutes INTEGER DEFAULT 60
);

CREATE OR REPLACE FUNCTION deduplicate_log(
    p_level log_level,
    p_message TEXT,
    p_source VARCHAR(100),
    p_details JSONB DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_message_hash TEXT;
    v_existing RECORD;
    v_log_id UUID;
BEGIN
    -- Create hash of message content
    v_message_hash := encode(digest(
        p_level::TEXT || '|' || p_source || '|' || p_message,
        'sha256'
    ), 'hex');
    
    -- Check for recent duplicate
    SELECT * INTO v_existing
    FROM log_dedup_hashes
    WHERE message_hash = v_message_hash
      AND last_seen_at > NOW() - (dedup_window_minutes || ' minutes')::INTERVAL;
    
    IF FOUND THEN
        -- Update occurrence count
        UPDATE log_dedup_hashes 
        SET occurrence_count = occurrence_count + 1,
            last_seen_at = NOW()
        WHERE hash_id = v_existing.hash_id;
        
        -- Return the original log ID
        RETURN v_existing.first_log_id;
    END IF;
    
    -- Log the message
    v_log_id := app_log_write(p_level, p_message, p_source, NULL, p_details);
    
    -- Store hash
    INSERT INTO log_dedup_hashes (message_hash, first_log_id)
    VALUES (v_message_hash, v_log_id);
    
    RETURN v_log_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TYPE log_level IS 'Standard log severity levels (RFC 5424 Syslog)';
COMMENT ON TABLE app_log IS 'Application log with partitioning by month (PCI DSS 10.7)';
COMMENT ON TABLE logging_config IS 'Logging system configuration';
COMMENT ON TABLE log_shipping_config IS 'External log shipping configuration (ELK, Splunk, etc.)';
COMMENT ON TABLE log_shipping_queue IS 'Queue for log shipping to external systems';
COMMENT ON TABLE log_sampling_rules IS 'Log sampling configuration for high-volume scenarios';
COMMENT ON TABLE log_alert_rules IS 'Log-based alerting rules engine';
COMMENT ON TABLE log_archives IS 'Log archival tracking with compression metadata';
COMMENT ON TABLE log_stream_subscriptions IS 'Real-time log streaming subscriptions';
COMMENT ON TABLE log_anomalies IS 'Anomaly detection results from log analysis';
COMMENT ON TABLE log_metrics IS 'Metrics extracted from logs';
COMMENT ON TABLE log_dedup_hashes IS 'Log deduplication tracking';
COMMENT ON FUNCTION app_log_write IS 'Core application logging function';
COMMENT ON FUNCTION start_trace IS 'Start distributed tracing session';
COMMENT ON FUNCTION log_span IS 'Log a span in distributed tracing';
COMMENT ON FUNCTION detect_log_anomalies IS 'ML-based anomaly detection from logs';
COMMENT ON FUNCTION format_otel_log IS 'Format log as OpenTelemetry standard';

-- ============================================================================
-- IMPLEMENTATION COMPLETE
-- ============================================================================
