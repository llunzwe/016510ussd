-- =============================================================================
-- USSD KERNEL CORE SCHEMA - MONITORING & ALERTING
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    071_core_monitoring_alerting.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      core
-- DESCRIPTION: Real-time monitoring, alerting, and operational dashboards for
--              production USSD fintech operations.
-- =============================================================================

/*
================================================================================
MONITORING FRAMEWORK
================================================================================

This migration implements a comprehensive monitoring and alerting system:

Metrics Categories:
├── Performance: Response times, throughput, queue depths
├── Business: Transaction volumes, success rates, user activity
├── Security: Failed logins, suspicious patterns, access violations
├── Compliance: Audit trail health, key rotation status, data retention
└── Operational: Error rates, system health, resource utilization

Alert Levels:
├── CRITICAL: Immediate action required (page on-call)
├── HIGH: Urgent attention needed (notify team lead)
├── MEDIUM: Monitor closely (add to daily report)
├── LOW: Informational (weekly summary)
└── INFO: Operational insights (dashboard only)

================================================================================
SLA DEFINITIONS
================================================================================

Transaction Processing:
- P50 latency: < 200ms
- P95 latency: < 500ms  
- P99 latency: < 1000ms
- Availability: 99.99% (52 minutes downtime/year)

USSD Session:
- Session timeout: 3 minutes
- Response time: < 2 seconds per menu
- Concurrent sessions: 10,000+

Data Integrity:
- Hash chain verification: 100%
- Audit trail completeness: 100%
- Backup RPO: < 1 hour
- Backup RTO: < 4 hours

================================================================================
*/

-- =============================================================================
-- ALERT RULES
-- =============================================================================

CREATE TABLE core.alert_rules (
    rule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Rule identification
    rule_name VARCHAR(100) NOT NULL,
    rule_description TEXT,
    
    -- Category
    alert_category VARCHAR(30) NOT NULL 
        CHECK (alert_category IN ('PERFORMANCE', 'SECURITY', 'BUSINESS', 'COMPLIANCE', 'OPERATIONAL')),
    
    -- Severity
    severity VARCHAR(20) NOT NULL 
        CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    
    -- Condition
    metric_name VARCHAR(50) NOT NULL,
    metric_source VARCHAR(50),  -- 'TRANSACTION_LOG', 'AUDIT_TRAIL', 'SESSION_STATE', etc.
    condition_operator VARCHAR(10) NOT NULL 
        CHECK (condition_operator IN ('>', '<', '>=', '<=', '=', '!=', 'IN', 'NOT IN')),
    threshold_value NUMERIC,
    threshold_string TEXT,
    
    -- Aggregation
    lookback_window INTERVAL DEFAULT INTERVAL '5 minutes',
    aggregation_function VARCHAR(20) DEFAULT 'COUNT' 
        CHECK (aggregation_function IN ('COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'PERCENTILE')),
    
    -- Throttling
    cooldown_period INTERVAL DEFAULT INTERVAL '5 minutes',
    max_alerts_per_hour INTEGER DEFAULT 10,
    
    -- Notification
    notification_channels VARCHAR(20)[] DEFAULT ARRAY['LOG'],  -- LOG, EMAIL, SMS, WEBHOOK, PAGERDUTY, SLACK
    notification_recipients TEXT[],  -- Email addresses, phone numbers, webhook URLs
    escalation_rule_id UUID,  -- Reference to escalation rule
    
    -- Status
    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT core.precise_now(),
    created_by UUID,
    last_triggered_at TIMESTAMPTZ,
    trigger_count INTEGER DEFAULT 0
);

-- =============================================================================
-- ALERT INSTANCES
-- =============================================================================

CREATE TABLE core.alert_instances (
    alert_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID REFERENCES core.alert_rules(rule_id),
    
    -- Alert details
    alert_status VARCHAR(20) DEFAULT 'ACTIVE' 
        CHECK (alert_status IN ('ACTIVE', 'ACKNOWLEDGED', 'RESOLVED', 'SUPPRESSSED')),
    severity VARCHAR(20),
    
    -- Trigger context
    triggered_at TIMESTAMPTZ DEFAULT core.precise_now(),
    triggered_value NUMERIC,
    triggered_value_string TEXT,
    trigger_context JSONB,  -- Additional context at time of trigger
    
    -- Acknowledgment
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by UUID,
    acknowledgment_note TEXT,
    
    -- Resolution
    resolved_at TIMESTAMPTZ,
    resolved_by UUID,
    resolution_note TEXT,
    resolution_action TEXT,  -- What was done to resolve
    
    -- Escalation
    escalated_at TIMESTAMPTZ,
    escalated_to UUID,
    
    -- Notification tracking
    notifications_sent JSONB DEFAULT '[]'::jsonb,  -- Array of {channel, sent_at, status}
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- METRICS SNAPSHOTS
-- =============================================================================

CREATE TABLE core.metrics_snapshots (
    snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_time TIMESTAMPTZ DEFAULT core.precise_now(),
    
    -- Performance metrics
    txn_per_second NUMERIC,
    avg_response_time_ms NUMERIC,
    p95_response_time_ms NUMERIC,
    p99_response_time_ms NUMERIC,
    error_rate_pct NUMERIC,
    
    -- Business metrics
    active_users INTEGER,
    session_count INTEGER,
    pending_transactions INTEGER,
    queued_operations INTEGER,
    
    -- Security metrics
    failed_login_attempts INTEGER,
    suspicious_transactions INTEGER,
    blocked_ips INTEGER,
    
    -- System metrics
    db_connection_pool_usage NUMERIC,
    disk_usage_pct NUMERIC,
    memory_usage_pct NUMERIC,
    
    -- Custom metrics
    custom_metrics JSONB
);

-- =============================================================================
-- INCIDENT MANAGEMENT
-- =============================================================================

CREATE TABLE core.incidents (
    incident_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_number VARCHAR(20) UNIQUE NOT NULL,  -- INC-YYYY-NNNN
    
    -- Classification
    incident_type VARCHAR(30) NOT NULL
        CHECK (incident_type IN ('OUTAGE', 'DEGRADATION', 'SECURITY_BREACH', 'DATA_LOSS', 'COMPLIANCE_VIOLATION')),
    severity VARCHAR(20) NOT NULL,
    
    -- Status workflow
    status VARCHAR(20) DEFAULT 'DETECTED' 
        CHECK (status IN ('DETECTED', 'ACKNOWLEDGED', 'INVESTIGATING', 'MITIGATING', 'RESOLVED', 'CLOSED')),
    
    -- Description
    title VARCHAR(200) NOT NULL,
    description TEXT,
    root_cause TEXT,
    
    -- Timeline
    detected_at TIMESTAMPTZ DEFAULT core.precise_now(),
    acknowledged_at TIMESTAMPTZ,
    mitigation_started_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    
    -- Impact
    affected_systems TEXT[],
    affected_users_count INTEGER,
    affected_transactions_count INTEGER,
    estimated_financial_impact NUMERIC,
    
    -- Resolution
    resolution_summary TEXT,
    preventive_measures TEXT[],
    lessons_learned TEXT,
    
    -- Ownership
    detected_by UUID,
    incident_commander UUID,
    responders UUID[],
    
    -- Related alerts
    related_alerts UUID[],
    
    -- Post-incident review
    postmortem_required BOOLEAN DEFAULT FALSE,
    postmortem_completed_at TIMESTAMPTZ,
    postmortem_document_url TEXT,
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- INDEXES
-- =============================================================================

CREATE INDEX idx_alert_rules_category ON core.alert_rules(alert_category, severity) WHERE is_enabled = TRUE;
CREATE INDEX idx_alert_rules_metric ON core.alert_rules(metric_name, is_enabled);

CREATE INDEX idx_alert_instances_rule ON core.alert_instances(rule_id, alert_status);
CREATE INDEX idx_alert_instances_time ON core.alert_instances(triggered_at DESC);
CREATE INDEX idx_alert_instances_active ON core.alert_instances(alert_status, severity) WHERE alert_status = 'ACTIVE';

CREATE INDEX idx_metrics_snapshots_time ON core.metrics_snapshots(snapshot_time DESC);

CREATE INDEX idx_incidents_status ON core.incidents(status, severity);
CREATE INDEX idx_incidents_time ON core.incidents(detected_at DESC);

-- =============================================================================
-- IMMUTABILITY TRIGGERS
-- =============================================================================

CREATE TRIGGER trg_alert_instances_immutable
    BEFORE UPDATE ON core.alert_instances
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update_except_status();

CREATE TRIGGER trg_metrics_snapshots_prevent_update
    BEFORE UPDATE ON core.metrics_snapshots
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_incidents_immutable
    BEFORE UPDATE ON core.incidents
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update_except_status();

-- =============================================================================
-- ALERT EVALUATION FUNCTION
-- =============================================================================

CREATE OR REPLACE FUNCTION core.evaluate_alert_rules()
RETURNS TABLE (
    rule_id UUID,
    rule_name VARCHAR,
    triggered BOOLEAN,
    current_value NUMERIC,
    message TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_rule RECORD;
    v_current_value NUMERIC;
    v_triggered BOOLEAN;
    v_query TEXT;
BEGIN
    FOR v_rule IN 
        SELECT * FROM core.alert_rules 
        WHERE is_enabled = TRUE
        AND (last_triggered_at IS NULL OR last_triggered_at + cooldown_period < core.precise_now())
    LOOP
        -- Build and execute metric query based on rule
        v_query := format(
            'SELECT %s(%s) FROM %s WHERE %s',
            v_rule.aggregation_function,
            CASE 
                WHEN v_rule.metric_source = 'TRANSACTION_LOG' THEN 'transaction_id'
                WHEN v_rule.metric_source = 'AUDIT_TRAIL' THEN 'audit_id'
                ELSE '1'
            END,
            CASE 
                WHEN v_rule.metric_source = 'TRANSACTION_LOG' THEN 'core.transaction_log'
                WHEN v_rule.metric_source = 'AUDIT_TRAIL' THEN 'core.audit_trail'
                WHEN v_rule.metric_source = 'SESSION_STATE' THEN 'ussd_gateway.session_state'
                ELSE 'core.metrics_snapshots'
            END,
            CASE 
                WHEN v_rule.lookback_window IS NOT NULL 
                THEN format('committed_at > NOW() - INTERVAL ''%s''', v_rule.lookback_window)
                ELSE '1=1'
            END
        );
        
        BEGIN
            EXECUTE v_query INTO v_current_value;
        EXCEPTION
            WHEN OTHERS THEN
                v_current_value := 0;
        END;
        
        -- Evaluate condition
        v_triggered := CASE v_rule.condition_operator
            WHEN '>' THEN v_current_value > v_rule.threshold_value
            WHEN '<' THEN v_current_value < v_rule.threshold_value
            WHEN '>=' THEN v_current_value >= v_rule.threshold_value
            WHEN '<=' THEN v_current_value <= v_rule.threshold_value
            WHEN '=' THEN v_current_value = v_rule.threshold_value
            ELSE FALSE
        END;
        
        -- Create alert if triggered
        IF v_triggered THEN
            INSERT INTO core.alert_instances (
                rule_id, severity, triggered_value, trigger_context
            ) VALUES (
                v_rule.rule_id,
                v_rule.severity,
                v_current_value,
                jsonb_build_object('metric_source', v_rule.metric_source)
            );
            
            -- Update rule
            UPDATE core.alert_rules SET
                last_triggered_at = core.precise_now(),
                trigger_count = trigger_count + 1
            WHERE alert_rules.rule_id = v_rule.rule_id;
        END IF;
        
        rule_id := v_rule.rule_id;
        rule_name := v_rule.rule_name;
        triggered := v_triggered;
        current_value := v_current_value;
        message := CASE WHEN v_triggered THEN 'Alert triggered' ELSE 'Within threshold' END;
        RETURN NEXT;
    END LOOP;
END;
$$;

-- =============================================================================
-- METRICS COLLECTION FUNCTION
-- =============================================================================

CREATE OR REPLACE FUNCTION core.collect_metrics_snapshot()
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_snapshot_id UUID;
    v_txn_count INTEGER;
    v_avg_response NUMERIC;
    v_p95_response NUMERIC;
    v_error_count INTEGER;
BEGIN
    -- Calculate metrics from transaction log (last 5 minutes)
    SELECT 
        COUNT(*),
        AVG(processing_duration_ms),
        PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY processing_duration_ms)
    INTO v_txn_count, v_avg_response, v_p95_response
    FROM core.transaction_log
    WHERE committed_at > core.precise_now() - INTERVAL '5 minutes';
    
    -- Error count
    SELECT COUNT(*) INTO v_error_count
    FROM core.transaction_log
    WHERE committed_at > core.precise_now() - INTERVAL '5 minutes'
    AND status = 'failed';
    
    -- Insert snapshot
    INSERT INTO core.metrics_snapshots (
        txn_per_second,
        avg_response_time_ms,
        p95_response_time_ms,
        error_rate_pct,
        custom_metrics
    ) VALUES (
        v_txn_count::NUMERIC / 300,  -- per second
        v_avg_response,
        v_p95_response,
        CASE WHEN v_txn_count > 0 THEN (v_error_count::NUMERIC / v_txn_count * 100) ELSE 0 END,
        jsonb_build_object(
            'error_count_5min', v_error_count,
            'transaction_count_5min', v_txn_count
        )
    )
    RETURNING snapshot_id INTO v_snapshot_id;
    
    RETURN v_snapshot_id;
END;
$$;

-- =============================================================================
-- INCIDENT MANAGEMENT FUNCTIONS
-- =============================================================================

CREATE OR REPLACE FUNCTION core.create_incident(
    p_title VARCHAR,
    p_description TEXT,
    p_incident_type VARCHAR,
    p_severity VARCHAR,
    p_detected_by UUID DEFAULT NULL,
    p_affected_systems TEXT[] DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_incident_id UUID;
    v_incident_number VARCHAR(20);
BEGIN
    -- Generate incident number
    v_incident_number := 'INC-' || TO_CHAR(NOW(), 'YYYY') || '-' || 
                         LPAD((SELECT COUNT(*) + 1 FROM core.incidents 
                               WHERE incident_number LIKE 'INC-' || TO_CHAR(NOW(), 'YYYY') || '-%')::TEXT, 4, '0');
    
    INSERT INTO core.incidents (
        incident_number, title, description, incident_type, severity,
        detected_by, affected_systems, postmortem_required
    ) VALUES (
        v_incident_number, p_title, p_description, p_incident_type, p_severity,
        p_detected_by, p_affected_systems, (p_severity IN ('CRITICAL', 'HIGH'))
    )
    RETURNING incident_id INTO v_incident_id;
    
    -- Link any active alerts
    UPDATE core.alert_instances SET
        alert_status = 'ACKNOWLEDGED',
        acknowledged_at = core.precise_now()
    WHERE alert_status = 'ACTIVE' AND severity = p_severity;
    
    RETURN v_incident_id;
END;
$$;

CREATE OR REPLACE FUNCTION core.update_incident_status(
    p_incident_id UUID,
    p_new_status VARCHAR,
    p_updated_by UUID DEFAULT NULL,
    p_note TEXT DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.incidents SET
        status = p_new_status,
        acknowledged_at = CASE WHEN p_new_status = 'ACKNOWLEDGED' THEN core.precise_now() ELSE acknowledged_at END,
        mitigation_started_at = CASE WHEN p_new_status = 'MITIGATING' THEN core.precise_now() ELSE mitigation_started_at END,
        resolved_at = CASE WHEN p_new_status = 'RESOLVED' THEN core.precise_now() ELSE resolved_at END,
        closed_at = CASE WHEN p_new_status = 'CLOSED' THEN core.precise_now() ELSE closed_at END,
        incident_commander = COALESCE(incident_commander, p_updated_by)
    WHERE incident_id = p_incident_id;
    
    RETURN FOUND;
END;
$$;

-- =============================================================================
-- OPERATIONAL DASHBOARD VIEWS
-- =============================================================================

-- Real-time system health
CREATE OR REPLACE VIEW core.system_health AS
SELECT 
    'Transactions (last 5min)' as metric,
    COUNT(*)::TEXT as value,
    CASE 
        WHEN COUNT(*) < 10 THEN 'WARNING'
        ELSE 'OK'
    END as status
FROM core.transaction_log
WHERE committed_at > core.precise_now() - INTERVAL '5 minutes'
UNION ALL
SELECT 
    'Average Response Time (ms)',
    ROUND(AVG(processing_duration_ms), 2)::TEXT,
    CASE 
        WHEN AVG(processing_duration_ms) > 1000 THEN 'CRITICAL'
        WHEN AVG(processing_duration_ms) > 500 THEN 'WARNING'
        ELSE 'OK'
    END
FROM core.transaction_log
WHERE committed_at > core.precise_now() - INTERVAL '5 minutes'
UNION ALL
SELECT 
    'Error Rate (%)',
    ROUND(
        COUNT(*) FILTER (WHERE status = 'failed')::NUMERIC / 
        NULLIF(COUNT(*), 0) * 100, 
        2
    )::TEXT,
    CASE 
        WHEN COUNT(*) FILTER (WHERE status = 'failed')::NUMERIC / NULLIF(COUNT(*), 0) * 100 > 5 THEN 'CRITICAL'
        WHEN COUNT(*) FILTER (WHERE status = 'failed')::NUMERIC / NULLIF(COUNT(*), 0) * 100 > 1 THEN 'WARNING'
        ELSE 'OK'
    END
FROM core.transaction_log
WHERE committed_at > core.precise_now() - INTERVAL '5 minutes'
UNION ALL
SELECT 
    'Active Alerts',
    COUNT(*)::TEXT,
    CASE 
        WHEN COUNT(*) FILTER (WHERE severity = 'CRITICAL') > 0 THEN 'CRITICAL'
        WHEN COUNT(*) FILTER (WHERE severity = 'HIGH') > 0 THEN 'WARNING'
        ELSE 'OK'
    END
FROM core.alert_instances
WHERE alert_status = 'ACTIVE';

-- Active incidents dashboard
CREATE OR REPLACE VIEW core.active_incidents AS
SELECT 
    i.incident_number,
    i.title,
    i.severity,
    i.status,
    i.detected_at,
    EXTRACT(EPOCH FROM (core.precise_now() - i.detected_at))/60 as age_minutes,
    i.affected_systems,
    i.incident_commander
FROM core.incidents i
WHERE i.status NOT IN ('RESOLVED', 'CLOSED')
ORDER BY 
    CASE i.severity 
        WHEN 'CRITICAL' THEN 1 
        WHEN 'HIGH' THEN 2 
        WHEN 'MEDIUM' THEN 3 
        ELSE 4 
    END,
    i.detected_at;

-- =============================================================================
-- SEED ALERT RULES
-- =============================================================================

INSERT INTO core.alert_rules (
    rule_name, rule_description, alert_category, severity,
    metric_name, metric_source, condition_operator, threshold_value,
    lookback_window, notification_channels
)
VALUES 
    ('High Transaction Error Rate', 'Transaction failure rate exceeds 5%', 'BUSINESS', 'HIGH',
     'error_rate', 'TRANSACTION_LOG', '>', 5, INTERVAL '5 minutes', ARRAY['LOG', 'EMAIL']),
    
    ('Low Transaction Volume', 'Unusually low transaction volume', 'BUSINESS', 'MEDIUM',
     'transaction_count', 'TRANSACTION_LOG', '<', 10, INTERVAL '5 minutes', ARRAY['LOG']),
    
    ('Slow Response Time', 'P95 response time exceeds 1 second', 'PERFORMANCE', 'HIGH',
     'response_time_p95', 'TRANSACTION_LOG', '>', 1000, INTERVAL '10 minutes', ARRAY['LOG', 'EMAIL']),
    
    ('Security: Failed Logins', 'Multiple failed login attempts', 'SECURITY', 'MEDIUM',
     'failed_logins', 'AUDIT_TRAIL', '>', 5, INTERVAL '5 minutes', ARRAY['LOG', 'EMAIL']),
    
    ('Compliance: Audit Gap', 'Audit trail gap detected', 'COMPLIANCE', 'CRITICAL',
     'audit_sequence_gap', 'AUDIT_TRAIL', '>', 0, INTERVAL '1 minute', ARRAY['LOG', 'EMAIL', 'SMS'])
ON CONFLICT DO NOTHING;

-- =============================================================================
-- EMERGENCY ADMIN FUNCTIONS
-- =============================================================================

-- Emergency function to verify hash chain (read-only, safe)
CREATE OR REPLACE FUNCTION core.emergency_verify_hash_chain(
    p_start_transaction_id BIGINT DEFAULT NULL,
    p_end_transaction_id BIGINT DEFAULT NULL
)
RETURNS TABLE (
    transaction_id BIGINT,
    is_valid BOOLEAN,
    expected_hash VARCHAR(64),
    actual_hash VARCHAR(64),
    error_message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_record RECORD;
    v_previous_hash VARCHAR(64);
BEGIN
    v_previous_hash := 'GENESIS';
    
    FOR v_record IN 
        SELECT t.transaction_id, t.previous_hash, t.current_hash, t.payload_hash
        FROM core.transaction_log t
        WHERE (p_start_transaction_id IS NULL OR t.transaction_id >= p_start_transaction_id)
        AND (p_end_transaction_id IS NULL OR t.transaction_id <= p_end_transaction_id)
        ORDER BY t.transaction_id
    LOOP
        transaction_id := v_record.transaction_id;
        
        -- Check chain link
        IF v_record.previous_hash IS DISTINCT FROM v_previous_hash THEN
            is_valid := FALSE;
            expected_hash := v_previous_hash;
            actual_hash := v_record.previous_hash;
            error_message := 'Previous hash mismatch in chain';
            RETURN NEXT;
        ELSE
            is_valid := TRUE;
            expected_hash := v_record.current_hash;
            actual_hash := v_record.current_hash;
            error_message := NULL;
            RETURN NEXT;
        END IF;
        
        v_previous_hash := v_record.current_hash;
    END LOOP;
END;
$$;

-- Emergency function to get system status
CREATE OR REPLACE FUNCTION core.emergency_system_status()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_result JSONB;
BEGIN
    SELECT jsonb_build_object(
        'database', current_database(),
        'timestamp', NOW(),
        'session_user', session_user,
        'current_user', current_user,
        'transaction_log_count', (SELECT COUNT(*) FROM core.transaction_log),
        'blocks_count', (SELECT COUNT(*) FROM core.blocks),
        'pending_transactions', (SELECT COUNT(*) FROM core.transaction_log WHERE status = 'pending'),
        'failed_transactions', (SELECT COUNT(*) FROM core.transaction_log WHERE status = 'failed'),
        'active_applications', (SELECT COUNT(*) FROM app.applications WHERE status = 'active'),
        'immutability_checks', (SELECT jsonb_agg(jsonb_build_object('check', check_name, 'status', check_status)) FROM core.final_immutability_check()),
        'recent_errors', (SELECT jsonb_agg(jsonb_build_object('time', event_timestamp, 'type', event_type)) FROM core.security_audit_log WHERE severity = 'CRITICAL' AND event_timestamp > NOW() - INTERVAL '24 hours' LIMIT 5)
    ) INTO v_result;
    
    RETURN v_result;
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE core.alert_rules IS 
    'Configuration for automated monitoring and alerting';
COMMENT ON TABLE core.alert_instances IS 
    'Triggered alert instances with lifecycle tracking';
COMMENT ON TABLE core.incidents IS 
    'Incident management for outages and security events';
COMMENT ON VIEW core.system_health IS 
    'Real-time system health indicators';
COMMENT ON FUNCTION core.emergency_verify_hash_chain() IS 
    'Emergency function to verify hash chain integrity (read-only, safe)';
COMMENT ON FUNCTION core.emergency_system_status() IS 
    'Emergency function to get complete system status in JSON format';

-- =============================================================================
-- END OF FILE
-- =============================================================================
