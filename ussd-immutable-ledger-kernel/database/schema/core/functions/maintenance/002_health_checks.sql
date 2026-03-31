-- =============================================================================
-- USSD KERNEL CORE SCHEMA - MAINTENANCE FUNCTIONS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    002_health_checks.sql
-- SCHEMA:      core
-- CATEGORY:    Maintenance Functions
-- DESCRIPTION: Database health monitoring including integrity checks,
--              performance metrics, and alerting triggers.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Health monitoring
├── A.16.1 Management of information security incidents - Alerting
└── A.16.2 Assessment and decision - Health assessment

ISO/IEC 27031:2025 (Business Continuity ICT Readiness)
├── Health metrics: Availability monitoring
├── Alerting: Automated incident creation
└── Recovery: Health-guided recovery

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. HEALTH CHECKS
   - Integrity verification
   - Performance metrics
   - Resource utilization
   - Error rate monitoring

2. ALERTING
   - Threshold-based alerts
   - Trend analysis
   - Anomaly detection

3. REPORTING
   - Health dashboards
   - Compliance reports
   - Trend analysis

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

MONITORING SECURITY:
- Secure metric collection
- Alert authentication
- Audit logging

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

CHECK OPTIMIZATION:
- Lightweight checks
- Sampling for large tables
- Incremental checks

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- HEALTH_CHECK_PASSED
- HEALTH_CHECK_FAILED
- ALERT_TRIGGERED

RETENTION: 2 years
================================================================================
*/

-- =============================================================================
-- TYPE: Health check result
-- =============================================================================
CREATE TYPE core.health_check_result AS (
    check_name TEXT,
    check_category TEXT,
    status TEXT,  -- 'PASS', 'WARN', 'FAIL', 'ERROR'
    check_timestamp TIMESTAMPTZ,
    execution_time_ms INTEGER,
    details JSONB,
    recommendation TEXT
);

-- =============================================================================
-- HELPER FUNCTION: Check hash chain integrity
-- Description: Verifies the cryptographic hash chain in transaction_log
-- =============================================================================
CREATE OR REPLACE FUNCTION core.check_hash_chain_integrity(
    p_sample_size INTEGER DEFAULT 10000
)
RETURNS core.health_check_result
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_result core.health_check_result;
    v_start_time TIMESTAMPTZ;
    v_broken_count INTEGER;
    v_total_checked INTEGER;
    v_first_broken_id BIGINT;
BEGIN
    v_start_time := clock_timestamp();
    
    v_result.check_name := 'hash_chain_integrity';
    v_result.check_category := 'integrity';
    v_result.check_timestamp := NOW();
    
    -- Check for hash chain breaks
    WITH chain_check AS (
        SELECT 
            transaction_id,
            transaction_hash,
            previous_hash,
            LAG(transaction_hash) OVER (ORDER BY chain_sequence) AS expected_previous_hash
        FROM core.transaction_log
        WHERE chain_sequence IS NOT NULL
        ORDER BY chain_sequence
        LIMIT p_sample_size
    )
    SELECT 
        COUNT(*),
        MIN(transaction_id) FILTER (WHERE previous_hash IS DISTINCT FROM expected_previous_hash)
    INTO v_broken_count, v_first_broken_id
    FROM chain_check
    WHERE previous_hash IS DISTINCT FROM expected_previous_hash;
    
    v_total_checked := LEAST(p_sample_size, (SELECT COUNT(*) FROM core.transaction_log));
    
    IF v_broken_count > 0 THEN
        v_result.status := 'FAIL';
        v_result.details := jsonb_build_object(
            'broken_chains', v_broken_count,
            'first_broken_transaction_id', v_first_broken_id,
            'sample_size', v_total_checked
        );
        v_result.recommendation := 'CRITICAL: Hash chain integrity violation detected. Initiate incident response.';
    ELSE
        v_result.status := 'PASS';
        v_result.details := jsonb_build_object(
            'checked_transactions', v_total_checked,
            'broken_chains', 0
        );
        v_result.recommendation := 'Hash chain integrity verified.';
    END IF;
    
    v_result.execution_time_ms := EXTRACT(MILLISECOND FROM (clock_timestamp() - v_start_time))::INTEGER;
    
    RETURN v_result;
END;
$$;

-- =============================================================================
-- HELPER FUNCTION: Check partition health
-- Description: Verifies partition coverage and status
-- =============================================================================
CREATE OR REPLACE FUNCTION core.check_partition_health()
RETURNS core.health_check_result
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_result core.health_check_result;
    v_start_time TIMESTAMPTZ;
    v_partitioned_tables INTEGER;
    v_total_partitions INTEGER;
    v_missing_partitions INTEGER;
    v_partitions_needing_attention JSONB;
BEGIN
    v_start_time := clock_timestamp();
    
    v_result.check_name := 'partition_health';
    v_result.check_category := 'maintenance';
    v_result.check_timestamp := NOW();
    
    -- Count partitioned tables
    SELECT COUNT(*) INTO v_partitioned_tables
    FROM pg_partitioned_table pt
    JOIN pg_class c ON pt.partrelid = c.oid
    JOIN pg_namespace n ON c.relnamespace = n.oid
    WHERE n.nspname = 'core';
    
    -- Count total partitions
    SELECT COUNT(*) INTO v_total_partitions
    FROM pg_inherits i
    JOIN pg_class c ON i.inhparent = c.oid
    JOIN pg_namespace n ON c.relnamespace = n.oid
    WHERE n.nspname = 'core';
    
    -- Check for missing future partitions
    SELECT COUNT(*) INTO v_missing_partitions
    FROM generate_series(0, 2) AS months_ahead
    WHERE NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = 'core'
        AND c.relname LIKE 'transaction_log_' || TO_CHAR(CURRENT_DATE + (months_ahead || ' months')::INTERVAL, 'YYYY_MM')
    );
    
    v_partitions_needing_attention := jsonb_build_array();
    
    IF v_missing_partitions > 0 THEN
        v_partitions_needing_attention := v_partitions_needing_attention || jsonb_build_object(
            'issue', 'missing_future_partitions',
            'count', v_missing_partitions
        );
    END IF;
    
    IF v_partitions_needing_attention = '[]'::jsonb THEN
        v_result.status := 'PASS';
        v_result.recommendation := 'All partitions healthy.';
    ELSE
        v_result.status := 'WARN';
        v_result.recommendation := 'Some partitions need attention. Run core.manage_partitions().';
    END IF;
    
    v_result.details := jsonb_build_object(
        'partitioned_tables', v_partitioned_tables,
        'total_partitions', v_total_partitions,
        'missing_future_partitions', v_missing_partitions,
        'attention_needed', v_partitions_needing_attention
    );
    
    v_result.execution_time_ms := EXTRACT(MILLISECOND FROM (clock_timestamp() - v_start_time))::INTEGER;
    
    RETURN v_result;
END;
$$;

-- =============================================================================
-- HELPER FUNCTION: Check index health
-- Description: Identifies invalid or bloated indexes
-- =============================================================================
CREATE OR REPLACE FUNCTION core.check_index_health(
    p_bloat_threshold_percent NUMERIC DEFAULT 30
)
RETURNS core.health_check_result
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_result core.health_check_result;
    v_start_time TIMESTAMPTZ;
    v_invalid_count INTEGER;
    v_bloated_indexes JSONB;
BEGIN
    v_start_time := clock_timestamp();
    
    v_result.check_name := 'index_health';
    v_result.check_category := 'performance';
    v_result.check_timestamp := NOW();
    
    -- Count invalid indexes
    SELECT COUNT(*) INTO v_invalid_count
    FROM pg_index i
    JOIN pg_class c ON i.indrelid = c.oid
    JOIN pg_namespace n ON c.relnamespace = n.oid
    WHERE NOT i.indisvalid
    AND n.nspname = 'core';
    
    -- Check for bloated indexes (simplified - actual bloat detection requires pgstattuple)
    SELECT jsonb_agg(jsonb_build_object(
        'table', t.relname,
        'index', i.relname,
        'estimated_bloat', 'unknown - run pgstattuple for accurate measurement'
    ))
    INTO v_bloated_indexes
    FROM pg_index ix
    JOIN pg_class i ON ix.indexrelid = i.oid
    JOIN pg_class t ON ix.indrelid = t.oid
    JOIN pg_namespace n ON t.relnamespace = n.oid
    WHERE n.nspname = 'core'
    AND i.relpages > 1000;  -- Only check larger indexes
    
    IF v_invalid_count = 0 AND v_bloated_indexes IS NULL THEN
        v_result.status := 'PASS';
        v_result.recommendation := 'All indexes healthy.';
    ELSIF v_invalid_count > 0 THEN
        v_result.status := 'FAIL';
        v_result.recommendation := format('%s invalid indexes found. Rebuild required.', v_invalid_count);
    ELSE
        v_result.status := 'WARN';
        v_result.recommendation := 'Some indexes may be bloated. Consider REINDEX during maintenance window.';
    END IF;
    
    v_result.details := jsonb_build_object(
        'invalid_indexes', v_invalid_count,
        'large_indexes_checked', (SELECT COUNT(*) FROM pg_class c 
                                  JOIN pg_namespace n ON c.relnamespace = n.oid 
                                  WHERE n.nspname = 'core' AND c.relpages > 1000)
    );
    
    v_result.execution_time_ms := EXTRACT(MILLISECOND FROM (clock_timestamp() - v_start_time))::INTEGER;
    
    RETURN v_result;
END;
$$;

-- =============================================================================
-- HELPER FUNCTION: Check replication lag
-- Description: Monitors streaming replication lag
-- =============================================================================
CREATE OR REPLACE FUNCTION core.check_replication_lag(
    p_max_lag_bytes BIGINT DEFAULT 100000000,  -- 100MB
    p_max_lag_seconds INTEGER DEFAULT 300       -- 5 minutes
)
RETURNS core.health_check_result
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_result core.health_check_result;
    v_start_time TIMESTAMPTZ;
    v_replication_info JSONB;
    v_max_lag_bytes BIGINT;
    v_max_lag_seconds INTEGER;
BEGIN
    v_start_time := clock_timestamp();
    
    v_result.check_name := 'replication_lag';
    v_result.check_category := 'availability';
    v_result.check_timestamp := NOW();
    
    -- Get replication info if available
    BEGIN
        SELECT jsonb_agg(jsonb_build_object(
            'client_addr', client_addr,
            'state', state,
            'sent_lsn', sent_lsn,
            'write_lsn', write_lsn,
            'flush_lsn', flush_lsn,
            'replay_lsn', replay_lsn,
            'write_lag', write_lag,
            'flush_lag', flush_lag,
            'replay_lag', replay_lag,
            'pg_wal_lsn_diff_sent', pg_wal_lsn_diff(sent_lsn, replay_lsn)
        ))
        INTO v_replication_info
        FROM pg_stat_replication;
        
        IF v_replication_info IS NULL THEN
            v_result.status := 'PASS';
            v_result.details := jsonb_build_object('message', 'No active replication');
            v_result.recommendation := 'No replication configured or no active connections.';
        ELSE
            -- Check for lag issues
            SELECT MAX((d->>'pg_wal_lsn_diff_sent')::BIGINT),
                   MAX(EXTRACT(EPOCH FROM (d->>'replay_lag')::INTERVAL))::INTEGER
            INTO v_max_lag_bytes, v_max_lag_seconds
            FROM jsonb_array_elements(v_replication_info) AS d;
            
            IF v_max_lag_bytes > p_max_lag_bytes OR COALESCE(v_max_lag_seconds, 0) > p_max_lag_seconds THEN
                v_result.status := 'WARN';
                v_result.recommendation := 'Replication lag detected. Monitor closely.';
            ELSE
                v_result.status := 'PASS';
                v_result.recommendation := 'Replication healthy.';
            END IF;
            
            v_result.details := jsonb_build_object(
                'replicas', jsonb_array_length(v_replication_info),
                'max_lag_bytes', v_max_lag_bytes,
                'max_lag_seconds', v_max_lag_seconds,
                'replica_details', v_replication_info
            );
        END IF;
        
    EXCEPTION WHEN undefined_table THEN
        v_result.status := 'ERROR';
        v_result.details := jsonb_build_object('message', 'Cannot access pg_stat_replication');
        v_result.recommendation := 'Check permissions for pg_stat_replication.';
    END;
    
    v_result.execution_time_ms := EXTRACT(MILLISECOND FROM (clock_timestamp() - v_start_time))::INTEGER;
    
    RETURN v_result;
END;
$$;

-- =============================================================================
-- HELPER FUNCTION: Check table bloat
-- Description: Estimates table bloat levels
-- =============================================================================
CREATE OR REPLACE FUNCTION core.check_table_bloat(
    p_bloat_threshold_percent NUMERIC DEFAULT 50
)
RETURNS core.health_check_result
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_result core.health_check_result;
    v_start_time TIMESTAMPTZ;
    v_bloated_tables JSONB;
BEGIN
    v_start_time := clock_timestamp();
    
    v_result.check_name := 'table_bloat';
    v_result.check_category := 'maintenance';
    v_result.check_timestamp := NOW();
    
    -- Simplified bloat check using pg_stat_user_tables
    -- For accurate bloat detection, use pgstattuple extension
    SELECT jsonb_agg(jsonb_build_object(
        'table', relname,
        'n_live_tup', n_live_tup,
        'n_dead_tup', n_dead_tup,
        'dead_tuple_ratio', CASE WHEN n_live_tup + n_dead_tup > 0 
            THEN (n_dead_tup::NUMERIC / (n_live_tup + n_dead_tup)) * 100 
            ELSE 0 END,
        'last_vacuum', last_vacuum,
        'last_autovacuum', last_autovacuum
    ))
    INTO v_bloated_tables
    FROM pg_stat_user_tables
    WHERE schemaname = 'core'
    AND n_live_tup > 1000  -- Focus on larger tables
    AND n_dead_tup > n_live_tup * (p_bloat_threshold_percent / 100.0);
    
    IF v_bloated_tables IS NULL THEN
        v_result.status := 'PASS';
        v_result.details := jsonb_build_object('message', 'No significant table bloat detected');
        v_result.recommendation := 'Tables look healthy. Continue regular VACUUM.';
    ELSE
        v_result.status := 'WARN';
        v_result.details := jsonb_build_object('bloated_tables', v_bloated_tables);
        v_result.recommendation := 'Some tables have dead tuple ratios above threshold. Consider VACUUM.';
    END IF;
    
    v_result.execution_time_ms := EXTRACT(MILLISECOND FROM (clock_timestamp() - v_start_time))::INTEGER;
    
    RETURN v_result;
END;
$$;

-- =============================================================================
-- HELPER FUNCTION: Check connection health
-- Description: Monitors connection pool and limits
-- =============================================================================
CREATE OR REPLACE FUNCTION core.check_connection_health(
    p_max_connection_percent NUMERIC DEFAULT 80
)
RETURNS core.health_check_result
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_result core.health_check_result;
    v_start_time TIMESTAMPTZ;
    v_max_connections INTEGER;
    v_current_connections INTEGER;
    v_connection_percent NUMERIC;
BEGIN
    v_start_time := clock_timestamp();
    
    v_result.check_name := 'connection_health';
    v_result.check_category := 'availability';
    v_result.check_timestamp := NOW();
    
    -- Get connection stats
    SELECT setting::INTEGER INTO v_max_connections
    FROM pg_settings WHERE name = 'max_connections';
    
    SELECT COUNT(*) INTO v_current_connections
    FROM pg_stat_activity;
    
    v_connection_percent := (v_current_connections::NUMERIC / v_max_connections) * 100;
    
    IF v_connection_percent > p_max_connection_percent THEN
        v_result.status := 'WARN';
        v_result.recommendation := format('Connection usage at %.1f%%. Consider increasing max_connections or optimizing connection pooling.', v_connection_percent);
    ELSE
        v_result.status := 'PASS';
        v_result.recommendation := 'Connection usage normal.';
    END IF;
    
    v_result.details := jsonb_build_object(
        'max_connections', v_max_connections,
        'current_connections', v_current_connections,
        'connection_percent', v_connection_percent,
        'active_queries', (SELECT COUNT(*) FROM pg_stat_activity WHERE state = 'active'),
        'idle_queries', (SELECT COUNT(*) FROM pg_stat_activity WHERE state = 'idle'),
        'waiting_queries', (SELECT COUNT(*) FROM pg_stat_activity WHERE wait_event_type IS NOT NULL)
    );
    
    v_result.execution_time_ms := EXTRACT(MILLISECOND FROM (clock_timestamp() - v_start_time))::INTEGER;
    
    RETURN v_result;
END;
$$;

-- =============================================================================
-- MAIN FUNCTION: Run comprehensive health checks
-- Description: Comprehensive health check suite
-- PRIORITY: HIGH
-- =============================================================================
CREATE OR REPLACE FUNCTION core.run_health_checks(
    p_include_checks TEXT[] DEFAULT ARRAY['all'],
    p_raise_alerts BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (
    check_name TEXT,
    check_category TEXT,
    status TEXT,
    check_timestamp TIMESTAMPTZ,
    execution_time_ms INTEGER,
    details JSONB,
    recommendation TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_result core.health_check_result;
    v_overall_status TEXT := 'PASS';
    v_fail_count INTEGER := 0;
    v_warn_count INTEGER := 0;
BEGIN
    -- Hash chain integrity check
    IF 'all' = ANY(p_include_checks) OR 'integrity' = ANY(p_include_checks) OR 'hash_chain' = ANY(p_include_checks) THEN
        v_result := core.check_hash_chain_integrity();
        check_name := v_result.check_name;
        check_category := v_result.check_category;
        status := v_result.status;
        check_timestamp := v_result.check_timestamp;
        execution_time_ms := v_result.execution_time_ms;
        details := v_result.details;
        recommendation := v_result.recommendation;
        
        IF status = 'FAIL' THEN v_fail_count := v_fail_count + 1; v_overall_status := 'FAIL'; 
        ELSIF status = 'WARN' THEN v_warn_count := v_warn_count + 1; 
            IF v_overall_status = 'PASS' THEN v_overall_status := 'WARN'; END IF;
        END IF;
        
        RETURN NEXT;
    END IF;
    
    -- Partition health check
    IF 'all' = ANY(p_include_checks) OR 'maintenance' = ANY(p_include_checks) OR 'partitions' = ANY(p_include_checks) THEN
        v_result := core.check_partition_health();
        check_name := v_result.check_name;
        check_category := v_result.check_category;
        status := v_result.status;
        check_timestamp := v_result.check_timestamp;
        execution_time_ms := v_result.execution_time_ms;
        details := v_result.details;
        recommendation := v_result.recommendation;
        
        IF status = 'FAIL' THEN v_fail_count := v_fail_count + 1; v_overall_status := 'FAIL'; 
        ELSIF status = 'WARN' THEN v_warn_count := v_warn_count + 1; 
            IF v_overall_status = 'PASS' THEN v_overall_status := 'WARN'; END IF;
        END IF;
        
        RETURN NEXT;
    END IF;
    
    -- Index health check
    IF 'all' = ANY(p_include_checks) OR 'performance' = ANY(p_include_checks) OR 'indexes' = ANY(p_include_checks) THEN
        v_result := core.check_index_health();
        check_name := v_result.check_name;
        check_category := v_result.check_category;
        status := v_result.status;
        check_timestamp := v_result.check_timestamp;
        execution_time_ms := v_result.execution_time_ms;
        details := v_result.details;
        recommendation := v_result.recommendation;
        
        IF status = 'FAIL' THEN v_fail_count := v_fail_count + 1; v_overall_status := 'FAIL'; 
        ELSIF status = 'WARN' THEN v_warn_count := v_warn_count + 1; 
            IF v_overall_status = 'PASS' THEN v_overall_status := 'WARN'; END IF;
        END IF;
        
        RETURN NEXT;
    END IF;
    
    -- Replication lag check
    IF 'all' = ANY(p_include_checks) OR 'availability' = ANY(p_include_checks) OR 'replication' = ANY(p_include_checks) THEN
        v_result := core.check_replication_lag();
        check_name := v_result.check_name;
        check_category := v_result.check_category;
        status := v_result.status;
        check_timestamp := v_result.check_timestamp;
        execution_time_ms := v_result.execution_time_ms;
        details := v_result.details;
        recommendation := v_result.recommendation;
        
        IF status = 'FAIL' THEN v_fail_count := v_fail_count + 1; v_overall_status := 'FAIL'; 
        ELSIF status = 'WARN' THEN v_warn_count := v_warn_count + 1; 
            IF v_overall_status = 'PASS' THEN v_overall_status := 'WARN'; END IF;
        END IF;
        
        RETURN NEXT;
    END IF;
    
    -- Table bloat check
    IF 'all' = ANY(p_include_checks) OR 'maintenance' = ANY(p_include_checks) OR 'bloat' = ANY(p_include_checks) THEN
        v_result := core.check_table_bloat();
        check_name := v_result.check_name;
        check_category := v_result.check_category;
        status := v_result.status;
        check_timestamp := v_result.check_timestamp;
        execution_time_ms := v_result.execution_time_ms;
        details := v_result.details;
        recommendation := v_result.recommendation;
        
        IF status = 'FAIL' THEN v_fail_count := v_fail_count + 1; v_overall_status := 'FAIL'; 
        ELSIF status = 'WARN' THEN v_warn_count := v_warn_count + 1; 
            IF v_overall_status = 'PASS' THEN v_overall_status := 'WARN'; END IF;
        END IF;
        
        RETURN NEXT;
    END IF;
    
    -- Connection health check
    IF 'all' = ANY(p_include_checks) OR 'availability' = ANY(p_include_checks) OR 'connections' = ANY(p_include_checks) THEN
        v_result := core.check_connection_health();
        check_name := v_result.check_name;
        check_category := v_result.check_category;
        status := v_result.status;
        check_timestamp := v_result.check_timestamp;
        execution_time_ms := v_result.execution_time_ms;
        details := v_result.details;
        recommendation := v_result.recommendation;
        
        IF status = 'FAIL' THEN v_fail_count := v_fail_count + 1; v_overall_status := 'FAIL'; 
        ELSIF status = 'WARN' THEN v_warn_count := v_warn_count + 1; 
            IF v_overall_status = 'PASS' THEN v_overall_status := 'WARN'; END IF;
        END IF;
        
        RETURN NEXT;
    END IF;
    
    -- Log overall health check results
    IF p_raise_alerts AND (v_fail_count > 0 OR v_warn_count > 0) THEN
        INSERT INTO core.audit_trail (
            event_type,
            event_description,
            event_timestamp,
            metadata
        ) VALUES (
            CASE WHEN v_fail_count > 0 THEN 'HEALTH_CHECK_FAILED' ELSE 'HEALTH_CHECK_WARNING' END,
            format('Health check completed with %s failures and %s warnings', v_fail_count, v_warn_count),
            NOW(),
            jsonb_build_object(
                'overall_status', v_overall_status,
                'fail_count', v_fail_count,
                'warn_count', v_warn_count
            )
        );
    END IF;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Get health check summary
-- Description: Returns a summary of health check results
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_health_summary()
RETURNS TABLE (
    overall_status TEXT,
    checks_passed INTEGER,
    checks_warned INTEGER,
    checks_failed INTEGER,
    last_check_time TIMESTAMPTZ,
    critical_issues TEXT[]
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_results core.health_check_result[];
    v_result core.health_check_result;
    v_passed INTEGER := 0;
    v_warned INTEGER := 0;
    v_failed INTEGER := 0;
    v_overall TEXT := 'PASS';
    v_critical TEXT[] := ARRAY[]::TEXT[];
BEGIN
    -- Run all health checks and collect results
    FOR v_result IN SELECT * FROM core.run_health_checks(p_raise_alerts => FALSE)
    LOOP
        IF v_result.status = 'PASS' THEN
            v_passed := v_passed + 1;
        ELSIF v_result.status = 'WARN' THEN
            v_warned := v_warned + 1;
            IF v_overall = 'PASS' THEN v_overall := 'WARN'; END IF;
        ELSIF v_result.status = 'FAIL' THEN
            v_failed := v_failed + 1;
            v_overall := 'FAIL';
            v_critical := array_append(v_critical, v_result.check_name);
        END IF;
    END LOOP;
    
    overall_status := v_overall;
    checks_passed := v_passed;
    checks_warned := v_warned;
    checks_failed := v_failed;
    last_check_time := NOW();
    critical_issues := v_critical;
    
    RETURN NEXT;
END;
$$;

-- =============================================================================
-- MIGRATION CHECKLIST:
-- □ Create run_health_checks function
-- □ Test each health check
-- □ Set up alerting
-- □ Schedule regular checks
================================================================================

-- =============================================================================
-- END OF FILE
-- =============================================================================
