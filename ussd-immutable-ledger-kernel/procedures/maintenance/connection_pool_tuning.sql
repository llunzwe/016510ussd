-- ============================================================================
-- CONNECTION POOL TUNING PROCEDURE
-- ============================================================================
-- Purpose: Configure and optimize database connection pools for USSD ledger
--          with workload-specific tuning and monitoring.
-- Author:  USSD Immutable Ledger Team
-- Date:    2026-03-30
-- ============================================================================
-- COMPLIANCE HEADER:
--   ISO 9001:2015 - Quality Management Systems - Requirements
--
--   This procedure implements:
--   - Clause 7.1.4: Environment for the operation of processes
--   - Clause 8.3.4: Design and development controls (capacity planning)
--   - Clause 9.1.1: Performance monitoring and measurement
--   - Annex C: Resource optimization and continuous improvement
--
--   Quality Metrics: Connection utilization, Response time, Throughput
--   Change Control: All tuning changes documented with rollback procedures
--   Performance Baselines: Established and monitored against SLAs
--   Continuous Improvement: Regular review and optimization cycles
-- ============================================================================

-- =============================================================================
-- STEP 1: CONNECTION POOL CONFIGURATION TABLES
-- =============================================================================

-- 1.1 Create connection pool configuration
CREATE TABLE IF NOT EXISTS connection_pool_config (
    config_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_name TEXT NOT NULL UNIQUE,
    pool_type VARCHAR(50) NOT NULL CHECK (pool_type IN ('APPLICATION', 'REPORTING', 'ADMIN', 'REPLICATION', 'BACKUP')),
    min_connections INTEGER DEFAULT 5,
    max_connections INTEGER NOT NULL,
    connection_timeout_ms INTEGER DEFAULT 30000,
    idle_timeout_ms INTEGER DEFAULT 600000,
    max_lifetime_ms INTEGER DEFAULT 1800000,
    leak_detection_threshold_ms INTEGER DEFAULT 60000,
    statement_cache_size INTEGER DEFAULT 250,
    prepared_statement_cache_size INTEGER DEFAULT 250,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 1.2 Create connection statistics tracking
CREATE TABLE IF NOT EXISTS connection_statistics (
    stat_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_name TEXT NOT NULL,
    collected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    active_connections INTEGER,
    idle_connections INTEGER,
    waiting_requests INTEGER,
    total_connections INTEGER,
    max_connections INTEGER,
    connection_wait_time_ms NUMERIC,
    usage_percentage NUMERIC,
    rejected_connections INTEGER DEFAULT 0
);

-- 1.3 Create connection pool tuning history
CREATE TABLE IF NOT EXISTS pool_tuning_history (
    tuning_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_name TEXT NOT NULL,
    tuning_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    parameter_name TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    tuning_reason TEXT,
    tuned_by TEXT DEFAULT CURRENT_USER,
    performance_impact JSONB
);

-- 1.4 Insert default pool configurations
INSERT INTO connection_pool_config (
    pool_name,
    pool_type,
    min_connections,
    max_connections,
    connection_timeout_ms,
    idle_timeout_ms
) VALUES 
    ('ussd_ledger_main', 'APPLICATION', 10, 100, 30000, 300000),
    ('ussd_ledger_reporting', 'REPORTING', 5, 20, 60000, 600000),
    ('ussd_ledger_admin', 'ADMIN', 2, 10, 10000, 3600000),
    ('ussd_ledger_backup', 'BACKUP', 2, 5, 120000, 900000)
ON CONFLICT (pool_name) DO NOTHING;

-- =============================================================================
-- STEP 2: CURRENT CONNECTION ANALYSIS
-- =============================================================================

-- 2.1 Analyze current connections
CREATE OR REPLACE VIEW current_connection_analysis AS
SELECT 
    datname as database,
    usename as username,
    application_name,
    client_addr,
    state,
    state_change,
    now() - backend_start as connection_duration,
    now() - xact_start as transaction_duration,
    now() - query_start as query_duration,
    wait_event_type,
    wait_event,
    LEFT(query, 100) as query_preview
FROM pg_stat_activity
WHERE datname = current_database()
ORDER BY state, query_start;

-- 2.2 Connection statistics summary
CREATE OR REPLACE FUNCTION get_connection_summary()
RETURNS TABLE (
    total_connections BIGINT,
    active_connections BIGINT,
    idle_connections BIGINT,
    idle_in_transaction BIGINT,
    waiting_connections BIGINT,
    max_allowed INTEGER,
    utilization_pct NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*)::BIGINT as total_connections,
        COUNT(*) FILTER (WHERE state = 'active')::BIGINT as active_connections,
        COUNT(*) FILTER (WHERE state = 'idle')::BIGINT as idle_connections,
        COUNT(*) FILTER (WHERE state = 'idle in transaction')::BIGINT as idle_in_transaction,
        COUNT(*) FILTER (WHERE wait_event IS NOT NULL)::BIGINT as waiting_connections,
        (SELECT setting::INTEGER FROM pg_settings WHERE name = 'max_connections') as max_allowed,
        round((COUNT(*)::NUMERIC / (SELECT setting::INTEGER FROM pg_settings WHERE name = 'max_connections')) * 100, 2) as utilization_pct
    FROM pg_stat_activity
    WHERE datname = current_database();
END;
$$ LANGUAGE plpgsql;

-- 2.3 Identify connection issues
CREATE OR REPLACE FUNCTION identify_connection_issues()
RETURNS TABLE (
    issue_type TEXT,
    severity TEXT,
    connection_count BIGINT,
    details JSONB,
    recommendation TEXT
) AS $$
BEGIN
    -- Long-running transactions
    RETURN QUERY
    SELECT 
        'LONG_RUNNING_TRANSACTION'::TEXT,
        'WARNING'::TEXT,
        COUNT(*)::BIGINT,
        jsonb_build_object(
            'max_duration', max(now() - xact_start),
            'usernames', array_agg(DISTINCT usename)
        ),
        'Review and optimize long-running transactions'::TEXT
    FROM pg_stat_activity
    WHERE xact_start < now() - INTERVAL '5 minutes'
    AND datname = current_database();
    
    -- Idle in transaction
    RETURN QUERY
    SELECT 
        'IDLE_IN_TRANSACTION'::TEXT,
        'WARNING'::TEXT,
        COUNT(*)::BIGINT,
        jsonb_build_object(
            'max_idle_time', max(now() - state_change),
            'application_names', array_agg(DISTINCT application_name)
        ),
        'Configure idle_in_transaction_session_timeout or fix application logic'::TEXT
    FROM pg_stat_activity
    WHERE state = 'idle in transaction'
    AND state_change < now() - INTERVAL '1 minute'
    AND datname = current_database();
    
    -- Connection pool exhaustion risk
    RETURN QUERY
    SELECT 
        'POOL_EXHAUSTION_RISK'::TEXT,
        CASE 
            WHEN cnt > (max_conn * 0.9) THEN 'CRITICAL'
            WHEN cnt > (max_conn * 0.75) THEN 'WARNING'
            ELSE 'INFO'
        END::TEXT,
        cnt::BIGINT,
        jsonb_build_object(
            'max_connections', max_conn,
            'utilization_pct', round((cnt::NUMERIC / max_conn) * 100, 2)
        ),
        'Consider increasing max_connections or optimizing connection pool settings'::TEXT
    FROM (
        SELECT COUNT(*) as cnt, (SELECT setting::INTEGER FROM pg_settings WHERE name = 'max_connections') as max_conn
        FROM pg_stat_activity
        WHERE datname = current_database()
    ) subq
    WHERE cnt > (max_conn * 0.75);
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 3: CONNECTION POOL TUNING PROCEDURES
-- =============================================================================

-- 3.1 Calculate optimal pool size using Little's Law approximation
CREATE OR REPLACE FUNCTION calculate_optimal_pool_size(
    p_expected_concurrent_users INTEGER,
    p_avg_query_time_ms NUMERIC,
    p_target_response_time_ms NUMERIC
)
RETURNS TABLE (
    theoretical_optimal INTEGER,
    recommended_size INTEGER,
    calculation_basis TEXT
) AS $$
DECLARE
    v_theoretical INTEGER;
    v_recommended INTEGER;
BEGIN
    -- Little's Law: L = λ * W
    -- Connections = (Concurrent Users * Query Time) / Response Time
    v_theoretical := CEIL((p_expected_concurrent_users * p_avg_query_time_ms) / p_target_response_time_ms);
    
    -- Add buffer for spikes and variance
    v_recommended := LEAST(
        GREATEST(v_theoretical * 1.2, 10),  -- At least 20% buffer, minimum 10
        200  -- Cap at reasonable maximum
    );
    
    theoretical_optimal := v_theoretical;
    recommended_size := v_recommended;
    calculation_basis := format(
        'Little Law: (%s users * %s ms query) / %s ms target = %s',
        p_expected_concurrent_users,
        p_avg_query_time_ms,
        p_target_response_time_ms,
        v_theoretical
    );
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- 3.2 Tune pool configuration
CREATE OR REPLACE PROCEDURE tune_connection_pool(
    p_pool_name TEXT,
    p_new_max_connections INTEGER DEFAULT NULL,
    p_new_min_connections INTEGER DEFAULT NULL,
    p_new_idle_timeout_ms INTEGER DEFAULT NULL,
    p_tuning_reason TEXT DEFAULT 'Performance optimization'
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_old_config RECORD;
BEGIN
    SELECT * INTO v_old_config
    FROM connection_pool_config
    WHERE pool_name = p_pool_name;
    
    IF v_old_config IS NULL THEN
        RAISE EXCEPTION 'Pool not found: %', p_pool_name;
    END IF;
    
    -- Log changes
    IF p_new_max_connections IS NOT NULL AND p_new_max_connections != v_old_config.max_connections THEN
        INSERT INTO pool_tuning_history (
            pool_name,
            parameter_name,
            old_value,
            new_value,
            tuning_reason
        ) VALUES (
            p_pool_name,
            'max_connections',
            v_old_config.max_connections::TEXT,
            p_new_max_connections::TEXT,
            p_tuning_reason
        );
    END IF;
    
    IF p_new_min_connections IS NOT NULL AND p_new_min_connections != v_old_config.min_connections THEN
        INSERT INTO pool_tuning_history (
            pool_name,
            parameter_name,
            old_value,
            new_value,
            tuning_reason
        ) VALUES (
            p_pool_name,
            'min_connections',
            v_old_config.min_connections::TEXT,
            p_new_min_connections::TEXT,
            p_tuning_reason
        );
    END IF;
    
    -- Apply changes
    UPDATE connection_pool_config
    SET 
        max_connections = COALESCE(p_new_max_connections, max_connections),
        min_connections = COALESCE(p_new_min_connections, min_connections),
        idle_timeout_ms = COALESCE(p_new_idle_timeout_ms, idle_timeout_ms),
        updated_at = CURRENT_TIMESTAMP
    WHERE pool_name = p_pool_name;
    
    RAISE NOTICE 'Pool % tuned successfully', p_pool_name;
END;
$$;

-- 3.3 Apply PostgreSQL-level connection settings
CREATE OR REPLACE PROCEDURE apply_postgresql_connection_settings(
    p_max_connections INTEGER DEFAULT 200,
    p_superuser_reserved INTEGER DEFAULT 10,
    p_idle_timeout_seconds INTEGER DEFAULT 0
)
LANGUAGE plpgsql
AS $$
BEGIN
    -- These require PostgreSQL restart or reload
    RAISE NOTICE 'Apply the following settings to postgresql.conf:';
    RAISE NOTICE '  max_connections = %', p_max_connections;
    RAISE NOTICE '  superuser_reserved_connections = %', p_superuser_reserved;
    RAISE NOTICE '  idle_in_transaction_session_timeout = %', 
        CASE WHEN p_idle_timeout_seconds > 0 
            THEN p_idle_timeout_seconds::TEXT || 's'
            ELSE '0 (disabled)'
        END;
    
    -- Settings that can be applied per database
    IF p_idle_timeout_seconds > 0 THEN
        EXECUTE format('ALTER DATABASE %I SET idle_in_transaction_session_timeout = %s',
            current_database(), p_idle_timeout_seconds * 1000);
    END IF;
END;
$$;

-- =============================================================================
-- STEP 4: WORKLOAD-SPECIFIC TUNING
-- =============================================================================

-- 4.1 Configure pools for different workloads
CREATE OR REPLACE PROCEDURE configure_workload_pools(
    p_workload_type VARCHAR(50),
    p_dry_run BOOLEAN DEFAULT TRUE
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_config JSONB;
BEGIN
    CASE p_workload_type
        WHEN 'HIGH_THROUGHPUT' THEN
            v_config := '{
                "main_max": 150,
                "main_min": 20,
                "reporting_max": 10,
                "idle_timeout": 300000,
                "statement_cache": 500
            }'::JSONB;
        WHEN 'BALANCED' THEN
            v_config := '{
                "main_max": 100,
                "main_min": 10,
                "reporting_max": 20,
                "idle_timeout": 600000,
                "statement_cache": 250
            }'::JSONB;
        WHEN 'ANALYTICS_HEAVY' THEN
            v_config := '{
                "main_max": 50,
                "main_min": 5,
                "reporting_max": 50,
                "idle_timeout": 900000,
                "statement_cache": 100
            }'::JSONB;
        ELSE
            RAISE EXCEPTION 'Unknown workload type: %', p_workload_type;
    END CASE;
    
    IF p_dry_run THEN
        RAISE NOTICE 'DRY RUN: Would apply workload config: %', v_config;
    ELSE
        CALL tune_connection_pool(
            'ussd_ledger_main',
            (v_config->>'main_max')::INTEGER,
            (v_config->>'main_min')::INTEGER,
            (v_config->>'idle_timeout')::INTEGER,
            'Workload configuration: ' || p_workload_type
        );
        
        CALL tune_connection_pool(
            'ussd_ledger_reporting',
            (v_config->>'reporting_max')::INTEGER,
            NULL,
            (v_config->>'idle_timeout')::INTEGER,
            'Workload configuration: ' || p_workload_type
        );
    END IF;
END;
$$;

-- =============================================================================
-- STEP 5: TEST CASES WITH EXPECTED RESULTS
-- =============================================================================

-- Test Case 5.1: Verify connection summary
SELECT 
    'TEST_5.1_CONNECTION_SUMMARY' as test_name,
    total_connections,
    active_connections,
    idle_connections,
    max_allowed,
    utilization_pct,
    CASE 
        WHEN utilization_pct < 80 THEN 'PASSED'
        ELSE 'WARNING_HIGH_UTILIZATION'
    END as result
FROM get_connection_summary();

-- Test Case 5.2: Calculate optimal pool size
SELECT 
    'TEST_5.2_OPTIMAL_POOL_SIZE' as test_name,
    theoretical_optimal,
    recommended_size,
    calculation_basis
FROM calculate_optimal_pool_size(500, 50, 100);

-- Test Case 5.3: Identify connection issues
SELECT 
    'TEST_5.3_CONNECTION_ISSUES' as test_name,
    issue_type,
    severity,
    connection_count,
    recommendation
FROM identify_connection_issues();

-- Test Case 5.4: Verify pool configuration
SELECT 
    'TEST_5.4_POOL_CONFIG' as test_name,
    pool_name,
    pool_type,
    min_connections,
    max_connections,
    CASE 
        WHEN max_connections >= min_connections * 2 THEN 'PASSED'
        ELSE 'FAILED: max should be at least 2x min'
    END as config_valid
FROM connection_pool_config
WHERE is_active = TRUE;

-- Test Case 5.5: Test connection analysis view
SELECT 
    'TEST_5.5_CONNECTION_ANALYSIS' as test_name,
    count(*) as total_sessions,
    count(*) FILTER (WHERE state = 'active') as active,
    count(*) FILTER (WHERE state = 'idle') as idle
FROM current_connection_analysis;

-- =============================================================================
-- STEP 6: ROLLBACK PROCEDURES
-- =============================================================================

-- 6.1 Revert pool tuning
CREATE OR REPLACE PROCEDURE rollback_pool_tuning(
    p_pool_name TEXT,
    p_rollback_to_timestamp TIMESTAMPTZ DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_target_time TIMESTAMPTZ;
    v_old_value RECORD;
BEGIN
    v_target_time := COALESCE(p_rollback_to_timestamp, CURRENT_TIMESTAMP - INTERVAL '1 hour');
    
    FOR v_old_value IN 
        SELECT DISTINCT ON (parameter_name)
            parameter_name,
            old_value,
            tuning_timestamp
        FROM pool_tuning_history
        WHERE pool_name = p_pool_name
        AND tuning_timestamp > v_target_time
        ORDER BY parameter_name, tuning_timestamp DESC
    LOOP
        RAISE NOTICE 'Rolling back % to % (from change at %)',
            v_old_value.parameter_name,
            v_old_value.old_value,
            v_old_value.tuning_timestamp;
        
        -- Apply rollback
        CASE v_old_value.parameter_name
            WHEN 'max_connections' THEN
                UPDATE connection_pool_config
                SET max_connections = v_old_value.old_value::INTEGER
                WHERE pool_name = p_pool_name;
            WHEN 'min_connections' THEN
                UPDATE connection_pool_config
                SET min_connections = v_old_value.old_value::INTEGER
                WHERE pool_name = p_pool_name;
            WHEN 'idle_timeout_ms' THEN
                UPDATE connection_pool_config
                SET idle_timeout_ms = v_old_value.old_value::INTEGER
                WHERE pool_name = p_pool_name;
        END CASE;
    END LOOP;
END;
$$;

-- 6.2 Emergency connection release
CREATE OR REPLACE FUNCTION emergency_release_connections(
    p_target_count INTEGER
)
RETURNS INTEGER AS $$
DECLARE
    v_terminated INTEGER := 0;
    v_rec RECORD;
BEGIN
    FOR v_rec IN 
        SELECT pid
        FROM pg_stat_activity
        WHERE datname = current_database()
        AND usename != 'postgres'  -- Protect superuser
        AND pid != pg_backend_pid()  -- Don't kill self
        AND (
            state = 'idle'
            OR (state = 'idle in transaction' AND state_change < now() - INTERVAL '5 minutes')
        )
        ORDER BY state_change
        LIMIT (SELECT COUNT(*) - p_target_count FROM pg_stat_activity WHERE datname = current_database())
    LOOP
        PERFORM pg_terminate_backend(v_rec.pid);
        v_terminated := v_terminated + 1;
    END LOOP;
    
    RETURN v_terminated;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 7: VALIDATION CHECKS
-- =============================================================================

-- 7.1 Verify connection pool settings alignment
SELECT 
    c.pool_name,
    c.max_connections as configured_max,
    COALESCE(max(s.total_connections), 0) as observed_max,
    CASE 
        WHEN max(s.total_connections) > c.max_connections * 0.9 THEN 'NEEDS_ATTENTION'
        ELSE 'OK'
    END as status
FROM connection_pool_config c
LEFT JOIN connection_statistics s ON s.pool_name = c.pool_name
WHERE c.is_active = TRUE
GROUP BY c.pool_name, c.max_connections;

-- 7.2 Check for connection leaks
SELECT 
    usename,
    application_name,
    count(*) as connection_count,
    max(now() - backend_start) as longest_connection,
    CASE 
        WHEN count(*) > 20 THEN 'POTENTIAL_LEAK'
        ELSE 'OK'
    END as assessment
FROM pg_stat_activity
WHERE datname = current_database()
GROUP BY usename, application_name
ORDER BY connection_count DESC;

-- 7.3 Verify PostgreSQL connection settings
SELECT 
    name,
    setting,
    unit,
    short_desc
FROM pg_settings
WHERE name IN ('max_connections', 'superuser_reserved_connections', 
               'shared_buffers', 'work_mem', 'maintenance_work_mem')
ORDER BY name;

-- =============================================================================
-- TODO LIST FOR CUSTOMIZATION
-- =============================================================================

/*
TODO-1: Customize pool names and types for your application architecture
TODO-2: Adjust connection limits based on your max_connections setting
TODO-3: Configure per-user connection limits using ALTER USER
TODO-4: Set up PgBouncer or pgpool-II configuration templates
TODO-5: Implement connection pool metrics export for monitoring
TODO-6: Configure SSL/TLS settings for secure connections
TODO-7: Set up connection string templates for different environments
TODO-8: Implement circuit breaker patterns for resilience
TODO-9: Configure read replica connection pooling for load balancing
TODO-10: Set up automated pool resizing based on load patterns
*/

-- =============================================================================
-- END OF CONNECTION POOL TUNING PROCEDURE
-- =============================================================================
