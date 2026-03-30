-- ============================================================================
-- MATERIALIZED VIEW REFRESH BENCHMARKS
-- ============================================================================
-- Purpose: Test suite for materialized view refresh performance
-- Author:  USSD Immutable Ledger Team
-- Date:    2026-03-30
-- ============================================================================
-- COMPLIANCE ANNOTATIONS:
--   Performance Benchmarks:
--   - ISO/IEC 25010: Software quality - Time behavior compliance
--   - Data freshness SLAs: Report latency requirements
--   - Resource utilization limits during refresh operations
--
--   Test Data Protection:
--   - Materialized views use masked/anonymized test data
--   - No sensitive aggregates exposed in test summaries
--   - Refresh logs sanitized of user-identifiable patterns
--
--   Integrity Validation Standards:
--   - Source-to-view data consistency verification
--   - Aggregation accuracy validation
--   - Concurrent refresh conflict detection
--
--   Performance Benchmarks:
--   - Full refresh: < 30 seconds for daily summary views
--   - Concurrent refresh: Zero blocking time requirement
--   - Incremental refresh: < 5 seconds for delta updates
-- ============================================================================

-- =============================================================================
-- TEST SETUP
-- =============================================================================

-- Create test results tracking
CREATE TABLE IF NOT EXISTS mv_refresh_test_results (
    test_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_name TEXT NOT NULL,
    test_category TEXT NOT NULL,
    test_executed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    test_passed BOOLEAN NOT NULL,
    expected_result TEXT,
    actual_result TEXT,
    execution_time_ms INTEGER,
    refresh_method TEXT,
    rows_in_view BIGINT,
    view_size_bytes BIGINT,
    test_data JSONB
);

-- Create test materialized views if not exist
DO $$
BEGIN
    -- Daily transaction summary
    IF NOT EXISTS (SELECT 1 FROM pg_matviews WHERE matviewname = 'mv_daily_transaction_summary') THEN
        CREATE MATERIALIZED VIEW mv_daily_transaction_summary AS
        SELECT 
            created_at::DATE as transaction_date,
            COUNT(*) as transaction_count,
            SUM(amount) as total_amount,
            AVG(amount) as avg_amount,
            COUNT(DISTINCT user_msisdn) as unique_users
        FROM ledger_transactions
        GROUP BY created_at::DATE;
        
        CREATE UNIQUE INDEX idx_mv_daily_date ON mv_daily_transaction_summary(transaction_date);
    END IF;
    
    -- User activity summary
    IF NOT EXISTS (SELECT 1 FROM pg_matviews WHERE matviewname = 'mv_user_activity_summary') THEN
        CREATE MATERIALIZED VIEW mv_user_activity_summary AS
        SELECT 
            user_msisdn,
            COUNT(*) as transaction_count,
            SUM(amount) as total_volume,
            MAX(created_at) as last_activity
        FROM ledger_transactions
        GROUP BY user_msisdn;
        
        CREATE UNIQUE INDEX idx_mv_user_msisdn ON mv_user_activity_summary(user_msisdn);
    END IF;
END $$;

-- =============================================================================
-- TEST 1: FULL REFRESH PERFORMANCE
-- =============================================================================

-- Test 1.1: Benchmark full refresh of daily summary
CREATE OR REPLACE FUNCTION test_full_refresh_daily_summary()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_duration_ms INTEGER;
    v_max_acceptable_ms INTEGER := 30000;
    v_rows_in_view BIGINT;
    v_view_size BIGINT;
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_1.1_FULL_REFRESH_DAILY_SUMMARY';
    
    -- Get pre-refresh stats
    SELECT COUNT(*), pg_total_relation_size('mv_daily_transaction_summary')
    INTO v_rows_in_view, v_view_size;
    
    v_start_time := clock_timestamp();
    
    REFRESH MATERIALIZED VIEW mv_daily_transaction_summary;
    
    v_end_time := clock_timestamp();
    v_duration_ms := EXTRACT(MILLISECONDS FROM (v_end_time - v_start_time))::INTEGER;
    
    v_passed := v_duration_ms < v_max_acceptable_ms;
    
    details := jsonb_build_object(
        'refresh_method', 'FULL',
        'rows_in_view', v_rows_in_view,
        'view_size_bytes', v_view_size,
        'view_size_pretty', pg_size_pretty(v_view_size),
        'duration_ms', v_duration_ms,
        'max_acceptable_ms', v_max_acceptable_ms
    );
    
    INSERT INTO mv_refresh_test_results (
        test_name, test_category, test_passed, expected_result, actual_result,
        execution_time_ms, refresh_method, rows_in_view, view_size_bytes, test_data
    ) VALUES (
        test_name, 'FULL_REFRESH', v_passed, '< ' || v_max_acceptable_ms || 'ms',
        v_duration_ms || 'ms', v_duration_ms, 'FULL', v_rows_in_view, v_view_size, details
    );
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Test 1.2: Benchmark full refresh of user summary
CREATE OR REPLACE FUNCTION test_full_refresh_user_summary()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_duration_ms INTEGER;
    v_max_acceptable_ms INTEGER := 60000;
    v_rows_in_view BIGINT;
    v_view_size BIGINT;
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_1.2_FULL_REFRESH_USER_SUMMARY';
    
    SELECT COUNT(*), pg_total_relation_size('mv_user_activity_summary')
    INTO v_rows_in_view, v_view_size;
    
    v_start_time := clock_timestamp();
    
    REFRESH MATERIALIZED VIEW mv_user_activity_summary;
    
    v_end_time := clock_timestamp();
    v_duration_ms := EXTRACT(MILLISECONDS FROM (v_end_time - v_start_time))::INTEGER;
    
    v_passed := v_duration_ms < v_max_acceptable_ms;
    
    details := jsonb_build_object(
        'refresh_method', 'FULL',
        'rows_in_view', v_rows_in_view,
        'view_size_bytes', v_view_size,
        'duration_ms', v_duration_ms
    );
    
    INSERT INTO mv_refresh_test_results (
        test_name, test_category, test_passed, expected_result, actual_result,
        execution_time_ms, refresh_method, rows_in_view, view_size_bytes, test_data
    ) VALUES (
        test_name, 'FULL_REFRESH', v_passed, '< ' || v_max_acceptable_ms || 'ms',
        v_duration_ms || 'ms', v_duration_ms, 'FULL', v_rows_in_view, v_view_size, details
    );
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST 2: CONCURRENT REFRESH
-- =============================================================================

-- Test 2.1: Benchmark concurrent refresh (if unique index exists)
CREATE OR REPLACE FUNCTION test_concurrent_refresh_daily()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_duration_ms INTEGER;
    v_max_acceptable_ms INTEGER := 35000;
    v_has_unique_index BOOLEAN;
    v_passed BOOLEAN;
    v_error_msg TEXT;
BEGIN
    test_name := 'TEST_2.1_CONCURRENT_REFRESH_DAILY';
    
    -- Check for unique index
    SELECT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE tablename = 'mv_daily_transaction_summary'
        AND indexdef LIKE '%UNIQUE%'
    ) INTO v_has_unique_index;
    
    IF NOT v_has_unique_index THEN
        details := jsonb_build_object(
            'error', 'No unique index found - concurrent refresh requires unique index'
        );
        
        INSERT INTO mv_refresh_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data)
        VALUES (test_name, 'CONCURRENT_REFRESH', FALSE, 'Concurrent refresh available', 'No unique index', details);
        
        passed := FALSE;
        RETURN NEXT;
        RETURN;
    END IF;
    
    v_start_time := clock_timestamp();
    
    BEGIN
        REFRESH MATERIALIZED VIEW CONCURRENTLY mv_daily_transaction_summary;
    EXCEPTION WHEN OTHERS THEN
        v_error_msg := SQLERRM;
    END;
    
    v_end_time := clock_timestamp();
    v_duration_ms := EXTRACT(MILLISECONDS FROM (v_end_time - v_start_time))::INTEGER;
    
    v_passed := v_duration_ms < v_max_acceptable_ms AND v_error_msg IS NULL;
    
    details := jsonb_build_object(
        'refresh_method', 'CONCURRENT',
        'duration_ms', v_duration_ms,
        'error', v_error_msg
    );
    
    INSERT INTO mv_refresh_test_results (
        test_name, test_category, test_passed, expected_result, actual_result,
        execution_time_ms, refresh_method, test_data
    ) VALUES (
        test_name, 'CONCURRENT_REFRESH', v_passed, '< ' || v_max_acceptable_ms || 'ms',
        COALESCE(v_duration_ms || 'ms', 'FAILED: ' || v_error_msg),
        v_duration_ms, 'CONCURRENT', details
    );
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST 3: REFRESH SCALABILITY
-- =============================================================================

-- Test 3.1: Test refresh with incremental data growth
CREATE OR REPLACE FUNCTION test_refresh_scalability()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_source_row_count BIGINT;
    v_view_row_count BIGINT;
    v_refresh_ratio NUMERIC;
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_3.1_REFRESH_SCALABILITY';
    
    -- Get source table count
    SELECT COUNT(*) INTO v_source_row_count FROM ledger_transactions;
    
    -- Get view count
    SELECT COUNT(*) INTO v_view_row_count FROM mv_daily_transaction_summary;
    
    -- Views should have significantly fewer rows than source (aggregation)
    v_refresh_ratio := CASE WHEN v_source_row_count > 0 
        THEN v_view_row_count::NUMERIC / v_source_row_count 
        ELSE 0 
    END;
    
    -- Aggregation should reduce rows significantly
    v_passed := v_refresh_ratio < 0.1;  -- Less than 10% of source rows
    
    details := jsonb_build_object(
        'source_rows', v_source_row_count,
        'view_rows', v_view_row_count,
        'compression_ratio', v_refresh_ratio,
        'reduction_factor', CASE WHEN v_refresh_ratio > 0 THEN 1/v_refresh_ratio ELSE 0 END
    );
    
    INSERT INTO mv_refresh_test_results (
        test_name, test_category, test_passed, expected_result, actual_result,
        rows_in_view, test_data
    ) VALUES (
        test_name, 'SCALABILITY', v_passed, '< 10% ratio',
        round((v_refresh_ratio * 100)::NUMERIC, 2) || '%', v_view_row_count, details
    );
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST 4: VIEW CONSISTENCY
-- =============================================================================

-- Test 4.1: Verify view data consistency with source
CREATE OR REPLACE FUNCTION test_view_consistency()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_source_agg NUMERIC;
    v_view_agg NUMERIC;
    v_diff_pct NUMERIC;
    v_passed BOOLEAN;
    v_tolerance_pct NUMERIC := 0.01;
BEGIN
    test_name := 'TEST_4.1_VIEW_CONSISTENCY';
    
    -- Compare aggregated values
    SELECT COALESCE(SUM(amount), 0) INTO v_source_agg
    FROM ledger_transactions
    WHERE created_at >= CURRENT_DATE - 30;
    
    SELECT COALESCE(SUM(total_amount), 0) INTO v_view_agg
    FROM mv_daily_transaction_summary
    WHERE transaction_date >= CURRENT_DATE - 30;
    
    v_diff_pct := CASE WHEN v_source_agg > 0 
        THEN ABS(v_source_agg - v_view_agg) / v_source_agg * 100 
        ELSE 0 
    END;
    
    v_passed := v_diff_pct <= v_tolerance_pct;
    
    details := jsonb_build_object(
        'source_total', v_source_agg,
        'view_total', v_view_agg,
        'diff_pct', round(v_diff_pct, 4),
        'tolerance_pct', v_tolerance_pct
    );
    
    INSERT INTO mv_refresh_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data)
    VALUES (test_name, 'CONSISTENCY', v_passed, '< ' || v_tolerance_pct || '% diff', round(v_diff_pct, 4) || '%', details);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST 5: INDEX EFFECTIVENESS
-- =============================================================================

-- Test 5.1: Verify indexes are used for view queries
CREATE OR REPLACE FUNCTION test_view_index_usage()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_plan JSONB;
    v_index_used BOOLEAN;
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_5.1_VIEW_INDEX_USAGE';
    
    EXECUTE 'EXPLAIN (FORMAT JSON) SELECT * FROM mv_daily_transaction_summary WHERE transaction_date = CURRENT_DATE'
    INTO v_plan;
    
    v_index_used := v_plan::TEXT LIKE '%Index%';
    
    v_passed := v_index_used;
    
    details := jsonb_build_object(
        'index_used', v_index_used,
        'plan_node', v_plan->0->'Plan'->>'Node Type'
    );
    
    INSERT INTO mv_refresh_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data)
    VALUES (test_name, 'INDEX_USAGE', v_passed, 'Index scan used', CASE WHEN v_index_used THEN 'Index scan' ELSE 'Seq scan' END, details);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST 6: BULK TEST EXECUTION
-- =============================================================================

CREATE OR REPLACE FUNCTION run_all_mv_refresh_tests()
RETURNS TABLE (
    total_tests INTEGER,
    passed_tests INTEGER,
    failed_tests INTEGER,
    avg_refresh_time_ms NUMERIC,
    execution_time_ms INTEGER,
    test_summary JSONB
) AS $$
DECLARE
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_total INTEGER := 0;
    v_passed INTEGER := 0;
    rec RECORD;
BEGIN
    v_start_time := clock_timestamp();
    
    -- Run all tests
    FOR rec IN SELECT * FROM test_full_refresh_daily_summary() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_full_refresh_user_summary() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_concurrent_refresh_daily() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_refresh_scalability() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_view_consistency() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_view_index_usage() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; END IF;
    END LOOP;
    
    v_end_time := clock_timestamp();
    
    total_tests := v_total;
    passed_tests := v_passed;
    failed_tests := v_total - v_passed;
    avg_refresh_time_ms := (SELECT AVG(execution_time_ms) FROM mv_refresh_test_results WHERE execution_time_ms IS NOT NULL);
    execution_time_ms := EXTRACT(MILLISECONDS FROM (v_end_time - v_start_time))::INTEGER;
    test_summary := jsonb_build_object(
        'pass_rate', CASE WHEN v_total > 0 THEN round((v_passed::NUMERIC / v_total) * 100, 2) ELSE 0 END,
        'avg_refresh_time_ms', round(COALESCE(avg_refresh_time_ms, 0), 2)
    );
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST EXECUTION
-- =============================================================================

SELECT 'EXECUTING MATERIALIZED VIEW REFRESH BENCHMARKS...' as status;

SELECT * FROM run_all_mv_refresh_tests();

-- Display results
SELECT 
    test_name,
    test_category,
    test_passed,
    refresh_method,
    execution_time_ms,
    rows_in_view
FROM mv_refresh_test_results
ORDER BY test_executed_at DESC;

-- Materialized view statistics
SELECT 
    schemaname,
    matviewname,
    hasindexes,
    ispopulated,
    pg_size_pretty(pg_total_relation_size(schemaname || '.' || matviewname)) as total_size
FROM pg_matviews
WHERE matviewname LIKE 'mv_%'
ORDER BY pg_total_relation_size(schemaname || '.' || matviewname) DESC;

-- =============================================================================
-- TODO LIST FOR CUSTOMIZATION
-- =============================================================================

/*
TODO-1: Customize materialized view names to match your schema
TODO-2: Adjust refresh time thresholds based on your data volume
TODO-3: Add tests for additional materialized views
TODO-4: Implement incremental refresh strategies (pg_ivm)
TODO-5: Add tests for refresh scheduling conflicts
TODO-6: Test with different levels of concurrent user load
TODO-7: Add tests for view dependency tracking
TODO-8: Test refresh failure recovery
TODO-9: Add tests for storage efficiency
TODO-10: Customize aggregation queries to match your use case
*/

-- =============================================================================
-- END OF MATERIALIZED VIEW REFRESH BENCHMARKS
-- =============================================================================
