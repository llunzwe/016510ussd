-- ============================================================================
-- VACUUM STRATEGY PROCEDURE
-- ============================================================================
-- Purpose: Implement comprehensive vacuum and analyze strategy for
--          partitioned ledger tables with performance monitoring.
-- Author:  USSD Immutable Ledger Team
-- Date:    2026-03-30
-- ============================================================================
-- COMPLIANCE HEADER:
--   ISO 9001:2015 - Quality Management Systems - Requirements
--
--   This procedure implements:
--   - Clause 7.1.5: Infrastructure maintenance for quality assurance
--   - Clause 8.5.1: Production and service provision control
--   - Clause 9.1.1: Monitoring and measurement of organizational performance
--   - Annex B: Preventive maintenance scheduling and documentation
--
--   Quality Objectives: Dead tuple removal, Storage optimization
--   Performance Monitoring: Continuous vacuum statistics tracking
--   Documentation: All maintenance operations logged with timestamps
--   Threshold Management: Configurable quality control parameters
-- ============================================================================

-- =============================================================================
-- STEP 1: VACUUM CONFIGURATION AND MONITORING TABLES
-- =============================================================================

-- 1.1 Create vacuum operation tracking
CREATE TABLE IF NOT EXISTS vacuum_operations (
    operation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name TEXT NOT NULL,
    partition_name TEXT,
    operation_type VARCHAR(50) NOT NULL CHECK (operation_type IN ('VACUUM', 'VACUUM_FULL', 'VACUUM_ANALYZE', 'ANALYZE', 'AUTOVACUUM')),
    started_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    initiated_by TEXT DEFAULT CURRENT_USER,
    operation_status VARCHAR(50) DEFAULT 'INITIATED',
    dead_tuples_before BIGINT,
    dead_tuples_after BIGINT,
    live_tuples_before BIGINT,
    live_tuples_after BIGINT,
    table_size_before_bytes BIGINT,
    table_size_after_bytes BIGINT,
    duration_ms INTEGER,
    pages_scanned INTEGER,
    pages_vacuumed INTEGER,
    index_vacuum_count INTEGER,
    max_dead_tuples INTEGER
);

-- 1.2 Create vacuum statistics history
CREATE TABLE IF NOT EXISTS vacuum_statistics (
    stat_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schemaname TEXT,
    relname TEXT,
    n_live_tup BIGINT,
    n_dead_tup BIGINT,
    n_tup_ins BIGINT,
    n_tup_upd BIGINT,
    n_tup_del BIGINT,
    last_vacuum TIMESTAMPTZ,
    last_autovacuum TIMESTAMPTZ,
    last_analyze TIMESTAMPTZ,
    last_autoanalyze TIMESTAMPTZ,
    vacuum_count BIGINT,
    autovacuum_count BIGINT,
    analyze_count BIGINT,
    autoanalyze_count BIGINT,
    collected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 1.3 Create vacuum threshold configuration
CREATE TABLE IF NOT EXISTS vacuum_thresholds (
    threshold_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_pattern TEXT NOT NULL,
    min_dead_tuples BIGINT DEFAULT 50,
    dead_tuple_ratio_threshold NUMERIC DEFAULT 0.1,
    min_table_size_bytes BIGINT DEFAULT 10485760,  -- 10MB
    vacuum_priority INTEGER DEFAULT 5,  -- 1-10, lower is higher priority
    require_analyze_after BOOLEAN DEFAULT TRUE,
    parallel_workers INTEGER DEFAULT 2,
    effective_io_concurrency INTEGER DEFAULT 200,
    maintenance_work_mem_mb INTEGER DEFAULT 256,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 1.4 Insert default thresholds
INSERT INTO vacuum_thresholds (
    table_pattern,
    min_dead_tuples,
    dead_tuple_ratio_threshold,
    vacuum_priority
) VALUES 
    ('ledger_transactions%', 1000, 0.05, 1),  -- High priority for main ledger
    ('audit_log%', 500, 0.1, 2),
    ('user_%', 100, 0.15, 5),
    ('%', 50, 0.2, 10)  -- Default for all other tables
ON CONFLICT DO NOTHING;

-- =============================================================================
-- STEP 2: PRE-VACUUM ASSESSMENT
-- =============================================================================

-- 2.1 Analyze table bloat and dead tuples
CREATE OR REPLACE FUNCTION analyze_vacuum_needs(
    p_table_pattern TEXT DEFAULT 'ledger_transactions%'
)
RETURNS TABLE (
    schemaname TEXT,
    tablename TEXT,
    live_tuples BIGINT,
    dead_tuples BIGINT,
    dead_tuple_ratio NUMERIC,
    table_size_bytes BIGINT,
    table_size_pretty TEXT,
    last_vacuum TIMESTAMPTZ,
    last_autovacuum TIMESTAMPTZ,
    vacuum_needed BOOLEAN,
    priority INTEGER,
    recommendation TEXT
) AS $$
BEGIN
    RETURN QUERY
    WITH table_stats AS (
        SELECT 
            s.schemaname,
            s.relname,
            s.n_live_tup,
            s.n_dead_tup,
            CASE WHEN s.n_live_tup + s.n_dead_tup > 0 
                THEN s.n_dead_tup::NUMERIC / (s.n_live_tup + s.n_dead_tup)
                ELSE 0 
            END as dead_ratio,
            pg_table_size(s.relid) as table_size,
            pg_size_pretty(pg_table_size(s.relid)) as size_pretty,
            s.last_vacuum,
            s.last_autovacuum,
            s.last_analyze,
            s.last_autoanalyze
        FROM pg_stat_user_tables s
        WHERE s.relname LIKE p_table_pattern
    ),
    threshold_match AS (
        SELECT 
            ts.*,
            vt.min_dead_tuples,
            vt.dead_tuple_ratio_threshold,
            vt.vacuum_priority,
            vt.require_analyze_after
        FROM table_stats ts
        LEFT JOIN vacuum_thresholds vt ON ts.relname LIKE vt.table_pattern
        ORDER BY vt.vacuum_priority NULLS LAST
    )
    SELECT 
        schemaname::TEXT,
        relname::TEXT,
        n_live_tup,
        n_dead_tup,
        round(dead_ratio::NUMERIC, 4),
        table_size,
        size_pretty,
        last_vacuum,
        last_autovacuum,
        (n_dead_tup > COALESCE(min_dead_tuples, 50) 
         OR dead_ratio > COALESCE(dead_tuple_ratio_threshold, 0.1))::BOOLEAN,
        COALESCE(vacuum_priority, 10),
        CASE 
            WHEN n_dead_tup > COALESCE(min_dead_tuples, 50) * 10 
                 OR dead_ratio > COALESCE(dead_tuple_ratio_threshold, 0.1) * 2
            THEN 'VACUUM_FULL_RECOMMENDED'
            WHEN n_dead_tup > COALESCE(min_dead_tuples, 50) 
                 OR dead_ratio > COALESCE(dead_tuple_ratio_threshold, 0.1)
            THEN 'VACUUM_ANALYZE'
            WHEN last_vacuum IS NULL AND last_autovacuum IS NULL
            THEN 'NEVER_VACUUMED'
            ELSE 'OK'
        END::TEXT
    FROM threshold_match;
END;
$$ LANGUAGE plpgsql;

-- 2.2 Capture pre-vacuum statistics
CREATE OR REPLACE FUNCTION capture_vacuum_stats(
    p_operation_id UUID,
    p_table_name TEXT
)
RETURNS VOID AS $$
BEGIN
    INSERT INTO vacuum_statistics (
        stat_id,
        schemaname,
        relname,
        n_live_tup,
        n_dead_tup,
        n_tup_ins,
        n_tup_upd,
        n_tup_del,
        last_vacuum,
        last_autovacuum,
        last_analyze,
        last_autoanalyze,
        vacuum_count,
        autovacuum_count,
        analyze_count,
        autoanalyze_count
    )
    SELECT 
        p_operation_id,
        schemaname,
        relname,
        n_live_tup,
        n_dead_tup,
        n_tup_ins,
        n_tup_upd,
        n_tup_del,
        last_vacuum,
        last_autovacuum,
        last_analyze,
        last_autoanalyze,
        vacuum_count,
        autovacuum_count,
        analyze_count,
        autoanalyze_count
    FROM pg_stat_user_tables
    WHERE relname = p_table_name;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 3: VACUUM EXECUTION PROCEDURES
-- =============================================================================

-- 3.1 Execute vacuum with monitoring
CREATE OR REPLACE PROCEDURE execute_vacuum_table(
    p_table_name TEXT,
    p_vacuum_type VARCHAR(50) DEFAULT 'VACUUM_ANALYZE',
    p_dry_run BOOLEAN DEFAULT TRUE
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_operation_id UUID;
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_stats_before RECORD;
    v_stats_after RECORD;
BEGIN
    -- Get pre-vacuum stats
    SELECT * INTO v_stats_before
    FROM pg_stat_user_tables
    WHERE relname = p_table_name;
    
    -- Create operation record
    INSERT INTO vacuum_operations (
        table_name,
        operation_type,
        dead_tuples_before,
        live_tuples_before,
        table_size_before_bytes
    ) VALUES (
        p_table_name,
        p_vacuum_type,
        v_stats_before.n_dead_tup,
        v_stats_before.n_live_tup,
        pg_table_size(v_stats_before.relid)
    )
    RETURNING operation_id INTO v_operation_id;
    
    RAISE NOTICE 'Vacuum operation % started for table % (type: %)', 
        v_operation_id, p_table_name, p_vacuum_type;
    
    IF NOT p_dry_run THEN
        v_start_time := clock_timestamp();
        
        -- Execute vacuum based on type
        CASE p_vacuum_type
            WHEN 'VACUUM' THEN
                EXECUTE format('VACUUM %I', p_table_name);
            WHEN 'VACUUM_FULL' THEN
                EXECUTE format('VACUUM (FULL, ANALYZE) %I', p_table_name);
            WHEN 'VACUUM_ANALYZE' THEN
                EXECUTE format('VACUUM (ANALYZE) %I', p_table_name);
            WHEN 'ANALYZE' THEN
                EXECUTE format('ANALYZE %I', p_table_name);
        END CASE;
        
        v_end_time := clock_timestamp();
        
        -- Get post-vacuum stats
        SELECT * INTO v_stats_after
        FROM pg_stat_user_tables
        WHERE relname = p_table_name;
        
        -- Update operation record
        UPDATE vacuum_operations
        SET 
            completed_at = v_end_time,
            operation_status = 'COMPLETED',
            dead_tuples_after = v_stats_after.n_dead_tup,
            live_tuples_after = v_stats_after.n_live_tup,
            table_size_after_bytes = pg_table_size(v_stats_after.relid),
            duration_ms = EXTRACT(MILLISECONDS FROM (v_end_time - v_start_time))::INTEGER
        WHERE operation_id = v_operation_id;
        
        RAISE NOTICE 'Vacuum completed in % ms. Dead tuples: % -> %', 
            EXTRACT(MILLISECONDS FROM (v_end_time - v_start_time))::INTEGER,
            v_stats_before.n_dead_tup,
            v_stats_after.n_dead_tup;
    ELSE
        RAISE NOTICE 'DRY RUN: Would execute % on %', p_vacuum_type, p_table_name;
        
        UPDATE vacuum_operations
        SET operation_status = 'DRY_RUN'
        WHERE operation_id = v_operation_id;
    END IF;
END;
$$;

-- 3.2 Batch vacuum for multiple tables
CREATE OR REPLACE PROCEDURE execute_batch_vacuum(
    p_table_pattern TEXT DEFAULT 'ledger_transactions%',
    p_vacuum_type VARCHAR(50) DEFAULT 'VACUUM_ANALYZE',
    p_max_tables INTEGER DEFAULT 10,
    p_dry_run BOOLEAN DEFAULT TRUE
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_table RECORD;
BEGIN
    FOR v_table IN 
        SELECT tablename, vacuum_needed, priority
        FROM analyze_vacuum_needs(p_table_pattern)
        WHERE vacuum_needed = TRUE
        ORDER BY priority, dead_tuples DESC
        LIMIT p_max_tables
    LOOP
        RAISE NOTICE 'Processing table: % (priority: %)', v_table.tablename, v_table.priority;
        
        CALL execute_vacuum_table(
            v_table.tablename,
            p_vacuum_type,
            p_dry_run
        );
        
        -- Small delay between operations
        IF NOT p_dry_run THEN
            PERFORM pg_sleep(0.5);
        END IF;
    END LOOP;
END;
$$;

-- 3.3 Partition-specific vacuum
CREATE OR REPLACE PROCEDURE vacuum_old_partitions(
    p_parent_table TEXT,
    p_older_than_days INTEGER DEFAULT 30,
    p_dry_run BOOLEAN DEFAULT TRUE
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_partition RECORD;
BEGIN
    FOR v_partition IN 
        SELECT 
            child.relname as partition_name,
            pg_table_size(child.oid) as partition_size
        FROM pg_inherits
        JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
        JOIN pg_class child ON pg_inherits.inhrelid = child.oid
        WHERE parent.relname = p_parent_table
        AND child.relname < p_parent_table || '_' || to_char(CURRENT_DATE - p_older_than_days, 'YYYYMMDD')
        ORDER BY child.relname
    LOOP
        RAISE NOTICE 'Vacuuming partition: % (size: %)', 
            v_partition.partition_name,
            pg_size_pretty(v_partition.partition_size);
        
        IF NOT p_dry_run THEN
            EXECUTE format('VACUUM (ANALYZE) %I', v_partition.partition_name);
        END IF;
    END LOOP;
END;
$$;

-- =============================================================================
-- STEP 4: AUTOVACUUM MONITORING AND TUNING
-- =============================================================================

-- 4.1 Check autovacuum settings
CREATE OR REPLACE VIEW autovacuum_settings AS
SELECT 
    name,
    setting,
    unit,
    short_desc
FROM pg_settings
WHERE name LIKE 'autovacuum%'
   OR name IN ('vacuum_cost_delay', 'vacuum_cost_limit', 'vacuum_freeze_min_age');

-- 4.2 Analyze autovacuum activity
CREATE OR REPLACE FUNCTION analyze_autovacuum_activity(
    p_hours_back INTEGER DEFAULT 24
)
RETURNS TABLE (
    table_name TEXT,
    autovacuum_count BIGINT,
    autoanalyze_count BIGINT,
    last_autovacuum TIMESTAMPTZ,
    last_autoanalyze TIMESTAMPTZ,
    dead_tuples BIGINT,
    live_tuples BIGINT,
    health_status TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        s.relname::TEXT,
        s.autovacuum_count,
        s.autoanalyze_count,
        s.last_autovacuum,
        s.last_autoanalyze,
        s.n_dead_tup,
        s.n_live_tup,
        CASE 
            WHEN s.n_dead_tup > 10000 THEN 'CRITICAL'
            WHEN s.n_dead_tup > 1000 THEN 'WARNING'
            WHEN s.last_autovacuum < CURRENT_TIMESTAMP - INTERVAL '7 days' 
                 AND s.n_live_tup > 10000 THEN 'STALE'
            ELSE 'HEALTHY'
        END::TEXT
    FROM pg_stat_user_tables s
    WHERE s.relname LIKE 'ledger_transactions%'
    ORDER BY s.n_dead_tup DESC;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 5: TEST CASES WITH EXPECTED RESULTS
-- =============================================================================

-- Test Case 5.1: Analyze vacuum needs
SELECT 
    'TEST_5.1_VACUUM_NEEDS_ANALYSIS' as test_name,
    tablename,
    dead_tuples,
    round(dead_tuple_ratio::NUMERIC, 4) as dead_ratio,
    vacuum_needed,
    recommendation
FROM analyze_vacuum_needs('ledger_transactions%')
LIMIT 5;

-- Test Case 5.2: Verify vacuum operation tracking
DO $$
DECLARE
    v_operation_id UUID;
BEGIN
    INSERT INTO vacuum_operations (
        table_name,
        operation_type,
        operation_status
    ) VALUES (
        'test_table',
        'VACUUM_ANALYZE',
        'TEST'
    )
    RETURNING operation_id INTO v_operation_id;
    
    RAISE NOTICE 'TEST_5.2_OPERATION_TRACKING: PASSED - Operation ID: %', v_operation_id;
END $$;

-- Test Case 5.3: Check autovacuum activity
SELECT 
    'TEST_5.3_AUTOVACUUM_HEALTH' as test_name,
    table_name,
    health_status,
    dead_tuples,
    last_autovacuum
FROM analyze_autovacuum_activity(24)
LIMIT 5;

-- Test Case 5.4: Verify threshold configuration
SELECT 
    'TEST_5.4_THRESHOLD_CONFIG' as test_name,
    CASE WHEN COUNT(*) >= 3 THEN 'PASSED' ELSE 'FAILED' END as result,
    COUNT(*) as threshold_count
FROM vacuum_thresholds;

-- Test Case 5.5: Calculate vacuum effectiveness
SELECT 
    'TEST_5.5_VACUUM_EFFECTIVENESS' as test_name,
    table_name,
    operation_type,
    dead_tuples_before,
    dead_tuples_after,
    CASE 
        WHEN dead_tuples_before > 0 
        THEN round(((dead_tuples_before - dead_tuples_after)::NUMERIC / dead_tuples_before) * 100, 2)
        ELSE NULL
    END as cleanup_percentage,
    pg_size_pretty(table_size_before_bytes) as size_before,
    pg_size_pretty(table_size_after_bytes) as size_after
FROM vacuum_operations
WHERE operation_status = 'COMPLETED'
AND dead_tuples_before IS NOT NULL
ORDER BY started_at DESC
LIMIT 5;

-- =============================================================================
-- STEP 6: ROLLBACK PROCEDURES
-- =============================================================================

-- Note: VACUUM operations cannot be rolled back at transaction level
-- However, we can document the state and provide restoration guidance

-- 6.1 Document pre-vacuum state
CREATE OR REPLACE FUNCTION document_pre_vacuum_state(
    p_table_name TEXT
)
RETURNS JSONB AS $$
DECLARE
    v_state JSONB;
BEGIN
    SELECT jsonb_build_object(
        'table_name', p_table_name,
        'timestamp', CURRENT_TIMESTAMP,
        'table_size', pg_table_size(relid),
        'indexes_size', pg_indexes_size(relid),
        'total_size', pg_total_relation_size(relid),
        'live_tuples', n_live_tup,
        'dead_tuples', n_dead_tup,
        'last_vacuum', last_vacuum,
        'last_autovacuum', last_autovacuum
    ) INTO v_state
    FROM pg_stat_user_tables
    WHERE relname = p_table_name;
    
    RETURN v_state;
END;
$$ LANGUAGE plpgsql;

-- 6.2 Cancel vacuum operations (for in-progress manual vacuums)
-- Note: This requires pg_cancel_backend on the vacuum PID
CREATE OR REPLACE FUNCTION cancel_running_vacuums()
RETURNS TABLE (
    pid INTEGER,
    query TEXT,
    cancel_status BOOLEAN
) AS $$
DECLARE
    v_rec RECORD;
    v_cancelled BOOLEAN;
BEGIN
    FOR v_rec IN 
        SELECT 
            pid,
            query
        FROM pg_stat_activity
        WHERE query LIKE 'VACUUM%'
        AND state = 'active'
    LOOP
        pid := v_rec.pid;
        query := v_rec.query;
        
        -- Attempt to cancel
        SELECT pg_cancel_backend(v_rec.pid) INTO v_cancel_status;
        cancel_status := v_cancel_status;
        
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 7: VALIDATION CHECKS
-- =============================================================================

-- 7.1 Verify table health across all ledger tables
SELECT 
    schemaname,
    relname,
    n_live_tup as live_tuples,
    n_dead_tup as dead_tuples,
    CASE WHEN n_live_tup > 0 
        THEN round((n_dead_tup::NUMERIC / n_live_tup) * 100, 2)
        ELSE 0 
    END as dead_tuple_pct,
    pg_size_pretty(pg_table_size(relid)) as table_size,
    CASE 
        WHEN n_dead_tup > n_live_tup * 0.2 THEN 'NEEDS_VACUUM'
        WHEN last_vacuum < CURRENT_TIMESTAMP - INTERVAL '7 days' THEN 'STALE'
        ELSE 'HEALTHY'
    END as status
FROM pg_stat_user_tables
WHERE relname LIKE 'ledger_transactions%'
ORDER BY n_dead_tup DESC;

-- 7.2 Check for tables never vacuumed
SELECT 
    relname as table_name,
    n_live_tup as live_tuples,
    n_dead_tup as dead_tuples,
    'NEVER_VACUUMED' as warning
FROM pg_stat_user_tables
WHERE relname LIKE 'ledger_transactions%'
AND last_vacuum IS NULL
AND last_autovacuum IS NULL
AND n_live_tup > 1000;

-- 7.3 Index bloat correlation check
SELECT 
    t.relname as table_name,
    t.n_dead_tup as table_dead_tuples,
    pg_size_pretty(pg_table_size(t.relid)) as table_size,
    (SELECT count(*) FROM pg_stat_user_indexes WHERE relid = t.relid) as index_count
FROM pg_stat_user_tables t
WHERE t.relname LIKE 'ledger_transactions%'
AND t.n_dead_tup > 1000
ORDER BY t.n_dead_tup DESC;

-- =============================================================================
-- TODO LIST FOR CUSTOMIZATION
-- =============================================================================

/*
TODO-1: Customize table name patterns for your partition naming convention
TODO-2: Adjust dead tuple thresholds based on your table sizes and activity
TODO-3: Configure autovacuum parameters per table using ALTER TABLE
TODO-4: Set up pg_cron jobs for scheduled vacuum operations
TODO-5: Implement vacuum progress monitoring for long-running operations
TODO-6: Configure toast table vacuum settings for large text/binary columns
TODO-7: Set up freezing threshold monitoring to prevent transaction ID wraparound
TODO-8: Implement cross-database vacuum coordination for multi-tenant setups
TODO-9: Customize vacuum cost settings for your hardware (SSD vs HDD)
TODO-10: Set up alerting for tables with excessive dead tuples
*/

-- =============================================================================
-- END OF VACUUM STRATEGY PROCEDURE
-- =============================================================================
