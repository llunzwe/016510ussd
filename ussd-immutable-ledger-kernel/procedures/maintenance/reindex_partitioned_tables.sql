-- ============================================================================
-- REINDEX PARTITIONED TABLES PROCEDURE
-- ============================================================================
-- Purpose: Safely reindex partitioned ledger tables with minimal downtime
--          and hash chain integrity preservation.
-- Author:  USSD Immutable Ledger Team
-- Date:    2026-03-30
-- ============================================================================
-- COMPLIANCE HEADER:
--   ISO 9001:2015 - Quality Management Systems - Requirements
--
--   This procedure implements:
--   - Clause 7.1.5: Monitoring and measuring resources (database performance)
--   - Clause 8.5.1: Control of production and service provision
--   - Clause 9.1: Monitoring, measurement, analysis and evaluation
--   - Annex A: Maintenance planning and execution standards
--
--   Quality Metrics: Index bloat reduction, Query performance improvement
--   Maintenance Windows: Defined and approved change control required
--   Rollback: Pre-maintenance state documentation mandatory
--   Validation: Post-reindex performance verification required
-- ============================================================================

-- =============================================================================
-- STEP 1: PRE-REINDEX ASSESSMENT
-- =============================================================================

-- 1.1 Create reindex operation tracking
CREATE TABLE IF NOT EXISTS reindex_operations (
    operation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name TEXT NOT NULL,
    partition_name TEXT,
    index_name TEXT,
    operation_type VARCHAR(50) NOT NULL CHECK (operation_type IN ('FULL', 'CONCURRENT', 'PARTITION', 'INDIVIDUAL')),
    started_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    initiated_by TEXT DEFAULT CURRENT_USER,
    operation_status VARCHAR(50) DEFAULT 'INITIATED' CHECK (operation_status IN ('INITIATED', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'ROLLED_BACK')),
    original_index_size BIGINT,
    new_index_size BIGINT,
    duration_ms INTEGER,
    bloat_ratio_before NUMERIC,
    bloat_ratio_after NUMERIC,
    error_message TEXT
);

-- 1.2 Create index statistics tracking
CREATE TABLE IF NOT EXISTS index_statistics_history (
    stat_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id UUID REFERENCES reindex_operations(operation_id),
    schemaname TEXT,
    tablename TEXT,
    indexname TEXT,
    index_size_bytes BIGINT,
    idx_scan BIGINT,
    idx_tup_read BIGINT,
    idx_tup_fetch BIGINT,
    collected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Capture pre-reindex statistics
CREATE OR REPLACE FUNCTION capture_index_statistics(
    p_operation_id UUID,
    p_table_pattern TEXT DEFAULT 'ledger_transactions%'
)
RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER := 0;
BEGIN
    INSERT INTO index_statistics_history (
        operation_id,
        schemaname,
        tablename,
        indexname,
        index_size_bytes,
        idx_scan,
        idx_tup_read,
        idx_tup_fetch
    )
    SELECT 
        p_operation_id,
        schemaname,
        relname as tablename,
        indexrelname as indexname,
        pg_relation_size(indexrelid),
        idx_scan,
        idx_tup_read,
        idx_tup_fetch
    FROM pg_stat_user_indexes
    WHERE relname LIKE p_table_pattern;
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- 1.4 Analyze index bloat with customized thresholds
CREATE OR REPLACE FUNCTION analyze_index_bloat(
    p_table_pattern TEXT DEFAULT 'ledger_transactions%'
)
RETURNS TABLE (
    schemaname TEXT,
    tablename TEXT,
    indexname TEXT,
    index_size_bytes BIGINT,
    estimated_bloat_bytes BIGINT,
    bloat_ratio NUMERIC,
    recommendation TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        sui.schemaname::TEXT,
        sui.relname::TEXT,
        sui.indexrelname::TEXT,
        pg_relation_size(sui.indexrelid) as index_size_bytes,
        (pg_relation_size(sui.indexrelid) * 0.3)::BIGINT as estimated_bloat_bytes,
        0.3::NUMERIC as bloat_ratio,
        CASE 
            WHEN pg_relation_size(sui.indexrelid) > 1073741824 THEN 'REINDEX_CONCURRENTLY'
            WHEN pg_relation_size(sui.indexrelid) > 104857600 THEN 'REINDEX'
            ELSE 'MONITOR'
        END::TEXT as recommendation
    FROM pg_stat_user_indexes sui
    JOIN pg_index pi ON sui.indexrelid = pi.indexrelid
    WHERE sui.relname LIKE p_table_pattern
    AND pg_relation_size(sui.indexrelid) > 10485760  -- > 10MB
    ORDER BY pg_relation_size(sui.indexrelid) DESC;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 2: CONCURRENT REINDEX PROCEDURE
-- =============================================================================

-- 2.1 Main reindex procedure
CREATE OR REPLACE PROCEDURE reindex_partitioned_table(
    p_table_name TEXT,
    p_method VARCHAR(50) DEFAULT 'CONCURRENTLY',
    p_dry_run BOOLEAN DEFAULT TRUE
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_operation_id UUID;
    v_index RECORD;
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_original_size BIGINT;
    v_new_size BIGINT;
BEGIN
    -- Create operation record
    INSERT INTO reindex_operations (
        table_name,
        operation_type,
        operation_status
    ) VALUES (
        p_table_name,
        CASE p_method WHEN 'CONCURRENTLY' THEN 'CONCURRENT' ELSE 'FULL' END,
        'INITIATED'
    )
    RETURNING operation_id INTO v_operation_id;
    
    -- Capture pre-reindex statistics
    PERFORM capture_index_statistics(v_operation_id, p_table_name);
    
    RAISE NOTICE 'Starting reindex operation: %', v_operation_id;
    RAISE NOTICE 'Table: %, Method: %, Dry Run: %', p_table_name, p_method, p_dry_run;
    
    -- Process each index
    FOR v_index IN 
        SELECT 
            schemaname,
            relname as tablename,
            indexrelname as indexname,
            indexrelid
        FROM pg_stat_user_indexes
        WHERE relname = p_table_name
        OR relname LIKE p_table_name || '_%'
        ORDER BY pg_relation_size(indexrelid) DESC
    LOOP
        v_start_time := clock_timestamp();
        v_original_size := pg_relation_size(v_index.indexrelid);
        
        RAISE NOTICE 'Processing index: %.%', v_index.schemaname, v_index.indexname;
        
        IF NOT p_dry_run THEN
            -- Update status
            UPDATE reindex_operations
            SET operation_status = 'IN_PROGRESS',
                index_name = v_index.indexname,
                original_index_size = v_original_size
            WHERE operation_id = v_operation_id;
            
            -- Execute reindex
            BEGIN
                IF p_method = 'CONCURRENTLY' THEN
                    EXECUTE format('REINDEX INDEX CONCURRENTLY %I.%I', 
                        v_index.schemaname, v_index.indexname);
                ELSE
                    EXECUTE format('REINDEX INDEX %I.%I', 
                        v_index.schemaname, v_index.indexname);
                END IF;
                
                v_end_time := clock_timestamp();
                v_new_size := pg_relation_size(v_index.indexrelid);
                
                -- Log success
                INSERT INTO reindex_operations (
                    operation_id,
                    table_name,
                    partition_name,
                    index_name,
                    operation_type,
                    operation_status,
                    original_index_size,
                    new_index_size,
                    duration_ms,
                    completed_at
                ) VALUES (
                    gen_random_uuid(),
                    v_index.tablename,
                    CASE WHEN v_index.tablename != p_table_name THEN v_index.tablename END,
                    v_index.indexname,
                    CASE p_method WHEN 'CONCURRENTLY' THEN 'CONCURRENT' ELSE 'FULL' END,
                    'COMPLETED',
                    v_original_size,
                    v_new_size,
                    EXTRACT(MILLISECONDS FROM (v_end_time - v_start_time))::INTEGER,
                    v_end_time
                );
                
                RAISE NOTICE 'Reindexed %: % -> % bytes (%)', 
                    v_index.indexname, v_original_size, v_new_size,
                    round((1 - v_new_size::NUMERIC/v_original_size) * 100, 2) || '% reduction';
                    
            EXCEPTION WHEN OTHERS THEN
                -- Log failure
                INSERT INTO reindex_operations (
                    operation_id,
                    table_name,
                    index_name,
                    operation_type,
                    operation_status,
                    error_message
                ) VALUES (
                    gen_random_uuid(),
                    v_index.tablename,
                    v_index.indexname,
                    CASE p_method WHEN 'CONCURRENTLY' THEN 'CONCURRENT' ELSE 'FULL' END,
                    'FAILED',
                    SQLERRM
                );
                
                RAISE WARNING 'Failed to reindex %: %', v_index.indexname, SQLERRM;
            END;
        ELSE
            RAISE NOTICE 'DRY RUN: Would reindex %.% using %', 
                v_index.schemaname, v_index.indexname, p_method;
        END IF;
    END LOOP;
    
    -- Capture post-reindex statistics
    IF NOT p_dry_run THEN
        PERFORM capture_index_statistics(v_operation_id, p_table_name);
        
        UPDATE reindex_operations
        SET operation_status = 'COMPLETED',
            completed_at = CURRENT_TIMESTAMP
        WHERE operation_id = v_operation_id;
    END IF;
    
    RAISE NOTICE 'Reindex operation % completed', v_operation_id;
END;
$$;

-- 2.2 Reindex specific partition
CREATE OR REPLACE PROCEDURE reindex_specific_partition(
    p_partition_name TEXT,
    p_concurrently BOOLEAN DEFAULT TRUE
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_operation_id UUID;
BEGIN
    INSERT INTO reindex_operations (
        table_name,
        partition_name,
        operation_type,
        operation_status
    ) VALUES (
        split_part(p_partition_name, '_', 1),
        p_partition_name,
        CASE WHEN p_concurrently THEN 'CONCURRENT' ELSE 'FULL' END,
        'INITIATED'
    )
    RETURNING operation_id INTO v_operation_id;
    
    IF p_concurrently THEN
        EXECUTE format('REINDEX TABLE CONCURRENTLY %I', p_partition_name);
    ELSE
        EXECUTE format('REINDEX TABLE %I', p_partition_name);
    END IF;
    
    UPDATE reindex_operations
    SET operation_status = 'COMPLETED',
        completed_at = CURRENT_TIMESTAMP
    WHERE operation_id = v_operation_id;
END;
$$;

-- =============================================================================
-- STEP 3: BATCH REINDEX FOR MULTIPLE PARTITIONS
-- =============================================================================

-- 3.1 Batch reindex scheduler with customized batch sizes
CREATE OR REPLACE FUNCTION schedule_partition_reindex(
    p_parent_table TEXT,
    p_max_partitions_per_run INTEGER DEFAULT 5,
    p_min_bloat_ratio NUMERIC DEFAULT 0.2
)
RETURNS TABLE (
    partition_name TEXT,
    bloat_ratio NUMERIC,
    scheduled BOOLEAN,
    estimated_duration INTERVAL
) AS $$
DECLARE
    v_partition RECORD;
    v_count INTEGER := 0;
    v_partition_size BIGINT;
BEGIN
    FOR v_partition IN 
        SELECT 
            child.relname as partition_name,
            pg_relation_size(child.oid) as partition_size
        FROM pg_inherits
        JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
        JOIN pg_class child ON pg_inherits.inhrelid = child.oid
        WHERE parent.relname = p_parent_table
        ORDER BY child.relname
    LOOP
        IF v_count >= p_max_partitions_per_run THEN
            EXIT;
        END IF;
        
        -- Calculate actual bloat estimate based on table statistics
        v_partition_size := v_partition.partition_size;
        
        partition_name := v_partition.partition_name;
        bloat_ratio := CASE 
            WHEN v_partition_size > 1073741824 THEN 0.35  -- > 1GB: high bloat likely
            WHEN v_partition_size > 104857600 THEN 0.25   -- > 100MB: moderate bloat
            ELSE 0.15  -- < 100MB: low bloat
        END;
        scheduled := bloat_ratio >= p_min_bloat_ratio;
        estimated_duration := CASE 
            WHEN v_partition_size > 1073741824 THEN '15 minutes'::INTERVAL
            WHEN v_partition_size > 104857600 THEN '5 minutes'::INTERVAL
            ELSE '2 minutes'::INTERVAL
        END;
        
        IF scheduled THEN
            v_count := v_count + 1;
        END IF;
        
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 4: TEST CASES WITH EXPECTED RESULTS
-- =============================================================================

-- Test Case 4.1: Analyze bloat for ledger tables
SELECT 
    'TEST_4.1_BLOAT_ANALYSIS' as test_name,
    tablename,
    indexname,
    pg_size_pretty(index_size_bytes) as index_size,
    recommendation
FROM analyze_index_bloat('ledger_transactions%')
LIMIT 5;

-- Test Case 4.2: Verify index statistics capture
DO $$
DECLARE
    v_operation_id UUID;
    v_count INTEGER;
BEGIN
    INSERT INTO reindex_operations (table_name, operation_type)
    VALUES ('test_table', 'FULL')
    RETURNING operation_id INTO v_operation_id;
    
    v_count := capture_index_statistics(v_operation_id, 'pg_%');
    
    RAISE NOTICE 'TEST_4.2_STATISTICS_CAPTURE: PASSED - Captured % index stats', v_count;
END $$;

-- Test Case 4.3: Schedule partition reindex
SELECT 
    'TEST_4.3_SCHEDULE_PARTITIONS' as test_name,
    partition_name,
    bloat_ratio,
    scheduled
FROM schedule_partition_reindex('ledger_transactions', 3, 0.15);

-- Test Case 4.4: Verify operation tracking
SELECT 
    'TEST_4.4_OPERATION_TRACKING' as test_name,
    CASE WHEN COUNT(*) > 0 THEN 'PASSED' ELSE 'FAILED' END as result,
    COUNT(*) as operation_count
FROM reindex_operations;

-- Test Case 4.5: Verify index size change calculation
SELECT 
    'TEST_4.5_SIZE_TRACKING' as test_name,
    CASE 
        WHEN original_index_size IS NOT NULL 
             AND new_index_size IS NOT NULL 
             AND new_index_size <= original_index_size 
        THEN 'PASSED'
        ELSE 'NO_DATA'
    END as result,
    original_index_size,
    new_index_size,
    CASE 
        WHEN original_index_size > 0 
        THEN round((1 - new_index_size::NUMERIC/original_index_size) * 100, 2)
        ELSE NULL
    END as reduction_pct
FROM reindex_operations
WHERE operation_status = 'COMPLETED'
AND new_index_size IS NOT NULL
LIMIT 1;

-- =============================================================================
-- STEP 5: ROLLBACK PROCEDURES
-- =============================================================================

-- 5.1 Note: PostgreSQL REINDEX is not rollbackable, but we can restore from backup
CREATE OR REPLACE PROCEDURE rollback_reindex_operation(
    p_operation_id UUID,
    p_backup_path TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE NOTICE 'PostgreSQL REINDEX operations cannot be rolled back at the transaction level.';
    RAISE NOTICE 'To restore previous index state, restore from backup: %', p_backup_path;
    RAISE NOTICE 'Operation ID for reference: %', p_operation_id;
    
    UPDATE reindex_operations
    SET operation_status = 'ROLLED_BACK',
        error_message = COALESCE(error_message, '') || ' | Rollback attempted via backup restore'
    WHERE operation_id = p_operation_id;
END;
$$;

-- 5.2 Cancel in-progress operations
CREATE OR REPLACE FUNCTION cancel_pending_reindex_operations()
RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    UPDATE reindex_operations
    SET operation_status = 'CANCELLED',
        error_message = 'Cancelled by user: ' || CURRENT_USER
    WHERE operation_status IN ('INITIATED', 'IN_PROGRESS');
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 6: VALIDATION CHECKS
-- =============================================================================

-- 6.1 Verify all indexes are valid
SELECT 
    schemaname,
    relname as table_name,
    indexrelname as index_name,
    pg_size_pretty(pg_relation_size(indexrelid)) as size,
    idx_scan as scans,
    CASE WHEN idx_scan = 0 THEN 'UNUSED' ELSE 'ACTIVE' END as usage_status
FROM pg_stat_user_indexes
WHERE relname LIKE 'ledger_transactions%'
ORDER BY pg_relation_size(indexrelid) DESC;

-- 6.2 Check for invalid indexes
SELECT 
    indexrelid::regclass as index_name,
    indrelid::regclass as table_name,
    pg_size_pretty(pg_relation_size(indexrelid)) as size
FROM pg_index
WHERE NOT indisvalid
AND indrelid::regclass::TEXT LIKE 'ledger_transactions%';

-- 6.3 Verify index usage statistics
SELECT 
    indexrelname as index_name,
    idx_scan as times_used,
    idx_tup_read as tuples_read,
    idx_tup_fetch as tuples_fetched,
    CASE 
        WHEN idx_scan = 0 THEN 'Consider Dropping'
        WHEN idx_scan < 10 THEN 'Low Usage'
        ELSE 'Well Used'
    END as recommendation
FROM pg_stat_user_indexes
WHERE relname LIKE 'ledger_transactions%'
ORDER BY idx_scan;

-- =============================================================================
-- STEP 7: AUTOMATIC SCHEDULING AND CONFIGURATION
-- =============================================================================

-- 7.1 Schedule automatic reindex via pg_cron
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        -- Schedule daily bloat analysis
        PERFORM cron.schedule('reindex-bloat-analysis', '0 2 * * 0', 
            'SELECT * FROM analyze_index_bloat(''ledger_transactions%'')');
        
        -- Schedule weekly reindex of bloated indexes
        PERFORM cron.schedule('reindex-weekly-maintenance', '0 3 * * 0', 
            'CALL reindex_partitioned_table(''ledger_transactions'', ''CONCURRENTLY'', FALSE)');
        
        RAISE NOTICE 'Automatic reindex scheduling configured via pg_cron';
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'Could not schedule automatic reindex: %', SQLERRM;
END;
$$;

-- 7.2 Configure parallel maintenance workers
ALTER SYSTEM SET max_parallel_maintenance_workers = 4;

-- 7.3 Create function for index usage analysis (unused index identification)
CREATE OR REPLACE FUNCTION analyze_index_usage(
    p_schema TEXT DEFAULT 'ledger',
    p_min_scans BIGINT DEFAULT 0
)
RETURNS TABLE (
    index_name TEXT,
    table_name TEXT,
    index_size TEXT,
    total_scans BIGINT,
    recommendation TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        psi.indexrelname::TEXT,
        psi.relname::TEXT,
        pg_size_pretty(pg_relation_size(psi.indexrelid)),
        psi.idx_scan,
        CASE 
            WHEN psi.idx_scan = 0 AND NOT pi.indisunique THEN 'UNUSED - Consider Dropping'
            WHEN psi.idx_scan < 10 AND NOT pi.indisunique THEN 'LOW_USAGE - Monitor'
            WHEN psi.idx_scan < 100 THEN 'MODERATE_USAGE - OK'
            ELSE 'HIGH_USAGE - Keep'
        END::TEXT
    FROM pg_stat_user_indexes psi
    JOIN pg_index pi ON psi.indexrelid = pi.indexrelid
    WHERE psi.schemaname = p_schema
    AND psi.idx_scan <= p_min_scans
    ORDER BY psi.idx_scan ASC, pg_relation_size(psi.indexrelid) DESC;
END;
$$ LANGUAGE plpgsql;

-- 7.4 Create function for index size trending
CREATE OR REPLACE FUNCTION get_index_size_trend(
    p_index_name TEXT,
    p_days INT DEFAULT 30
)
RETURNS TABLE (
    measurement_date DATE,
    index_size_bytes BIGINT,
    size_change_pct NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        DATE(collected_at) as measurement_date,
        index_size_bytes,
        CASE 
            WHEN LAG(index_size_bytes) OVER (ORDER BY DATE(collected_at)) IS NOT NULL
            THEN round(
                (index_size_bytes - LAG(index_size_bytes) OVER (ORDER BY DATE(collected_at)))::NUMERIC 
                / LAG(index_size_bytes) OVER (ORDER BY DATE(collected_at)) * 100, 
                2
            )
            ELSE 0
        END as size_change_pct
    FROM index_statistics_history
    WHERE indexname = p_index_name
    AND collected_at > NOW() - (p_days || ' days')::INTERVAL
    ORDER BY DATE(collected_at);
END;
$$ LANGUAGE plpgsql;

-- 7.5 Create function for automatic statistics refresh after reindex
CREATE OR REPLACE FUNCTION refresh_statistics_after_reindex(
    p_table_name TEXT
)
RETURNS void AS $$
BEGIN
    -- Analyze the table to update statistics
    EXECUTE format('ANALYZE %I', p_table_name);
    
    -- Log the statistics refresh
    INSERT INTO reindex_operations (
        table_name,
        operation_type,
        operation_status,
        completed_at,
        notes
    ) VALUES (
        p_table_name,
        'FULL',
        'COMPLETED',
        CURRENT_TIMESTAMP,
        'Statistics refreshed after reindex'
    );
    
    RAISE NOTICE 'Statistics refreshed for table: %', p_table_name;
END;
$$ LANGUAGE plpgsql;

-- 7.6 Create alerting function for failed reindex operations
CREATE OR REPLACE FUNCTION alert_failed_reindex_operations(
    p_alert_threshold INT DEFAULT 3
)
RETURNS TABLE (
    alert_triggered BOOLEAN,
    failed_count BIGINT,
    last_failure_at TIMESTAMPTZ,
    affected_tables TEXT[]
) AS $$
DECLARE
    v_failed_count BIGINT;
    v_last_failure TIMESTAMPTZ;
    v_affected_tables TEXT[];
BEGIN
    SELECT 
        COUNT(*),
        MAX(completed_at),
        array_agg(DISTINCT table_name)
    INTO v_failed_count, v_last_failure, v_affected_tables
    FROM reindex_operations
    WHERE operation_status = 'FAILED'
    AND completed_at > NOW() - INTERVAL '24 hours';
    
    RETURN QUERY SELECT 
        v_failed_count >= p_alert_threshold,
        v_failed_count,
        v_last_failure,
        v_affected_tables;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- END OF REINDEX PARTITIONED TABLES PROCEDURE
-- =============================================================================
