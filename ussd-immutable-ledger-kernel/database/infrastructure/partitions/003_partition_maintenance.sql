-- =============================================================================
-- PARTITION MAINTENANCE
-- Automated maintenance procedures for partition health
-- =============================================================================

-- =============================================================================
-- MAINTENANCE SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS maintenance;

COMMENT ON SCHEMA maintenance IS 'Schema for partition maintenance operations';

-- =============================================================================
-- MAINTENANCE LOG TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS maintenance.maintenance_log (
    id BIGSERIAL PRIMARY KEY,
    job_type VARCHAR(50) NOT NULL, -- PARTITION_MAINTENANCE, INDEX_REBUILD, STATS_UPDATE
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    schema_name VARCHAR(63),
    table_name VARCHAR(63),
    partition_name VARCHAR(128),
    status VARCHAR(20) DEFAULT 'RUNNING', -- RUNNING, SUCCESS, FAILED, SKIPPED
    details JSONB,
    error_message TEXT,
    duration_ms INTEGER
);

CREATE INDEX IF NOT EXISTS idx_maint_log_type 
ON maintenance.maintenance_log(job_type, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_maint_log_status 
ON maintenance.maintenance_log(status);

-- =============================================================================
-- MAINTENANCE CONFIGURATION
-- =============================================================================
CREATE TABLE IF NOT EXISTS maintenance.maintenance_config (
    id SERIAL PRIMARY KEY,
    job_type VARCHAR(50) NOT NULL UNIQUE,
    schedule_cron VARCHAR(100),
    is_enabled BOOLEAN DEFAULT TRUE,
    max_runtime_minutes INTEGER DEFAULT 60,
    retry_attempts INTEGER DEFAULT 3,
    notify_on_failure BOOLEAN DEFAULT TRUE,
    parameters JSONB DEFAULT '{}',
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ
);

INSERT INTO maintenance.maintenance_config (job_type, schedule_cron, parameters) VALUES
    ('PARTITION_MAINTENANCE', '0 2 * * *', '{"days_ahead": 30}'),
    ('INDEX_REBUILD', '0 3 * * 0', '{"min_bloat_percent": 30}'),
    ('STATS_UPDATE', '0 4 * * *', '{"analyze_threshold": 0.1}'),
    ('ARCHIVE_OLD_PARTITIONS', '0 1 * * *', '{"older_than_days": 90}'),
    ('VACUUM_PARTITIONS', '0 5 * * *', '{"vacuum_scale_factor": 0.2}')
ON CONFLICT (job_type) DO UPDATE SET
    schedule_cron = EXCLUDED.schedule_cron,
    parameters = EXCLUDED.parameters;

-- =============================================================================
-- FUNCTION: Analyze partition bloat
-- =============================================================================
CREATE OR REPLACE FUNCTION maintenance.analyze_partition_bloat(
    p_schema_name VARCHAR DEFAULT NULL,
    p_table_name VARCHAR DEFAULT NULL
)
RETURNS TABLE(
    schema_name VARCHAR,
    table_name VARCHAR,
    partition_name VARCHAR,
    estimated_rows BIGINT,
    table_size_bytes BIGINT,
    bloat_size_bytes BIGINT,
    bloat_percent NUMERIC
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    WITH table_stats AS (
        SELECT 
            schemaname::VARCHAR as schema_name,
            relname::VARCHAR as table_name,
            n_live_tup as estimated_rows,
            pg_total_relation_size(schemaname || '.' || relname) as table_size
        FROM pg_stat_user_tables
        WHERE (p_schema_name IS NULL OR schemaname = p_schema_name)
          AND (p_table_name IS NULL OR relname = p_table_name)
    ),
    bloat_estimate AS (
        SELECT 
            schemaname::VARCHAR,
            relname::VARCHAR,
            pg_relation_size(schemaname || '.' || relname) as relation_size,
            pg_relation_size(schemaname || '.' || relname) * 0.2 as bloat_estimate -- Simplified estimate
        FROM pg_stat_user_tables
        WHERE (p_schema_name IS NULL OR schemaname = p_schema_name)
          AND (p_table_name IS NULL OR relname = p_table_name)
    )
    SELECT 
        ts.schema_name::VARCHAR,
        ts.table_name::VARCHAR,
        ts.table_name::VARCHAR as partition_name,
        ts.estimated_rows,
        ts.table_size as table_size_bytes,
        be.bloat_estimate::BIGINT as bloat_size_bytes,
        CASE WHEN ts.table_size > 0 
            THEN ROUND((be.bloat_estimate / ts.table_size::NUMERIC) * 100, 2)
            ELSE 0 
        END as bloat_percent
    FROM table_stats ts
    JOIN bloat_estimate be ON (ts.schema_name = be.schemaname AND ts.table_name = be.relname)
    WHERE ts.table_size > 100000000 -- Only tables > 100MB
    ORDER BY be.bloat_estimate DESC;
END;
$$;

-- =============================================================================
-- FUNCTION: Rebuild partition indexes
-- =============================================================================
CREATE OR REPLACE FUNCTION maintenance.rebuild_partition_indexes(
    p_schema_name VARCHAR,
    p_table_name VARCHAR,
    p_min_bloat_percent NUMERIC DEFAULT 30
)
RETURNS TABLE(index_name TEXT, status TEXT, duration_ms INTEGER)
LANGUAGE plpgsql
AS $$
DECLARE
    v_start_time TIMESTAMPTZ;
    v_index RECORD;
BEGIN
    v_start_time := clock_timestamp();
    
    FOR v_index IN 
        SELECT 
            schemaname || '.' || indexrelname as full_index_name,
            indexrelname as idx_name
        FROM pg_stat_user_indexes
        WHERE schemaname = p_schema_name
          AND relname = p_table_name
    LOOP
        index_name := v_index.idx_name;
        
        BEGIN
            -- Reindex concurrently to avoid locks
            EXECUTE format('REINDEX INDEX CONCURRENTLY %s', v_index.full_index_name);
            
            status := 'SUCCESS';
            duration_ms := EXTRACT(MILLISECOND FROM clock_timestamp() - v_start_time)::INTEGER;
            
        EXCEPTION WHEN OTHERS THEN
            status := 'FAILED: ' || SQLERRM;
            duration_ms := EXTRACT(MILLISECOND FROM clock_timestamp() - v_start_time)::INTEGER;
        END;
        
        RETURN NEXT;
        v_start_time := clock_timestamp();
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Update partition statistics
-- =============================================================================
CREATE OR REPLACE FUNCTION maintenance.update_partition_stats(
    p_schema_name VARCHAR DEFAULT NULL,
    p_table_name VARCHAR DEFAULT NULL
)
RETURNS TABLE(schema_name TEXT, table_name TEXT, status TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_table RECORD;
BEGIN
    FOR v_table IN 
        SELECT schemaname, relname
        FROM pg_stat_user_tables
        WHERE (p_schema_name IS NULL OR schemaname = p_schema_name)
          AND (p_table_name IS NULL OR relname = p_table_name)
          AND n_tup_ins + n_tup_upd + n_tup_del > 0
        ORDER BY pg_total_relation_size(schemaname || '.' || relname) DESC
        LIMIT 100
    LOOP
        schema_name := v_table.schemaname;
        table_name := v_table.relname;
        
        BEGIN
            EXECUTE format('ANALYZE %I.%I', v_table.schemaname, v_table.relname);
            status := 'ANALYZED';
        EXCEPTION WHEN OTHERS THEN
            status := 'FAILED: ' || SQLERRM;
        END;
        
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Vacuum old partitions
-- =============================================================================
CREATE OR REPLACE FUNCTION maintenance.vacuum_partitions(
    p_schema_name VARCHAR,
    p_table_name VARCHAR,
    p_older_than_days INTEGER DEFAULT 7
)
RETURNS TABLE(partition_name TEXT, status TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_partition RECORD;
BEGIN
    FOR v_partition IN 
        SELECT pm.partition_schema, pm.partition_name
        FROM partition_mgmt.partition_metadata pm
        WHERE pm.parent_schema = p_schema_name
          AND pm.parent_table = p_table_name
          AND pm.range_to < NOW() - (p_older_than_days || ' days')::INTERVAL
          AND pm.is_active = TRUE
    LOOP
        partition_name := v_partition.partition_schema || '.' || v_partition.partition_name;
        
        BEGIN
            -- Vacuum analyze the partition
            EXECUTE format('VACUUM ANALYZE %I.%I', 
                v_partition.partition_schema, v_partition.partition_name);
            status := 'VACUUMED';
        EXCEPTION WHEN OTHERS THEN
            status := 'FAILED: ' || SQLERRM;
        END;
        
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Run full maintenance cycle
-- =============================================================================
CREATE OR REPLACE FUNCTION maintenance.run_maintenance_cycle()
RETURNS TABLE(job_type TEXT, started_at TIMESTAMPTZ, status TEXT, details JSONB)
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
    v_start_time TIMESTAMPTZ;
    v_log_id BIGINT;
    v_result JSONB;
BEGIN
    FOR v_config IN 
        SELECT * FROM maintenance.maintenance_config 
        WHERE is_enabled = TRUE
        ORDER BY job_type
    LOOP
        job_type := v_config.job_type;
        started_at := NOW();
        v_start_time := clock_timestamp();
        
        -- Log start
        INSERT INTO maintenance.maintenance_log (job_type, started_at)
        VALUES (v_config.job_type, started_at)
        RETURNING id INTO v_log_id;
        
        BEGIN
            CASE v_config.job_type
                WHEN 'PARTITION_MAINTENANCE' THEN
                    v_result := maintenance._maintain_all_partitions();
                    
                WHEN 'INDEX_REBUILD' THEN
                    v_result := maintenance._rebuild_all_indexes(
                        (v_config.parameters->>'min_bloat_percent')::NUMERIC
                    );
                    
                WHEN 'STATS_UPDATE' THEN
                    v_result := maintenance._update_all_stats();
                    
                WHEN 'ARCHIVE_OLD_PARTITIONS' THEN
                    v_result := maintenance._archive_all_old_partitions(
                        (v_config.parameters->>'older_than_days')::INTEGER
                    );
                    
                WHEN 'VACUUM_PARTITIONS' THEN
                    v_result := maintenance._vacuum_all_partitions();
                    
                ELSE
                    v_result := jsonb_build_object('message', 'Unknown job type');
            END CASE;
            
            status := 'SUCCESS';
            details := v_result;
            
            -- Update log
            UPDATE maintenance.maintenance_log
            SET completed_at = NOW(),
                status = 'SUCCESS',
                details = v_result,
                duration_ms = EXTRACT(MILLISECOND FROM clock_timestamp() - v_start_time)::INTEGER
            WHERE id = v_log_id;
            
        EXCEPTION WHEN OTHERS THEN
            status := 'FAILED';
            details := jsonb_build_object('error', SQLERRM);
            
            UPDATE maintenance.maintenance_log
            SET completed_at = NOW(),
                status = 'FAILED',
                error_message = SQLERRM,
                duration_ms = EXTRACT(MILLISECOND FROM clock_timestamp() - v_start_time)::INTEGER
            WHERE id = v_log_id;
        END;
        
        -- Update next run
        UPDATE maintenance.maintenance_config
        SET last_run_at = started_at,
            next_run_at = started_at + INTERVAL '1 day'
        WHERE job_type = v_config.job_type;
        
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- HELPER FUNCTIONS (private)
-- =============================================================================

CREATE OR REPLACE FUNCTION maintenance._maintain_all_partitions()
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_result JSONB := '[]'::JSONB;
    v_config RECORD;
    v_partition_result TEXT;
BEGIN
    FOR v_config IN SELECT * FROM partition_mgmt.partition_config WHERE is_active = TRUE LOOP
        FOR i IN 1..v_config.premake LOOP
            v_partition_result := partition_mgmt.create_future_partition(
                v_config.schema_name, v_config.table_name, i
            );
            v_result := v_result || jsonb_build_object(
                'table', v_config.schema_name || '.' || v_config.table_name,
                'action', v_partition_result
            );
        END LOOP;
    END LOOP;
    
    RETURN v_result;
END;
$$;

CREATE OR REPLACE FUNCTION maintenance._rebuild_all_indexes(p_min_bloat NUMERIC)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_result JSONB := '[]'::JSONB;
    v_bloat RECORD;
BEGIN
    FOR v_bloat IN 
        SELECT * FROM maintenance.analyze_partition_bloat() 
        WHERE bloat_percent >= p_min_bloat
    LOOP
        v_result := v_result || jsonb_build_object(
            'partition', v_bloat.partition_name,
            'bloat_percent', v_bloat.bloat_percent
        );
    END LOOP;
    
    RETURN v_result;
END;
$$;

CREATE OR REPLACE FUNCTION maintenance._update_all_stats()
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER := 0;
BEGIN
    SELECT COUNT(*) INTO v_count
    FROM maintenance.update_partition_stats();
    
    RETURN jsonb_build_object('tables_analyzed', v_count);
END;
$$;

CREATE OR REPLACE FUNCTION maintenance._archive_all_old_partitions(p_days INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_result JSONB := '[]'::JSONB;
    v_config RECORD;
    v_archive RECORD;
BEGIN
    FOR v_config IN SELECT * FROM archive_mgmt.archive_config WHERE is_active = TRUE LOOP
        FOR v_archive IN 
            SELECT * FROM archive_mgmt.archive_old_partitions(
                v_config.source_schema, v_config.source_table, p_days
            )
        LOOP
            v_result := v_result || jsonb_build_object(
                'partition', v_archive.partition_name,
                'status', v_archive.status,
                'rows', v_archive.rows_archived
            );
        END LOOP;
    END LOOP;
    
    RETURN v_result;
END;
$$;

CREATE OR REPLACE FUNCTION maintenance._vacuum_all_partitions()
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER := 0;
BEGIN
    -- Count partitions that would be vacuumed
    SELECT COUNT(*) INTO v_count
    FROM partition_mgmt.partition_metadata
    WHERE range_to < NOW() - INTERVAL '7 days'
      AND is_active = TRUE;
    
    RETURN jsonb_build_object('partitions_to_vacuum', v_count);
END;
$$;

-- =============================================================================
-- VIEW: Maintenance status
-- =============================================================================
CREATE OR REPLACE VIEW maintenance.maintenance_status AS
SELECT 
    mc.job_type,
    mc.schedule_cron,
    mc.is_enabled,
    mc.last_run_at,
    mc.next_run_at,
    COUNT(ml.id) FILTER (WHERE ml.status = 'SUCCESS') as success_count,
    COUNT(ml.id) FILTER (WHERE ml.status = 'FAILED') as failure_count,
    MAX(ml.started_at) FILTER (WHERE ml.status = 'FAILED') as last_failure_at
FROM maintenance.maintenance_config mc
LEFT JOIN maintenance.maintenance_log ml ON ml.job_type = mc.job_type
GROUP BY mc.job_type, mc.schedule_cron, mc.is_enabled, mc.last_run_at, mc.next_run_at;

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA maintenance TO maintenance_admin;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA maintenance TO maintenance_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA maintenance TO maintenance_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA maintenance TO maintenance_admin;
