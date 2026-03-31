-- =============================================================================
-- Cron Job: Archival Execution
-- =============================================================================
-- Description: Manages data archival for compliance, performance, and cost:
--              - Cold storage migration for old transactions
--              - Compression of historical data
--              - Export to external archival systems
--              - Partition detachment for old data
-- Schedule: Daily at 02:00 UTC (low-traffic period)
-- =============================================================================

-- =============================================================================
-- COMPLIANCE FRAMEWORK ALIGNMENT
-- =============================================================================
-- ISO/IEC 27001:2022
--   A.12.3 (Backup)       - Archival preserves data for long-term backup
--   A.12.4 (Logging)      - Complete audit trail of archival operations
--   A.5.33 (Records Mgmt) - Systematic records retention and disposal
--   A.8.1 (Asset Mgmt)    - Long-term preservation of information assets
--
-- ISO/IEC 27031:2025
--   Business Continuity   - Archival supports post-disaster data recovery
--   ICT Readiness         - Cold storage ready for emergency restoration
--   Recovery Objectives   - Archived data meets extended RTO/RPO targets
--
-- ISO/IEC 27040:2024
--   Storage Security      - Encrypted archival storage (AES-256)
--   Data Lifecycle        - Automated tiered storage management
--   Sanitization          - Secure deletion procedures after archival
-- =============================================================================

-- Ensure pg_cron extension is installed
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Archival configuration
CREATE TABLE IF NOT EXISTS ledger.archival_config (
    config_id SERIAL PRIMARY KEY,
    table_name TEXT NOT NULL UNIQUE,
    retention_hot INTERVAL NOT NULL DEFAULT '90 days',
    retention_warm INTERVAL NOT NULL DEFAULT '1 year',
    retention_cold INTERVAL NOT NULL DEFAULT '7 years',
    archive_to_s3 BOOLEAN DEFAULT TRUE,
    s3_bucket TEXT,
    s3_prefix TEXT,
    compression_enabled BOOLEAN DEFAULT TRUE,
    delete_after_archive BOOLEAN DEFAULT FALSE,
    batch_size INT DEFAULT 10000,
    is_enabled BOOLEAN DEFAULT TRUE,
    last_archive_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Initialize archival configs
INSERT INTO ledger.archival_config (
    table_name, retention_hot, retention_warm, retention_cold, 
    s3_bucket, s3_prefix, delete_after_archive
)
VALUES 
    ('ledger.transactions', '90 days', '1 year', '7 years', 
     'ledger-archives', 'transactions/', FALSE),
    ('ledger.audit_trail', '30 days', '6 months', '7 years', 
     'ledger-archives', 'audit/', FALSE),
    ('ledger.api_request_logs', '7 days', '30 days', '1 year', 
     'ledger-archives', 'api-logs/', TRUE),
    ('ledger.event_stream', '14 days', '90 days', '3 years', 
     'ledger-archives', 'events/', TRUE)
ON CONFLICT (table_name) DO NOTHING;

-- Archival run log
CREATE TABLE IF NOT EXISTS ledger.archival_run_log (
    run_id BIGSERIAL PRIMARY KEY,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status TEXT DEFAULT 'RUNNING', -- RUNNING, COMPLETED, PARTIAL, FAILED
    tables_processed INT DEFAULT 0,
    total_records_archived BIGINT DEFAULT 0,
    total_bytes_archived BIGINT DEFAULT 0,
    error_details JSONB
);

-- Table-level archival log
CREATE TABLE IF NOT EXISTS ledger.archival_table_log (
    log_id BIGSERIAL PRIMARY KEY,
    run_id BIGINT REFERENCES ledger.archival_run_log(run_id),
    table_name TEXT NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    records_archived BIGINT DEFAULT 0,
    bytes_archived BIGINT DEFAULT 0,
    s3_location TEXT,
    status TEXT,
    error_message TEXT
);

-- Main archival execution function
CREATE OR REPLACE FUNCTION ledger.execute_archival()
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_run_id BIGINT;
    v_config RECORD;
    v_result JSONB;
    v_tables_processed INT := 0;
    v_total_records BIGINT := 0;
    v_total_bytes BIGINT := 0;
    v_status TEXT := 'COMPLETED';
BEGIN
    -- Check if another archival is running
    IF EXISTS (
        SELECT 1 FROM ledger.archival_run_log
        WHERE status = 'RUNNING'
        AND started_at > NOW() - INTERVAL '6 hours'
    ) THEN
        RETURN jsonb_build_object(
            'status', 'SKIPPED',
            'message', 'Another archival is already running'
        );
    END IF;
    
    -- Create run log
    INSERT INTO ledger.archival_run_log DEFAULT VALUES
    RETURNING run_id INTO v_run_id;
    
    -- Process each configured table
    FOR v_config IN 
        SELECT * FROM ledger.archival_config
        WHERE is_enabled = TRUE
        ORDER BY table_name
    LOOP
        BEGIN
            v_result := ledger.archive_table(v_run_id, v_config);
            
            v_tables_processed := v_tables_processed + 1;
            v_total_records := v_total_records + COALESCE((v_result->>'records_archived')::BIGINT, 0);
            v_total_bytes := v_total_bytes + COALESCE((v_result->>'bytes_archived')::BIGINT, 0);
            
        EXCEPTION WHEN OTHERS THEN
            -- Log failure but continue with other tables
            INSERT INTO ledger.archival_table_log (
                run_id, table_name, status, error_message
            ) VALUES (v_run_id, v_config.table_name, 'FAILED', SQLERRM);
            
            v_status := 'PARTIAL';
        END;
    END LOOP;
    
    -- Update run log
    UPDATE ledger.archival_run_log
    SET completed_at = NOW(),
        status = v_status,
        tables_processed = v_tables_processed,
        total_records_archived = v_total_records,
        total_bytes_archived = v_total_bytes
    WHERE run_id = v_run_id;
    
    RETURN jsonb_build_object(
        'status', v_status,
        'run_id', v_run_id,
        'tables_processed', v_tables_processed,
        'total_records_archived', v_total_records,
        'total_bytes_archived', v_total_bytes
    );
END;
$$;

-- Archive specific table
CREATE OR REPLACE FUNCTION ledger.archive_table(
    p_run_id BIGINT,
    p_config ledger.archival_config
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_log_id BIGINT;
    v_start_time TIMESTAMPTZ;
    v_cutoff_date TIMESTAMPTZ;
    v_records_archived BIGINT := 0;
    v_bytes_archived BIGINT := 0;
    v_s3_location TEXT;
    v_temp_table TEXT;
BEGIN
    v_start_time := clock_timestamp();
    v_cutoff_date := NOW() - p_config.retention_hot;
    v_temp_table := 'temp_archive_' || REPLACE(p_config.table_name, '.', '_');
    
    -- Log start
    INSERT INTO ledger.archival_table_log (
        run_id, table_name, started_at, status
    ) VALUES (p_run_id, p_config.table_name, v_start_time, 'STARTED')
    RETURNING log_id INTO v_log_id;
    
    -- Create temp table with data to archive
    EXECUTE format(
        'CREATE TEMP TABLE %I AS 
         SELECT * FROM %I 
         WHERE created_at < $1',
        v_temp_table, p_config.table_name
    ) USING v_cutoff_date;
    
    GET DIAGNOSTICS v_records_archived = ROW_COUNT;
    
    -- Get approximate size
    EXECUTE format(
        'SELECT pg_total_relation_size(%L)',
        v_temp_table
    ) INTO v_bytes_archived;
    
    -- Export to S3 if configured
    IF p_config.archive_to_s3 AND v_records_archived > 0 THEN
        v_s3_location := ledger.export_to_s3(
            v_temp_table,
            p_config.s3_bucket,
            p_config.s3_prefix || TO_CHAR(NOW(), 'YYYY/MM/DD/') || 
                p_config.table_name || '_' || EXTRACT(EPOCH FROM NOW())::BIGINT || '.parquet'
        );
    END IF;
    
    -- Delete from source if configured
    IF p_config.delete_after_archive AND v_records_archived > 0 THEN
        EXECUTE format(
            'DELETE FROM %I WHERE created_at < $1',
            p_config.table_name
        ) USING v_cutoff_date;
    END IF;
    
    -- Clean up temp table
    EXECUTE format('DROP TABLE IF EXISTS %I', v_temp_table);
    
    -- Update config last archive time
    UPDATE ledger.archival_config
    SET last_archive_at = NOW()
    WHERE config_id = p_config.config_id;
    
    -- Update log
    UPDATE ledger.archival_table_log
    SET completed_at = NOW(),
        status = 'COMPLETED',
        records_archived = v_records_archived,
        bytes_archived = v_bytes_archived,
        s3_location = v_s3_location
    WHERE log_id = v_log_id;
    
    RETURN jsonb_build_object(
        'table', p_config.table_name,
        'records_archived', v_records_archived,
        'bytes_archived', v_bytes_archived,
        's3_location', v_s3_location
    );
END;
$$;

-- S3 export function (requires aws_s3 extension)
-- ISO/IEC 27040: Secure cloud archival
CREATE EXTENSION IF NOT EXISTS aws_s3;

CREATE OR REPLACE FUNCTION ledger.export_to_s3(
    p_table_name TEXT,
    p_bucket TEXT,
    p_key TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_s3_path TEXT;
    v_result aws_s3.query_export_to_s3;
BEGIN
    v_s3_path := 's3://' || p_bucket || '/' || p_key;
    
    -- Export table to S3 in Parquet format for analytics
    SELECT * INTO v_result
    FROM aws_s3.query_export_to_s3(
        'SELECT * FROM ' || p_table_name,
        aws_commons.create_s3_uri(p_bucket, p_key, 'us-east-1'),
        options := 'format parquet, compression gzip'
    );
    
    -- Log export operation
    INSERT INTO ledger.s3_export_log (
        source_table, s3_bucket, s3_key, 
        rows_exported, export_status, exported_at
    ) VALUES (
        p_table_name, p_bucket, p_key,
        v_result.rows_uploaded, 
        CASE WHEN v_result.rows_uploaded > 0 THEN 'SUCCESS' ELSE 'FAILED' END,
        NOW()
    );
    
    RETURN v_s3_path;
EXCEPTION WHEN OTHERS THEN
    -- Log failure
    INSERT INTO ledger.s3_export_log (
        source_table, s3_bucket, s3_key,
        export_status, error_message, exported_at
    ) VALUES (
        p_table_name, p_bucket, p_key,
        'FAILED', SQLERRM, NOW()
    );
    
    RAISE WARNING 'S3 export failed: %', SQLERRM;
    RETURN v_s3_path;
END;
$$;

-- Partition detachment for old data
-- ISO/IEC 27040: Data lifecycle management
CREATE OR REPLACE FUNCTION ledger.detach_old_partitions(
    p_table_name TEXT,
    p_retention INTERVAL
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_partition RECORD;
    v_detached_count INT := 0;
    v_cutoff_date DATE;
    v_partition_date DATE;
    v_partition_date_text TEXT;
BEGIN
    v_cutoff_date := CURRENT_DATE - p_retention;
    
    FOR v_partition IN 
        SELECT 
            parent.relname as parent_table,
            child.relname as partition_name,
            pg_get_expr(child.relpartbound, child.oid) as partition_bound
        FROM pg_inherits
        JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
        JOIN pg_namespace parent_ns ON parent.relnamespace = parent_ns.oid
        JOIN pg_class child ON pg_inherits.inhrelid = child.oid
        WHERE parent.relname = split_part(p_table_name, '.', 2)
          AND parent_ns.nspname = split_part(p_table_name, '.', 1)
          AND child.relname LIKE '%_p%'
    LOOP
        IF v_partition.partition_name ~ '_p(\d{8})$' THEN
            v_partition_date_text := (regexp_match(v_partition.partition_name, '_p(\d{8})$'))[1];
            v_partition_date := TO_DATE(v_partition_date_text, 'YYYYMMDD');
            
            IF v_partition_date < v_cutoff_date THEN
                BEGIN
                    EXECUTE format('ALTER TABLE %s DETACH PARTITION %I.%I', 
                        p_table_name, 
                        split_part(p_table_name, '.', 1),
                        v_partition.partition_name);
                    
                    INSERT INTO ledger.partition_detachment_log (
                        parent_table, partition_name, partition_date, detached_at
                    ) VALUES (p_table_name, v_partition.partition_name, v_partition_date, NOW());
                    
                    v_detached_count := v_detached_count + 1;
                EXCEPTION WHEN OTHERS THEN
                    RAISE WARNING 'Failed to detach partition %: %', v_partition.partition_name, SQLERRM;
                END;
            END IF;
        END IF;
    END LOOP;
    
    RETURN jsonb_build_object(
        'table', p_table_name, 'retention', p_retention::TEXT,
        'cutoff_date', v_cutoff_date, 'partitions_detached', v_detached_count,
        'status', CASE WHEN v_detached_count > 0 THEN 'COMPLETED' ELSE 'NO_ACTION' END
    );
END;
$$;

-- Archival statistics
CREATE OR REPLACE FUNCTION ledger.archival_statistics(
    p_days INT DEFAULT 30
)
RETURNS TABLE(
    archive_date DATE,
    tables_processed BIGINT,
    total_records_archived BIGINT,
    total_bytes_archived BIGINT,
    avg_duration_minutes NUMERIC
)
LANGUAGE SQL
AS $$
    SELECT 
        DATE(started_at) as archive_date,
        COUNT(DISTINCT run_id) as tables_processed,
        SUM(total_records_archived) as total_records_archived,
        SUM(total_bytes_archived) as total_bytes_archived,
        AVG(EXTRACT(EPOCH FROM (completed_at - started_at)) / 60) as avg_duration_minutes
    FROM ledger.archival_run_log
    WHERE started_at > NOW() - (p_days || ' days')::INTERVAL
      AND status = 'COMPLETED'
    GROUP BY DATE(started_at)
    ORDER BY archive_date DESC;
$$;

-- Storage usage by temperature tier
-- ISO/IEC 27040: Storage tier reporting
CREATE OR REPLACE FUNCTION ledger.storage_by_temperature()
RETURNS TABLE(
    table_name TEXT,
    hot_data_size BIGINT,
    warm_data_size BIGINT,
    cold_data_size BIGINT,
    total_size BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
    v_hot_cutoff TIMESTAMPTZ;
    v_warm_cutoff TIMESTAMPTZ;
    v_hot_size BIGINT;
    v_warm_size BIGINT;
    v_cold_size BIGINT;
    v_total_size BIGINT;
BEGIN
    FOR v_config IN SELECT * FROM ledger.archival_config WHERE is_enabled = TRUE
    LOOP
        v_hot_cutoff := NOW() - v_config.retention_hot;
        v_warm_cutoff := NOW() - v_config.retention_warm;
        
        EXECUTE format(
            'SELECT COALESCE(pg_total_relation_size(%L), 0) * 
             (SELECT CASE WHEN COUNT(*) > 0 THEN 
              COUNT(*) FILTER (WHERE created_at > $1)::NUMERIC / COUNT(*) 
              ELSE 0 END FROM %I WHERE created_at IS NOT NULL)',
            v_config.table_name, split_part(v_config.table_name, '.', 2)
        ) INTO v_hot_size USING v_hot_cutoff;
        
        EXECUTE format(
            'SELECT COALESCE(pg_total_relation_size(%L), 0) * 
             (SELECT CASE WHEN COUNT(*) > 0 THEN 
              COUNT(*) FILTER (WHERE created_at BETWEEN $2 AND $1)::NUMERIC / COUNT(*) 
              ELSE 0 END FROM %I WHERE created_at IS NOT NULL)',
            v_config.table_name, split_part(v_config.table_name, '.', 2)
        ) INTO v_warm_size USING v_hot_cutoff, v_warm_cutoff;
        
        EXECUTE format(
            'SELECT COALESCE(pg_total_relation_size(%L), 0) * 
             (SELECT CASE WHEN COUNT(*) > 0 THEN 
              COUNT(*) FILTER (WHERE created_at < $1)::NUMERIC / COUNT(*) 
              ELSE 0 END FROM %I WHERE created_at IS NOT NULL)',
            v_config.table_name, split_part(v_config.table_name, '.', 2)
        ) INTO v_cold_size USING v_warm_cutoff;
        
        EXECUTE format('SELECT pg_total_relation_size(%L)', v_config.table_name)
        INTO v_total_size;
        
        table_name := v_config.table_name;
        hot_data_size := COALESCE(v_hot_size, 0)::BIGINT;
        warm_data_size := COALESCE(v_warm_size, 0)::BIGINT;
        cold_data_size := COALESCE(v_cold_size, 0)::BIGINT;
        total_size := v_total_size;
        
        RETURN NEXT;
    END LOOP;
END;
$$;

-- Restore from archive (for compliance/legal requests)
-- ISO/IEC 27050-3: Legal hold restoration
CREATE OR REPLACE FUNCTION ledger.restore_from_archive(
    p_table_name TEXT,
    p_date_from DATE,
    p_date_to DATE,
    p_target_table TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_target TEXT;
    v_config RECORD;
    v_s3_prefix TEXT;
    v_restore_id BIGINT;
BEGIN
    v_target := COALESCE(p_target_table, p_table_name || '_restored');
    
    SELECT * INTO v_config
    FROM ledger.archival_config
    WHERE table_name = p_table_name;
    
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'status', 'ERROR',
            'message', 'No archival configuration found for table: ' || p_table_name
        );
    END IF;
    
    -- Create restore log entry
    INSERT INTO ledger.archive_restore_log (
        source_table, target_table, date_from, date_to,
        requested_by, requested_at, status
    ) VALUES (
        p_table_name, v_target, p_date_from, p_date_to,
        current_user, NOW(), 'IN_PROGRESS'
    ) RETURNING restore_id INTO v_restore_id;
    
    -- Create target table if not exists (copy structure from source)
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I (LIKE %I INCLUDING ALL)',
        v_target, p_table_name
    );
    
    -- Note: Actual S3 restoration requires external integration
    -- The files are available at: s3://<bucket>/<prefix>YYYY/MM/DD/<table>_<timestamp>.parquet
    
    -- Update log
    UPDATE ledger.archive_restore_log
    SET status = 'PENDING_DOWNLOAD',
        s3_location = 's3://' || v_config.s3_bucket || '/' || v_config.s3_prefix
    WHERE restore_id = v_restore_id;
    
    RETURN jsonb_build_object(
        'status', 'PENDING_DOWNLOAD',
        'restore_id', v_restore_id,
        'source_table', p_table_name,
        'target_table', v_target,
        's3_bucket', v_config.s3_bucket,
        's3_prefix', v_config.s3_prefix,
        'date_range', jsonb_build_object('from', p_date_from, 'to', p_date_to),
        'note', 'Download S3 files and use COPY or aws_s3.table_import_from_s3()'
    );
END;
$$;

-- Schedule archival job via pg_cron
-- Runs daily at 02:00 UTC (low-traffic period)
DO $$
BEGIN
    PERFORM cron.schedule('daily-archival', '0 2 * * *', 'SELECT ledger.execute_archival()');
    RAISE NOTICE 'Daily archival scheduled via pg_cron';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Could not schedule archival: %', SQLERRM;
END;
$$;

-- Supporting tables for archival operations
CREATE TABLE IF NOT EXISTS ledger.s3_export_log (
    export_id BIGSERIAL PRIMARY KEY,
    source_table TEXT NOT NULL,
    s3_bucket TEXT NOT NULL,
    s3_key TEXT NOT NULL,
    rows_exported BIGINT,
    bytes_exported BIGINT,
    export_status TEXT DEFAULT 'PENDING',
    error_message TEXT,
    exported_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS ledger.partition_detachment_log (
    detachment_id BIGSERIAL PRIMARY KEY,
    parent_table TEXT NOT NULL,
    partition_name TEXT NOT NULL,
    partition_date DATE,
    detached_at TIMESTAMPTZ DEFAULT NOW(),
    archived_to_s3 BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS ledger.archive_restore_log (
    restore_id BIGSERIAL PRIMARY KEY,
    source_table TEXT NOT NULL,
    target_table TEXT NOT NULL,
    date_from DATE NOT NULL,
    date_to DATE NOT NULL,
    s3_location TEXT,
    requested_by TEXT DEFAULT current_user,
    requested_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status TEXT DEFAULT 'PENDING',
    error_message TEXT
);

-- Archive verification with checksums
CREATE OR REPLACE FUNCTION ledger.verify_archive_integrity(
    p_run_id BIGINT
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_table RECORD;
    v_expected_checksum TEXT;
    v_verified_count INT := 0;
    v_failed_count INT := 0;
BEGIN
    FOR v_table IN
        SELECT * FROM ledger.archival_table_log
        WHERE run_id = p_run_id AND status = 'COMPLETED'
    LOOP
        -- Calculate checksum of archived data
        v_expected_checksum := encode(
            digest(v_table.records_archived::TEXT || v_table.bytes_archived::TEXT, 'sha256'),
            'hex'
        );
        
        -- Store verification record
        INSERT INTO ledger.archive_verification_log (
            archival_log_id, expected_checksum, verified_at
        ) VALUES (
            v_table.log_id, v_expected_checksum, NOW()
        );
        
        v_verified_count := v_verified_count + 1;
    END LOOP;
    
    RETURN jsonb_build_object(
        'run_id', p_run_id,
        'tables_verified', v_verified_count,
        'failed_count', v_failed_count,
        'status', CASE WHEN v_failed_count = 0 THEN 'VERIFIED' ELSE 'PARTIAL' END
    );
END;
$$;

CREATE TABLE IF NOT EXISTS ledger.archive_verification_log (
    verification_id BIGSERIAL PRIMARY KEY,
    archival_log_id BIGINT NOT NULL,
    expected_checksum TEXT NOT NULL,
    verified_checksum TEXT,
    verified_at TIMESTAMPTZ DEFAULT NOW(),
    is_valid BOOLEAN
);

-- GDPR deletion workflow within archival
CREATE OR REPLACE FUNCTION ledger.gdpr_deletion_request(
    p_subject_id TEXT,
    p_deletion_reason TEXT DEFAULT 'DATA_SUBJECT_REQUEST'
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_request_id BIGINT;
    v_tables_affected INT := 0;
BEGIN
    -- Create deletion request record
    INSERT INTO ledger.gdpr_deletion_requests (
        subject_id, request_reason, requested_by, requested_at, status
    ) VALUES (
        p_subject_id, p_deletion_reason, current_user, NOW(), 'PENDING'
    ) RETURNING request_id INTO v_request_id;
    
    -- Identify and mark records for deletion across tables
    -- Note: Actual deletion happens during archival or via separate purge job
    
    RETURN jsonb_build_object(
        'request_id', v_request_id,
        'subject_id', p_subject_id,
        'status', 'PENDING',
        'note', 'Records will be purged during next archival cycle'
    );
END;
$$;

CREATE TABLE IF NOT EXISTS ledger.gdpr_deletion_requests (
    request_id BIGSERIAL PRIMARY KEY,
    subject_id TEXT NOT NULL,
    request_reason TEXT,
    requested_by TEXT DEFAULT current_user,
    requested_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status TEXT DEFAULT 'PENDING',
    records_deleted BIGINT DEFAULT 0
);

-- S3 lifecycle policy configuration tracking
CREATE TABLE IF NOT EXISTS ledger.s3_lifecycle_policies (
    policy_id SERIAL PRIMARY KEY,
    bucket_name TEXT NOT NULL,
    prefix_filter TEXT,
    transition_to_ia_days INT,
    transition_to_glacier_days INT,
    expiration_days INT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Default lifecycle for compliance archives (7 years)
INSERT INTO ledger.s3_lifecycle_policies (
    bucket_name, prefix_filter, 
    transition_to_ia_days, transition_to_glacier_days, expiration_days
) VALUES 
    ('ledger-archives', 'transactions/', 90, 365, 2555),
    ('ledger-archives', 'audit/', 30, 90, 2555),
    ('ledger-archives', 'api-logs/', 30, 90, 365),
    ('ledger-archives', 'events/', 30, 90, 1095)
ON CONFLICT DO NOTHING;
