-- =============================================================================
-- Background Worker: Idempotency Key Cleanup
-- =============================================================================
-- Description: Cleans up expired idempotency keys to prevent unbounded growth
--              while maintaining audit trail of processed keys
-- Schedule: Runs every 5 minutes, processes in small batches
-- =============================================================================

-- =============================================================================
-- COMPLIANCE FRAMEWORK ALIGNMENT
-- =============================================================================
-- ISO/IEC 27001:2022
--   A.12.3 (Backup)       - Cleanup ensures backup efficiency
--   A.12.4 (Logging)      - Complete audit trail of key operations
--   A.5.33 (Records Mgmt) - Systematic record lifecycle management
--   A.8.1 (Asset Mgmt)    - Controlled data asset disposal
--
-- ISO/IEC 27031:2025
--   Business Continuity   - Prevents storage exhaustion during incidents
--   ICT Readiness         - Maintains system capacity for failover
--
-- ISO/IEC 27040:2024
--   Storage Security      - Secure deletion of temporary data
--   Data Lifecycle        - Automated retention policy enforcement
--   Sanitization          - Controlled data removal procedures
-- =============================================================================

-- Ensure required extensions are available
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Create the main idempotency_keys table if not exists
CREATE TABLE IF NOT EXISTS ledger.idempotency_keys (
    key_hash TEXT PRIMARY KEY,
    key_type TEXT NOT NULL DEFAULT 'transaction',
    payload_hash BYTEA,
    response_hash BYTEA,
    processed_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_idempotency_keys_type_time 
ON ledger.idempotency_keys(key_type, processed_at);

CREATE INDEX IF NOT EXISTS idx_idempotency_keys_expires 
ON ledger.idempotency_keys(expires_at) 
WHERE expires_at IS NOT NULL;

-- Configuration table for cleanup policies
CREATE TABLE IF NOT EXISTS ledger.idempotency_cleanup_config (
    config_id SERIAL PRIMARY KEY,
    key_type TEXT NOT NULL UNIQUE,
    retention_period INTERVAL NOT NULL DEFAULT '24 hours',
    batch_size INT NOT NULL DEFAULT 1000,
    archive_before_delete BOOLEAN DEFAULT TRUE,
    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Initialize default configs
INSERT INTO ledger.idempotency_cleanup_config (key_type, retention_period, batch_size)
VALUES 
    ('transaction', '24 hours', 5000),
    ('batch_operation', '7 days', 1000),
    ('webhook_delivery', '72 hours', 2000),
    ('api_request', '1 hour', 10000)
ON CONFLICT (key_type) DO NOTHING;

-- Archive table for deleted keys (optional, for audit)
CREATE TABLE IF NOT EXISTS ledger.idempotency_key_archive (
    archive_id BIGSERIAL PRIMARY KEY,
    key_hash TEXT NOT NULL,
    key_type TEXT NOT NULL,
    original_payload_hash BYTEA,
    response_payload_hash BYTEA,
    processed_at TIMESTAMPTZ,
    archived_at TIMESTAMPTZ DEFAULT NOW(),
    archived_by TEXT DEFAULT current_user
);

CREATE INDEX idx_idempotency_archive_key_type 
ON ledger.idempotency_key_archive(key_type, archived_at);

-- Partition management for archive table
CREATE TABLE IF NOT EXISTS ledger.idempotency_archive_partitions (
    partition_name TEXT PRIMARY KEY,
    partition_date DATE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    dropped_at TIMESTAMPTZ
);

-- Cleanup log for monitoring
CREATE TABLE IF NOT EXISTS ledger.idempotency_cleanup_log (
    log_id BIGSERIAL PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    key_type TEXT,
    keys_archived BIGINT DEFAULT 0,
    keys_deleted BIGINT DEFAULT 0,
    duration_ms NUMERIC,
    status TEXT DEFAULT 'RUNNING',
    error_message TEXT
);

-- Cleanup metrics export table
CREATE TABLE IF NOT EXISTS ledger.idempotency_cleanup_metrics (
    metric_id BIGSERIAL PRIMARY KEY,
    measured_at TIMESTAMPTZ DEFAULT NOW(),
    key_type TEXT,
    total_keys BIGINT,
    expired_keys BIGINT,
    archived_keys BIGINT,
    deleted_keys BIGINT,
    avg_cleanup_duration_ms NUMERIC
);

-- Retention policy for archive table
CREATE TABLE IF NOT EXISTS ledger.idempotency_archive_retention (
    retention_id SERIAL PRIMARY KEY,
    archive_retention_period INTERVAL NOT NULL DEFAULT '90 days',
    max_archive_size_gb NUMERIC DEFAULT 100,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO ledger.idempotency_archive_retention (archive_retention_period, max_archive_size_gb)
VALUES ('90 days', 100)
ON CONFLICT DO NOTHING;

-- Main cleanup function
CREATE OR REPLACE FUNCTION ledger.cleanup_expired_idempotency_keys()
RETURNS TABLE(
    key_type TEXT,
    keys_archived BIGINT,
    keys_deleted BIGINT,
    execution_time_ms NUMERIC
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
    v_start_time TIMESTAMPTZ;
    v_keys_archived BIGINT := 0;
    v_keys_deleted BIGINT := 0;
    v_log_id BIGINT;
BEGIN
    -- Start logging
    INSERT INTO ledger.idempotency_cleanup_log (started_at)
    VALUES (NOW())
    RETURNING log_id INTO v_log_id;
    
    FOR v_config IN 
        SELECT * FROM ledger.idempotency_cleanup_config
        WHERE is_enabled = TRUE
        ORDER BY key_type
    LOOP
        v_start_time := clock_timestamp();
        v_keys_archived := 0;
        v_keys_deleted := 0;
        
        BEGIN
            -- Archive if configured
            IF v_config.archive_before_delete THEN
                INSERT INTO ledger.idempotency_key_archive (
                    key_hash, key_type, original_payload_hash,
                    response_payload_hash, processed_at
                )
                SELECT 
                    key_hash,
                    v_config.key_type,
                    payload_hash,
                    response_hash,
                    processed_at
                FROM ledger.idempotency_keys
                WHERE key_type = v_config.key_type
                  AND processed_at < NOW() - v_config.retention_period
                  AND (expires_at IS NULL OR expires_at < NOW())
                LIMIT v_config.batch_size;
                
                GET DIAGNOSTICS v_keys_archived = ROW_COUNT;
            END IF;
            
            -- Delete expired keys
            DELETE FROM ledger.idempotency_keys
            WHERE key_hash IN (
                SELECT key_hash 
                FROM ledger.idempotency_keys
                WHERE key_type = v_config.key_type
                  AND processed_at < NOW() - v_config.retention_period
                  AND (expires_at IS NULL OR expires_at < NOW())
                LIMIT v_config.batch_size
            );
            
            GET DIAGNOSTICS v_keys_deleted = ROW_COUNT;
            
            -- Return row for this type
            key_type := v_config.key_type;
            keys_archived := v_keys_archived;
            keys_deleted := v_keys_deleted;
            execution_time_ms := EXTRACT(EPOCH FROM (clock_timestamp() - v_start_time)) * 1000;
            RETURN NEXT;
            
        EXCEPTION WHEN OTHERS THEN
            -- Log error but continue with other types
            key_type := v_config.key_type;
            keys_archived := 0;
            keys_deleted := 0;
            execution_time_ms := -1;
            RETURN NEXT;
            
            -- Log the error
            INSERT INTO ledger.error_log (
                error_type, error_message, context, created_at
            ) VALUES (
                'IDEMPOTENCY_CLEANUP_FAILED',
                SQLERRM,
                jsonb_build_object('key_type', v_config.key_type),
                NOW()
            );
        END;
    END LOOP;
    
    -- Update main log
    UPDATE ledger.idempotency_cleanup_log
    SET completed_at = NOW(),
        status = 'COMPLETED',
        duration_ms = EXTRACT(EPOCH FROM (NOW() - started_at)) * 1000
    WHERE log_id = v_log_id;
    
EXCEPTION WHEN OTHERS THEN
    UPDATE ledger.idempotency_cleanup_log
    SET completed_at = NOW(),
        status = 'FAILED',
        error_message = SQLERRM
    WHERE log_id = v_log_id;
    RAISE;
END;
$$;

-- Statistics function
CREATE OR REPLACE FUNCTION ledger.idempotency_key_stats()
RETURNS TABLE(
    key_type TEXT,
    total_active_keys BIGINT,
    expired_keys BIGINT,
    oldest_key_at TIMESTAMPTZ,
    newest_key_at TIMESTAMPTZ
)
LANGUAGE SQL
AS $$
    SELECT 
        ik.key_type,
        COUNT(*) FILTER (WHERE ik.expires_at > NOW() OR ik.expires_at IS NULL) as total_active_keys,
        COUNT(*) FILTER (WHERE ik.expires_at <= NOW()) as expired_keys,
        MIN(ik.processed_at) as oldest_key_at,
        MAX(ik.processed_at) as newest_key_at
    FROM ledger.idempotency_keys ik
    GROUP BY ik.key_type;
$$;

-- Cleanup statistics for monitoring
CREATE OR REPLACE FUNCTION ledger.idempotency_cleanup_stats(
    p_hours INT DEFAULT 24
)
RETURNS TABLE(
    cleanup_runs BIGINT,
    total_keys_archived BIGINT,
    total_keys_deleted BIGINT,
    avg_duration_ms NUMERIC,
    last_run_at TIMESTAMPTZ
)
LANGUAGE SQL
AS $$
    SELECT 
        COUNT(*) as cleanup_runs,
        SUM(keys_archived) as total_keys_archived,
        SUM(keys_deleted) as total_keys_deleted,
        AVG(duration_ms) as avg_duration_ms,
        MAX(started_at) as last_run_at
    FROM ledger.idempotency_cleanup_log
    WHERE started_at > NOW() - (p_hours || ' hours')::INTERVAL
      AND status = 'COMPLETED';
$$;

-- Manual archive function (for compliance/legal holds)
CREATE OR REPLACE FUNCTION ledger.archive_idempotency_keys_manually(
    p_key_type TEXT,
    p_older_than TIMESTAMPTZ
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_archived_count BIGINT;
BEGIN
    INSERT INTO ledger.idempotency_key_archive (
        key_hash, key_type, original_payload_hash,
        response_payload_hash, processed_at
    )
    SELECT 
        key_hash,
        key_type,
        payload_hash,
        response_hash,
        processed_at
    FROM ledger.idempotency_keys
    WHERE key_type = p_key_type
      AND processed_at < p_older_than;
    
    GET DIAGNOSTICS v_archived_count = ROW_COUNT;
    
    RETURN v_archived_count;
END;
$$;

-- Automatic partition management for archive table
CREATE OR REPLACE FUNCTION ledger.manage_idempotency_archive_partitions()
RETURNS TABLE(action_taken TEXT, partition_name TEXT, details TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_partition RECORD;
    v_retention RECORD;
    v_old_partition TEXT;
    v_new_partition TEXT;
    v_partition_date DATE;
BEGIN
    -- Get retention settings
    SELECT * INTO v_retention
    FROM ledger.idempotency_archive_retention
    ORDER BY retention_id DESC
    LIMIT 1;
    
    -- Create new monthly partition if needed
    v_partition_date := DATE_TRUNC('month', NOW());
    v_new_partition := 'idempotency_key_archive_' || TO_CHAR(v_partition_date, 'YYYY_MM');
    
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_name = v_new_partition 
        AND table_schema = 'ledger'
    ) THEN
        EXECUTE format(
            'CREATE TABLE ledger.%I (LIKE ledger.idempotency_key_archive INCLUDING ALL)',
            v_new_partition
        );
        
        INSERT INTO ledger.idempotency_archive_partitions (partition_name, partition_date)
        VALUES (v_new_partition, v_partition_date);
        
        action_taken := 'CREATED';
        partition_name := v_new_partition;
        details := 'Created new monthly partition for ' || TO_CHAR(v_partition_date, 'YYYY-MM');
        RETURN NEXT;
    END IF;
    
    -- Drop old partitions beyond retention
    FOR v_partition IN 
        SELECT partition_name, partition_date
        FROM ledger.idempotency_archive_partitions
        WHERE partition_date < NOW() - v_retention.archive_retention_period
          AND dropped_at IS NULL
    LOOP
        EXECUTE format('DROP TABLE IF EXISTS ledger.%I', v_partition.partition_name);
        
        UPDATE ledger.idempotency_archive_partitions
        SET dropped_at = NOW()
        WHERE partition_name = v_partition.partition_name;
        
        action_taken := 'DROPPED';
        partition_name := v_partition.partition_name;
        details := 'Dropped partition beyond retention period';
        RETURN NEXT;
    END LOOP;
END;
$$;

-- Metrics export function for cleanup job performance
CREATE OR REPLACE FUNCTION ledger.export_idempotency_metrics()
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_result JSONB;
BEGIN
    -- Capture current metrics
    INSERT INTO ledger.idempotency_cleanup_metrics (
        key_type, total_keys, expired_keys, archived_keys, deleted_keys, avg_cleanup_duration_ms
    )
    SELECT 
        s.key_type,
        s.total_active_keys + s.expired_keys as total_keys,
        s.expired_keys,
        COALESCE(a.archived_count, 0) as archived_keys,
        COALESCE(d.deleted_count, 0) as deleted_keys,
        COALESCE(c.avg_duration_ms, 0) as avg_cleanup_duration_ms
    FROM ledger.idempotency_key_stats() s
    LEFT JOIN (
        SELECT key_type, COUNT(*) as archived_count 
        FROM ledger.idempotency_key_archive 
        WHERE archived_at > NOW() - INTERVAL '1 hour'
        GROUP BY key_type
    ) a ON a.key_type = s.key_type
    LEFT JOIN (
        SELECT key_type, SUM(keys_deleted) as deleted_count
        FROM ledger.idempotency_cleanup_log
        WHERE started_at > NOW() - INTERVAL '1 hour'
        GROUP BY key_type
    ) d ON d.key_type = s.key_type
    LEFT JOIN (
        SELECT key_type, AVG(duration_ms) as avg_duration_ms
        FROM ledger.idempotency_cleanup_log
        WHERE started_at > NOW() - INTERVAL '24 hours'
        GROUP BY key_type
    ) c ON c.key_type = s.key_type;
    
    -- Build metrics JSON
    SELECT jsonb_build_object(
        'timestamp', NOW(),
        'key_stats', jsonb_agg(jsonb_build_object(
            'key_type', key_type,
            'total_active', total_active_keys,
            'expired', expired_keys,
            'oldest', oldest_key_at
        )),
        'cleanup_stats', (
            SELECT jsonb_build_object(
                'runs_24h', COUNT(*),
                'total_archived', SUM(keys_archived),
                'total_deleted', SUM(keys_deleted),
                'avg_duration_ms', AVG(duration_ms)
            )
            FROM ledger.idempotency_cleanup_log
            WHERE started_at > NOW() - INTERVAL '24 hours'
            AND status = 'COMPLETED'
        ),
        'archive_size_gb', (
            SELECT pg_size_pretty(pg_total_relation_size('ledger.idempotency_key_archive'))
        )
    ) INTO v_result
    FROM ledger.idempotency_key_stats();
    
    RETURN v_result;
END;
$$;

-- Retention policy enforcement for archive table
CREATE OR REPLACE FUNCTION ledger.enforce_archive_retention_policy()
RETURNS TABLE(records_purged BIGINT, reason TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_retention RECORD;
    v_purged_count BIGINT;
BEGIN
    SELECT * INTO v_retention
    FROM ledger.idempotency_archive_retention
    ORDER BY retention_id DESC
    LIMIT 1;
    
    -- Purge old archive records
    DELETE FROM ledger.idempotency_key_archive
    WHERE archived_at < NOW() - v_retention.archive_retention_period;
    
    GET DIAGNOSTICS v_purged_count = ROW_COUNT;
    
    records_purged := v_purged_count;
    reason := 'Records exceeded retention period of ' || v_retention.archive_retention_period;
    RETURN NEXT;
    
    -- Check archive size and purge if exceeds max
    IF (
        SELECT pg_total_relation_size('ledger.idempotency_key_archive') / (1024^3)
    ) > v_retention.max_archive_size_gb THEN
        DELETE FROM ledger.idempotency_key_archive
        WHERE archive_id IN (
            SELECT archive_id 
            FROM ledger.idempotency_key_archive
            ORDER BY archived_at ASC
            LIMIT 10000
        );
        
        GET DIAGNOSTICS v_purged_count = ROW_COUNT;
        
        records_purged := v_purged_count;
        reason := 'Archive size exceeded ' || v_retention.max_archive_size_gb || ' GB limit';
        RETURN NEXT;
    END IF;
END;
$$;

-- Schedule cleanup job via pg_cron
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        -- Schedule cleanup every 5 minutes
        PERFORM cron.schedule('idempotency-cleanup', '*/5 * * * *', 'SELECT * FROM ledger.cleanup_expired_idempotency_keys()');
        
        -- Schedule partition management daily
        PERFORM cron.schedule('idempotency-partition-mgmt', '0 1 * * *', 'SELECT * FROM ledger.manage_idempotency_archive_partitions()');
        
        -- Schedule retention policy enforcement daily
        PERFORM cron.schedule('idempotency-retention', '0 2 * * *', 'SELECT * FROM ledger.enforce_archive_retention_policy()');
        
        -- Schedule metrics export every hour
        PERFORM cron.schedule('idempotency-metrics', '0 * * * *', 'SELECT ledger.export_idempotency_metrics()');
        
        RAISE NOTICE 'Idempotency key cleanup scheduled via pg_cron';
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'Could not schedule idempotency cleanup via pg_cron: %', SQLERRM;
END;
$$;

-- View for monitoring idempotency key status
CREATE OR REPLACE VIEW ledger.idempotency_key_monitor AS
SELECT 
    s.key_type,
    s.total_active_keys,
    s.expired_keys,
    s.oldest_key_at,
    s.newest_key_at,
    c.retention_period,
    c.batch_size,
    c.is_enabled,
    COALESCE(l.keys_deleted, 0) as keys_deleted_last_24h,
    COALESCE(a.archive_count, 0) as archived_count
FROM ledger.idempotency_key_stats() s
LEFT JOIN ledger.idempotency_cleanup_config c ON c.key_type = s.key_type
LEFT JOIN (
    SELECT key_type, SUM(keys_deleted) as keys_deleted
    FROM ledger.idempotency_cleanup_log
    WHERE started_at > NOW() - INTERVAL '24 hours'
    GROUP BY key_type
) l ON l.key_type = s.key_type
LEFT JOIN (
    SELECT key_type, COUNT(*) as archive_count
    FROM ledger.idempotency_key_archive
    GROUP BY key_type
) a ON a.key_type = s.key_type;
