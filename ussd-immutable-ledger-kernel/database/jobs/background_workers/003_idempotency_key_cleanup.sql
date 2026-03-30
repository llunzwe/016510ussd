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

-- TODO: Ensure required extensions are available
-- CREATE EXTENSION IF NOT EXISTS pg_cron;

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

-- TODO: Create the main idempotency_keys table if not exists
/*
CREATE TABLE IF NOT EXISTS ledger.idempotency_keys (
    key_hash TEXT PRIMARY KEY,
    key_type TEXT NOT NULL DEFAULT 'transaction',
    payload_hash BYTEA,
    response_hash BYTEA,
    processed_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    metadata JSONB
);

CREATE INDEX idx_idempotency_keys_type_time 
ON ledger.idempotency_keys(key_type, processed_at);

CREATE INDEX idx_idempotency_keys_expires 
ON ledger.idempotency_keys(expires_at) 
WHERE expires_at IS NOT NULL;
*/

-- TODO: Schedule cleanup job via pg_cron
-- SELECT cron.schedule('idempotency-cleanup', '*/5 * * * *', 'SELECT * FROM ledger.cleanup_expired_idempotency_keys()');

-- TODO: Implement automatic partition management for archive table
-- TODO: Add metrics export for cleanup job performance
-- TODO: Create retention policy for archive table itself
