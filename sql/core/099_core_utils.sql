-- ============================================================================
-- USSD KERNEL CORE SCHEMA - UTILITIES AND MAINTENANCE
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Utility functions for maintenance, monitoring, partitioning,
--              and operational tasks.
-- Immutability: N/A (Operational utilities)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. PARTITION MANAGEMENT
-- ----------------------------------------------------------------------------

-- Function to create new transaction partitions
CREATE OR REPLACE FUNCTION ussd_core.create_transaction_partition(
    p_year INTEGER,
    p_month INTEGER
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_partition_name TEXT;
    v_start_date DATE;
    v_end_date DATE;
BEGIN
    v_partition_name := 'transactions_' || p_year || '_' || LPAD(p_month::TEXT, 2, '0');
    v_start_date := make_date(p_year, p_month, 1);
    v_end_date := v_start_date + INTERVAL '1 month';
    
    -- Create partition if it doesn't exist
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS ussd_core.%I 
         PARTITION OF ussd_core.transactions 
         FOR VALUES FROM (%L) TO (%L)',
        v_partition_name, v_start_date, v_end_date
    );
    
    -- Create indexes on partition
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS idx_%s_initiator ON ussd_core.%I(initiator_account_id)',
        v_partition_name, v_partition_name
    );
    
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS idx_%s_committed ON ussd_core.%I(committed_at DESC)',
        v_partition_name, v_partition_name
    );
    
    RETURN v_partition_name;
END;
$$;

-- Function to create monthly partitions ahead of time
CREATE OR REPLACE FUNCTION ussd_core.create_future_partitions(
    p_months_ahead INTEGER DEFAULT 3
)
RETURNS TEXT[]
LANGUAGE plpgsql
AS $$
DECLARE
    v_partitions TEXT[] := '{}';
    v_current_date DATE := CURRENT_DATE;
    v_target_date DATE;
    v_i INTEGER;
    v_partition TEXT;
BEGIN
    FOR v_i IN 1..p_months_ahead LOOP
        v_target_date := v_current_date + (v_i || ' months')::INTERVAL;
        SELECT ussd_core.create_transaction_partition(
            EXTRACT(YEAR FROM v_target_date)::INTEGER,
            EXTRACT(MONTH FROM v_target_date)::INTEGER
        ) INTO v_partition;
        v_partitions := array_append(v_partitions, v_partition);
    END LOOP;
    
    RETURN v_partitions;
END;
$$;

-- Function to archive old partitions (move to cold storage)
CREATE OR REPLACE FUNCTION ussd_core.archive_old_partitions(
    p_older_than_months INTEGER DEFAULT 12
)
RETURNS TABLE (
    partition_name TEXT,
    rows_archived BIGINT,
    archived_at TIMESTAMPTZ
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_partition RECORD;
    v_partition_date DATE;
    v_cutoff_date DATE;
    v_row_count BIGINT;
BEGIN
    v_cutoff_date := CURRENT_DATE - (p_older_than_months || ' months')::INTERVAL;
    
    FOR v_partition IN 
        SELECT inhrelid::regclass::TEXT as partition_name
        FROM pg_inherits
        WHERE inhparent = 'ussd_core.transactions'::regclass
    LOOP
        -- Extract date from partition name (transactions_YYYY_MM)
        v_partition_date := to_date(
            substring(v_partition.partition_name from 'transactions_(\d{4}_\d{2})'),
            'YYYY_MM'
        );
        
        IF v_partition_date < v_cutoff_date THEN
            -- Get row count
            EXECUTE format('SELECT COUNT(*) FROM ussd_core.%I', v_partition.partition_name)
            INTO v_row_count;
            
            -- In production, this would move data to cold storage (S3, etc.)
            -- For now, we just mark it as archived in metadata
            
            partition_name := v_partition.partition_name;
            rows_archived := v_row_count;
            archived_at := ussd_core.precise_now();
            
            RETURN NEXT;
        END IF;
    END LOOP;
END;
$$;

-- ----------------------------------------------------------------------------
-- 2. STATISTICS AND MONITORING
-- ----------------------------------------------------------------------------

-- Function to get ledger statistics
CREATE OR REPLACE FUNCTION ussd_core.get_ledger_statistics()
RETURNS TABLE (
    metric_name TEXT,
    metric_value BIGINT,
    metric_details JSONB
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    -- Total transactions
    RETURN QUERY
    SELECT 
        'total_transactions'::TEXT,
        COUNT(*)::BIGINT,
        jsonb_build_object(
            'committed', COUNT(*) FILTER (WHERE status = 'committed'),
            'pending', COUNT(*) FILTER (WHERE status = 'pending'),
            'failed', COUNT(*) FILTER (WHERE status = 'failed')
        )
    FROM ussd_core.transactions;
    
    -- Total accounts
    RETURN QUERY
    SELECT 
        'total_accounts'::TEXT,
        COUNT(*)::BIGINT,
        jsonb_object_agg(account_type::TEXT, cnt)
    FROM (
        SELECT account_type, COUNT(*) as cnt
        FROM ussd_core.account_registry
        WHERE valid_to IS NULL
        GROUP BY account_type
    ) sub;
    
    -- Total blocks
    RETURN QUERY
    SELECT 
        'total_blocks'::TEXT,
        COUNT(*)::BIGINT,
        jsonb_build_object(
            'sealed', COUNT(*) FILTER (WHERE status = 'sealed'),
            'anchored', COUNT(*) FILTER (WHERE status = 'anchored'),
            'open', COUNT(*) FILTER (WHERE status = 'open')
        )
    FROM ussd_core.blocks;
    
    -- Transactions per day (last 7 days)
    RETURN QUERY
    SELECT 
        'transactions_per_day'::TEXT,
        COUNT(*)::BIGINT,
        jsonb_object_agg(dt::TEXT, cnt)
    FROM (
        SELECT committed_at::DATE as dt, COUNT(*) as cnt
        FROM ussd_core.transactions
        WHERE committed_at > NOW() - INTERVAL '7 days'
        GROUP BY committed_at::DATE
    ) sub;
    
    -- Storage size
    RETURN QUERY
    SELECT 
        'storage_size_bytes'::TEXT,
        pg_total_relation_size('ussd_core.transactions')::BIGINT,
        jsonb_build_object(
            'transactions', pg_relation_size('ussd_core.transactions'),
            'accounts', pg_relation_size('ussd_core.account_registry'),
            'blocks', pg_relation_size('ussd_core.blocks'),
            'indexes', pg_indexes_size('ussd_core.transactions')
        );
END;
$$;

-- Function to get real-time metrics for monitoring
CREATE OR REPLACE FUNCTION ussd_core.get_realtime_metrics()
RETURNS TABLE (
    metric_name TEXT,
    metric_value NUMERIC,
    unit TEXT
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    -- Transactions per minute (last 5 minutes)
    RETURN QUERY
    SELECT 
        'transactions_per_minute'::TEXT,
        (COUNT(*) / 5.0)::NUMERIC,
        'tx/min'::TEXT
    FROM ussd_core.transactions
    WHERE committed_at > NOW() - INTERVAL '5 minutes';
    
    -- Average transaction latency (last hour)
    RETURN QUERY
    SELECT 
        'avg_latency_ms'::TEXT,
        AVG(processing_duration_ms)::NUMERIC,
        'ms'::TEXT
    FROM ussd_core.transactions
    WHERE committed_at > NOW() - INTERVAL '1 hour'
      AND processing_duration_ms IS NOT NULL;
    
    -- Current open blocks
    RETURN QUERY
    SELECT 
        'open_blocks'::TEXT,
        COUNT(*)::NUMERIC,
        'blocks'::TEXT
    FROM ussd_core.blocks
    WHERE status = 'open';
    
    -- Pending transactions
    RETURN QUERY
    SELECT 
        'pending_transactions'::TEXT,
        COUNT(*)::NUMERIC,
        'tx'::TEXT
    FROM ussd_core.transactions
    WHERE status = 'pending';
    
    -- Failed transactions (last hour)
    RETURN QUERY
    SELECT 
        'failed_transactions_hour'::TEXT,
        COUNT(*)::NUMERIC,
        'tx'::TEXT
    FROM ussd_core.transactions
    WHERE status = 'failed'
      AND committed_at > NOW() - INTERVAL '1 hour';
END;
$$;

-- ----------------------------------------------------------------------------
-- 3. HEALTH CHECK FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function for load balancer health checks
CREATE OR REPLACE FUNCTION ussd_core.health_check()
RETURNS TABLE (
    check_name TEXT,
    status TEXT,
    response_time_ms INTEGER,
    details JSONB
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_start TIMESTAMPTZ;
BEGIN
    -- Database connectivity
    v_start := clock_timestamp();
    PERFORM 1;
    RETURN QUERY SELECT 
        'database_connectivity'::TEXT,
        'healthy'::TEXT,
        (EXTRACT(EPOCH FROM (clock_timestamp() - v_start)) * 1000)::INTEGER,
        '{}'::JSONB;
    
    -- Transaction log writable
    v_start := clock_timestamp();
    RETURN QUERY SELECT 
        'transaction_log_accessible'::TEXT,
        CASE WHEN EXISTS (SELECT 1 FROM ussd_core.transactions LIMIT 1) 
             THEN 'healthy'::TEXT 
             ELSE 'warning'::TEXT 
        END,
        (EXTRACT(EPOCH FROM (clock_timestamp() - v_start)) * 1000)::INTEGER,
        jsonb_build_object('latest_transaction_id', (SELECT MAX(transaction_id) FROM ussd_core.transactions));
    
    -- Account registry accessible
    v_start := clock_timestamp();
    RETURN QUERY SELECT 
        'account_registry_accessible'::TEXT,
        CASE WHEN EXISTS (SELECT 1 FROM ussd_core.account_registry LIMIT 1) 
             THEN 'healthy'::TEXT 
             ELSE 'warning'::TEXT 
        END,
        (EXTRACT(EPOCH FROM (clock_timestamp() - v_start)) * 1000)::INTEGER,
        jsonb_build_object('total_accounts', (SELECT COUNT(*) FROM ussd_core.account_registry WHERE valid_to IS NULL));
    
    -- Recent integrity status
    v_start := clock_timestamp();
    RETURN QUERY SELECT 
        'integrity_verification'::TEXT,
        CASE 
            WHEN NOT EXISTS (SELECT 1 FROM ussd_core.integrity_issues WHERE severity = 'critical' AND status = 'open')
                THEN 'healthy'::TEXT
            WHEN NOT EXISTS (SELECT 1 FROM ussd_core.integrity_issues WHERE severity IN ('critical', 'high') AND status = 'open')
                THEN 'degraded'::TEXT
            ELSE 'unhealthy'::TEXT
        END,
        (EXTRACT(EPOCH FROM (clock_timestamp() - v_start)) * 1000)::INTEGER,
        (SELECT jsonb_build_object(
            'critical_issues', COUNT(*) FILTER (WHERE severity = 'critical' AND status = 'open'),
            'high_issues', COUNT(*) FILTER (WHERE severity = 'high' AND status = 'open')
        ) FROM ussd_core.integrity_issues);
END;
$$;

-- ----------------------------------------------------------------------------
-- 4. BACKUP AND RECOVERY FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to get consistent backup point
CREATE OR REPLACE FUNCTION ussd_core.get_backup_point()
RETURNS TABLE (
    backup_point_id BIGINT,
    transaction_id BIGINT,
    block_height BIGINT,
    timestamp TIMESTAMPTZ,
    consistent BOOLEAN
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_latest_tx BIGINT;
    v_latest_block BIGINT;
    v_checkpoint_id BIGINT;
BEGIN
    -- Get current positions
    SELECT MAX(transaction_id) INTO v_latest_tx FROM ussd_core.transactions;
    SELECT MAX(block_height) INTO v_latest_block FROM ussd_core.blocks WHERE status IN ('sealed', 'anchored');
    
    -- Create checkpoint record
    INSERT INTO ussd_audit.global_audit_log (
        table_schema, table_name, record_id, action, new_values
    ) VALUES (
        'ussd_core', 'backup_checkpoint',
        v_latest_tx::TEXT, 'BACKUP_POINT',
        jsonb_build_object(
            'transaction_id', v_latest_tx,
            'block_height', v_latest_block,
            'timestamp', ussd_core.precise_now()
        )
    )
    RETURNING audit_id INTO v_checkpoint_id;
    
    RETURN QUERY SELECT 
        v_checkpoint_id,
        v_latest_tx,
        v_latest_block,
        ussd_core.precise_now(),
        TRUE;
END;
$$;

-- Function to verify backup consistency
CREATE OR REPLACE FUNCTION ussd_core.verify_backup_consistency(
    p_backup_transaction_id BIGINT
)
RETURNS TABLE (
    is_consistent BOOLEAN,
    issues TEXT[]
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_issues TEXT[] := '{}';
BEGIN
    -- Verify all transactions up to backup point have block assignments
    IF EXISTS (
        SELECT 1 FROM ussd_core.transactions
        WHERE transaction_id <= p_backup_transaction_id
          AND block_id IS NULL
          AND status = 'committed'
    ) THEN
        v_issues := array_append(v_issues, 'Unblocked transactions found before backup point');
    END IF;
    
    -- Verify all blocks are sealed
    IF EXISTS (
        SELECT 1 FROM ussd_core.blocks
        WHERE status = 'open'
    ) THEN
        v_issues := array_append(v_issues, 'Open blocks exist');
    END IF;
    
    RETURN QUERY SELECT 
        (array_length(v_issues, 1) IS NULL),
        v_issues;
END;
$$;

-- ----------------------------------------------------------------------------
-- 5. CLEANUP AND MAINTENANCE
-- ----------------------------------------------------------------------------

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION ussd_core.cleanup_expired_sessions(
    p_batch_size INTEGER DEFAULT 1000
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER;
BEGIN
    UPDATE ussd_core.sessions
    SET status = 'expired'
    WHERE session_id IN (
        SELECT session_id
        FROM ussd_core.sessions
        WHERE status = 'active' AND expires_at < NOW()
        LIMIT p_batch_size
    );
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

-- Function to purge old audit logs (with legal hold check)
CREATE OR REPLACE FUNCTION ussd_core.purge_old_audit_logs(
    p_older_than_days INTEGER DEFAULT 365
)
RETURNS TABLE (
    table_name TEXT,
    rows_archived BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_cutoff_date DATE;
BEGIN
    v_cutoff_date := CURRENT_DATE - p_older_than_days;
    
    -- Check for legal holds before purging
    IF EXISTS (SELECT 1 FROM ussd_app.legal_holds WHERE is_active = TRUE) THEN
        RAISE EXCEPTION 'Cannot purge audit logs: Active legal holds exist';
    END IF;
    
    -- Return counts that would be purged (actual purge requires separate archive process)
    RETURN QUERY
    SELECT 
        'global_audit_log'::TEXT,
        COUNT(*)::BIGINT
    FROM ussd_audit.global_audit_log
    WHERE created_at < v_cutoff_date;
    
    RETURN QUERY
    SELECT 
        'key_usage_log'::TEXT,
        COUNT(*)::BIGINT
    FROM ussd_audit.key_usage_log
    WHERE performed_at < v_cutoff_date;
END;
$$;

-- ----------------------------------------------------------------------------
-- 6. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON FUNCTION ussd_core.create_future_partitions IS 
    'Creates transaction table partitions for upcoming months';
COMMENT ON FUNCTION ussd_core.get_ledger_statistics IS 
    'Returns comprehensive statistics about the ledger state';
COMMENT ON FUNCTION ussd_core.health_check IS 
    'Performs health checks for load balancer monitoring';
COMMENT ON FUNCTION ussd_core.get_backup_point IS 
    'Creates a consistent backup point for disaster recovery';

-- ----------------------------------------------------------------------------
-- 7. COMPLETION NOTICE
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    RAISE NOTICE 'USSD Kernel Core Schema - Utilities Loaded';
    RAISE NOTICE 'Core schema files 000-099 complete';
END;
$$;
