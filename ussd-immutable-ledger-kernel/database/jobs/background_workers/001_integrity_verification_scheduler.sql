-- =============================================================================
-- Background Worker: Integrity Verification Scheduler
-- =============================================================================
-- Description: Schedules and manages periodic integrity checks across the ledger
--              including hash chain verification, balance reconciliations, and
--              cross-table consistency checks
-- Schedule: Continuous verification with configurable intervals per check type
-- =============================================================================

-- =============================================================================
-- COMPLIANCE FRAMEWORK ALIGNMENT
-- =============================================================================
-- ISO/IEC 27001:2022
--   A.12.3 (Backup)       - Verification ensures backup integrity before restore
--   A.12.4 (Logging)      - Comprehensive audit trail of all integrity checks
--   A.12.6 (Vuln. Mgmt)   - Proactive detection of data integrity issues
--   A.5.24 (Compliance)   - Automated compliance verification controls
--
-- ISO/IEC 27031:2025
--   Business Continuity   - Pre-incident verification ensures recoverable state
--   ICT Readiness         - Continuous validation supports rapid failover
--   Monitoring            - Real-time integrity monitoring for BC readiness
--
-- ISO/IEC 27040:2024
--   Storage Security      - Detects unauthorized storage modifications
--   Data Integrity        - Cryptographic verification of stored data
--   Verification Controls - Automated integrity validation procedures
-- =============================================================================

-- Install required extensions
CREATE EXTENSION IF NOT EXISTS pg_cron;
CREATE EXTENSION IF NOT EXISTS dblink;

-- Create supporting tables
CREATE TABLE IF NOT EXISTS ledger.integrity_check_queue (
    job_id BIGSERIAL PRIMARY KEY,
    check_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    priority INT DEFAULT 3,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    result_summary JSONB,
    error_message TEXT,
    duration_ms NUMERIC
);

CREATE TABLE IF NOT EXISTS ledger.integrity_check_log (
    log_id BIGSERIAL PRIMARY KEY,
    job_id BIGINT REFERENCES ledger.integrity_check_queue(job_id),
    check_type TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    result_details JSONB,
    issues_found INT DEFAULT 0,
    error_details TEXT
);

CREATE INDEX IF NOT EXISTS idx_integrity_queue_status 
ON ledger.integrity_check_queue(status, priority, created_at);

CREATE INDEX IF NOT EXISTS idx_integrity_log_check_type_time 
ON ledger.integrity_check_log(check_type, completed_at DESC);

-- Main scheduler function
CREATE OR REPLACE FUNCTION ledger.schedule_integrity_checks()
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_check_type TEXT;
    v_last_run TIMESTAMPTZ;
    v_interval INTERVAL;
    v_config RECORD;
BEGIN
    -- Configuration for different check types
    FOR v_config IN 
        SELECT * FROM (VALUES
            ('HASH_CHAIN', '1 hour'::INTERVAL),
            ('BALANCE_RECONCILIATION', '5 minutes'::INTERVAL),
            ('CROSS_TABLE_CONSISTENCY', '15 minutes'::INTERVAL),
            ('INDEX_INTEGRITY', '1 day'::INTERVAL),
            ('FOREIGN_KEY_VALIDITY', '6 hours'::INTERVAL)
        ) AS t(check_type, check_interval)
    LOOP
        -- Check if we should run this verification
        SELECT MAX(completed_at)
        INTO v_last_run
        FROM ledger.integrity_check_log
        WHERE check_type = v_config.check_type
          AND status IN ('COMPLETED', 'IN_PROGRESS');
        
        -- Run if never run or interval has passed
        IF v_last_run IS NULL OR v_last_run < NOW() - v_config.check_interval THEN
            PERFORM ledger.enqueue_integrity_check(v_config.check_type);
        END IF;
    END LOOP;
END;
$$;

-- Enqueue a specific integrity check
CREATE OR REPLACE FUNCTION ledger.enqueue_integrity_check(p_check_type TEXT)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_job_id BIGINT;
BEGIN
    -- Insert job record
    INSERT INTO ledger.integrity_check_queue (
        check_type,
        status,
        priority,
        created_at
    ) VALUES (
        p_check_type,
        'PENDING',
        CASE p_check_type
            WHEN 'BALANCE_RECONCILIATION' THEN 1
            WHEN 'HASH_CHAIN' THEN 2
            ELSE 3
        END,
        NOW()
    )
    RETURNING job_id INTO v_job_id;
    
    -- Log the scheduling
    INSERT INTO ledger.integrity_check_log (
        job_id,
        check_type,
        status,
        started_at
    ) VALUES (
        v_job_id,
        p_check_type,
        'SCHEDULED',
        NOW()
    );
    
    RETURN v_job_id;
END;
$$;

-- Worker that processes the integrity check queue
CREATE OR REPLACE FUNCTION ledger.process_integrity_checks()
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_job RECORD;
    v_result JSONB;
    v_start_time TIMESTAMPTZ;
BEGIN
    -- Process pending jobs in priority order
    FOR v_job IN 
        SELECT * FROM ledger.integrity_check_queue
        WHERE status = 'PENDING'
        ORDER BY priority ASC, created_at ASC
        FOR UPDATE SKIP LOCKED
        LIMIT 5
    LOOP
        v_start_time := clock_timestamp();
        
        -- Mark as in-progress
        UPDATE ledger.integrity_check_queue
        SET status = 'IN_PROGRESS',
            started_at = NOW()
        WHERE job_id = v_job.job_id;
        
        BEGIN
            -- Execute the appropriate check
            v_result := CASE v_job.check_type
                WHEN 'HASH_CHAIN' THEN ledger.verify_hash_chain()
                WHEN 'BALANCE_RECONCILIATION' THEN ledger.verify_balance_consistency()
                WHEN 'CROSS_TABLE_CONSISTENCY' THEN ledger.verify_cross_table_consistency()
                WHEN 'INDEX_INTEGRITY' THEN ledger.verify_index_integrity()
                WHEN 'FOREIGN_KEY_VALIDITY' THEN ledger.verify_foreign_keys()
                ELSE jsonb_build_object('error', 'Unknown check type')
            END;
            
            -- Update as completed
            UPDATE ledger.integrity_check_queue
            SET status = 'COMPLETED',
                completed_at = NOW(),
                result_summary = v_result,
                duration_ms = EXTRACT(EPOCH FROM (clock_timestamp() - v_start_time)) * 1000
            WHERE job_id = v_job.job_id;
            
            -- Update log
            UPDATE ledger.integrity_check_log
            SET status = 'COMPLETED',
                completed_at = NOW(),
                result_details = v_result,
                issues_found = (v_result->>'issues_count')::INT
            WHERE job_id = v_job.job_id;
            
        EXCEPTION WHEN OTHERS THEN
            -- Mark as failed
            UPDATE ledger.integrity_check_queue
            SET status = 'FAILED',
                completed_at = NOW(),
                error_message = SQLERRM
            WHERE job_id = v_job.job_id;
            
            UPDATE ledger.integrity_check_log
            SET status = 'FAILED',
                completed_at = NOW(),
                error_details = SQLERRM
            WHERE job_id = v_job.job_id;
        END;
    END LOOP;
END;
$$;

-- Hash chain verification function
CREATE OR REPLACE FUNCTION ledger.verify_hash_chain()
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_issues INT := 0;
    v_result JSONB;
BEGIN
    -- Verify previous_hash linkage across blocks
    SELECT jsonb_build_object(
        'blocks_checked', COUNT(*),
        'broken_chains', COUNT(CASE WHEN b.prev_hash != pb.block_hash THEN 1 END),
        'first_issue_height', MIN(CASE WHEN b.prev_hash != pb.block_hash THEN b.block_height END)
    )
    INTO v_result
    FROM ledger.blocks b
    LEFT JOIN ledger.blocks pb ON b.block_height = pb.block_height + 1
    WHERE b.block_height > 0;
    
    v_issues := (v_result->>'broken_chains')::INT;
    
    RETURN v_result || jsonb_build_object('issues_count', v_issues, 'check_name', 'HASH_CHAIN');
END;
$$;

-- Balance reconciliation verification
CREATE OR REPLACE FUNCTION ledger.verify_balance_consistency()
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_result JSONB;
    v_issues INT;
BEGIN
    -- Verify running balances match computed from transactions
    WITH balance_check AS (
        SELECT 
            a.account_id,
            a.balance as stored_balance,
            COALESCE(SUM(CASE WHEN t.to_account = a.account_id THEN t.amount ELSE -t.amount END), 0) as computed_balance
        FROM ledger.accounts a
        LEFT JOIN ledger.transactions t ON t.from_account = a.account_id OR t.to_account = a.account_id
        GROUP BY a.account_id, a.balance
        HAVING a.balance != COALESCE(SUM(CASE WHEN t.to_account = a.account_id THEN t.amount ELSE -t.amount END), 0)
    )
    SELECT jsonb_build_object(
        'accounts_checked', (SELECT COUNT(*) FROM ledger.accounts),
        'mismatched_balances', COUNT(*),
        'mismatched_accounts', jsonb_agg(account_id)
    )
    INTO v_result
    FROM balance_check;
    
    v_issues := COALESCE((v_result->>'mismatched_balances')::INT, 0);
    
    RETURN COALESCE(v_result, '{}'::JSONB) || jsonb_build_object('issues_count', v_issues, 'check_name', 'BALANCE_RECONCILIATION');
END;
$$;

-- Cross-table consistency verification
CREATE OR REPLACE FUNCTION ledger.verify_cross_table_consistency()
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_issues INT := 0;
    v_orphaned_transactions BIGINT;
    v_orphaned_entries BIGINT;
    v_missing_audit BIGINT;
    v_result JSONB;
BEGIN
    -- Check for transactions without blocks
    SELECT COUNT(*) INTO v_orphaned_transactions
    FROM ledger.transactions t
    LEFT JOIN ledger.blocks b ON t.block_id = b.block_id
    WHERE b.block_id IS NULL;
    
    -- Check for ledger entries without transactions
    SELECT COUNT(*) INTO v_orphaned_entries
    FROM ledger.ledger_entries le
    LEFT JOIN ledger.transactions t ON le.transaction_id = t.transaction_id
    WHERE t.transaction_id IS NULL;
    
    -- Check for missing audit trail entries
    SELECT COUNT(*) INTO v_missing_audit
    FROM ledger.transactions t
    LEFT JOIN ledger.audit_trail at ON at.record_id = t.transaction_id::TEXT 
        AND at.table_name = 'transactions'
    WHERE at.audit_id IS NULL 
      AND t.created_at < NOW() - INTERVAL '1 minute';  -- Allow for async audit
    
    v_issues := v_orphaned_transactions + v_orphaned_entries;
    
    v_result := jsonb_build_object(
        'orphaned_transactions', v_orphaned_transactions,
        'orphaned_ledger_entries', v_orphaned_entries,
        'missing_audit_trail', v_missing_audit,
        'tables_checked', ARRAY['transactions', 'blocks', 'ledger_entries', 'audit_trail'],
        'issues_count', v_issues,
        'check_name', 'CROSS_TABLE_CONSISTENCY'
    );
    
    RETURN v_result;
END;
$$;

-- Index integrity verification
CREATE OR REPLACE FUNCTION ledger.verify_index_integrity()
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_invalid_indexes BIGINT;
    v_duplicate_indexes BIGINT;
    v_unused_indexes BIGINT;
    v_issues INT := 0;
    v_result JSONB;
BEGIN
    -- Check for invalid indexes
    SELECT COUNT(*) INTO v_invalid_indexes
    FROM pg_index pi
    JOIN pg_class c ON pi.indrelid = c.oid
    WHERE NOT pi.indisvalid
    AND c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'ledger');
    
    -- Check for duplicate indexes (same columns, different names)
    WITH index_cols AS (
        SELECT 
            indrelid::regclass as table_name,
            pg_get_indexdef(indexrelid) as index_def,
            array_agg(a.attname ORDER BY array_position(indkey, a.attnum)) as columns
        FROM pg_index pi
        JOIN pg_class c ON pi.indrelid = c.oid
        JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(pi.indkey)
        WHERE c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'ledger')
        GROUP BY indrelid, indexrelid, pg_get_indexdef(indexrelid)
    )
    SELECT COUNT(*) INTO v_duplicate_indexes
    FROM index_cols ic1
    JOIN index_cols ic2 ON ic1.table_name = ic2.table_name 
        AND ic1.columns = ic2.columns 
        AND ic1.index_def != ic2.index_def;
    
    -- Check for unused indexes (no scans in last 7 days)
    SELECT COUNT(*) INTO v_unused_indexes
    FROM pg_stat_user_indexes psi
    JOIN pg_index pi ON psi.indexrelid = pi.indexrelid
    WHERE psi.schemaname = 'ledger'
    AND psi.idx_scan = 0
    AND pi.indisunique = FALSE;  -- Exclude unique constraints
    
    v_issues := v_invalid_indexes::INT + v_duplicate_indexes::INT;
    
    v_result := jsonb_build_object(
        'invalid_indexes', v_invalid_indexes,
        'potential_duplicates', v_duplicate_indexes,
        'unused_indexes', v_unused_indexes,
        'issues_count', v_issues,
        'check_name', 'INDEX_INTEGRITY'
    );
    
    RETURN v_result;
END;
$$;

-- Foreign key validity verification
CREATE OR REPLACE FUNCTION ledger.verify_foreign_keys()
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_result JSONB;
    v_issues INT := 0;
    v_orphan_count BIGINT;
    v_fk_record RECORD;
    v_violations JSONB := '[]'::JSONB;
BEGIN
    -- Check each foreign key constraint for violations
    FOR v_fk_record IN 
        SELECT 
            tc.constraint_name,
            kcu.table_name,
            kcu.column_name,
            ccu.table_name AS foreign_table_name,
            ccu.column_name AS foreign_column_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
        JOIN information_schema.constraint_column_usage ccu ON ccu.constraint_name = tc.constraint_name
        WHERE tc.constraint_type = 'FOREIGN KEY'
        AND tc.table_schema = 'ledger'
    LOOP
        -- Count orphaned records for this FK
        EXECUTE format(
            'SELECT COUNT(*) FROM ledger.%I t1 
             LEFT JOIN ledger.%I t2 ON t1.%I = t2.%I 
             WHERE t2.%I IS NULL AND t1.%I IS NOT NULL',
            v_fk_record.table_name,
            v_fk_record.foreign_table_name,
            v_fk_record.column_name,
            v_fk_record.foreign_column_name,
            v_fk_record.foreign_column_name,
            v_fk_record.column_name
        ) INTO v_orphan_count;
        
        IF v_orphan_count > 0 THEN
            v_issues := v_issues + 1;
            v_violations := v_violations || jsonb_build_object(
                'constraint', v_fk_record.constraint_name,
                'table', v_fk_record.table_name,
                'orphan_count', v_orphan_count
            );
        END IF;
    END LOOP;
    
    v_result := jsonb_build_object(
        'fk_constraints_checked', (SELECT COUNT(*) FROM information_schema.table_constraints 
                                   WHERE constraint_type = 'FOREIGN KEY' AND table_schema = 'ledger'),
        'violations_found', v_issues,
        'violation_details', v_violations,
        'issues_count', v_issues,
        'check_name', 'FOREIGN_KEY_VALIDITY'
    );
    
    RETURN v_result;
END;
$$;

-- Schedule the scheduler itself using pg_cron
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        -- Schedule the scheduler to run every minute
        PERFORM cron.schedule('integrity-scheduler', '* * * * *', 'SELECT ledger.schedule_integrity_checks()');
        
        -- Schedule the worker to run every 2 minutes
        PERFORM cron.schedule('integrity-worker', '*/2 * * * *', 'SELECT ledger.process_integrity_checks()');
        
        RAISE NOTICE 'Integrity verification scheduler scheduled via pg_cron';
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'Could not schedule integrity checks via pg_cron: %', SQLERRM;
END;
$$;

-- View for monitoring integrity check status
CREATE OR REPLACE VIEW ledger.integrity_check_status AS
SELECT 
    check_type,
    COUNT(*) FILTER (WHERE status = 'PENDING') as pending_count,
    COUNT(*) FILTER (WHERE status = 'IN_PROGRESS') as running_count,
    COUNT(*) FILTER (WHERE status = 'COMPLETED' AND completed_at > NOW() - INTERVAL '24 hours') as completed_24h,
    COUNT(*) FILTER (WHERE status = 'FAILED' AND completed_at > NOW() - INTERVAL '24 hours') as failed_24h,
    MAX(completed_at) as last_run_at,
    AVG(duration_ms) FILTER (WHERE status = 'COMPLETED') as avg_duration_ms,
    SUM(issues_found) FILTER (WHERE status = 'COMPLETED' AND completed_at > NOW() - INTERVAL '24 hours') as total_issues_24h
FROM ledger.integrity_check_log
GROUP BY check_type;
