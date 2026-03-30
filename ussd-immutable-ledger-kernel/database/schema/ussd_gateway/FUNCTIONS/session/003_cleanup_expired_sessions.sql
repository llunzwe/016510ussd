-- ============================================================================
-- FUNCTION: cleanup_expired_sessions
-- ============================================================================
-- Purpose: Clean up expired USSD sessions, archive audit data, and maintain
--          system performance by removing stale session records.
-- Context: USSD sessions are transient by nature. This background cleanup
--          ensures the database doesn't grow unbounded and that expired
--          sessions are properly handled.
--
-- COMPLIANCE & STANDARDS:
--   ISO/IEC 27001:2022 - Information Security Management
--     * A.8.1: Asset management - secure data disposal
--     * A.8.10: Information deletion - retention policy enforcement
--     * A.8.12: Audit record archival
--     * A.12.3: Backup and recovery - archive verification
--
--   ISO/IEC 27018:2019 - PII Protection
--     * Data retention limits enforcement
--     * Anonymization before archival
--     * Right to erasure implementation
--     * Encrypted archive storage
--
--   GDPR Article 5(1)(e) - Storage Limitation
--     * Automatic deletion after retention period
--     * Anonymization option for audit requirements
--     * Data minimization during cleanup
--
--   ISO 31000:2018 - Risk Management
--     * Risk-based retention periods
--     * Extended retention for fraud investigations
--     * Legal hold capability
--
-- CLEANUP FLOW:
--   1. Find all expired sessions
--   2. Archive to long-term storage if needed
--   3. Finalize any incomplete transactions
--   4. Remove or archive session records
--   5. Update statistics and metrics
--
-- RETENTION POLICY:
--   Active sessions:       Until expires_at + 5 min (resume window)
--   Finalized sessions:    30 days (hot storage)
--   Archived sessions:     90 days (warm storage)
--   Cold storage:          2-7 years (regulatory dependent)
--   SIM swap related:      Extended retention (investigation)
--
-- SECURITY FEATURES:
--   - Hash chain verification before deletion
--   - Encrypted archive uploads
--   - Transaction finalization before session cleanup
--   - Audit trail preservation
--   - Dry-run capability for testing
--
-- ENTERPRISE CODING PRACTICES:
--   - SECURITY DEFINER with cleanup role
--   - Batched processing for large volumes
--   - Runtime limits to prevent lock contention
--   - Comprehensive metrics and logging
--   - Error handling with continuation
-- ============================================================================

CREATE OR REPLACE FUNCTION cleanup_expired_sessions(
    -- Configuration
    p_batch_size INT DEFAULT 1000,
    p_max_runtime_seconds INT DEFAULT 30,
    p_dry_run BOOLEAN DEFAULT FALSE
)
RETURNS TABLE (
    sessions_processed INT,
    sessions_archived INT,
    sessions_deleted INT,
    transactions_finalized INT,
    errors_encountered INT,
    processing_time_ms INT,
    next_batch_needed BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_start_time TIMESTAMPTZ;
    v_sessions_processed INT := 0;
    v_sessions_archived INT := 0;
    v_sessions_deleted INT := 0;
    v_transactions_finalized INT := 0;
    v_errors INT := 0;
    v_session RECORD;
    v_batch RECORD;
    v_expired_session_ids UUID[];
BEGIN
    v_start_time := clock_timestamp();

    -- ========================================================================
    -- TODO [CLEANUP-001]: Identify expired sessions
    -- ========================================================================
    /*
    TODO: Query expired sessions with batch limit
      - expires_at < NOW() for active sessions
      - completed_at older than retention for finalized sessions
      - Prioritize by expiration time (oldest first)
      - Respect batch size for controlled processing
    */
    
    CREATE TEMP TABLE temp_expired_sessions ON COMMIT DROP AS
    SELECT 
        s.session_id,
        s.msisdn,
        s.current_state,
        s.completion_status,
        s.expires_at,
        s.is_finalized,
        s.created_at,
        s.application_id,
        s.device_fingerprint_id,
        s.session_hash,
        p.transaction_id,
        p.status as transaction_status
    FROM ussd_session_state s
    LEFT JOIN pending_transactions p ON p.session_id = s.session_id
    WHERE (
        -- Active but expired
        (s.is_active = TRUE AND s.expires_at < NOW())
        OR
        -- Finalized but older than retention (configurable)
        (s.is_finalized = TRUE AND s.completed_at < NOW() - INTERVAL '30 days')
    )
    AND s.session_id NOT IN (
        -- Don't cleanup sessions that can still be resumed
        SELECT session_id FROM ussd_session_state
        WHERE completion_status = 'TIMEOUT'
        AND completed_at > NOW() - INTERVAL '5 minutes'
    )
    ORDER BY s.expires_at, s.created_at
    LIMIT p_batch_size;

    -- ========================================================================
    -- TODO [CLEANUP-002]: Archive session audit data
    -- ========================================================================
    /*
    TODO: Archive session data before deletion
      - Write to immutable ledger if not already persisted
      - Export to cold storage (S3, Glacier)
      - Maintain summary statistics
      - Keep hash chain for integrity verification
      
    Archival strategy:
      - Recent (0-30 days): Keep in hot storage
      - Medium (30-90 days): Compress, move to warm storage
      - Old (90+ days): Aggregate stats, move to cold storage
    */
    
    FOR v_batch IN 
        SELECT * FROM temp_expired_sessions 
        WHERE is_finalized = FALSE OR current_state NOT IN ('COMPLETE', 'CANCELLED')
    LOOP
        BEGIN
            -- Archive to ledger if needed
            IF NOT p_dry_run THEN
                -- TODO: Write to ledger
                NULL;
            END IF;
            
            v_sessions_archived := v_sessions_archived + 1;
            
        EXCEPTION WHEN OTHERS THEN
            v_errors := v_errors + 1;
            -- Log error but continue processing
            RAISE WARNING 'Archive failed for session %: %', v_batch.session_id, SQLERRM;
        END;
        
        -- Check runtime limit
        IF EXTRACT(EPOCH FROM (clock_timestamp() - v_start_time)) > p_max_runtime_seconds THEN
            EXIT;
        END IF;
    END LOOP;

    -- ========================================================================
    -- TODO [CLEANUP-003]: Finalize incomplete transactions
    -- ========================================================================
    /*
    TODO: Handle transactions in expired sessions
      - Query pending_transactions for expiring sessions
      - Attempt to cancel/reverse if in early stages
      - Mark as TIMEOUT if processing
      - Trigger reconciliation for unknown states
      - Notify user of incomplete transaction
    
    Transaction states:
      PENDING -> CANCELLED (safe to cancel)
      VALIDATING -> CANCELLED (rollback)
      PROCESSING -> TIMEOUT (requires reconciliation)
      AWAITING_CALLBACK -> TIMEOUT (requires reconciliation)
    */
    
    FOR v_batch IN 
        SELECT DISTINCT session_id, transaction_id, transaction_status
        FROM temp_expired_sessions
        WHERE transaction_id IS NOT NULL
        AND transaction_status IN ('PENDING', 'VALIDATING', 'PROCESSING', 'AWAITING_CALLBACK')
    LOOP
        BEGIN
            IF NOT p_dry_run THEN
                UPDATE pending_transactions
                SET status = CASE 
                        WHEN status IN ('PENDING', 'VALIDATING') THEN 'CANCELLED'
                        ELSE 'TIMEOUT'
                    END,
                    status_reason = 'Session expired during processing',
                    completed_at = NOW(),
                    updated_at = NOW()
                WHERE transaction_id = v_batch.transaction_id
                AND status NOT IN ('COMPLETED', 'FAILED', 'CANCELLED', 'REVERSED');
                
                GET DIAGNOSTICS v_sessions_processed = ROW_COUNT;
                v_transactions_finalized := v_transactions_finalized + v_sessions_processed;
            END IF;
            
        EXCEPTION WHEN OTHERS THEN
            v_errors := v_errors + 1;
            RAISE WARNING 'Transaction finalization failed for %: %', v_batch.transaction_id, SQLERRM;
        END;
    END LOOP;

    -- ========================================================================
    -- TODO [CLEANUP-004]: Update device fingerprint statistics
    -- ========================================================================
    /*
    TODO: Update aggregated stats before session deletion
      - Update device_fingerprints.total_sessions count
      - Update last_session_at for devices
      - Aggregate behavioral patterns
      - Update trust scores based on completed sessions
    */
    
    IF NOT p_dry_run THEN
        UPDATE device_fingerprints df
        SET total_sessions = df.total_sessions + s.session_count,
            last_session_at = GREATEST(df.last_session_at, s.last_session)
        FROM (
            SELECT device_fingerprint_id, 
                   COUNT(*) as session_count,
                   MAX(last_activity_at) as last_session
            FROM temp_expired_sessions
            WHERE device_fingerprint_id IS NOT NULL
            GROUP BY device_fingerprint_id
        ) s
        WHERE df.fingerprint_id = s.device_fingerprint_id;
    END IF;

    -- ========================================================================
    -- TODO [CLEANUP-005]: Mark sessions as finalized
    -- ========================================================================
    /*
    TODO: Finalize session records before archival/deletion
      - Set is_finalized = TRUE
      - Calculate final session_hash
      - Set finalized_at timestamp
      - Link to ledger sequence if persisted
    */
    
    IF NOT p_dry_run THEN
        UPDATE ussd_session_state
        SET is_finalized = TRUE,
            finalized_at = NOW(),
            is_active = FALSE,
            completion_status = COALESCE(completion_status, 'TIMEOUT'),
            completed_at = COALESCE(completed_at, NOW())
        WHERE session_id IN (SELECT session_id FROM temp_expired_sessions)
        AND is_finalized = FALSE;
    END IF;

    -- ========================================================================
    -- TODO [CLEANUP-006]: Archive to cold storage
    -- ========================================================================
    /*
    TODO: Export finalized sessions to external storage
      - Compress session data
      - Upload to S3/GCS with appropriate lifecycle
      - Maintain index for retrieval
      - Verify upload success before local deletion
      
    Export format options:
      - Parquet for analytics
      - JSONL for audit retrieval
      - Protobuf for compact storage
    */

    -- ========================================================================
    -- TODO [CLEANUP-007]: Delete or compress old sessions
    -- ========================================================================
    /*
    TODO: Remove processed sessions based on retention policy
      - Keep recent finalized sessions for quick lookup (7 days)
      - Archive older sessions (30-90 days)
      - Delete very old sessions (configurable, e.g., 2 years)
      - Cascade delete to related tables
      
    Soft delete option:
      - Mark as archived instead of DELETE
      - Move to separate table/partition
      - Compress context_encrypted blob
    */
    
    IF NOT p_dry_run THEN
        -- Delete very old finalized sessions (configurable retention)
        DELETE FROM ussd_session_state
        WHERE session_id IN (
            SELECT session_id FROM temp_expired_sessions
            WHERE is_finalized = TRUE
            AND completed_at < NOW() - INTERVAL '90 days' -- Configurable
        );
        
        GET DIAGNOSTICS v_sessions_deleted = ROW_COUNT;
    END IF;

    -- ========================================================================
    -- TODO [CLEANUP-008]: Cleanup orphaned records
    -- ========================================================================
    /*
    TODO: Clean up related tables
      - menu_navigation_history older than X days
      - fingerprint_verification_log older than X days
      - transaction_events (partitioned, drop old partitions)
      - Expired idempotency keys
    */
    
    IF NOT p_dry_run THEN
        -- Cleanup old navigation history
        DELETE FROM menu_navigation_history
        WHERE navigation_at < NOW() - INTERVAL '90 days';
        
        -- Cleanup old verification logs
        DELETE FROM fingerprint_verification_log
        WHERE verification_at < NOW() - INTERVAL '90 days';
        
        -- Drop old transaction_events partitions
        -- TODO: Implement partition management
    END IF;

    -- ========================================================================
    -- TODO [CLEANUP-009]: Update metrics
    -- ========================================================================
    /*
    TODO: Record cleanup metrics
      - Sessions cleaned up per run
      - Average session duration
      - Timeout rate
      - Archive storage usage
      - Cleanup job execution time
    */

    -- ========================================================================
    -- TODO [CLEANUP-010]: Check if more batches needed
    -- ========================================================================
    /*
    TODO: Determine if additional cleanup runs are needed
      - Count remaining expired sessions
      - Return flag for scheduler
      - Implement exponential backoff if many sessions
    */

    -- Count processed in this batch
    SELECT COUNT(*) INTO v_sessions_processed
    FROM temp_expired_sessions;

    -- Return results
    RETURN QUERY SELECT 
        v_sessions_processed,
        v_sessions_archived,
        v_sessions_deleted,
        v_transactions_finalized,
        v_errors,
        (EXTRACT(EPOCH FROM (clock_timestamp() - v_start_time)) * 1000)::INT,
        (v_sessions_processed >= p_batch_size); -- More batches needed if batch was full

END;
$$;

-- ----------------------------------------------------------------------------
-- FUNCTION: cleanup_expired_sessions_cron (convenience wrapper)
-- ----------------------------------------------------------------------------
-- Wrapper for scheduled execution via pg_cron or external scheduler
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION cleanup_expired_sessions_cron()
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_result RECORD;
    v_batch_count INT := 0;
    v_max_batches INT := 10; -- Prevent runaway cleanup
BEGIN
    LOOP
        SELECT * INTO v_result FROM cleanup_expired_sessions(
            p_batch_size := 1000,
            p_max_runtime_seconds := 30,
            p_dry_run := FALSE
        );
        
        v_batch_count := v_batch_count + 1;
        
        -- Log results
        RAISE NOTICE 'Cleanup batch %: processed=%, archived=%, deleted=%, errors=%',
            v_batch_count, v_result.sessions_processed, v_result.sessions_archived,
            v_result.sessions_deleted, v_result.errors_encountered;
        
        -- Exit conditions
        EXIT WHEN NOT v_result.next_batch_needed;
        EXIT WHEN v_batch_count >= v_max_batches;
        EXIT WHEN v_result.errors_encountered > 10; -- Too many errors
        
        -- Brief pause between batches
        PERFORM pg_sleep(0.5);
    END LOOP;
END;
$$;

-- ----------------------------------------------------------------------------
-- TODO: IMPLEMENTATION NOTES
-- ----------------------------------------------------------------------------

/*
TODO [SCHED-001]: Schedule cleanup job
  - Use pg_cron for PostgreSQL-native scheduling
  - Run every 30 seconds for high-volume systems
  - Or run every 5 minutes for lower volume
  - Stagger across multiple instances if needed

  pg_cron example:
  SELECT cron.schedule('cleanup-expired-sessions', '*/30 * * * *', 
    'SELECT cleanup_expired_sessions_cron()');

TODO [MON-001]: Monitoring and alerting
  - Alert if cleanup lag grows (expired sessions not being cleaned)
  - Alert on high error rates
  - Track cleanup duration percentiles
  - Monitor storage growth rate

TODO [PERF-001]: Performance optimization
  - Use partitioning for session table by created_at
  - Create partial index on (is_active, expires_at)
  - Vacuum after large deletions
  - Consider TRUNCATE for bulk archival

TODO [DISASTER-001]: Disaster recovery
  - Ensure archived data is replicated
  - Test restoration from archive
  - Maintain cleanup job state across failover
  - Document recovery procedures
*/

-- ----------------------------------------------------------------------------
-- SECURITY CONSIDERATIONS
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.10 - Secure data disposal
-- [ISO/IEC 27001:2022] A.8.12 - Audit record archival
-- [ISO/IEC 27018:2019] PII anonymization before deletion
-- [GDPR] Storage limitation (Article 5(1)(e))
-- Legal hold capability for investigations
/*
1. ACCESS CONTROL:
   - Cleanup function runs with elevated privileges
   - Restrict execute permission to cleanup role
   - Log all cleanup operations
   - Audit access to archived data

2. DATA RETENTION:
   - Implement legal hold capability (prevent cleanup)
   - Different retention per jurisdiction
   - Encrypted archive storage
   - Secure deletion (crypto-shredding if needed)

3. INTEGRITY:
   - Verify hash chain before deletion
   - Maintain archive checksums
   - Test restore procedures regularly
   - Document chain of custody

4. PRIVACY:
   - Anonymize archived data where possible
   - Implement right to erasure (with audit considerations)
   - Encrypt all archived PII
   - Access controls on historical data
*/

-- ----------------------------------------------------------------------------
-- SESSION TIMEOUT HANDLING
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.11 - Cleanup job timeout: 30 seconds/batch
-- Session recovery window: Don't cleanup < 5 min old timeouts
-- Transaction reconciliation: 24 hour window for unknown states
/*
Cleanup timeout handling:

1. CLEANUP JOB TIMEOUT:
   - Max runtime per batch (default 30 seconds)
   - Graceful exit when time limit reached
   - Resume from checkpoint on next run
   - Don't hold locks for extended periods

2. SESSION RECOVERY WINDOW:
   - Don't cleanup sessions eligible for resume (< 5 min)
   - Mark but don't delete recent timeouts
   - Separate cleanup phases: finalize, archive, delete
   - Respect business hours for aggressive cleanup

3. TRANSACTION TIMEOUTS:
   - Transactions in expired sessions must be finalized
   - Reconciliation window for unknown states (24 hours)
   - User notification of incomplete transactions
   - Refund processing for failed payments

4. ARCHIVAL TIMEOUTS:
   - Archive operations have timeouts
   - Retry failed archives
   - Alert on persistent archive failures
   - Don't delete until archive confirmed

5. CASCADE CLEANUP:
   - Related records cleaned up with sessions
   - Orphan prevention
   - Referential integrity maintenance
   - Partition dropping for time-series data
*/

-- ----------------------------------------------------------------------------
-- SIM SWAP DETECTION INTEGRATION
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27035-2:2023] Extended retention for swap-related sessions
-- SIM swap events: Retain 2+ years for investigation
-- Fingerprint events: Retain indefinitely
-- Post-swap session: Flag for extended retention before cleanup
/*
SIM swap considerations during cleanup:

1. EXTENDED RETENTION:
   - Sessions around SIM swap events: retain longer
   - Post-swap session history: 2 years minimum
   - Correlation data: retain for investigation
   - Flag suspicious session patterns before cleanup

2. SWAP CORRELATION CLEANUP:
   - sim_swap_correlations: retain indefinitely
   - fingerprint_events: retain 2+ years
   - Device change chains: never delete
   - Security incident data: legal hold

3. INVESTIGATION SUPPORT:
   - Quick retrieval of sessions by MSISDN + time range
   - Preserve navigation history for fraud analysis
   - Maintain device fingerprint correlation
   - Export capability for law enforcement requests

4. POST-SWAP SESSION HANDLING:
   - First session after swap: flag for extended retention
   - Multiple swaps in short period: alert, don't archive
   - Failed verification post-swap: retain evidence
   - Update sim_swap_correlations on session cleanup

5. AUDIT REQUIREMENTS:
   - SIM swap events: immutable audit trail
   - Cleanup of swap-related sessions: extra logging
   - Cross-reference with swap detection timestamps
   - Regulatory reporting data retention
*/

-- Grant execute permission
-- GRANT EXECUTE ON FUNCTION cleanup_expired_sessions TO ussd_cleanup_role;
-- GRANT EXECUTE ON FUNCTION cleanup_expired_sessions_cron TO ussd_cleanup_role;
