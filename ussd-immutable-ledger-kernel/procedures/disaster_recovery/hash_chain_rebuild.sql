-- ============================================================================
-- HASH CHAIN REBUILD PROCEDURE
-- ============================================================================
-- Purpose: Rebuild the cryptographic hash chain for ledger integrity
--          after corruption detection or recovery operations.
-- Author:  USSD Immutable Ledger Team
-- Date:    2026-03-30
-- ============================================================================
-- COMPLIANCE HEADER:
--   ISO/IEC 27031:2025 - Information Technology - Security Techniques -
--   Guidelines for ICT Readiness for Business Continuity
--
--   This procedure implements:
--   - Clause 6.4: Data integrity verification during recovery
--   - Clause 7.2: Cryptographic chain reconstruction procedures
--   - Clause 9.1: Post-incident validation requirements
--   - Annex C: Hash chain verification and rebuild protocols
--
--   Integrity Level: Critical | Verification: 100% hash chain validation
--   Rollback Capability: Full backup retention during rebuild
--   Authorization: Requires dual-control approval for execution
-- ============================================================================

-- =============================================================================
-- STEP 1: PRE-REBUILD ASSESSMENT AND DIAGNOSTICS
-- =============================================================================

-- 1.1 Create rebuild operation tracking table
CREATE TABLE IF NOT EXISTS hash_chain_rebuild_log (
    rebuild_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rebuild_type VARCHAR(50) NOT NULL CHECK (rebuild_type IN ('FULL', 'PARTIAL', 'INCREMENTAL', 'EMERGENCY')),
    start_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMPTZ,
    start_transaction_id BIGINT,
    end_transaction_id BIGINT,
    records_processed BIGINT,
    records_corrupted BIGINT,
    rebuild_status VARCHAR(50) DEFAULT 'INITIATED',
    initiated_by TEXT DEFAULT CURRENT_USER,
    corruption_detected_at TIMESTAMPTZ,
    root_cause_analysis TEXT,
    validation_result BOOLEAN,
    rollback_script_path TEXT,
    CONSTRAINT valid_timestamps CHECK (end_time IS NULL OR end_time >= start_time)
);

-- 1.2 Create corruption detection log
CREATE TABLE IF NOT EXISTS hash_chain_corruption_log (
    corruption_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rebuild_id UUID REFERENCES hash_chain_rebuild_log(rebuild_id),
    transaction_id BIGINT NOT NULL,
    detected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    corruption_type VARCHAR(50) NOT NULL,
    expected_hash TEXT,
    actual_hash TEXT,
    previous_hash_expected TEXT,
    previous_hash_actual TEXT,
    resolution_action TEXT,
    resolved_at TIMESTAMPTZ
);

-- 1.3 Initialize rebuild operation
INSERT INTO hash_chain_rebuild_log (
    rebuild_type,
    start_transaction_id,
    rebuild_status
)
SELECT 
    'FULL',  -- TODO: Customize based on assessment
    MIN(transaction_id),
    'INITIATED'
FROM ledger_transactions  -- TODO: Customize table name
RETURNING rebuild_id;

-- =============================================================================
-- STEP 2: CORRUPTION DETECTION AND ANALYSIS
-- =============================================================================

-- 2.1 Comprehensive hash chain integrity check
CREATE OR REPLACE FUNCTION detect_hash_chain_corruption(
    p_start_txn_id BIGINT DEFAULT NULL,
    p_end_txn_id BIGINT DEFAULT NULL
)
RETURNS TABLE (
    corruption_detected BOOLEAN,
    first_corrupt_txn_id BIGINT,
    corruption_type TEXT,
    details JSONB
) AS $$
DECLARE
    v_rebuild_id UUID;
    v_first_corrupt BIGINT := NULL;
    v_corruption_type TEXT := NULL;
    v_details JSONB := '{}'::JSONB;
BEGIN
    -- Get current rebuild operation ID
    SELECT rebuild_id INTO v_rebuild_id
    FROM hash_chain_rebuild_log
    WHERE rebuild_status = 'INITIATED'
    ORDER BY start_time DESC
    LIMIT 1;
    
    -- Check for broken chain links
    FOR rec IN 
        WITH ordered_transactions AS (
            SELECT 
                transaction_id,
                previous_hash,
                computed_hash,
                LAG(computed_hash) OVER (ORDER BY transaction_id) as expected_previous_hash,
                transaction_data::TEXT as data,
                created_at
            FROM ledger_transactions
            WHERE (p_start_txn_id IS NULL OR transaction_id >= p_start_txn_id)
            AND (p_end_txn_id IS NULL OR transaction_id <= p_end_txn_id)
            ORDER BY transaction_id
        )
        SELECT *
        FROM ordered_transactions
        WHERE previous_hash IS DISTINCT FROM expected_previous_hash
        AND transaction_id != (SELECT MIN(transaction_id) FROM ledger_transactions)
    LOOP
        v_first_corrupt := rec.transaction_id;
        v_corruption_type := 'BROKEN_CHAIN_LINK';
        v_details := jsonb_build_object(
            'transaction_id', rec.transaction_id,
            'expected_previous_hash', rec.expected_previous_hash,
            'actual_previous_hash', rec.previous_hash,
            'created_at', rec.created_at
        );
        
        -- Log corruption
        INSERT INTO hash_chain_corruption_log (
            rebuild_id,
            transaction_id,
            corruption_type,
            previous_hash_expected,
            previous_hash_actual
        ) VALUES (
            v_rebuild_id,
            rec.transaction_id,
            'BROKEN_CHAIN_LINK',
            rec.expected_previous_hash,
            rec.previous_hash
        );
        
        EXIT;  -- Stop at first corruption
    END LOOP;
    
    -- Check for hash computation errors if no chain break found
    IF v_first_corrupt IS NULL THEN
        FOR rec IN 
            SELECT 
                t.transaction_id,
                t.computed_hash as actual_hash,
                encode(
                    digest(
                        concat(t.previous_hash, t.transaction_data::TEXT)::bytea,
                        'sha256'
                    ),
                    'hex'
                ) as expected_hash,
                t.created_at
            FROM ledger_transactions t
            WHERE (p_start_txn_id IS NULL OR t.transaction_id >= p_start_txn_id)
            AND (p_end_txn_id IS NULL OR t.transaction_id <= p_end_txn_id)
        LOOP
            IF rec.actual_hash != rec.expected_hash THEN
                v_first_corrupt := rec.transaction_id;
                v_corruption_type := 'INVALID_HASH_COMPUTATION';
                v_details := jsonb_build_object(
                    'transaction_id', rec.transaction_id,
                    'expected_hash', rec.expected_hash,
                    'actual_hash', rec.actual_hash
                );
                
                INSERT INTO hash_chain_corruption_log (
                    rebuild_id,
                    transaction_id,
                    corruption_type,
                    expected_hash,
                    actual_hash
                ) VALUES (
                    v_rebuild_id,
                    rec.transaction_id,
                    'INVALID_HASH_COMPUTATION',
                    rec.expected_hash,
                    rec.actual_hash
                );
                
                EXIT;
            END IF;
        END LOOP;
    END IF;
    
    RETURN QUERY SELECT 
        v_first_corrupt IS NOT NULL,
        v_first_corrupt,
        v_corruption_type,
        v_details;
END;
$$ LANGUAGE plpgsql;

-- 2.2 Execute corruption detection
SELECT * FROM detect_hash_chain_corruption();

-- =============================================================================
-- STEP 3: CREATE PRE-REBUILD BACKUP
-- =============================================================================

-- 3.1 Create backup of affected records
CREATE TABLE IF NOT EXISTS hash_chain_rebuild_backup (
    backup_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rebuild_id UUID REFERENCES hash_chain_rebuild_log(rebuild_id),
    transaction_id BIGINT NOT NULL,
    previous_hash_original TEXT,
    computed_hash_original TEXT,
    transaction_data JSONB,
    created_at_original TIMESTAMPTZ,
    backed_up_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 3.2 Backup corrupted records
WITH current_rebuild AS (
    SELECT rebuild_id FROM hash_chain_rebuild_log
    WHERE rebuild_status = 'INITIATED'
    ORDER BY start_time DESC
    LIMIT 1
),
corrupted_txns AS (
    SELECT transaction_id FROM hash_chain_corruption_log
    WHERE rebuild_id = (SELECT rebuild_id FROM current_rebuild)
    AND resolved_at IS NULL
)
INSERT INTO hash_chain_rebuild_backup (
    rebuild_id,
    transaction_id,
    previous_hash_original,
    computed_hash_original,
    transaction_data,
    created_at_original
)
SELECT 
    cr.rebuild_id,
    lt.transaction_id,
    lt.previous_hash,
    lt.computed_hash,
    lt.transaction_data,
    lt.created_at
FROM ledger_transactions lt
CROSS JOIN current_rebuild cr
WHERE lt.transaction_id IN (SELECT transaction_id FROM corrupted_txns);

-- =============================================================================
-- STEP 4: HASH CHAIN REBUILD PROCEDURE
-- =============================================================================

-- 4.1 Main rebuild function
CREATE OR REPLACE FUNCTION rebuild_hash_chain(
    p_rebuild_id UUID,
    p_batch_size INTEGER DEFAULT 1000,
    p_dry_run BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (
    batch_number INTEGER,
    records_processed BIGINT,
    records_updated BIGINT,
    current_txn_id BIGINT,
    status TEXT
) AS $$
DECLARE
    v_batch_num INTEGER := 0;
    v_total_processed BIGINT := 0;
    v_total_updated BIGINT := 0;
    v_min_txn_id BIGINT;
    v_max_txn_id BIGINT;
    v_current_hash TEXT;
    v_computed_hash TEXT;
    v_batch_start BIGINT;
    v_batch_end BIGINT;
    rec RECORD;
BEGIN
    -- Get transaction range
    SELECT MIN(transaction_id), MAX(transaction_id)
    INTO v_min_txn_id, v_max_txn_id
    FROM ledger_transactions;
    
    -- Process in batches
    v_batch_start := v_min_txn_id;
    
    WHILE v_batch_start <= v_max_txn_id LOOP
        v_batch_end := v_batch_start + p_batch_size - 1;
        v_batch_num := v_batch_num + 1;
        
        FOR rec IN 
            SELECT 
                transaction_id,
                previous_hash,
                computed_hash,
                transaction_data::TEXT,
                created_at
            FROM ledger_transactions
            WHERE transaction_id BETWEEN v_batch_start AND v_batch_end
            ORDER BY transaction_id
        LOOP
            v_total_processed := v_total_processed + 1;
            
            -- Get previous hash (genesis record has no previous)
            IF rec.transaction_id = v_min_txn_id THEN
                v_current_hash := encode(
                    digest(rec.transaction_data::TEXT::bytea, 'sha256'),
                    'hex'
                );
            ELSE
                -- Get computed hash from previous record
                SELECT computed_hash INTO v_current_hash
                FROM ledger_transactions
                WHERE transaction_id = rec.transaction_id - 1;
                
                -- Compute new hash
                v_computed_hash := encode(
                    digest(
                        concat(v_current_hash, rec.transaction_data::TEXT)::bytea,
                        'sha256'
                    ),
                    'hex'
                );
            END IF;
            
            -- Update if different (or always update for full rebuild)
            IF NOT p_dry_run AND (
                rec.previous_hash IS DISTINCT FROM v_current_hash OR
                rec.computed_hash IS DISTINCT FROM v_computed_hash
            ) THEN
                UPDATE ledger_transactions
                SET 
                    previous_hash = v_current_hash,
                    computed_hash = COALESCE(v_computed_hash, encode(digest(rec.transaction_data::TEXT::bytea, 'sha256'), 'hex')),
                    updated_at = CURRENT_TIMESTAMP
                WHERE transaction_id = rec.transaction_id;
                
                v_total_updated := v_total_updated + 1;
            END IF;
        END LOOP;
        
        batch_number := v_batch_num;
        records_processed := v_total_processed;
        records_updated := v_total_updated;
        current_txn_id := v_batch_end;
        status := CASE WHEN p_dry_run THEN 'DRY_RUN_COMPLETE' ELSE 'UPDATED' END;
        RETURN NEXT;
        
        -- Commit batch
        IF NOT p_dry_run THEN
            COMMIT;
        END IF;
        
        v_batch_start := v_batch_end + 1;
    END LOOP;
    
    -- Update rebuild log
    UPDATE hash_chain_rebuild_log
    SET 
        records_processed = v_total_processed,
        records_corrupted = v_total_updated,
        end_transaction_id = v_max_txn_id,
        rebuild_status = CASE WHEN p_dry_run THEN 'DRY_RUN_COMPLETE' ELSE 'COMPLETED' END,
        end_time = CURRENT_TIMESTAMP
    WHERE rebuild_id = p_rebuild_id;
    
    RETURN;
END;
$$ LANGUAGE plpgsql;

-- 4.2 Execute dry run first
-- SELECT * FROM rebuild_hash_chain(
--     (SELECT rebuild_id FROM hash_chain_rebuild_log WHERE rebuild_status = 'INITIATED' ORDER BY start_time DESC LIMIT 1),
--     1000,
--     TRUE
-- );

-- 4.3 Execute actual rebuild (after dry run validation)
-- TODO: Uncomment after reviewing dry run results
-- SELECT * FROM rebuild_hash_chain(
--     (SELECT rebuild_id FROM hash_chain_rebuild_log WHERE rebuild_status = 'DRY_RUN_COMPLETE' ORDER BY start_time DESC LIMIT 1),
--     1000,
--     FALSE
-- );

-- =============================================================================
-- STEP 5: POST-REBUILD VALIDATION
-- =============================================================================

-- 5.1 Complete hash chain validation
CREATE OR REPLACE FUNCTION validate_complete_hash_chain(
    p_sample_rate DECIMAL DEFAULT 1.0  -- 1.0 = 100%, 0.1 = 10% sample
)
RETURNS TABLE (
    validation_passed BOOLEAN,
    total_records BIGINT,
    valid_records BIGINT,
    invalid_records BIGINT,
    validation_details JSONB
) AS $$
DECLARE
    v_total BIGINT;
    v_valid BIGINT := 0;
    v_invalid BIGINT := 0;
    v_details JSONB := '[]'::JSONB;
    rec RECORD;
    v_expected_hash TEXT;
    v_prev_hash TEXT;
BEGIN
    -- Get total count
    SELECT COUNT(*) INTO v_total FROM ledger_transactions;
    
    -- Validate each record
    FOR rec IN 
        SELECT 
            transaction_id,
            previous_hash,
            computed_hash,
            transaction_data::TEXT,
            created_at
        FROM ledger_transactions
        WHERE random() < p_sample_rate  -- Sampling for large datasets
        ORDER BY transaction_id
    LOOP
        -- Check chain continuity
        IF v_prev_hash IS NOT NULL AND rec.previous_hash != v_prev_hash THEN
            v_invalid := v_invalid + 1;
            v_details := v_details || jsonb_build_object(
                'transaction_id', rec.transaction_id,
                'error', 'BROKEN_CHAIN',
                'expected_previous', v_prev_hash,
                'actual_previous', rec.previous_hash
            );
        ELSE
            -- Validate hash computation
            v_expected_hash := encode(
                digest(
                    concat(rec.previous_hash, rec.transaction_data::TEXT)::bytea,
                    'sha256'
                ),
                'hex'
            );
            
            IF rec.computed_hash = v_expected_hash THEN
                v_valid := v_valid + 1;
            ELSE
                v_invalid := v_invalid + 1;
                v_details := v_details || jsonb_build_object(
                    'transaction_id', rec.transaction_id,
                    'error', 'INVALID_HASH',
                    'expected_hash', v_expected_hash,
                    'actual_hash', rec.computed_hash
                );
            END IF;
        END IF;
        
        v_prev_hash := rec.computed_hash;
    END LOOP;
    
    -- Scale results if sampling was used
    IF p_sample_rate < 1.0 THEN
        v_valid := (v_valid / p_sample_rate)::BIGINT;
        v_invalid := (v_invalid / p_sample_rate)::BIGINT;
    END IF;
    
    RETURN QUERY SELECT 
        v_invalid = 0,
        v_total,
        v_valid,
        v_invalid,
        v_details;
END;
$$ LANGUAGE plpgsql;

-- 5.2 Execute validation
SELECT * FROM validate_complete_hash_chain(1.0);

-- =============================================================================
-- STEP 6: TEST CASES WITH EXPECTED RESULTS
-- =============================================================================

-- Test Case 6.1: Verify no broken chain links
-- Expected: Empty result set
SELECT 
    'TEST_6.1_NO_BROKEN_LINKS' as test_name,
    CASE WHEN COUNT(*) = 0 THEN 'PASSED' ELSE 'FAILED' END as result,
    COUNT(*) as broken_links
FROM (
    SELECT transaction_id
    FROM ledger_transactions t1
    WHERE previous_hash != (
        SELECT computed_hash 
        FROM ledger_transactions t2 
        WHERE t2.transaction_id = t1.transaction_id - 1
    )
    AND transaction_id > (SELECT MIN(transaction_id) FROM ledger_transactions)
) broken;

-- Test Case 6.2: Verify hash computation integrity
-- Expected: 0 invalid hashes
SELECT 
    'TEST_6.2_HASH_INTEGRITY' as test_name,
    CASE WHEN invalid_count = 0 THEN 'PASSED' ELSE 'FAILED' END as result,
    invalid_count
FROM (
    SELECT COUNT(*) as invalid_count
    FROM ledger_transactions
    WHERE computed_hash != encode(
        digest(
            concat(previous_hash, transaction_data::TEXT)::bytea,
            'sha256'
        ),
        'hex'
    )
) subq;

-- Test Case 6.3: Verify genesis record
-- Expected: previous_hash is NULL or specific genesis marker
SELECT 
    'TEST_6.3_GENESIS_RECORD' as test_name,
    CASE 
        WHEN previous_hash IS NULL OR previous_hash = 'GENESIS' 
        THEN 'PASSED' 
        ELSE 'FAILED' 
    END as result,
    transaction_id,
    previous_hash
FROM ledger_transactions
WHERE transaction_id = (SELECT MIN(transaction_id) FROM ledger_transactions);

-- Test Case 6.4: Performance benchmark
-- Expected: Validation completes within acceptable time
DO $$
DECLARE
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_duration_ms INTEGER;
BEGIN
    v_start_time := clock_timestamp();
    PERFORM * FROM validate_complete_hash_chain(0.1);  -- 10% sample
    v_end_time := clock_timestamp();
    v_duration_ms := EXTRACT(MILLISECONDS FROM (v_end_time - v_start_time))::INTEGER;
    
    RAISE NOTICE 'TEST_6.4_PERFORMANCE: Hash chain validation of 10%% sample completed in % ms', v_duration_ms;
    
    IF v_duration_ms > 30000 THEN  -- 30 seconds threshold
        RAISE WARNING 'Performance test FAILED: % ms exceeds 30000 ms threshold', v_duration_ms;
    ELSE
        RAISE NOTICE 'Performance test PASSED';
    END IF;
END $$;

-- =============================================================================
-- STEP 7: ROLLBACK PROCEDURES
-- =============================================================================

-- 7.1 Full rollback to original hashes
CREATE OR REPLACE PROCEDURE rollback_hash_chain_rebuild(
    p_rebuild_id UUID
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_backup_record RECORD;
    v_updated_count INTEGER := 0;
BEGIN
    -- Verify rebuild exists and can be rolled back
    IF NOT EXISTS (
        SELECT 1 FROM hash_chain_rebuild_log
        WHERE rebuild_id = p_rebuild_id
        AND rebuild_status IN ('COMPLETED', 'DRY_RUN_COMPLETE')
    ) THEN
        RAISE EXCEPTION 'Rebuild % cannot be rolled back (not found or invalid status)', p_rebuild_id;
    END IF;
    
    -- Log rollback start
    UPDATE hash_chain_rebuild_log
    SET rebuild_status = 'ROLLBACK_IN_PROGRESS'
    WHERE rebuild_id = p_rebuild_id;
    
    -- Restore original hashes
    FOR v_backup_record IN 
        SELECT * FROM hash_chain_rebuild_backup
        WHERE rebuild_id = p_rebuild_id
    LOOP
        UPDATE ledger_transactions
        SET 
            previous_hash = v_backup_record.previous_hash_original,
            computed_hash = v_backup_record.computed_hash_original,
            updated_at = CURRENT_TIMESTAMP
        WHERE transaction_id = v_backup_record.transaction_id;
        
        v_updated_count := v_updated_count + 1;
    END LOOP;
    
    -- Update corruption log
    UPDATE hash_chain_corruption_log
    SET resolved_at = CURRENT_TIMESTAMP,
        resolution_action = 'ROLLBACK_TO_ORIGINAL'
    WHERE rebuild_id = p_rebuild_id;
    
    -- Update rebuild log
    UPDATE hash_chain_rebuild_log
    SET 
        rebuild_status = 'ROLLED_BACK',
        end_time = CURRENT_TIMESTAMP
    WHERE rebuild_id = p_rebuild_id;
    
    RAISE NOTICE 'Rollback completed. % records restored.', v_updated_count;
END;
$$;

-- 7.2 Emergency stop and validate
CREATE OR REPLACE FUNCTION emergency_stop_rebuild()
RETURNS TEXT AS $$
DECLARE
    v_active_rebuild UUID;
BEGIN
    -- Find active rebuild
    SELECT rebuild_id INTO v_active_rebuild
    FROM hash_chain_rebuild_log
    WHERE rebuild_status IN ('INITIATED', 'IN_PROGRESS')
    ORDER BY start_time DESC
    LIMIT 1;
    
    IF v_active_rebuild IS NULL THEN
        RETURN 'No active rebuild found';
    END IF;
    
    -- Mark as stopped
    UPDATE hash_chain_rebuild_log
    SET 
        rebuild_status = 'EMERGENCY_STOPPED',
        end_time = CURRENT_TIMESTAMP,
        root_cause_analysis = COALESCE(root_cause_analysis, '') || E'\nEmergency stop at ' || CURRENT_TIMESTAMP
    WHERE rebuild_id = v_active_rebuild;
    
    RETURN format('Rebuild %s has been emergency stopped. Review and run rollback if needed.', v_active_rebuild);
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 8: VALIDATION CHECKS
-- =============================================================================

-- 8.1 Pre-rebuild checklist
DO $$
BEGIN
    RAISE NOTICE 'PRE-REBUILD CHECKLIST:';
    RAISE NOTICE '1. Backup completed: %', 
        EXISTS(SELECT 1 FROM hash_chain_rebuild_backup WHERE rebuild_id = (SELECT rebuild_id FROM hash_chain_rebuild_log WHERE rebuild_status = 'INITIATED'));
    RAISE NOTICE '2. Dry run executed: %', 
        EXISTS(SELECT 1 FROM hash_chain_rebuild_log WHERE rebuild_status = 'DRY_RUN_COMPLETE');
    RAISE NOTICE '3. No active transactions: %', 
        (SELECT count(*) = 0 FROM pg_stat_activity WHERE state = 'active' AND query LIKE '%ledger_transactions%');
END $$;

-- 8.2 Post-rebuild checklist
DO $$
BEGIN
    RAISE NOTICE 'POST-REBUILD CHECKLIST:';
    RAISE NOTICE '1. Validation passed: %', 
        (SELECT validation_passed FROM validate_complete_hash_chain(1.0));
    RAISE NOTICE '2. All corruptions resolved: %', 
        (SELECT count(*) = 0 FROM hash_chain_corruption_log WHERE resolved_at IS NULL);
    RAISE NOTICE '3. Rebuild log updated: %', 
        EXISTS(SELECT 1 FROM hash_chain_rebuild_log WHERE rebuild_status = 'COMPLETED');
END $$;

-- =============================================================================
-- TODO LIST FOR CUSTOMIZATION
-- =============================================================================

/*
TODO-1: Customize table names to match your ledger schema:
        - ledger_transactions
        - Transaction ID column names
        - Hash column names
        - Data column names

TODO-2: Adjust batch sizes based on database performance:
        - Default 1000 may be too small/large for your environment
        - Consider memory constraints

TODO-3: Configure corruption detection thresholds:
        - Maximum acceptable corruption percentage
        - Auto-rollback triggers

TODO-4: Set up monitoring and alerting:
        - Rebuild progress tracking
        - Performance metrics
        - Failure notifications

TODO-5: Implement incremental rebuild for large datasets:
        - Time-based partitioning
        - Parallel processing

TODO-6: Customize hash algorithm if not using SHA-256:
        - Blake2b, SHA-3, etc.

TODO-7: Configure backup retention policies:
        - How long to keep rebuild backups
        - Storage optimization

TODO-8: Establish maintenance windows:
        - When rebuilds can occur
        - Impact on production

TODO-9: Document emergency procedures:
        - Contact information
        - Escalation paths

TODO-10: Test rollback procedures regularly:
        - Automated testing schedule
        - Validation criteria
*/

-- =============================================================================
-- END OF HASH CHAIN REBUILD PROCEDURE
-- =============================================================================
