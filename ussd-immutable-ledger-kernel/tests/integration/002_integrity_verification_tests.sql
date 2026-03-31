-- =============================================================================
-- USSD KERNEL INTEGRATION TESTS - INTEGRITY VERIFICATION
-- =============================================================================
-- FILENAME:    002_integrity_verification_tests.sql
-- DESCRIPTION: Automated tests for hash chain integrity, Merkle proofs,
--              and cryptographic verification. Run after baseline migration.
-- =============================================================================

/*
================================================================================
INTEGRITY VERIFICATION TEST SUITE
================================================================================

This test suite verifies:
1. Hash chain integrity (linked list verification)
2. Merkle tree construction and proofs
3. Block sealing and validation
4. Digital signature verification
5. Tamper detection capabilities

All tests are designed to run in a transaction that rolls back,
ensuring no test data persists in the database.

================================================================================
*/

-- Start test transaction
BEGIN;

-- =============================================================================
-- TEST FRAMEWORK
-- =============================================================================

CREATE OR REPLACE FUNCTION test_framework.assert_true(
    condition BOOLEAN,
    test_name TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    IF condition THEN
        RAISE NOTICE 'PASS: %', test_name;
        RETURN TRUE;
    ELSE
        RAISE NOTICE 'FAIL: %', test_name;
        RETURN FALSE;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION test_framework.assert_equals(
    expected TEXT,
    actual TEXT,
    test_name TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    IF expected = actual THEN
        RAISE NOTICE 'PASS: %', test_name;
        RETURN TRUE;
    ELSE
        RAISE NOTICE 'FAIL: % - Expected: %, Got: %', test_name, expected, actual;
        RETURN FALSE;
    END IF;
END;
$$;

-- =============================================================================
-- TEST SUITE 1: HASH CHAIN INTEGRITY
-- =============================================================================

-- Test 1.1: Verify hash chain is unbroken
DO $$
DECLARE
    v_broken_links INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_broken_links
    FROM core.transaction_log t
    WHERE t.previous_transaction_id IS NOT NULL
    AND NOT EXISTS (
        SELECT 1 FROM core.transaction_log t2 
        WHERE t2.transaction_id = t.previous_transaction_id
    );
    
    PERFORM test_framework.assert_equals(
        '0',
        v_broken_links::TEXT,
        'Hash chain: No broken links in transaction_log'
    );
END;
$$;

-- Test 1.2: Verify each transaction links correctly to previous
DO $$
DECLARE
    v_invalid_links INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_invalid_links
    FROM core.transaction_log t
    JOIN core.transaction_log t_prev ON t.previous_transaction_id = t_prev.transaction_id
    WHERE t.previous_hash != t_prev.current_hash;
    
    PERFORM test_framework.assert_equals(
        '0',
        v_invalid_links::TEXT,
        'Hash chain: All previous_hash values match current_hash of predecessor'
    );
END;
$$;

-- Test 1.3: Verify genesis transactions have NULL previous_hash
DO $$
DECLARE
    v_invalid_genesis INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_invalid_genesis
    FROM core.transaction_log
    WHERE previous_transaction_id IS NULL
    AND previous_hash IS NOT NULL;
    
    PERFORM test_framework.assert_equals(
        '0',
        v_invalid_genesis::TEXT,
        'Hash chain: Genesis transactions have NULL previous_hash'
    );
END;
$$;

-- Test 1.4: Verify transaction hash format (64 character hex)
DO $$
DECLARE
    v_invalid_hashes INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_invalid_hashes
    FROM core.transaction_log
    WHERE current_hash IS NOT NULL
    AND (LENGTH(current_hash) != 64 OR current_hash !~ '^[a-f0-9]+$');
    
    PERFORM test_framework.assert_equals(
        '0',
        v_invalid_hashes::TEXT,
        'Hash chain: All hashes are valid 64-character hex strings'
    );
END;
$$;

-- =============================================================================
-- TEST SUITE 2: MERKLE TREE INTEGRITY
-- =============================================================================

-- Test 2.1: Verify all blocks have Merkle roots
DO $$
DECLARE
    v_missing_roots INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_missing_roots
    FROM core.blocks
    WHERE merkle_root IS NULL
    AND status IN ('SEALED', 'CONFIRMED', 'ANCHORED');
    
    PERFORM test_framework.assert_equals(
        '0',
        v_missing_roots::TEXT,
        'Merkle: All sealed blocks have Merkle roots'
    );
END;
$$;

-- Test 2.2: Verify Merkle root format
DO $$
DECLARE
    v_invalid_roots INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_invalid_roots
    FROM core.blocks
    WHERE merkle_root IS NOT NULL
    AND (LENGTH(merkle_root) != 64 OR merkle_root !~ '^[a-f0-9]+$');
    
    PERFORM test_framework.assert_equals(
        '0',
        v_invalid_roots::TEXT,
        'Merkle: All Merkle roots are valid 64-character hex strings'
    );
END;
$$;

-- Test 2.3: Verify block chain links
DO $$
DECLARE
    v_broken_links INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_broken_links
    FROM core.blocks b
    WHERE b.previous_block_hash IS NOT NULL
    AND NOT EXISTS (
        SELECT 1 FROM core.blocks b2 
        WHERE b2.block_hash = b.previous_block_hash
    );
    
    PERFORM test_framework.assert_equals(
        '0',
        v_broken_links::TEXT,
        'Merkle: Block chain links are unbroken'
    );
END;
$$;

-- Test 2.4: Verify block numbers are sequential
DO $$
DECLARE
    v_gaps INTEGER;
BEGIN
    WITH block_gaps AS (
        SELECT block_number, 
               LAG(block_number) OVER (ORDER BY block_number) as prev_number
        FROM core.blocks
    )
    SELECT COUNT(*) INTO v_gaps
    FROM block_gaps
    WHERE prev_number IS NOT NULL
    AND block_number != prev_number + 1;
    
    PERFORM test_framework.assert_equals(
        '0',
        v_gaps::TEXT,
        'Merkle: Block numbers are sequential with no gaps'
    );
END;
$$;

-- =============================================================================
-- TEST SUITE 3: MERKLE PROOF VERIFICATION
-- =============================================================================

-- Test 3.1: Verify Merkle proof structure
DO $$
DECLARE
    v_invalid_proofs INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_invalid_proofs
    FROM core.merkle_proofs
    WHERE proof_path IS NULL
    OR jsonb_array_length(proof_path) = 0;
    
    -- Skip if no proofs exist
    IF NOT EXISTS (SELECT 1 FROM core.merkle_proofs) THEN
        RAISE NOTICE 'SKIP: Merkle proof structure - No proofs in database';
    ELSE
        PERFORM test_framework.assert_equals(
            '0',
            v_invalid_proofs::TEXT,
            'Merkle proofs: All proofs have valid path structure'
        );
    END IF;
END;
$$;

-- Test 3.2: Test Merkle inclusion verification function
DO $$
DECLARE
    v_test_result BOOLEAN;
    v_leaf_hash VARCHAR(64);
    v_root_hash VARCHAR(64);
BEGIN
    -- Get a sample leaf and root
    SELECT leaf_hash, root_hash 
    INTO v_leaf_hash, v_root_hash
    FROM core.merkle_proofs
    LIMIT 1;
    
    IF v_leaf_hash IS NULL THEN
        RAISE NOTICE 'SKIP: Merkle inclusion verification - No proofs available';
    ELSE
        -- Call the verification function
        SELECT core.verify_merkle_inclusion(v_leaf_hash, v_root_hash) INTO v_test_result;
        
        PERFORM test_framework.assert_true(
            v_test_result,
            'Merkle inclusion: Proof verification returns correct result'
        );
    END IF;
END;
$$;

-- =============================================================================
-- TEST SUITE 4: DIGITAL SIGNATURES
-- =============================================================================

-- Test 4.1: Verify transaction signatures exist
DO $$
DECLARE
    v_unsigned_transactions INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_unsigned_transactions
    FROM core.transaction_log
    WHERE digital_signature IS NULL
    AND status = 'completed';
    
    -- This is informational - not all transactions may require signatures
    RAISE NOTICE 'INFO: % completed transactions lack digital signatures', v_unsigned_transactions;
END;
$$;

-- Test 4.2: Verify signature key references
DO $$
DECLARE
    v_invalid_key_refs INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_invalid_key_refs
    FROM core.transaction_log t
    WHERE t.signing_key_id IS NOT NULL
    AND NOT EXISTS (
        SELECT 1 FROM core.signing_keys k 
        WHERE k.key_id = t.signing_key_id
    );
    
    PERFORM test_framework.assert_equals(
        '0',
        v_invalid_key_refs::TEXT,
        'Signatures: All signing_key_id references are valid'
    );
END;
$$;

-- Test 4.3: Verify block kernel signatures
DO $$
DECLARE
    v_unsigned_blocks INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_unsigned_blocks
    FROM core.blocks
    WHERE kernel_signature IS NULL
    AND status IN ('SEALED', 'CONFIRMED', 'ANCHORED');
    
    PERFORM test_framework.assert_equals(
        '0',
        v_unsigned_blocks::TEXT,
        'Signatures: All sealed blocks have kernel signatures'
    );
END;
$$;

-- =============================================================================
-- TEST SUITE 5: TAMPER DETECTION
-- =============================================================================

-- Test 5.1: Verify audit trail captures all changes
DO $$
DECLARE
    v_audit_gap BOOLEAN;
BEGIN
    -- Check for gaps in audit sequence
    SELECT EXISTS (
        SELECT 1 FROM (
            SELECT audit_id, 
                   audit_id - LAG(audit_id) OVER (ORDER BY audit_id) as gap
            FROM core.audit_trail
        ) sub
        WHERE gap > 1
    ) INTO v_audit_gap;
    
    -- This is informational as audit_id may not be sequential
    IF v_audit_gap THEN
        RAISE NOTICE 'INFO: Gaps detected in audit_trail sequence (may be normal with UUIDs)';
    ELSE
        RAISE NOTICE 'PASS: No gaps in audit_trail';
    END IF;
END;
$$;

-- Test 5.2: Verify continuous audit trail chain
DO $$
DECLARE
    v_broken_chains INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_broken_chains
    FROM core.continuous_audit_trail c
    WHERE c.previous_hash != 'GENESIS'
    AND NOT EXISTS (
        SELECT 1 FROM core.continuous_audit_trail c2 
        WHERE c2.record_hash = c.previous_hash
    );
    
    PERFORM test_framework.assert_equals(
        '0',
        v_broken_chains::TEXT,
        'Tamper detection: Continuous audit trail chain is unbroken'
    );
END;
$$;

-- Test 5.3: Verify security audit log has integrity
DO $$
DECLARE
    v_security_events INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_security_events
    FROM core.security_audit_log
    WHERE severity IN ('HIGH', 'CRITICAL');
    
    RAISE NOTICE 'INFO: % HIGH/CRITICAL security events logged', v_security_events;
END;
$$;

-- =============================================================================
-- TEST SUITE 6: EXTERNAL BLOCKCHAIN ANCHORING
-- =============================================================================

-- Test 6.1: Verify blockchain anchors reference valid blocks
DO $$
DECLARE
    v_invalid_refs INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_invalid_refs
    FROM core.external_blockchain_anchors a
    WHERE NOT EXISTS (
        SELECT 1 FROM core.blocks b WHERE b.block_id = a.block_id
    );
    
    PERFORM test_framework.assert_equals(
        '0',
        v_invalid_refs::TEXT,
        'Blockchain anchor: All anchors reference valid blocks'
    );
END;
$$;

-- Test 6.2: Verify anchor status transitions
DO $$
DECLARE
    v_invalid_transitions INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_invalid_transitions
    FROM core.external_blockchain_anchors
    WHERE anchor_status = 'FINALIZED'
    AND finalized_at IS NULL;
    
    PERFORM test_framework.assert_equals(
        '0',
        v_invalid_transitions::TEXT,
        'Blockchain anchor: Finalized anchors have finalized_at timestamp'
    );
END;
$$;

-- =============================================================================
-- TEST SUITE 7: PERFORMANCE BOUNDS
-- =============================================================================

-- Test 7.1: Verify hash chain verification performance
DO $$
DECLARE
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_elapsed_ms NUMERIC;
    v_sample_size INTEGER := 1000;
BEGIN
    v_start_time := clock_timestamp();
    
    PERFORM COUNT(*) FROM core.transaction_log
    WHERE transaction_id IN (
        SELECT transaction_id FROM core.transaction_log
        ORDER BY transaction_id
        LIMIT v_sample_size
    );
    
    v_end_time := clock_timestamp();
    v_elapsed_ms := EXTRACT(EPOCH FROM (v_end_time - v_start_time)) * 1000;
    
    RAISE NOTICE 'INFO: Sample query of % records took % ms', v_sample_size, ROUND(v_elapsed_ms, 2);
    
    -- Should complete in less than 1 second for 1000 records
    IF v_elapsed_ms > 1000 THEN
        RAISE WARNING 'PERFORMANCE: Query took longer than 1 second';
    ELSE
        RAISE NOTICE 'PASS: Query performance within bounds';
    END IF;
END;
$$;

-- =============================================================================
-- TEST RESULTS SUMMARY
-- =============================================================================

DO $$
DECLARE
    v_total_tests INTEGER := 0;
    v_passed_tests INTEGER := 0;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '================================================================================';
    RAISE NOTICE 'INTEGRITY VERIFICATION TEST SUITE COMPLETE';
    RAISE NOTICE '================================================================================';
    RAISE NOTICE '';
    RAISE NOTICE 'Test Categories:';
    RAISE NOTICE '  1. Hash Chain Integrity (4 tests)';
    RAISE NOTICE '  2. Merkle Tree Integrity (4 tests)';
    RAISE NOTICE '  3. Merkle Proof Verification (2 tests)';
    RAISE NOTICE '  4. Digital Signatures (3 tests)';
    RAISE NOTICE '  5. Tamper Detection (3 tests)';
    RAISE NOTICE '  6. External Blockchain Anchoring (2 tests)';
    RAISE NOTICE '  7. Performance Bounds (1 test)';
    RAISE NOTICE '';
    RAISE NOTICE 'All integrity verification tests have been executed.';
    RAISE NOTICE 'Review any FAIL messages above for issues.';
    RAISE NOTICE '';
    RAISE NOTICE 'Recommended Actions:';
    RAISE NOTICE '  - If hash chain tests fail: Run core.emergency_verify_hash_chain()';
    RAISE NOTICE '  - If Merkle tests fail: Rebuild Merkle trees for affected blocks';
    RAISE NOTICE '  - If signature tests fail: Verify signing keys are properly configured';
    RAISE NOTICE '';
    RAISE NOTICE '================================================================================';
END;
$$;

-- Rollback test transaction to ensure no test data persists
ROLLBACK;

-- =============================================================================
-- END OF TESTS
-- =============================================================================
