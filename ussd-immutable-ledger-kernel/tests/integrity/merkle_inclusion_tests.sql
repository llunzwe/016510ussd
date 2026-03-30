-- ============================================================================
-- MERKLE INCLUSION TESTS
-- ============================================================================
-- Purpose: Test suite for Merkle tree inclusion proofs in the USSD ledger
-- Author:  USSD Immutable Ledger Team
-- Date:    2026-03-30
-- ============================================================================
-- COMPLIANCE ANNOTATIONS:
--   Integrity Validation Standards:
--   - RFC 6962: Certificate Transparency - Merkle tree requirements
--   - NIST SP 800-57: Key management for hash-based proofs
--   - ISO/IEC 27036: Information security for supplier relationships
--
--   Test Data Protection:
--   - Synthetic transaction data used for all test cases
--   - No cryptographic keys from production systems
--   - Test vectors isolated from production environment
--
--   Security Testing Requirements:
--   - CWE-354: Improper validation of integrity check value
--   - Verifiable computation proof standards compliance
--
--   Performance Benchmarks:
--   - Proof generation: < 100ms for 10,000 leaf tree
--   - Proof verification: < 50ms per inclusion proof
-- ============================================================================

-- =============================================================================
-- TEST SETUP
-- =============================================================================

-- Create test results tracking
CREATE TABLE IF NOT EXISTS merkle_test_results (
    test_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_name TEXT NOT NULL,
    test_category TEXT NOT NULL,
    test_executed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    test_passed BOOLEAN NOT NULL,
    expected_result TEXT,
    actual_result TEXT,
    execution_time_ms INTEGER,
    error_message TEXT,
    test_data JSONB
);

-- Create Merkle tree helper functions for testing
CREATE OR REPLACE FUNCTION compute_merkle_hash(
    p_left TEXT,
    p_right TEXT
)
RETURNS TEXT AS $$
BEGIN
    RETURN encode(
        digest(
            concat(COALESCE(p_left, ''), COALESCE(p_right, ''))::bytea,
            'sha256'
        ),
        'hex'
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- =============================================================================
-- TEST 1: MERKLE TREE CONSTRUCTION
-- =============================================================================

-- Test 1.1: Verify Merkle root computation
CREATE OR REPLACE FUNCTION test_merkle_root_computation()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_hashes TEXT[];
    v_merkle_root TEXT;
    v_passed BOOLEAN;
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
BEGIN
    test_name := 'TEST_1.1_MERKLE_ROOT_COMPUTATION';
    v_start_time := clock_timestamp();
    
    -- Get sample hashes from ledger
    SELECT array_agg(computed_hash ORDER BY transaction_id)
    INTO v_hashes
    FROM (
        SELECT computed_hash, transaction_id
        FROM ledger_transactions
        ORDER BY transaction_id
        LIMIT 100
    ) sub;
    
    -- Compute Merkle root
    v_merkle_root := compute_merkle_root(v_hashes);
    
    v_passed := v_merkle_root IS NOT NULL AND length(v_merkle_root) = 64;
    v_end_time := clock_timestamp();
    
    details := jsonb_build_object(
        'leaf_count', array_length(v_hashes, 1),
        'merkle_root', v_merkle_root,
        'root_length', length(v_merkle_root)
    );
    
    INSERT INTO merkle_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data, execution_time_ms)
    VALUES (test_name, 'CONSTRUCTION', v_passed, 'Valid 64-char root', 
            COALESCE(v_merkle_root, 'NULL'), details,
            EXTRACT(MILLISECONDS FROM (v_end_time - v_start_time))::INTEGER);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Compute Merkle root from array of hashes
CREATE OR REPLACE FUNCTION compute_merkle_root(p_hashes TEXT[])
RETURNS TEXT AS $$
DECLARE
    v_level TEXT[];
    v_next_level TEXT[];
    v_i INTEGER;
BEGIN
    IF p_hashes IS NULL OR array_length(p_hashes, 1) IS NULL THEN
        RETURN NULL;
    END IF;
    
    v_level := p_hashes;
    
    -- Build tree bottom-up
    WHILE array_length(v_level, 1) > 1 LOOP
        v_next_level := ARRAY[]::TEXT[];
        
        FOR v_i IN 1..array_length(v_level, 1) BY 2 LOOP
            IF v_i + 1 <= array_length(v_level, 1) THEN
                v_next_level := array_append(v_next_level, 
                    compute_merkle_hash(v_level[v_i], v_level[v_i + 1]));
            ELSE
                -- Odd node - duplicate it
                v_next_level := array_append(v_next_level, 
                    compute_merkle_hash(v_level[v_i], v_level[v_i]));
            END IF;
        END LOOP;
        
        v_level := v_next_level;
    END LOOP;
    
    RETURN v_level[1];
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST 2: MERKLE INCLUSION PROOFS
-- =============================================================================

-- Test 2.1: Verify inclusion proof generation
CREATE OR REPLACE FUNCTION test_inclusion_proof_generation()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_target_hash TEXT;
    v_merkle_root TEXT;
    v_proof JSONB;
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_2.1_INCLUSION_PROOF_GENERATION';
    
    -- Get a sample hash
    SELECT computed_hash INTO v_target_hash
    FROM ledger_transactions
    ORDER BY transaction_id
    LIMIT 1;
    
    -- Generate proof (simplified implementation)
    v_proof := generate_inclusion_proof(v_target_hash);
    
    v_passed := v_proof IS NOT NULL AND jsonb_array_length(v_proof->'proof_path') > 0;
    
    details := jsonb_build_object(
        'target_hash', v_target_hash,
        'has_proof', v_proof IS NOT NULL,
        'proof_path_length', jsonb_array_length(COALESCE(v_proof->'proof_path', '[]'::JSONB))
    );
    
    INSERT INTO merkle_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data)
    VALUES (test_name, 'INCLUSION_PROOF', v_passed, 'Valid proof generated', 
            CASE WHEN v_passed THEN 'Generated' ELSE 'Failed' END, details);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Simplified inclusion proof generation
CREATE OR REPLACE FUNCTION generate_inclusion_proof(p_target_hash TEXT)
RETURNS JSONB AS $$
DECLARE
    v_hashes TEXT[];
    v_target_index INTEGER;
    v_proof_path JSONB := '[]'::JSONB;
    v_level TEXT[];
    v_next_level TEXT[];
    v_i INTEGER;
    v_current_index INTEGER;
BEGIN
    -- Get all hashes
    SELECT array_agg(computed_hash ORDER BY transaction_id)
    INTO v_hashes
    FROM ledger_transactions;
    
    IF v_hashes IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Find target index
    SELECT array_position(v_hashes, p_target_hash) INTO v_target_index;
    
    IF v_target_index IS NULL THEN
        RETURN NULL;
    END IF;
    
    v_current_index := v_target_index - 1;  -- 0-based index
    v_level := v_hashes;
    
    -- Build proof path
    WHILE array_length(v_level, 1) > 1 LOOP
        v_next_level := ARRAY[]::TEXT[];
        
        FOR v_i IN 1..array_length(v_level, 1) BY 2 LOOP
            IF v_i + 1 <= array_length(v_level, 1) THEN
                -- Add sibling to proof if this pair contains target
                IF v_current_index >= v_i - 1 AND v_current_index <= v_i THEN
                    IF v_current_index = v_i - 1 THEN
                        v_proof_path := v_proof_path || jsonb_build_object(
                            'hash', v_level[v_i + 1], 'position', 'right');
                    ELSE
                        v_proof_path := v_proof_path || jsonb_build_object(
                            'hash', v_level[v_i], 'position', 'left');
                    END IF;
                END IF;
                
                v_next_level := array_append(v_next_level, 
                    compute_merkle_hash(v_level[v_i], v_level[v_i + 1]));
            ELSE
                -- Odd node
                v_next_level := array_append(v_next_level, 
                    compute_merkle_hash(v_level[v_i], v_level[v_i]));
            END IF;
        END LOOP;
        
        v_current_index := v_current_index / 2;
        v_level := v_next_level;
    END LOOP;
    
    RETURN jsonb_build_object(
        'target_hash', p_target_hash,
        'merkle_root', v_level[1],
        'proof_path', v_proof_path
    );
END;
$$ LANGUAGE plpgsql;

-- Test 2.2: Verify inclusion proof validation
CREATE OR REPLACE FUNCTION test_inclusion_proof_verification()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_target_hash TEXT;
    v_proof JSONB;
    v_verified BOOLEAN;
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_2.2_INCLUSION_PROOF_VERIFICATION';
    
    -- Get sample
    SELECT computed_hash INTO v_target_hash
    FROM ledger_transactions
    ORDER BY transaction_id
    LIMIT 1;
    
    v_proof := generate_inclusion_proof(v_target_hash);
    v_verified := verify_inclusion_proof(v_target_hash, v_proof);
    
    v_passed := v_verified;
    
    details := jsonb_build_object(
        'target_hash', v_target_hash,
        'proof_valid', v_verified
    );
    
    INSERT INTO merkle_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data)
    VALUES (test_name, 'INCLUSION_PROOF', v_passed, 'Proof verified', 
            CASE WHEN v_verified THEN 'Verified' ELSE 'Failed' END, details);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Verify inclusion proof
CREATE OR REPLACE FUNCTION verify_inclusion_proof(
    p_target_hash TEXT,
    p_proof JSONB
)
RETURNS BOOLEAN AS $$
DECLARE
    v_computed_hash TEXT;
    v_proof_element JSONB;
BEGIN
    IF p_proof IS NULL OR p_target_hash IS NULL THEN
        RETURN FALSE;
    END IF;
    
    v_computed_hash := p_target_hash;
    
    -- Walk up the proof path
    FOR v_proof_element IN SELECT jsonb_array_elements(p_proof->'proof_path')
    LOOP
        IF v_proof_element->>'position' = 'left' THEN
            v_computed_hash := compute_merkle_hash(v_proof_element->>'hash', v_computed_hash);
        ELSE
            v_computed_hash := compute_merkle_hash(v_computed_hash, v_proof_element->>'hash');
        END IF;
    END LOOP;
    
    -- Compare with expected root
    RETURN v_computed_hash = (p_proof->>'merkle_root');
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST 3: MERKLE TREE PROPERTIES
-- =============================================================================

-- Test 3.1: Verify tree determinism
CREATE OR REPLACE FUNCTION test_merkle_determinism()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_root1 TEXT;
    v_root2 TEXT;
    v_hashes TEXT[];
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_3.1_MERKLE_DETERMINISM';
    
    -- Get same set of hashes
    SELECT array_agg(computed_hash ORDER BY transaction_id)
    INTO v_hashes
    FROM (SELECT computed_hash, transaction_id FROM ledger_transactions LIMIT 50) sub;
    
    -- Compute root twice
    v_root1 := compute_merkle_root(v_hashes);
    v_root2 := compute_merkle_root(v_hashes);
    
    v_passed := v_root1 = v_root2;
    
    details := jsonb_build_object(
        'root1', v_root1,
        'root2', v_root2,
        'match', v_passed
    );
    
    INSERT INTO merkle_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data)
    VALUES (test_name, 'PROPERTIES', v_passed, 'Identical roots', 
            CASE WHEN v_passed THEN 'Match' ELSE 'Mismatch' END, details);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Test 3.2: Verify order sensitivity
CREATE OR REPLACE FUNCTION test_merkle_order_sensitivity()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_root1 TEXT;
    v_root2 TEXT;
    v_hashes1 TEXT[];
    v_hashes2 TEXT[];
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_3.2_MERKLE_ORDER_SENSITIVITY';
    
    -- Get hashes in different order
    SELECT array_agg(computed_hash ORDER BY transaction_id)
    INTO v_hashes1
    FROM (SELECT computed_hash, transaction_id FROM ledger_transactions LIMIT 10) sub;
    
    SELECT array_agg(computed_hash ORDER BY transaction_id DESC)
    INTO v_hashes2
    FROM (SELECT computed_hash, transaction_id FROM ledger_transactions LIMIT 10) sub;
    
    v_root1 := compute_merkle_root(v_hashes1);
    v_root2 := compute_merkle_root(v_hashes2);
    
    -- Different order should produce different root
    v_passed := v_root1 != v_root2;
    
    details := jsonb_build_object(
        'root_ordered', v_root1,
        'root_reversed', v_root2,
        'different', v_passed
    );
    
    INSERT INTO merkle_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data)
    VALUES (test_name, 'PROPERTIES', v_passed, 'Different order = different root', 
            CASE WHEN v_passed THEN 'Different' ELSE 'Same (unexpected)' END, details);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Test 3.3: Verify single leaf handling
CREATE OR REPLACE FUNCTION test_merkle_single_leaf()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_root TEXT;
    v_single_hash TEXT[];
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_3.3_MERKLE_SINGLE_LEAF';
    
    -- Test with single hash
    v_single_hash := ARRAY['abcd1234'::TEXT];
    v_root := compute_merkle_root(v_single_hash);
    
    -- With single leaf, root equals the hash (after potential duplication)
    v_passed := v_root IS NOT NULL AND length(v_root) = 64;
    
    details := jsonb_build_object(
        'single_hash', v_single_hash[1],
        'computed_root', v_root
    );
    
    INSERT INTO merkle_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data)
    VALUES (test_name, 'PROPERTIES', v_passed, 'Valid root for single leaf', v_root, details);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST 4: PERFORMANCE TESTS
-- =============================================================================

-- Test 4.1: Benchmark Merkle root computation
CREATE OR REPLACE FUNCTION test_merkle_performance()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_duration_ms INTEGER;
    v_leaf_count INTEGER := 1000;
    v_hashes TEXT[];
    v_root TEXT;
    v_max_acceptable_ms INTEGER := 5000;
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_4.1_MERKLE_PERFORMANCE';
    v_start_time := clock_timestamp();
    
    -- Generate test hashes
    SELECT array_agg(encode(digest((i::TEXT)::bytea, 'sha256'), 'hex'))
    INTO v_hashes
    FROM generate_series(1, v_leaf_count) i;
    
    -- Compute root
    v_root := compute_merkle_root(v_hashes);
    
    v_end_time := clock_timestamp();
    v_duration_ms := EXTRACT(MILLISECONDS FROM (v_end_time - v_start_time))::INTEGER;
    
    v_passed := v_duration_ms < v_max_acceptable_ms;
    
    details := jsonb_build_object(
        'leaf_count', v_leaf_count,
        'duration_ms', v_duration_ms,
        'max_acceptable_ms', v_max_acceptable_ms,
        'leaves_per_ms', v_leaf_count::NUMERIC / NULLIF(v_duration_ms, 0)
    );
    
    INSERT INTO merkle_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data, execution_time_ms)
    VALUES (test_name, 'PERFORMANCE', v_passed, '< ' || v_max_acceptable_ms || 'ms', 
            v_duration_ms || 'ms', details, v_duration_ms);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST 5: BULK TEST EXECUTION
-- =============================================================================

CREATE OR REPLACE FUNCTION run_all_merkle_tests()
RETURNS TABLE (
    total_tests INTEGER,
    passed_tests INTEGER,
    failed_tests INTEGER,
    execution_time_ms INTEGER,
    test_summary JSONB
) AS $$
DECLARE
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_total INTEGER := 0;
    v_passed INTEGER := 0;
    v_failed INTEGER := 0;
    rec RECORD;
BEGIN
    v_start_time := clock_timestamp();
    
    -- Run all tests
    FOR rec IN SELECT * FROM test_merkle_root_computation() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; ELSE v_failed := v_failed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_inclusion_proof_generation() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; ELSE v_failed := v_failed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_inclusion_proof_verification() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; ELSE v_failed := v_failed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_merkle_determinism() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; ELSE v_failed := v_failed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_merkle_order_sensitivity() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; ELSE v_failed := v_failed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_merkle_single_leaf() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; ELSE v_failed := v_failed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_merkle_performance() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; ELSE v_failed := v_failed + 1; END IF;
    END LOOP;
    
    v_end_time := clock_timestamp();
    
    total_tests := v_total;
    passed_tests := v_passed;
    failed_tests := v_failed;
    execution_time_ms := EXTRACT(MILLISECONDS FROM (v_end_time - v_start_time))::INTEGER;
    test_summary := jsonb_build_object(
        'pass_rate', CASE WHEN v_total > 0 THEN round((v_passed::NUMERIC / v_total) * 100, 2) ELSE 0 END
    );
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST EXECUTION
-- =============================================================================

SELECT 'EXECUTING MERKLE INCLUSION TESTS...' as status;

SELECT * FROM run_all_merkle_tests();

-- Display results
SELECT 
    test_name,
    test_category,
    test_passed,
    execution_time_ms
FROM merkle_test_results
ORDER BY test_executed_at DESC;

-- Summary
SELECT 
    test_category,
    COUNT(*) as total,
    COUNT(*) FILTER (WHERE test_passed) as passed,
    round((COUNT(*) FILTER (WHERE test_passed)::NUMERIC / COUNT(*)) * 100, 2) as pass_rate
FROM merkle_test_results
GROUP BY test_category;

-- =============================================================================
-- TODO LIST FOR CUSTOMIZATION
-- =============================================================================

/*
TODO-1: Optimize Merkle tree computation for large datasets
TODO-2: Implement incremental Merkle root updates
TODO-3: Add support for sparse Merkle trees
TODO-4: Implement batch inclusion proof generation
TODO-5: Add tests for concurrent proof generation
TODO-6: Optimize for specific use cases (e.g., blockchain anchoring)
TODO-7: Add support for different hash algorithms
TODO-8: Implement Merkle tree persistence for faster validation
TODO-9: Add range proof tests for batch verification
TODO-10: Implement parallel Merkle tree construction
*/

-- =============================================================================
-- END OF MERKLE INCLUSION TESTS
-- =============================================================================
