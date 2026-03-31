-- ============================================================================
-- Integration Tests
-- ============================================================================

-- Test: End-to-end transaction flow
CREATE OR REPLACE FUNCTION test.end_to_end_transaction_test()
RETURNS BOOLEAN
LANGUAGE plpgsql
SET search_path = test, core, public
AS $$
DECLARE
    v_debit_account UUID;
    v_credit_account UUID;
    v_transaction_id UUID;
    v_movement_id UUID;
BEGIN
    -- Create accounts
    v_debit_account := core.create_account('TEST-DEBIT', 'ASSET', 'USD', 'Test Debit', NULL, '{}', NULL);
    v_credit_account := core.create_account('TEST-CREDIT', 'ASSET', 'USD', 'Test Credit', NULL, '{}', NULL);
    
    -- Create transaction
    v_transaction_id := core.create_transaction(
        'TRANSFER',
        '{"description": "Test transfer"}'::jsonb,
        'test-e2e-' || extract(epoch from now())::text,
        NULL,
        NULL
    );
    
    -- Post movement
    v_movement_id := core.post_movement(
        v_transaction_id,
        v_debit_account,
        v_credit_account,
        100.00,
        'USD',
        'Test movement',
        'TEST-REF',
        CURRENT_DATE,
        NULL
    );
    
    IF v_movement_id IS NULL THEN
        RAISE EXCEPTION 'Movement creation failed';
    END IF;
    
    RETURN TRUE;
END;
$$;

-- Test: Saga pattern
CREATE OR REPLACE FUNCTION test.saga_pattern_test()
RETURNS BOOLEAN
LANGUAGE plpgsql
SET search_path = test, core, public
AS $$
DECLARE
    v_saga_id UUID;
    v_op_id UUID;
BEGIN
    -- Start saga
    v_saga_id := core.start_saga('TEST_SAGA', '{"test": true}'::jsonb, NULL, NULL);
    
    IF v_saga_id IS NULL THEN
        RAISE EXCEPTION 'Saga creation failed';
    END IF;
    
    -- Add step
    v_op_id := core.add_saga_step(v_saga_id, 'step1', 'ACTION', '{}', '{}', NULL);
    
    -- Complete step
    PERFORM core.execute_saga_step(v_op_id, 'COMPLETED', '{}', NULL);
    
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION test.end_to_end_transaction_test IS 'Integration test for complete transaction flow';
COMMENT ON FUNCTION test.saga_pattern_test IS 'Integration test for saga pattern';
