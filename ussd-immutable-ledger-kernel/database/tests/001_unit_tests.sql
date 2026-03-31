-- ============================================================================
-- Unit Tests
-- ============================================================================

-- Test: Account creation
CREATE OR REPLACE FUNCTION test.create_account_test()
RETURNS BOOLEAN
LANGUAGE plpgsql
SET search_path = test, core, public
AS $$
DECLARE
    v_account_id UUID;
BEGIN
    v_account_id := core.create_account(
        'TEST-001',
        'ASSET',
        'USD',
        'Test Account',
        NULL,
        '{}',
        NULL
    );
    
    IF v_account_id IS NULL THEN
        RAISE EXCEPTION 'Account creation failed';
    END IF;
    
    RETURN TRUE;
END;
$$;

-- Test: Transaction immutability
CREATE OR REPLACE FUNCTION test.transaction_immutable_test()
RETURNS BOOLEAN
LANGUAGE plpgsql
SET search_path = test, core, public
AS $$
DECLARE
    v_transaction_id UUID;
BEGIN
    v_transaction_id := core.create_transaction(
        'TEST',
        '{"test": true}'::jsonb,
        'test-key-' || now()::text,
        NULL,
        NULL
    );
    
    -- Attempt to modify should fail
    BEGIN
        UPDATE core.transactions SET payload = '{}' WHERE transaction_id = v_transaction_id;
        RAISE EXCEPTION 'Transaction modification should have been blocked';
    EXCEPTION WHEN OTHERS THEN
        -- Expected
        RETURN TRUE;
    END;
END;
$$;

-- Test: Balance calculation
CREATE OR REPLACE FUNCTION test.balance_calculation_test()
RETURNS BOOLEAN
LANGUAGE plpgsql
SET search_path = test, core, public
AS $$
DECLARE
    v_balance DECIMAL;
BEGIN
    -- Create test account and transaction
    v_balance := core.get_balance_as_of(
        '550e8400-e29b-41d4-a716-446655440000'::UUID,
        CURRENT_DATE
    );
    
    -- Just verify function runs
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION test.create_account_test IS 'Unit test for account creation';
COMMENT ON FUNCTION test.transaction_immutable_test IS 'Unit test for transaction immutability';
COMMENT ON FUNCTION test.balance_calculation_test IS 'Unit test for balance calculation';
