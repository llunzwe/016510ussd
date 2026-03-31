-- =============================================================================
-- USSD KERNEL EXAMPLE - USSD WALLET APPLICATION
-- =============================================================================
-- FILENAME:    001_ussd_wallet_app.sql
-- DESCRIPTION: Complete example of a USSD mobile money wallet application
--              demonstrating all kernel capabilities.
-- =============================================================================

/*
================================================================================
EXAMPLE OVERVIEW
================================================================================

This example creates a complete USSD mobile money wallet application including:
1. Application registration
2. Chart of Accounts setup
3. Transaction types configuration
4. Fee schedules
5. Commission structures
6. Sample transactions
7. Financial reporting

To run this example:
1. Ensure kernel migrations are applied
2. Run this script as a kernel administrator
3. The example creates a 'Demo Wallet App' with full configuration

================================================================================
*/

-- =============================================================================
-- STEP 1: REGISTER APPLICATION
-- =============================================================================

DO $$
DECLARE
    v_app_id UUID;
    v_owner_id UUID;
BEGIN
    -- Get or create owner account
    SELECT account_id INTO v_owner_id 
    FROM core.account_registry 
    WHERE account_type = 'system' 
    LIMIT 1;
    
    -- Register the wallet application
    INSERT INTO app.t_application_registry (
        app_code,
        app_name,
        description,
        owner_account_id,
        status,
        encryption_config
    ) VALUES (
        'DEMO_WALLET',
        'Demo USSD Wallet',
        'Example USSD mobile money wallet application',
        v_owner_id,
        'ACTIVE',
        '{"algorithm": "AES-256-GCM"}'::JSONB
    )
    ON CONFLICT (app_code) DO UPDATE SET
        app_name = EXCLUDED.app_name,
        description = EXCLUDED.description
    RETURNING app_id INTO v_app_id;
    
    RAISE NOTICE 'Application registered with ID: %', v_app_id;
    
    -- Store for later use
    PERFORM set_config('app.demo_wallet_id', v_app_id::TEXT, FALSE);
END;
$$;

-- =============================================================================
-- STEP 2: SETUP CHART OF ACCOUNTS
-- =============================================================================

DO $$
DECLARE
    v_app_id UUID := current_setting('app.demo_wallet_id', TRUE)::UUID;
    v_asset_id UUID;
    v_liability_id UUID;
    v_equity_id UUID;
    v_revenue_id UUID;
    v_expense_id UUID;
BEGIN
    IF v_app_id IS NULL THEN
        RAISE EXCEPTION 'Application not registered. Run Step 1 first.';
    END IF;
    
    -- Assets
    v_asset_id := app.create_account(v_app_id, '1000', 'ASSETS', 'ASSET', 'DEBIT', NULL, 'Root asset account', NULL);
    PERFORM app.create_account(v_app_id, '1100', 'Cash and Equivalents', 'ASSET', 'DEBIT', '1000', 'Liquid assets', NULL);
    PERFORM app.create_account(v_app_id, '1110', 'Customer Float Account', 'ASSET', 'DEBIT', '1100', 'Customer e-money float', NULL);
    PERFORM app.create_account(v_app_id, '1120', 'Bank Accounts', 'ASSET', 'DEBIT', '1100', 'Settlement bank accounts', NULL);
    PERFORM app.create_account(v_app_id, '1200', 'Receivables', 'ASSET', 'DEBIT', '1000', 'Money owed to us', NULL);
    
    -- Liabilities
    v_liability_id := app.create_account(v_app_id, '2000', 'LIABILITIES', 'LIABILITY', 'CREDIT', NULL, 'Root liability account', NULL);
    PERFORM app.create_account(v_app_id, '2100', 'Customer Deposits', 'LIABILITY', 'CREDIT', '2000', 'Customer wallet balances', NULL);
    PERFORM app.create_account(v_app_id, '2200', 'Agent Float', 'LIABILITY', 'CREDIT', '2000', 'Agent outstanding float', NULL);
    PERFORM app.create_account(v_app_id, '2300', 'Merchant Payables', 'LIABILITY', 'CREDIT', '2000', 'Amounts owed to merchants', NULL);
    
    -- Equity
    v_equity_id := app.create_account(v_app_id, '3000', 'EQUITY', 'EQUITY', 'CREDIT', NULL, 'Root equity account', NULL);
    PERFORM app.create_account(v_app_id, '3100', 'Retained Earnings', 'EQUITY', 'CREDIT', '3000', 'Accumulated profits', NULL);
    
    -- Revenue
    v_revenue_id := app.create_account(v_app_id, '4000', 'REVENUE', 'REVENUE', 'CREDIT', NULL, 'Root revenue account', NULL);
    PERFORM app.create_account(v_app_id, '4100', 'Transaction Fees', 'REVENUE', 'CREDIT', '4000', 'Fees from transactions', NULL);
    PERFORM app.create_account(v_app_id, '4200', 'Commission Income', 'REVENUE', 'CREDIT', '4000', 'Commission from services', NULL);
    
    -- Expenses
    v_expense_id := app.create_account(v_app_id, '5000', 'EXPENSES', 'EXPENSE', 'DEBIT', NULL, 'Root expense account', NULL);
    PERFORM app.create_account(v_app_id, '5100', 'Agent Commissions', 'EXPENSE', 'DEBIT', '5000', 'Commissions paid to agents', NULL);
    PERFORM app.create_account(v_app_id, '5200', 'Bank Charges', 'EXPENSE', 'DEBIT', '5000', 'Bank settlement fees', NULL);
    PERFORM app.create_account(v_app_id, '5300', 'Technology Costs', 'EXPENSE', 'DEBIT', '5000', 'System and technology costs', NULL);
    
    RAISE NOTICE 'Chart of Accounts created successfully';
END;
$$;

-- =============================================================================
-- STEP 3: CONFIGURE FEE SCHEDULES
-- =============================================================================

DO $$
DECLARE
    v_app_id UUID := current_setting('app.demo_wallet_id', TRUE)::UUID;
BEGIN
    -- P2P Transfer Fees
    INSERT INTO app.fee_schedules (
        app_id, schedule_code, schedule_name, fee_type, fee_category,
        tier_config, revenue_account_id, effective_from
    )
    SELECT 
        v_app_id, 'P2P_FEE', 'P2P Transfer Fee', 'TIERED', 'TRANSACTION',
        '[
            {"min_amount": 0, "max_amount": 100, "flat": 0.50},
            {"min_amount": 100.01, "max_amount": 1000, "flat": 1.00},
            {"min_amount": 1000.01, "max_amount": 10000, "rate": 0.5}
        ]'::JSONB,
        (SELECT account_id FROM app.chart_of_accounts WHERE account_code = '4100' AND app_id = v_app_id),
        CURRENT_DATE;
    
    -- Cash Out Fees
    INSERT INTO app.fee_schedules (
        app_id, schedule_code, schedule_name, fee_type, fee_category,
        percentage_rate, minimum_fee, revenue_account_id, effective_from
    )
    SELECT 
        v_app_id, 'CASH_OUT_FEE', 'Cash Withdrawal Fee', 'PERCENTAGE', 'TRANSACTION',
        1.0, 1.00,
        (SELECT account_id FROM app.chart_of_accounts WHERE account_code = '4100' AND app_id = v_app_id),
        CURRENT_DATE;
    
    -- Merchant Commission
    INSERT INTO app.commission_schedules (
        app_id, schedule_code, schedule_name, commission_type, recipient_type,
        percentage_rate, percentage_basis, expense_account_id, effective_from
    )
    SELECT 
        v_app_id, 'MERCHANT_COMM', 'Merchant Commission', 'PERCENTAGE', 'MERCHANT',
        1.5, 'TRANSACTION_AMOUNT',
        (SELECT account_id FROM app.chart_of_accounts WHERE account_code = '5100' AND app_id = v_app_id),
        CURRENT_DATE;
    
    -- Agent Commission for Cash In
    INSERT INTO app.commission_schedules (
        app_id, schedule_code, schedule_name, commission_type, recipient_type,
        percentage_rate, percentage_basis, expense_account_id, effective_from
    )
    SELECT 
        v_app_id, 'AGENT_CASHIN', 'Agent Cash In Commission', 'PERCENTAGE', 'AGENT',
        0.5, 'TRANSACTION_AMOUNT',
        (SELECT account_id FROM app.chart_of_accounts WHERE account_code = '5100' AND app_id = v_app_id),
        CURRENT_DATE;
    
    RAISE NOTICE 'Fee and commission schedules configured';
END;
$$;

-- =============================================================================
-- STEP 4: CREATE SAMPLE CUSTOMERS AND AGENTS
-- =============================================================================

DO $$
DECLARE
    v_app_id UUID := current_setting('app.demo_wallet_id', TRUE)::UUID;
    v_customer_id UUID;
    v_agent_id UUID;
    v_merchant_id UUID;
BEGIN
    -- Create customer
    INSERT INTO core.account_registry (
        account_type, account_subtype, primary_identifier, 
        primary_identifier_hash, display_name, status
    ) VALUES (
        'individual', 'standard', '+263771234567',
        encode(digest('+263771234567', 'sha256'), 'hex'),
        'John Customer',
        'active'
    )
    RETURNING account_id INTO v_customer_id;
    
    -- Create agent
    INSERT INTO core.account_registry (
        account_type, account_subtype, primary_identifier,
        primary_identifier_hash, display_name, status
    ) VALUES (
        'agent', 'standard', '+263772345678',
        encode(digest('+263772345678', 'sha256'), 'hex'),
        'Jane Agent',
        'active'
    )
    RETURNING account_id INTO v_agent_id;
    
    -- Create merchant
    INSERT INTO core.account_registry (
        account_type, account_subtype, primary_identifier,
        primary_identifier_hash, display_name, status
    ) VALUES (
        'merchant', 'retail', 'MERCHANT001',
        encode(digest('MERCHANT001', 'sha256'), 'hex'),
        'SuperMart Zimbabwe',
        'active'
    )
    RETURNING account_id INTO v_merchant_id;
    
    -- Enroll in application
    INSERT INTO app.t_account_membership (app_id, account_id, membership_type, status)
    VALUES 
        (v_app_id, v_customer_id, 'CUSTOMER', 'ACTIVE'),
        (v_app_id, v_agent_id, 'AGENT', 'ACTIVE'),
        (v_app_id, v_merchant_id, 'MERCHANT', 'ACTIVE');
    
    -- Store for later
    PERFORM set_config('app.demo_customer_id', v_customer_id::TEXT, FALSE);
    PERFORM set_config('app.demo_agent_id', v_agent_id::TEXT, FALSE);
    PERFORM set_config('app.demo_merchant_id', v_merchant_id::TEXT, FALSE);
    
    RAISE NOTICE 'Sample customers/agents/merchants created';
END;
$$;

-- =============================================================================
-- STEP 5: PROCESS SAMPLE TRANSACTIONS
-- =============================================================================

DO $$
DECLARE
    v_app_id UUID := current_setting('app.demo_wallet_id', TRUE)::UUID;
    v_customer_id UUID := current_setting('app.demo_customer_id', TRUE)::UUID;
    v_agent_id UUID := current_setting('app.demo_agent_id', TRUE)::UUID;
    v_merchant_id UUID := current_setting('app.demo_merchant_id', TRUE)::UUID;
    v_txn_result RECORD;
    v_fee_id UUID;
    v_commission_id UUID;
BEGIN
    -- Transaction 1: Customer deposits cash via agent
    RAISE NOTICE 'Processing cash deposit...';
    
    SELECT * INTO v_txn_result FROM core.submit_transaction(
        'demo-cashin-001',
        'CASH_IN',
        v_customer_id,
        jsonb_build_object(
            'amount', 500.00,
            'currency', 'USD',
            'agent_id', v_agent_id,
            'narrative', 'Cash deposit at agent'
        ),
        v_app_id
    );
    
    RAISE NOTICE 'Cash deposit recorded: id=%, hash=%', v_txn_result.transaction_id, v_txn_result.transaction_hash;
    
    -- Post journal entries
    PERFORM app.post_journal_entry(
        v_app_id,
        (SELECT account_id FROM app.chart_of_accounts WHERE account_code = '1110' AND app_id = v_app_id),
        'DEBIT', 500.00, 'USD',
        'Cash deposit - customer',
        v_txn_result.transaction_id,
        v_txn_result.committed_at::DATE
    );
    
    PERFORM app.post_journal_entry(
        v_app_id,
        (SELECT account_id FROM app.chart_of_accounts WHERE account_code = '2100' AND app_id = v_app_id),
        'CREDIT', 500.00, 'USD',
        'Customer deposit liability',
        v_txn_result.transaction_id,
        v_txn_result.committed_at::DATE
    );
    
    -- Calculate agent commission
    SELECT * INTO v_commission_id FROM app.create_commission(
        (SELECT schedule_id FROM app.commission_schedules WHERE schedule_code = 'AGENT_CASHIN' AND app_id = v_app_id),
        v_agent_id,
        500.00,
        'USD',
        v_txn_result.transaction_id,
        v_txn_result.committed_at::DATE
    );
    
    RAISE NOTICE 'Agent commission calculated: %', v_commission_id;
    
    -- Transaction 2: Customer pays merchant
    RAISE NOTICE 'Processing merchant payment...';
    
    SELECT * INTO v_txn_result FROM core.submit_transaction(
        'demo-merchant-pay-001',
        'MERCHANT_PAY',
        v_customer_id,
        jsonb_build_object(
            'amount', 150.00,
            'currency', 'USD',
            'merchant_id', v_merchant_id,
            'narrative', 'Purchase at SuperMart'
        ),
        v_app_id
    );
    
    -- Post journal entries for merchant payment
    PERFORM app.post_journal_entry(
        v_app_id,
        (SELECT account_id FROM app.chart_of_accounts WHERE account_code = '2100' AND app_id = v_app_id),
        'DEBIT', 150.00, 'USD',
        'Customer payment to merchant',
        v_txn_result.transaction_id,
        v_txn_result.committed_at::DATE
    );
    
    PERFORM app.post_journal_entry(
        v_app_id,
        (SELECT account_id FROM app.chart_of_accounts WHERE account_code = '2300' AND app_id = v_app_id),
        'CREDIT', 150.00, 'USD',
        'Merchant payable',
        v_txn_result.transaction_id,
        v_txn_result.committed_at::DATE
    );
    
    RAISE NOTICE 'Sample transactions processed successfully';
END;
$$;

-- =============================================================================
-- STEP 6: GENERATE FINANCIAL REPORTS
-- =============================================================================

DO $$
DECLARE
    v_app_id UUID := current_setting('app.demo_wallet_id', TRUE)::UUID;
    v_record RECORD;
BEGIN
    RAISE NOTICE '========================================';
    RAISE NOTICE 'FINANCIAL REPORTS - DEMO WALLET';
    RAISE NOTICE '========================================';
    
    -- Trial Balance
    RAISE NOTICE 'TRIAL BALANCE:';
    FOR v_record IN 
        SELECT * FROM app.get_trial_balance(v_app_id, CURRENT_DATE)
    LOOP
        RAISE NOTICE '  % - %: Dr=%, Cr=%, Net=%',
            v_record.account_code, v_record.account_name,
            v_record.total_debits, v_record.total_credits, v_record.net_balance;
    END LOOP;
    
    -- Balance Sheet Summary
    RAISE NOTICE '';
    RAISE NOTICE 'BALANCE SHEET SUMMARY:';
    FOR v_record IN 
        SELECT * FROM app.v_balance_sheet_summary WHERE app_id = v_app_id
    LOOP
        RAISE NOTICE '  Total Assets: %', v_record.total_assets;
        RAISE NOTICE '  Total Liabilities: %', v_record.total_liabilities;
        RAISE NOTICE '  Total Equity: %', v_record.total_equity;
    END LOOP;
    
    -- Fee Revenue
    RAISE NOTICE '';
    RAISE NOTICE 'FEE REVENUE:';
    FOR v_record IN 
        SELECT * FROM app.v_fee_revenue_analysis WHERE app_id = v_app_id
    LOOP
        RAISE NOTICE '  %: Gross=%, Net=%',
            v_record.fee_category, v_record.gross_revenue, v_record.net_revenue;
    END LOOP;
    
    -- Commission Analysis
    RAISE NOTICE '';
    RAISE NOTICE 'COMMISSION PAYABLE:';
    FOR v_record IN 
        SELECT * FROM app.v_commission_analysis WHERE app_id = v_app_id
    LOOP
        RAISE NOTICE '  %: Gross=%, Net=%, Pending=%',
            v_record.recipient_type, v_record.gross_commission, 
            v_record.net_payable, v_record.pending_payment;
    END LOOP;
    
    RAISE NOTICE '';
    RAISE NOTICE '========================================';
    RAISE NOTICE 'DEMO COMPLETE';
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Application ID: %', v_app_id;
END;
$$;

-- =============================================================================
-- CLEANUP INSTRUCTIONS
-- =============================================================================
/*
To clean up this demo:

-- Remove transactions
DELETE FROM app.journal_entries WHERE app_id = '<app_id>';
DELETE FROM app.commission_transactions WHERE app_id = '<app_id>';
DELETE FROM app.fee_transactions WHERE app_id = '<app_id>';

-- Remove configuration
DELETE FROM app.commission_schedules WHERE app_id = '<app_id>';
DELETE FROM app.fee_schedules WHERE app_id = '<app_id>';
DELETE FROM app.chart_of_accounts WHERE app_id = '<app_id>';
DELETE FROM app.t_account_membership WHERE app_id = '<app_id>';

-- Remove application
DELETE FROM app.t_application_registry WHERE app_id = '<app_id>';

-- Note: Core transaction_log entries are immutable and will remain
-- for audit purposes.
*/
