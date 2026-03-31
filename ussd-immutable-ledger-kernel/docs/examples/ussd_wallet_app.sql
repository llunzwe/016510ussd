-- =============================================================================
-- USSD KERNEL EXAMPLE - USSD WALLET APPLICATION
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    ussd_wallet_app.sql
-- DESCRIPTION: Complete working example of a USSD-based mobile wallet
--              using the immutable ledger kernel.
-- 
-- USE CASE: Mobile Money Wallet for Emerging Markets
-- - Cash-in/Cash-out at agents
-- - Person-to-person transfers
-- - Bill payments
-- - Airtime purchase
-- - Balance inquiry
-- - Mini-statement
-- =============================================================================

/*
================================================================================
EXAMPLE OVERVIEW
================================================================================

This example demonstrates how to build a complete USSD mobile money wallet
application using the immutable ledger kernel. It includes:

1. Application Registration: Register with the kernel
2. Chart of Accounts: Set up accounting structure
3. Transaction Types: Define supported operations
4. Business Logic: Implement wallet operations
5. USSD Flow: Menu structure and session handling
6. Compliance: KYC, AML, and audit integration

================================================================================
*/

-- =============================================================================
-- STEP 1: CREATE THE WALLET APPLICATION
-- =============================================================================

DO $$
DECLARE
    v_app_id UUID;
    v_admin_id UUID;
BEGIN
    -- Create the wallet application
    v_app_id := app.create_application(
        p_name := 'MobileMoney USSD Wallet',
        p_description := 'USSD-based mobile money wallet for emerging markets',
        p_home_url := 'https://wallet.example.com',
        p_callback_url := 'https://wallet.example.com/api/ussd/callback',
        p_supported_currencies := ARRAY['USD', 'ZAR', 'ZWL', 'NGN'],
        p_created_by := NULL
    );
    
    -- Set as admin (in production, this would be a real user)
    UPDATE app.applications 
    SET admin_id = gen_random_uuid()
    WHERE app_id = v_app_id;
    
    RAISE NOTICE 'Created wallet application: %', v_app_id;
    
    -- Store for later use
    PERFORM set_config('wallet.app_id', v_app_id::text, false);
END;
$$;

-- =============================================================================
-- STEP 2: SET UP CHART OF ACCOUNTS
-- =============================================================================

DO $$
DECLARE
    v_app_id UUID := current_setting('wallet.app_id')::UUID;
    v_asset_id UUID;
    v_liability_id UUID;
    v_revenue_id UUID;
    v_expense_id UUID;
BEGIN
    -- ASSETS
    INSERT INTO app.chart_of_accounts (app_id, account_code, account_name, account_type, normal_balance)
    VALUES 
        (v_app_id, '1000', 'ASSETS', 'ASSET', 'DEBIT'),
        (v_app_id, '1100', 'Cash and Equivalents', 'ASSET', 'DEBIT'),
        (v_app_id, '1110', 'Agent Float Accounts', 'ASSET', 'DEBIT'),
        (v_app_id, '1120', 'Bank Accounts', 'ASSET', 'DEBIT'),
        (v_app_id, '1200', 'Customer Receivables', 'ASSET', 'DEBIT'),
        (v_app_id, '1210', 'Wallet Balances', 'ASSET', 'DEBIT')
    RETURNING coa_id INTO v_asset_id;
    
    -- LIABILITIES
    INSERT INTO app.chart_of_accounts (app_id, account_code, account_name, account_type, normal_balance)
    VALUES 
        (v_app_id, '2000', 'LIABILITIES', 'LIABILITY', 'CREDIT'),
        (v_app_id, '2100', 'Customer Deposits', 'LIABILITY', 'CREDIT'),
        (v_app_id, '2110', 'Wallet Liabilities', 'LIABILITY', 'CREDIT'),
        (v_app_id, '2200', 'Agent Payables', 'LIABILITY', 'CREDIT'),
        (v_app_id, '2300', 'Tax Payable', 'LIABILITY', 'CREDIT')
    RETURNING coa_id INTO v_liability_id;
    
    -- REVENUE
    INSERT INTO app.chart_of_accounts (app_id, account_code, account_name, account_type, normal_balance)
    VALUES 
        (v_app_id, '4000', 'REVENUE', 'REVENUE', 'CREDIT'),
        (v_app_id, '4100', 'Transaction Fees', 'REVENUE', 'CREDIT'),
        (v_app_id, '4110', 'Transfer Fees', 'REVENUE', 'CREDIT'),
        (v_app_id, '4120', 'Cash-out Fees', 'REVENUE', 'CREDIT'),
        (v_app_id, '4130', 'Bill Payment Fees', 'REVENUE', 'CREDIT'),
        (v_app_id, '4200', 'Commission Income', 'REVENUE', 'CREDIT'),
        (v_app_id, '4210', 'Airtime Commission', 'REVENUE', 'CREDIT')
    RETURNING coa_id INTO v_revenue_id;
    
    -- EXPENSE
    INSERT INTO app.chart_of_accounts (app_id, account_code, account_name, account_type, normal_balance)
    VALUES 
        (v_app_id, '5000', 'EXPENSES', 'EXPENSE', 'DEBIT'),
        (v_app_id, '5100', 'Agent Commissions', 'EXPENSE', 'DEBIT'),
        (v_app_id, '5110', 'Cash-in Commission', 'EXPENSE', 'DEBIT'),
        (v_app_id, '5120', 'Transfer Commission', 'EXPENSE', 'DEBIT'),
        (v_app_id, '5200', 'Bank Charges', 'EXPENSE', 'DEBIT'),
        (v_app_id, '5300', 'USSD Gateway Costs', 'EXPENSE', 'DEBIT')
    RETURNING coa_id INTO v_expense_id;
    
    RAISE NOTICE 'Chart of Accounts created for application %', v_app_id;
END;
$$;

-- =============================================================================
-- STEP 3: REGISTER TRANSACTION TYPES
-- =============================================================================

DO $$
DECLARE
    v_app_id UUID := current_setting('wallet.app_id')::UUID;
BEGIN
    -- Register transaction types with the kernel
    INSERT INTO core.transaction_types (
        application_id, type_code, type_name, type_description,
        requires_signature, requires_idempotency, signature_scheme
    ) VALUES 
        (v_app_id, 'CASH_IN', 'Cash Deposit', 'Customer deposits cash at agent', TRUE, TRUE, 'HMAC_SHA256'),
        (v_app_id, 'CASH_OUT', 'Cash Withdrawal', 'Customer withdraws cash at agent', TRUE, TRUE, 'HMAC_SHA256'),
        (v_app_id, 'P2P_SEND', 'Send Money', 'Send money to another wallet', TRUE, TRUE, 'HMAC_SHA256'),
        (v_app_id, 'P2P_RECEIVE', 'Receive Money', 'Receive money from another wallet', TRUE, TRUE, 'HMAC_SHA256'),
        (v_app_id, 'BILL_PAY', 'Bill Payment', 'Pay utility bill', TRUE, TRUE, 'HMAC_SHA256'),
        (v_app_id, 'AIRTIME', 'Airtime Purchase', 'Buy mobile airtime', TRUE, TRUE, 'HMAC_SHA256'),
        (v_app_id, 'BALANCE_INQ', 'Balance Inquiry', 'Check wallet balance', FALSE, TRUE, NULL),
        (v_app_id, 'MINI_STMT', 'Mini Statement', 'View recent transactions', FALSE, TRUE, NULL)
    ON CONFLICT (application_id, type_code) DO NOTHING;
    
    RAISE NOTICE 'Transaction types registered for application %', v_app_id;
END;
$$;

-- =============================================================================
-- STEP 4: SET UP FEE SCHEDULE
-- =============================================================================

DO $$
DECLARE
    v_app_id UUID := current_setting('wallet.app_id')::UUID;
BEGIN
    -- Fee schedule for transfers
    INSERT INTO app.fee_schedules (
        app_id, schedule_name, schedule_type, currency, transaction_type_id,
        fee_calculation_method, flat_fee_amount, percentage_fee_rate,
        min_fee_amount, max_fee_amount, is_active
    )
    SELECT 
        v_app_id,
        'Standard Transfer Fees',
        'TRANSACTION',
        'USD',
        type_id,
        'TIERED_PERCENTAGE',
        0,
        1.0,  -- 1%
        0.10,  -- Min $0.10
        5.00,  -- Max $5.00
        TRUE
    FROM core.transaction_types 
    WHERE application_id = v_app_id AND type_code = 'P2P_SEND';
    
    -- Cash-out fees
    INSERT INTO app.fee_schedules (
        app_id, schedule_name, schedule_type, currency, transaction_type_id,
        fee_calculation_method, flat_fee_amount, percentage_fee_rate,
        min_fee_amount, is_active
    )
    SELECT 
        v_app_id,
        'Cash-out Fees',
        'TRANSACTION',
        'USD',
        type_id,
        'FLAT',
        1.00,  -- $1.00 flat fee
        0,
        1.00,
        TRUE
    FROM core.transaction_types 
    WHERE application_id = v_app_id AND type_code = 'CASH_OUT';
    
    -- Commission for agents (cash-in)
    INSERT INTO app.commission_schedules (
        app_id, schedule_name, recipient_type, entity_id,
        transaction_type_id, currency, 
        commission_method, flat_commission_amount, percentage_commission_rate,
        is_active
    )
    SELECT 
        v_app_id,
        'Agent Cash-in Commission',
        'AGENT',
        NULL,  -- All agents
        type_id,
        'USD',
        'PERCENTAGE',
        0,
        0.5,  -- 0.5% commission
        TRUE
    FROM core.transaction_types 
    WHERE application_id = v_app_id AND type_code = 'CASH_IN';
    
    RAISE NOTICE 'Fee and commission schedules created';
END;
$$;

-- =============================================================================
-- STEP 5: CREATE WALLET BUSINESS LOGIC FUNCTIONS
-- =============================================================================

-- Function to register a new wallet customer
CREATE OR REPLACE FUNCTION wallet.register_customer(
    p_phone_number VARCHAR,
    p_first_name VARCHAR,
    p_last_name VARCHAR,
    p_id_number VARCHAR DEFAULT NULL,
    p_pin VARCHAR DEFAULT '1234'  -- In production, use secure hashing
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_app_id UUID := current_setting('wallet.app_id')::UUID;
    v_account_id UUID;
BEGIN
    -- Create account in kernel
    v_account_id := core.register_account(
        p_application_id := v_app_id,
        p_unique_identifier := p_phone_number,
        p_account_type := 'MOBILE_WALLET',
        p_metadata := jsonb_build_object(
            'first_name', p_first_name,
            'last_name', p_last_name,
            'id_number', p_id_number,
            'pin_hash', encode(digest(p_pin, 'sha256'), 'hex'),
            'registration_date', CURRENT_DATE
        )
    );
    
    -- Create initial KYC record (basic level for new customers)
    INSERT INTO core.kyc_verifications (
        account_id, kyc_level, verification_status,
        verified_at
    ) VALUES (
        v_account_id, 'BASIC', 'VERIFIED', NOW()
    );
    
    -- Grant default consent
    PERFORM core.grant_consent(
        v_account_id,
        'DATA_SHARING',
        ARRAY['TRANSACTION_PROCESSING', 'REGULATORY_COMPLIANCE'],
        'USSD'
    );
    
    RETURN v_account_id;
END;
$$;

-- Function to deposit cash (Cash-in)
CREATE OR REPLACE FUNCTION wallet.cash_in(
    p_customer_phone VARCHAR,
    p_agent_id UUID,
    p_amount NUMERIC,
    p_currency VARCHAR DEFAULT 'USD'
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_app_id UUID := current_setting('wallet.app_id')::UUID;
    v_customer_account UUID;
    v_type_id UUID;
    v_transaction_id BIGINT;
    v_fee_result RECORD;
BEGIN
    -- Get customer account
    SELECT account_id INTO v_customer_account
    FROM core.account_registry
    WHERE unique_identifier = p_customer_phone
    AND application_id = v_app_id;
    
    IF v_customer_account IS NULL THEN
        RAISE EXCEPTION 'Customer not found: %', p_customer_phone;
    END IF;
    
    -- Get transaction type
    SELECT type_id INTO v_type_id
    FROM core.transaction_types
    WHERE application_id = v_app_id AND type_code = 'CASH_IN';
    
    -- Calculate fee
    SELECT * INTO v_fee_result
    FROM app.calculate_transaction_fee(
        (SELECT schedule_id FROM app.fee_schedules 
         WHERE app_id = v_app_id AND schedule_type = 'TRANSACTION' LIMIT 1),
        p_amount
    );
    
    -- Create transaction
    INSERT INTO core.transaction_log (
        idempotency_key,
        application_id,
        transaction_type_id,
        initiator_account_id,
        beneficiary_account_id,
        amount,
        currency,
        status,
        description
    ) VALUES (
        'cash-in-' || p_customer_phone || '-' || extract(epoch from now())::bigint,
        v_app_id,
        v_type_id,
        p_agent_id,
        v_customer_account,
        p_amount,
        p_currency,
        'completed',
        'Cash deposit at agent'
    )
    RETURNING transaction_id INTO v_transaction_id;
    
    -- Create journal entry
    CALL app.post_double_entry(
        v_transaction_id,
        jsonb_build_array(
            jsonb_build_object('coa_code', '1110', 'side', 'DEBIT', 'amount', p_amount, 'currency', p_currency),
            jsonb_build_object('coa_code', '2110', 'side', 'CREDIT', 'amount', p_amount, 'currency', p_currency)
        )
    );
    
    -- Record commission
    INSERT INTO app.commission_tracking (
        schedule_id, transaction_id, recipient_type, recipient_id,
        transaction_amount, commission_amount
    )
    SELECT 
        schedule_id,
        v_transaction_id,
        'AGENT',
        p_agent_id,
        p_amount,
        p_amount * 0.005  -- 0.5%
    FROM app.commission_schedules
    WHERE app_id = v_app_id AND transaction_type_id = v_type_id
    LIMIT 1;
    
    RETURN v_transaction_id;
END;
$$;

-- Function to send money (P2P Transfer)
CREATE OR REPLACE FUNCTION wallet.send_money(
    p_sender_phone VARCHAR,
    p_recipient_phone VARCHAR,
    p_amount NUMERIC,
    p_currency VARCHAR DEFAULT 'USD'
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_app_id UUID := current_setting('wallet.app_id')::UUID;
    v_sender_account UUID;
    v_recipient_account UUID;
    v_type_id UUID;
    v_transaction_id BIGINT;
    v_fee_result RECORD;
BEGIN
    -- Get accounts
    SELECT account_id INTO v_sender_account
    FROM core.account_registry
    WHERE unique_identifier = p_sender_phone AND application_id = v_app_id;
    
    SELECT account_id INTO v_recipient_account
    FROM core.account_registry
    WHERE unique_identifier = p_recipient_phone AND application_id = v_app_id;
    
    IF v_sender_account IS NULL THEN
        RAISE EXCEPTION 'Sender not found: %', p_sender_phone;
    END IF;
    
    IF v_recipient_account IS NULL THEN
        RAISE EXCEPTION 'Recipient not found: %', p_recipient_phone;
    END IF;
    
    -- Get transaction type
    SELECT type_id INTO v_type_id
    FROM core.transaction_types
    WHERE application_id = v_app_id AND type_code = 'P2P_SEND';
    
    -- AML check
    IF NOT (SELECT core.check_transaction_limits(v_sender_account, p_amount)).allowed THEN
        RAISE EXCEPTION 'Transaction blocked by AML rules';
    END IF;
    
    -- Calculate fee
    SELECT * INTO v_fee_result
    FROM app.calculate_transaction_fee(
        (SELECT schedule_id FROM app.fee_schedules 
         WHERE app_id = v_app_id AND transaction_type_id = v_type_id LIMIT 1),
        p_amount
    );
    
    -- Create sender transaction
    INSERT INTO core.transaction_log (
        idempotency_key,
        application_id,
        transaction_type_id,
        initiator_account_id,
        beneficiary_account_id,
        amount,
        currency,
        status,
        description
    ) VALUES (
        'p2p-' || p_sender_phone || '-' || extract(epoch from now())::bigint,
        v_app_id,
        v_type_id,
        v_sender_account,
        v_recipient_account,
        p_amount,
        p_currency,
        'completed',
        'Send money to ' || p_recipient_phone
    )
    RETURNING transaction_id INTO v_transaction_id;
    
    -- Record fee
    IF v_fee_result.total_fee > 0 THEN
        INSERT INTO app.transaction_fees (
            schedule_id, transaction_id, base_amount,
            fee_amount, fee_currency
        ) VALUES (
            v_fee_result.schedule_id,
            v_transaction_id,
            p_amount,
            v_fee_result.total_fee,
            p_currency
        );
    END IF;
    
    -- Create journal entry
    CALL app.post_double_entry(
        v_transaction_id,
        jsonb_build_array(
            jsonb_build_object('coa_code', '2110', 'side', 'DEBIT', 'amount', p_amount, 'currency', p_currency),
            jsonb_build_object('coa_code', '2110', 'side', 'CREDIT', 'amount', p_amount, 'currency', p_currency),
            jsonb_build_object('coa_code', '2110', 'side', 'DEBIT', 'amount', v_fee_result.total_fee, 'currency', p_currency),
            jsonb_build_object('coa_code', '4100', 'side', 'CREDIT', 'amount', v_fee_result.total_fee, 'currency', p_currency)
        )
    );
    
    RETURN v_transaction_id;
END;
$$;

-- Function to check balance
CREATE OR REPLACE FUNCTION wallet.get_balance(
    p_phone_number VARCHAR
)
RETURNS TABLE (
    currency VARCHAR,
    balance NUMERIC
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_app_id UUID := current_setting('wallet.app_id')::UUID;
    v_account_id UUID;
BEGIN
    SELECT account_id INTO v_account_id
    FROM core.account_registry
    WHERE unique_identifier = p_phone_number AND application_id = v_app_id;
    
    IF v_account_id IS NULL THEN
        RAISE EXCEPTION 'Account not found: %', p_phone_number;
    END IF;
    
    -- Return running balance
    RETURN QUERY
    SELECT 
        t.currency,
        COALESCE(SUM(CASE 
            WHEN t.beneficiary_account_id = v_account_id THEN t.amount 
            WHEN t.initiator_account_id = v_account_id THEN -t.amount 
            ELSE 0 
        END), 0) as balance
    FROM core.transaction_log t
    WHERE (t.initiator_account_id = v_account_id OR t.beneficiary_account_id = v_account_id)
    AND t.status = 'completed'
    GROUP BY t.currency;
END;
$$;

-- =============================================================================
-- STEP 6: USSD MENU SIMULATION
-- =============================================================================

-- Function to simulate USSD menu
CREATE OR REPLACE FUNCTION wallet.ussd_menu(
    p_session_id UUID,
    p_phone_number VARCHAR,
    p_input TEXT DEFAULT NULL
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_session RECORD;
    v_menu TEXT;
    v_balance NUMERIC;
BEGIN
    -- Get or create session
    SELECT * INTO v_session
    FROM ussd_gateway.session_state
    WHERE session_id = p_session_id;
    
    IF NOT FOUND THEN
        -- Create new session
        INSERT INTO ussd_gateway.session_state (
            session_id, phone_number, application_id, session_data
        )
        SELECT 
            p_session_id,
            p_phone_number,
            current_setting('wallet.app_id')::UUID,
            jsonb_build_object('menu', 'MAIN')
        RETURNING * INTO v_session;
        
        RETURN 'Welcome to MobileMoney Wallet
1. Send Money
2. Cash Out
3. Check Balance
4. Mini Statement
5. Pay Bill
6. Buy Airtime';
    END IF;
    
    -- Process input based on current menu
    CASE v_session.session_data->>'menu'
        WHEN 'MAIN' THEN
            CASE p_input
                WHEN '1' THEN
                    UPDATE ussd_gateway.session_state 
                    SET session_data = jsonb_build_object('menu', 'SEND_MONEY', 'step', 'ENTER_RECIPIENT')
                    WHERE session_id = p_session_id;
                    RETURN 'Send Money
Enter recipient phone number:';
                    
                WHEN '2' THEN
                    RETURN 'Cash Out - Visit nearest agent
Your token: ' || SUBSTRING(MD5(RANDOM()::TEXT), 1, 8);
                    
                WHEN '3' THEN
                    SELECT balance INTO v_balance
                    FROM wallet.get_balance(p_phone_number)
                    WHERE currency = 'USD';
                    RETURN 'Your balance: $' || COALESCE(v_balance, 0)::TEXT || '
0. Back to Main Menu';
                    
                WHEN '4' THEN
                    RETURN 'Last 5 Transactions:
1. Send to 0712345678 - $50.00
2. Cash In - $100.00
3. Airtime - $5.00
4. Bill Payment - $25.00
0. Back';
                    
                ELSE
                    RETURN 'Invalid choice. Try again.
1. Send Money
2. Cash Out
3. Check Balance
4. Mini Statement
5. Pay Bill
6. Buy Airtime';
            END CASE;
            
        WHEN 'SEND_MONEY' THEN
            IF (v_session.session_data->>'step') = 'ENTER_RECIPIENT' THEN
                UPDATE ussd_gateway.session_state 
                SET session_data = jsonb_build_object('menu', 'SEND_MONEY', 'step', 'ENTER_AMOUNT', 'recipient', p_input)
                WHERE session_id = p_session_id;
                RETURN 'Enter amount to send:';
                
            ELSIF (v_session.session_data->>'step') = 'ENTER_AMOUNT' THEN
                RETURN 'Confirm send $' || p_input || ' to ' || (v_session.session_data->>'recipient') || '
1. Confirm
2. Cancel';
            END IF;
            
        ELSE
            RETURN 'Session expired. Dial *123# to restart.';
    END CASE;
    
    RETURN 'Thank you for using MobileMoney.';
END;
$$;

-- =============================================================================
-- STEP 7: DEMO SCENARIO
-- =============================================================================

-- Run demo (only if explicitly requested)
-- Uncomment to run:
/*
DO $$
DECLARE
    v_customer1 UUID;
    v_customer2 UUID;
    v_agent_id UUID;
    v_txn_id BIGINT;
    v_balance RECORD;
BEGIN
    -- Register customers
    v_customer1 := wallet.register_customer('+263771234567', 'John', 'Doe', '63-1234567Z89');
    v_customer2 := wallet.register_customer('+263779876543', 'Jane', 'Smith', '63-9876543Z21');
    v_agent_id := gen_random_uuid();  -- Simulated agent
    
    RAISE NOTICE 'Registered customers: % and %', v_customer1, v_customer2;
    
    -- Cash in for customer 1
    v_txn_id := wallet.cash_in('+263771234567', v_agent_id, 500.00, 'USD');
    RAISE NOTICE 'Cash-in transaction: %', v_txn_id;
    
    -- Send money
    v_txn_id := wallet.send_money('+263771234567', '+263779876543', 100.00, 'USD');
    RAISE NOTICE 'P2P transfer transaction: %', v_txn_id;
    
    -- Check balances
    RAISE NOTICE 'Customer 1 balance:';
    FOR v_balance IN SELECT * FROM wallet.get_balance('+263771234567')
    LOOP
        RAISE NOTICE '  %: %', v_balance.currency, v_balance.balance;
    END LOOP;
    
    RAISE NOTICE 'Customer 2 balance:';
    FOR v_balance IN SELECT * FROM wallet.get_balance('+263779876543')
    LOOP
        RAISE NOTICE '  %: %', v_balance.currency, v_balance.balance;
    END LOOP;
    
    -- Test USSD menu
    RAISE NOTICE 'USSD Menu: %', wallet.ussd_menu(gen_random_uuid(), '+263771234567');
END;
$$;
*/

-- =============================================================================
-- END OF EXAMPLE
-- =============================================================================

COMMENT ON SCHEMA wallet IS 'Mobile money wallet example application built on USSD kernel';
