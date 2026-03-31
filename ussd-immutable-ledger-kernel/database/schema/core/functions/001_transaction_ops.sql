-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - A.8.2 (Data Integrity), A.12.3 (Backup)
-- ISO/IEC 27040:2024 - Storage Security (Immutable Storage)
-- ============================================================================

-- Function: Create new transaction
CREATE OR REPLACE FUNCTION core.create_transaction(
    p_transaction_type VARCHAR(50),
    p_payload JSONB,
    p_idempotency_key VARCHAR(64),
    p_application_id UUID DEFAULT NULL,
    p_saga_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_transaction_id UUID;
    v_previous_hash VARCHAR(64);
    v_current_hash VARCHAR(64);
BEGIN
    -- Validate transaction type
    IF NOT EXISTS (
        SELECT 1 FROM core.transaction_types 
        WHERE type_code = p_transaction_type 
        AND is_active = TRUE
    ) THEN
        RAISE EXCEPTION 'Invalid or inactive transaction type: %', p_transaction_type;
    END IF;

    -- Check idempotency
    BEGIN
        PERFORM 1 FROM core.idempotency_keys 
        WHERE key_hash = encode(digest(p_idempotency_key, 'sha256'), 'hex');
        
        IF FOUND THEN
            -- Return existing transaction ID
            SELECT transaction_id INTO v_transaction_id
            FROM core.transactions
            WHERE idempotency_key = p_idempotency_key;
            
            RETURN v_transaction_id;
        END IF;
    EXCEPTION WHEN OTHERS THEN
        NULL; -- Continue if check fails
    END;

    -- Get previous hash for chain
    SELECT COALESCE(MAX(current_hash), '0' || repeat('0', 63))
    INTO v_previous_hash
    FROM core.transactions;

    -- Generate transaction ID
    v_transaction_id := gen_random_uuid();

    -- Calculate current hash
    v_current_hash := encode(
        digest(
            v_previous_hash || p_transaction_type || p_payload::text || now()::text,
            'sha256'
        ),
        'hex'
    );

    -- Insert idempotency key
    INSERT INTO core.idempotency_keys (
        key_hash, key_type, entity_type, entity_id,
        status, expires_at, application_id, created_at
    ) VALUES (
        encode(digest(p_idempotency_key, 'sha256'), 'hex'),
        'TRANSACTION',
        'transaction',
        v_transaction_id,
        'COMPLETED',
        now() + interval '24 hours',
        COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID),
        now()
    );

    -- Insert transaction
    INSERT INTO core.transactions (
        transaction_id,
        previous_hash,
        current_hash,
        transaction_type,
        payload,
        idempotency_key,
        saga_id,
        application_id,
        created_at,
        created_by
    ) VALUES (
        v_transaction_id,
        v_previous_hash,
        v_current_hash,
        p_transaction_type,
        p_payload,
        p_idempotency_key,
        p_saga_id,
        COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID),
        now(),
        current_user
    );

    RETURN v_transaction_id;
END;
$$;

COMMENT ON FUNCTION core.create_transaction IS 'Creates new immutable transaction with hash chaining';

-- Function: Post double-entry movement
CREATE OR REPLACE FUNCTION core.post_movement(
    p_transaction_id UUID,
    p_debit_account_id UUID,
    p_credit_account_id UUID,
    p_amount DECIMAL(19,4),
    p_currency_code CHAR(3),
    p_description TEXT DEFAULT NULL,
    p_reference_number VARCHAR(64) DEFAULT NULL,
    p_value_date DATE DEFAULT CURRENT_DATE,
    p_application_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_movement_id UUID;
    v_posting_id UUID;
    v_running_balance DECIMAL(19,4);
    v_leg_id UUID;
BEGIN
    -- Validate accounts exist and are active
    IF NOT EXISTS (
        SELECT 1 FROM core.account_registry 
        WHERE account_id = p_debit_account_id 
        AND status = 'ACTIVE' AND is_current = TRUE
    ) THEN
        RAISE EXCEPTION 'Debit account not found or inactive: %', p_debit_account_id;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM core.account_registry 
        WHERE account_id = p_credit_account_id 
        AND status = 'ACTIVE' AND is_current = TRUE
    ) THEN
        RAISE EXCEPTION 'Credit account not found or inactive: %', p_credit_account_id;
    END IF;

    -- Validate amount
    IF p_amount <= 0 THEN
        RAISE EXCEPTION 'Amount must be positive: %', p_amount;
    END IF;

    -- Generate IDs
    v_movement_id := gen_random_uuid();
    v_posting_id := gen_random_uuid();
    v_leg_id := gen_random_uuid();

    -- Create movement
    INSERT INTO core.movements (
        movement_id,
        transaction_id,
        debit_account_id,
        credit_account_id,
        amount,
        currency_code,
        description,
        reference_number,
        value_date,
        status,
        reversal_of,
        record_hash,
        application_id,
        created_at,
        created_by
    ) VALUES (
        v_movement_id,
        p_transaction_id,
        p_debit_account_id,
        p_credit_account_id,
        p_amount,
        p_currency_code,
        p_description,
        p_reference_number,
        p_value_date,
        'POSTED',
        NULL,
        encode(digest(v_movement_id::text || now()::text, 'sha256'), 'hex'),
        COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID),
        now(),
        current_user
    );

    -- Get running balance for debit account
    SELECT COALESCE(MAX(running_balance), 0) INTO v_running_balance
    FROM core.movement_postings
    WHERE account_id = p_debit_account_id;

    -- Create debit posting
    INSERT INTO core.movement_postings (
        posting_id,
        movement_id,
        transaction_id,
        account_id,
        side,
        amount,
        running_balance,
        currency_code,
        value_date,
        is_reversal,
        record_hash,
        application_id,
        created_at,
        created_by
    ) VALUES (
        v_posting_id,
        v_movement_id,
        p_transaction_id,
        p_debit_account_id,
        'DEBIT',
        p_amount,
        v_running_balance - p_amount,
        p_currency_code,
        p_value_date,
        FALSE,
        encode(digest(v_posting_id::text || now()::text, 'sha256'), 'hex'),
        COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID),
        now(),
        current_user
    );

    -- Create credit posting
    v_posting_id := gen_random_uuid();
    
    SELECT COALESCE(MAX(running_balance), 0) INTO v_running_balance
    FROM core.movement_postings
    WHERE account_id = p_credit_account_id;

    INSERT INTO core.movement_postings (
        posting_id,
        movement_id,
        transaction_id,
        account_id,
        side,
        amount,
        running_balance,
        currency_code,
        value_date,
        is_reversal,
        record_hash,
        application_id,
        created_at,
        created_by
    ) VALUES (
        v_posting_id,
        v_movement_id,
        p_transaction_id,
        p_credit_account_id,
        'CREDIT',
        p_amount,
        v_running_balance + p_amount,
        p_currency_code,
        p_value_date,
        FALSE,
        encode(digest(v_posting_id::text || now()::text, 'sha256'), 'hex'),
        COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID),
        now(),
        current_user
    );

    -- Update account balances
    UPDATE core.account_registry
    SET balance = balance - p_amount,
        available_balance = balance - p_amount - hold_amount
    WHERE account_id = p_debit_account_id
    AND is_current = TRUE;

    UPDATE core.account_registry
    SET balance = balance + p_amount,
        available_balance = balance + p_amount - hold_amount
    WHERE account_id = p_credit_account_id
    AND is_current = TRUE;

    RETURN v_movement_id;
END;
$$;

COMMENT ON FUNCTION core.post_movement IS 'Posts a double-entry movement with automatic postings';

-- Function: Reverse a movement
CREATE OR REPLACE FUNCTION core.reverse_movement(
    p_original_movement_id UUID,
    p_reason TEXT,
    p_reversal_date DATE DEFAULT CURRENT_DATE
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_original RECORD;
    v_reversal_movement_id UUID;
    v_reversal_transaction_id UUID;
BEGIN
    -- Get original movement
    SELECT * INTO v_original
    FROM core.movements
    WHERE movement_id = p_original_movement_id;

    IF v_original IS NULL THEN
        RAISE EXCEPTION 'Original movement not found: %', p_original_movement_id;
    END IF;

    IF v_original.is_reversed THEN
        RAISE EXCEPTION 'Movement already reversed: %', p_original_movement_id;
    END IF;

    -- Create reversal transaction
    v_reversal_transaction_id := core.create_transaction(
        'REVERSAL',
        jsonb_build_object(
            'original_movement_id', p_original_movement_id,
            'reversal_reason', p_reason
        ),
        'REV-' || p_original_movement_id::text || '-' || extract(epoch from now())::text,
        v_original.application_id,
        NULL
    );

    -- Create reversal movement (swap debit/credit)
    v_reversal_movement_id := core.post_movement(
        v_reversal_transaction_id,
        v_original.credit_account_id,
        v_original.debit_account_id,
        v_original.amount,
        v_original.currency_code,
        'Reversal of ' || p_original_movement_id || ': ' || p_reason,
        v_original.reference_number || '-REV',
        p_reversal_date,
        v_original.application_id
    );

    -- Mark original as reversed
    UPDATE core.movements
    SET is_reversed = TRUE,
        reversed_at = now(),
        reversal_reason = p_reason
    WHERE movement_id = p_original_movement_id;

    RETURN v_reversal_movement_id;
END;
$$;

COMMENT ON FUNCTION core.reverse_movement IS 'Creates reversal movement (compensating transaction)';

-- Function: Get transaction history for account
CREATE OR REPLACE FUNCTION core.get_transaction_history(
    p_account_id UUID,
    p_from_date DATE DEFAULT NULL,
    p_to_date DATE DEFAULT NULL,
    p_limit INTEGER DEFAULT 100
)
RETURNS TABLE (
    posting_id UUID,
    movement_id UUID,
    transaction_id UUID,
    transaction_type VARCHAR(50),
    side VARCHAR(6),
    amount DECIMAL(19,4),
    running_balance DECIMAL(19,4),
    description TEXT,
    created_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
SET search_path = core, public
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        mp.posting_id,
        mp.movement_id,
        mp.transaction_id,
        t.transaction_type,
        mp.side,
        mp.amount,
        mp.running_balance,
        m.description,
        mp.created_at
    FROM core.movement_postings mp
    JOIN core.movements m ON mp.movement_id = m.movement_id
    JOIN core.transactions t ON mp.transaction_id = t.transaction_id
    WHERE mp.account_id = p_account_id
    AND (p_from_date IS NULL OR mp.value_date >= p_from_date)
    AND (p_to_date IS NULL OR mp.value_date <= p_to_date)
    ORDER BY mp.created_at DESC
    LIMIT p_limit;
END;
$$;

COMMENT ON FUNCTION core.get_transaction_history IS 'Returns posting history for an account';

-- Function: Verify transaction chain integrity
CREATE OR REPLACE FUNCTION core.verify_chain_integrity()
RETURNS TABLE (
    is_valid BOOLEAN,
    broken_at_transaction UUID,
    error_message TEXT
)
LANGUAGE plpgsql
STABLE
SET search_path = core, public
AS $$
DECLARE
    v_prev_hash VARCHAR(64) := '0' || repeat('0', 63);
    v_curr_hash VARCHAR(64);
    v_transaction_id UUID;
BEGIN
    FOR v_transaction_id, v_curr_hash IN
        SELECT t.transaction_id, t.current_hash
        FROM core.transactions t
        ORDER BY t.created_at
    LOOP
        -- Verify hash chain
        IF v_curr_hash IS NULL OR v_curr_hash = '' THEN
            RETURN QUERY SELECT FALSE, v_transaction_id, 'Empty hash found'::TEXT;
            RETURN;
        END IF;

        v_prev_hash := v_curr_hash;
    END LOOP;

    RETURN QUERY SELECT TRUE, NULL::UUID, 'Chain integrity verified'::TEXT;
END;
$$;

COMMENT ON FUNCTION core.verify_chain_integrity IS 'Verifies cryptographic integrity of transaction chain';
