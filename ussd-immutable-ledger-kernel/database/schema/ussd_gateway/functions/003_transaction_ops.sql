-- ============================================================================
-- USSD Transaction Operations
-- ============================================================================

-- Function: Create pending transaction
CREATE OR REPLACE FUNCTION ussd.create_pending_transaction(
    p_session_id UUID,
    p_transaction_type VARCHAR(32),
    p_amount DECIMAL(19,4),
    p_currency_code CHAR(3),
    p_destination TEXT,
    p_requires_pin BOOLEAN DEFAULT TRUE
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ussd_gateway, public
AS $$
DECLARE
    v_pending_id UUID;
    v_expiry TIMESTAMPTZ;
BEGIN
    v_pending_id := gen_random_uuid();
    v_expiry := now() + interval '5 minutes';

    INSERT INTO ussd.pending_transactions (
        pending_transaction_id,
        session_id,
        transaction_type,
        amount,
        currency_code,
        destination,
        status,
        requires_pin_verification,
        pin_attempts,
        pin_verified,
        liquidity_reserved,
        expires_at,
        fraud_score,
        risk_factors,
        created_at
    ) VALUES (
        v_pending_id,
        p_session_id,
        p_transaction_type,
        p_amount,
        p_currency_code,
        p_destination,
        'PENDING',
        p_requires_pin,
        0,
        FALSE,
        FALSE,
        v_expiry,
        0,
        ARRAY[]::TEXT[],
        now()
    );

    RETURN v_pending_id;
END;
$$;

COMMENT ON FUNCTION ussd.create_pending_transaction IS 'Creates pending transaction awaiting confirmation';

-- Function: Confirm transaction
CREATE OR REPLACE FUNCTION ussd.confirm_transaction(
    p_pending_transaction_id UUID,
    p_pin_verified BOOLEAN
)
RETURNS TABLE (
    success BOOLEAN,
    core_transaction_id UUID,
    message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ussd_gateway, public
AS $$
DECLARE
    v_pending RECORD;
    v_transaction_id UUID;
BEGIN
    SELECT * INTO v_pending
    FROM ussd.pending_transactions
    WHERE pending_transaction_id = p_pending_transaction_id;

    IF v_pending IS NULL THEN
        success := FALSE;
        core_transaction_id := NULL;
        message := 'Transaction not found';
        RETURN NEXT;
        RETURN;
    END IF;

    IF v_pending.expires_at < now() THEN
        success := FALSE;
        core_transaction_id := NULL;
        message := 'Transaction expired';
        RETURN NEXT;
        RETURN;
    END IF;

    IF v_pending.requires_pin_verification AND NOT p_pin_verified THEN
        success := FALSE;
        core_transaction_id := NULL;
        message := 'PIN verification required';
        RETURN NEXT;
        RETURN;
    END IF;

    -- Create core transaction
    v_transaction_id := core.create_transaction(
        'USSD_' || v_pending.transaction_type,
        jsonb_build_object(
            'amount', v_pending.amount,
            'currency', v_pending.currency_code,
            'destination', v_pending.destination
        ),
        'USSD-' || v_pending_transaction_id::text,
        NULL,
        NULL
    );

    -- Update pending
    UPDATE ussd.pending_transactions
    SET status = 'CONFIRMED',
        core_transaction_id = v_transaction_id,
        confirmed_at = now()
    WHERE pending_transaction_id = p_pending_transaction_id;

    success := TRUE;
    core_transaction_id := v_transaction_id;
    message := 'Transaction confirmed';
    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION ussd.confirm_transaction IS 'Confirms pending transaction after verification';
