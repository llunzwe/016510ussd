-- ============================================================================
-- Settlement and Liquidity Operations
-- ============================================================================

-- Function: Create settlement instruction
CREATE OR REPLACE FUNCTION core.create_settlement(
    p_settlement_type VARCHAR(16),
    p_from_account_id UUID,
    p_to_account_id UUID,
    p_amount DECIMAL(19,4),
    p_currency_code CHAR(3),
    p_settlement_date DATE,
    p_priority INTEGER DEFAULT 5,
    p_application_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_settlement_id UUID;
BEGIN
    v_settlement_id := gen_random_uuid();

    INSERT INTO core.settlement_instructions (
        settlement_id,
        settlement_type,
        status,
        from_account_id,
        to_account_id,
        amount,
        currency_code,
        settlement_date,
        priority,
        retry_count,
        record_hash,
        application_id,
        created_at,
        created_by
    ) VALUES (
        v_settlement_id,
        p_settlement_type,
        'PENDING',
        p_from_account_id,
        p_to_account_id,
        p_amount,
        p_currency_code,
        p_settlement_date,
        p_priority,
        0,
        encode(digest(v_settlement_id::text || now()::text, 'sha256'), 'hex'),
        COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID),
        now(),
        current_user
    );

    RETURN v_settlement_id;
END;
$$;

COMMENT ON FUNCTION core.create_settlement IS 'Creates a settlement instruction';

-- Function: Execute settlement batch
CREATE OR REPLACE FUNCTION core.execute_settlement_batch(
    p_settlement_date DATE,
    p_settlement_type VARCHAR(16) DEFAULT NULL
)
RETURNS TABLE (
    settlement_id UUID,
    status VARCHAR(16),
    message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_settlement RECORD;
    v_transaction_id UUID;
    v_result TEXT;
BEGIN
    FOR v_settlement IN
        SELECT * FROM core.settlement_instructions
        WHERE settlement_date = p_settlement_date
        AND status = 'PENDING'
        AND (p_settlement_type IS NULL OR settlement_type = p_settlement_type)
        ORDER BY priority, created_at
    LOOP
        BEGIN
            -- Create transaction
            v_transaction_id := core.create_transaction(
                'SETTLEMENT',
                jsonb_build_object(
                    'settlement_id', v_settlement.settlement_id,
                    'from_account', v_settlement.from_account_id,
                    'to_account', v_settlement.to_account_id,
                    'amount', v_settlement.amount
                ),
                'STL-' || v_settlement.settlement_id::text,
                v_settlement.application_id,
                NULL
            );

            -- Post movement
            PERFORM core.post_movement(
                v_transaction_id,
                v_settlement.from_account_id,
                v_settlement.to_account_id,
                v_settlement.amount,
                v_settlement.currency_code,
                'Settlement ' || v_settlement.settlement_id,
                'STL-' || v_settlement.settlement_id::text,
                p_settlement_date,
                v_settlement.application_id
            );

            -- Mark as completed
            UPDATE core.settlement_instructions
            SET status = 'COMPLETED',
                executed_at = now()
            WHERE settlement_id = v_settlement.settlement_id;

            settlement_id := v_settlement.settlement_id;
            status := 'COMPLETED';
            message := 'Settlement executed successfully';
            RETURN NEXT;

        EXCEPTION WHEN OTHERS THEN
            -- Update retry count
            UPDATE core.settlement_instructions
            SET retry_count = retry_count + 1,
                last_error = SQLERRM,
                status = CASE WHEN retry_count >= 3 THEN 'FAILED' ELSE 'PENDING' END
            WHERE settlement_id = v_settlement.settlement_id;

            settlement_id := v_settlement.settlement_id;
            status := 'FAILED';
            message := SQLERRM;
            RETURN NEXT;
        END;
    END LOOP;
END;
$$;

COMMENT ON FUNCTION core.execute_settlement_batch IS 'Executes all pending settlements for date';

-- Function: Update liquidity position
CREATE OR REPLACE FUNCTION core.update_liquidity_position(
    p_position_type VARCHAR(32),
    p_currency_code CHAR(3),
    p_amount_change DECIMAL(19,4),
    p_description TEXT DEFAULT NULL,
    p_application_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_position_id UUID;
    v_app_id UUID;
BEGIN
    v_app_id := COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID);

    -- Get or create position
    SELECT position_id INTO v_position_id
    FROM core.liquidity_positions
    WHERE position_type = p_position_type
    AND currency_code = p_currency_code
    AND application_id = v_app_id
    AND is_current = TRUE;

    IF v_position_id IS NULL THEN
        v_position_id := gen_random_uuid();
        
        INSERT INTO core.liquidity_positions (
            position_id, position_type, currency_code, amount,
            status, description, expires_at, record_hash,
            application_id, created_at, created_by
        ) VALUES (
            v_position_id, p_position_type, p_currency_code, p_amount_change,
            'ACTIVE', p_description, NULL,
            encode(digest(v_position_id::text || now()::text, 'sha256'), 'hex'),
            v_app_id, now(), current_user
        );
    ELSE
        UPDATE core.liquidity_positions
        SET amount = amount + p_amount_change,
            description = COALESCE(p_description, description)
        WHERE position_id = v_position_id;
    END IF;

    RETURN v_position_id;
END;
$$;

COMMENT ON FUNCTION core.update_liquidity_position IS 'Updates liquidity position amount';
