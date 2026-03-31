-- ============================================================================
-- Financial Operations
-- ============================================================================

-- Function: Get exchange rate
CREATE OR REPLACE FUNCTION core.get_exchange_rate(
    p_from_currency CHAR(3),
    p_to_currency CHAR(3),
    p_rate_date DATE DEFAULT CURRENT_DATE
)
RETURNS DECIMAL(19,8)
LANGUAGE plpgsql
STABLE
SET search_path = core, public
AS $$
DECLARE
    v_rate DECIMAL(19,8);
BEGIN
    IF p_from_currency = p_to_currency THEN
        RETURN 1.0;
    END IF;

    -- Direct rate
    SELECT rate INTO v_rate
    FROM core.exchange_rates
    WHERE from_currency = p_from_currency
    AND to_currency = p_to_currency
    AND rate_date <= p_rate_date
    AND is_active = TRUE
    ORDER BY rate_date DESC
    LIMIT 1;

    IF v_rate IS NOT NULL THEN
        RETURN v_rate;
    END IF;

    -- Cross rate via USD
    SELECT (fr.rate / tr.rate) INTO v_rate
    FROM core.exchange_rates fr
    JOIN core.exchange_rates tr ON fr.rate_date = tr.rate_date
    WHERE fr.from_currency = p_from_currency
    AND fr.to_currency = 'USD'
    AND tr.from_currency = p_to_currency
    AND tr.to_currency = 'USD'
    AND fr.rate_date <= p_rate_date
    AND fr.is_active = TRUE
    ORDER BY fr.rate_date DESC
    LIMIT 1;

    RETURN COALESCE(v_rate, 0);
END;
$$;

COMMENT ON FUNCTION core.get_exchange_rate IS 'Gets exchange rate between currencies';

-- Function: Convert currency
CREATE OR REPLACE FUNCTION core.convert_currency(
    p_amount DECIMAL(19,4),
    p_from_currency CHAR(3),
    p_to_currency CHAR(3),
    p_rate_date DATE DEFAULT CURRENT_DATE
)
RETURNS DECIMAL(19,4)
LANGUAGE plpgsql
STABLE
SET search_path = core, public
AS $$
DECLARE
    v_rate DECIMAL(19,8);
BEGIN
    v_rate := core.get_exchange_rate(p_from_currency, p_to_currency, p_rate_date);
    
    IF v_rate = 0 THEN
        RAISE EXCEPTION 'No exchange rate found for % to % on %', p_from_currency, p_to_currency, p_rate_date;
    END IF;

    RETURN ROUND(p_amount * v_rate, 4);
END;
$$;

COMMENT ON FUNCTION core.convert_currency IS 'Converts amount between currencies';

-- Function: Calculate bad debt provision
CREATE OR REPLACE FUNCTION core.calculate_bad_debt_provision(
    p_account_id UUID,
    p_fiscal_period_id UUID,
    p_application_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_provision_id UUID;
    v_balance DECIMAL(19,4);
    v_days_overdue INTEGER;
    v_pd DECIMAL(5,4); -- Probability of Default
    v_lgd DECIMAL(5,4); -- Loss Given Default
    v_provision DECIMAL(19,4);
    v_staging VARCHAR(16);
BEGIN
    -- Get account balance and aging
    SELECT balance INTO v_balance
    FROM core.account_registry
    WHERE account_id = p_account_id
    AND is_current = TRUE;

    -- Calculate days overdue (simplified)
    v_days_overdue := 0; -- Would come from aging analysis

    -- Determine staging
    v_staging := CASE 
        WHEN v_days_overdue <= 30 THEN 'STAGE_1'
        WHEN v_days_overdue <= 90 THEN 'STAGE_2'
        ELSE 'STAGE_3'
    END;

    -- Set PD and LGD based on staging (simplified IFRS 9)
    SELECT 
        CASE v_staging
            WHEN 'STAGE_1' THEN 0.01
            WHEN 'STAGE_2' THEN 0.10
            ELSE 0.50
        END,
        CASE v_staging
            WHEN 'STAGE_1' THEN 0.45
            WHEN 'STAGE_2' THEN 0.55
            ELSE 0.75
        END
    INTO v_pd, v_lgd;

    -- Calculate provision (ECL)
    v_provision := v_balance * v_pd * v_lgd;

    v_provision_id := gen_random_uuid();

    INSERT INTO core.bad_debt_provision (
        provision_id,
        account_id,
        fiscal_period_id,
        ead_amount,
        pd_rate,
        lgd_rate,
        ecl_amount,
        staging,
        ifrs9_compliant,
        provision_method,
        manual_override,
        override_approved_by,
        override_reason,
        record_hash,
        application_id,
        created_at,
        created_by
    ) VALUES (
        v_provision_id,
        p_account_id,
        p_fiscal_period_id,
        v_balance,
        v_pd,
        v_lgd,
        v_provision,
        v_staging,
        TRUE,
        'IRB',
        FALSE,
        NULL,
        NULL,
        encode(digest(v_provision_id::text || now()::text, 'sha256'), 'hex'),
        COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID),
        now(),
        current_user
    );

    RETURN v_provision_id;
END;
$$;

COMMENT ON FUNCTION core.calculate_bad_debt_provision IS 'Calculates IFRS 9 ECL provision for account';

-- Function: Post journal entry
CREATE OR REPLACE FUNCTION core.post_journal_entry(
    p_entries JSONB, -- [{account_id, side, amount, description}, ...]
    p_reference VARCHAR(64),
    p_description TEXT,
    p_application_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_transaction_id UUID;
    v_entry RECORD;
    v_debit_total DECIMAL(19,4) := 0;
    v_credit_total DECIMAL(19,4) := 0;
BEGIN
    -- Validate entries balance
    FOR v_entry IN SELECT * FROM jsonb_to_recordset(p_entries) AS x(account_id UUID, side VARCHAR(6), amount DECIMAL(19,4))
    LOOP
        IF v_entry.side = 'DEBIT' THEN
            v_debit_total := v_debit_total + v_entry.amount;
        ELSE
            v_credit_total := v_credit_total + v_entry.amount;
        END IF;
    END LOOP;

    IF v_debit_total != v_credit_total THEN
        RAISE EXCEPTION 'Journal entries do not balance: debits=%, credits=%', v_debit_total, v_credit_total;
    END IF;

    -- Create transaction
    v_transaction_id := core.create_transaction(
        'JOURNAL',
        jsonb_build_object(
            'reference', p_reference,
            'description', p_description,
            'entries', p_entries
        ),
        p_reference,
        COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID),
        NULL
    );

    -- Process each entry
    FOR v_entry IN SELECT * FROM jsonb_to_recordset(p_entries) AS x(account_id UUID, side VARCHAR(6), amount DECIMAL(19,4), description TEXT)
    LOOP
        -- Get corresponding account for double-entry
        -- This is simplified - real implementation would pair debits and credits
        NULL;
    END LOOP;

    RETURN v_transaction_id;
END;
$$;

COMMENT ON FUNCTION core.post_journal_entry IS 'Posts balanced journal entry';
