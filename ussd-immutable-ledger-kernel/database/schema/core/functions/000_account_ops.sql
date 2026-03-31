-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Controls A.5.1, A.8.1, A.9.2, A.12.1)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Multi-tenancy)
-- ISO/IEC 27040:2024 - Storage Security (Schema isolation)
-- ============================================================================
-- CODING PRACTICES:
-- - Use explicit schema qualification (schema.object)
-- - Set search_path explicitly in each function
-- - Use SECURITY DEFINER only for privileged operations
-- ============================================================================

-- Function: Create new account
CREATE OR REPLACE FUNCTION core.create_account(
    p_account_number VARCHAR(32),
    p_account_type VARCHAR(32),
    p_currency_code CHAR(3),
    p_account_name VARCHAR(255),
    p_parent_account_id UUID DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}',
    p_application_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_account_id UUID;
    v_parent_path LTREE;
    v_record_hash VARCHAR(64);
BEGIN
    -- Validate account type
    IF p_account_type NOT IN ('ASSET', 'LIABILITY', 'EQUITY', 'REVENUE', 'EXPENSE') THEN
        RAISE EXCEPTION 'Invalid account type: %', p_account_type;
    END IF;

    -- Validate currency
    IF NOT EXISTS (SELECT 1 FROM core.exchange_rates WHERE currency_code = p_currency_code) THEN
        RAISE EXCEPTION 'Invalid currency code: %', p_currency_code;
    END IF;

    -- Get parent path if parent specified
    IF p_parent_account_id IS NOT NULL THEN
        SELECT path INTO v_parent_path
        FROM core.account_registry
        WHERE account_id = p_parent_account_id;
        
        IF v_parent_path IS NULL THEN
            RAISE EXCEPTION 'Parent account not found: %', p_parent_account_id;
        END IF;
    END IF;

    -- Generate UUID
    v_account_id := gen_random_uuid();

    -- Calculate record hash
    v_record_hash := encode(
        digest(
            v_account_id::text || p_account_number || p_account_type || p_currency_code || now()::text,
            'sha256'
        ),
        'hex'
    );

    -- Insert account
    INSERT INTO core.account_registry (
        account_id,
        account_number,
        account_type,
        currency_code,
        account_name,
        parent_account_id,
        path,
        balance,
        available_balance,
        hold_amount,
        status,
        metadata,
        valid_from,
        valid_to,
        superseded_by,
        is_current,
        record_hash,
        application_id,
        created_at,
        created_by
    ) VALUES (
        v_account_id,
        p_account_number,
        p_account_type,
        p_currency_code,
        p_account_name,
        p_parent_account_id,
        COALESCE(v_parent_path, '') || COALESCE(v_parent_path, '') || '.' || v_account_id::text,
        0,
        0,
        0,
        'ACTIVE',
        p_metadata,
        now(),
        'infinity'::timestamptz,
        NULL,
        TRUE,
        v_record_hash,
        COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID),
        now(),
        current_user
    );

    -- Create initial balance record
    INSERT INTO core.period_end_balances (
        balance_id,
        account_id,
        fiscal_period_id,
        opening_balance,
        closing_balance,
        total_credits,
        total_debits,
        currency_code,
        reconciliation_status,
        reconciliation_reference,
        ifrs_compliant,
        compliance_notes,
        record_hash,
        application_id,
        created_at,
        created_by
    ) VALUES (
        gen_random_uuid(),
        v_account_id,
        (SELECT fiscal_period_id FROM core.fiscal_periods 
         WHERE is_current = TRUE 
         AND application_id = COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID)
         LIMIT 1),
        0,
        0,
        0,
        0,
        p_currency_code,
        'PENDING',
        NULL,
        TRUE,
        'Initial balance on account creation',
        encode(digest(gen_random_uuid()::text, 'sha256'), 'hex'),
        COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID),
        now(),
        current_user
    );

    -- Log audit
    INSERT INTO core.audit_trail (
        table_name, record_id, action, old_values, new_values, 
        changed_by, changed_at, transaction_id, severity
    ) VALUES (
        'account_registry', v_account_id, 'INSERT', '{}',
        jsonb_build_object(
            'account_number', p_account_number,
            'account_type', p_account_type,
            'account_name', p_account_name
        ),
        current_user, now(), txid_current(), 'INFO'
    );

    RETURN v_account_id;
END;
$$;

COMMENT ON FUNCTION core.create_account IS 'Creates a new account with initial balance record';

-- Function: Update account (creates new version)
CREATE OR REPLACE FUNCTION core.update_account(
    p_account_id UUID,
    p_account_name VARCHAR(255) DEFAULT NULL,
    p_metadata JSONB DEFAULT NULL,
    p_status VARCHAR(16) DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_old_record RECORD;
    v_new_account_id UUID;
    v_record_hash VARCHAR(64);
BEGIN
    -- Get current version
    SELECT * INTO v_old_record
    FROM core.account_registry
    WHERE account_id = p_account_id
    AND is_current = TRUE;

    IF v_old_record IS NULL THEN
        RAISE EXCEPTION 'Account not found or not current: %', p_account_id;
    END IF;

    -- Generate new version UUID
    v_new_account_id := gen_random_uuid();

    -- Calculate new record hash
    v_record_hash := encode(
        digest(
            v_new_account_id::text || v_old_record.account_number || 
            COALESCE(p_account_name, v_old_record.account_name) || now()::text,
            'sha256'
        ),
        'hex'
    );

    -- Mark old record as superseded
    UPDATE core.account_registry
    SET is_current = FALSE,
        valid_to = now(),
        superseded_by = v_new_account_id
    WHERE account_id = p_account_id
    AND is_current = TRUE;

    -- Insert new version
    INSERT INTO core.account_registry (
        account_id,
        account_number,
        account_type,
        currency_code,
        account_name,
        parent_account_id,
        path,
        balance,
        available_balance,
        hold_amount,
        status,
        metadata,
        valid_from,
        valid_to,
        superseded_by,
        is_current,
        record_hash,
        application_id,
        created_at,
        created_by
    ) VALUES (
        v_new_account_id,
        v_old_record.account_number,
        v_old_record.account_type,
        v_old_record.currency_code,
        COALESCE(p_account_name, v_old_record.account_name),
        v_old_record.parent_account_id,
        v_old_record.path,
        v_old_record.balance,
        v_old_record.available_balance,
        v_old_record.hold_amount,
        COALESCE(p_status, v_old_record.status),
        COALESCE(p_metadata, v_old_record.metadata),
        now(),
        'infinity'::timestamptz,
        NULL,
        TRUE,
        v_record_hash,
        v_old_record.application_id,
        now(),
        current_user
    );

    RETURN v_new_account_id;
END;
$$;

COMMENT ON FUNCTION core.update_account IS 'Creates new version of account (immutable versioning)';

-- Function: Place hold on account
CREATE OR REPLACE FUNCTION core.place_hold(
    p_account_id UUID,
    p_hold_amount DECIMAL(19,4),
    p_hold_reason VARCHAR(100),
    p_expires_at TIMESTAMPTZ DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_hold_id UUID;
    v_current_balance DECIMAL(19,4);
    v_current_holds DECIMAL(19,4);
BEGIN
    -- Get current balances
    SELECT balance, hold_amount 
    INTO v_current_balance, v_current_holds
    FROM core.account_registry
    WHERE account_id = p_account_id
    AND is_current = TRUE;

    IF v_current_balance IS NULL THEN
        RAISE EXCEPTION 'Account not found: %', p_account_id;
    END IF;

    -- Check available balance
    IF (v_current_balance - v_current_holds) < p_hold_amount THEN
        RAISE EXCEPTION 'Insufficient available balance for hold: requested %, available %',
            p_hold_amount, (v_current_balance - v_current_holds);
    END IF;

    -- Generate hold ID
    v_hold_id := gen_random_uuid();

    -- Note: Actual hold tracking would be in a separate holds table
    -- For now, update the account's hold amount
    UPDATE core.account_registry
    SET hold_amount = hold_amount + p_hold_amount
    WHERE account_id = p_account_id
    AND is_current = TRUE;

    -- Log to audit
    INSERT INTO core.audit_trail (
        table_name, record_id, action, old_values, new_values,
        changed_by, changed_at, transaction_id, severity
    ) VALUES (
        'account_registry', p_account_id, 'HOLD_PLACED',
        jsonb_build_object('hold_amount', v_current_holds),
        jsonb_build_object('hold_amount', v_current_holds + p_hold_amount),
        current_user, now(), txid_current(), 'INFO'
    );

    RETURN v_hold_id;
END;
$$;

COMMENT ON FUNCTION core.place_hold IS 'Places a hold on account balance';

-- Function: Release hold
CREATE OR REPLACE FUNCTION core.release_hold(
    p_account_id UUID,
    p_hold_amount DECIMAL(19,4)
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_current_holds DECIMAL(19,4);
BEGIN
    -- Get current holds
    SELECT hold_amount INTO v_current_holds
    FROM core.account_registry
    WHERE account_id = p_account_id
    AND is_current = TRUE;

    IF v_current_holds IS NULL THEN
        RAISE EXCEPTION 'Account not found: %', p_account_id;
    END IF;

    IF v_current_holds < p_hold_amount THEN
        RAISE EXCEPTION 'Hold amount exceeds current holds: requested %, current %',
            p_hold_amount, v_current_holds;
    END IF;

    -- Update hold amount
    UPDATE core.account_registry
    SET hold_amount = hold_amount - p_hold_amount
    WHERE account_id = p_account_id
    AND is_current = TRUE;

    -- Log to audit
    INSERT INTO core.audit_trail (
        table_name, record_id, action, old_values, new_values,
        changed_by, changed_at, transaction_id, severity
    ) VALUES (
        'account_registry', p_account_id, 'HOLD_RELEASED',
        jsonb_build_object('hold_amount', v_current_holds),
        jsonb_build_object('hold_amount', v_current_holds - p_hold_amount),
        current_user, now(), txid_current(), 'INFO'
    );

    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION core.release_hold IS 'Releases a hold on account balance';

-- Function: Get account balance
CREATE OR REPLACE FUNCTION core.get_account_balance(
    p_account_id UUID
)
RETURNS TABLE (
    total_balance DECIMAL(19,4),
    hold_amount DECIMAL(19,4),
    available_balance DECIMAL(19,4),
    currency_code CHAR(3)
)
LANGUAGE plpgsql
STABLE
SET search_path = core, public
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ar.balance,
        ar.hold_amount,
        ar.balance - ar.hold_amount,
        ar.currency_code
    FROM core.account_registry ar
    WHERE ar.account_id = p_account_id
    AND ar.is_current = TRUE;
END;
$$;

COMMENT ON FUNCTION core.get_account_balance IS 'Returns current balance information for an account';

-- Function: List child accounts
CREATE OR REPLACE FUNCTION core.list_child_accounts(
    p_parent_account_id UUID
)
RETURNS TABLE (
    account_id UUID,
    account_number VARCHAR(32),
    account_name VARCHAR(255),
    account_type VARCHAR(32),
    balance DECIMAL(19,4)
)
LANGUAGE plpgsql
STABLE
SET search_path = core, public
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ar.account_id,
        ar.account_number,
        ar.account_name,
        ar.account_type,
        ar.balance
    FROM core.account_registry ar
    WHERE ar.parent_account_id = p_parent_account_id
    AND ar.is_current = TRUE
    ORDER BY ar.account_number;
END;
$$;

COMMENT ON FUNCTION core.list_child_accounts IS 'Lists all direct child accounts';

-- Function: Get account tree
CREATE OR REPLACE FUNCTION core.get_account_tree(
    p_root_account_id UUID DEFAULT NULL
)
RETURNS TABLE (
    account_id UUID,
    account_number VARCHAR(32),
    account_name VARCHAR(255),
    path LTREE,
    depth INTEGER,
    balance DECIMAL(19,4)
)
LANGUAGE plpgsql
STABLE
SET search_path = core, public
AS $$
DECLARE
    v_root_path LTREE;
BEGIN
    IF p_root_account_id IS NOT NULL THEN
        SELECT path INTO v_root_path
        FROM core.account_registry
        WHERE account_id = p_root_account_id
        AND is_current = TRUE;
    END IF;

    RETURN QUERY
    SELECT 
        ar.account_id,
        ar.account_number,
        ar.account_name,
        ar.path,
        nlevel(ar.path) - COALESCE(nlevel(v_root_path), 0) AS depth,
        ar.balance
    FROM core.account_registry ar
    WHERE ar.is_current = TRUE
    AND (v_root_path IS NULL OR ar.path <@ v_root_path)
    ORDER BY ar.path;
END;
$$;

COMMENT ON FUNCTION core.get_account_tree IS 'Returns hierarchical account tree';
