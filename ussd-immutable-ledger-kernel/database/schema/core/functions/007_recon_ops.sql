-- ============================================================================
-- Reconciliation Operations
-- ============================================================================

-- Function: Start reconciliation run
CREATE OR REPLACE FUNCTION core.start_reconciliation(
    p_reconciliation_type VARCHAR(32),
    p_source_system VARCHAR(100),
    p_fiscal_period_id UUID,
    p_application_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_run_id UUID;
BEGIN
    v_run_id := gen_random_uuid();

    INSERT INTO core.reconciliation_runs (
        run_id,
        reconciliation_type,
        status,
        source_system,
        fiscal_period_id,
        total_records,
        matched_records,
        unmatched_records,
        discrepancy_amount,
        record_hash,
        application_id,
        created_at,
        created_by
    ) VALUES (
        v_run_id,
        p_reconciliation_type,
        'IN_PROGRESS',
        p_source_system,
        p_fiscal_period_id,
        0, 0, 0, 0,
        encode(digest(v_run_id::text || now()::text, 'sha256'), 'hex'),
        COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID),
        now(),
        current_user
    );

    RETURN v_run_id;
END;
$$;

COMMENT ON FUNCTION core.start_reconciliation IS 'Starts a new reconciliation run';

-- Function: Add reconciliation item
CREATE OR REPLACE FUNCTION core.add_reconciliation_item(
    p_run_id UUID,
    p_external_reference VARCHAR(64),
    p_external_amount DECIMAL(19,4),
    p_external_date DATE,
    p_ledger_transaction_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_item_id UUID;
    v_match_status VARCHAR(16);
    v_discrepancy DECIMAL(19,4);
    v_ledger_amount DECIMAL(19,4);
BEGIN
    v_item_id := gen_random_uuid();

    -- Check for match
    IF p_ledger_transaction_id IS NOT NULL THEN
        SELECT mp.amount INTO v_ledger_amount
        FROM core.movement_postings mp
        WHERE mp.transaction_id = p_ledger_transaction_id
        LIMIT 1;

        IF v_ledger_amount = p_external_amount THEN
            v_match_status := 'MATCHED';
            v_discrepancy := 0;
        ELSE
            v_match_status := 'MISMATCHED';
            v_discrepancy := ABS(v_ledger_amount - p_external_amount);
        END IF;
    ELSE
        v_match_status := 'UNMATCHED';
        v_discrepancy := p_external_amount;
    END IF;

    INSERT INTO core.reconciliation_items (
        item_id,
        run_id,
        external_reference,
        external_amount,
        external_date,
        ledger_transaction_id,
        ledger_amount,
        match_status,
        discrepancy_amount,
        investigation_status,
        record_hash,
        created_at
    ) VALUES (
        v_item_id,
        p_run_id,
        p_external_reference,
        p_external_amount,
        p_external_date,
        p_ledger_transaction_id,
        v_ledger_amount,
        v_match_status,
        v_discrepancy,
        CASE v_match_status WHEN 'MATCHED' THEN NULL ELSE 'PENDING' END,
        encode(digest(v_item_id::text || now()::text, 'sha256'), 'hex'),
        now()
    );

    -- Update run totals
    UPDATE core.reconciliation_runs
    SET total_records = total_records + 1,
        matched_records = matched_records + CASE WHEN v_match_status = 'MATCHED' THEN 1 ELSE 0 END,
        unmatched_records = unmatched_records + CASE WHEN v_match_status != 'MATCHED' THEN 1 ELSE 0 END,
        discrepancy_amount = discrepancy_amount + v_discrepancy
    WHERE run_id = p_run_id;

    RETURN v_item_id;
END;
$$;

COMMENT ON FUNCTION core.add_reconciliation_item IS 'Adds external record to reconciliation';

-- Function: Complete reconciliation
CREATE OR REPLACE FUNCTION core.complete_reconciliation(
    p_run_id UUID,
    p_approval_notes TEXT DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
BEGIN
    UPDATE core.reconciliation_runs
    SET status = CASE 
            WHEN unmatched_records = 0 AND discrepancy_amount = 0 THEN 'APPROVED'
            ELSE 'PENDING_REVIEW'
        END,
        approved_by = CASE 
            WHEN unmatched_records = 0 AND discrepancy_amount = 0 THEN current_user
            ELSE NULL
        END,
        approved_at = CASE 
            WHEN unmatched_records = 0 AND discrepancy_amount = 0 THEN now()
            ELSE NULL
        END,
        approval_notes = p_approval_notes,
        completed_at = now()
    WHERE run_id = p_run_id;

    RETURN FOUND;
END;
$$;

COMMENT ON FUNCTION core.complete_reconciliation IS 'Finalizes reconciliation run';
