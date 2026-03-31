-- ============================================================================
-- Ledger Views
-- ============================================================================

-- View: Complete ledger entries
CREATE OR REPLACE VIEW core.v_ledger_entries AS
SELECT 
    mp.posting_id,
    mp.movement_id,
    t.transaction_id,
    t.transaction_type,
    t.created_at AS transaction_date,
    ar.account_id,
    ar.account_number,
    ar.account_name,
    mp.side,
    mp.amount,
    mp.running_balance,
    mp.currency_code,
    mp.value_date,
    m.description,
    m.reference_number,
    t.application_id
FROM core.movement_postings mp
JOIN core.account_registry ar ON mp.account_id = ar.account_id AND ar.is_current = TRUE
JOIN core.movements m ON mp.movement_id = m.movement_id
JOIN core.transactions t ON mp.transaction_id = t.transaction_id
ORDER BY mp.created_at DESC;

COMMENT ON VIEW core.v_ledger_entries IS 'Complete ledger with account details';

-- View: Trial balance
CREATE OR REPLACE VIEW core.v_trial_balance AS
SELECT 
    ar.account_id,
    ar.account_number,
    ar.account_name,
    ar.account_type,
    ar.currency_code,
    COALESCE(SUM(CASE WHEN mp.side = 'DEBIT' THEN mp.amount ELSE 0 END), 0) AS total_debits,
    COALESCE(SUM(CASE WHEN mp.side = 'CREDIT' THEN mp.amount ELSE 0 END), 0) AS total_credits,
    CASE ar.account_type
        WHEN 'ASSET' THEN COALESCE(SUM(CASE WHEN mp.side = 'DEBIT' THEN mp.amount ELSE -mp.amount END), 0)
        WHEN 'EXPENSE' THEN COALESCE(SUM(CASE WHEN mp.side = 'DEBIT' THEN mp.amount ELSE -mp.amount END), 0)
        ELSE COALESCE(SUM(CASE WHEN mp.side = 'CREDIT' THEN mp.amount ELSE -mp.amount END), 0)
    END AS balance
FROM core.account_registry ar
LEFT JOIN core.movement_postings mp ON ar.account_id = mp.account_id
WHERE ar.is_current = TRUE
GROUP BY ar.account_id, ar.account_number, ar.account_name, ar.account_type, ar.currency_code;

COMMENT ON VIEW core.v_trial_balance IS 'Trial balance by account';

-- View: Block summary
CREATE OR REPLACE VIEW core.v_block_summary AS
SELECT 
    b.block_id,
    b.block_number,
    b.current_hash,
    b.previous_hash,
    b.merkle_root,
    b.transaction_count,
    b.created_at,
    COUNT(bt.transaction_id) AS confirmed_transactions
FROM core.blocks b
LEFT JOIN core.block_transactions bt ON b.block_id = bt.block_id
GROUP BY b.block_id, b.block_number, b.current_hash, b.previous_hash, b.merkle_root, b.transaction_count, b.created_at
ORDER BY b.block_number DESC;

COMMENT ON VIEW core.v_block_summary IS 'Block summary with transaction counts';

-- View: Audit trail summary
CREATE OR REPLACE VIEW core.v_audit_summary AS
SELECT 
    table_name,
    action,
    COUNT(*) AS action_count,
    MIN(changed_at) AS first_occurrence,
    MAX(changed_at) AS last_occurrence
FROM core.audit_trail
GROUP BY table_name, action
ORDER BY table_name, action;

COMMENT ON VIEW core.v_audit_summary IS 'Summary of audit trail activity';
