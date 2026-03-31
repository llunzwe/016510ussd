-- ============================================================================
-- Balance Views
-- ============================================================================

-- View: Current balances
CREATE OR REPLACE VIEW core.v_current_balances AS
SELECT 
    ar.account_id,
    ar.account_number,
    ar.account_name,
    ar.account_type,
    ar.currency_code,
    ar.balance AS total_balance,
    ar.hold_amount,
    ar.balance - ar.hold_amount AS available_balance,
    ar.status,
    ar.application_id
FROM core.account_registry ar
WHERE ar.is_current = TRUE;

COMMENT ON VIEW core.v_current_balances IS 'Current account balances';

-- View: Balance history
CREATE OR REPLACE VIEW core.v_balance_history AS
SELECT 
    mp.account_id,
    ar.account_number,
    ar.account_name,
    mp.side,
    mp.amount,
    mp.running_balance,
    mp.currency_code,
    mp.value_date,
    mp.created_at,
    m.description,
    m.reference_number
FROM core.movement_postings mp
JOIN core.account_registry ar ON mp.account_id = ar.account_id AND ar.is_current = TRUE
LEFT JOIN core.movements m ON mp.movement_id = m.movement_id
ORDER BY mp.account_id, mp.created_at DESC;

COMMENT ON VIEW core.v_balance_history IS 'Historical balance movements';

-- View: Period-end balances summary
CREATE OR REPLACE VIEW core.v_period_balances AS
SELECT 
    peb.balance_id,
    peb.account_id,
    ar.account_number,
    ar.account_name,
    fp.period_name,
    fp.period_start,
    fp.period_end,
    peb.opening_balance,
    peb.total_credits,
    peb.total_debits,
    peb.closing_balance,
    peb.reconciliation_status,
    peb.ifrs_compliant
FROM core.period_end_balances peb
JOIN core.account_registry ar ON peb.account_id = ar.account_id AND ar.is_current = TRUE
JOIN core.fiscal_periods fp ON peb.fiscal_period_id = fp.fiscal_period_id;

COMMENT ON VIEW core.v_period_balances IS 'Period-end balance summary with fiscal period info';

-- View: Multi-currency balances
CREATE OR REPLACE VIEW core.v_multi_currency_balances AS
SELECT 
    ar.account_id,
    ar.account_number,
    ar.account_name,
    ar.currency_code AS base_currency,
    ar.balance AS base_balance,
    ar.balance * er.rate AS usd_equivalent,
    ar.application_id
FROM core.account_registry ar
LEFT JOIN core.exchange_rates er ON ar.currency_code = er.from_currency 
    AND er.to_currency = 'USD' AND er.is_active = TRUE
WHERE ar.is_current = TRUE;

COMMENT ON VIEW core.v_multi_currency_balances IS 'Account balances with USD equivalents';
