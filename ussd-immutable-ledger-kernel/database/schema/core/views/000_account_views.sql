-- ============================================================================
-- Account Views
-- ============================================================================

-- View: Current accounts only
CREATE OR REPLACE VIEW core.v_current_accounts AS
SELECT 
    account_id,
    account_number,
    account_type,
    currency_code,
    account_name,
    balance,
    available_balance,
    hold_amount,
    status,
    created_at,
    application_id
FROM core.account_registry
WHERE is_current = TRUE;

COMMENT ON VIEW core.v_current_accounts IS 'Shows only current version of each account';

-- View: Account hierarchy
CREATE OR REPLACE VIEW core.v_account_hierarchy AS
SELECT 
    ar.account_id,
    ar.account_number,
    ar.account_name,
    ar.path,
    nlevel(ar.path) AS depth,
    ar.balance,
    ar.currency_code,
    ar.status,
    ar.parent_account_id,
    par.account_name AS parent_account_name
FROM core.account_registry ar
LEFT JOIN core.account_registry par ON ar.parent_account_id = par.account_id
WHERE ar.is_current = TRUE
ORDER BY ar.path;

COMMENT ON VIEW core.v_account_hierarchy IS 'Hierarchical view of accounts with depth';

-- View: Account summary with children
CREATE OR REPLACE VIEW core.v_account_summary AS
WITH RECURSIVE account_tree AS (
    SELECT 
        account_id,
        account_number,
        account_name,
        balance,
        currency_code,
        path,
        account_id AS root_id
    FROM core.account_registry
    WHERE is_current = TRUE
    UNION ALL
    SELECT 
        ar.account_id,
        ar.account_number,
        ar.account_name,
        ar.balance,
        ar.currency_code,
        ar.path,
        at.root_id
    FROM core.account_registry ar
    JOIN account_tree at ON ar.path <@ at.path AND ar.account_id != at.account_id
    WHERE ar.is_current = TRUE
)
SELECT 
    root_id AS account_id,
    (SELECT account_number FROM core.account_registry WHERE account_id = root_id) AS account_number,
    (SELECT account_name FROM core.account_registry WHERE account_id = root_id) AS account_name,
    currency_code,
    SUM(balance) AS total_balance,
    COUNT(*) AS child_count
FROM account_tree
GROUP BY root_id, currency_code;

COMMENT ON VIEW core.v_account_summary IS 'Account balances aggregated with all children';
