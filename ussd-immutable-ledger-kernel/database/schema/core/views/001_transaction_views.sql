-- ============================================================================
-- Transaction Views
-- ============================================================================

-- View: Recent transactions with details
CREATE OR REPLACE VIEW core.v_recent_transactions AS
SELECT 
    t.transaction_id,
    t.transaction_type,
    t.current_hash,
    t.created_at,
    t.application_id,
    tt.type_description,
    COUNT(m.movement_id) AS movement_count,
    SUM(m.amount) AS total_amount
FROM core.transactions t
JOIN core.transaction_types tt ON t.transaction_type = tt.type_code
LEFT JOIN core.movements m ON t.transaction_id = m.transaction_id
GROUP BY t.transaction_id, t.transaction_type, t.current_hash, t.created_at, 
         t.application_id, tt.type_description
ORDER BY t.created_at DESC;

COMMENT ON VIEW core.v_recent_transactions IS 'Recent transactions with movement summaries';

-- View: Transaction with full movement details
CREATE OR REPLACE VIEW core.v_transaction_details AS
SELECT 
    t.transaction_id,
    t.transaction_type,
    t.payload,
    t.idempotency_key,
    t.created_at,
    m.movement_id,
    m.amount,
    m.currency_code,
    m.description,
    da.account_number AS debit_account,
    da.account_name AS debit_account_name,
    ca.account_number AS credit_account,
    ca.account_name AS credit_account_name
FROM core.transactions t
LEFT JOIN core.movements m ON t.transaction_id = m.transaction_id
LEFT JOIN core.account_registry da ON m.debit_account_id = da.account_id AND da.is_current = TRUE
LEFT JOIN core.account_registry ca ON m.credit_account_id = ca.account_id AND ca.is_current = TRUE;

COMMENT ON VIEW core.v_transaction_details IS 'Full transaction details with account names';

-- View: Pending transactions (for monitoring)
CREATE OR REPLACE VIEW core.v_pending_transactions AS
SELECT 
    t.*,
    ts.status AS saga_status,
    ts.timeout_at
FROM core.transactions t
LEFT JOIN core.transaction_sagas ts ON t.saga_id = ts.saga_id
WHERE ts.status IN ('PENDING', 'RUNNING', 'COMPENSATING')
OR t.transaction_id NOT IN (SELECT DISTINCT transaction_id FROM core.movements);

COMMENT ON VIEW core.v_pending_transactions IS 'Transactions not yet fully processed';
