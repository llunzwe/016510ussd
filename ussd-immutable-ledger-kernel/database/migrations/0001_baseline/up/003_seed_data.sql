-- ============================================================================
-- Seed Data
-- ============================================================================

-- Seed transaction types
INSERT INTO core.transaction_types (type_id, type_code, type_description, is_active, requires_approval, approval_threshold)
VALUES 
    (gen_random_uuid(), 'DEPOSIT', 'Deposit transaction', TRUE, FALSE, NULL),
    (gen_random_uuid(), 'WITHDRAWAL', 'Withdrawal transaction', TRUE, FALSE, 10000.00),
    (gen_random_uuid(), 'TRANSFER', 'Transfer between accounts', TRUE, FALSE, 50000.00),
    (gen_random_uuid(), 'PAYMENT', 'Payment transaction', TRUE, FALSE, NULL),
    (gen_random_uuid(), 'FEE', 'Fee deduction', TRUE, FALSE, NULL),
    (gen_random_uuid(), 'INTEREST', 'Interest credit', TRUE, FALSE, NULL),
    (gen_random_uuid(), 'ADJUSTMENT', 'Manual adjustment', TRUE, TRUE, 0.00),
    (gen_random_uuid(), 'REVERSAL', 'Reversal of prior transaction', TRUE, TRUE, 0.00)
ON CONFLICT (type_code) DO NOTHING;

-- Seed exchange rates (base USD)
INSERT INTO core.exchange_rates (rate_id, from_currency, to_currency, rate, rate_date, source, is_active)
VALUES
    (gen_random_uuid(), 'USD', 'EUR', 0.85, CURRENT_DATE, 'ECB', TRUE),
    (gen_random_uuid(), 'USD', 'GBP', 0.73, CURRENT_DATE, 'ECB', TRUE),
    (gen_random_uuid(), 'USD', 'JPY', 110.0, CURRENT_DATE, 'ECB', TRUE),
    (gen_random_uuid(), 'USD', 'ZAR', 14.5, CURRENT_DATE, 'ECB', TRUE)
ON CONFLICT DO NOTHING;

-- Seed entity sequences
INSERT INTO core.entity_sequences (sequence_name, current_value, increment_by, application_id)
VALUES
    ('transaction_ref', 1000000, 1, NULL),
    ('account_number', 1000000000, 1, NULL),
    ('batch_id', 1, 1, NULL),
    ('document_id', 1, 1, NULL),
    ('settlement_id', 1, 1, NULL)
ON CONFLICT DO NOTHING;

-- Seed system account
INSERT INTO core.account_registry (
    account_id, account_number, account_type, currency_code, account_name,
    balance, available_balance, hold_amount, status, is_current, record_hash, created_by
)
VALUES (
    gen_random_uuid(), 'SYSTEM', 'EQUITY', 'USD', 'System Account',
    0, 0, 0, 'ACTIVE', TRUE, encode(digest('system', 'sha256'), 'hex'), 'system'
)
ON CONFLICT DO NOTHING;
