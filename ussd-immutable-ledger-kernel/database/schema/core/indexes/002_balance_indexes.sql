-- ============================================================================
-- Balance and Posting Indexes
-- ============================================================================

-- Posting lookups
CREATE INDEX IF NOT EXISTS idx_postings_account ON core.movement_postings(account_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_postings_movement ON core.movement_postings(movement_id);

CREATE INDEX IF NOT EXISTS idx_postings_transaction ON core.movement_postings(transaction_id);

CREATE INDEX IF NOT EXISTS idx_postings_value_date ON core.movement_postings(value_date);

-- Movement lookups
CREATE INDEX IF NOT EXISTS idx_movements_debit ON core.movements(debit_account_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_movements_credit ON core.movements(credit_account_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_movements_transaction ON core.movements(transaction_id);

CREATE INDEX IF NOT EXISTS idx_movements_date ON core.movements(value_date);

CREATE INDEX IF NOT EXISTS idx_movements_reversal ON core.movements(is_reversed) WHERE is_reversed = TRUE;

-- Period balances
CREATE UNIQUE INDEX IF NOT EXISTS idx_period_balances_unique ON core.period_end_balances(account_id, fiscal_period_id);

CREATE INDEX IF NOT EXISTS idx_period_balances_period ON core.period_end_balances(fiscal_period_id, reconciliation_status);
