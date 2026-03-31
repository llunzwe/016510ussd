-- ============================================================================
-- Transaction Indexes
-- ============================================================================

-- Time-series queries (hypertable already optimized)
CREATE INDEX IF NOT EXISTS idx_transactions_type ON core.transactions(transaction_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_transactions_app ON core.transactions(application_id, created_at DESC);

-- Idempotency lookups
CREATE UNIQUE INDEX IF NOT EXISTS idx_transactions_idempotency ON core.transactions(idempotency_key);

-- Hash chain verification
CREATE INDEX IF NOT EXISTS idx_transactions_hash ON core.transactions(current_hash);

-- Saga lookups
CREATE INDEX IF NOT EXISTS idx_transactions_saga ON core.transactions(saga_id) WHERE saga_id IS NOT NULL;

-- JSON payload queries
CREATE INDEX IF NOT EXISTS idx_transactions_payload ON core.transactions USING GIN(payload jsonb_path_ops);

-- Block linkage
CREATE INDEX IF NOT EXISTS idx_block_tx_block ON core.block_transactions(block_id);
CREATE INDEX IF NOT EXISTS idx_block_tx_transaction ON core.block_transactions(transaction_id);
