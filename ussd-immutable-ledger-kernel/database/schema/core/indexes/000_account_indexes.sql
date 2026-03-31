-- ============================================================================
-- Account Indexes
-- ============================================================================

-- Primary lookups
CREATE INDEX IF NOT EXISTS idx_accounts_number ON core.account_registry(account_number) 
    WHERE is_current = TRUE;

CREATE INDEX IF NOT EXISTS idx_accounts_type ON core.account_registry(account_type, is_current);

CREATE INDEX IF NOT EXISTS idx_accounts_currency ON core.account_registry(currency_code, is_current);

-- Hierarchy search
CREATE INDEX IF NOT EXISTS idx_accounts_path ON core.account_registry USING GIST(path);

CREATE INDEX IF NOT EXISTS idx_accounts_parent ON core.account_registry(parent_account_id) 
    WHERE is_current = TRUE;

-- Application isolation
CREATE INDEX IF NOT EXISTS idx_accounts_app ON core.account_registry(application_id, is_current);

-- Status filtering
CREATE INDEX IF NOT EXISTS idx_accounts_status ON core.account_registry(status) 
    WHERE is_current = TRUE;

-- Date range queries
CREATE INDEX IF NOT EXISTS idx_accounts_created ON core.account_registry(created_at DESC);

-- Multi-column for common queries
CREATE INDEX IF NOT EXISTS idx_accounts_app_type ON core.account_registry(application_id, account_type, is_current);
