-- ============================================================================
-- Row Level Security Policies
-- ============================================================================

-- Enable RLS on all tables
ALTER TABLE core.account_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.movements ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.movement_postings ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.period_end_balances ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.exchange_rates ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their application's data
CREATE POLICY account_isolation ON core.account_registry
    FOR ALL
    USING (application_id = current_setting('app.current_account_id', true)::UUID);

CREATE POLICY transaction_isolation ON core.transactions
    FOR ALL
    USING (application_id = current_setting('app.current_account_id', true)::UUID);

CREATE POLICY movement_isolation ON core.movements
    FOR ALL
    USING (application_id = current_setting('app.current_account_id', true)::UUID);

CREATE POLICY posting_isolation ON core.movement_postings
    FOR ALL
    USING (application_id = current_setting('app.current_account_id', true)::UUID);

-- Policy: Admin bypass (for administrative operations)
CREATE POLICY admin_bypass_accounts ON core.account_registry
    FOR ALL
    TO admin
    USING (true);

CREATE POLICY admin_bypass_transactions ON core.transactions
    FOR ALL
    TO admin
    USING (true);

-- Policy: Read-only access for auditors
CREATE POLICY auditor_read_accounts ON core.account_registry
    FOR SELECT
    TO auditor
    USING (true);

CREATE POLICY auditor_read_transactions ON core.transactions
    FOR SELECT
    TO auditor
    USING (true);

CREATE POLICY auditor_read_movements ON core.movements
    FOR SELECT
    TO auditor
    USING (true);
