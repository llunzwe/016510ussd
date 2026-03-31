-- ============================================================================
-- Security Policies
-- ============================================================================

-- Enable RLS on security-related tables
ALTER TABLE core.suspense_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.reconciliation_runs ENABLE ROW LEVEL SECURITY;

-- Policy: Suspense item access
CREATE POLICY suspense_isolation ON core.suspense_items
    FOR ALL
    USING (application_id = current_setting('app.current_account_id', true)::UUID);

-- Policy: Reconciliation access
CREATE POLICY reconciliation_isolation ON core.reconciliation_runs
    FOR ALL
    USING (application_id = current_setting('app.current_account_id', true)::UUID);

-- Policy: Force RLS for all users
ALTER TABLE core.account_registry FORCE ROW LEVEL SECURITY;
ALTER TABLE core.transactions FORCE ROW LEVEL SECURITY;
ALTER TABLE core.movements FORCE ROW LEVEL SECURITY;
