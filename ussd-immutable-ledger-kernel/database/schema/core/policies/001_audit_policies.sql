-- ============================================================================
-- Audit Policies
-- ============================================================================

-- Enable RLS on audit tables
ALTER TABLE core.audit_trail ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.idempotency_keys ENABLE ROW LEVEL SECURITY;

-- Policy: Audit trail read-only
CREATE POLICY audit_read_only ON core.audit_trail
    FOR SELECT
    USING (true);

-- Policy: No modification of audit trail
CREATE POLICY audit_no_insert ON core.audit_trail
    FOR INSERT
    TO admin
    WITH CHECK (true);

CREATE POLICY audit_no_update ON core.audit_trail
    FOR UPDATE
    USING (false);

CREATE POLICY audit_no_delete ON core.audit_trail
    FOR DELETE
    USING (false);

-- Policy: Idempotency key access
CREATE POLICY idempotency_isolation ON core.idempotency_keys
    FOR ALL
    USING (application_id = current_setting('app.current_account_id', true)::UUID);
