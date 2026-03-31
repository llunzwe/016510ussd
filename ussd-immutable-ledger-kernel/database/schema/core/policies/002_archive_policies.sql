-- ============================================================================
-- Archive Policies
-- ============================================================================

-- Enable RLS on archive tables
ALTER TABLE core.archive_manifest ENABLE ROW LEVEL SECURITY;

-- Policy: Archive manifest access
CREATE POLICY archive_isolation ON core.archive_manifest
    FOR ALL
    USING (application_id = current_setting('app.current_account_id', true)::UUID);

-- Policy: Admin full access
CREATE POLICY archive_admin ON core.archive_manifest
    FOR ALL
    TO admin
    USING (true);

-- Policy: Auditor read-only
CREATE POLICY archive_auditor ON core.archive_manifest
    FOR SELECT
    TO auditor
    USING (true);
