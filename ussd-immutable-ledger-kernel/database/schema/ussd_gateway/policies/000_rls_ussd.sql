-- ============================================================================
-- USSD Gateway - Row Level Security (RLS) Policies
-- PII protection and data isolation
-- ============================================================================

-- Enable RLS on all tables with sensitive data
ALTER TABLE ussd.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.ledger_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.otp_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.fraud_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.blocked_devices ENABLE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------------
-- Policy: Sessions - Users can only see their own sessions
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS sessions_user_isolation ON ussd.sessions;
CREATE POLICY sessions_user_isolation ON ussd.sessions
    FOR SELECT
    TO ussd_app_user
    USING (
        msisdn_hash = current_setting('app.current_user_hash', TRUE)
    );

COMMENT ON POLICY sessions_user_isolation ON ussd.sessions IS 
'Users can only access their own session records';

-- ----------------------------------------------------------------------------
-- Policy: Sessions - Service role can see all sessions
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS sessions_service_access ON ussd.sessions;
CREATE POLICY sessions_service_access ON ussd.sessions
    FOR ALL
    TO ussd_service_role
    USING (TRUE);

COMMENT ON POLICY sessions_service_access ON ussd.sessions IS 
'Service role has full access to sessions for operational needs';

-- ----------------------------------------------------------------------------
-- Policy: Sessions - Admin read-only access
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS sessions_admin_readonly ON ussd.sessions;
CREATE POLICY sessions_admin_readonly ON ussd.sessions
    FOR SELECT
    TO ussd_admin_role
    USING (TRUE);

COMMENT ON POLICY sessions_admin_readonly ON ussd.sessions IS 
'Admins have read-only access to all sessions';

-- ----------------------------------------------------------------------------
-- Policy: User Profiles - Self access only
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS profiles_self_access ON ussd.user_profiles;
CREATE POLICY profiles_self_access ON ussd.user_profiles
    FOR ALL
    TO ussd_app_user
    USING (
        msisdn_hash = current_setting('app.current_user_hash', TRUE)
    );

COMMENT ON POLICY profiles_self_access ON ussd.user_profiles IS 
'Users can only access their own profile';

-- ----------------------------------------------------------------------------
-- Policy: User Profiles - Service role full access
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS profiles_service_access ON ussd.user_profiles;
CREATE POLICY profiles_service_access ON ussd.user_profiles
    FOR ALL
    TO ussd_service_role
    USING (TRUE);

-- ----------------------------------------------------------------------------
-- Policy: Transactions - User can see own transactions
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS transactions_user_isolation ON ussd.transactions;
CREATE POLICY transactions_user_isolation ON ussd.transactions
    FOR SELECT
    TO ussd_app_user
    USING (
        session_id IN (
            SELECT id FROM ussd.sessions 
            WHERE msisdn_hash = current_setting('app.current_user_hash', TRUE)
        )
    );

COMMENT ON POLICY transactions_user_isolation ON ussd.transactions IS 
'Users can only view their own transaction history';

-- ----------------------------------------------------------------------------
-- Policy: Transactions - Service role full access
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS transactions_service_access ON ussd.transactions;
CREATE POLICY transactions_service_access ON ussd.transactions
    FOR ALL
    TO ussd_service_role
    USING (TRUE);

-- ----------------------------------------------------------------------------
-- Policy: Transactions - Audit role read access
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS transactions_audit_access ON ussd.transactions;
CREATE POLICY transactions_audit_access ON ussd.transactions
    FOR SELECT
    TO ussd_audit_role
    USING (TRUE);

-- ----------------------------------------------------------------------------
-- Policy: Ledger Entries - Read-only for users (own data)
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS ledger_user_isolation ON ussd.ledger_entries;
CREATE POLICY ledger_user_isolation ON ussd.ledger_entries
    FOR SELECT
    TO ussd_app_user
    USING (
        transaction_id IN (
            SELECT t.id FROM ussd.transactions t
            JOIN ussd.sessions s ON t.session_id = s.id
            WHERE s.msisdn_hash = current_setting('app.current_user_hash', TRUE)
        )
    );

COMMENT ON POLICY ledger_user_isolation ON ussd.ledger_entries IS 
'Users can view their own ledger entries (immutable records)';

-- ----------------------------------------------------------------------------
-- Policy: Ledger Entries - No modifications allowed
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS ledger_immutable ON ussd.ledger_entries;
CREATE POLICY ledger_immutable ON ussd.ledger_entries
    FOR ALL
    TO PUBLIC
    USING (FALSE);

COMMENT ON POLICY ledger_immutable ON ussd.ledger_entries IS 
'Ledger entries are immutable - no modifications allowed';

-- ----------------------------------------------------------------------------
-- Policy: Ledger Entries - Service role append-only
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS ledger_service_append ON ussd.ledger_entries;
CREATE POLICY ledger_service_append ON ussd.ledger_entries
    FOR INSERT
    TO ussd_service_role
    WITH CHECK (TRUE);

COMMENT ON POLICY ledger_service_append ON ussd.ledger_entries IS 
'Service role can append new ledger entries only';

-- ----------------------------------------------------------------------------
-- Policy: Audit Logs - No direct user access
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS audit_logs_no_user_access ON ussd.audit_logs;
CREATE POLICY audit_logs_no_user_access ON ussd.audit_logs
    FOR ALL
    TO ussd_app_user
    USING (FALSE);

COMMENT ON POLICY audit_logs_no_user_access ON ussd.audit_logs IS 
'Users cannot directly access audit logs';

-- ----------------------------------------------------------------------------
-- Policy: Audit Logs - Audit role full read access
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS audit_logs_audit_role ON ussd.audit_logs;
CREATE POLICY audit_logs_audit_role ON ussd.audit_logs
    FOR SELECT
    TO ussd_audit_role
    USING (TRUE);

COMMENT ON POLICY audit_logs_audit_role ON ussd.audit_logs IS 
'Audit role has full read access to audit logs';

-- ----------------------------------------------------------------------------
-- Policy: Audit Logs - Service role for system operations
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS audit_logs_service_role ON ussd.audit_logs;
CREATE POLICY audit_logs_service_role ON ussd.audit_logs
    FOR ALL
    TO ussd_service_role
    USING (TRUE);

-- ----------------------------------------------------------------------------
-- Policy: OTP Records - No direct user access
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS otp_no_user_access ON ussd.otp_records;
CREATE POLICY otp_no_user_access ON ussd.otp_records
    FOR ALL
    TO ussd_app_user
    USING (FALSE);

COMMENT ON POLICY otp_no_user_access ON ussd.otp_records IS 
'Users cannot access OTP records directly';

-- ----------------------------------------------------------------------------
-- Policy: OTP Records - Service role access
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS otp_service_access ON ussd.otp_records;
CREATE POLICY otp_service_access ON ussd.otp_records
    FOR ALL
    TO ussd_service_role
    USING (TRUE);

-- ----------------------------------------------------------------------------
-- Policy: Security Events - Restricted access
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS security_events_restricted ON ussd.security_events;
CREATE POLICY security_events_restricted ON ussd.security_events
    FOR ALL
    TO ussd_app_user
    USING (FALSE);

DROP POLICY IF EXISTS security_events_service ON ussd.security_events;
CREATE POLICY security_events_service ON ussd.security_events
    FOR ALL
    TO ussd_service_role
    USING (TRUE);

DROP POLICY IF EXISTS security_events_admin ON ussd.security_events;
CREATE POLICY security_events_admin ON ussd.security_events
    FOR SELECT
    TO ussd_admin_role
    USING (TRUE);

-- ----------------------------------------------------------------------------
-- Policy: Fraud Checks - Restricted access
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS fraud_checks_restricted ON ussd.fraud_checks;
CREATE POLICY fraud_checks_restricted ON ussd.fraud_checks
    FOR ALL
    TO ussd_app_user
    USING (FALSE);

DROP POLICY IF EXISTS fraud_checks_service ON ussd.fraud_checks;
CREATE POLICY fraud_checks_service ON ussd.fraud_checks
    FOR ALL
    TO ussd_service_role
    USING (TRUE);

DROP POLICY IF EXISTS fraud_checks_admin ON ussd.fraud_checks;
CREATE POLICY fraud_checks_admin ON ussd.fraud_checks
    FOR SELECT
    TO ussd_admin_role
    USING (TRUE);

-- ----------------------------------------------------------------------------
-- Policy: Blocked Devices - Admin only
-- ----------------------------------------------------------------------------
DROP POLICY IF EXISTS blocked_devices_admin_only ON ussd.blocked_devices;
CREATE POLICY blocked_devices_admin_only ON ussd.blocked_devices
    FOR ALL
    TO ussd_admin_role
    USING (TRUE);

DROP POLICY IF EXISTS blocked_devices_service ON ussd.blocked_devices;
CREATE POLICY blocked_devices_service ON ussd.blocked_devices
    FOR ALL
    TO ussd_service_role
    USING (TRUE);

-- ----------------------------------------------------------------------------
-- Force RLS for table owners (bypass RLS disabled)
-- ----------------------------------------------------------------------------
ALTER TABLE ussd.sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE ussd.user_profiles FORCE ROW LEVEL SECURITY;
ALTER TABLE ussd.transactions FORCE ROW LEVEL SECURITY;
ALTER TABLE ussd.ledger_entries FORCE ROW LEVEL SECURITY;
ALTER TABLE ussd.audit_logs FORCE ROW LEVEL SECURITY;
ALTER TABLE ussd.otp_records FORCE ROW LEVEL SECURITY;
ALTER TABLE ussd.security_events FORCE ROW LEVEL SECURITY;
ALTER TABLE ussd.fraud_checks FORCE ROW LEVEL SECURITY;
ALTER TABLE ussd.blocked_devices FORCE ROW LEVEL SECURITY;

-- ----------------------------------------------------------------------------
-- Helper function to set current user context for RLS
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.set_user_context(
    p_msisdn VARCHAR(20)
) RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_user_hash', encode(digest(p_msisdn, 'sha256'), 'hex'), FALSE);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.set_user_context IS 
'Sets the user context for RLS policies';

-- ----------------------------------------------------------------------------
-- Helper function to clear user context
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.clear_user_context()
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_user_hash', '', FALSE);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.clear_user_context IS 
'Clears the user context for RLS policies';

-- ----------------------------------------------------------------------------
-- Function to create roles if they don't exist
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.setup_rls_roles()
RETURNS VOID AS $$
BEGIN
    -- Application user role (end users)
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ussd_app_user') THEN
        CREATE ROLE ussd_app_user NOLOGIN;
    END IF;
    
    -- Service role (application backend)
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ussd_service_role') THEN
        CREATE ROLE ussd_service_role NOLOGIN;
    END IF;
    
    -- Admin role (system administrators)
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ussd_admin_role') THEN
        CREATE ROLE ussd_admin_role NOLOGIN;
    END IF;
    
    -- Audit role (compliance/auditing)
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ussd_audit_role') THEN
        CREATE ROLE ussd_audit_role NOLOGIN;
    END IF;
    
    -- Grant schema usage
    GRANT USAGE ON SCHEMA ussd TO ussd_app_user, ussd_service_role, ussd_admin_role, ussd_audit_role;
    
    -- Grant table permissions
    GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA ussd TO ussd_service_role;
    GRANT SELECT ON ALL TABLES IN SCHEMA ussd TO ussd_audit_role;
    GRANT SELECT ON ALL TABLES IN SCHEMA ussd TO ussd_admin_role;
    
    -- Grant sequence usage
    GRANT USAGE ON ALL SEQUENCES IN SCHEMA ussd TO ussd_service_role;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION ussd.setup_rls_roles IS 
'Creates RLS roles and grants permissions';
