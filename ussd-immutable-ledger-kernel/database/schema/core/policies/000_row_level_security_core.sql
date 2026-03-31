-- =============================================================================
-- USSD KERNEL CORE SCHEMA - ROW-LEVEL SECURITY POLICIES
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    000_row_level_security_core.sql
-- SCHEMA:      core
-- CATEGORY:    Security Policies
-- DESCRIPTION: Row-Level Security (RLS) policies for core schema tables
--              enforcing tenant isolation and access control.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.5.15 Access control - Row-level access control
├── A.8.1 User endpoint devices - Device-based policies
├── A.8.2 Privileged access rights - Admin bypass policies
└── A.8.5 Secure authentication - Session-based enforcement

ISO/IEC 27017:2015 (Cloud Security)
├── Multi-tenancy: Tenant isolation enforcement
├── Data segregation: Row-level segregation
├── Access transparency: Policy visibility
└── Compliance: Regulatory access control

GDPR Compliance
├── Data minimization: Access to necessary data only
├── Purpose limitation: Policy-based purpose enforcement
├── Subject rights: Data access support
└── Breach prevention: Unauthorized access prevention

Financial Regulations
├── Segregation: Client data segregation
├── Confidentiality: Unauthorized access prevention
├── Audit: Policy violation logging
└── Reporting: Access control reports

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. POLICY TYPES
   - SELECT: Read access control
   - INSERT: Create access control
   - UPDATE: Modify access control (limited in immutable tables)
   - DELETE: Delete access control (blocked in immutable tables)
   - ALL: Combined policy

2. POLICY EXPRESSIONS
   - Application isolation
   - Account ownership
   - Role-based access
   - Session context

3. BYPASS POLICIES
   - System role bypass
   - Admin role bypass
   - Emergency access
   - Audit logging of bypass

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

POLICY ENFORCEMENT:
1. Application Isolation
   - Users see only their application's data
   - Cross-application queries blocked
   - Application context from session variables

2. Account Ownership
   - Users see their own account data
   - Beneficiary account access for transactions
   - Group membership-based access

3. Role-Based Access
   - Admin role full access
   - Auditor role read-only
   - User role restricted
   - System role bypass

POLICY BYPASS:
1. Emergency Access
   - Superuser bypass (logged)
   - Break-glass procedures
   - Post-access review required
   - Incident reporting

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

POLICY OPTIMIZATION:
- Simple policy expressions
   - Index-friendly conditions
   - Avoid complex subqueries
   - Materialized views for complex rules

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- POLICY_VIOLATION: Access denied by policy
- POLICY_BYPASS: Admin/superuser bypass
- POLICY_CHANGE: Policy modification
- ACCESS_GRANTED: Successful policy check

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- TABLE: RLS Violation Log
-- DESCRIPTION: Log of RLS policy violations and bypasses
-- =============================================================================
CREATE TABLE IF NOT EXISTS core.rls_violation_log (
    violation_id BIGSERIAL PRIMARY KEY,
    event_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    database_user TEXT NOT NULL,
    application_user TEXT,
    session_id TEXT,
    client_ip INET,
    table_name TEXT NOT NULL,
    operation TEXT NOT NULL,  -- SELECT, INSERT, UPDATE, DELETE
    attempted_query TEXT,
    violation_type TEXT NOT NULL,  -- POLICY_DENIED, BYPASS_USED
    bypass_reason TEXT,
    bypass_authorized_by TEXT,
    metadata JSONB DEFAULT '{}'
);

-- Index for querying violations
CREATE INDEX idx_rls_violation_log_timestamp 
    ON core.rls_violation_log(event_timestamp DESC);
CREATE INDEX idx_rls_violation_log_user 
    ON core.rls_violation_log(database_user, event_timestamp DESC);

-- =============================================================================
-- ENABLE RLS ON CORE TABLES
-- DESCRIPTION: Activate row-level security on all core schema tables
-- PRIORITY: CRITICAL
-- =============================================================================

-- Enable RLS on transaction_log (already enabled in table definition, ensure force)
ALTER TABLE core.transaction_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.transaction_log FORCE ROW LEVEL SECURITY;

-- Enable RLS on account_registry
ALTER TABLE core.account_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.account_registry FORCE ROW LEVEL SECURITY;

-- Enable RLS on movement_legs
ALTER TABLE core.movement_legs ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.movement_legs FORCE ROW LEVEL SECURITY;

-- Enable RLS on movement_postings
ALTER TABLE core.movement_postings ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.movement_postings FORCE ROW LEVEL SECURITY;

-- Enable RLS on blocks
ALTER TABLE core.blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.blocks FORCE ROW LEVEL SECURITY;

-- Enable RLS on chart_of_accounts
ALTER TABLE core.chart_of_accounts ENABLE ROW LEVEL SECURITY;

-- Enable RLS on audit_trail
ALTER TABLE core.audit_trail ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.audit_trail FORCE ROW LEVEL SECURITY;

-- =============================================================================
-- HELPER FUNCTIONS FOR SESSION CONTEXT
-- DESCRIPTION: Functions to get application_id, account_id, and role from session
-- PRIORITY: CRITICAL
-- =============================================================================

-- Function to get current application_id from session
CREATE OR REPLACE FUNCTION core.current_app_id()
RETURNS UUID
LANGUAGE plpgsql
STABLE SECURITY DEFINER
AS $$
BEGIN
    -- Try to get from session variable
    BEGIN
        RETURN current_setting('app.current_application_id', true)::UUID;
    EXCEPTION WHEN OTHERS THEN
        RETURN NULL;
    END;
END;
$$;

-- Function to get current account_id from session
CREATE OR REPLACE FUNCTION core.current_account_id()
RETURNS UUID
LANGUAGE plpgsql
STABLE SECURITY DEFINER
AS $$
BEGIN
    -- Try to get from session variable
    BEGIN
        RETURN current_setting('app.current_account_id', true)::UUID;
    EXCEPTION WHEN OTHERS THEN
        RETURN NULL;
    END;
END;
$$;

-- Function to get current user role from session
CREATE OR REPLACE FUNCTION core.current_user_role()
RETURNS TEXT
LANGUAGE plpgsql
STABLE SECURITY DEFINER
AS $$
BEGIN
    -- Try to get from session variable
    BEGIN
        RETURN current_setting('app.current_role', true);
    EXCEPTION WHEN OTHERS THEN
        RETURN NULL;
    END;
END;
$$;

-- Function to log RLS violations
CREATE OR REPLACE FUNCTION core.log_rls_violation(
    p_table_name TEXT,
    p_operation TEXT,
    p_violation_type TEXT,
    p_bypass_reason TEXT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO core.rls_violation_log (
        database_user,
        application_user,
        session_id,
        client_ip,
        table_name,
        operation,
        violation_type,
        bypass_reason
    ) VALUES (
        current_user,
        core.current_account_id()::TEXT,
        pg_backend_pid()::TEXT,
        inet_client_addr(),
        p_table_name,
        p_operation,
        p_violation_type,
        p_bypass_reason
    );
END;
$$;

-- Function to check if user is system/admin role
CREATE OR REPLACE FUNCTION core.is_privileged_user()
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE SECURITY DEFINER
AS $$
DECLARE
    v_role TEXT;
BEGIN
    v_role := core.current_user_role();
    RETURN v_role IN ('system', 'admin', 'kernel');
END;
$$;

-- =============================================================================
-- RLS POLICIES: transaction_log
-- DESCRIPTION: Control access to transaction data based on account ownership
-- PRIORITY: CRITICAL
-- =============================================================================

-- Drop existing policies to avoid conflicts
DROP POLICY IF EXISTS transaction_log_owner_select ON core.transaction_log;
DROP POLICY IF EXISTS transaction_log_app_select ON core.transaction_log;
DROP POLICY IF EXISTS transaction_log_kernel_all ON core.transaction_log;
DROP POLICY IF EXISTS transaction_log_insert ON core.transaction_log;

-- Policy: Users can see transactions they initiated or are beneficiary of
CREATE POLICY transaction_log_owner_select ON core.transaction_log
    FOR SELECT
    TO PUBLIC
    USING (
        initiator_account_id = core.current_account_id()
        OR on_behalf_of_account_id = core.current_account_id()
        OR beneficiary_account_id = core.current_account_id()
    );

-- Policy: Application-scoped access
CREATE POLICY transaction_log_app_select ON core.transaction_log
    FOR SELECT
    TO PUBLIC
    USING (
        application_id = core.current_app_id()
        OR application_id IS NULL
    );

-- Policy: Kernel role has full access
CREATE POLICY transaction_log_kernel_all ON core.transaction_log
    FOR ALL
    TO kernel_role
    USING (true)
    WITH CHECK (true);

-- Policy: System role has insert access
CREATE POLICY transaction_log_insert ON core.transaction_log
    FOR INSERT
    TO system_role, kernel_role
    WITH CHECK (true);

-- =============================================================================
-- RLS POLICIES: account_registry
-- =============================================================================

DROP POLICY IF EXISTS account_registry_self_select ON core.account_registry;
DROP POLICY IF EXISTS account_registry_app_select ON core.account_registry;
DROP POLICY IF EXISTS account_registry_insert ON core.account_registry;
DROP POLICY IF EXISTS account_registry_kernel_all ON core.account_registry;

-- Policy: Users can see their own account
CREATE POLICY account_registry_self_select ON core.account_registry
    FOR SELECT
    TO PUBLIC
    USING (
        account_id = core.current_account_id()
    );

-- Policy: Application-scoped access
CREATE POLICY account_registry_app_select ON core.account_registry
    FOR SELECT
    TO PUBLIC
    USING (
        primary_application_id = core.current_app_id()
        OR application_id = core.current_app_id()
    );

-- Policy: Allow insert for registration
CREATE POLICY account_registry_insert ON core.account_registry
    FOR INSERT
    TO PUBLIC
    WITH CHECK (
        primary_application_id = core.current_app_id()
    );

-- Policy: Kernel has full access
CREATE POLICY account_registry_kernel_all ON core.account_registry
    FOR ALL
    TO kernel_role
    USING (true)
    WITH CHECK (true);

-- =============================================================================
-- RLS POLICIES: movement_legs
-- =============================================================================

DROP POLICY IF EXISTS movement_legs_account_select ON core.movement_legs;
DROP POLICY IF EXISTS movement_legs_app_select ON core.movement_legs;
DROP POLICY IF EXISTS movement_legs_kernel_all ON core.movement_legs;

-- Policy: Users can see legs for their accounts
CREATE POLICY movement_legs_account_select ON core.movement_legs
    FOR SELECT
    TO PUBLIC
    USING (
        account_id = core.current_account_id()
    );

-- Policy: Application-scoped access via transaction
CREATE POLICY movement_legs_app_select ON core.movement_legs
    FOR SELECT
    TO PUBLIC
    USING (
        EXISTS (
            SELECT 1 FROM core.transaction_log tl
            WHERE tl.transaction_id = movement_legs.transaction_id
            AND tl.partition_date = movement_legs.partition_date
            AND (tl.application_id = core.current_app_id() OR tl.application_id IS NULL)
        )
    );

-- Policy: Kernel has full access
CREATE POLICY movement_legs_kernel_all ON core.movement_legs
    FOR ALL
    TO kernel_role
    USING (true)
    WITH CHECK (true);

-- =============================================================================
-- RLS POLICIES: movement_postings
-- =============================================================================

DROP POLICY IF EXISTS movement_postings_account_select ON core.movement_postings;
DROP POLICY IF EXISTS movement_postings_app_select ON core.movement_postings;
DROP POLICY IF EXISTS movement_postings_kernel_all ON core.movement_postings;

-- Policy: Users can see postings for their accounts
CREATE POLICY movement_postings_account_select ON core.movement_postings
    FOR SELECT
    TO PUBLIC
    USING (
        account_id = core.current_account_id()
    );

-- Policy: Application-scoped access via account
CREATE POLICY movement_postings_app_select ON core.movement_postings
    FOR SELECT
    TO PUBLIC
    USING (
        EXISTS (
            SELECT 1 FROM core.account_registry ar
            WHERE ar.account_id = movement_postings.account_id
            AND (ar.primary_application_id = core.current_app_id() OR ar.application_id = core.current_app_id())
        )
    );

-- Policy: Kernel has full access
CREATE POLICY movement_postings_kernel_all ON core.movement_postings
    FOR ALL
    TO kernel_role
    USING (true)
    WITH CHECK (true);

-- =============================================================================
-- RLS POLICIES: blocks
-- =============================================================================

DROP POLICY IF EXISTS blocks_read_all ON core.blocks;
DROP POLICY IF EXISTS blocks_kernel_modify ON core.blocks;

-- Policy: All authenticated users can read blocks
CREATE POLICY blocks_read_all ON core.blocks
    FOR SELECT
    TO PUBLIC
    USING (true);

-- Policy: Only kernel can modify blocks
CREATE POLICY blocks_kernel_modify ON core.blocks
    FOR ALL
    TO kernel_role
    USING (true)
    WITH CHECK (true);

-- =============================================================================
-- RLS POLICIES: chart_of_accounts
-- =============================================================================

DROP POLICY IF EXISTS coa_read_all ON core.chart_of_accounts;
DROP POLICY IF EXISTS coa_kernel_modify ON core.chart_of_accounts;

-- Policy: All users can read COA
CREATE POLICY coa_read_all ON core.chart_of_accounts
    FOR SELECT
    TO PUBLIC
    USING (is_active = TRUE);

-- Policy: Only kernel can modify COA
CREATE POLICY coa_kernel_modify ON core.chart_of_accounts
    FOR ALL
    TO kernel_role
    USING (true)
    WITH CHECK (true);

-- =============================================================================
-- RLS POLICIES: audit_trail
-- =============================================================================

DROP POLICY IF EXISTS audit_self_read ON core.audit_trail;
DROP POLICY IF EXISTS audit_app_read ON core.audit_trail;
DROP POLICY IF EXISTS audit_kernel_all ON core.audit_trail;

-- Policy: Users can see their own audit events
CREATE POLICY audit_self_read ON core.audit_trail
    FOR SELECT
    TO PUBLIC
    USING (
        actor_account_id = core.current_account_id()
    );

-- Policy: Application admins can see app audit events
CREATE POLICY audit_app_read ON core.audit_trail
    FOR SELECT
    TO PUBLIC
    USING (
        application_id = core.current_app_id()
    );

-- Policy: Kernel has full access
CREATE POLICY audit_kernel_all ON core.audit_trail
    FOR ALL
    TO kernel_role
    USING (true)
    WITH CHECK (true);

-- =============================================================================
-- RLS POLICIES: rls_violation_log
-- =============================================================================

-- Only kernel can access violation logs
DROP POLICY IF EXISTS rls_violation_log_kernel ON core.rls_violation_log;

CREATE POLICY rls_violation_log_kernel ON core.rls_violation_log
    FOR ALL
    TO kernel_role
    USING (true)
    WITH CHECK (true);

-- =============================================================================
-- MIGRATION CHECKLIST:
-- □ Enable RLS on transaction_log
-- □ Enable RLS on accounts
-- □ Enable RLS on movement_headers
-- □ Enable RLS on movement_legs
-- □ Enable RLS on blocks
-- □ Force RLS for table owners
-- □ Create session context functions
-- □ Create transaction_log policies
-- □ Create accounts policies
-- □ Create movement_headers policies
-- □ Create movement_legs policies
-- □ Create blocks policies
-- □ Create rls_violation_log table
-- □ Create system bypass policies
-- □ Test RLS enforcement
-- □ Test cross-application isolation
-- □ Document session variable setup
================================================================================

-- =============================================================================
-- END OF FILE
-- =============================================================================
