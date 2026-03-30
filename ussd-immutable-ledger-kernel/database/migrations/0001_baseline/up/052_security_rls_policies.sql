-- =============================================================================
-- MIGRATION: 052_security_rls_policies.sql
-- DESCRIPTION: Row-Level Security Policies
-- TABLES: rls_policies, policy_applications
-- DEPENDENCIES: Multiple tables for RLS
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.5.15: Access control
  - A.5.18: Access rights
  - A.8.2: Privileged access rights
  - A.8.3: Information access restriction
  - A.9.4: Access to source code

ISO/IEC 27018:2019 - Protection of PII in Public Clouds
  - Clause 8.1: Return, transfer, and disposal of PII
  - Clause 9.1: Customer participation (tenant isolation)

ISO/IEC 27050-3:2020 - Electronic Discovery
  - Section 6: Preservation scope controlled via RLS

GDPR / Zimbabwe Data Protection Act (Chapter 11:12)
  - Article 32: Security of processing (access control)
  - Section 14: Security measures
  - Principle of least privilege
  - Data minimization per access

SECURITY CLASSIFICATION: CONFIDENTIAL
DATA SENSITIVITY: ACCESS CONTROL POLICIES
RETENTION PERIOD: Policy versions permanent; Enforcement logs 7 years
AUDIT REQUIREMENT: All policy changes logged; Access denials logged
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 6. Entitlements & Access Control / 5. Security & Access Control
- Feature: Row-Level Security (RLS)
- Source: adkjfnwr.md

BUSINESS CONTEXT:
PostgreSQL RLS policies ensure that users can only access transactions and
accounts for applications they are authorized for. A transport app user
cannot see health app transactions.

KEY FEATURES:
- Tenant isolation by application_id
- Account-based access control
- Role-based filtering
- Session-based enforcement
- Bypass for admin roles

SECURITY PRINCIPLES:
- Default deny: No access without explicit policy
- Least privilege: Minimum necessary access
- Defense in depth: RLS + application checks
- Audit everything: All access attempts logged
================================================================================
*/

-- =============================================================================
-- TODO: Create RLS policy configuration table
-- DESCRIPTION: RLS policy definitions
-- PRIORITY: HIGH
-- SECURITY: Restricted to security administrators
-- AUDIT: All policy changes logged
-- =============================================================================
-- TODO: [RLS-001] Create security.rls_policies table
-- INSTRUCTIONS:
--   - Document RLS policy configuration
--   - For audit and management
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE security.rls_policies (
--       policy_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Target
--       table_schema        VARCHAR(50) NOT NULL,
--       table_name          VARCHAR(100) NOT NULL,
--       
--       -- Policy Details
--       policy_name         VARCHAR(100) NOT NULL,
--       policy_type         VARCHAR(20) NOT NULL,        -- SELECT, INSERT, UPDATE, DELETE
--       
--       -- Expression
--       using_expression    TEXT NOT NULL,               -- USING clause
--       with_check_expression TEXT,                      -- WITH CHECK clause
--       
--       -- Roles
--       applies_to_roles    VARCHAR(100)[],              -- NULL = all roles
--       
--       -- Status
--       is_active           BOOLEAN DEFAULT true,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Enable RLS on core tables
-- DESCRIPTION: Activate row-level security
-- PRIORITY: CRITICAL
-- SECURITY: FORCE RLS for all users including table owners
-- AUDIT: Log RLS enablement events
-- =============================================================================
-- TODO: [RLS-002] Enable RLS on tables
-- INSTRUCTIONS:
--   ALTER TABLE core.transaction_log ENABLE ROW LEVEL SECURITY;
--   ALTER TABLE core.accounts ENABLE ROW LEVEL SECURITY;
--   ALTER TABLE core.movement_headers ENABLE ROW LEVEL SECURITY;
--   ALTER TABLE core.movement_legs ENABLE ROW LEVEL SECURITY;
--   -- etc.

-- =============================================================================
-- TODO: Create application isolation policies
-- DESCRIPTION: Tenant isolation by application
-- PRIORITY: CRITICAL
-- SECURITY: STRICT - users cannot access other tenants' data
-- PRIVACY: Enforces data segregation per controller
-- =============================================================================
-- TODO: [RLS-003] Create application isolation policies
-- INSTRUCTIONS:
--   -- Policy: Users can only see their application's transactions
--   CREATE POLICY transaction_application_isolation ON core.transaction_log
--       FOR SELECT
--       USING (application_id = current_setting('app.current_application_id')::UUID);
--   
--   -- Policy: Users can only see accounts they have access to
--   CREATE POLICY account_access_policy ON core.accounts
--       FOR SELECT
--       USING (
--           EXISTS (
--               SELECT 1 FROM app.current_memberships
--               WHERE account_id = accounts.account_id
--           )
--           OR current_setting('app.is_admin')::BOOLEAN = true
--       );

-- =============================================================================
-- TODO: Create account-based access policies
-- DESCRIPTION: Limit access to specific accounts
-- PRIORITY: HIGH
-- SECURITY: Membership-based access verification
-- =============================================================================
-- TODO: [RLS-004] Create account-based policies
-- INSTRUCTIONS:
--   -- Movement access limited to account participants
--   CREATE POLICY movement_account_access ON core.movement_legs
--       FOR SELECT
--       USING (
--           account_id IN (
--               SELECT account_id FROM app.current_memberships
--               WHERE account_id = movement_legs.account_id
--           )
--           OR current_setting('app.is_admin')::BOOLEAN = true
--       );

-- =============================================================================
-- TODO: Create admin bypass policies
-- DESCRIPTION: Allow admin override
-- PRIORITY: HIGH
-- SECURITY: Admin role tightly controlled; all actions audited
-- PRIVACY: Admin access logged for compliance review
-- =============================================================================
-- TODO: [RLS-005] Create admin bypass policies
-- INSTRUCTIONS:
--   -- Admin can see all data
--   CREATE POLICY admin_all_access ON core.transaction_log
--       FOR ALL
--       TO admin_role
--       USING (true);

-- =============================================================================
-- TODO: Create RLS helper functions
-- DESCRIPTION: Support RLS evaluation
-- PRIORITY: HIGH
-- SECURITY: SECURITY DEFINER; validates permissions
-- PERFORMANCE: STABLE for query optimization
-- =============================================================================
-- TODO: [RLS-006] Create RLS helper functions
-- INSTRUCTIONS:
--   -- Get current user's accessible applications
--   CREATE OR REPLACE FUNCTION security.get_user_applications()
--   RETURNS UUID[] AS $$
--   BEGIN
--       RETURN (
--           SELECT ARRAY_AGG(DISTINCT application_id)
--           FROM app.current_memberships
--           WHERE account_id = current_setting('app.current_account_id')::UUID
--       );
--   END;
--   $$ LANGUAGE plpgsql STABLE SECURITY DEFINER;
--   
--   -- Check if user has access to account
--   CREATE OR REPLACE FUNCTION security.has_account_access(p_account_id UUID)
--   RETURNS BOOLEAN AS $$
--   BEGIN
--       RETURN EXISTS (
--           SELECT 1 FROM app.current_memberships
--           WHERE account_id = p_account_id
--       ) OR current_setting('app.is_admin')::BOOLEAN = true;
--   END;
--   $$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- =============================================================================
-- TODO: Force RLS for table owners
-- DESCRIPTION: Ensure RLS applies to all users
-- PRIORITY: CRITICAL
-- SECURITY: Prevents owner bypass
-- =============================================================================
-- TODO: [RLS-007] Force RLS for owners
-- INSTRUCTIONS:
--   ALTER TABLE core.transaction_log FORCE ROW LEVEL SECURITY;
--   ALTER TABLE core.accounts FORCE ROW LEVEL SECURITY;
--   ALTER TABLE core.movement_headers FORCE ROW LEVEL SECURITY;

/*
================================================================================
ROW-LEVEL SECURITY IMPLEMENTATION GUIDE
================================================================================

1. RLS POLICY ARCHITECTURE:
   ┌─────────────────────────────────────────────────────────────────────────┐
   │ Layer                    │ Policy Type      │ Scope                    │
   ├─────────────────────────────────────────────────────────────────────────┤
   │ 1. Application Isolation │ Mandatory        │ All multi-tenant tables  │
   │ 2. Account Access        │ Membership-based │ Account-related data     │
   │ 3. Role-Based            │ Role-specific    │ Administrative functions │
   │ 4. Time-Based            │ Temporal         │ Historical data access   │
   │ 5. Admin Bypass          │ Elevated         │ Emergency/support access │
   └─────────────────────────────────────────────────────────────────────────┘

2. POLICY EVALUATION ORDER:
   a. Session context variables set on connection
   b. RLS policies evaluated for each query
   c. Multiple policies combined with OR
   d. Explicit deny overrides implicit allow
   e. Admin bypass only if role matches

3. SECURITY CONTEXT VARIABLES:
   - app.current_user_id: Authenticated user UUID
   - app.current_account_id: Primary account context
   - app.current_application_id: Tenant context
   - app.current_role: Role for permission checks
   - app.is_admin: Boolean admin flag
   - app.session_id: Current session for audit

4. PERFORMANCE OPTIMIZATION:
   - Index on columns used in RLS predicates
   - SECURITY DEFINER functions for complex checks
   - Materialized views for membership lists
   - Query plan analysis for policy overhead

5. AUDIT REQUIREMENTS:
   - Policy changes: Who, when, before/after
   - Policy violations: Denied access attempts
   - Admin bypass: All elevated access logged
   - Performance: Slow policy evaluation alerts

PRIVACY BY DESIGN:
- RLS enforces data minimization automatically
- Users only see their own data
- Cross-tenant queries impossible
- Admin access requires explicit privilege

COMPLIANCE MAPPING:
- ISO 27001 A.9.4: System access control
- GDPR Article 32: Security of processing
- Data Protection Act Section 14: Security measures
- SOX: Financial data segregation
================================================================================
*/

/*
================================================================================
MIGRATION CHECKLIST:
□ Create security.rls_policies documentation table
□ Enable RLS on all tenant-scoped tables
□ Create application isolation policies
□ Create account-based access policies
□ Create admin bypass policies
□ Implement RLS helper functions
□ Force RLS for table owners
□ Test policy enforcement
□ Test admin bypass
□ Verify tenant isolation
□ Document security context variables
□ Set up policy violation monitoring
□ Test performance impact
================================================================================
*/
