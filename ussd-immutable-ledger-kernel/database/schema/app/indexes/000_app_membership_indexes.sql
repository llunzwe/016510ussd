/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - INDEXES: APP MEMBERSHIP INDEXES
 * =============================================================================
 * 
 * Feature:      CORE-APP-IDX-001
 * Description:  Optimized indexes for application membership queries,
 *               role lookups, and permission checks. Covers common
 *               query patterns for the RBAC system.
 * 
 * Version:      1.0.0
 * Author:       Platform Engineering Team
 * Created:      2026-03-30
 * 
 * DEPENDENCIES:
 *   - app.t_application_registry
 *   - app.t_account_membership
 *   - app.t_roles_permissions
 *   - app.t_user_role_assignments
 *   - app.t_entitlement_limits
 * 
 * PERFORMANCE NOTES:
 *   - Index maintenance overhead considered
 *   - Partial indexes for filtered queries
 *   - GIN indexes for JSONB/array columns
 *   - BRIN indexes for temporal data
 * =============================================================================
 */



-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Controls A.5.x - A.9.x)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Multi-tenancy)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds
-- ISO 9001:2015 - Quality Management Systems
-- ISO 31000:2018 - Risk Management Guidelines
-- ============================================================================
-- CODING PRACTICES:
-- - Use parameterized queries to prevent SQL injection
-- - Implement proper error handling with transaction rollback
-- - Use SECURITY DEFINER
-- - Enforce RLS policies for multi-tenant data isolation
-- - Use explicit column lists (avoid SELECT *)
-- - Add audit logging for all security-relevant operations
-- - Use UUIDs for primary identifiers to prevent enumeration
-- - Implement optimistic locking with version columns
-- - Use TIMESTAMPTZ for all timestamp columns
-- - Validate all inputs with CHECK constraints
-- ============================================================================

-- =============================================================================
-- TABLE: app.t_application_registry
-- =============================================================================

-- TODO: Primary lookups by status (for listing active apps)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_app_registry_status 
--     ON app.t_application_registry(status);

-- TODO: Owner-based lookups (for ownership queries)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_app_registry_owner 
--     ON app.t_application_registry(default_owner_account_id);

-- TODO: Tenant lookups (for RLS and data isolation)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_app_registry_tenant 
--     ON app.t_application_registry(ledger_tenant_id);

-- TODO: Category-based filtering
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_app_registry_category 
--     ON app.t_application_registry(app_category);

-- TODO: Composite for tier-based queries
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_app_registry_tier_status 
--     ON app.t_application_registry(app_tier, status);

-- TODO: Partial index for active apps only (most common query)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_app_registry_active 
--     ON app.t_application_registry(app_code, app_name) 
--     WHERE status = 'active';

-- =============================================================================
-- TABLE: app.t_account_membership
-- =============================================================================

-- TODO: App-based membership lookups (primary query pattern)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_membership_app 
--     ON app.t_account_membership(app_id);

-- TODO: User identity lookups (for finding user's apps)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_membership_user 
--     ON app.t_account_membership(user_identity_id);

-- TODO: Status-based filtering
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_membership_status 
--     ON app.t_account_membership(status);

-- TODO: Composite for active memberships by app
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_membership_app_status 
--     ON app.t_account_membership(app_id, status);

-- TODO: Unique constraint enforcement with NULL handling
-- CREATE UNIQUE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_membership_app_user_unique 
--     ON app.t_account_membership(app_id, user_identity_id) 
--     WHERE status IN ('active', 'pending', 'suspended');

-- TODO: Role-based lookups
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_membership_primary_role 
--     ON app.t_account_membership(primary_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference) 
--     WHERE primary_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference IS NOT NULL;

-- TODO: Invitation token lookups (for acceptance flow)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_membership_invitation 
--     ON app.t_account_membership(invitation_token_hash) 
--     WHERE invitation_token_hash IS NOT NULL;

-- TODO: GIN index for secondary roles array
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_membership_secondary_roles 
--     ON app.t_account_membership USING GIN (secondary_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment references) 
--     WHERE secondary_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment references IS NOT NULL;

-- TODO: Org unit hierarchical lookups
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_membership_org_unit 
--     ON app.t_account_membership(org_unit_id) 
--     WHERE org_unit_id IS NOT NULL;

-- TODO: Self-referential parent lookup
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_membership_parent 
--     ON app.t_account_membership(parent_membership_id) 
--     WHERE parent_membership_id IS NOT NULL;

-- TODO: Pending invitations with expiry (for cleanup jobs)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_membership_pending_expiry 
--     ON app.t_account_membership(invitation_expires_at) 
--     WHERE status = 'pending' AND invitation_expires_at IS NOT NULL;

-- =============================================================================
-- TABLE: app.t_roles_permissions
-- =============================================================================

-- TODO: App-scoped role lookups
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_roles_app 
--     ON app.t_roles_permissions(app_id);

-- TODO: Role type filtering (for UI grouping)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_roles_type 
--     ON app.t_roles_permissions(role_type);

-- TODO: Active roles only (most common query)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_roles_active 
--     ON app.t_roles_permissions(app_id, role_code) 
--     WHERE status = 'active';

-- TODO: System role identification (fast path)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_roles_system 
--     ON app.t_roles_permissions(is_system_role) 
--     WHERE is_system_role = TRUE;

-- TODO: GIN index for permissions JSONB
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_roles_permissions_gin 
--     ON app.t_roles_permissions USING GIN (permissions);

-- TODO: GIN index for allowed resources
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_roles_allowed_resources 
--     ON app.t_roles_permissions USING GIN (allowed_resources);

-- TODO: GIN index for parent roles (inheritance)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_roles_parent_roles 
--     ON app.t_roles_permissions USING GIN (parent_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment references) 
--     WHERE parent_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment references IS NOT NULL;

-- TODO: Scope level filtering
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_roles_scope 
--     ON app.t_roles_permissions(scope_level);

-- =============================================================================
-- TABLE: app.t_user_role_assignments
-- =============================================================================

-- TODO: Primary lookup by membership
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_membership 
--     ON app.t_user_role_assignments(membership_id);

-- TODO: Role-based lookups
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_role 
--     ON app.t_user_role_assignments(role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference);

-- TODO: Composite for active assignments (most important index)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_active 
--     ON app.t_user_role_assignments(membership_id, role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference) 
--     WHERE is_revoked = FALSE AND approval_status = 'approved';

-- TODO: Assignment type filtering
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_type 
--     ON app.t_user_role_assignments(assignment_type  -- [RBAC] ISO 27001: Assignment classification (direct/inherited/delegated));

-- TODO: Temporal validity queries (BRIN for large tables)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_temporal 
--     ON app.t_user_role_assignments USING BRIN (valid_from  -- [RBAC] ISO 27001: Temporal access control boundaries, valid_until  -- [RBAC] ISO 27001: Temporal access control boundaries);

-- TODO: Pending approvals (for admin dashboards)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_pending 
--     ON app.t_user_role_assignments(created_at) 
--     WHERE approval_status = 'pending';

-- TODO: Break-glass identification
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_break_glass 
--     ON app.t_user_role_assignments(break_glass_expires_at) 
--     WHERE is_break_glass  -- [RBAC] ISO 27001: Emergency access indicator = TRUE;

-- TODO: Expired assignments (for cleanup)
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_expired 
--     ON app.t_user_role_assignments(valid_until  -- [RBAC] ISO 27001: Temporal access control boundaries) 
--     WHERE valid_until  -- [RBAC] ISO 27001: Temporal access control boundaries IS NOT NULL AND valid_until  -- [RBAC] ISO 27001: Temporal access control boundaries < NOW() AND is_revoked = FALSE;

-- TODO: Delegation chain lookups
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_delegated 
--     ON app.t_user_role_assignments(delegated_from_assignment_id) 
--     WHERE delegated_from_assignment_id IS NOT NULL;

-- =============================================================================
-- TABLE: app.t_entitlement_limits
-- =============================================================================

-- TODO: Target-based lookups
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_entitlements_target 
--     ON app.t_entitlement_limits(target_type, target_id);

-- TODO: Resource type filtering
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_entitlements_resource 
--     ON app.t_entitlement_limits(resource_type, resource_subtype);

-- TODO: Active effective limits
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_entitlements_active 
--     ON app.t_entitlement_limits(app_id, resource_type, priority) 
--     WHERE status = 'active' 
--       AND effective_from <= NOW() 
--       AND (effective_until IS NULL OR effective_until > NOW());

-- TODO: Window-based queries
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_entitlements_window 
--     ON app.t_entitlement_limits(window_type);

-- =============================================================================
-- TABLE: app.t_feature_flags
-- =============================================================================

-- TODO: Key-based lookups
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_flags_key 
--     ON app.t_feature_flags(app_id, flag_key);

-- TODO: Active flags by state
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_flags_state 
--     ON app.t_feature_flags(app_id, flag_state  -- [FEATURE_FLAG] ISO 9001: Controlled feature state management) 
--     WHERE status = 'active';

-- TODO: Kill switch identification
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_flags_kill_switch 
--     ON app.t_feature_flags(app_id) 
--     WHERE is_kill_switch  -- [FEATURE_FLAG] ISO 27001: Emergency disable switch = TRUE AND status = 'active';

-- =============================================================================
-- TABLE: app.t_configuration_store
-- =============================================================================

-- TODO: Config key lookups with scope resolution
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_config_lookup 
--     ON app.t_configuration_store(app_id, config_key, environment, scope_level, is_current);

-- TODO: Current configs only
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_config_current 
--     ON app.t_configuration_store(app_id, config_key) 
--     WHERE is_current = TRUE;

-- TODO: Encrypted config identification
-- CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_config_encrypted 
--     ON app.t_configuration_store(config_key) 
--     WHERE is_encrypted = TRUE;

-- =============================================================================
-- MAINTENANCE NOTES
-- =============================================================================
-- 1. Use CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation to avoid table locks
-- 2. Monitor index usage with pg_stat_user_indexes
-- 3. Drop unused indexes identified by idx_scan = 0
-- 4. Consider partial indexes for frequently filtered data
-- 5. Reindex periodically during low-traffic windows
-- 6. GIN indexes have slower writes but fast reads
-- =============================================================================

-- =============================================================================
-- TODO: ANALYZE after index creation
-- =============================================================================
-- ANALYZE app.t_application_registry;
-- ANALYZE app.t_account_membership;
-- ANALYZE app.t_roles_permissions;
-- ANALYZE app.t_user_role_assignments;
