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

-- Primary lookups by status (for listing active apps)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_app_registry_status 
    ON app.t_application_registry(status);

-- Owner-based lookups (for ownership queries)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_app_registry_owner 
    ON app.t_application_registry(default_owner_account_id);

-- Tenant lookups (for RLS and data isolation)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_app_registry_tenant 
    ON app.t_application_registry(ledger_tenant_id);

-- Category-based filtering
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_app_registry_category 
    ON app.t_application_registry(app_category);

-- Composite for tier-based queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_app_registry_tier_status 
    ON app.t_application_registry(app_tier, status);

-- Partial index for active apps only (most common query)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_app_registry_active 
    ON app.t_application_registry(app_code, app_name) 
    WHERE status = 'active';

-- =============================================================================
-- TABLE: app.t_account_membership
-- =============================================================================

-- App-based membership lookups (primary query pattern)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_membership_app 
    ON app.t_account_membership(app_id);

-- User identity lookups (for finding user's apps)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_membership_user 
    ON app.t_account_membership(user_identity_id);

-- Status-based filtering
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_membership_status 
    ON app.t_account_membership(status);

-- Composite for active memberships by app
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_membership_app_status 
    ON app.t_account_membership(app_id, status);

-- Unique constraint enforcement with NULL handling
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_membership_app_user_unique 
    ON app.t_account_membership(app_id, user_identity_id) 
    WHERE status IN ('active', 'pending', 'suspended');

-- Role-based lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_membership_primary_role 
    ON app.t_account_membership(primary_role_id) 
    WHERE primary_role_id IS NOT NULL;

-- Invitation token lookups (for acceptance flow)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_membership_invitation 
    ON app.t_account_membership(invitation_token_hash) 
    WHERE invitation_token_hash IS NOT NULL;

-- GIN index for secondary roles array
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_membership_secondary_roles 
    ON app.t_account_membership USING GIN (secondary_role_ids) 
    WHERE secondary_role_ids IS NOT NULL;

-- Org unit hierarchical lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_membership_org_unit 
    ON app.t_account_membership(org_unit_id) 
    WHERE org_unit_id IS NOT NULL;

-- Self-referential parent lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_membership_parent 
    ON app.t_account_membership(parent_membership_id) 
    WHERE parent_membership_id IS NOT NULL;

-- Pending invitations with expiry (for cleanup jobs)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_membership_pending_expiry 
    ON app.t_account_membership(invitation_expires_at) 
    WHERE status = 'pending' AND invitation_expires_at IS NOT NULL;

-- =============================================================================
-- TABLE: app.t_roles_permissions
-- =============================================================================

-- App-scoped role lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_roles_app 
    ON app.t_roles_permissions(app_id);

-- Role type filtering (for UI grouping)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_roles_type 
    ON app.t_roles_permissions(role_type);

-- Active roles only (most common query)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_roles_active 
    ON app.t_roles_permissions(app_id, role_code) 
    WHERE status = 'active';

-- System role identification (fast path)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_roles_system 
    ON app.t_roles_permissions(is_system_role) 
    WHERE is_system_role = TRUE;

-- GIN index for permissions JSONB
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_roles_permissions_gin 
    ON app.t_roles_permissions USING GIN (permissions);

-- GIN index for allowed resources
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_roles_allowed_resources 
    ON app.t_roles_permissions USING GIN (allowed_resources);

-- GIN index for parent roles (inheritance)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_roles_parent_roles 
    ON app.t_roles_permissions USING GIN (parent_role_ids) 
    WHERE parent_role_ids IS NOT NULL;

-- Scope level filtering
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_roles_scope 
    ON app.t_roles_permissions(scope_level);

-- =============================================================================
-- TABLE: app.t_user_role_assignments
-- =============================================================================

-- Primary lookup by membership
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assignments_membership 
    ON app.t_user_role_assignments(membership_id);

-- Role-based lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assignments_role 
    ON app.t_user_role_assignments(role_id);

-- Composite for active assignments (most important index)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assignments_active 
    ON app.t_user_role_assignments(membership_id, role_id) 
    WHERE is_revoked = FALSE AND approval_status = 'approved';

-- Assignment type filtering
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assignments_type 
    ON app.t_user_role_assignments(assignment_type);

-- Temporal validity queries (BRIN for large tables)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assignments_temporal 
    ON app.t_user_role_assignments USING BRIN (valid_from, valid_until);

-- Pending approvals (for admin dashboards)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assignments_pending 
    ON app.t_user_role_assignments(created_at) 
    WHERE approval_status = 'pending';

-- Break-glass identification
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assignments_break_glass 
    ON app.t_user_role_assignments(break_glass_expires_at) 
    WHERE is_break_glass = TRUE;

-- Expired assignments (for cleanup)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assignments_expired 
    ON app.t_user_role_assignments(valid_until) 
    WHERE valid_until IS NOT NULL AND valid_until < NOW() AND is_revoked = FALSE;

-- Delegation chain lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assignments_delegated 
    ON app.t_user_role_assignments(delegated_from_assignment_id) 
    WHERE delegated_from_assignment_id IS NOT NULL;

-- =============================================================================
-- TABLE: app.t_entitlement_limits
-- =============================================================================

-- Target-based lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_entitlements_target 
    ON app.t_entitlement_limits(target_type, target_id);

-- Resource type filtering
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_entitlements_resource 
    ON app.t_entitlement_limits(resource_type, resource_subtype);

-- Active effective limits
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_entitlements_active 
    ON app.t_entitlement_limits(app_id, resource_type, priority) 
    WHERE status = 'active' 
      AND effective_from <= NOW() 
      AND (effective_until IS NULL OR effective_until > NOW());

-- Window-based queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_entitlements_window 
    ON app.t_entitlement_limits(window_type);

-- =============================================================================
-- TABLE: app.t_feature_flags
-- =============================================================================

-- Key-based lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_flags_key 
    ON app.t_feature_flags(app_id, flag_key);

-- Active flags by state
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_flags_state 
    ON app.t_feature_flags(app_id, flag_state) 
    WHERE status = 'active';

-- Kill switch identification
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_flags_kill_switch 
    ON app.t_feature_flags(app_id) 
    WHERE is_kill_switch = TRUE AND status = 'active';

-- =============================================================================
-- TABLE: app.t_configuration_store
-- =============================================================================

-- Config key lookups with scope resolution
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_config_lookup 
    ON app.t_configuration_store(app_id, config_key, environment, scope_level, is_current);

-- Current configs only
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_config_current 
    ON app.t_configuration_store(app_id, config_key) 
    WHERE is_current = TRUE;

-- Encrypted config identification
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_config_encrypted 
    ON app.t_configuration_store(config_key) 
    WHERE is_encrypted = TRUE;

-- =============================================================================
-- MAINTENANCE NOTES
-- =============================================================================
-- 1. Use CREATE INDEX CONCURRENTLY to avoid table locks
-- 2. Monitor index usage with pg_stat_user_indexes
-- 3. Drop unused indexes identified by idx_scan = 0
-- 4. Consider partial indexes for frequently filtered data
-- 5. Reindex periodically during low-traffic windows
-- 6. GIN indexes have slower writes but fast reads
-- =============================================================================

-- =============================================================================
-- ANALYZE after index creation
-- =============================================================================
ANALYZE app.t_application_registry;
ANALYZE app.t_account_membership;
ANALYZE app.t_roles_permissions;
ANALYZE app.t_user_role_assignments;
