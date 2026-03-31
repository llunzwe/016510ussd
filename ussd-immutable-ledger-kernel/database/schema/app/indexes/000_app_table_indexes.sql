/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - INDEXES: APP TABLE INDEXES
 * =============================================================================
 * 
 * Feature:      CORE-APP-IDX-002
 * Description:  Comprehensive indexes for application schema tables.
 *               Optimized for multi-tenant queries, RBAC lookups,
 *               and audit trail performance.
 * 
 * Version:      1.0.0
 * Author:       Eng. llunzwe
 * Created:      2026-03-30
 * Last Modified: 2026-03-30
 * 
 * =============================================================================
 * COMPLIANCE & CERTIFICATIONS
 * =============================================================================
 * 
 * ISO/IEC 27001:2022 (ISMS)
 *   - Control A.5.15: Access control optimization
 *   - Control A.8.15: Audit log performance
 * 
 * ISO 9001:2015 (Quality Management)
 *   - Section 7.1.5: Monitoring and measuring resources
 * 
 * SOC 2 Type II
 *   - CC7.2: System monitoring performance
 * 
 * =============================================================================
 * INDEXING STRATEGY
 * =============================================================================
 * 
 * B-TREE INDEXES:
 *   - Primary keys and foreign keys
 *   - Equality and range queries
 *   - Sorting and ordering
 * 
 * GIN INDEXES:
 *   - JSONB columns for flexible queries
 *   - Array columns for membership lookups
 *   - Full-text search preparation
 * 
 * PARTIAL INDEXES:
 *   - Active records only (most common query)
 *   - Reduced index size and maintenance
 *   - Improved query performance
 * 
 * BRIN INDEXES:
 *   - Large temporal tables
 *   - Naturally ordered data
 *   - Low storage overhead
 * 
 * COMPOSITE INDEXES:
 *   - Multi-column lookups
 *   - Covering indexes for common queries
 * =============================================================================
 */

-- =============================================================================
-- COMPLIANCE STANDARDS
-- =============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework
-- ISO 9001:2015 - Quality Management Systems
-- SOC 2 Type II - Security Controls
-- =============================================================================

-- =============================================================================
-- TABLE: app.t_application_registry
-- =============================================================================

-- Primary lookups by status (active app listings)
CREATE INDEX IF NOT EXISTS idx_app_registry_status 
    ON app.t_application_registry(status) 
    WHERE deleted_at IS NULL;

-- Code-based lookups (API authentication)
CREATE INDEX IF NOT EXISTS idx_app_registry_code 
    ON app.t_application_registry(app_code) 
    WHERE deleted_at IS NULL;

-- Tenant lookups (RLS enforcement)
CREATE INDEX IF NOT EXISTS idx_app_registry_tenant 
    ON app.t_application_registry(ledger_tenant_id) 
    WHERE deleted_at IS NULL;

-- Owner-based lookups
CREATE INDEX IF NOT EXISTS idx_app_registry_owner 
    ON app.t_application_registry(default_owner_account_id) 
    WHERE deleted_at IS NULL;

-- Category filtering
CREATE INDEX IF NOT EXISTS idx_app_registry_category 
    ON app.t_application_registry(app_category) 
    WHERE deleted_at IS NULL;

-- Composite: Tier + Status (dashboard queries)
CREATE INDEX IF NOT EXISTS idx_app_registry_tier_status 
    ON app.t_application_registry(app_tier, status) 
    WHERE deleted_at IS NULL;

-- Partial: Active apps only (most common query pattern)
CREATE INDEX IF NOT EXISTS idx_app_registry_active 
    ON app.t_application_registry(app_code, app_name) 
    WHERE status = 'active' AND deleted_at IS NULL;

-- Activation date (reporting)
CREATE INDEX IF NOT EXISTS idx_app_registry_activated 
    ON app.t_application_registry(activated_at DESC NULLS LAST) 
    WHERE activated_at IS NOT NULL;

-- GIN index for metadata JSONB
CREATE INDEX IF NOT EXISTS idx_app_registry_metadata 
    ON app.t_application_registry USING GIN (metadata) 
    WHERE deleted_at IS NULL;

-- Soft delete filtering
CREATE INDEX IF NOT EXISTS idx_app_registry_not_deleted 
    ON app.t_application_registry(created_at) 
    WHERE deleted_at IS NULL;

-- =============================================================================
-- TABLE: app.t_account_membership
-- =============================================================================

-- App-based membership lookups (primary query pattern)
CREATE INDEX IF NOT EXISTS idx_membership_app 
    ON app.t_account_membership(app_id) 
    WHERE deleted_at IS NULL;

-- User identity lookups (user's app listing)
CREATE INDEX IF NOT EXISTS idx_membership_user 
    ON app.t_account_membership(user_identity_id) 
    WHERE deleted_at IS NULL;

-- Status-based filtering
CREATE INDEX IF NOT EXISTS idx_membership_status 
    ON app.t_account_membership(status) 
    WHERE deleted_at IS NULL;

-- Composite: App + Status (active members listing)
CREATE INDEX IF NOT EXISTS idx_membership_app_status 
    ON app.t_account_membership(app_id, status) 
    WHERE deleted_at IS NULL;

-- Unique: Active memberships per app+user
CREATE UNIQUE INDEX IF NOT EXISTS idx_membership_app_user_active 
    ON app.t_account_membership(app_id, user_identity_id) 
    WHERE status IN ('active', 'pending', 'suspended') AND deleted_at IS NULL;

-- Membership type filtering
CREATE INDEX IF NOT EXISTS idx_membership_type 
    ON app.t_account_membership(membership_type) 
    WHERE deleted_at IS NULL;

-- Role-based lookups
CREATE INDEX IF NOT EXISTS idx_membership_primary_role 
    ON app.t_account_membership(primary_role_id) 
    WHERE primary_role_id IS NOT NULL AND deleted_at IS NULL;

-- GIN index for secondary roles array
CREATE INDEX IF NOT EXISTS idx_membership_secondary_roles 
    ON app.t_account_membership USING GIN (secondary_role_ids) 
    WHERE secondary_role_ids IS NOT NULL AND deleted_at IS NULL;

-- Org unit hierarchical lookups
CREATE INDEX IF NOT EXISTS idx_membership_org_unit 
    ON app.t_account_membership(org_unit_id) 
    WHERE org_unit_id IS NOT NULL AND deleted_at IS NULL;

-- Parent membership (delegation chains)
CREATE INDEX IF NOT EXISTS idx_membership_parent 
    ON app.t_account_membership(parent_membership_id) 
    WHERE parent_membership_id IS NOT NULL AND deleted_at IS NULL;

-- Hierarchy level
CREATE INDEX IF NOT EXISTS idx_membership_hierarchy_level 
    ON app.t_account_membership(hierarchy_level) 
    WHERE deleted_at IS NULL;

-- Invitation token lookups
CREATE INDEX IF NOT EXISTS idx_membership_invitation 
    ON app.t_account_membership(invitation_token_hash) 
    WHERE invitation_token_hash IS NOT NULL AND deleted_at IS NULL;

-- Pending invitations with expiry (cleanup jobs)
CREATE INDEX IF NOT EXISTS idx_membership_pending_expiry 
    ON app.t_account_membership(invitation_expires_at) 
    WHERE status = 'pending' 
      AND invitation_expires_at IS NOT NULL 
      AND deleted_at IS NULL;

-- Joined date (reporting)
CREATE INDEX IF NOT EXISTS idx_membership_joined 
    ON app.t_account_membership(joined_at DESC NULLS LAST) 
    WHERE joined_at IS NOT NULL AND deleted_at IS NULL;

-- GIN index for custom permissions JSONB
CREATE INDEX IF NOT EXISTS idx_membership_custom_perms 
    ON app.t_account_membership USING GIN (custom_permissions) 
    WHERE custom_permissions IS NOT NULL AND deleted_at IS NULL;

-- Soft delete
CREATE INDEX IF NOT EXISTS idx_membership_deleted 
    ON app.t_account_membership(deleted_at) 
    WHERE deleted_at IS NOT NULL;

-- =============================================================================
-- TABLE: app.t_roles_permissions
-- =============================================================================

-- App-scoped role lookups
CREATE INDEX IF NOT EXISTS idx_roles_app 
    ON app.t_roles_permissions(app_id) 
    WHERE deleted_at IS NULL;

-- Role code lookups
CREATE INDEX IF NOT EXISTS idx_roles_code 
    ON app.t_roles_permissions(role_code) 
    WHERE deleted_at IS NULL;

-- Role type filtering
CREATE INDEX IF NOT EXISTS idx_roles_type 
    ON app.t_roles_permissions(role_type) 
    WHERE deleted_at IS NULL;

-- Status filtering (active roles)
CREATE INDEX IF NOT EXISTS idx_roles_status 
    ON app.t_roles_permissions(status) 
    WHERE deleted_at IS NULL;

-- Composite: App + Code (role lookups)
CREATE INDEX IF NOT EXISTS idx_roles_app_code 
    ON app.t_roles_permissions(app_id, role_code) 
    WHERE status = 'active' AND deleted_at IS NULL;

-- System role identification
CREATE INDEX IF NOT EXISTS idx_roles_system 
    ON app.t_roles_permissions(is_system_role) 
    WHERE is_system_role = TRUE AND deleted_at IS NULL;

-- GIN index for permissions JSONB
CREATE INDEX IF NOT EXISTS idx_roles_permissions_gin 
    ON app.t_roles_permissions USING GIN (permissions) 
    WHERE deleted_at IS NULL;

-- GIN index for allowed resources array
CREATE INDEX IF NOT EXISTS idx_roles_allowed_resources 
    ON app.t_roles_permissions USING GIN (allowed_resources) 
    WHERE deleted_at IS NULL;

-- GIN index for denied resources array
CREATE INDEX IF NOT EXISTS idx_roles_denied_resources 
    ON app.t_roles_permissions USING GIN (denied_resources) 
    WHERE deleted_at IS NULL;

-- GIN index for parent roles (inheritance)
CREATE INDEX IF NOT EXISTS idx_roles_parent_roles 
    ON app.t_roles_permissions USING GIN (parent_role_ids) 
    WHERE parent_role_ids IS NOT NULL AND deleted_at IS NULL;

-- GIN index for entitlement limits JSONB
CREATE INDEX IF NOT EXISTS idx_roles_entitlements 
    ON app.t_roles_permissions USING GIN (entitlement_limits) 
    WHERE deleted_at IS NULL;

-- Scope level filtering
CREATE INDEX IF NOT EXISTS idx_roles_scope 
    ON app.t_roles_permissions(scope_level) 
    WHERE deleted_at IS NULL;

-- Applicable membership types array
CREATE INDEX IF NOT EXISTS idx_roles_membership_types 
    ON app.t_roles_permissions USING GIN (applicable_membership_types) 
    WHERE deleted_at IS NULL;

-- =============================================================================
-- TABLE: app.t_user_role_assignments
-- =============================================================================

-- Primary lookup by membership
CREATE INDEX IF NOT EXISTS idx_assignments_membership 
    ON app.t_user_role_assignments(membership_id) 
    WHERE deleted_at IS NULL;

-- Role-based lookups
CREATE INDEX IF NOT EXISTS idx_assignments_role 
    ON app.t_user_role_assignments(role_id) 
    WHERE deleted_at IS NULL;

-- Composite: Membership + Role (active assignments)
CREATE INDEX IF NOT EXISTS idx_assignments_membership_role 
    ON app.t_user_role_assignments(membership_id, role_id) 
    WHERE is_revoked = FALSE AND deleted_at IS NULL;

-- Active assignments (most important index for permission checks)
CREATE INDEX IF NOT EXISTS idx_assignments_active 
    ON app.t_user_role_assignments(membership_id, role_id) 
    WHERE is_revoked = FALSE 
      AND approval_status = 'approved' 
      AND deleted_at IS NULL;

-- Assignment type filtering
CREATE INDEX IF NOT EXISTS idx_assignments_type 
    ON app.t_user_role_assignments(assignment_type) 
    WHERE deleted_at IS NULL;

-- Assignment source
CREATE INDEX IF NOT EXISTS idx_assignments_source 
    ON app.t_user_role_assignments(assignment_source) 
    WHERE deleted_at IS NULL;

-- Temporal validity (BRIN for large tables)
CREATE INDEX IF NOT EXISTS idx_assignments_valid_from 
    ON app.t_user_role_assignments USING BRIN (valid_from) 
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_assignments_valid_until 
    ON app.t_user_role_assignments(valid_until) 
    WHERE valid_until IS NOT NULL AND deleted_at IS NULL;

-- Pending approvals
CREATE INDEX IF NOT EXISTS idx_assignments_pending 
    ON app.t_user_role_assignments(created_at) 
    WHERE approval_status = 'pending' AND deleted_at IS NULL;

-- Break-glass identification
CREATE INDEX IF NOT EXISTS idx_assignments_break_glass 
    ON app.t_user_role_assignments(break_glass_expires_at) 
    WHERE is_break_glass = TRUE AND deleted_at IS NULL;

-- Expired assignments cleanup
CREATE INDEX IF NOT EXISTS idx_assignments_expired 
    ON app.t_user_role_assignments(valid_until) 
    WHERE valid_until < NOW() 
      AND is_revoked = FALSE 
      AND deleted_at IS NULL;

-- Delegation chain lookups
CREATE INDEX IF NOT EXISTS idx_assignments_delegated 
    ON app.t_user_role_assignments(delegated_from_assignment_id) 
    WHERE delegated_from_assignment_id IS NOT NULL AND deleted_at IS NULL;

-- GIN index for resource scope JSONB
CREATE INDEX IF NOT EXISTS idx_assignments_resource_scope 
    ON app.t_user_role_assignments USING GIN (resource_scope) 
    WHERE resource_scope IS NOT NULL AND deleted_at IS NULL;

-- GIN index for delegation constraints JSONB
CREATE INDEX IF NOT EXISTS idx_assignments_constraints 
    ON app.t_user_role_assignments USING GIN (delegation_constraints) 
    WHERE delegation_constraints IS NOT NULL AND deleted_at IS NULL;

-- Approval tracking
CREATE INDEX IF NOT EXISTS idx_assignments_approved_by 
    ON app.t_user_role_assignments(approved_by) 
    WHERE approved_by IS NOT NULL AND deleted_at IS NULL;

-- Revocation tracking
CREATE INDEX IF NOT EXISTS idx_assignments_revoked 
    ON app.t_user_role_assignments(revoked_at) 
    WHERE is_revoked = TRUE AND deleted_at IS NULL;

-- =============================================================================
-- TABLE: app.t_entitlement_limits
-- =============================================================================

-- App-based lookups
CREATE INDEX IF NOT EXISTS idx_entitlements_app 
    ON app.t_entitlement_limits(app_id) 
    WHERE status = 'active';

-- Target-based lookups (polymorphic)
CREATE INDEX IF NOT EXISTS idx_entitlements_target 
    ON app.t_entitlement_limits(target_type, target_id) 
    WHERE status = 'active';

-- Resource type filtering
CREATE INDEX IF NOT EXISTS idx_entitlements_resource 
    ON app.t_entitlement_limits(resource_type, resource_subtype) 
    WHERE status = 'active';

-- Active effective limits (highest priority)
CREATE INDEX IF NOT EXISTS idx_entitlements_active 
    ON app.t_entitlement_limits(app_id, resource_type, priority) 
    WHERE status = 'active' 
      AND effective_from <= NOW() 
      AND (effective_until IS NULL OR effective_until > NOW());

-- Window-based queries
CREATE INDEX IF NOT EXISTS idx_entitlements_window 
    ON app.t_entitlement_limits(window_type) 
    WHERE status = 'active';

-- Override tracking
CREATE INDEX IF NOT EXISTS idx_entitlements_override 
    ON app.t_entitlement_limits(override_expires_at) 
    WHERE override_value IS NOT NULL;

-- Usage reset tracking
CREATE INDEX IF NOT EXISTS idx_entitlements_usage_reset 
    ON app.t_entitlement_limits(usage_reset_at) 
    WHERE status = 'active';

-- =============================================================================
-- TABLE: app.t_configuration_store
-- =============================================================================

-- App + Key lookups (primary access pattern)
CREATE INDEX IF NOT EXISTS idx_config_app_key 
    ON app.t_configuration_store(app_id, config_key, environment) 
    WHERE is_current = TRUE;

-- Environment filtering
CREATE INDEX IF NOT EXISTS idx_config_environment 
    ON app.t_configuration_store(environment) 
    WHERE is_current = TRUE;

-- Scope-based lookups
CREATE INDEX IF NOT EXISTS idx_config_scope 
    ON app.t_configuration_store(scope_level, scope_id) 
    WHERE is_current = TRUE;

-- Current configs only
CREATE INDEX IF NOT EXISTS idx_config_current 
    ON app.t_configuration_store(app_id, config_key) 
    WHERE is_current = TRUE;

-- Encrypted config identification
CREATE INDEX IF NOT EXISTS idx_config_encrypted 
    ON app.t_configuration_store(config_key) 
    WHERE is_encrypted = TRUE AND is_current = TRUE;

-- Effective period
CREATE INDEX IF NOT EXISTS idx_config_effective 
    ON app.t_configuration_store(effective_from, effective_until) 
    WHERE is_current = TRUE;

-- =============================================================================
-- TABLE: app.t_feature_flags
-- =============================================================================

-- App + Key lookups
CREATE INDEX IF NOT EXISTS idx_flags_app_key 
    ON app.t_feature_flags(app_id, flag_key) 
    WHERE status = 'active';

-- Flag state filtering
CREATE INDEX IF NOT EXISTS idx_flags_state 
    ON app.t_feature_flags(app_id, flag_state) 
    WHERE status = 'active';

-- Kill switch identification
CREATE INDEX IF NOT EXISTS idx_flags_kill_switch 
    ON app.t_feature_flags(app_id) 
    WHERE is_kill_switch = TRUE AND status = 'active';

-- Gradual rollout filtering
CREATE INDEX IF NOT EXISTS idx_flags_gradual 
    ON app.t_feature_flags(rollout_percentage) 
    WHERE flag_state = 'gradual' AND status = 'active';

-- =============================================================================
-- MAINTENANCE NOTES
-- =============================================================================
-- 1. Use REINDEX CONCURRENTLY for maintenance
-- 2. Monitor index usage with pg_stat_user_indexes
-- 3. Drop unused indexes (idx_scan = 0 after sufficient time)
-- 4. Consider partial indexes for high-cardinality filters
-- 5. BRIN indexes require naturally ordered data
-- 6. GIN indexes benefit from fastupdate = off for bulk loads
-- =============================================================================

-- =============================================================================
-- ANALYZE after index creation
-- =============================================================================
ANALYZE app.t_application_registry;
ANALYZE app.t_account_membership;
ANALYZE app.t_roles_permissions;
ANALYZE app.t_user_role_assignments;
ANALYZE app.t_entitlement_limits;
ANALYZE app.t_configuration_store;
ANALYZE app.t_feature_flags;
