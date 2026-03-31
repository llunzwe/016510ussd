-- ============================================================================
-- App Schema - Account Indexes
-- ============================================================================

-- Application registry
CREATE INDEX IF NOT EXISTS idx_app_registry_status ON app.application_registry(status, is_current);
CREATE INDEX IF NOT EXISTS idx_app_registry_tier ON app.application_registry(tier, is_current);

-- Account membership
CREATE INDEX IF NOT EXISTS idx_account_membership_account ON app.account_membership(account_id);
CREATE INDEX IF NOT EXISTS idx_account_membership_app ON app.account_membership(application_id);
CREATE INDEX IF NOT EXISTS idx_account_membership_status ON app.account_membership(status, enrolled_at);

-- Roles and permissions
CREATE INDEX IF NOT EXISTS idx_roles_app ON app.roles_permissions(application_id, is_current);
CREATE INDEX IF NOT EXISTS idx_roles_parent ON app.roles_permissions(parent_role_id);

-- User role assignments
CREATE INDEX IF NOT EXISTS idx_user_roles_membership ON app.user_role_assignments(membership_id, is_current);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON app.user_role_assignments(role_id);
