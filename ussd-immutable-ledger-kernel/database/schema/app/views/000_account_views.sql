-- ============================================================================
-- App Schema - Account Views
-- ============================================================================

-- View: Active applications
CREATE OR REPLACE VIEW app.v_active_applications AS
SELECT 
    application_id,
    application_name,
    description,
    status,
    tier,
    max_users,
    max_transactions_monthly,
    data_retention_days,
    encryption_required,
    mfa_required,
    activated_at,
    valid_from,
    valid_to,
    is_current
FROM app.application_registry
WHERE is_current = TRUE
AND status IN ('ACTIVE', 'PENDING');

COMMENT ON VIEW app.v_active_applications IS 'Currently active applications';

-- View: Application enrollment summary
CREATE OR REPLACE VIEW app.v_enrollment_summary AS
SELECT 
    am.membership_id,
    ar.application_name,
    am.account_id,
    am.status,
    am.enrolled_at,
    am.enrolled_by,
    rp.role_name,
    ura.valid_from AS role_assigned_at
FROM app.account_membership am
JOIN app.application_registry ar ON am.application_id = ar.application_id
LEFT JOIN app.user_role_assignments ura ON am.membership_id = ura.membership_id AND ura.is_current = TRUE
LEFT JOIN app.roles_permissions rp ON ura.role_id = rp.role_id AND rp.is_current = TRUE
WHERE am.status = 'ACTIVE'
AND ar.is_current = TRUE;

COMMENT ON VIEW app.v_enrollment_summary IS 'Summary of account enrollments with roles';

-- View: Current configuration
CREATE OR REPLACE VIEW app.v_current_config AS
SELECT 
    config_id,
    application_id,
    config_key,
    config_value,
    description,
    valid_from,
    changed_by,
    change_reason
FROM app.configuration_store
WHERE is_current = TRUE;

COMMENT ON VIEW app.v_current_config IS 'Current configuration values';

-- View: Feature flags status
CREATE OR REPLACE VIEW app.v_feature_flags AS
SELECT 
    flag_id,
    application_id,
    feature_name,
    enabled,
    rollout_percentage,
    valid_from,
    valid_to,
    is_current
FROM app.feature_flags
WHERE is_current = TRUE;

COMMENT ON VIEW app.v_feature_flags IS 'Current feature flag status';
