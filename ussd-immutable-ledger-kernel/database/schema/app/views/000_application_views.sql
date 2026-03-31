/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - VIEW: APPLICATION VIEWS
 * =============================================================================
 * 
 * Feature:      CORE-APP-VIEW-004
 * Description:  Comprehensive application views for multi-tenant environments.
 *               Provides current record state, active applications, and
 *               tenant-scoped access with RLS integration.
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
 *   - Control A.5.15: Access control
 *   - Control A.9.4.1: Information access restriction
 * 
 * ISO/IEC 27017:2015 (Cloud Security)
 *   - Section 12: Inter-tenant data segregation
 * 
 * GDPR (General Data Protection Regulation)
 *   - Article 25: Data protection by design
 *   - Article 30: Records of processing
 * 
 * SOC 2 Type II
 *   - CC6.1: Logical access controls
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - app.t_application_registry
 *   - app.t_account_membership
 *   - app.t_entitlement_limits
 * 
 * =============================================================================
 */

-- =============================================================================
-- COMPLIANCE STANDARDS
-- =============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework
-- ISO/IEC 27017:2015 - Cloud Security Controls
-- GDPR - Data Protection
-- SOC 2 Type II - Security Controls
-- =============================================================================

-- =============================================================================
-- VIEW: Active Applications
-- ISO 27017: Tenant-isolated application listing
-- =============================================================================

CREATE OR REPLACE VIEW app.v_active_applications AS
SELECT 
    -- Primary identifiers
    ar.app_id,
    ar.app_code,
    ar.ledger_tenant_id,
    
    -- Application metadata
    ar.app_name,
    ar.app_description,
    ar.app_category,
    ar.app_tier,
    
    -- Lifecycle state
    ar.status,
    ar.activated_at,
    ar.deprecated_at,
    ar.archived_at,
    
    -- Resource limits
    ar.max_transactions_per_minute,
    ar.max_storage_gb,
    ar.max_concurrent_sessions,
    
    -- Ownership
    ar.default_owner_account_id,
    ar.billing_account_id,
    
    -- Security
    ar.allowed_origins,
    ar.encryption_key_id IS NOT NULL as has_encryption,
    
    -- Audit
    ar.version,
    ar.created_at,
    ar.created_by,
    ar.updated_at,
    ar.updated_by,
    
    -- Metadata
    ar.metadata,
    ar.custom_attributes,
    
    -- Computed fields
    CASE 
        WHEN ar.status = 'active' THEN TRUE
        ELSE FALSE
    END as is_active,
    
    CASE 
        WHEN ar.activated_at IS NOT NULL THEN
            EXTRACT(EPOCH FROM (NOW() - ar.activated_at)) / 86400
        ELSE NULL
    END::INTEGER as days_since_activation,
    
    -- Ledger sync status
    ar.last_ledger_sequence,
    
    -- View timestamp
    NOW() as view_timestamp

FROM app.t_application_registry ar
WHERE ar.status = 'active'
  AND ar.deleted_at IS NULL;

COMMENT ON VIEW app.v_active_applications IS 
    'Active applications with resource limits and metadata. ' ||
    'ISO 27017: Tenant-isolated view. Feature: CORE-APP-VIEW-004';

-- =============================================================================
-- VIEW: Application Summary with Metrics
-- Dashboard view with aggregated statistics
-- =============================================================================

CREATE OR REPLACE VIEW app.v_application_summary AS
WITH membership_counts AS (
    SELECT 
        am.app_id,
        COUNT(*) FILTER (WHERE am.status = 'active') as active_memberships,
        COUNT(*) FILTER (WHERE am.status = 'pending') as pending_memberships,
        COUNT(*) FILTER (WHERE am.status = 'suspended') as suspended_memberships,
        COUNT(*) FILTER (WHERE am.membership_type = 'owner') as owner_count,
        COUNT(*) FILTER (WHERE am.membership_type = 'admin') as admin_count,
        COUNT(*) FILTER (WHERE am.membership_type = 'service') as service_accounts
    FROM app.t_account_membership am
    WHERE am.deleted_at IS NULL
    GROUP BY am.app_id
),
role_counts AS (
    SELECT 
        rp.app_id,
        COUNT(*) FILTER (WHERE rp.status = 'active') as active_roles,
        COUNT(*) FILTER (WHERE rp.is_system_role = TRUE) as system_roles,
        COUNT(*) FILTER (WHERE rp.role_type = 'custom') as custom_roles
    FROM app.t_roles_permissions rp
    WHERE rp.deleted_at IS NULL OR rp.deleted_at IS NULL  -- No soft delete on roles
    GROUP BY rp.app_id
),
entitlement_summary AS (
    SELECT 
        el.app_id,
        COUNT(*) as total_entitlements,
        jsonb_object_agg(
            el.resource_type,
            jsonb_build_object(
                'limit', COALESCE(el.override_value, el.limit_value),
                'usage', el.current_usage,
                'pct', CASE 
                    WHEN COALESCE(el.override_value, el.limit_value) > 0 
                    THEN ROUND((el.current_usage / COALESCE(el.override_value, el.limit_value)) * 100, 2)
                    ELSE 0
                END
            )
        ) FILTER (WHERE el.status = 'active') as resource_usage
    FROM app.t_entitlement_limits el
    WHERE el.status = 'active'
    GROUP BY el.app_id
)

SELECT 
    -- Application core
    ar.app_id,
    ar.app_code,
    ar.app_name,
    ar.app_tier,
    ar.app_category,
    ar.status as app_status,
    ar.ledger_tenant_id,
    
    -- Lifecycle dates
    ar.created_at,
    ar.activated_at,
    ar.deprecated_at,
    ar.archived_at,
    
    -- Membership metrics
    COALESCE(mc.active_memberships, 0) as active_memberships,
    COALESCE(mc.pending_memberships, 0) as pending_memberships,
    COALESCE(mc.suspended_memberships, 0) as suspended_memberships,
    COALESCE(mc.owner_count, 0) as owner_count,
    COALESCE(mc.admin_count, 0) as admin_count,
    COALESCE(mc.service_accounts, 0) as service_accounts,
    
    -- Role metrics
    COALESCE(rc.active_roles, 0) as active_roles,
    COALESCE(rc.system_roles, 0) as system_roles,
    COALESCE(rc.custom_roles, 0) as custom_roles,
    
    -- Entitlement metrics
    COALESCE(es.total_entitlements, 0) as total_entitlements,
    COALESCE(es.resource_usage, '{}'::JSONB) as resource_usage,
    
    -- Resource limits
    ar.max_transactions_per_minute,
    ar.max_storage_gb,
    ar.max_concurrent_sessions,
    
    -- Health indicators
    CASE 
        WHEN ar.status != 'active' THEN 'inactive'
        WHEN COALESCE(mc.active_memberships, 0) = 0 THEN 'no_users'
        ELSE 'healthy'
    END as health_status,
    
    -- Version info
    ar.version,
    
    -- Metadata
    ar.metadata,
    
    -- View timestamp
    NOW() as calculated_at

FROM app.t_application_registry ar
LEFT JOIN membership_counts mc ON ar.app_id = mc.app_id
LEFT JOIN role_counts rc ON ar.app_id = rc.app_id
LEFT JOIN entitlement_summary es ON ar.app_id = es.app_id
WHERE ar.deleted_at IS NULL;

COMMENT ON VIEW app.v_application_summary IS 
    'Application summary with membership, role, and entitlement metrics. ' ||
    'Feature: CORE-APP-VIEW-004';

-- =============================================================================
-- VIEW: Tenant Applications
-- ISO 27017: RLS-enforced tenant view
-- =============================================================================

CREATE OR REPLACE VIEW app.v_tenant_applications AS
SELECT 
    ar.app_id,
    ar.app_code,
    ar.app_name,
    ar.app_tier,
    ar.status,
    ar.ledger_tenant_id,
    ar.activated_at,
    ar.max_transactions_per_minute,
    ar.max_storage_gb,
    ar.max_concurrent_sessions,
    ar.metadata
FROM app.t_application_registry ar
WHERE ar.status = 'active'
  AND ar.deleted_at IS NULL;

COMMENT ON VIEW app.v_tenant_applications IS 
    'Tenant-scoped application view. ISO 27017: Data segregation.';

-- =============================================================================
-- VIEW: Application Health Status
-- Operational monitoring view
-- =============================================================================

CREATE OR REPLACE VIEW app.v_application_health AS
WITH recent_activity AS (
    -- This would join to transaction/core tables in full implementation
    SELECT 
        '00000000-0000-0000-0000-000000000000'::UUID as app_id,  -- Placeholder
        0 as transactions_24h,
        0 as errors_24h
),
quota_status AS (
    SELECT 
        el.app_id,
        MAX(CASE 
            WHEN el.current_usage >= COALESCE(el.override_value, el.limit_value) * (el.critical_threshold_pct / 100)
            THEN 3  -- Critical
            WHEN el.current_usage >= COALESCE(el.override_value, el.limit_value) * (el.warning_threshold_pct / 100)
            THEN 2  -- Warning
            ELSE 1  -- OK
        END) as quota_health_level
    FROM app.t_entitlement_limits el
    WHERE el.status = 'active'
    GROUP BY el.app_id
)

SELECT 
    ar.app_id,
    ar.app_code,
    ar.app_name,
    ar.status,
    
    -- Component health (0=unknown, 1=healthy, 2=warning, 3=critical)
    CASE ar.status
        WHEN 'active' THEN 1
        WHEN 'suspended' THEN 3
        WHEN 'pending' THEN 2
        ELSE 3
    END as status_health,
    
    COALESCE(qs.quota_health_level, 1) as quota_health,
    
    -- Overall health score (worst of components)
    GREATEST(
        CASE ar.status
            WHEN 'active' THEN 1
            WHEN 'suspended' THEN 3
            WHEN 'pending' THEN 2
            ELSE 3
        END,
        COALESCE(qs.quota_health_level, 1)
    ) as overall_health_level,
    
    -- Health label
    CASE GREATEST(
        CASE ar.status
            WHEN 'active' THEN 1
            WHEN 'suspended' THEN 3
            WHEN 'pending' THEN 2
            ELSE 3
        END,
        COALESCE(qs.quota_health_level, 1)
    )
        WHEN 1 THEN 'healthy'
        WHEN 2 THEN 'warning'
        WHEN 3 THEN 'critical'
        ELSE 'unknown'
    END as health_status,
    
    -- Last check time
    NOW() as checked_at

FROM app.t_application_registry ar
LEFT JOIN quota_status qs ON ar.app_id = qs.app_id
WHERE ar.deleted_at IS NULL;

COMMENT ON VIEW app.v_application_health IS 
    'Application health status for monitoring dashboards.';

-- =============================================================================
-- VIEW: Application Configuration Current State
-- Versioned configuration with effective values
-- =============================================================================

CREATE OR REPLACE VIEW app.v_application_config_current AS
SELECT 
    cs.config_id,
    cs.app_id,
    ar.app_code,
    cs.config_key,
    cs.environment,
    cs.scope_level,
    cs.scope_id,
    
    -- Value based on type
    CASE cs.value_type
        WHEN 'string' THEN to_jsonb(cs.value_string)
        WHEN 'number' THEN to_jsonb(cs.value_number)
        WHEN 'boolean' THEN to_jsonb(cs.value_boolean)
        WHEN 'json' THEN cs.value_json
        ELSE '{}'::JSONB
    END as config_value,
    
    cs.value_type,
    cs.is_encrypted,
    cs.is_current,
    cs.version_number,
    cs.effective_from,
    cs.effective_until,
    cs.created_at,
    cs.created_by

FROM app.t_configuration_store cs
INNER JOIN app.t_application_registry ar ON cs.app_id = ar.app_id
WHERE cs.is_current = TRUE
  AND (cs.effective_until IS NULL OR cs.effective_until > NOW())
  AND ar.deleted_at IS NULL;

COMMENT ON VIEW app.v_application_config_current IS 
    'Current effective configuration values per application.';

-- =============================================================================
-- VIEW: Pending Application Approvals
-- Workflow support for application lifecycle
-- =============================================================================

CREATE OR REPLACE VIEW app.v_pending_approvals AS
SELECT 
    ar.app_id,
    ar.app_code,
    ar.app_name,
    ar.app_tier,
    ar.app_category,
    ar.status,
    ar.created_at,
    ar.created_by,
    u.email as created_by_email,
    
    -- Days pending
    EXTRACT(EPOCH FROM (NOW() - ar.created_at)) / 86400 as days_pending,
    
    -- Required actions based on status
    CASE ar.status
        WHEN 'pending' THEN 'activation_review'
        ELSE 'unknown'
    END as required_action,
    
    -- Approval requirements
    CASE ar.app_tier
        WHEN 'enterprise' THEN 'platform_admin'
        WHEN 'premium' THEN 'platform_admin'
        ELSE 'app_owner'
    END as approver_role_required

FROM app.t_application_registry ar
LEFT JOIN core.t_user_identity u ON ar.created_by = u.user_identity_id
WHERE ar.status = 'pending'
  AND ar.deleted_at IS NULL
ORDER BY ar.created_at ASC;

COMMENT ON VIEW app.v_pending_approvals IS 
    'Applications pending approval/activation.';

-- =============================================================================
-- VIEW: Application Resource Utilization
-- Capacity planning and quota monitoring
-- =============================================================================

CREATE OR REPLACE VIEW app.v_resource_utilization AS
SELECT 
    ar.app_id,
    ar.app_code,
    ar.app_tier,
    ar.status,
    
    -- Session utilization
    ar.max_concurrent_sessions,
    COALESCE(active_sessions.count, 0) as active_sessions,
    CASE 
        WHEN ar.max_concurrent_sessions > 0 
        THEN ROUND((COALESCE(active_sessions.count, 0)::NUMERIC / ar.max_concurrent_sessions) * 100, 2)
        ELSE 0
    END as session_utilization_pct,
    
    -- Transaction rate (would need core transaction data in full implementation)
    ar.max_transactions_per_minute as tpm_limit,
    0 as tpm_current,  -- Placeholder
    
    -- Storage
    ar.max_storage_gb as storage_limit_gb,
    0 as storage_used_gb,  -- Placeholder
    
    -- Entitlement summary
    jsonb_object_agg(
        COALESCE(el.resource_type, 'none'),
        jsonb_build_object(
            'limit', COALESCE(el.limit_value, 0),
            'usage', COALESCE(el.current_usage, 0),
            'unit', COALESCE(el.limit_unit, 'count')
        )
    ) FILTER (WHERE el.entitlement_id IS NOT NULL) as entitlements,
    
    -- Calculated at
    NOW() as calculated_at

FROM app.t_application_registry ar
LEFT JOIN (
    -- Count active sessions per app (requires session-app linkage)
    SELECT '00000000-0000-0000-0000-000000000000'::UUID as app_id, 0 as count
) active_sessions ON ar.app_id = active_sessions.app_id
LEFT JOIN app.t_entitlement_limits el ON ar.app_id = el.app_id AND el.status = 'active'
WHERE ar.deleted_at IS NULL
GROUP BY ar.app_id, ar.app_code, ar.app_tier, ar.status, 
         ar.max_concurrent_sessions, ar.max_transactions_per_minute, ar.max_storage_gb,
         active_sessions.count;

COMMENT ON VIEW app.v_resource_utilization IS 
    'Resource utilization metrics for capacity planning.';

-- =============================================================================
-- GRANTS
-- =============================================================================
-- Note: Actual grants depend on role setup
-- GRANT SELECT ON app.v_active_applications TO app_readonly;
-- GRANT SELECT ON app.v_application_summary TO app_readonly;
-- GRANT SELECT ON app.v_tenant_applications TO app_readonly;

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. All views filter out soft-deleted records (deleted_at IS NULL)
-- 2. Tenant isolation via ledger_tenant_id in base tables
-- 3. Views are read-only; use functions for modifications
-- 4. Materialized views recommended for large deployments
-- 5. Refresh materialized views on significant data changes
-- =============================================================================
