/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - VIEW: APPLICATION STATE DERIVED
 * =============================================================================
 * 
 * Feature:      CORE-APP-VIEW-003
 * Description:  Comprehensive application state view combining registry
 *               data with operational metrics, health indicators, and
 *               aggregated statistics for monitoring and dashboards.
 * 
 * Version:      1.0.0
 * Author:       Eng. llunzwe
 * Created:      2026-03-30
 * 
 * DEPENDENCIES:
 *   - app.t_application_registry
 *   - app.t_account_membership
 *   - app.t_roles_permissions
 *   - app.t_user_role_assignments
 *   - app.t_feature_flags
 *   - core.t_transaction_log (for metrics)
 * 
 * CHANGE LOG:
 *   1.0.0 - Initial view creation
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
-- VIEW: app.v_application_state_derived
-- =============================================================================

DROP VIEW IF EXISTS app.v_application_state_derived CASCADE;

CREATE OR REPLACE VIEW app.v_application_state_derived AS

WITH membership_stats AS (
    -- Membership statistics per app
    SELECT 
        app_id,
        COUNT(*) as total_memberships,
        COUNT(*) FILTER (WHERE status = 'active') as active_memberships,
        COUNT(*) FILTER (WHERE status = 'pending') as pending_invitations,
        COUNT(*) FILTER (WHERE status = 'suspended') as suspended_memberships,
        COUNT(DISTINCT user_identity_id) as unique_users,
        COUNT(*) FILTER (WHERE membership_type = 'service') as service_accounts  -- [RBAC] ISO 27001: Privilege level classification
    FROM app.t_account_membership
    GROUP BY app_id
),

role_stats AS (
    -- Role statistics per app
    SELECT 
        app_id,
        COUNT(*) as total_roles,
        COUNT(*) FILTER (WHERE status = 'active') as active_roles,
        COUNT(*) FILTER (WHERE is_system_role = TRUE) as system_roles,
        COUNT(*) FILTER (WHERE role_type = 'custom') as custom_roles
    FROM app.t_roles_permissions
    GROUP BY app_id
),

assignment_stats AS (
    -- Role assignment statistics
    SELECT 
        am.app_id,
        COUNT(*) as total_assignments,
        COUNT(*) FILTER (WHERE ra.is_break_glass = TRUE) as break_glass_assignments,  -- [RBAC] ISO 27001: Emergency access indicator
        COUNT(*) FILTER (WHERE ra.approval_status = 'pending') as pending_approvals
    FROM app.t_user_role_assignments ra
    INNER JOIN app.t_account_membership am ON ra.membership_id = am.membership_id
    WHERE ra.is_revoked = FALSE
    GROUP BY am.app_id
),

feature_flag_stats AS (
    -- Feature flag statistics
    SELECT 
        app_id,
        COUNT(*) as total_flags,
        COUNT(*) FILTER (WHERE flag_state = 'on') as enabled_flags,  -- [FEATURE_FLAG] ISO 9001: Controlled feature state management
        COUNT(*) FILTER (WHERE flag_state = 'gradual') as gradual_rollouts,  -- [FEATURE_FLAG] ISO 9001: Controlled feature state management
        COUNT(*) FILTER (WHERE flag_state = 'experiment') as experiments,  -- [FEATURE_FLAG] ISO 9001: Controlled feature state management
        COUNT(*) FILTER (WHERE is_kill_switch = TRUE) as kill_switches  -- [FEATURE_FLAG] ISO 27001: Emergency disable switch
    FROM app.t_feature_flags
    GROUP BY app_id
),

-- Transaction metrics (requires core ledger tables)
transaction_stats AS (
    SELECT 
        tenant_id as app_id,
        COUNT(*) as total_transactions,
        COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as transactions_24h,
        COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days') as transactions_7d,
        COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '30 days') as transactions_30d
    FROM core.t_transaction_log
    GROUP BY tenant_id
),

health_indicators AS (
    -- Calculate health scores based on various factors
    SELECT 
        ar.app_id,
        CASE 
            WHEN ar.status != 'active' THEN 'critical'
            WHEN ar.api_key_hash IS NULL THEN 'warning'
            ELSE 'healthy'
        END as api_health,
        
        CASE 
            WHEN COALESCE(ms.active_memberships, 0) = 0 THEN 'warning'
            WHEN COALESCE(ms.suspended_memberships, 0) > COALESCE(ms.active_memberships, 0) THEN 'critical'
            ELSE 'healthy'
        END as membership_health,
        
        CASE 
            WHEN COALESCE(asgn.pending_approvals, 0) > 10 THEN 'warning'
            ELSE 'healthy'
        END as approval_health,
        
        CASE 
            WHEN COALESCE(ffs.kill_switches, 0) > 0 THEN 'warning'
            ELSE 'healthy'
        END as feature_health
        
    FROM app.t_application_registry ar
    LEFT JOIN membership_stats ms ON ar.app_id = ms.app_id
    LEFT JOIN assignment_stats asgn ON ar.app_id = asgn.app_id
    LEFT JOIN feature_flag_stats ffs ON ar.app_id = ffs.app_id
)

SELECT 
    -- Application identification
    ar.app_id,
    ar.app_code,
    ar.app_name,
    ar.app_tier,
    ar.status as app_status,
    ar.app_category,
    
    -- Status details
    ar.activated_at,
    ar.deprecated_at,
    ar.archived_at,
    ar.status_reason,
    
    -- Resource limits
    ar.max_transactions_per_minute,
    ar.max_storage_gb,
    ar.max_concurrent_sessions,
    
    -- Membership statistics
    COALESCE(ms.total_memberships, 0) as total_memberships,
    COALESCE(ms.active_memberships, 0) as active_memberships,
    COALESCE(ms.pending_invitations, 0) as pending_invitations,
    COALESCE(ms.suspended_memberships, 0) as suspended_memberships,
    COALESCE(ms.unique_users, 0) as unique_users,
    COALESCE(ms.service_accounts, 0) as service_accounts,
    
    -- Role statistics
    COALESCE(rs.total_roles, 0) as total_roles,
    COALESCE(rs.active_roles, 0) as active_roles,
    COALESCE(rs.system_roles, 0) as system_roles,
    COALESCE(rs.custom_roles, 0) as custom_roles,
    
    -- Assignment statistics
    COALESCE(asgn.total_assignments, 0) as total_assignments,
    COALESCE(asgn.break_glass_assignments, 0) as break_glass_assignments,
    COALESCE(asgn.pending_approvals, 0) as pending_approvals,
    
    -- Feature flag statistics
    COALESCE(ffs.total_flags, 0) as total_feature_flags,
    COALESCE(ffs.enabled_flags, 0) as enabled_flags,
    COALESCE(ffs.gradual_rollouts, 0) as gradual_rollouts,
    COALESCE(ffs.experiments, 0) as experiments,
    COALESCE(ffs.kill_switches, 0) as kill_switches,
    
    -- Transaction metrics
    COALESCE(ts.total_transactions, 0) as total_transactions,
    COALESCE(ts.transactions_24h, 0) as transactions_24h,
    COALESCE(ts.transactions_7d, 0) as transactions_7d,
    COALESCE(ts.transactions_30d, 0) as transactions_30d,
    
    -- Health indicators
    hi.api_health,
    hi.membership_health,
    hi.approval_health,
    hi.feature_health,
    
    -- Overall health score
    CASE 
        WHEN 'critical' IN (hi.api_health, hi.membership_health, hi.approval_health, hi.feature_health) THEN 'critical'
        WHEN 'warning' IN (hi.api_health, hi.membership_health, hi.approval_health, hi.feature_health) THEN 'warning'
        ELSE 'healthy'
    END as overall_health,
    
    -- Ledger information
    ar.ledger_tenant_id,  -- [RLS] ISO 27017: Tenant isolation identifier for RLS
    ar.last_ledger_sequence,
    
    -- Metadata
    ar.version as app_version,
    ar.created_at as app_created_at,
    ar.updated_at as app_updated_at,
    ar.metadata,
    
    -- View metadata
    NOW() as calculated_at

FROM app.t_application_registry ar
LEFT JOIN membership_stats ms ON ar.app_id = ms.app_id
LEFT JOIN role_stats rs ON ar.app_id = rs.app_id
LEFT JOIN assignment_stats asgn ON ar.app_id = asgn.app_id
LEFT JOIN feature_flag_stats ffs ON ar.app_id = ffs.app_id
LEFT JOIN health_indicators hi ON ar.app_id = hi.app_id
LEFT JOIN transaction_stats ts ON ar.app_id = ts.app_id;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON VIEW app.v_application_state_derived IS 
    'Derived application state with metrics and health indicators. Feature: CORE-APP-VIEW-003';

-- =============================================================================
-- MATERIALIZED VIEW VARIANT
-- =============================================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS app.mv_application_state_derived AS
SELECT * FROM app.v_application_state_derived;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_app_state_app_id 
    ON app.mv_application_state_derived(app_id);

CREATE INDEX IF NOT EXISTS idx_mv_app_state_health 
    ON app.mv_application_state_derived(overall_health);

CREATE INDEX IF NOT EXISTS idx_mv_app_state_status 
    ON app.mv_application_state_derived(app_status);

-- =============================================================================
-- HELPER FUNCTION: Get app health score
-- =============================================================================

CREATE OR REPLACE FUNCTION app.get_app_health_score(p_app_id UUID)
RETURNS INTEGER  -- 0-100
LANGUAGE SQL
STABLE
SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged function execution context
AS $$
    SELECT CASE overall_health
        WHEN 'healthy' THEN 100
        WHEN 'warning' THEN 50
        WHEN 'critical' THEN 0
    END
    FROM app.v_application_state_derived
    WHERE app_id = p_app_id;
$$;

-- =============================================================================
-- HELPER FUNCTION: Refresh materialized view
-- =============================================================================

CREATE OR REPLACE FUNCTION app.refresh_application_state()
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged function execution context
AS $$
BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
    REFRESH MATERIALIZED VIEW CONCURRENTLY app.mv_application_state_derived;  -- [TXN] ISO 9001: Non-blocking index creation
    
    INSERT INTO core.t_audit_log (action, entity_type, entity_id, details, created_at)  -- [AUDIT] ISO 27001 A.8.15: Security event logging
    VALUES ('mv_refresh', 'materialized_view', NULL,
        jsonb_build_object('view_name', 'app.mv_application_state_derived', 'refreshed_at', NOW()),
        NOW());
END;
$$;

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Aggregates data from multiple tables for dashboard use
-- 2. Health indicators based on operational thresholds
-- 3. Statistics cached for performance
-- 4. Transaction metrics from core ledger tables
-- 5. Consider materializing for large datasets
-- 6. Refresh triggered by significant state changes
-- =============================================================================
