-- ============================================================================
-- USSD KERNEL APP SCHEMA - UTILITIES AND MAINTENANCE
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Utility functions for app schema maintenance, multi-tenancy
--              enforcement, and operational tasks.
-- Immutability: N/A (Operational utilities)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. MULTI-TENANCY UTILITIES
-- ----------------------------------------------------------------------------

-- Function to set tenant context (call at start of session)
CREATE OR REPLACE FUNCTION ussd_app.set_tenant_context(
    p_application_id UUID,
    p_account_id UUID DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    PERFORM set_config('app.application_id', p_application_id::TEXT, FALSE);
    IF p_account_id IS NOT NULL THEN
        PERFORM set_config('app.current_account_id', p_account_id::TEXT, FALSE);
    END IF;
    PERFORM set_config('app.tenant_set_at', ussd_core.precise_now()::TEXT, FALSE);
END;
$$;

-- Function to clear tenant context
CREATE OR REPLACE FUNCTION ussd_app.clear_tenant_context()
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    PERFORM set_config('app.application_id', '', FALSE);
    PERFORM set_config('app.current_account_id', '', FALSE);
    PERFORM set_config('app.tenant_set_at', '', FALSE);
END;
$$;

-- Function to get current tenant
CREATE OR REPLACE FUNCTION ussd_app.get_current_tenant()
RETURNS TABLE (
    application_id UUID,
    account_id UUID,
    set_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY SELECT
        NULLIF(current_setting('app.application_id', TRUE), '')::UUID,
        NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID,
        NULLIF(current_setting('app.tenant_set_at', TRUE), '')::TIMESTAMPTZ;
END;
$$;

-- Function to enforce tenant isolation
CREATE OR REPLACE FUNCTION ussd_app.enforce_tenant_isolation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_current_app_id UUID;
BEGIN
    v_current_app_id := NULLIF(current_setting('app.application_id', TRUE), '')::UUID;
    
    IF v_current_app_id IS NULL THEN
        -- No tenant context, allow (for system operations)
        RETURN NEW;
    END IF;
    
    -- Check if the operation is for the current tenant
    IF TG_TABLE_NAME = 'applications' THEN
        IF NEW.application_id != v_current_app_id THEN
            RAISE EXCEPTION 'Tenant isolation violation: Cannot modify other tenant data';
        END IF;
    ELSIF TG_TABLE_NAME IN ('account_memberships', 'membership_requests') THEN
        IF NEW.application_id != v_current_app_id THEN
            RAISE EXCEPTION 'Tenant isolation violation: Cannot modify other tenant data';
        END IF;
    END IF;
    
    RETURN NEW;
END;
$$;

-- ----------------------------------------------------------------------------
-- 2. RESOURCE QUOTA MANAGEMENT
-- ----------------------------------------------------------------------------

CREATE TABLE ussd_app.resource_quotas (
    quota_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    application_id UUID NOT NULL UNIQUE,
    
    -- Transaction limits
    max_transactions_per_second INTEGER DEFAULT 100,
    max_transactions_per_day BIGINT DEFAULT 100000,
    max_transaction_amount NUMERIC(20, 8) DEFAULT 1000000,
    
    -- Storage limits
    max_storage_gb INTEGER DEFAULT 100,
    max_retention_days INTEGER DEFAULT 2555,  -- ~7 years
    
    -- API limits
    max_api_calls_per_minute INTEGER DEFAULT 10000,
    max_concurrent_sessions INTEGER DEFAULT 1000,
    
    -- Hook limits
    max_hooks INTEGER DEFAULT 50,
    max_hook_executions_per_day BIGINT DEFAULT 100000,
    
    -- Current usage (updated periodically)
    current_usage JSONB DEFAULT '{}',
    last_updated TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    
    -- Alerts
    alert_threshold_percentage INTEGER DEFAULT 80,
    alert_email VARCHAR(255),
    
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    updated_at TIMESTAMPTZ DEFAULT ussd_core.precise_now()
);

-- Quota usage log
CREATE TABLE ussd_app.quota_usage_log (
    log_id BIGSERIAL PRIMARY KEY,
    application_id UUID NOT NULL,
    quota_type VARCHAR(50) NOT NULL,
    usage_value BIGINT NOT NULL,
    limit_value BIGINT NOT NULL,
    percentage_used NUMERIC(5, 2),
    recorded_at TIMESTAMPTZ DEFAULT ussd_core.precise_now()
);

-- Function to check quota
CREATE OR REPLACE FUNCTION ussd_app.check_quota(
    p_application_id UUID,
    p_quota_type VARCHAR,
    p_requested_value BIGINT DEFAULT 1
)
RETURNS TABLE (
    allowed BOOLEAN,
    current_usage BIGINT,
    quota_limit BIGINT,
    remaining BIGINT
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_quota ussd_app.resource_quotas%ROWTYPE;
    v_current BIGINT;
    v_limit BIGINT;
BEGIN
    SELECT * INTO v_quota
    FROM ussd_app.resource_quotas
    WHERE application_id = p_application_id;
    
    IF NOT FOUND THEN
        -- No quota defined, use defaults (allow)
        RETURN QUERY SELECT TRUE, 0::BIGINT, 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;
    
    -- Get current usage based on type
    v_current := CASE p_quota_type
        WHEN 'transactions_per_day' THEN 
            (SELECT COUNT(*) FROM ussd_core.transactions 
             WHERE application_id = p_application_id 
               AND committed_at > CURRENT_DATE)
        WHEN 'api_calls_per_minute' THEN
            (COALESCE(v_quota.current_usage->>'api_calls_last_minute', '0'))::BIGINT
        WHEN 'storage_gb' THEN
            (COALESCE(v_quota.current_usage->>'storage_gb', '0'))::BIGINT
        ELSE 0
    END;
    
    v_limit := CASE p_quota_type
        WHEN 'transactions_per_day' THEN v_quota.max_transactions_per_day
        WHEN 'api_calls_per_minute' THEN v_quota.max_api_calls_per_minute
        WHEN 'storage_gb' THEN v_quota.max_storage_gb
        ELSE 0
    END;
    
    RETURN QUERY SELECT 
        (v_current + p_requested_value <= v_limit),
        v_current,
        v_limit,
        GREATEST(0, v_limit - v_current);
END;
$$;

-- ----------------------------------------------------------------------------
-- 3. LEGAL HOLD MANAGEMENT
-- ----------------------------------------------------------------------------

CREATE TABLE ussd_app.legal_holds (
    hold_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    hold_name VARCHAR(200) NOT NULL,
    hold_reason TEXT NOT NULL,
    
    -- Scope
    application_id UUID,
    account_id UUID,
    transaction_type_id UUID,
    date_range_start DATE,
    date_range_end DATE,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Audit
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    released_by UUID,
    released_at TIMESTAMPTZ,
    release_reason TEXT
);

-- Function to check if data is under legal hold
CREATE OR REPLACE FUNCTION ussd_app.is_under_legal_hold(
    p_application_id UUID DEFAULT NULL,
    p_account_id UUID DEFAULT NULL,
    p_transaction_date DATE DEFAULT CURRENT_DATE
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM ussd_app.legal_holds
        WHERE is_active = TRUE
          AND (application_id IS NULL OR application_id = p_application_id)
          AND (account_id IS NULL OR account_id = p_account_id)
          AND (date_range_start IS NULL OR date_range_start <= p_transaction_date)
          AND (date_range_end IS NULL OR date_range_end >= p_transaction_date)
    );
END;
$$;

-- ----------------------------------------------------------------------------
-- 4. USAGE TRACKING FOR BILLING
-- ----------------------------------------------------------------------------

CREATE TABLE ussd_app.usage_tracking (
    tracking_id BIGSERIAL PRIMARY KEY,
    
    application_id UUID NOT NULL,
    billing_period VARCHAR(7) NOT NULL,  -- YYYY-MM format
    
    -- Metrics
    transaction_count BIGINT DEFAULT 0,
    transaction_volume NUMERIC(20, 8) DEFAULT 0,
    storage_gb NUMERIC(10, 4) DEFAULT 0,
    api_calls BIGINT DEFAULT 0,
    hook_executions BIGINT DEFAULT 0,
    unique_active_users INTEGER DEFAULT 0,
    
    -- Computed costs (if applicable)
    estimated_cost NUMERIC(12, 4),
    
    recorded_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    
    UNIQUE(application_id, billing_period)
);

-- Function to record usage
CREATE OR REPLACE FUNCTION ussd_app.record_usage(
    p_application_id UUID,
    p_metric_type VARCHAR,
    p_value NUMERIC,
    p_transaction_id BIGINT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_period VARCHAR(7);
BEGIN
    v_period := to_char(CURRENT_DATE, 'YYYY-MM');
    
    INSERT INTO ussd_app.usage_tracking (
        application_id,
        billing_period,
        transaction_count,
        transaction_volume,
        api_calls,
        hook_executions
    ) VALUES (
        p_application_id,
        v_period,
        CASE WHEN p_metric_type = 'transaction' THEN 1 ELSE 0 END,
        CASE WHEN p_metric_type = 'volume' THEN p_value ELSE 0 END,
        CASE WHEN p_metric_type = 'api_call' THEN 1 ELSE 0 END,
        CASE WHEN p_metric_type = 'hook' THEN 1 ELSE 0 END
    )
    ON CONFLICT (application_id, billing_period) DO UPDATE
    SET transaction_count = usage_tracking.transaction_count + 
        CASE WHEN p_metric_type = 'transaction' THEN 1 ELSE 0 END,
        transaction_volume = usage_tracking.transaction_volume + 
        CASE WHEN p_metric_type = 'volume' THEN p_value ELSE 0 END,
        api_calls = usage_tracking.api_calls + 
        CASE WHEN p_metric_type = 'api_call' THEN 1 ELSE 0 END,
        hook_executions = usage_tracking.hook_executions + 
        CASE WHEN p_metric_type = 'hook' THEN 1 ELSE 0 END,
        recorded_at = ussd_core.precise_now();
END;
$$;

-- ----------------------------------------------------------------------------
-- 5. DATA RETENTION POLICIES
-- ----------------------------------------------------------------------------

CREATE TABLE ussd_app.data_retention_policies (
    policy_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    application_id UUID,
    transaction_type_id UUID,
    
    -- Retention settings
    retention_days INTEGER NOT NULL,
    archive_after_days INTEGER,  -- Move to cold storage
    delete_after_days INTEGER,   -- Actually delete (rarely used)
    
    -- Compliance
    compliance_requirement VARCHAR(50),  -- e.g., 'SOX', 'GDPR', 'PCI'
    legal_hold_exempt BOOLEAN DEFAULT FALSE,
    
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    updated_at TIMESTAMPTZ DEFAULT ussd_core.precise_now()
);

-- Function to apply retention policy
CREATE OR REPLACE FUNCTION ussd_app.apply_retention_policy(
    p_application_id UUID DEFAULT NULL
)
RETURNS TABLE (
    partition_name TEXT,
    action_taken TEXT,
    rows_affected BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_policy RECORD;
    v_partition RECORD;
    v_cutoff_date DATE;
BEGIN
    FOR v_policy IN 
        SELECT * FROM ussd_app.data_retention_policies
        WHERE (p_application_id IS NULL OR application_id = p_application_id)
          AND legal_hold_exempt = FALSE
    LOOP
        v_cutoff_date := CURRENT_DATE - v_policy.retention_days;
        
        -- Check for legal holds
        IF ussd_app.is_under_legal_hold(v_policy.application_id, NULL, v_cutoff_date) THEN
            CONTINUE;  -- Skip if under legal hold
        END IF;
        
        -- In production, this would trigger archival to cold storage
        -- For now, we just report what would be done
        
        partition_name := 'transactions_' || to_char(v_cutoff_date, 'YYYY_MM');
        action_taken := 'would_archive';
        rows_affected := 0;  -- Placeholder
        
        RETURN NEXT;
    END LOOP;
END;
$$;

-- ----------------------------------------------------------------------------
-- 6. INDEXES
-- ----------------------------------------------------------------------------
CREATE INDEX idx_resource_quotas_app ON ussd_app.resource_quotas(application_id);
CREATE INDEX idx_quota_usage_log_app ON ussd_app.quota_usage_log(application_id);
CREATE INDEX idx_quota_usage_log_time ON ussd_app.quota_usage_log(recorded_at DESC);

CREATE INDEX idx_legal_holds_active ON ussd_app.legal_holds(is_active) WHERE is_active = TRUE;
CREATE INDEX idx_legal_holds_app ON ussd_app.legal_holds(application_id);

CREATE INDEX idx_usage_tracking_app ON ussd_app.usage_tracking(application_id);
CREATE INDEX idx_usage_tracking_period ON ussd_app.usage_tracking(billing_period);

CREATE INDEX idx_retention_policies_app ON ussd_app.data_retention_policies(application_id);

-- ----------------------------------------------------------------------------
-- 7. VIEWS
-- ----------------------------------------------------------------------------

-- Tenant overview
CREATE VIEW ussd_app.tenant_overview AS
SELECT 
    a.application_id,
    a.app_code,
    a.name,
    a.status,
    a.tier,
    COALESCE(am.member_count, 0) as member_count,
    COALESCE(ut.transaction_count, 0) as monthly_transactions,
    COALESCE(rq.current_usage->>'storage_gb', '0')::NUMERIC as storage_gb,
    CASE 
        WHEN lh.hold_count > 0 THEN TRUE
        ELSE FALSE
    END as has_active_legal_hold
FROM ussd_app.applications a
LEFT JOIN (
    SELECT application_id, COUNT(*) as member_count
    FROM ussd_app.account_memberships
    WHERE valid_to IS NULL AND status = 'active'
    GROUP BY application_id
) am ON a.application_id = am.application_id
LEFT JOIN ussd_app.usage_tracking ut ON a.application_id = ut.application_id 
    AND ut.billing_period = to_char(CURRENT_DATE, 'YYYY-MM')
LEFT JOIN ussd_app.resource_quotas rq ON a.application_id = rq.application_id
LEFT JOIN (
    SELECT application_id, COUNT(*) as hold_count
    FROM ussd_app.legal_holds
    WHERE is_active = TRUE
    GROUP BY application_id
) lh ON a.application_id = lh.application_id
WHERE a.valid_to IS NULL;

-- Quota utilization
CREATE VIEW ussd_app.quota_utilization AS
SELECT 
    rq.*,
    a.app_code,
    a.name as application_name,
    CASE 
        WHEN (rq.current_usage->>'transactions_today')::BIGINT > rq.max_transactions_per_day * 0.9 THEN 'critical'
        WHEN (rq.current_usage->>'transactions_today')::BIGINT > rq.max_transactions_per_day * 0.8 THEN 'warning'
        ELSE 'normal'
    END as quota_status
FROM ussd_app.resource_quotas rq
JOIN ussd_app.applications a ON rq.application_id = a.application_id;

-- ----------------------------------------------------------------------------
-- 8. COMPLETION NOTICE
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    RAISE NOTICE 'USSD Kernel App Schema - Utilities Loaded';
    RAISE NOTICE 'App schema files 100-199 complete';
END;
$$;

-- ----------------------------------------------------------------------------
-- 9. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_app.resource_quotas IS 
    'Per-application resource limits for multi-tenant isolation';
COMMENT ON TABLE ussd_app.legal_holds IS 
    'Legal hold records preventing data deletion during litigation';
COMMENT ON TABLE ussd_app.usage_tracking IS 
    'Monthly usage metrics for billing and chargeback';
COMMENT ON FUNCTION ussd_app.set_tenant_context IS 
    'Sets the tenant context for the current session (RLS enforcement)';
