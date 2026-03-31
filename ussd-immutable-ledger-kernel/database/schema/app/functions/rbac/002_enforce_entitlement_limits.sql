/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - RBAC: ENFORCE ENTITLEMENT LIMITS
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-FUNC-003
 * Feature Name:       Entitlement Limit Enforcement
 * Description:        Entitlement limit enforcement with consumption tracking,
 *                     burst handling, and configurable enforcement actions.
 *                     Supports hierarchical limits (app -> role -> membership).
 * 
 * Version:            1.0.0
 * Author:             Eng. llunzwe
 * Created:            2026-03-30
 * Last Modified:      2026-03-30
 * 
 * =============================================================================
 * COMPLIANCE & CERTIFICATIONS
 * =============================================================================
 * 
 * ISO/IEC 27001:2022 (ISMS)
 *   - Control A.5.7: Threat intelligence (usage monitoring)
 *   - Control A.8.7: Protection against malware (DoS prevention)
 *   - Control A.8.20: Networks security (rate limiting)
 * 
 * ISO/IEC 27017:2015 (Cloud Security)
 *   - Section 12: Multi-tenant resource isolation
 * 
 * SOC 2 Type II
 *   - CC6.1: Logical access controls
 *   - CC7.2: System monitoring
 * 
 * =============================================================================
 * MULTI-TENANCY SECURITY ANNOTATIONS
 * =============================================================================
 * 
 * HIERARCHICAL LIMIT RESOLUTION:
 *   Priority (lower = higher):
 *     10: Membership-specific overrides
 *     50: Role-based limits
 *     100: Application default limits
 *     200: Global platform limits
 * 
 * ENFORCEMENT ACTIONS:
 *   - block:    Reject request
 *   - throttle: Slow processing
 *   - queue:    Defer processing
 *   - log:      Log only
 *   - notify:   Alert admins
 * 
 * =============================================================================
 * AUDIT TRAIL REQUIREMENTS
 * =============================================================================
 * 
 * MANDATORY LOGGING:
 *   - Limit exceeded (security event if hard limit)
 *   - Override set
 *   - Threshold warnings
 *   - Enforcement actions
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - app.t_entitlement_limits
 *   - app.t_account_membership
 * 
 * CHANGE LOG:
 *   1.0.0 - Initial function creation
 *   1.0.1 - Implemented TODOs: Usage window reset logic
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
-- FUNCTION: app.check_entitlement()
-- =============================================================================

CREATE OR REPLACE FUNCTION app.check_entitlement(
    p_membership_id UUID,
    p_resource_type TEXT,
    p_requested_amount NUMERIC DEFAULT 1,
    p_resource_subtype TEXT DEFAULT NULL
)
RETURNS TABLE (
    allowed BOOLEAN,
    remaining NUMERIC,
    limit_value NUMERIC,
    enforcement_action TEXT,
    warning_threshold_reached BOOLEAN,
    limit_source TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = app, core, public
AS $$
DECLARE
    v_app_id UUID;
    v_role_id UUID;
    v_effective_limit RECORD;
    v_projected_usage NUMERIC;
    v_usage_pct NUMERIC;
    v_warning_threshold NUMERIC;
    v_critical_threshold NUMERIC;
    v_window_start TIMESTAMPTZ;
    v_window_end TIMESTAMPTZ;
BEGIN
    -- ========================================================================
    -- GET MEMBERSHIP CONTEXT
    -- ========================================================================
    SELECT app_id, primary_role_id 
    INTO v_app_id, v_role_id
    FROM app.t_account_membership
    WHERE membership_id = p_membership_id
      AND status = 'active';
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT 
            FALSE, 0::NUMERIC, 0::NUMERIC, 'block'::TEXT, FALSE, 'none'::TEXT;
        RETURN;
    END IF;
    
    -- ========================================================================
    -- GET EFFECTIVE LIMIT (Hierarchical resolution)
    -- ========================================================================
    SELECT * INTO v_effective_limit
    FROM app.t_entitlement_limits
    WHERE status = 'active'
      AND effective_from <= NOW()
      AND (effective_until IS NULL OR effective_until > NOW())
      AND resource_type = p_resource_type
      AND (resource_subtype = p_resource_subtype OR resource_subtype IS NULL)
      AND (
          (target_type = 'membership' AND target_id = p_membership_id)
          OR (target_type = 'role' AND target_id = v_role_id)
          OR (target_type = 'application' AND target_id = v_app_id)
          OR target_type = 'global'
      )
    ORDER BY priority ASC
    LIMIT 1;
    
    -- No limit found - allow with logging
    IF v_effective_limit IS NULL THEN
        RETURN QUERY SELECT 
            TRUE, NULL::NUMERIC, NULL::NUMERIC, 'log'::TEXT, FALSE, 'none'::TEXT;
        RETURN;
    END IF;
    
    -- ========================================================================
    -- CALCULATE CURRENT USAGE WITH WINDOW MANAGEMENT
    -- ========================================================================
    -- Calculate window boundaries based on window_type
    CASE v_effective_limit.window_type
        WHEN 'rolling' THEN
            -- Rolling window: reset if window has passed
            IF v_effective_limit.window_duration IS NOT NULL THEN
                v_window_start := NOW() - v_effective_limit.window_duration;
                v_window_end := NOW();
                
                -- Check if we need to reset usage
                IF v_effective_limit.usage_reset_at IS NOT NULL AND
                   v_effective_limit.usage_reset_at < v_window_start THEN
                    -- Reset the usage counter via background job trigger
                    PERFORM pg_notify('entitlement_reset', jsonb_build_object(
                        'entitlement_id', v_effective_limit.entitlement_id,
                        'reason', 'rolling_window_expired',
                        'window_start', v_window_start,
                        'window_end', v_window_end
                    )::TEXT);
                    
                    -- Log the reset event
                    INSERT INTO core.audit_trail (
                        audit_category,
                        audit_level,
                        audit_event,
                        audit_description,
                        action,
                        action_status,
                        table_schema,
                        table_name,
                        record_id,
                        new_data
                    ) VALUES (
                        'SYSTEM',
                        'INFO',
                        'entitlement_window_reset',
                        'Rolling window usage reset triggered',
                        'MAINTENANCE',
                        'SUCCESS',
                        'app',
                        't_entitlement_limits',
                        v_effective_limit.entitlement_id::TEXT,
                        jsonb_build_object(
                            'membership_id', p_membership_id,
                            'resource_type', p_resource_type,
                            'previous_usage', v_effective_limit.current_usage,
                            'window_start', v_window_start
                        )
                    );
                    
                    -- For this check, treat as reset
                    v_effective_limit.current_usage := 0;
                END IF;
            END IF;
            
        WHEN 'fixed' THEN
            -- Fixed window: check if we're in a new window period
            IF v_effective_limit.window_start IS NOT NULL AND
               v_effective_limit.window_end IS NOT NULL THEN
                
                IF NOW() > v_effective_limit.window_end THEN
                    -- Window has passed, trigger reset for new window
                    PERFORM pg_notify('entitlement_reset', jsonb_build_object(
                        'entitlement_id', v_effective_limit.entitlement_id,
                        'reason', 'fixed_window_expired',
                        'new_window_start', v_effective_limit.window_end,
                        'new_window_end', v_effective_limit.window_end + (v_effective_limit.window_end - v_effective_limit.window_start)
                    )::TEXT);
                    
                    v_effective_limit.current_usage := 0;
                END IF;
            END IF;
            
        WHEN 'calendar' THEN
            -- Calendar-based window (daily, weekly, monthly)
            IF v_effective_limit.usage_reset_at IS NOT NULL THEN
                -- Check if we crossed a calendar boundary
                CASE 
                    WHEN v_effective_limit.window_type_detail = 'daily' AND
                         DATE(v_effective_limit.usage_reset_at) < CURRENT_DATE THEN
                        v_effective_limit.current_usage := 0;
                    WHEN v_effective_limit.window_type_detail = 'weekly' AND
                         DATE_TRUNC('week', v_effective_limit.usage_reset_at) < DATE_TRUNC('week', CURRENT_DATE) THEN
                        v_effective_limit.current_usage := 0;
                    WHEN v_effective_limit.window_type_detail = 'monthly' AND
                         DATE_TRUNC('month', v_effective_limit.usage_reset_at) < DATE_TRUNC('month', CURRENT_DATE) THEN
                        v_effective_limit.current_usage := 0;
                END CASE;
            END IF;
    END CASE;
    
    -- ========================================================================
    -- CHECK AGAINST LIMITS
    -- ========================================================================
    v_projected_usage := COALESCE(v_effective_limit.current_usage, 0) + p_requested_amount;
    
    -- Apply override if active
    IF v_effective_limit.override_value IS NOT NULL AND
       v_effective_limit.override_expires_at > NOW() THEN
        v_effective_limit.limit_value := v_effective_limit.override_value;
    END IF;
    
    v_usage_pct := (v_projected_usage / v_effective_limit.limit_value) * 100;
    v_warning_threshold := COALESCE(v_effective_limit.warning_threshold_pct, 80);
    v_critical_threshold := COALESCE(v_effective_limit.critical_threshold_pct, 95);
    
    -- ========================================================================
    -- DETERMINE ENFORCEMENT ACTION
    -- ========================================================================
    IF v_projected_usage > v_effective_limit.limit_value THEN
        -- Limit exceeded
        CASE v_effective_limit.limit_type
            WHEN 'hard' THEN
                RETURN QUERY SELECT 
                    FALSE,
                    GREATEST(0, v_effective_limit.limit_value - COALESCE(v_effective_limit.current_usage, 0)),
                    v_effective_limit.limit_value,
                    v_effective_limit.enforcement_action,
                    TRUE,
                    v_effective_limit.target_type;
                    
                -- Log enforcement
                INSERT INTO core.audit_trail (
                    audit_category,
                    audit_level,
                    audit_event,
                    audit_description,
                    action,
                    action_status,
                    table_schema,
                    table_name,
                    record_id,
                    new_data
                ) VALUES (
                    'SECURITY',
                    'WARNING',
                    'entitlement_limit_exceeded',
                    'Hard entitlement limit exceeded',
                    'ENFORCEMENT',
                    'DENIED',
                    'app',
                    't_entitlement_limits',
                    v_effective_limit.entitlement_id::TEXT,
                    jsonb_build_object(
                        'membership_id', p_membership_id,
                        'resource_type', p_resource_type,
                        'requested', p_requested_amount,
                        'current_usage', v_effective_limit.current_usage,
                        'limit', v_effective_limit.limit_value
                    )
                );
                    
            WHEN 'soft' THEN
                RETURN QUERY SELECT 
                    TRUE,
                    GREATEST(0, v_effective_limit.limit_value - v_projected_usage),
                    v_effective_limit.limit_value,
                    'log'::TEXT,
                    TRUE,
                    v_effective_limit.target_type;
                    
            WHEN 'burst' THEN
                -- Allow with burst capacity
                RETURN QUERY SELECT 
                    TRUE,
                    GREATEST(0, v_effective_limit.limit_value * 1.5 - v_projected_usage),
                    v_effective_limit.limit_value * 1.5,
                    'notify'::TEXT,
                    TRUE,
                    v_effective_limit.target_type;
                    
            ELSE -- advisory
                RETURN QUERY SELECT 
                    TRUE,
                    GREATEST(0, v_effective_limit.limit_value - v_projected_usage),
                    v_effective_limit.limit_value,
                    'log'::TEXT,
                    FALSE,
                    v_effective_limit.target_type;
        END CASE;
    ELSE
        -- Within limit
        RETURN QUERY SELECT 
            TRUE,
            GREATEST(0, v_effective_limit.limit_value - v_projected_usage),
            v_effective_limit.limit_value,
            'allow'::TEXT,
            v_usage_pct >= v_warning_threshold,
            v_effective_limit.target_type;
    END IF;
    
    -- Check warning threshold
    IF v_usage_pct >= v_warning_threshold AND COALESCE(v_effective_limit.alert_enabled, TRUE) THEN
        PERFORM pg_notify('entitlement_warning', jsonb_build_object(
            'entitlement_id', v_effective_limit.entitlement_id,
            'membership_id', p_membership_id,
            'resource_type', p_resource_type,
            'usage_pct', v_usage_pct,
            'warning_threshold', v_warning_threshold,
            'critical_threshold', v_critical_threshold,
            'severity', CASE 
                WHEN v_usage_pct >= v_critical_threshold THEN 'CRITICAL'
                ELSE 'WARNING'
            END
        )::TEXT);
    END IF;
END;
$$;

-- =============================================================================
-- FUNCTION: app.consume_entitlement()
-- =============================================================================
CREATE OR REPLACE FUNCTION app.consume_entitlement(
    p_membership_id UUID,
    p_resource_type TEXT,
    p_amount NUMERIC DEFAULT 1,
    p_resource_subtype TEXT DEFAULT NULL,
    p_transaction_id UUID DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_check_result RECORD;
    v_entitlement_id UUID;
BEGIN
    -- Check entitlement first
    SELECT * INTO v_check_result
    FROM app.check_entitlement(p_membership_id, p_resource_type, p_amount, p_resource_subtype);
    
    IF NOT v_check_result.allowed THEN
        IF v_check_result.enforcement_action = 'block' THEN
            RAISE EXCEPTION 'Entitlement limit exceeded for %', p_resource_type;
        END IF;
    END IF;
    
    -- Get the entitlement ID for the update
    SELECT entitlement_id INTO v_entitlement_id
    FROM app.t_entitlement_limits
    WHERE resource_type = p_resource_type
      AND (resource_subtype = p_resource_subtype OR resource_subtype IS NULL)
      AND target_type = 'membership' 
      AND target_id = p_membership_id
      AND status = 'active'
    ORDER BY priority ASC
    LIMIT 1;
    
    -- Update usage counters if membership-specific limit exists
    IF v_entitlement_id IS NOT NULL THEN
        UPDATE app.t_entitlement_limits
        SET current_usage = COALESCE(current_usage, 0) + p_amount,
            usage_updated_at = NOW(),
            usage_reset_at = COALESCE(usage_reset_at, NOW())
        WHERE entitlement_id = v_entitlement_id;
    END IF;
    
    -- Log consumption
    INSERT INTO core.audit_trail (
        audit_category,
        audit_level,
        audit_event,
        audit_description,
        action,
        action_status,
        table_schema,
        table_name,
        record_id,
        new_data,
        transaction_id
    ) VALUES (
        'SYSTEM',
        'DEBUG',
        'entitlement_consumed',
        'Entitlement consumed for resource',
        'CONSUMPTION',
        'SUCCESS',
        'app',
        't_entitlement_limits',
        COALESCE(v_entitlement_id::TEXT, 'none'),
        jsonb_build_object(
            'membership_id', p_membership_id,
            'resource_type', p_resource_type,
            'amount', p_amount,
            'remaining', v_check_result.remaining
        ),
        p_transaction_id
    );
    
    RETURN TRUE;
END;
$$;

-- =============================================================================
-- FUNCTION: app.reset_entitlement_window()
-- Background job function to reset usage counters
-- =============================================================================
CREATE OR REPLACE FUNCTION app.reset_entitlement_window(
    p_entitlement_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_old_usage NUMERIC;
    v_limit RECORD;
BEGIN
    SELECT * INTO v_limit
    FROM app.t_entitlement_limits
    WHERE entitlement_id = p_entitlement_id;
    
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    
    v_old_usage := v_limit.current_usage;
    
    -- Reset usage and update window
    UPDATE app.t_entitlement_limits
    SET current_usage = 0,
        usage_reset_at = NOW(),
        window_start = CASE window_type
            WHEN 'fixed' THEN window_end
            ELSE NOW()
        END,
        window_end = CASE window_type
            WHEN 'fixed' THEN window_end + (window_end - window_start)
            ELSE window_end
        END
    WHERE entitlement_id = p_entitlement_id;
    
    -- Log the reset
    INSERT INTO core.audit_trail (
        audit_category,
        audit_level,
        audit_event,
        audit_description,
        action,
        action_status,
        table_schema,
        table_name,
        record_id,
        old_data,
        new_data
    ) VALUES (
        'SYSTEM',
        'INFO',
        'entitlement_usage_reset',
        'Entitlement usage counter reset',
        'MAINTENANCE',
        'SUCCESS',
        'app',
        't_entitlement_limits',
        p_entitlement_id::TEXT,
        jsonb_build_object('previous_usage', v_old_usage),
        jsonb_build_object('new_usage', 0, 'reset_at', NOW())
    );
    
    RETURN TRUE;
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON FUNCTION app.check_entitlement(UUID, TEXT, NUMERIC, TEXT) IS 
    'Check if entitlement request is within limits. ' ||
    'Feature: CORE-APP-FUNC-003. ' ||
    'Compliance: ISO 27001, ISO 27017. ' ||
    'Security: Hierarchical enforcement, audit logging. ' ||
    'Returns: allowed, remaining, limit, action, warning, source.';

COMMENT ON FUNCTION app.reset_entitlement_window(UUID) IS
    'Reset entitlement usage counter for a new window period. Called by background job.';

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Hierarchical limit resolution: membership > role > application > global
-- 2. Usage counters cached for performance, synced periodically
-- 3. Window resets handled by scheduled job calling reset_entitlement_window()
-- 4. Override expiration checked at enforcement time
-- 5. All consumption logged for audit
-- 6. Warning alerts sent via PostgreSQL NOTIFY
-- =============================================================================
