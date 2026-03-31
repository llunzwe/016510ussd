/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - QUOTA ENFORCEMENT FUNCTIONS
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-FUNC-007
 * Feature Name:       Quota and Entitlement Enforcement
 * Description:        Functions for enforcing resource limits, quota tracking,
 *                     and session management. Provides real-time enforcement
 *                     with configurable actions (block, throttle, notify).
 * 
 * Version:            1.0.0
 * Author:             Platform Engineering Team
 * Created:            2026-03-30
 * Last Modified:      2026-03-30
 * 
 * =============================================================================
 * COMPLIANCE & CERTIFICATIONS
 * =============================================================================
 * 
 * ISO/IEC 27001:2022 (ISMS)
 *   - Control A.5.7: Threat intelligence (anomaly detection)
 *   - Control A.8.7: Protection against malware (DoS prevention)
 *   - Control A.8.20: Networks security (rate limiting)
 *   - Control A.8.24: Use of cryptography
 * 
 * ISO/IEC 27017:2015 (Cloud Security)
 *   - Section 6: Asset management
 *   - Section 12: Multi-tenant resource isolation
 * 
 * ISO 9001:2015 (Quality Management)
 *   - Section 7.1.5: Monitoring and measuring resources
 * 
 * SOC 2 Type II
 *   - CC6.1: Logical access controls
 *   - CC7.2: System monitoring
 * 
 * =============================================================================
 * AUDIT TRAIL REQUIREMENTS
 * =============================================================================
 * 
 * MANDATORY AUDIT EVENTS:
 *   - Quota threshold reached (warning/critical)
 *   - Quota exceeded (enforcement action)
 *   - Override granted
 *   - Session limit reached
 *   - Rate limit triggered
 * 
 * AUDIT RETENTION: 3 years (operational)
 * =============================================================================
 */

-- =============================================================================
-- COMPLIANCE STANDARDS
-- =============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework
-- ISO/IEC 27017:2015 - Cloud Security Controls
-- ISO 9001:2015 - Quality Management
-- SOC 2 Type II - Security Controls
-- =============================================================================

-- =============================================================================
-- FUNCTION: Check Entitlement
-- ISO 27001: Resource limit enforcement
-- =============================================================================

CREATE OR REPLACE FUNCTION app.check_entitlement(
    p_app_id UUID,
    p_resource_type VARCHAR(50),
    p_resource_subtype VARCHAR(50) DEFAULT NULL,
    p_target_type VARCHAR(20) DEFAULT 'application',
    p_target_id UUID DEFAULT NULL,
    p_requested_amount NUMERIC DEFAULT 1
)
RETURNS TABLE (
    allowed BOOLEAN,
    current_usage NUMERIC,
    limit_value NUMERIC,
    remaining NUMERIC,
    enforcement_action VARCHAR(20),
    message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = app, core, public
AS $$
DECLARE
    v_entitlement RECORD;
    v_effective_limit NUMERIC;
    v_remaining NUMERIC;
    v_enforcement_action VARCHAR(20);
    v_allowed BOOLEAN;
    v_message TEXT;
    v_threshold_warning NUMERIC;
    v_threshold_critical NUMERIC;
BEGIN
    -- Find applicable entitlement limit (highest priority wins)
    SELECT 
        el.entitlement_id,
        el.limit_type,
        el.limit_value,
        el.current_usage,
        COALESCE(el.override_value, el.limit_value) as effective_limit,
        el.warning_threshold_pct,
        el.critical_threshold_pct,
        el.enforcement_action,
        el.priority
    INTO v_entitlement
    FROM app.t_entitlement_limits el
    WHERE el.app_id = p_app_id
      AND el.resource_type = p_resource_type
      AND (el.resource_subtype = p_resource_subtype OR p_resource_subtype IS NULL)
      AND el.target_type = p_target_type
      AND (el.target_id = p_target_id OR p_target_id IS NULL)
      AND el.status = 'active'
      AND el.effective_from <= NOW()
      AND (el.effective_until IS NULL OR el.effective_until > NOW())
    ORDER BY el.priority ASC, el.created_at DESC
    LIMIT 1;
    
    -- No entitlement found - use application defaults
    IF NOT FOUND THEN
        -- Get application default limits
        SELECT 
            CASE p_resource_type
                WHEN 'transactions' THEN max_transactions_per_minute
                WHEN 'storage' THEN max_storage_gb
                WHEN 'concurrent_sessions' THEN max_concurrent_sessions
                ELSE 1000
            END INTO v_effective_limit
        FROM app.t_application_registry
        WHERE app_id = p_app_id;
        
        IF NOT FOUND THEN
            RETURN QUERY SELECT 
                FALSE, 
                0::NUMERIC, 
                0::NUMERIC, 
                0::NUMERIC, 
                'block'::VARCHAR(20),
                'Application not found'::TEXT;
            RETURN;
        END IF;
        
        v_entitlement := ROW(
            NULL::UUID, 'hard'::VARCHAR(20), v_effective_limit, 
            0::NUMERIC, v_effective_limit, 80::NUMERIC, 95::NUMERIC, 
            'block'::VARCHAR(20), 100::INTEGER
        );
    END IF;
    
    -- Calculate remaining
    v_remaining := GREATEST(0, v_entitlement.effective_limit - v_entitlement.current_usage);
    
    -- Check if allowed
    v_allowed := (v_entitlement.current_usage + p_requested_amount <= v_entitlement.effective_limit);
    
    -- Determine enforcement action if exceeded
    IF NOT v_allowed THEN
        v_enforcement_action := v_entitlement.enforcement_action;
        v_message := format('Quota exceeded: %s/%s %s used', 
            v_entitlement.current_usage, 
            v_entitlement.effective_limit,
            p_resource_type
        );
        
        -- [AUDIT] Log quota exceeded
        INSERT INTO core.t_audit_trail (
            table_name, record_id, action, details, performed_at, result
        ) VALUES (
            'app.t_entitlement_limits',
            COALESCE(v_entitlement.entitlement_id, p_app_id),
            'QUOTA_EXCEEDED',
            jsonb_build_object(
                'resource_type', p_resource_type,
                'current_usage', v_entitlement.current_usage,
                'requested', p_requested_amount,
                'limit', v_entitlement.effective_limit,
                'enforcement', v_enforcement_action
            ),
            NOW(),
            'blocked'
        );
    ELSE
        v_enforcement_action := 'allow';
        
        -- Calculate threshold percentages
        v_threshold_warning := v_entitlement.effective_limit * (v_entitlement.warning_threshold_pct / 100);
        v_threshold_critical := v_entitlement.effective_limit * (v_entitlement.critical_threshold_pct / 100);
        
        -- Check thresholds
        IF v_entitlement.current_usage >= v_threshold_critical THEN
            v_message := format('CRITICAL: %s usage at %.1f%% of limit', 
                p_resource_type,
                (v_entitlement.current_usage / v_entitlement.effective_limit) * 100
            );
            
            -- [AUDIT] Log critical threshold
            INSERT INTO core.t_audit_trail (
                table_name, record_id, action, details, performed_at, severity
            ) SELECT 
                'app.t_entitlement_limits',
                v_entitlement.entitlement_id,
                'THRESHOLD_CRITICAL',
                jsonb_build_object(
                    'resource_type', p_resource_type,
                    'usage_pct', (v_entitlement.current_usage / v_entitlement.effective_limit) * 100
                ),
                NOW(),
                'high';
                
        ELSIF v_entitlement.current_usage >= v_threshold_warning THEN
            v_message := format('WARNING: %s usage at %.1f%% of limit', 
                p_resource_type,
                (v_entitlement.current_usage / v_entitlement.effective_limit) * 100
            );
        ELSE
            v_message := 'OK';
        END IF;
    END IF;
    
    RETURN QUERY SELECT 
        v_allowed,
        v_entitlement.current_usage,
        v_entitlement.effective_limit,
        v_remaining,
        v_enforcement_action::VARCHAR(20),
        v_message;
END;
$$;

COMMENT ON FUNCTION app.check_entitlement IS 
    'Check if resource request is within entitlement limits. ISO 27001: Resource control.';

-- =============================================================================
-- FUNCTION: Record Resource Usage
-- ISO 27001: Usage tracking
-- =============================================================================

CREATE OR REPLACE FUNCTION app.record_usage(
    p_app_id UUID,
    p_resource_type VARCHAR(50),
    p_amount NUMERIC DEFAULT 1,
    p_resource_subtype VARCHAR(50) DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_entitlement_id UUID;
    v_window_reset TIMESTAMPTZ;
    v_window_type VARCHAR(20);
    v_current_usage NUMERIC;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    
    -- Find applicable entitlement
    SELECT entitlement_id, window_type, usage_reset_at, current_usage
    INTO v_entitlement_id, v_window_type, v_window_reset, v_current_usage
    FROM app.t_entitlement_limits
    WHERE app_id = p_app_id
      AND resource_type = p_resource_type
      AND (resource_subtype = p_resource_subtype OR p_resource_subtype IS NULL)
      AND status = 'active'
    ORDER BY priority ASC
    LIMIT 1;
    
    -- Check if window needs reset
    IF v_window_reset IS NOT NULL AND v_window_reset < NOW() THEN
        -- Reset usage counter
        UPDATE app.t_entitlement_limits
        SET current_usage = p_amount,
            usage_reset_at = CASE v_window_type
                WHEN 'rolling' THEN NOW()
                WHEN 'fixed' THEN NOW() + COALESCE(window_duration, INTERVAL '1 hour')
                ELSE NOW() + INTERVAL '1 hour'
            END,
            usage_updated_at = NOW()
        WHERE entitlement_id = v_entitlement_id;
    ELSIF v_entitlement_id IS NOT NULL THEN
        -- Increment usage
        UPDATE app.t_entitlement_limits
        SET current_usage = current_usage + p_amount,
            usage_updated_at = NOW()
        WHERE entitlement_id = v_entitlement_id;
    END IF;
    
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION app.record_usage IS 
    'Record resource usage against entitlement. ISO 27001: Usage tracking.';

-- =============================================================================
-- FUNCTION: Create Entitlement Limit
-- ISO 27017: Resource limit configuration
-- =============================================================================

CREATE OR REPLACE FUNCTION app.create_entitlement(
    p_app_id UUID,
    p_target_type VARCHAR(20),
    p_target_id UUID,
    p_resource_type VARCHAR(50),
    p_resource_subtype VARCHAR(50) DEFAULT NULL,
    p_limit_type VARCHAR(20) DEFAULT 'hard',
    p_limit_value NUMERIC DEFAULT 1000,
    p_limit_unit VARCHAR(20) DEFAULT 'count',
    p_window_type VARCHAR(20) DEFAULT 'rolling',
    p_window_duration INTERVAL DEFAULT INTERVAL '1 hour',
    p_warning_threshold_pct NUMERIC DEFAULT 80,
    p_critical_threshold_pct NUMERIC DEFAULT 95,
    p_enforcement_action VARCHAR(20) DEFAULT 'block',
    p_priority INTEGER DEFAULT 100
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_entitlement_id UUID;
    v_current_membership UUID;
    v_current_user UUID;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_membership := current_setting('app.current_membership_id', TRUE)::UUID;
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Authorization check
    IF NOT app.check_permission(v_current_membership, 'app:entitlement:create') THEN
        RAISE EXCEPTION '[RBAC] Insufficient privileges to create entitlement';
    END IF;
    
    -- Validate inputs
    IF p_target_type NOT IN ('application', 'role', 'membership', 'global') THEN
        RAISE EXCEPTION '[VALIDATION] Invalid target_type: %', p_target_type;
    END IF;
    
    IF p_limit_type NOT IN ('hard', 'soft', 'burst', 'advisory') THEN
        RAISE EXCEPTION '[VALIDATION] Invalid limit_type: %', p_limit_type;
    END IF;
    
    IF p_enforcement_action NOT IN ('block', 'throttle', 'queue', 'log', 'notify') THEN
        RAISE EXCEPTION '[VALIDATION] Invalid enforcement_action: %', p_enforcement_action;
    END IF;
    
    IF p_warning_threshold_pct >= p_critical_threshold_pct THEN
        RAISE EXCEPTION '[VALIDATION] Warning threshold must be less than critical threshold';
    END IF;
    
    -- Create entitlement
    INSERT INTO app.t_entitlement_limits (
        app_id,
        target_type,
        target_id,
        resource_type,
        resource_subtype,
        limit_type,
        limit_value,
        limit_unit,
        window_type,
        window_duration,
        warning_threshold_pct,
        critical_threshold_pct,
        enforcement_action,
        priority,
        created_by,
        updated_by
    ) VALUES (
        p_app_id,
        p_target_type,
        p_target_id,
        p_resource_type,
        p_resource_subtype,
        p_limit_type,
        p_limit_value,
        p_limit_unit,
        p_window_type,
        p_window_duration,
        p_warning_threshold_pct,
        p_critical_threshold_pct,
        p_enforcement_action,
        p_priority,
        v_current_user,
        v_current_user
    )
    RETURNING app.t_entitlement_limits.entitlement_id INTO v_entitlement_id;
    
    -- [AUDIT] Log creation
    INSERT INTO core.t_audit_trail (
        table_name, record_id, action, new_values, performed_by, performed_at
    ) VALUES (
        'app.t_entitlement_limits',
        v_entitlement_id,
        'CREATE',
        jsonb_build_object(
            'app_id', p_app_id,
            'target_type', p_target_type,
            'resource_type', p_resource_type,
            'limit_value', p_limit_value
        ),
        v_current_user,
        NOW()
    );
    
    RETURN v_entitlement_id;
END;
$$;

COMMENT ON FUNCTION app.create_entitlement IS 
    'Create a new entitlement limit. ISO 27017: Resource management.';

-- =============================================================================
-- FUNCTION: Set Entitlement Override
-- ISO 27001: Emergency resource adjustment
-- =============================================================================

CREATE OR REPLACE FUNCTION app.set_entitlement_override(
    p_entitlement_id UUID,
    p_override_value NUMERIC,
    p_duration_hours INTEGER DEFAULT 24,
    p_reason TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_current_membership UUID;
    v_current_user UUID;
    v_old_limit NUMERIC;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_membership := current_setting('app.current_membership_id', TRUE)::UUID;
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Require reason
    IF p_reason IS NULL OR trim(p_reason) = '' THEN
        RAISE EXCEPTION '[VALIDATION] Override reason is required';
    END IF;
    
    -- Authorization check
    IF NOT app.check_permission(v_current_membership, 'app:entitlement:override') THEN
        RAISE EXCEPTION '[RBAC] Insufficient privileges to set entitlement override';
    END IF;
    
    -- Get current limit
    SELECT limit_value INTO v_old_limit
    FROM app.t_entitlement_limits
    WHERE entitlement_id = p_entitlement_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION '[NOT_FOUND] Entitlement % not found', p_entitlement_id;
    END IF;
    
    -- Set override
    UPDATE app.t_entitlement_limits
    SET override_value = p_override_value,
        override_expires_at = NOW() + (p_duration_hours || ' hours')::INTERVAL,
        override_reason = p_reason,
        overridden_by = v_current_user,
        updated_at = NOW(),
        updated_by = v_current_user
    WHERE entitlement_id = p_entitlement_id;
    
    -- [AUDIT] Log override with high severity
    INSERT INTO core.t_audit_trail (
        table_name, record_id, action, 
        old_values, new_values, 
        performed_by, performed_at, severity
    ) VALUES (
        'app.t_entitlement_limits',
        p_entitlement_id,
        'OVERRIDE_SET',
        jsonb_build_object('limit_value', v_old_limit),
        jsonb_build_object(
            'override_value', p_override_value,
            'reason', p_reason,
            'expires_at', NOW() + (p_duration_hours || ' hours')::INTERVAL
        ),
        v_current_user,
        NOW(),
        'high'
    );
    
    -- Send notification
    PERFORM pg_notify('quota_alert', jsonb_build_object(
        'type', 'override_set',
        'entitlement_id', p_entitlement_id,
        'old_limit', v_old_limit,
        'override_value', p_override_value,
        'reason', p_reason
    )::TEXT);
    
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION app.set_entitlement_override IS 
    'Set temporary entitlement override. ISO 27001: Emergency adjustment.';

-- =============================================================================
-- FUNCTION: Check Session Limit
-- ISO 27001: Session management
-- =============================================================================

CREATE OR REPLACE FUNCTION app.check_session_limit(
    p_app_id UUID,
    p_user_identity_id UUID DEFAULT NULL
)
RETURNS TABLE (
    allowed BOOLEAN,
    current_sessions INTEGER,
    max_sessions INTEGER,
    message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = app, core, public
AS $$
DECLARE
    v_max_sessions INTEGER;
    v_current_sessions INTEGER;
    v_allowed BOOLEAN;
BEGIN
    -- Get application session limit
    SELECT max_concurrent_sessions INTO v_max_sessions
    FROM app.t_application_registry
    WHERE app_id = p_app_id;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, 0, 0, 'Application not found'::TEXT;
        RETURN;
    END IF;
    
    -- Count current active sessions for user in app
    -- Note: This assumes a sessions table exists
    SELECT COUNT(*) INTO v_current_sessions
    FROM app.agent_sessions
    WHERE user_id = COALESCE(p_user_identity_id, current_setting('app.current_user_id', TRUE)::UUID)
      AND status IN ('active', 'processing', 'waiting_input');
    
    v_allowed := (v_current_sessions < v_max_sessions);
    
    RETURN QUERY SELECT 
        v_allowed,
        v_current_sessions,
        v_max_sessions,
        CASE 
            WHEN v_allowed THEN 'Session allowed'
            ELSE format('Session limit reached: %s/%s sessions', v_current_sessions, v_max_sessions)
        END;
END;
$$;

COMMENT ON FUNCTION app.check_session_limit IS 
    'Check if new session is allowed within limits. ISO 27001: Session control.';

-- =============================================================================
-- FUNCTION: Track Session Start
-- ISO 27001: Session creation tracking
-- =============================================================================

CREATE OR REPLACE FUNCTION app.track_session_start(
    p_app_id UUID,
    p_session_id TEXT,
    p_agent_type VARCHAR(100) DEFAULT 'conversational',
    p_model_id UUID DEFAULT NULL,
    p_ttl_seconds INTEGER DEFAULT 86400
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_session_uuid UUID;
    v_user_id UUID;
    v_current_user UUID;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    v_user_id := COALESCE(v_current_user, gen_random_uuid());
    
    -- Check session limit first
    IF NOT (SELECT allowed FROM app.check_session_limit(p_app_id, v_user_id)) THEN
        RAISE EXCEPTION '[QUOTA] Session limit exceeded for application';
    END IF;
    
    -- Create session record
    INSERT INTO app.agent_sessions (
        session_id,
        agent_type,
        model_id,
        user_id,
        status,
        started_at,
        last_activity_at,
        expires_at,
        ttl_seconds,
        created_by
    ) VALUES (
        p_session_id,
        p_agent_type,
        p_model_id,
        v_user_id,
        'active',
        NOW(),
        NOW(),
        NOW() + (p_ttl_seconds || ' seconds')::INTERVAL,
        p_ttl_seconds,
        v_current_user
    )
    RETURNING id INTO v_session_uuid;
    
    -- Record usage
    PERFORM app.record_usage(p_app_id, 'concurrent_sessions', 1);
    
    RETURN v_session_uuid;
END;
$$;

COMMENT ON FUNCTION app.track_session_start IS 
    'Track a new session start. ISO 27001: Session management.';

-- =============================================================================
-- FUNCTION: Track Session End
-- ISO 27001: Session termination tracking
-- =============================================================================

CREATE OR REPLACE FUNCTION app.track_session_end(
    p_session_id TEXT,
    p_status VARCHAR(20) DEFAULT 'completed'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_session_record RECORD;
    v_current_user UUID;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Get session details
    SELECT id, user_id, status INTO v_session_record
    FROM app.agent_sessions
    WHERE session_id = p_session_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION '[NOT_FOUND] Session % not found', p_session_id;
    END IF;
    
    -- Update session status
    UPDATE app.agent_sessions
    SET status = p_status,
        updated_at = NOW(),
        updated_by = v_current_user,
        deleted_at = CASE WHEN p_status IN ('completed', 'terminated', 'expired') THEN NOW() ELSE NULL END
    WHERE session_id = p_session_id;
    
    -- Decrement usage (if session was active)
    IF v_session_record.status IN ('active', 'processing', 'waiting_input') THEN
        -- Note: Usage tracking for decrement would need separate counter
        -- or use current session count directly
        NULL;
    END IF;
    
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION app.track_session_end IS 
    'Track session end/termination. ISO 27001: Session management.';

-- =============================================================================
-- FUNCTION: Get Quota Status
-- Dashboard helper
-- =============================================================================

CREATE OR REPLACE FUNCTION app.get_quota_status(p_app_id UUID)
RETURNS TABLE (
    resource_type VARCHAR(50),
    current_usage NUMERIC,
    limit_value NUMERIC,
    usage_pct NUMERIC,
    status TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = app, core, public
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        el.resource_type::VARCHAR(50),
        el.current_usage,
        COALESCE(el.override_value, el.limit_value) as limit_value,
        ROUND((el.current_usage / NULLIF(COALESCE(el.override_value, el.limit_value), 0)) * 100, 2) as usage_pct,
        CASE 
            WHEN el.current_usage >= COALESCE(el.override_value, el.limit_value) * (el.critical_threshold_pct / 100) 
                THEN 'CRITICAL'
            WHEN el.current_usage >= COALESCE(el.override_value, el.limit_value) * (el.warning_threshold_pct / 100) 
                THEN 'WARNING'
            ELSE 'OK'
        END::TEXT as status
    FROM app.t_entitlement_limits el
    WHERE el.app_id = p_app_id
      AND el.status = 'active'
    ORDER BY el.resource_type;
END;
$$;

COMMENT ON FUNCTION app.get_quota_status IS 
    'Get quota status summary for an application.';

-- =============================================================================
-- FUNCTION: Reset Usage Counters
-- Periodic maintenance
-- =============================================================================

CREATE OR REPLACE FUNCTION app.reset_expired_usage_counters()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_reset_count INTEGER := 0;
BEGIN
    -- Reset usage for expired windows
    UPDATE app.t_entitlement_limits
    SET current_usage = 0,
        usage_reset_at = NOW(),
        usage_updated_at = NOW()
    WHERE status = 'active'
      AND usage_reset_at < NOW();
    
    GET DIAGNOSTICS v_reset_count = ROW_COUNT;
    
    RETURN v_reset_count;
END;
$$;

COMMENT ON FUNCTION app.reset_expired_usage_counters IS 
    'Reset usage counters for expired time windows. Run periodically.';

-- =============================================================================
-- ANALYZE for query optimizer
-- =============================================================================
ANALYZE app.t_entitlement_limits;
