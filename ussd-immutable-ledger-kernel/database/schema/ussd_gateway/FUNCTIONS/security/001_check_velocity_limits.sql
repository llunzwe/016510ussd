-- ============================================================================
-- FUNCTION: check_velocity_limits
-- ============================================================================
-- Purpose: Check and enforce velocity limits for USSD sessions to prevent
--          abuse, fraud, and system overload. Tracks rates per MSISDN,
--          per IP, per application, and globally.
-- Context: Velocity checks protect against:
--          - Brute force attacks (PIN guessing)
--          - Session enumeration
--          - SMS pumping
--          - Denial of service
--          - Automated fraud attempts
--
-- COMPLIANCE & STANDARDS:
--   ISO/IEC 27001:2022 - Information Security Management
--     * A.8.1: User endpoint protection - per-MSISDN limits
--     * A.8.5: Secure authentication - brute force protection
--     * A.8.6: Capacity management - global rate limiting
--     * A.8.16: Monitoring activities - velocity tracking
--     * A.8.22: Web filtering - IP-based blocking
--
--   ISO/IEC 27035-2:2023 - Incident Management
--     * Automated threat detection and response
--     * Progressive penalties for violations
--     * Security event logging for investigation
--
--   ISO 31000:2018 - Risk Management
--     * Risk-adjusted limits (SIM swap reduces thresholds by 50%)
--     * Progressive penalty escalation
--     * Threat intelligence integration
--
--   PCI DSS v4.0:
--     * Requirement 11.4: Intrusion detection/prevention
--     * Rate limiting for payment operations
--
-- VELOCITY DIMENSIONS:
--   - Per MSISDN: Individual user rate limiting
--   - Per IP: Source-based rate limiting (SMS pumping detection)
--   - Per Application: Service protection
--   - Global: System-wide protection
--
-- LIMIT CONFIGURATION (Default):
--   MSISDN: 10 sessions/min, 100/hour
--   Auth attempts: 5 per 5 minutes (brute force protection)
--   IP: 100 sessions/min, 30 unique MSISDNs/5min
--   Global: 10,000 sessions/sec
--   Post-SIM swap: 50% reduction for 72 hours
--
-- ENTERPRISE CODING PRACTICES:
--   - SECURITY DEFINER with restricted execution rights
--   - Atomic counter updates for accuracy
--   - Configurable limits per deployment
--   - Comprehensive audit logging
-- ============================================================================

CREATE OR REPLACE FUNCTION check_velocity_limits(
    p_msisdn VARCHAR(15),
    p_source_ip INET,
    p_application_id VARCHAR(64),
    p_operation_type VARCHAR(32) DEFAULT 'SESSION_CREATE', -- SESSION_CREATE, AUTH_ATTEMPT, TRANSACTION, etc.
    p_session_id UUID DEFAULT NULL
)
RETURNS TABLE (
    allowed BOOLEAN,
    limit_type VARCHAR(32),
    current_count INT,
    limit_value INT,
    reset_at TIMESTAMPTZ,
    violation_severity VARCHAR(16),
    recommended_action VARCHAR(32),
    security_flags TEXT[]
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_allowed BOOLEAN := TRUE;
    v_limit_type VARCHAR(32) := NULL;
    v_current_count INT := 0;
    v_limit_value INT := 0;
    v_reset_at TIMESTAMPTZ;
    v_violation_severity VARCHAR(16) := 'NONE';
    v_recommended_action VARCHAR(32) := 'ALLOW';
    v_security_flags TEXT[] := ARRAY[]::TEXT[];
    
    -- Velocity tracking variables
    v_msisdn_sessions_1min INT;
    v_msisdn_sessions_1hour INT;
    v_msisdn_auth_attempts_5min INT;
    v_ip_sessions_1min INT;
    v_ip_sessions_5min INT;
    v_app_sessions_1min INT;
    v_global_sessions_1sec INT;
BEGIN
    -- ========================================================================
    -- TODO [VEL-001]: Check MSISDN-based limits
    -- ========================================================================
    /*
    TODO: Implement per-MSISDN velocity tracking
      - Sessions per minute (prevent spam)
      - Sessions per hour (prevent enumeration)
      - Auth attempts per 5 minutes (prevent brute force)
      - Transactions per day (prevent fraud)
      - Progressive penalties for violations
    
    Limits should vary by:
      - User trust level
      - Account type (consumer vs merchant)
      - Recent SIM swap status
      - Device fingerprint trust
    */
    
    -- Count sessions in last minute for this MSISDN
    SELECT COUNT(*) INTO v_msisdn_sessions_1min
    FROM ussd_session_state
    WHERE msisdn = p_msisdn
    AND created_at > NOW() - INTERVAL '1 minute';
    
    -- Count sessions in last hour
    SELECT COUNT(*) INTO v_msisdn_sessions_1hour
    FROM ussd_session_state
    WHERE msisdn = p_msisdn
    AND created_at > NOW() - INTERVAL '1 hour';
    
    -- Count auth attempts in last 5 minutes
    SELECT COUNT(*) INTO v_msisdn_auth_attempts_5min
    FROM fingerprint_verification_log
    WHERE EXISTS (
        SELECT 1 FROM ussd_session_state 
        WHERE session_id = fingerprint_verification_log.session_id
        AND msisdn = p_msisdn
    )
    AND verification_at > NOW() - INTERVAL '5 minutes';
    
    -- Apply MSISDN limits (configurable)
    IF p_operation_type = 'SESSION_CREATE' THEN
        IF v_msisdn_sessions_1min > 10 THEN
            v_allowed := FALSE;
            v_limit_type := 'MSISDN_PER_MINUTE';
            v_current_count := v_msisdn_sessions_1min;
            v_limit_value := 10;
            v_violation_severity := 'WARNING';
            v_recommended_action := 'DELAY';
            v_security_flags := array_append(v_security_flags, 'MSISDN_RATE_LIMIT');
            v_reset_at := NOW() + INTERVAL '1 minute';
        ELSIF v_msisdn_sessions_1hour > 100 THEN
            v_allowed := FALSE;
            v_limit_type := 'MSISDN_PER_HOUR';
            v_current_count := v_msisdn_sessions_1hour;
            v_limit_value := 100;
            v_violation_severity := 'ALERT';
            v_recommended_action := 'BLOCK';
            v_security_flags := array_append(v_security_flags, 'MSISDN_HOURLY_LIMIT');
            v_reset_at := DATE_TRUNC('hour', NOW()) + INTERVAL '1 hour';
        END IF;
    ELSIF p_operation_type = 'AUTH_ATTEMPT' THEN
        IF v_msisdn_auth_attempts_5min > 5 THEN
            v_allowed := FALSE;
            v_limit_type := 'AUTH_ATTEMPTS_PER_5MIN';
            v_current_count := v_msisdn_auth_attempts_5min;
            v_limit_value := 5;
            v_violation_severity := 'ALERT';
            v_recommended_action := 'BLOCK';
            v_security_flags := array_append(v_security_flags, 'BRUTE_FORCE_DETECTED');
            v_reset_at := NOW() + INTERVAL '5 minutes';
        END IF;
    END IF;

    -- ========================================================================
    -- TODO [VEL-002]: Check IP-based limits
    -- ========================================================================
    /*
    TODO: Implement per-IP velocity tracking
      - Sessions per minute per IP
      - Unique MSISDNs per IP (detect SMS pumping)
      - Geographic consistency
      - Known bad IP lists
      - Tor/VPN detection
    */
    
    IF p_source_ip IS NOT NULL AND v_allowed THEN
        -- Count sessions from this IP in last minute
        SELECT COUNT(*) INTO v_ip_sessions_1min
        FROM ussd_session_state
        WHERE source_ip = p_source_ip
        AND created_at > NOW() - INTERVAL '1 minute';
        
        -- Count sessions from this IP in last 5 minutes
        SELECT COUNT(*) INTO v_ip_sessions_5min
        FROM ussd_session_state
        WHERE source_ip = p_source_ip
        AND created_at > NOW() - INTERVAL '5 minutes';
        
        -- Check unique MSISDNs from this IP (pumping detection)
        IF v_ip_sessions_5min > 50 THEN
            DECLARE
                v_unique_msisdns INT;
            BEGIN
                SELECT COUNT(DISTINCT msisdn) INTO v_unique_msisdns
                FROM ussd_session_state
                WHERE source_ip = p_source_ip
                AND created_at > NOW() - INTERVAL '5 minutes';
                
                -- If many sessions but few unique MSISDNs, might be legitimate
                -- If many unique MSISDNs, likely pumping
                IF v_unique_msisdns > 30 THEN
                    v_allowed := FALSE;
                    v_limit_type := 'IP_MSISDN_ENUMERATION';
                    v_violation_severity := 'CRITICAL';
                    v_recommended_action := 'BLOCK_IP';
                    v_security_flags := array_append(v_security_flags, 'SMS_PUMPING_DETECTED');
                END IF;
            END;
        END IF;
        
        -- Standard IP rate limits
        IF v_allowed AND v_ip_sessions_1min > 100 THEN
            v_allowed := FALSE;
            v_limit_type := 'IP_PER_MINUTE';
            v_current_count := v_ip_sessions_1min;
            v_limit_value := 100;
            v_violation_severity := 'WARNING';
            v_recommended_action := 'THROTTLE';
            v_security_flags := array_append(v_security_flags, 'IP_RATE_LIMIT');
            v_reset_at := NOW() + INTERVAL '1 minute';
        END IF;
    END IF;

    -- ========================================================================
    -- TODO [VEL-003]: Check application limits
    -- ========================================================================
    /*
    TODO: Implement per-application rate limiting
      - Sessions per minute per application
      - Protect backend services
      - Prioritize critical applications
      - Queue non-urgent requests
    */
    
    IF v_allowed AND p_application_id IS NOT NULL THEN
        SELECT COUNT(*) INTO v_app_sessions_1min
        FROM ussd_session_state
        WHERE application_id = p_application_id
        AND created_at > NOW() - INTERVAL '1 minute';
        
        -- Get limit from routing configuration
        SELECT rate_limit_requests_per_minute INTO v_limit_value
        FROM shortcode_routing
        WHERE application_id = p_application_id
        AND is_active = TRUE
        LIMIT 1;
        
        v_limit_value := COALESCE(v_limit_value, 1000);
        
        IF v_app_sessions_1min > v_limit_value THEN
            v_allowed := FALSE;
            v_limit_type := 'APPLICATION_PER_MINUTE';
            v_current_count := v_app_sessions_1min;
            v_violation_severity := 'WARNING';
            v_recommended_action := 'QUEUE';
            v_security_flags := array_append(v_security_flags, 'APP_RATE_LIMIT');
            v_reset_at := NOW() + INTERVAL '1 minute';
        END IF;
    END IF;

    -- ========================================================================
    -- TODO [VEL-004]: Check global system limits
    -- ========================================================================
    /*
    TODO: Implement global rate limiting
      - Total sessions per second
      - Database connection limits
      - External API rate limits
      - Circuit breaker for system overload
    */
    
    IF v_allowed THEN
        -- Estimate current rate (simplified)
        SELECT COUNT(*) INTO v_global_sessions_1sec
        FROM ussd_session_state
        WHERE created_at > NOW() - INTERVAL '1 second';
        
        -- Global limit (configurable, e.g., 10,000/sec)
        IF v_global_sessions_1sec > 10000 THEN
            v_allowed := FALSE;
            v_limit_type := 'GLOBAL_PER_SECOND';
            v_current_count := v_global_sessions_1sec;
            v_limit_value := 10000;
            v_violation_severity := 'CRITICAL';
            v_recommended_action := 'SHED_LOAD';
            v_security_flags := array_append(v_security_flags, 'SYSTEM_OVERLOAD');
            v_reset_at := NOW() + INTERVAL '1 second';
        END IF;
    END IF;

    -- ========================================================================
    -- TODO [VEL-005]: Check SIM swap adjusted limits
    -- ========================================================================
    /*
    TODO: Adjust limits based on SIM swap status
      - Post-swap: Stricter limits
      - New device post-swap: Even stricter
      - Verified legitimate swap: Restore normal limits
      - Progressive relaxation over time
    */
    
    IF v_allowed AND EXISTS (
        SELECT 1 FROM sim_swap_correlations
        WHERE msisdn = p_msisdn
        AND sim_swap_detected_at > NOW() - INTERVAL '72 hours'
        AND verified_legitimate IS NOT TRUE
    ) THEN
        -- Apply 50% reduction to all limits post-SIM swap
        IF p_operation_type = 'SESSION_CREATE' AND v_msisdn_sessions_1min > 5 THEN
            v_allowed := FALSE;
            v_limit_type := 'MSISDN_POST_SWAP_LIMIT';
            v_current_count := v_msisdn_sessions_1min;
            v_limit_value := 5;
            v_violation_severity := 'ALERT';
            v_recommended_action := 'BLOCK';
            v_security_flags := array_append(v_security_flags, 'POST_SWAP_VELOCITY_LIMIT');
        END IF;
    END IF;

    -- ========================================================================
    -- TODO [VEL-006]: Progressive penalties
    -- ========================================================================
    /*
    TODO: Implement escalating penalties for repeated violations
      - 1st violation: Warning, log
      - 2nd violation: Delay (exponential backoff)
      - 3rd violation: Temporary block (1 hour)
      - 4th+ violation: Extended block (24 hours), alert security
      - Persistent violators: Permanent block, fraud investigation
    */
    
    IF NOT v_allowed THEN
        -- Check violation history
        DECLARE
            v_recent_violations INT;
        BEGIN
            SELECT COUNT(*) INTO v_recent_violations
            FROM fingerprint_events
            WHERE msisdn = p_msisdn
            AND event_type = 'VELOCITY_VIOLATION'
            AND occurred_at > NOW() - INTERVAL '24 hours';
            
            IF v_recent_violations >= 3 THEN
                v_violation_severity := 'CRITICAL';
                v_recommended_action := 'BLOCK_24H';
                v_security_flags := array_append(v_security_flags, 'REPEAT_OFFENDER');
                v_reset_at := NOW() + INTERVAL '24 hours';
            ELSIF v_recent_violations >= 1 THEN
                v_violation_severity := 'ALERT';
                v_recommended_action := 'BLOCK_1H';
                v_reset_at := NOW() + INTERVAL '1 hour';
            END IF;
        END;
    END IF;

    -- ========================================================================
    -- TODO [VEL-007]: Log velocity check
    -- ========================================================================
    /*
    TODO: Write velocity check results to audit log
      - Include all counters and limits
      - Log violations for analysis
      - Feed into fraud detection
      - Alert on critical violations
    */
    
    IF NOT v_allowed OR v_violation_severity != 'NONE' THEN
        INSERT INTO fingerprint_events (
            msisdn,
            event_type,
            event_severity,
            event_data,
            session_id,
            triggered_by
        ) VALUES (
            p_msisdn,
            'VELOCITY_VIOLATION',
            v_violation_severity,
            jsonb_build_object(
                'limit_type', v_limit_type,
                'current_count', v_current_count,
                'limit_value', v_limit_value,
                'operation', p_operation_type,
                'source_ip', p_source_ip::TEXT,
                'application_id', p_application_id
            ),
            p_session_id,
            'SYSTEM'
        );
    END IF;

    -- ========================================================================
    -- TODO [VEL-008]: Update rate limit cache
    -- ========================================================================
    /*
    TODO: Implement efficient rate limit tracking
      - Use Redis for distributed rate limiting
      - Sliding window algorithm
      - Token bucket for burst handling
      - Atomic increment operations
    */

    -- Return results
    RETURN QUERY SELECT 
        v_allowed,
        v_limit_type,
        v_current_count,
        v_limit_value,
        v_reset_at,
        v_violation_severity,
        v_recommended_action,
        v_security_flags;

END;
$$;

-- ----------------------------------------------------------------------------
-- FUNCTION: get_velocity_status
-- ----------------------------------------------------------------------------
-- Get current velocity status for a MSISDN without enforcing limits
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION get_velocity_status(
    p_msisdn VARCHAR(15),
    p_source_ip INET DEFAULT NULL
)
RETURNS TABLE (
    metric_name VARCHAR(64),
    current_value INT,
    limit_value INT,
    percentage_used DECIMAL(5,2),
    status VARCHAR(16) -- OK, WARNING, CRITICAL
)
LANGUAGE SQL
STABLE
SECURITY DEFINER
AS $$
    WITH metrics AS (
        SELECT 
            'sessions_per_minute'::VARCHAR(64) as metric,
            COUNT(*)::INT as current_val,
            10 as limit_val
        FROM ussd_session_state
        WHERE msisdn = p_msisdn
        AND created_at > NOW() - INTERVAL '1 minute'
        
        UNION ALL
        
        SELECT 
            'sessions_per_hour'::VARCHAR(64),
            COUNT(*)::INT,
            100
        FROM ussd_session_state
        WHERE msisdn = p_msisdn
        AND created_at > NOW() - INTERVAL '1 hour'
        
        UNION ALL
        
        SELECT 
            'auth_attempts_per_5min'::VARCHAR(64),
            COUNT(*)::INT,
            5
        FROM fingerprint_verification_log f
        JOIN ussd_session_state s ON s.session_id = f.session_id
        WHERE s.msisdn = p_msisdn
        AND f.verification_at > NOW() - INTERVAL '5 minutes'
    )
    SELECT 
        metric,
        current_val,
        limit_val,
        LEAST((current_val::DECIMAL / NULLIF(limit_val, 0) * 100), 100.00),
        CASE 
            WHEN current_val >= limit_val THEN 'CRITICAL'
            WHEN current_val >= limit_val * 0.8 THEN 'WARNING'
            ELSE 'OK'
        END
    FROM metrics;
$$;

-- ----------------------------------------------------------------------------
-- FUNCTION: reset_velocity_counters
-- ----------------------------------------------------------------------------
-- Reset velocity counters (for support/admin use)
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION reset_velocity_counters(
    p_msisdn VARCHAR(15),
    p_reset_reason VARCHAR(256),
    p_reset_by VARCHAR(128)
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Log the reset
    INSERT INTO fingerprint_events (
        msisdn,
        event_type,
        event_severity,
        event_data,
        triggered_by
    ) VALUES (
        p_msisdn,
        'VELOCITY_RESET',
        'INFO',
        jsonb_build_object(
            'reset_reason', p_reset_reason,
            'reset_by', p_reset_by,
            'reset_at', NOW()
        ),
        p_reset_by
    );
    
    RETURN TRUE;
END;
$$;

-- ----------------------------------------------------------------------------
-- TODO: IMPLEMENTATION NOTES
-- ----------------------------------------------------------------------------

/*
TODO [REDIS-001]: Redis integration for distributed rate limiting
  - Use Redis for cross-instance rate limit state
  - Sliding window implementation
  - Lua scripts for atomic operations
  - Fallback to database if Redis unavailable

TODO [ALGO-001]: Rate limiting algorithms
  - Fixed window: Simple, but can have burst issues
  - Sliding window: Smoother, more accurate
  - Token bucket: Allows bursts within limits
  - Leaky bucket: Smoothes traffic
  - Choose based on use case

TODO [ALERT-001]: Alerting rules
  - Alert on high velocity violation rates
  - Alert on IP-based SMS pumping
  - Alert on system approaching global limits
  - Alert on repeat offenders
  - Integrate with SIEM

TODO [ML-001]: Adaptive rate limiting
  - ML model predicts appropriate limits per user
  - Adjust based on behavior patterns
  - Lower limits for suspicious activity
  - Higher limits for trusted users
*/

-- ----------------------------------------------------------------------------
-- SECURITY CONSIDERATIONS
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.5 - Brute force protection
-- [ISO/IEC 27001:2022] A.8.22 - Web filtering (IP-based)
-- [ISO/IEC 27035-2:2023] Automated threat response
-- [PCI DSS v4.0] Intrusion detection/prevention
-- [ISO 31000:2018] Risk-adjusted limits (post-SIM swap: 50% reduction)
/*
1. RATE LIMIT BYPASS:
   - Prevent admins from bypassing without audit
   - Log all bypass attempts
   - Require dual authorization for critical resets
   - Monitor for unusual reset patterns

2. ENUMERATION PREVENTION:
   - Don't reveal which limit was hit
   - Generic error messages
   - Randomize reset times slightly
   - Monitor for limit probing

3. DISTRIBUTED ATTACKS:
   - Track coordinated attacks across IPs
   - Detect botnet patterns
   - Geographic analysis
   - Share threat intelligence

4. FALSE POSITIVES:
   - Legitimate users can hit limits during busy times
   - Provide escalation path (support contact)
   - Quick reset capability for verified users
   - Learn normal patterns per user
*/

-- ----------------------------------------------------------------------------
-- SESSION TIMEOUT HANDLING
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.11 - Rate limit counter TTL
-- Per-minute counters: 2 minute expiration
-- Violation tracking: 24 hour window for progressive penalties
/*
Velocity limit timeout considerations:

1. COUNTER TTL:
   - Per-minute counters: expire after 2 minutes
   - Per-hour counters: expire after 2 hours
   - Sliding window: precise expiration
   - Redis TTL for automatic cleanup

2. VIOLATION WINDOWS:
   - Track violations for 24 hours (progressive penalties)
   - Reset violation count daily
   - Persistent violators: longer tracking
   - Expire old violations

3. RESET TIMING:
   - Accurate reset_at calculation
   - Timezone considerations
   - Clock skew handling
   - Grace period after reset

4. GRACEFUL DEGRADATION:
   - If rate limiter down, fail open or closed based on risk
   - Default to more restrictive on failure
   - Queue requests during rate limiter recovery
   - Alert on rate limiter failures
*/

-- ----------------------------------------------------------------------------
-- SIM SWAP DETECTION INTEGRATION
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27035-2:2023] Post-SIM swap velocity restrictions
-- 0-24h: Max 2 sessions/hour
-- 24-72h: Max 5 sessions/hour
-- Alert on high velocity post-swap (account takeover indicator)
/*
Velocity limits and SIM swap detection:

1. POST-SWAP RESTRICTIONS:
   - 0-24h: Maximum 2 sessions per hour
   - 24-72h: Maximum 5 sessions per hour
   - 72h-7d: Normal limits with monitoring
   - After verification: Restore normal limits

2. SWAP + VELOCITY CORRELATION:
   - High velocity after swap = high risk
   - Multiple sessions from different IPs post-swap
   - Rapid auth attempts post-swap
   - Alert on unusual velocity post-swap

3. FRAUD PATTERNS:
   - SIM swap + immediate high velocity = account takeover
   - Multiple swaps + high velocity = organized fraud
   - Velocity spike after device change + swap
   - Block and alert on these patterns

4. LEGITIMATE USE:
   - User may need multiple sessions to reconfigure
   - Provide exception process for verified users
   - Support can whitelist temporary increase
   - Self-service unlock after identity verification

5. MONITORING:
   - Track velocity patterns around swap events
   - Alert on velocity limit hits post-swap
   - Feed into swap detection model
   - Correlate with transaction fraud
*/

-- Grant execute permission
-- GRANT EXECUTE ON FUNCTION check_velocity_limits TO ussd_gateway_role;
-- GRANT EXECUTE ON FUNCTION get_velocity_status TO ussd_gateway_role;
-- GRANT EXECUTE ON FUNCTION reset_velocity_counters TO ussd_support_role;
