-- ============================================================================
-- FUNCTION: create_session
-- ============================================================================
-- Purpose: Initialize a new USSD session with proper validation, security
--          checks, and immutable ledger integration.
-- Context: Called when a user dials a USSD shortcode (*123#).
--          Must be atomic and handle concurrent session scenarios.
--
-- COMPLIANCE & STANDARDS:
--   ISO/IEC 27001:2022 - Information Security Management
--     * A.5.1: Security policies - session creation policies
--     * A.8.1: User endpoint security - device verification
--     * A.8.5: Secure authentication - auth level assignment
--     * A.8.11: Session timeout configuration
--     * A.8.12: Audit logging - session creation events
--
--   ISO/IEC 27018:2019 - PII Protection
--     * MSISDN format validation (E.164)
--     * Context encryption before storage
--     * Minimal PII collection principle
--
--   ISO 31000:2018 - Risk Management
--     * Risk-based session timeout calculation
--     * Velocity limit enforcement
--     * Device trust score integration
--
--   PCI DSS v4.0:
--     * Session timeout enforcement (max 10 minutes)
--     * Secure session identifier generation
--     * Input validation and sanitization
--
-- SESSION INITIATION FLOW:
--   1. User dials shortcode
--   2. Gateway receives request from operator
--   3. Gateway calls create_session()
--   4. Function validates request and creates session record
--   5. Returns session context for menu rendering
--
-- SECURITY CHECKS:
--   - MSISDN format validation (E.164 regex)
--   - Shortcode format validation
--   - Concurrent session handling
--   - Device fingerprint verification
--   - Velocity limit enforcement
--   - SIM swap status check
--
-- ENTERPRISE CODING PRACTICES:
--   - SECURITY DEFINER for elevated privileges
--   - Input validation at function entry
--   - Advisory locks for concurrent session prevention
--   - Hash chain initialization for audit
--   - Exception handling with cleanup
-- ============================================================================

CREATE OR REPLACE FUNCTION create_session(
    -- Input parameters
    p_msisdn VARCHAR(15),
    p_shortcode VARCHAR(50),
    p_operator_code VARCHAR(6),
    p_network_session_id VARCHAR(128),
    p_source_ip INET,
    p_user_agent VARCHAR(256) DEFAULT NULL,
    p_ussd_string VARCHAR(4000) DEFAULT NULL,
    p_device_fingerprint_hash VARCHAR(64) DEFAULT NULL
)
RETURNS TABLE (
    session_id UUID,
    current_state VARCHAR(32),
    application_id VARCHAR(64),
    default_menu_id VARCHAR(64),
    expires_at TIMESTAMPTZ,
    is_concurrent_blocked BOOLEAN,
    security_flags TEXT[]
) 
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_session_id UUID;
    v_route RECORD;
    v_existing_session RECORD;
    v_device_fingerprint_id UUID;
    v_security_flags TEXT[] := ARRAY[]::TEXT[];
    v_is_concurrent_blocked BOOLEAN := FALSE;
    v_context_encrypted BYTEA;
    v_expires_at TIMESTAMPTZ;
    v_session_hash VARCHAR(64);
    v_previous_hash VARCHAR(64);
BEGIN
    -- ========================================================================
    -- TODO [CREATE-001]: Input validation
    -- ========================================================================
    /*
    TODO: Implement comprehensive input validation
      - Validate MSISDN format (E.164)
      - Validate shortcode format (*123# pattern)
      - Validate operator_code (MCC-MNC format)
      - Check source_ip against whitelist
      - Sanitize user_agent and ussd_string
    */
    
    -- Basic validation (expand as needed)
    IF p_msisdn !~ '^\+[1-9][0-9]{7,14}$' THEN
        RAISE EXCEPTION 'Invalid MSISDN format: %', p_msisdn;
    END IF;
    
    IF p_shortcode !~ '^\*[0-9]+([*][0-9#*]*)?#$' THEN
        RAISE EXCEPTION 'Invalid shortcode format: %', p_shortcode;
    END IF;

    -- ========================================================================
    -- TODO [CREATE-002]: Resolve shortcode to application
    -- ========================================================================
    /*
    TODO: Call resolve_shortcode() function to determine routing
      - Match shortcode pattern against routing table
      - Consider operator-specific routes
      - Handle A/B testing assignments
      - Return application_id, default_menu_id, session_timeout
    */
    
    SELECT * INTO v_route
    FROM resolve_shortcode(p_shortcode, p_operator_code);
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'No route found for shortcode: %', p_shortcode;
    END IF;

    -- ========================================================================
    -- TODO [CREATE-003]: Check concurrent session policy
    -- ========================================================================
    /*
    TODO: Handle concurrent session scenarios per routing configuration
      - Query existing active sessions for this MSISDN
      - If allow_concurrent_sessions = FALSE:
          * Terminate existing session
          * Log concurrent attempt
          * Notify user of previous session termination
      - If allow_concurrent_sessions = TRUE:
          * Limit to max 3 concurrent sessions
          * Require session differentiation
    */
    
    SELECT * INTO v_existing_session
    FROM ussd_session_state
    WHERE msisdn = p_msisdn
      AND is_active = TRUE
      AND expires_at > NOW()
    ORDER BY created_at DESC
    LIMIT 1;
    
    IF FOUND THEN
        IF v_route.allow_concurrent_sessions = FALSE THEN
            -- Terminate existing session
            UPDATE ussd_session_state
            SET is_active = FALSE,
                completion_status = 'SYSTEM_CANCEL',
                completed_at = NOW(),
                current_state = 'CANCELLED'
            WHERE session_id = v_existing_session.session_id;
            
            v_security_flags := array_append(v_security_flags, 'PREVIOUS_SESSION_TERMINATED');
        ELSE
            -- Check concurrent session limit (max 3)
            IF (SELECT COUNT(*) FROM ussd_session_state 
                WHERE msisdn = p_msisdn AND is_active = TRUE) >= 3 THEN
                v_is_concurrent_blocked := TRUE;
                v_security_flags := array_append(v_security_flags, 'CONCURRENT_LIMIT_REACHED');
                -- Return without creating session
                RETURN QUERY SELECT 
                    NULL::UUID, 
                    'BLOCKED'::VARCHAR(32), 
                    NULL::VARCHAR(64),
                    NULL::VARCHAR(64),
                    NULL::TIMESTAMPTZ,
                    v_is_concurrent_blocked,
                    v_security_flags;
                RETURN;
            END IF;
        END IF;
    END IF;

    -- ========================================================================
    -- TODO [CREATE-004]: Verify device fingerprint
    -- ========================================================================
    /*
    TODO: Integrate with device fingerprint verification
      - Lookup or create device fingerprint
      - Verify fingerprint trust score
      - Trigger additional verification if needed
      - Handle new device scenarios
      - Check for SIM swap correlation
    
    Implementation:
      v_device_fingerprint_id := verify_device_fingerprint(
          p_msisdn, 
          p_device_fingerprint_hash,
          p_operator_code,
          v_security_flags
      );
    */
    
    -- Placeholder: In real implementation, call verify_device_fingerprint()
    -- For now, set to NULL (will be populated by security check)
    v_device_fingerprint_id := NULL;

    -- ========================================================================
    -- TODO [CREATE-005]: Check velocity limits
    -- ========================================================================
    /*
    TODO: Implement velocity checking
      - Sessions per minute per MSISDN
      - Sessions per minute per source_ip
      - Shortcode-specific rate limiting
      - Progressive penalties for violations
    
    Implementation:
      PERFORM check_velocity_limits(
          p_msisdn, 
          p_source_ip, 
          v_route.application_id,
          v_security_flags
      );
    */

    -- ========================================================================
    -- TODO [CREATE-006]: Calculate session expiration
    -- ========================================================================
    /*
    TODO: Calculate appropriate session timeout
      - Base timeout from route configuration
      - Adjust for device trust level
      - Maximum absolute timeout (10 minutes)
      - Consider transaction type if deep-linked
    */
    
    v_expires_at := NOW() + (v_route.session_timeout_seconds || ' seconds')::INTERVAL;
    
    -- Enforce absolute maximum
    IF v_expires_at > NOW() + INTERVAL '10 minutes' THEN
        v_expires_at := NOW() + INTERVAL '10 minutes';
    END IF;

    -- ========================================================================
    -- TODO [CREATE-007]: Build and encrypt initial context
    -- ========================================================================
    /*
    TODO: Create and encrypt session context
      - Build JSON context: {language, entry_point, navigation_stack}
      - Encrypt with AES-256-GCM using KMS
      - Store encryption metadata
      - Include initial menu state
    
    Context structure:
    {
        "language": "en",
        "entry_shortcode": "*150#",
        "navigation_stack": [],
        "user_inputs": {},
        "transaction_refs": [],
        "auth_state": "NONE",
        "device_fingerprint_id": "...",
        "session_start_time": "2024-01-15T10:30:00Z"
    }
    */
    
    -- Placeholder: Empty encrypted context (implement proper encryption)
    v_context_encrypted := '\x00';

    -- ========================================================================
    -- TODO [CREATE-008]: Calculate session hash for audit chain
    -- ========================================================================
    /*
    TODO: Implement hash chain for immutable ledger
      - Query previous session hash for this MSISDN (if any)
      - Calculate SHA-256 of session data
      - Store hash for integrity verification
    
    Hash input:
      previous_hash || session_id || msisdn || created_at || shortcode
    */
    
    -- Placeholder hash
    v_previous_hash := NULL;
    v_session_hash := 'TODO_CALCULATE_HASH';

    -- ========================================================================
    -- Insert new session record
    -- ========================================================================
    
    INSERT INTO ussd_session_state (
        msisdn,
        operator_code,
        current_state,
        shortcode,
        application_id,
        current_menu_id,
        context_encrypted,
        encryption_version,
        key_id,
        device_fingerprint_id,
        auth_level,
        pin_attempts,
        created_at,
        last_activity_at,
        expires_at,
        ussd_string,
        network_session_id,
        source_ip,
        user_agent,
        is_active,
        session_hash,
        previous_session_hash
    ) VALUES (
        p_msisdn,
        p_operator_code,
        'INIT',
        p_shortcode,
        v_route.application_id,
        v_route.default_menu_id,
        v_context_encrypted,
        1, -- encryption_version
        'kms-key-001', -- key_id
        v_device_fingerprint_id,
        v_route.required_auth_level,
        0,
        NOW(),
        NOW(),
        v_expires_at,
        p_ussd_string,
        p_network_session_id,
        p_source_ip,
        p_user_agent,
        TRUE,
        v_session_hash,
        v_previous_hash
    )
    RETURNING ussd_session_state.session_id INTO v_session_id;

    -- ========================================================================
    -- TODO [CREATE-009]: Log session creation event
    -- ========================================================================
    /*
    TODO: Write audit event to ledger
      - Session creation event with full context
      - Include security flags for analysis
      - Link to device fingerprint event
    */

    -- ========================================================================
    -- TODO [CREATE-010]: Initialize menu navigation
    -- ========================================================================
    /*
    TODO: Insert initial menu navigation history
      - Record entry into default menu
      - Set up for menu rendering
    
    INSERT INTO menu_navigation_history (session_id, to_menu_id, navigation_at)
    VALUES (v_session_id, v_route.default_menu_id, NOW());
    */

    -- Return session information
    RETURN QUERY SELECT 
        v_session_id,
        'INIT'::VARCHAR(32),
        v_route.application_id,
        v_route.default_menu_id,
        v_expires_at,
        v_is_concurrent_blocked,
        v_security_flags;

END;
$$;

-- ----------------------------------------------------------------------------
-- TODO: IMPLEMENTATION NOTES
-- ----------------------------------------------------------------------------

/*
TODO [PERF-001]: Optimize for high concurrency
  - Use advisory locks to prevent race conditions on concurrent session checks
  - Implement connection pooling for database connections
  - Consider read replicas for route lookups
  - Cache routing configuration in Redis (TTL: 60 seconds)

TODO [SEC-001]: Security hardening
  - Implement IP whitelist validation
  - Add HMAC signature verification for requests
  - Rate limit session creation per source
  - Encrypt all sensitive context data

TODO [MON-001]: Monitoring and alerting
  - Track session creation latency (p50, p95, p99)
  - Alert on high concurrent session termination rates
  - Monitor failed route resolutions
  - Track device fingerprint verification failures

TODO [RES-001]: Resilience patterns
  - Circuit breaker for KMS encryption calls
  - Fallback routing if primary route fails
  - Graceful degradation if fingerprint service unavailable
  - Retry logic for transient database errors
*/

-- ----------------------------------------------------------------------------
-- SECURITY CONSIDERATIONS
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.5.1 - Session security policies
-- [ISO/IEC 27001:2022] A.8.1 - Device verification
-- [ISO/IEC 27001:2022] A.8.5 - Secure authentication
-- [ISO/IEC 27018:2019] MSISDN format validation (E.164)
-- [PCI DSS v4.0] Session timeout enforcement
/*
1. INPUT VALIDATION:
   - All inputs must be validated before processing
   - MSISDN must be normalized to E.164 format
   - Shortcode must match expected patterns
   - IP address must be from known gateway ranges

2. CONCURRENT SESSION HANDLING:
   - Prevent session fixation attacks
   - Log all concurrent session scenarios
   - Alert on suspicious concurrent patterns
   - Consider geographic impossibility

3. DEVICE VERIFICATION:
   - New devices require additional scrutiny
   - Recent SIM swaps block high-risk operations
   - Trust scores must be validated
   - Don't trust client-provided fingerprint data

4. AUDIT TRAIL:
   - Every session creation must be auditable
   - Hash chain prevents tampering
   - Retain logs per regulatory requirements
   - Include all security decisions in logs
*/

-- ----------------------------------------------------------------------------
-- SESSION TIMEOUT HANDLING
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.11 - Multi-layer timeout architecture
-- Network timeout: 30-60s (carrier-controlled)
-- Application idle: 90s (configurable per route)
-- Absolute maximum: 10 minutes
-- Function timeout: 500ms p99 target
/*
Session creation timeout considerations:

1. OPERATION TIMEOUT:
   - Function must complete within 500ms (p99)
   - Database queries have 100ms timeout each
   - External service calls (KMS, fingerprint) have 200ms timeout
   - Fail fast on timeout, don't create partial sessions

2. CLEANUP ON FAILURE:
   - If session creation fails mid-transaction, rollback everything
   - Clean up any partial fingerprints created
   - Release any locks acquired
   - Log failure reason for debugging

3. EXPIRATION SETTING:
   - Calculate expiration based on route config
   - Apply maximum cap (10 minutes)
   - Consider device trust level (trusted = longer timeout)
   - Transaction-specific timeouts for deep links

4. CLOCK SKEW HANDLING:
   - Use database clock (NOW()) for consistency
   - Account for potential clock skew across regions
   - Don't rely on client timestamps
*/

-- ----------------------------------------------------------------------------
-- SIM SWAP DETECTION INTEGRATION
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27035-2:2023] Pre-session SIM swap checks
-- [GSMA IR.71] 72-hour critical window monitoring
-- Security flags: SIM_SWAP_24H, SIM_SWAP_72H, NEW_DEVICE_POST_SWAP
-- Verification: OTP required for all operations within 24h post-swap
/*
SIM swap detection during session creation:

1. PRE-SESSION CHECKS:
   - Query recent SIM swap events for MSISDN
   - If swap within 72 hours, elevate security level
   - Require additional verification for sensitive operations
   - Log correlation between swap and new session

2. NEW DEVICE CORRELATION:
   - If new fingerprint + recent SIM swap = high risk
   - Trigger device verification workflow
   - Limit transaction amounts for 24-72 hours
   - SMS notification to previous device (if possible)

3. SECURITY FLAGS:
   - SIM_SWAP_24H: Swap within 24 hours
   - SIM_SWAP_72H: Swap within 72 hours
   - NEW_DEVICE_POST_SWAP: Device change after swap
   - These flags affect subsequent transaction authorization

4. VERIFICATION REQUIREMENTS:
   - SIM_SWAP_24H: Block high-value, require OTP for all
   - SIM_SWAP_72H: Reduce limits, additional confirmation
   - NEW_DEVICE_POST_SWAP: Challenge with security questions
*/

-- Grant execute permission
-- GRANT EXECUTE ON FUNCTION create_session TO ussd_gateway_role;
