-- ============================================================================
-- FUNCTION: resume_session
-- ============================================================================
-- Purpose: Resume a recently expired or interrupted USSD session,
--          allowing users to continue from where they left off.
-- Context: USSD sessions can be interrupted by network issues, timeouts,
--          or accidental session closure. This function enables recovery
--          within a limited window (typically 5 minutes).
--
-- COMPLIANCE & STANDARDS:
--   ISO/IEC 27001:2022 - Information Security Management
--     * A.8.1: Endpoint security - device verification on resume
--     * A.8.5: Re-authentication for sensitive state resumption
--     * A.8.11: Session recovery with security controls
--     * A.8.12: Audit logging of resume events
--
--   ISO/IEC 27018:2019 - PII Protection
--     * Context sanitization before restoration
--     * Sensitive data clearance (PIN attempts, tokens)
--     * Privacy-preserving recovery metadata
--
--   ISO/IEC 27035-2:2023 - Incident Management
--     * SIM swap check between original and resume time
--     * Fraud pattern detection for resume abuse
--     * Security termination detection
--
--   ISO 31000:2018 - Risk Management
--     * Risk-based recovery level determination
--     * Partial recovery for high-risk scenarios
--     * Velocity check on resume attempts
--
-- RESUME FLOW:
--   1. User dials resume shortcode (*123*99#) or original shortcode
--   2. Gateway calls resume_session()
--   3. Function finds recent session within recovery window
--   4. Creates new session with restored context
--   5. Returns to previous menu state
--
-- RECOVERY LEVELS:
--   FULL:    Complete state restoration (< 2 min, non-sensitive state)
--   PARTIAL: Safe checkpoint restoration (2-5 min, clear sensitive inputs)
--   AUTH_REQUIRED: Resume with re-authentication (CONFIRM state)
--   BLOCKED: Cannot resume (SYSTEM_CANCEL, fraud detected, SIM swap)
--
-- SECURITY FEATURES:
--   - Device fingerprint matching verification
--   - SIM swap detection between sessions
--   - Context sanitization (clear PIN attempts, tokens)
--   - Advisory locks for concurrent resume prevention
--   - Original session marking as RESUMED (one-time)
--
-- ENTERPRISE CODING PRACTICES:
--   - SECURITY DEFINER with restricted execution
--   - Idempotent resume (same result for duplicate calls)
--   - Comprehensive audit trail linking old/new sessions
--   - Graceful degradation on verification failures
-- ============================================================================

CREATE OR REPLACE FUNCTION resume_session(
    -- Identification
    p_msisdn VARCHAR(15),
    p_resuming_shortcode VARCHAR(50),
    
    -- New session metadata
    p_operator_code VARCHAR(6),
    p_network_session_id VARCHAR(128),
    p_source_ip INET,
    p_user_agent VARCHAR(256) DEFAULT NULL,
    p_device_fingerprint_hash VARCHAR(64) DEFAULT NULL,
    
    -- Resume options
    p_target_session_id UUID DEFAULT NULL, -- Specific session to resume
    p_recovery_window_minutes INT DEFAULT 5
)
RETURNS TABLE (
    success BOOLEAN,
    new_session_id UUID,
    resumed_session_id UUID,
    current_state VARCHAR(32),
    current_menu_id VARCHAR(64),
    restored_context JSONB,
    is_partial_recovery BOOLEAN,
    recovery_message VARCHAR(256),
    security_flags TEXT[]
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_target_session RECORD;
    v_new_session_id UUID;
    v_restored_context JSONB;
    v_is_partial_recovery BOOLEAN := FALSE;
    v_recovery_message VARCHAR(256);
    v_security_flags TEXT[] := ARRAY[]::TEXT[];
    v_expires_at TIMESTAMPTZ;
    v_can_resume BOOLEAN := TRUE;
    v_new_session_hash VARCHAR(64);
    v_resumable_states TEXT[] := ARRAY['MENU', 'INPUT', 'CONFIRM', 'PROCESS'];
BEGIN
    -- ========================================================================
    -- TODO [RESUME-001]: Validate resume eligibility
    -- ========================================================================
    /*
    TODO: Implement comprehensive resume validation
      - Check if MSISDN has recent sessions eligible for recovery
      - Validate session is within recovery window
      - Verify session was in resumable state (not COMPLETED)
      - Check if application supports session resume
      - Validate device fingerprint matches (if strict mode)
    */
    
    -- Find target session
    IF p_target_session_id IS NOT NULL THEN
        -- Specific session requested
        SELECT * INTO v_target_session
        FROM ussd_session_state
        WHERE session_id = p_target_session_id
          AND msisdn = p_msisdn
          AND current_state = ANY(v_resumable_states)
          AND completed_at > NOW() - (p_recovery_window_minutes || ' minutes')::INTERVAL;
    ELSE
        -- Find most recent eligible session
        SELECT * INTO v_target_session
        FROM ussd_session_state
        WHERE msisdn = p_msisdn
          AND (
              -- Recently expired sessions
              (is_active = FALSE AND completion_status = 'TIMEOUT' 
               AND completed_at > NOW() - (p_recovery_window_minutes || ' minutes')::INTERVAL)
              OR
              -- Or still active but interrupted
              (is_active = TRUE AND expires_at > NOW())
          )
          AND current_state = ANY(v_resumable_states)
        ORDER BY 
            CASE WHEN is_active THEN 0 ELSE 1 END, -- Active first
            last_activity_at DESC
        LIMIT 1;
    END IF;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT 
            FALSE, NULL::UUID, NULL::UUID, NULL::VARCHAR(32),
            NULL::VARCHAR(64), NULL::JSONB, FALSE, 
            'No eligible session found for recovery. Please start a new session.'::VARCHAR(256),
            ARRAY['NO_ELIGIBLE_SESSION']::TEXT[];
        RETURN;
    END IF;

    -- ========================================================================
    -- TODO [RESUME-002]: Verify security for resume
    -- ========================================================================
    /*
    TODO: Implement security checks for session resumption
      - Verify device fingerprint matches original session
      - Check for SIM swap since original session
      - Validate no suspicious activity detected
      - Require additional verification for sensitive states
      - Check if session was terminated for security reasons
    */
    
    -- Check for SIM swap since original session
    IF v_target_session.device_fingerprint_id IS NOT NULL THEN
        -- TODO: Query for SIM swap since session start
        -- If swap detected, may need to restrict or block resume
        NULL;
    END IF;
    
    -- Security check: Don't resume if session was terminated for fraud
    IF v_target_session.completion_status = 'SYSTEM_CANCEL' THEN
        v_can_resume := FALSE;
        v_security_flags := array_append(v_security_flags, 'SECURITY_TERMINATED');
    END IF;

    -- ========================================================================
    -- TODO [RESUME-003]: Determine recovery level
    -- ========================================================================
    /*
    TODO: Implement tiered recovery based on session state and elapsed time
      - Full recovery: < 2 min, non-sensitive state
      - Partial recovery: 2-5 min, restore to safe checkpoint
      - No recovery: > 5 min or sensitive transaction in progress
      
    Recovery levels:
      FULL: Restore exact state and context
      PARTIAL: Restore to last safe menu, clear sensitive inputs
      AUTH_REQUIRED: Resume but require re-authentication
      BLOCKED: Cannot resume, start fresh
    */
    
    IF v_target_session.current_state = 'PROCESS' THEN
        -- Don't resume mid-transaction
        v_is_partial_recovery := TRUE;
        v_target_session.current_state := 'MENU';
        v_recovery_message := 'Your previous transaction was interrupted. Please start again.';
        v_security_flags := array_append(v_security_flags, 'PARTIAL_RECOVERY_TX_INTERRUPTED');
    ELSIF v_target_session.current_state = 'CONFIRM' THEN
        -- Require re-auth for confirmation resumption
        v_is_partial_recovery := TRUE;
        v_target_session.auth_level := 'NONE'; -- Force re-auth
        v_security_flags := array_append(v_security_flags, 'REAUTH_REQUIRED');
    ELSIF v_target_session.completed_at IS NOT NULL AND
          v_target_session.completed_at < NOW() - INTERVAL '2 minutes' THEN
        -- Partial recovery for older sessions
        v_is_partial_recovery := TRUE;
        v_recovery_message := 'Welcome back! Continuing your session.';
    ELSE
        -- Full recovery
        v_recovery_message := 'Session resumed.';
    END IF;

    -- ========================================================================
    -- TODO [RESUME-004]: Restore and sanitize context
    -- ========================================================================
    /*
    TODO: Implement context restoration
      - Decrypt original session context
      - Sanitize sensitive data based on recovery level
      - Clear one-time tokens and PIN attempts
      - Update timestamps
      - Add resume metadata to context
    
    Context cleanup:
      - Clear: pin_attempts, temp_tokens, otp_codes
      - Keep: user_inputs (non-sensitive), navigation_stack, preferences
      - Add: resumed_from_session_id, resume_count, original_created_at
    */
    
    -- Placeholder: Build restored context
    v_restored_context := jsonb_build_object(
        'resumed_from_session_id', v_target_session.session_id,
        'original_created_at', v_target_session.created_at,
        'recovery_level', CASE WHEN v_is_partial_recovery THEN 'PARTIAL' ELSE 'FULL' END,
        'previous_state', v_target_session.current_state,
        'navigation_stack', '[]'::JSONB -- Restore from original
    );

    -- ========================================================================
    -- TODO [RESUME-005]: Calculate new expiration
    -- ========================================================================
    /*
    TODO: Set appropriate timeout for resumed session
      - Base timeout from original session or route config
      - Consider elapsed time since original start
      - Apply shorter timeout for resumed sessions
      - Absolute maximum from original session creation
    */
    
    v_expires_at := LEAST(
        NOW() + INTERVAL '90 seconds', -- Resumed session timeout
        v_target_session.created_at + INTERVAL '10 minutes' -- Absolute max
    );

    -- ========================================================================
    -- TODO [RESUME-006]: Create new session record
    -- ========================================================================
    /*
    TODO: Insert new session with restored context
      - Generate new session_id (don't reuse)
      - Link to original via resumed_from_session_id
      - Copy relevant security context
      - Encrypt restored context
      - Calculate hash for audit chain
    */
    
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
        v_target_session.current_state,
        p_resuming_shortcode,
        v_target_session.application_id,
        v_target_session.current_menu_id,
        '\x00', -- Placeholder: encrypt_context(v_restored_context)
        1,
        'kms-key-001',
        v_target_session.device_fingerprint_id,
        v_target_session.auth_level,
        0, -- Reset pin attempts
        NOW(),
        NOW(),
        v_expires_at,
        p_resuming_shortcode,
        p_network_session_id,
        p_source_ip,
        p_user_agent,
        TRUE,
        'TODO_NEW_HASH',
        v_target_session.session_hash
    )
    RETURNING ussd_session_state.session_id INTO v_new_session_id;

    -- ========================================================================
    -- TODO [RESUME-007]: Update original session
    -- ========================================================================
    /*
    TODO: Mark original session as resumed
      - Set completion_status to 'RESUMED'
      - Link to new session
      - Prevent duplicate resumption
      - Update audit trail
    */
    
    UPDATE ussd_session_state
    SET completion_status = 'RESUMED',
        completed_at = NOW(),
        is_active = FALSE
        -- Add column: resumed_to_session_id UUID
    WHERE session_id = v_target_session.session_id;

    -- ========================================================================
    -- TODO [RESUME-008]: Log resume event
    -- ========================================================================
    /*
    TODO: Write audit records
      - Session resume event to ledger
      - Link original and new sessions
      - Include recovery level and security flags
      - Update device fingerprint history
    */

    -- ========================================================================
    -- TODO [RESUME-009]: Handle concurrent resume attempts
    -- ========================================================================
    /*
    TODO: Prevent race conditions on resume
      - Use advisory lock on MSISDN during resume
      - Check if session already resumed
      - Handle simultaneous resume attempts gracefully
      - Return same new session for duplicate attempts
    */

    -- Return results
    RETURN QUERY SELECT 
        v_can_resume,
        v_new_session_id,
        v_target_session.session_id,
        v_target_session.current_state,
        v_target_session.current_menu_id,
        v_restored_context,
        v_is_partial_recovery,
        v_recovery_message,
        v_security_flags;

END;
$$;

-- ----------------------------------------------------------------------------
-- TODO: IMPLEMENTATION NOTES
-- ----------------------------------------------------------------------------

/*
TODO [PERF-001]: Optimize resume lookup
  - Create partial index on (msisdn, completed_at) for timeout recovery
  - Cache recent sessions in Redis for faster lookup
  - Use bloom filter to quickly check if resume possible
  - Target p99 < 100ms for resume operations

TODO [UX-001]: User experience considerations
  - Provide clear messaging about recovery level
  - Show what was restored vs. what needs re-entry
  - Allow user to decline resume and start fresh
  - Consider SMS notification of resumed session

TODO [SEC-001]: Security hardening
  - Limit resume attempts per MSISDN (max 3 per window)
  - Require additional verification for high-value sessions
  - Block resume if fraud detected on original session
  - Log all resume attempts for analysis

TODO [COMP-001]: Compliance considerations
  - Some regulations may require fresh auth after timeout
   b  - Implement jurisdiction-specific resume policies
  - Retain audit trail of original + resumed sessions
  - Consider data residency for cross-region resume
*/

-- ----------------------------------------------------------------------------
-- SECURITY CONSIDERATIONS
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.1 - Device verification on resume
-- [ISO/IEC 27001:2022] A.8.5 - Re-authentication requirements
-- [ISO/IEC 27035-2:2023] Fraud detection on resume attempts
-- [ISO/IEC 27018:2019] Context sanitization before restoration
/*
1. SESSION HIJACKING PREVENTION:
   - Verify device fingerprint matches before allowing resume
   - Require re-authentication for sensitive states
   - Limit resume window (5 minutes recommended)
   - Log all resume attempts with full context

2. CONTEXT SANITIZATION:
   - Never restore PIN attempts or auth tokens
   - Clear temporary codes and one-time data
   - Re-validate all restored inputs
   - Mark sensitive fields for re-entry

3. REPLAY ATTACK PREVENTION:
   - Each resume creates new session_id
   - Original session marked as RESUMED (one-time)
   - Include resume count in context
   - Alert on excessive resume patterns

4. CONCURRENT RESUME HANDLING:
   - Use distributed locks to prevent race conditions
   - Return consistent result for duplicate attempts
   - Prevent session forking (two active sessions from one resume)
   - Clean up on resume failure

5. AUDIT REQUIREMENTS:
   - Link original and resumed sessions in audit trail
   - Include recovery level in logs
   - Record security decisions and flags
   - Retain per regulatory requirements
*/

-- ----------------------------------------------------------------------------
-- SESSION TIMEOUT HANDLING
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.11 - Recovery window: 5 minutes default
-- Resumed session timeout: 60-90 seconds (shorter than new)
-- Maximum extensions: 1 for resumed sessions
-- Cascade timeout: Parent session expiration affects resumed
/*
Session resume timeout considerations:

1. RECOVERY WINDOW:
   - Default: 5 minutes from session timeout/interruption
   - Configurable per application
   - Shorter window for financial transactions (2 minutes)
   - Consider time-of-day (shorter at night)

2. TIMEOUT ADJUSTMENT:
   - Resumed sessions have shorter timeout (60-90 seconds)
   - Count down from original absolute maximum
   - Show remaining time in menu footer
   - Allow one extension for resumed sessions

3. PARTIAL RECOVERY TIMEOUTS:
   - If partial recovery, extend window slightly
   - Account for re-entry time
   - Don't penalize user for system interruption
   - Grace period for sensitive operations

4. CASCADE TIMEOUTS:
   - If parent session times out, child resumed session also expires
   - Maintain original absolute deadline
   - Alert user if resuming near absolute timeout
   - Prioritize completion over data collection

5. CLEANUP:
   - Resumed sessions cleaned up normally after completion
   - If resumed session times out, offer second resume (once)
   - After second timeout, require fresh start
   - Archive both sessions together
*/

-- ----------------------------------------------------------------------------
-- SIM SWAP DETECTION INTEGRATION
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27035-2:2023] Pre-resume SIM swap verification
-- [GSMA IR.71] Swap between sessions = High risk
-- SIM swap 0-24h: Block resume entirely
-- SIM swap 24-72h: Partial recovery + OTP required
/*
SIM swap detection during session resume:

1. PRE-RESUME CHECKS:
   - Query SIM swap status between original and resume time
   - If swap detected, evaluate risk level
   - Recent swap (< 72h) may block resume
   - Always require additional verification post-swap

2. RISK-BASED RESUME RESTRICTIONS:
   - SIM swap 0-24h: Block resume entirely
   - SIM swap 24-72h: Partial recovery only, require OTP
   - SIM swap 72h-7d: Full recovery with warning
   - > 7 days: Normal resume

3. DEVICE CORRELATION:
   - Compare device fingerprint at resume vs. original
   - If different device + SIM swap = high risk
   - If same device + SIM swap = possible legitimate swap
   - Update device_fingerprints with swap correlation

4. RESUME VALIDATION:
   - SMS notification to previous device (if technically possible)
   - Require PIN even if previously authenticated
   - Reduce transaction limits for resumed post-swap session
   - Flag for transaction monitoring

5. AUDIT CORRELATION:
   - Link resume event to any SIM swap events
   - Include swap status in security_flags
   - Extended retention for post-swap sessions
   - Feed into behavioral baseline updates
*/

-- Grant execute permission
-- GRANT EXECUTE ON FUNCTION resume_session TO ussd_gateway_role;
