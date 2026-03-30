-- ============================================================================
-- FUNCTION: update_session_context
-- ============================================================================
-- Purpose: Update session state, context, and navigation during active USSD
--          session. Handles state machine transitions and maintains audit trail.
-- Context: Called on each user interaction within a USSD session.
--          Must be atomic and handle concurrent update scenarios.
--
-- COMPLIANCE & STANDARDS:
--   ISO/IEC 27001:2022 - Information Security Management
--     * A.8.1: Endpoint security - session validation
--     * A.8.5: Authentication state management
--     * A.8.11: Session timeout extension (activity-based)
--     * A.8.12: Audit trail for all state changes
--     * A.8.15: Logging - navigation history
--
--   ISO/IEC 27018:2019 - PII Protection
--     * Context data encryption on update
--     * Sensitive key validation against whitelist
--     * Input sanitization before processing
--
--   ISO/IEC 27035-2:2023 - Incident Management
--     * SIM swap risk evaluation on sensitive transitions
--     * Anomaly detection for rapid state changes
--     * Security flag propagation
--
--   ISO 31000:2018 - Risk Management
--     * Risk-based authentication requirements
--     * State transition validation
--     * Progressive timeout adjustment
--
-- SESSION UPDATE FLOW:
--   1. User submits input (selection or text)
--   2. Gateway calls update_session_context()
--   3. Function validates session is active
--   4. Updates state and context
--   5. Returns next menu/state to gateway
--
-- STATE MACHINE:
--   INIT -> MENU -> INPUT -> VALIDATE -> PROCESS -> CONFIRM -> COMPLETE
--     |       |       |         |          |         |          |
--     v       v       v         v          v         v          v
--  TIMEOUT  ERROR   CANCELLED (terminal states)
--
-- SECURITY FEATURES:
--   - SELECT FOR UPDATE for concurrency control
--   - Context key whitelist validation
--   - Auth level step-up verification
--   - PIN attempt tracking and lockout
--   - Session hash chain update
--
-- ENTERPRISE CODING PRACTICES:
--   - SECURITY DEFINER with restricted permissions
--   - Row-level locking for session updates
--   - Immutable navigation history logging
--   - Graceful error handling with audit
-- ============================================================================

CREATE OR REPLACE FUNCTION update_session_context(
    -- Session identification
    p_session_id UUID,
    p_msisdn VARCHAR(15),
    
    -- User input
    p_user_input VARCHAR(400),
    p_current_menu_id VARCHAR(64),
    
    -- Context updates
    p_context_updates JSONB DEFAULT NULL,
    p_new_state VARCHAR(32) DEFAULT NULL,
    p_target_menu_id VARCHAR(64) DEFAULT NULL,
    
    -- Security
    p_auth_action VARCHAR(32) DEFAULT NULL, -- 'PIN_ENTERED', 'OTP_VERIFIED', etc.
    p_auth_data VARCHAR(256) DEFAULT NULL,
    
    -- Metadata
    p_source_ip INET DEFAULT NULL
)
RETURNS TABLE (
    success BOOLEAN,
    new_state VARCHAR(32),
    new_menu_id VARCHAR(64),
    session_expired BOOLEAN,
    auth_required BOOLEAN,
    auth_challenge VARCHAR(32),
    error_message VARCHAR(256),
    security_flags TEXT[]
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_session RECORD;
    v_context_decrypted JSONB;
    v_context_updated JSONB;
    v_new_state VARCHAR(32);
    v_new_menu_id VARCHAR(64);
    v_security_flags TEXT[] := ARRAY[]::TEXT[];
    v_session_expired BOOLEAN := FALSE;
    v_auth_required BOOLEAN := FALSE;
    v_auth_challenge VARCHAR(32) := NULL;
    v_error_message VARCHAR(256) := NULL;
    v_new_hash VARCHAR(64);
    v_menu_transition_id BIGINT;
    v_pin_attempts INT;
BEGIN
    -- ========================================================================
    -- TODO [UPDATE-001]: Validate session exists and is active
    -- ========================================================================
    /*
    TODO: Implement robust session validation
      - Lock session row for update (SELECT FOR UPDATE)
      - Verify session hasn't expired
      - Verify MSISDN matches session
      - Check session is not finalized
      - Handle race conditions with cleanup job
    */
    
    SELECT * INTO v_session
    FROM ussd_session_state
    WHERE session_id = p_session_id
      AND msisdn = p_msisdn
      AND is_active = TRUE
    FOR UPDATE;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT 
            FALSE, NULL::VARCHAR(32), NULL::VARCHAR(64), 
            TRUE, FALSE, NULL::VARCHAR(32), 
            'Session not found or inactive'::VARCHAR(256),
            ARRAY['SESSION_NOT_FOUND']::TEXT[];
        RETURN;
    END IF;
    
    -- Check expiration
    IF v_session.expires_at < NOW() THEN
        v_session_expired := TRUE;
        v_security_flags := array_append(v_security_flags, 'SESSION_EXPIRED');
        
        -- Mark session as expired
        UPDATE ussd_session_state
        SET current_state = 'TIMEOUT',
            completion_status = 'TIMEOUT',
            is_active = FALSE,
            completed_at = NOW()
        WHERE session_id = p_session_id;
        
        RETURN QUERY SELECT 
            FALSE, 'TIMEOUT'::VARCHAR(32), NULL::VARCHAR(64),
            TRUE, FALSE, NULL::VARCHAR(32),
            'Session has expired. Please dial again.'::VARCHAR(256),
            v_security_flags;
        RETURN;
    END IF;

    -- ========================================================================
    -- TODO [UPDATE-002]: Decrypt and validate context
    -- ========================================================================
    /*
    TODO: Implement context decryption and validation
      - Decrypt context_encrypted using KMS
      - Validate context structure
      - Check for context tampering
      - Handle decryption failures gracefully
    
    Implementation:
      v_context_decrypted := decrypt_context(
          v_session.context_encrypted,
          v_session.key_id,
          v_session.encryption_version
      );
    */
    
    -- Placeholder: Empty context
    v_context_decrypted := '{}'::JSONB;

    -- ========================================================================
    -- TODO [UPDATE-003]: Process authentication actions
    -- ========================================================================
    /*
    TODO: Handle authentication state transitions
      - PIN entry validation
      - OTP verification
      - Biometric result processing
      - Track failed attempts
      - Lockout after max attempts
    
    Implementation:
      IF p_auth_action = 'PIN_ENTERED' THEN
          IF NOT validate_pin(p_msisdn, p_auth_data) THEN
              v_pin_attempts := v_session.pin_attempts + 1;
              IF v_pin_attempts >= 5 THEN
                  -- Lock session, require support
                  v_security_flags := array_append(v_security_flags, 'PIN_LOCKED');
              END IF;
          END IF;
      END IF;
    */
    
    v_pin_attempts := v_session.pin_attempts;

    -- ========================================================================
    -- TODO [UPDATE-004]: Apply context updates
    -- ========================================================================
    /*
    TODO: Merge context updates securely
      - Validate all keys in p_context_updates against whitelist
      - Prevent injection of reserved keys
      - Sanitize string values
      - Handle nested JSON updates
      - Update navigation stack for back functionality
    
    Reserved keys (cannot be updated directly):
      - session_id, msisdn, created_at, encryption_version
      
    Navigation stack update:
      IF p_target_menu_id IS NOT NULL THEN
          v_context_updated['navigation_stack'] = 
              v_context_decrypted['navigation_stack'] || p_current_menu_id;
      END IF;
    */
    
    v_context_updated := COALESCE(v_context_decrypted, '{}'::JSONB) || 
                         COALESCE(p_context_updates, '{}'::JSONB);

    -- ========================================================================
    -- TODO [UPDATE-005]: Determine new state and menu
    -- ========================================================================
    /*
    TODO: Implement state machine logic
      - Validate state transition is allowed
      - Check menu navigation rules
      - Handle special inputs (0=back, #=home, *=repeat)
      - Process input validation
      - Determine target menu based on user input
    
    State transitions:
      INIT -> MENU -> INPUT -> VALIDATE -> PROCESS -> CONFIRM -> COMPLETE
      Any -> ERROR (on validation failure)
      Any -> TIMEOUT (on expiration)
    */
    
    v_new_state := COALESCE(p_new_state, v_session.current_state);
    v_new_menu_id := COALESCE(p_target_menu_id, v_session.current_menu_id);

    -- ========================================================================
    -- TODO [UPDATE-006]: Check authentication requirements
    -- ========================================================================
    /*
    TODO: Verify authentication for state/menu transition
      - Check if target menu requires auth
      - Verify current auth_level meets requirements
      - Trigger auth challenge if needed
      - Handle step-up authentication
    
    Implementation:
      SELECT required_auth INTO v_required_auth
      FROM menu_configurations WHERE menu_id = v_new_menu_id;
      
      IF v_required_auth > v_session.auth_level THEN
          v_auth_required := TRUE;
          v_auth_challenge := v_required_auth;
          v_new_menu_id := 'menu:auth_required';
      END IF;
    */

    -- ========================================================================
    -- TODO [UPDATE-007]: Check for SIM swap risk
    -- ========================================================================
    /*
    TODO: Evaluate SIM swap risk for state transition
      - Query recent SIM swap status
      - Elevate risk for sensitive state transitions
      - Require additional verification for high-risk scenarios
      - Update security_flags
    
    High-risk transitions:
      - Any -> PROCESS (financial transaction)
      - Any state change post-SIM swap
      
    Implementation:
      IF v_new_state IN ('PROCESS', 'CONFIRM') THEN
          PERFORM check_sim_swap_risk(p_msisdn, v_security_flags);
      END IF;
    */

    -- ========================================================================
    -- TODO [UPDATE-008]: Encrypt updated context
    -- ========================================================================
    /*
    TODO: Re-encrypt context with updated data
      - Use same encryption key as original
      - Include updated timestamp in context
      - Handle encryption failures
      - Rotate encryption if needed (policy-based)
    
    Implementation:
      v_context_encrypted := encrypt_context(
          v_context_updated,
          v_session.key_id
      );
    */

    -- ========================================================================
    -- TODO [UPDATE-009]: Calculate new session hash
    -- ========================================================================
    /*
    TODO: Update hash chain for audit trail
      - Calculate new hash including previous hash
      - Include all updated fields in hash input
      - Store for integrity verification
    
    Hash input:
      v_session.session_hash || v_new_state || NOW() || v_context_updated
    */
    
    v_new_hash := 'TODO_CALCULATE_NEW_HASH';

    -- ========================================================================
    -- Update session record
    -- ========================================================================
    
    UPDATE ussd_session_state
    SET current_state = v_new_state,
        current_menu_id = v_new_menu_id,
        context_encrypted = '\x00', -- Placeholder: v_context_encrypted
        last_activity_at = NOW(),
        expires_at = LEAST(
            NOW() + INTERVAL '90 seconds', -- Reset timeout
            created_at + INTERVAL '10 minutes' -- Absolute max
        ),
        pin_attempts = v_pin_attempts,
        session_hash = v_new_hash,
        previous_session_hash = v_session.session_hash,
        is_finalized = (v_new_state IN ('COMPLETE', 'TIMEOUT', 'ERROR', 'CANCELLED'))
    WHERE session_id = p_session_id;

    -- ========================================================================
    -- TODO [UPDATE-010]: Log menu navigation
    -- ========================================================================
    /*
    TODO: Record navigation history
      - Insert into menu_navigation_history
      - Include context snapshot
      - Calculate time spent on previous menu
    
    Implementation:
      INSERT INTO menu_navigation_history (
          session_id, from_menu_id, to_menu_id, 
          user_input, navigation_duration_ms
      ) VALUES (
          p_session_id, p_current_menu_id, v_new_menu_id,
          p_user_input, 
          EXTRACT(EPOCH FROM (NOW() - v_session.last_activity_at)) * 1000
      );
    */

    -- ========================================================================
    -- TODO [UPDATE-011]: Handle session finalization
    -- ========================================================================
    /*
    TODO: Finalize session if reaching terminal state
      - Set completed_at timestamp
      - Set completion_status
      - Write final state to ledger
      - Clean up transient context
      - Trigger any post-session actions
    */
    
    IF v_new_state IN ('COMPLETE', 'TIMEOUT', 'ERROR', 'CANCELLED') THEN
        UPDATE ussd_session_state
        SET completed_at = NOW(),
            completion_status = CASE v_new_state
n                WHEN 'COMPLETE' THEN 'SUCCESS'
                WHEN 'TIMEOUT' THEN 'TIMEOUT'
                WHEN 'ERROR' THEN 'ERROR'
                WHEN 'CANCELLED' THEN 'USER_CANCEL'
            END,
            is_active = FALSE
        WHERE session_id = p_session_id;
    END IF;

    -- ========================================================================
    -- TODO [UPDATE-012]: Write audit event
    -- ========================================================================
    /*
    TODO: Log state change to immutable ledger
      - Include all relevant metadata
      - Link to session hash chain
      - Include security flags
    */

    -- Return results
    RETURN QUERY SELECT 
        TRUE,
        v_new_state,
        v_new_menu_id,
        v_session_expired,
        v_auth_required,
        v_auth_challenge,
        v_error_message,
        v_security_flags;

END;
$$;

-- ----------------------------------------------------------------------------
-- TODO: IMPLEMENTATION NOTES
-- ----------------------------------------------------------------------------

/*
TODO [PERF-001]: Optimize for low latency
  - Target p99 < 50ms for context updates
  - Use prepared statements for frequent queries
  - Cache menu configurations in application memory
  - Batch audit log writes

TODO [SEC-001]: Security hardening
  - Implement row-level security policies
  - Validate all context update keys against whitelist
  - Sanitize user_input before processing
  - Implement rate limiting on updates per session

TODO [CONC-001]: Concurrency handling
  - Use SELECT FOR UPDATE NOWAIT to fail fast on conflicts
  - Implement optimistic locking with version column
  - Handle serialization failures with retry logic
  - Use advisory locks for cross-session operations

TODO [RES-001]: Resilience patterns
  - Circuit breaker for KMS operations
  - Fallback to cached context on decryption failure
  - Graceful degradation if audit logging fails
  - Dead letter queue for failed updates
*/

-- ----------------------------------------------------------------------------
-- SECURITY CONSIDERATIONS
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.1 - Session validation
-- [ISO/IEC 27001:2022] A.8.5 - Auth state management
-- [ISO/IEC 27001:2022] A.8.11 - Timeout extension on activity
-- [ISO/IEC 27018:2019] Context key whitelist validation
/*
1. SESSION VALIDATION:
   - Always verify session belongs to claimed MSISDN
   - Check session is active and not expired
   - Validate source_ip consistency (if enabled)
   - Reject updates to finalized sessions

2. CONTEXT SECURITY:
   - Never trust client-provided context updates
   - Validate all keys against strict whitelist
   - Sanitize all string inputs
   - Encrypt sensitive context data at rest

3. AUTHENTICATION STATE:
   - Track auth attempts and enforce lockouts
   - Never downgrade auth level
   - Require re-auth for sensitive operations
   - Log all auth state changes

4. AUDIT TRAIL:
   - Every state change must be auditable
   - Include full context hash for integrity
   - Log security flags and decisions
   - Retain per regulatory requirements
*/

-- ----------------------------------------------------------------------------
-- SESSION TIMEOUT HANDLING
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.11 - Activity-based timeout extension
-- Reset on valid input only (prevent extension attacks)
-- Absolute maximum: 10 minutes from session start
-- Warning at: 60 seconds before timeout
/*
Session update timeout considerations:

1. TIMEOUT EXTENSION:
   - Reset expires_at on each valid user interaction
   - Maximum extension: up to absolute session limit (10 min)
   - Don't extend on invalid inputs (prevent timeout extension attacks)
   - Show warning when approaching timeout

2. IDLE DETECTION:
   - Track time since last_activity_at
   - Consider shorter timeout for high-risk states
   - Auto-save context before timeout (for recovery)
   - Allow recovery within 5 minutes of timeout

3. TIMEOUT RECOVERY:
   - If session times out during update, mark as TIMEOUT
   - Save partial progress if possible
   - Notify user via SMS if transaction was in progress
   - Offer "resume" shortcode for quick restart

4. CLEANUP:
   - Finalized sessions cleaned up by background job
   - Retain audit trail indefinitely
   - Remove transient context data after finalization
   - Compress historical session data
*/

-- ----------------------------------------------------------------------------
-- SIM SWAP DETECTION INTEGRATION
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27035-2:2023] State-sensitive SIM swap checks
-- PROCESS/CONFIRM states: Full verification required
-- Risk elevation during session: Trigger additional verification
-- Session termination: If swap detected during active transaction
/*
SIM swap detection during session updates:

1. STATE-SENSITIVE CHECKS:
   - INIT -> MENU: Basic check (info only)
   - MENU -> PROCESS: Full check required
   - Any -> CONFIRM: Re-verify if time elapsed > 5 min
   - PROCESS -> COMPLETE: Final verification

2. RISK ELEVATION:
   - If SIM swap detected during session, elevate risk_score
   - Require additional confirmation for financial operations
   - Consider session termination for high-risk scenarios
   - Alert security team for manual review

3. POST-SWAP SESSION BEHAVIOR:
   - New session after SIM swap: reduced limits
   - Session active during swap: terminate and notify
   - Track session-to-swap correlation for analysis
   - Update behavioral baseline after verification

4. MITIGATION ACTIONS:
   - SIM_SWAP_24H: Require OTP for all financial operations
   - SIM_SWAP_72H: Show warning, reduce limits
   - NEW_DEVICE_POST_SWAP: Challenge with security questions
   - MULTIPLE_SWAPS: Block, require in-branch verification
*/

-- Grant execute permission
-- GRANT EXECUTE ON FUNCTION update_session_context TO ussd_gateway_role;
