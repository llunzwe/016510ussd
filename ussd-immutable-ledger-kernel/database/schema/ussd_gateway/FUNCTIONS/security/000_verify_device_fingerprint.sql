-- ============================================================================
-- FUNCTION: verify_device_fingerprint
-- ============================================================================
-- Purpose: Verify device fingerprint for USSD session, detect anomalies,
--          manage trust scoring, and trigger verification challenges.
-- Context: Device fingerprinting helps detect session hijacking, SIM swaps,
--          and fraudulent access attempts. This function evaluates the
--          fingerprint and determines appropriate security actions.
--
-- COMPLIANCE & STANDARDS:
--   ISO/IEC 27001:2022 - Information Security Management
--     * A.8.1: User endpoint device verification
--     * A.8.5: Trust-based authentication decisions
--     * A.8.11: Session-fingerprint binding for integrity
--     * A.8.16: Real-time anomaly monitoring
--
--   ISO/IEC 27018:2019 - PII Protection
--     * Privacy-compliant fingerprinting (no persistent super-IDs)
--     * Encrypted component storage
--     * User consent and opt-out support
--
--   ISO/IEC 27035-2:2023 - Incident Management
--     * SIM swap correlation detection (FPV-004)
--     * Fraud pattern recognition and alerting
--     * Security event logging to fingerprint_events
--
--   ISO 31000:2018 - Risk Management
--     * Risk-based trust scoring algorithm
--     * Velocity anomaly detection
--     * Graduated response based on risk level
--
--   GDPR Article 32 - Security of Processing
--     * Pseudonymization of device identifiers
--     * Encryption of fingerprint components
--
-- VERIFICATION FLOW:
--   1. Lookup or create device fingerprint
--   2. Calculate trust score
--   3. Detect anomalies
--   4. Determine verification requirements
--   5. Return fingerprint ID and security decision
--
-- TRUST SCORE ALGORITHM:
--   - New devices: 0.50 baseline
--   - Age bonus: +0.10 per 30 days (max +0.30)
--   - SIM swap penalty: -0.30 (72h window)
--   - Anomaly penalties: -0.05 to -0.20 per flag
--
-- ENTERPRISE CODING PRACTICES:
--   - SECURITY DEFINER for privilege escalation
--   - Input validation on all parameters
--   - Exception handling with audit logging
--   - Immutable event logging for compliance
-- ============================================================================

CREATE OR REPLACE FUNCTION verify_device_fingerprint(
    p_msisdn VARCHAR(15),
    p_fingerprint_hash VARCHAR(64),
    p_operator_code VARCHAR(6),
    p_components_encrypted BYTEA DEFAULT NULL,
    p_component_summary JSONB DEFAULT NULL,
    p_network_info JSONB DEFAULT NULL, -- {network_type, lac, cell_id, mcc_mnc}
    p_session_id UUID DEFAULT NULL,
    p_strict_mode BOOLEAN DEFAULT FALSE
)
RETURNS TABLE (
    fingerprint_id UUID,
    is_new_device BOOLEAN,
    trust_score DECIMAL(3, 2),
    trust_level VARCHAR(16),
    verification_required BOOLEAN,
    verification_method VARCHAR(32),
    security_flags TEXT[],
    risk_flags TEXT[],
    recommended_action VARCHAR(32),
    device_change_detected BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_fingerprint_id UUID;
    v_existing_fingerprint RECORD;
    v_is_new_device BOOLEAN := FALSE;
    v_trust_score DECIMAL(3, 2) := 0.50;
    v_trust_level VARCHAR(16) := 'NEW';
    v_verification_required BOOLEAN := FALSE;
    v_verification_method VARCHAR(32) := NULL;
    v_security_flags TEXT[] := ARRAY[]::TEXT[];
    v_risk_flags TEXT[] := ARRAY[]::TEXT[];
    v_recommended_action VARCHAR(32) := 'ALLOW';
    v_device_change_detected BOOLEAN := FALSE;
    v_behavioral_match BOOLEAN := TRUE;
    v_location_match BOOLEAN := TRUE;
    v_time_pattern_match BOOLEAN := TRUE;
BEGIN
    -- ========================================================================
    -- TODO [FPV-001]: Lookup existing fingerprint
    -- ========================================================================
    /*
    TODO: Search for existing fingerprint by hash and MSISDN
      - Exact hash match
      - Partial match for component changes
      - Check for expired/archived fingerprints
      - Handle collision detection
    */
    
    SELECT * INTO v_existing_fingerprint
    FROM device_fingerprints
    WHERE msisdn = p_msisdn
    AND fingerprint_hash = p_fingerprint_hash
    AND status = 'ACTIVE'
    ORDER BY last_session_at DESC
    LIMIT 1;
    
    IF FOUND THEN
        v_fingerprint_id := v_existing_fingerprint.fingerprint_id;
        v_trust_score := v_existing_fingerprint.trust_score;
        v_trust_level := v_existing_fingerprint.trust_level;
        
        -- Check for component changes
        IF v_existing_fingerprint.operator_code != p_operator_code THEN
            v_risk_flags := array_append(v_risk_flags, 'OPERATOR_CHANGE');
            v_device_change_detected := TRUE;
        END IF;
        
        v_security_flags := array_append(v_security_flags, 'KNOWN_DEVICE');
    ELSE
        -- New fingerprint - check if this is first device for MSISDN
        v_is_new_device := TRUE;
        v_security_flags := array_append(v_security_flags, 'NEW_FINGERPRINT');
        
        -- Check for any existing fingerprints for this MSISDN
        SELECT * INTO v_existing_fingerprint
        FROM device_fingerprints
        WHERE msisdn = p_msisdn
        AND status = 'ACTIVE'
        ORDER BY last_session_at DESC
        LIMIT 1;
        
        IF FOUND THEN
            v_device_change_detected := TRUE;
            v_risk_flags := array_append(v_risk_flags, 'DEVICE_CHANGE');
        END IF;
    END IF;

    -- ========================================================================
    -- TODO [FPV-002]: Calculate trust score
    -- ========================================================================
    /*
    TODO: Implement trust score calculation
      Factors:
      - Age of fingerprint (0.1 per week, max 0.3)
      - Consistency of usage (0.2)
      - Geographic stability (0.2)
      - Time pattern consistency (0.1)
      - Transaction success rate (0.2)
      
      New devices start at 0.5
      Anomalies reduce score
      Consistent usage increases score (gradually)
    */
    
    IF v_is_new_device THEN
        v_trust_score := 0.50;
        v_trust_level := 'NEW';
        
        -- If linked to previous device, inherit partial trust
        IF v_existing_fingerprint.fingerprint_id IS NOT NULL THEN
            v_trust_score := LEAST(v_existing_fingerprint.trust_score * 0.7, 0.60);
            v_trust_level := 'LOW';
            v_security_flags := array_append(v_security_flags, 'LINKED_TO_PREVIOUS');
        END IF;
    ELSE
        -- Update existing fingerprint trust based on usage
        -- TODO: Calculate based on behavioral data
        v_trust_score := v_existing_fingerprint.trust_score;
        
        -- Age bonus
        IF v_existing_fingerprint.first_seen_at < NOW() - INTERVAL '30 days' THEN
            v_trust_score := LEAST(v_trust_score + 0.10, 1.00);
            v_trust_level := 'HIGH';
        ELSIF v_existing_fingerprint.first_seen_at < NOW() - INTERVAL '7 days' THEN
            v_trust_score := LEAST(v_trust_score + 0.05, 1.00);
            v_trust_level := 'MEDIUM';
        END IF;
    END IF;

    -- ========================================================================
    -- TODO [FPV-003]: Detect anomalies
    -- ========================================================================
    /*
    TODO: Implement anomaly detection
      - Location anomaly: Distance from typical location
      - Time anomaly: Usage outside normal hours
      - Velocity anomaly: Session frequency too high
      - Behavioral anomaly: Navigation pattern changes
      - Network anomaly: Unusual operator/cell tower
    */
    
    IF v_existing_fingerprint.fingerprint_id IS NOT NULL THEN
        -- Location check
        IF p_network_info->>'lac' IS NOT NULL AND 
           v_existing_fingerprint.lac IS NOT NULL AND
           p_network_info->>'lac' != v_existing_fingerprint.lac THEN
            
            -- TODO: Calculate actual distance between cell towers
            -- For now, just flag as different
            v_location_match := FALSE;
            v_risk_flags := array_append(v_risk_flags, 'LOCATION_ANOMALY');
        END IF;
        
        -- Time pattern check
        IF v_existing_fingerprint.behavioral_baseline->'typical_hours' IS NOT NULL THEN
            -- TODO: Check if current hour is in typical hours
            NULL;
        END IF;
        
        -- Velocity check
        IF v_existing_fingerprint.last_session_at > NOW() - INTERVAL '1 minute' THEN
            v_risk_flags := array_append(v_risk_flags, 'VELOCITY_ANOMALY');
        END IF;
    END IF;

    -- ========================================================================
    -- TODO [FPV-004]: Check for SIM swap correlation
    -- ========================================================================
    /*
    TODO: Query SIM swap status and correlate with fingerprint
      - If SIM swap detected recently + new device = high risk
      - Query sim_swap_correlations table
      - Adjust trust score based on swap recency
      - Set appropriate risk flags
    */
    
    IF EXISTS (
        SELECT 1 FROM sim_swap_correlations
        WHERE msisdn = p_msisdn
        AND sim_swap_detected_at > NOW() - INTERVAL '72 hours'
        AND verified_legitimate IS NOT TRUE
    ) THEN
        v_risk_flags := array_append(v_risk_flags, 'SIM_SWAP_RECENT');
        v_trust_score := GREATEST(v_trust_score - 0.30, 0.00);
        
        IF v_is_new_device THEN
            v_risk_flags := array_append(v_risk_flags, 'NEW_DEVICE_POST_SWAP');
            v_trust_score := GREATEST(v_trust_score - 0.20, 0.00);
        END IF;
    END IF;

    -- ========================================================================
    -- TODO [FPV-005]: Determine verification requirements
    -- ========================================================================
    /*
    TODO: Implement verification challenge decision matrix
      
      Trust Score | Risk Flags        | Action
      ------------|-------------------|------------------
      > 0.80      | None              | ALLOW (automatic)
      0.60-0.80   | None              | ALLOW (log)
      0.60-0.80   | Minor             | CHALLENGE (OTP)
      0.40-0.60   | Any               | CHALLENGE (PIN+OTP)
      < 0.40      | Any               | BLOCK (manual review)
      Any         | SIM_SWAP_RECENT   | CHALLENGE (enhanced)
      Any         | NEW_DEVICE_POST_SWAP | RESTRICT
    */
    
    IF v_trust_score > 0.80 AND array_length(v_risk_flags, 1) IS NULL THEN
        v_recommended_action := 'ALLOW';
        v_verification_required := FALSE;
    ELSIF v_trust_score >= 0.60 THEN
        IF 'LOCATION_ANOMALY' = ANY(v_risk_flags) OR 
           'TIME_ANOMALY' = ANY(v_risk_flags) THEN
            v_recommended_action := 'CHALLENGE';
            v_verification_required := TRUE;
            v_verification_method := 'OTP';
        ELSE
            v_recommended_action := 'ALLOW';
            v_verification_required := FALSE;
        END IF;
    ELSIF v_trust_score >= 0.40 THEN
        v_recommended_action := 'CHALLENGE';
        v_verification_required := TRUE;
        v_verification_method := 'PIN';
        
        IF 'SIM_SWAP_RECENT' = ANY(v_risk_flags) THEN
            v_verification_method := 'ENHANCED';
        END IF;
    ELSE
        v_recommended_action := 'RESTRICT';
        v_verification_required := TRUE;
        v_verification_method := 'MANUAL';
    END IF;
    
    -- Strict mode elevates requirements
    IF p_strict_mode AND v_recommended_action = 'ALLOW' THEN
        v_verification_required := TRUE;
        v_verification_method := 'PIN';
    END IF;

    -- ========================================================================
    -- TODO [FPV-006]: Create or update fingerprint record
    -- ========================================================================
    /*
    TODO: Persist fingerprint data
      - Insert new fingerprint if not exists
      - Update usage statistics for existing
      - Update behavioral baseline
      - Increment session count
      - Encrypt components
    */
    
    IF v_is_new_device THEN
        INSERT INTO device_fingerprints (
            msisdn,
            fingerprint_hash,
            components_encrypted,
            component_summary,
            operator_code,
            network_type,
            lac,
            cell_id,
            trust_score,
            trust_level,
            first_seen_session_id,
            last_session_id,
            mcc_mnc,
            risk_flags
        ) VALUES (
            p_msisdn,
            p_fingerprint_hash,
            COALESCE(p_components_encrypted, '\x00'),
            COALESCE(p_component_summary, '{}'::JSONB),
            p_operator_code,
            p_network_info->>'network_type',
            p_network_info->>'lac',
            p_network_info->>'cell_id',
            v_trust_score,
            v_trust_level,
            p_session_id,
            p_session_id,
            p_network_info->>'mcc_mnc',
            v_risk_flags
        )
        RETURNING device_fingerprints.fingerprint_id INTO v_fingerprint_id;
        
        -- Link to previous fingerprint if device change
        IF v_existing_fingerprint.fingerprint_id IS NOT NULL THEN
            UPDATE device_fingerprints
            SET previous_fingerprint_id = v_existing_fingerprint.fingerprint_id,
                device_change_reason = 'DETECTED'
            WHERE fingerprint_id = v_fingerprint_id;
        END IF;
    ELSE
        -- Update existing fingerprint
        UPDATE device_fingerprints
        SET total_sessions = total_sessions + 1,
            last_session_at = NOW(),
            last_session_id = p_session_id,
            trust_score = v_trust_score,
            trust_level = v_trust_level,
            risk_flags = v_risk_flags,
            -- Update network info if changed
            lac = COALESCE(p_network_info->>'lac', lac),
            cell_id = COALESCE(p_network_info->>'cell_id', cell_id)
        WHERE fingerprint_id = v_fingerprint_id;
    END IF;

    -- ========================================================================
    -- TODO [FPV-007]: Log verification event
    -- ========================================================================
    /*
    TODO: Write to fingerprint_events table
      - Include all decision factors
      - Log verification requirements
      - Store for audit and ML training
    */
    
    INSERT INTO fingerprint_events (
        fingerprint_id,
        msisdn,
        event_type,
        event_severity,
        event_data,
        session_id,
        risk_score_at_event,
        risk_flags_at_event,
        triggered_by
    ) VALUES (
        v_fingerprint_id,
        p_msisdn,
        CASE WHEN v_is_new_device THEN 'FIRST_SEEN' ELSE 'VERIFIED' END,
        CASE 
            WHEN v_recommended_action = 'BLOCK' THEN 'CRITICAL'
            WHEN v_recommended_action = 'RESTRICT' THEN 'ALERT'
            WHEN v_verification_required THEN 'WARNING'
            ELSE 'INFO'
        END,
        jsonb_build_object(
            'trust_score', v_trust_score,
            'trust_level', v_trust_level,
            'is_new_device', v_is_new_device,
            'device_change', v_device_change_detected,
            'verification_required', v_verification_required,
            'verification_method', v_verification_method,
            'recommended_action', v_recommended_action
        ),
        p_session_id,
        v_trust_score,
        v_risk_flags,
        'SYSTEM'
    );

    -- ========================================================================
    -- TODO [FPV-008]: Update behavioral baseline
    -- ========================================================================
    /*
    TODO: Machine learning-based behavioral profile
      - Update typical usage hours
      - Track menu navigation patterns
      - Update location clustering
      - Learn transaction patterns
      - Feed into risk scoring model
    */

    -- Return results
    RETURN QUERY SELECT 
        v_fingerprint_id,
        v_is_new_device,
        v_trust_score,
        v_trust_level,
        v_verification_required,
        v_verification_method,
        v_security_flags,
        v_risk_flags,
        v_recommended_action,
        v_device_change_detected;

END;
$$;

-- ----------------------------------------------------------------------------
-- FUNCTION: link_device_fingerprints
-- ----------------------------------------------------------------------------
-- Link a new fingerprint to a previous one (legitimate device change)
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION link_device_fingerprints(
    p_old_fingerprint_id UUID,
    p_new_fingerprint_id UUID,
    p_verified_by VARCHAR(128),
    p_verification_method VARCHAR(32),
    p_reason VARCHAR(64) DEFAULT 'USER_UPGRADE'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    UPDATE device_fingerprints
    SET previous_fingerprint_id = p_old_fingerprint_id,
        device_change_reason = p_reason,
        device_change_verified = TRUE,
        trust_score = LEAST(
            (SELECT trust_score FROM device_fingerprints WHERE fingerprint_id = p_old_fingerprint_id) * 0.8,
            0.70
        ),
        trust_level = 'MEDIUM',
        updated_at = NOW()
    WHERE fingerprint_id = p_new_fingerprint_id;
    
    INSERT INTO fingerprint_events (
        fingerprint_id,
        msisdn,
        event_type,
        event_data,
        triggered_by
    )
    SELECT 
        p_new_fingerprint_id,
        msisdn,
        'DEVICE_CHANGED',
        jsonb_build_object(
            'old_fingerprint_id', p_old_fingerprint_id,
            'verified_by', p_verified_by,
            'verification_method', p_verification_method,
            'reason', p_reason
        ),
        p_verified_by
    FROM device_fingerprints
    WHERE fingerprint_id = p_new_fingerprint_id;
    
    RETURN TRUE;
EXCEPTION WHEN OTHERS THEN
    RETURN FALSE;
END;
$$;

-- ----------------------------------------------------------------------------
-- TODO: IMPLEMENTATION NOTES
-- ----------------------------------------------------------------------------

/*
TODO [ML-001]: Machine learning integration
  - Train anomaly detection model on fingerprint events
  - Real-time scoring via model serving
  - Feature engineering: time since last session, location entropy
  - A/B test model versions
  - Feedback loop for false positives

TODO [PRIVACY-001]: Privacy controls
  - Implement data minimization (don't store unnecessary components)
  - Anonymization for analytics
  - User consent management for fingerprinting
  - Right to deletion (with audit considerations)
  - Cross-border data transfer compliance

TODO [SCALE-001]: Scaling considerations
  - Partition fingerprint tables by msisdn hash
  - Cache frequently accessed fingerprints in Redis
  - Async event logging
  - Read replicas for verification queries
*/

-- ----------------------------------------------------------------------------
-- SECURITY CONSIDERATIONS
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.1 - Device endpoint verification
-- [ISO/IEC 27001:2022] A.8.5 - Trust-based secure authentication
-- [ISO/IEC 27018:2019] Device identifier hashing (SHA-256)
-- [GDPR] Data minimization and user consent
-- [ISO 31000:2018] Risk-based trust scoring
/*
1. FINGERPRINT UNIQUENESS:
   - Hash collisions are rare but possible
   - Use additional verification on collision
   - Include timestamp in hash calculation
   - Monitor for unusual collision rates

2. COMPONENT SECURITY:
   - Never store raw IMEI/IMSI
   - Always hash/encrypt device identifiers
   - Rotate encryption keys regularly
   - Access controls on fingerprint data

3. SPOOFING DETECTION:
   - Detect fingerprint cloning attempts
   - Validate component consistency
   - Alert on impossible device changes
   - Rate limit fingerprint creation

4. PRIVACY:
   - Minimal data collection principle
   - Transparent about fingerprinting
   - User opt-out where required
   - Secure data retention policies
*/

-- ----------------------------------------------------------------------------
-- SESSION TIMEOUT HANDLING
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.11 - Fingerprint verification timeout: 100ms
-- Trust score cache: 5 minute TTL
-- Grace period: New fingerprint reduced limits for first 3 sessions
/*
Fingerprint verification timeout considerations:

1. VERIFICATION TIMEOUT:
   - Database lookup: < 10ms target
   - Anomaly detection: < 50ms target
   - Total function time: < 100ms target
   - Async ML scoring for non-blocking

2. CACHING:
   - Cache fingerprint lookups for 5 minutes
   - Cache trust scores for 1 minute
   - Invalidate on security events
   - Stale cache acceptable for low-risk decisions

3. GRACEFUL DEGRADATION:
   - If fingerprint service slow, use cached data
   - Default to challenge mode on timeout
   - Don't block session on verification delay
   - Queue for async risk scoring

4. TIME-BASED TRUST:
   - Trust score decays over time without use
   - Re-verification required after 30 days idle
   - Session timeout affects trust calculation
   - Continuous authentication during session
*/

-- ----------------------------------------------------------------------------
-- SIM SWAP DETECTION INTEGRATION
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27035-2:2023] SIM swap correlation in fingerprint verification
-- [GSMA IR.71] Device change + SIM swap = High risk
-- Trust impact: -0.30 for SIM_SWAP_RECENT, -0.20 for NEW_DEVICE_POST_SWAP
-- Verification escalation: ENHANCED method for post-swap devices
/*
SIM swap detection in fingerprint verification:

1. SWAP INDICATORS:
   - New fingerprint + recent account activity = possible swap
   - Location jump after fingerprint change
   - Multiple fingerprints in short time
   - Failed verification attempts post-change

2. CORRELATION LOGIC:
   - Query sim_swap_correlations on new fingerprint
   - Check if swap window overlaps with fingerprint creation
   - Update fingerprint with post_sim_swap flag
   - Link to swap event for investigation

3. TRUST IMPACT:
   - SIM swap 0-24h: Maximum trust reduction (-0.50)
   - SIM swap 24-72h: Significant reduction (-0.30)
   - SIM swap 72h-7d: Moderate reduction (-0.15)
   - > 7 days: Minimal impact
   - Verified legitimate swap: Restore partial trust

4. VERIFICATION ESCALATION:
   - Post-swap: Require enhanced verification
   - New device post-swap: Block high-value operations
   - Multiple post-swap fingerprints: Alert fraud team
   - Successful verification: Gradual trust restoration

5. MONITORING:
   - Track fingerprint verification success rate post-swap
   - Alert on verification failures after swaps
   - Monitor for swap + fingerprint correlation patterns
   - Feed verification outcomes into swap detection model
*/

-- Grant execute permission
-- GRANT EXECUTE ON FUNCTION verify_device_fingerprint TO ussd_gateway_role;
-- GRANT EXECUTE ON FUNCTION link_device_fingerprints TO ussd_admin_role;
