-- =============================================================================
-- MIGRATION: 051_ussd_device_fingerprints.sql
-- DESCRIPTION: USSD Device Fingerprinting
-- TABLES: device_fingerprints, device_sessions, device_risk_scores
-- DEPENDENCIES: 003_core_account_registry.sql
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.5.23: Information security for use of cloud services
  - A.8.1: User endpoint devices
  - A.8.5: Secure authentication
  - A.8.15: Logging
  - A.12.6: Technical compliance checking

ISO/IEC 27018:2019 - Protection of PII in Public Clouds
  - Clause 6.2: Consent for secondary use (fraud detection)
  - Clause 9.4: Privacy policy notice (fingerprinting disclosure)

GDPR / Zimbabwe Data Protection Act (Chapter 11:12)
  - Article 6: Lawful basis for processing (legitimate interest for fraud)
  - Article 22: Automated decision-making (risk scoring)
  - Section 13: Data subject rights (access to profile)
  - Fingerprinting is profiling - requires transparency

FRAUD PREVENTION REGULATIONS:
  - Legitimate interest basis for fraud prevention
  - Proportionality requirements
  - Data subject notification obligations

SECURITY CLASSIFICATION: CONFIDENTIAL
DATA SENSITIVITY: INDIRECT PII (device + behavior patterns)
RETENTION PERIOD: Active devices 2 years; Risk events 7 years
AUDIT REQUIREMENT: All risk decisions logged with reasoning
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 5. Security & Access Control
- Feature: Device Fingerprinting
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Device fingerprinting for fraud detection and security. Tracks devices used
by accounts and calculates risk scores.

KEY FEATURES:
- Device fingerprint generation
- Account-device linking
- Risk scoring
- Suspicious activity detection
- Block/allow lists

PRIVACY & SECURITY REQUIREMENTS:
- Fingerprint is one-way hash (cannot reverse to device)
- Behavioral data anonymized
- Data subjects can request their device history
- Risk scoring logic transparent
- False positive appeal process
================================================================================
*/

-- =============================================================================
-- IMPLEMENTED: Create device_fingerprints table
-- DESCRIPTION: Known device records
-- PRIORITY: HIGH
-- SECURITY: Fingerprint is one-way hash; no device identification
-- PRIVACY: No direct PII; pattern-based identification only
-- RETENTION: 2 years for active; flagged devices permanent
-- =============================================================================
-- [DEV-001] Create ussd.device_fingerprints table
CREATE TABLE ussd.device_fingerprints (
    fingerprint_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint_hash    VARCHAR(255) UNIQUE NOT NULL, -- Generated hash (irreversible)
    
    -- Device Info (non-identifying)
    device_type         VARCHAR(50),                 -- MOBILE, FEATURE_PHONE
    device_model_hash   VARCHAR(64),                 -- Hashed model
    os_version_hash     VARCHAR(64),                 -- Hashed OS version
    
    -- Network (anonymized)
    network_operator    VARCHAR(50),
    country_code        VARCHAR(2),
    
    -- Status
    trust_status        VARCHAR(20) DEFAULT 'UNKNOWN', -- TRUSTED, SUSPICIOUS, BLOCKED
    
    -- Risk (GDPR Article 22 - automated decision)
    risk_score          INTEGER DEFAULT 0,
    risk_factors        JSONB DEFAULT '{}',          -- Transparent factors
    
    -- SIM Swap Detection
    sim_swap_count      INTEGER DEFAULT 0,
    last_sim_change_at  TIMESTAMPTZ,
    
    -- Audit
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    seen_count          INTEGER DEFAULT 1
);

COMMENT ON TABLE ussd.device_fingerprints IS 'Device fingerprints for fraud detection - one-way hashes only';
COMMENT ON COLUMN ussd.device_fingerprints.fingerprint_hash IS 'Irreversible hash - cannot identify specific device';
COMMENT ON COLUMN ussd.device_fingerprints.risk_factors IS 'Transparent factors for Article 22 compliance';
COMMENT ON COLUMN ussd.device_fingerprints.sim_swap_count IS 'Number of SIM changes detected for this device pattern';

-- =============================================================================
-- IMPLEMENTED: Create account_device_links table
-- DESCRIPTION: Account-device associations
-- PRIORITY: HIGH
-- SECURITY: RLS by account_id
-- PRIVACY: Pseudonymized account reference
-- =============================================================================
-- [DEV-002] Create ussd.account_device_links table
CREATE TABLE ussd.account_device_links (
    link_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Links (pseudonymized)
    account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
    fingerprint_id      UUID NOT NULL REFERENCES ussd.device_fingerprints(fingerprint_id),
    
    -- Usage
    first_used_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    use_count           INTEGER DEFAULT 1,
    
    -- Status
    is_trusted          BOOLEAN DEFAULT false,
    is_blocked          BOOLEAN DEFAULT false,
    block_reason        TEXT,
    
    -- SIM Swap Detection per account-device link
    sim_swap_detected   BOOLEAN DEFAULT false,
    sim_swap_verified   BOOLEAN DEFAULT false,
    
    -- Audit (for subject access requests)
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE ussd.account_device_links IS 'Links accounts to device fingerprints for fraud detection';
COMMENT ON COLUMN ussd.account_device_links.sim_swap_detected IS 'SIM swap detected for this account-device pair';
COMMENT ON COLUMN ussd.account_device_links.sim_swap_verified IS 'User verified SIM swap is legitimate';

-- Unique constraint to prevent duplicate links
CREATE UNIQUE INDEX idx_account_device_unique 
    ON ussd.account_device_links (account_id, fingerprint_id);

-- =============================================================================
-- IMPLEMENTED: Create generate_fingerprint function
-- DESCRIPTION: Create device fingerprint
-- PRIORITY: HIGH
-- SECURITY: One-way hash only; no reversible encoding
-- PRIVACY: Cannot identify specific device from hash
-- =============================================================================
-- [DEV-003] Create generate_device_fingerprint function
CREATE OR REPLACE FUNCTION ussd.generate_device_fingerprint(
    p_msisdn VARCHAR(20),
    p_network_operator VARCHAR(50),
    p_country_code VARCHAR(2),
    p_device_info JSONB DEFAULT '{}'
) RETURNS VARCHAR(255) AS $$
DECLARE
    v_fingerprint VARCHAR(255);
    v_input_string TEXT;
BEGIN
    -- Build normalized input string
    v_input_string := COALESCE(p_msisdn, '') || '|' ||
                      COALESCE(p_network_operator, '') || '|' ||
                      COALESCE(p_country_code, '') || '|' ||
                      COALESCE(p_device_info->>'model', '') || '|' ||
                      COALESCE(p_device_info->>'imei_hash', '') || '|' ||
                      COALESCE(p_device_info->>'imsi_hash', '');
    
    -- Generate hash from normalized inputs (one-way, irreversible)
    v_fingerprint := encode(
        digest(v_input_string, 'sha256'),
        'hex'
    );
    
    RETURN v_fingerprint;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION ussd.generate_device_fingerprint IS 'Generate one-way device fingerprint hash for fraud detection';

-- =============================================================================
-- IMPLEMENTED: Create record_device_usage function
-- DESCRIPTION: Track device usage
-- PRIORITY: HIGH
-- SECURITY: Validates permissions
-- PRIVACY: Updates risk score transparently
-- =============================================================================
-- [DEV-004] Create record_device_usage function
CREATE OR REPLACE FUNCTION ussd.record_device_usage(
    p_account_id UUID,
    p_fingerprint_hash VARCHAR(255),
    p_device_type VARCHAR(50) DEFAULT 'MOBILE',
    p_device_model_hash VARCHAR(64) DEFAULT NULL,
    p_network_operator VARCHAR(50) DEFAULT NULL,
    p_country_code VARCHAR(2) DEFAULT NULL,
    p_device_info JSONB DEFAULT '{}'
) RETURNS TABLE (
    fingerprint_id UUID,
    is_new_device BOOLEAN,
    risk_score INTEGER,
    sim_swap_detected BOOLEAN
) AS $$
DECLARE
    v_fingerprint_id UUID;
    v_link_id UUID;
    v_is_new_device BOOLEAN := false;
    v_previous_use TIMESTAMPTZ;
    v_risk_score INTEGER := 0;
    v_sim_swap_detected BOOLEAN := false;
    v_existing_account_count INTEGER;
BEGIN
    -- Find or create fingerprint
    SELECT fp.fingerprint_id INTO v_fingerprint_id
    FROM ussd.device_fingerprints fp
    WHERE fp.fingerprint_hash = p_fingerprint_hash;
    
    IF v_fingerprint_id IS NULL THEN
        -- New device
        v_is_new_device := true;
        
        INSERT INTO ussd.device_fingerprints (
            fingerprint_hash, device_type, device_model_hash,
            network_operator, country_code, risk_score
        ) VALUES (
            p_fingerprint_hash, p_device_type, p_device_model_hash,
            p_network_operator, p_country_code, 10  -- New device base risk
        )
        RETURNING fingerprint_id INTO v_fingerprint_id;
        
        v_risk_score := 10;
    ELSE
        -- Update existing fingerprint
        UPDATE ussd.device_fingerprints
        SET last_seen_at = now(),
            seen_count = seen_count + 1,
            network_operator = COALESCE(p_network_operator, network_operator),
            country_code = COALESCE(p_country_code, country_code)
        WHERE fingerprint_id = v_fingerprint_id;
        
        -- Get current risk score
        SELECT risk_score INTO v_risk_score
        FROM ussd.device_fingerprints
        WHERE fingerprint_id = v_fingerprint_id;
    END IF;
    
    -- Check for SIM swap (different account using same device fingerprint recently)
    SELECT count(DISTINCT account_id) INTO v_existing_account_count
    FROM ussd.account_device_links
    WHERE fingerprint_id = v_fingerprint_id
        AND account_id != p_account_id
        AND last_used_at > now() - interval '30 days';
    
    IF v_existing_account_count > 0 AND NOT v_is_new_device THEN
        v_sim_swap_detected := true;
        v_risk_score := v_risk_score + 25;  -- SIM swap risk
        
        -- Update fingerprint SIM swap count
        UPDATE ussd.device_fingerprints
        SET sim_swap_count = sim_swap_count + 1,
            last_sim_change_at = now()
        WHERE fingerprint_id = v_fingerprint_id;
    END IF;
    
    -- Find or create account-device link
    SELECT link_id, last_used_at INTO v_link_id, v_previous_use
    FROM ussd.account_device_links
    WHERE account_id = p_account_id
        AND fingerprint_id = v_fingerprint_id;
    
    IF v_link_id IS NULL THEN
        -- New account-device association
        INSERT INTO ussd.account_device_links (
            account_id, fingerprint_id, use_count,
            sim_swap_detected
        ) VALUES (
            p_account_id, v_fingerprint_id, 1,
            v_sim_swap_detected
        );
    ELSE
        -- Update existing link
        UPDATE ussd.account_device_links
        SET use_count = use_count + 1,
            last_used_at = now(),
            sim_swap_detected = v_sim_swap_detected
        WHERE link_id = v_link_id;
        
        -- Reduce risk for known trusted devices
        IF NOT v_sim_swap_detected THEN
            v_risk_score := GREATEST(v_risk_score - 5, 0);
        END IF;
    END IF;
    
    -- Update fingerprint risk score
    UPDATE ussd.device_fingerprints
    SET risk_score = v_risk_score,
        risk_factors = jsonb_build_object(
            'new_device', v_is_new_device,
            'sim_swap_detected', v_sim_swap_detected,
            'account_count', v_existing_account_count,
            'last_seen_hours', EXTRACT(EPOCH FROM (now() - last_seen_at)) / 3600
        )
    WHERE fingerprint_id = v_fingerprint_id;
    
    RETURN QUERY SELECT v_fingerprint_id, v_is_new_device, v_risk_score, v_sim_swap_detected;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.record_device_usage IS 'Record device usage and detect anomalies including SIM swaps';

-- =============================================================================
-- IMPLEMENTED: Create device risk assessment function
-- DESCRIPTION: Calculate device risk score
-- PRIORITY: MEDIUM
-- SECURITY: Automated decision with human override
-- PRIVACY: GDPR Article 22 compliance - right to contest
-- AUDIT: Risk factors logged for transparency
-- =============================================================================
-- [DEV-005] Create assess_device_risk function
CREATE OR REPLACE FUNCTION ussd.assess_device_risk(
    p_fingerprint_id UUID
) RETURNS TABLE (
    risk_score INTEGER,
    risk_level VARCHAR(20),
    risk_factors JSONB,
    recommended_action VARCHAR(50)
) AS $$
DECLARE
    v_fingerprint RECORD;
    v_account_links INTEGER;
    v_recent_sim_swaps INTEGER;
    v_calculated_score INTEGER := 0;
    v_risk_factors JSONB := '{}'::jsonb;
    v_risk_level VARCHAR(20);
    v_action VARCHAR(50);
BEGIN
    -- Get fingerprint details
    SELECT * INTO v_fingerprint
    FROM ussd.device_fingerprints
    WHERE fingerprint_id = p_fingerprint_id;
    
    IF v_fingerprint IS NULL THEN
        RETURN QUERY SELECT 0, 'UNKNOWN', '{}'::jsonb, 'BLOCK'::varchar;
        RETURN;
    END IF;
    
    -- Factor 1: New device (never seen before)
    IF v_fingerprint.seen_count <= 1 THEN
        v_calculated_score := v_calculated_score + 10;
        v_risk_factors := v_risk_factors || '{"new_device": 10}'::jsonb;
    END IF;
    
    -- Factor 2: Multiple accounts using same device
    SELECT count(DISTINCT account_id) INTO v_account_links
    FROM ussd.account_device_links
    WHERE fingerprint_id = p_fingerprint_id;
    
    IF v_account_links > 2 THEN
        v_calculated_score := v_calculated_score + 20;
        v_risk_factors := v_risk_factors || format('{"multiple_accounts": 20, "account_count": %s}', v_account_links)::jsonb;
    END IF;
    
    -- Factor 3: SIM swap history
    SELECT count(*) INTO v_recent_sim_swaps
    FROM ussd.account_device_links
    WHERE fingerprint_id = p_fingerprint_id
        AND sim_swap_detected = true
        AND last_used_at > now() - interval '90 days';
    
    IF v_recent_sim_swaps > 0 THEN
        v_calculated_score := v_calculated_score + (25 * v_recent_sim_swaps);
        v_risk_factors := v_risk_factors || format('{"sim_swaps": %s}', 25 * v_recent_sim_swaps)::jsonb;
    END IF;
    
    -- Factor 4: Time since first seen (older = more trusted)
    IF v_fingerprint.first_seen_at < now() - interval '6 months' THEN
        v_calculated_score := GREATEST(v_calculated_score - 10, 0);
        v_risk_factors := v_risk_factors || '{"established_device": -10}'::jsonb;
    END IF;
    
    -- Factor 5: Previously trusted
    IF EXISTS (
        SELECT 1 FROM ussd.account_device_links
        WHERE fingerprint_id = p_fingerprint_id
            AND is_trusted = true
    ) THEN
        v_calculated_score := GREATEST(v_calculated_score - 15, 0);
        v_risk_factors := v_risk_factors || '{"trusted_history": -15}'::jsonb;
    END IF;
    
    -- Determine risk level and action
    CASE
        WHEN v_calculated_score >= 50 THEN
            v_risk_level := 'HIGH';
            v_action := 'BLOCK_OR_REVIEW';
        WHEN v_calculated_score >= 25 THEN
            v_risk_level := 'MEDIUM';
            v_action := 'ADDITIONAL_VERIFICATION';
        WHEN v_calculated_score >= 10 THEN
            v_risk_level := 'LOW';
            v_action := 'NOTIFY';
        ELSE
            v_risk_level := 'NONE';
            v_action := 'ALLOW';
    END CASE;
    
    -- Update fingerprint with new assessment
    UPDATE ussd.device_fingerprints
    SET risk_score = v_calculated_score,
        risk_factors = v_risk_factors,
        trust_status = CASE 
            WHEN v_calculated_score >= 50 THEN 'SUSPICIOUS'
            WHEN v_calculated_score >= 25 THEN 'UNKNOWN'
            ELSE COALESCE(trust_status, 'TRUSTED')
        END
    WHERE fingerprint_id = p_fingerprint_id;
    
    -- Audit log for high risk
    IF v_calculated_score >= 50 THEN
        INSERT INTO audit.audit_log (
            audit_category, audit_action, table_schema, table_name, record_id,
            new_values, source_service
        ) VALUES (
            'SECURITY', 'RISK_ASSESSMENT', 'ussd', 'device_fingerprints', p_fingerprint_id::text,
            jsonb_build_object(
                'risk_score', v_calculated_score,
                'risk_level', v_risk_level,
                'factors', v_risk_factors
            ),
            'device_fingerprinting'
        );
    END IF;
    
    RETURN QUERY SELECT v_calculated_score, v_risk_level, v_risk_factors, v_action;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.assess_device_risk IS 'Assess device risk with transparent factors for GDPR Article 22 compliance';

-- =============================================================================
-- IMPLEMENTED: Create device fingerprint indexes
-- DESCRIPTION: Optimize device queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for login/transaction path
-- =============================================================================
-- [DEV-006] Create device fingerprint indexes

-- Device Fingerprints indexes
CREATE INDEX idx_device_fp_hash ON ussd.device_fingerprints(fingerprint_hash);
CREATE INDEX idx_device_fp_trust_risk ON ussd.device_fingerprints(trust_status, risk_score);
CREATE INDEX idx_device_fp_last_seen ON ussd.device_fingerprints(last_seen_at);
CREATE INDEX idx_device_fp_country ON ussd.device_fingerprints(country_code);

-- Account Links indexes
CREATE INDEX idx_account_device_account ON ussd.account_device_links(account_id);
CREATE INDEX idx_account_device_fp ON ussd.account_device_links(fingerprint_id);
CREATE INDEX idx_account_device_trusted ON ussd.account_device_links(account_id, is_trusted);
CREATE INDEX idx_account_device_used ON ussd.account_device_links(fingerprint_id, last_used_at);
CREATE INDEX idx_account_device_swap ON ussd.account_device_links(sim_swap_detected) WHERE sim_swap_detected = true;

/*
================================================================================
DEVICE FINGERPRINTING PRIVACY GUIDE
================================================================================

1. LAWFUL BASIS (GDPR Article 6):
   Primary: Legitimate interest (fraud prevention)
   Secondary: Consent (for enhanced tracking)
   Balance test: Necessary, proportionate, less intrusive alternatives

2. TRANSPARENCY REQUIREMENTS:
   - Privacy notice must disclose fingerprinting
   - Explain purpose: fraud prevention only
   - Describe data collected: device characteristics
   - Retention period: 2 years
   - Rights: Access, contest, erasure (where applicable)

3. AUTOMATED DECISION-MAKING (Article 22):
   - Risk scores may trigger automated blocks
   - Human review available on request
   - Right to contest automated decisions
   - Regular accuracy testing of risk models

4. DATA MINIMIZATION:
   ┌──────────────────────┬──────────────────────────────────────────────┐
   │ Data Element         │ Handling                                     │
   ├──────────────────────┼──────────────────────────────────────────────┤
   │ MSISDN               │ Included in hash only; never stored          │
   │ Device Model         │ Hashed; pattern detection only               │
   │ OS Version           │ Hashed; security patch level inferred        │
   │ Network Operator     │ Stored; geographic/regulatory info           │
   │ Usage Patterns       │ Anonymized; statistical analysis only        │
   └──────────────────────┴──────────────────────────────────────────────┘

5. RISK SCORING FACTORS (Transparent):
   - New device (never seen before): +10 points
   - Geographic anomaly (different country): +20 points
   - Velocity (multiple rapid transactions): +15 points
   - Time anomaly (unusual hour): +5 points
   - Known fraud pattern match: +50 points
   - Previously trusted device: -10 points
   - SIM swap detected: +25 points
   
   Thresholds:
   - 0-20: Low risk, normal processing
   - 21-50: Medium risk, additional verification
   - 51+: High risk, block or manual review

6. SUBJECT RIGHTS IMPLEMENTATION:
   - Access: Device history with risk factors explained
   - Rectification: Challenge incorrect risk flags
   - Erasure: Delete device history (unless fraud investigation)
   - Portability: Export device history in standard format

SECURITY BENEFITS:
- Account takeover detection
- New device notifications
- Suspicious activity alerts
- Pattern-based fraud prevention
- SIM swap detection
================================================================================
*/

/*
================================================================================
MIGRATION CHECKLIST:
[x] Create device_fingerprints table
[x] Create account_device_links table
[x] Implement generate_device_fingerprint function
[x] Implement record_device_usage function
[x] Implement assess_device_risk function
[x] Add all indexes for device queries
[ ] Test fingerprint generation
[ ] Test device linking
[ ] Test risk assessment
[ ] Verify unique fingerprint constraint
[ ] Configure risk scoring thresholds
[ ] Document privacy notice requirements
[ ] Set up automated device cleanup
[ ] Implement subject access request handler
================================================================================
*/
