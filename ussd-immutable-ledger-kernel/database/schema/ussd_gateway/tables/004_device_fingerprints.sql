-- =============================================================================
-- FILE: 004_device_fingerprints.sql
-- DESCRIPTION: USSD Device Fingerprinting for Fraud Detection
-- TABLES: device_fingerprints, account_device_links, sim_change_history
-- SCHEMA: ussd
-- PRIORITY: HIGH
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

GSMA IR.71 - SIM Swap Detection
  - Multi-source detection requirements
  - 72-hour critical monitoring window
  - Device correlation for swap detection

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

-- =============================================================================
-- TYPE DEFINITIONS
-- =============================================================================

-- Device trust status
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'device_trust_status') THEN
        CREATE TYPE ussd.device_trust_status AS ENUM (
            'UNKNOWN',      -- New device, no history
            'TRUSTED',      -- Known good device
            'SUSPICIOUS',   -- Anomalies detected
            'BLOCKED',      -- Blocked due to fraud
            'WHITELISTED',  -- Explicitly trusted
            'REVIEWING'     -- Under manual review
        );
    END IF;
END$$;

-- SIM change type
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'sim_change_type') THEN
        CREATE TYPE ussd.sim_change_type AS ENUM (
            'NEW_DEVICE',       -- First time device seen
            'DEVICE_CHANGE',    -- Different device, same SIM
            'SIM_CHANGE',       -- Same device, different SIM (potential swap)
            'BOTH_CHANGE',      -- Both device and SIM changed
            'NETWORK_CHANGE',   -- Same device/SIM, different network
            'LOCATION_CHANGE'   -- Significant location change
        );
    END IF;
END$$;

-- Risk factor category
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'risk_factor_category') THEN
        CREATE TYPE ussd.risk_factor_category AS ENUM (
            'DEVICE_NEW',           -- Never seen before
            'DEVICE_RARE',          -- Rarely used device
            'GEO_ANOMALY',          -- Unusual location
            'TIME_ANOMALY',         -- Unusual time
            'VELOCITY_EXCEEDED',    -- Too many transactions
            'SIM_RECENT_CHANGE',    -- SIM changed recently
            'IMEI_MISMATCH',        -- IMEI doesn't match history
            'NETWORK_ANOMALY',      -- Unusual network
            'BEHAVIOR_ANOMALY',     -- Behavioral mismatch
            'KNOWN_FRAUD_PATTERN',  -- Matches known fraud
            'BLACKLISTED',          -- Device on blacklist
            'HIGH_RISK_COUNTRY'     -- High-risk country
        );
    END IF;
END$$;

-- =============================================================================
-- TABLE: device_fingerprints
-- DESCRIPTION: Known device records with privacy-preserving hashes
-- SECURITY: Fingerprint is one-way hash; no device identification
-- PRIVACY: No direct PII; pattern-based identification only
-- RETENTION: 2 years for active; flagged devices permanent
-- =============================================================================
CREATE TABLE IF NOT EXISTS ussd.device_fingerprints (
    fingerprint_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint_hash        VARCHAR(255) UNIQUE NOT NULL,    -- Generated hash (irreversible)
    
    -- Device Info (all hashed or anonymized)
    device_type             VARCHAR(50),                     -- MOBILE, FEATURE_PHONE
    device_category         VARCHAR(50),                     -- SMARTPHONE, TABLET, etc.
    device_model_hash       VARCHAR(64),                     -- Hashed model (pattern only)
    os_type                 VARCHAR(50),                     -- ANDROID, IOS, KAIOS, etc.
    os_version_hash         VARCHAR(64),                     -- Hashed OS version
    os_version_bucket       VARCHAR(20),                     -- MAJOR version bucket only
    
    -- Network (anonymized)
    network_operator        VARCHAR(50),                     -- MNO name
    network_country         VARCHAR(2),                      -- ISO country
    network_type            VARCHAR(20),                     -- 2G, 3G, 4G, 5G
    
    -- Capabilities (for feature detection)
    ussd_capability         VARCHAR(20),                     -- Basic, Enhanced
    encryption_support      BOOLEAN DEFAULT false,
    
    -- Trust Status
    trust_status            ussd.device_trust_status DEFAULT 'UNKNOWN',
    trust_status_changed_at TIMESTAMPTZ,
    trust_status_reason     TEXT,
    
    -- Risk Scoring (GDPR Article 22 - automated decision)
    risk_score              INTEGER DEFAULT 0,               -- 0-100 calculated score
    risk_score_calculated_at TIMESTAMPTZ,
    risk_factors            JSONB DEFAULT '{}',              -- Transparent factors { "DEVICE_NEW": 10 }
    
    -- Velocity Tracking
    daily_transaction_count INTEGER DEFAULT 0,               -- Rolling 24h count
    daily_transaction_amount NUMERIC(20, 8) DEFAULT 0,
    last_velocity_reset     TIMESTAMPTZ DEFAULT now(),
    
    -- Geolocation (cell tower precision only)
    typical_country         VARCHAR(2),                      -- Most frequent country
    typical_region          VARCHAR(50),                     -- Region/Province
    location_confidence     NUMERIC(3, 2),                   -- Confidence in typical location
    
    -- Behavioral Profile
    typical_usage_hours     INTEGER[],                       -- Hours of day [0-23]
    typical_tx_types        VARCHAR(50)[],                   -- Common transaction types
    
    -- Blacklist/Whitelist
    is_whitelisted          BOOLEAN DEFAULT false,
    whitelisted_by          UUID REFERENCES core.accounts(account_id),
    whitelisted_at          TIMESTAMPTZ,
    whitelist_reason        TEXT,
    
    is_blacklisted          BOOLEAN DEFAULT false,
    blacklisted_by          UUID REFERENCES core.accounts(account_id),
    blacklisted_at          TIMESTAMPTZ,
    blacklist_reason        TEXT,
    blacklist_expires_at    TIMESTAMPTZ,
    
    -- Usage Statistics
    first_seen_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    seen_count              INTEGER DEFAULT 1,
    successful_tx_count     INTEGER DEFAULT 0,
    failed_tx_count         INTEGER DEFAULT 0,
    
    -- Compliance
    data_retention_until    TIMESTAMPTZ,                     -- GDPR retention limit
    
    -- Audit
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Constraints
    CONSTRAINT valid_risk_score CHECK (risk_score >= 0 AND risk_score <= 100),
    CONSTRAINT valid_location_confidence CHECK (location_confidence IS NULL OR (location_confidence >= 0 AND location_confidence <= 1))
);

COMMENT ON TABLE ussd.device_fingerprints IS 'Privacy-preserving device fingerprints for fraud detection';
COMMENT ON COLUMN ussd.device_fingerprints.fingerprint_hash IS 'One-way hash - cannot reverse to identify device';
COMMENT ON COLUMN ussd.device_fingerprints.risk_factors IS 'Transparent scoring factors for GDPR Article 22 compliance';

-- =============================================================================
-- TABLE: account_device_links
-- DESCRIPTION: Account-device associations
-- SECURITY: RLS by account_id
-- PRIVACY: Pseudonymized account reference
-- =============================================================================
CREATE TABLE IF NOT EXISTS ussd.account_device_links (
    link_id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Links (pseudonymized)
    account_id              UUID NOT NULL REFERENCES core.accounts(account_id),
    fingerprint_id          UUID NOT NULL REFERENCES ussd.device_fingerprints(fingerprint_id),
    
    -- Usage Statistics
    first_used_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    use_count               INTEGER DEFAULT 1,
    
    -- Transaction Statistics
    successful_tx_count     INTEGER DEFAULT 0,
    failed_tx_count         INTEGER DEFAULT 0,
    total_tx_amount         NUMERIC(20, 8) DEFAULT 0,
    last_tx_at              TIMESTAMPTZ,
    
    -- Status
    is_trusted              BOOLEAN DEFAULT false,
    trusted_at              TIMESTAMPTZ,
    trusted_reason          TEXT,
    
    is_blocked              BOOLEAN DEFAULT false,
    blocked_at              TIMESTAMPTZ,
    block_reason            TEXT,
    blocked_by              UUID REFERENCES core.accounts(account_id),
    
    -- Notifications
    new_device_notified     BOOLEAN DEFAULT false,           -- User notified of new device
    notified_at             TIMESTAMPTZ,
    
    -- SIM Association (for swap detection)
    current_imsi_hash       VARCHAR(64),
    current_imei_hash       VARCHAR(64),
    sim_first_seen_at       TIMESTAMPTZ,
    
    -- Audit
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    UNIQUE (account_id, fingerprint_id)
);

COMMENT ON TABLE ussd.account_device_links IS 'Links accounts to devices with usage tracking';

-- =============================================================================
-- TABLE: sim_change_history
-- DESCRIPTION: SIM change tracking for swap detection (GSMA IR.71)
-- SECURITY: All identifiers hashed
-- AUDIT: Complete SIM change history
-- =============================================================================
CREATE TABLE IF NOT EXISTS ussd.sim_change_history (
    change_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Links
    account_id              UUID NOT NULL REFERENCES core.accounts(account_id),
    fingerprint_id          UUID REFERENCES ussd.device_fingerprints(fingerprint_id),
    
    -- Change Details
    change_type             ussd.sim_change_type NOT NULL,
    change_detected_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Previous State (hashed)
    previous_imsi_hash      VARCHAR(64),
    previous_imei_hash      VARCHAR(64),
    previous_network        VARCHAR(50),
    previous_country        VARCHAR(2),
    
    -- New State (hashed)
    new_imsi_hash           VARCHAR(64),
    new_imei_hash           VARCHAR(64),
    new_network             VARCHAR(50),
    new_country             VARCHAR(2),
    
    -- Detection Source
    detection_source        VARCHAR(50) NOT NULL,            -- HLR, MNO_API, DEVICE_FP, BEHAVIORAL
    detection_confidence    NUMERIC(3, 2),                   -- 0.00-1.00
    
    -- Risk Assessment
    risk_level              VARCHAR(20) DEFAULT 'LOW',       -- LOW, MEDIUM, HIGH, CRITICAL
    risk_factors            JSONB DEFAULT '{}',
    requires_verification   BOOLEAN DEFAULT false,
    verification_completed  BOOLEAN DEFAULT false,
    verified_at             TIMESTAMPTZ,
    verified_by             UUID REFERENCES core.accounts(account_id),
    
    -- 72-Hour Monitoring (GSMA IR.71)
    monitoring_started_at   TIMESTAMPTZ,
    monitoring_ends_at      TIMESTAMPTZ,
    is_monitoring_active    BOOLEAN DEFAULT false,
    alerts_triggered        INTEGER DEFAULT 0,
    
    -- Actions Taken
    auto_actions_taken      JSONB DEFAULT '{}',              -- { "limits_reduced": true, "notifications_sent": [...] }
    manual_review_required  BOOLEAN DEFAULT false,
    reviewed_at             TIMESTAMPTZ,
    reviewed_by             UUID REFERENCES core.accounts(account_id),
    review_notes            TEXT,
    
    -- Resolution
    resolution_status       VARCHAR(20) DEFAULT 'PENDING',   -- PENDING, CONFIRMED_LEGIT, CONFIRMED_FRAUD, EXPIRED
    resolved_at             TIMESTAMPTZ,
    
    -- Audit
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    CONSTRAINT valid_risk_level CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT valid_detection_confidence CHECK (detection_confidence IS NULL OR (detection_confidence >= 0 AND detection_confidence <= 1))
);

COMMENT ON TABLE ussd.sim_change_history IS 'SIM swap detection history per GSMA IR.71 requirements';
COMMENT ON COLUMN ussd.sim_change_history.monitoring_ends_at IS '72-hour monitoring window per GSMA IR.71';

-- =============================================================================
-- TABLE: device_risk_events
-- DESCRIPTION: Risk event log for fraud analysis
-- SECURITY: Audit trail for all risk decisions
-- =============================================================================
CREATE TABLE IF NOT EXISTS ussd.device_risk_events (
    event_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint_id          UUID NOT NULL REFERENCES ussd.device_fingerprints(fingerprint_id),
    
    -- Event Details
    event_type              VARCHAR(50) NOT NULL,            -- RISK_SCORE_CHANGE, BLOCK, UNBLOCK, etc.
    event_category          ussd.risk_factor_category,
    event_severity          VARCHAR(20) DEFAULT 'INFO',      -- DEBUG, INFO, WARNING, ERROR, CRITICAL
    
    -- Risk Information
    previous_risk_score     INTEGER,
    new_risk_score          INTEGER,
    risk_delta              INTEGER,
    
    -- Context
    session_id              UUID REFERENCES ussd.ussd_sessions(session_id),
    transaction_id          UUID,
    account_id              UUID REFERENCES core.accounts(account_id),
    
    -- Location Context
    country_code            VARCHAR(2),
    network_operator        VARCHAR(50),
    
    -- Decision Reasoning (GDPR Article 22 transparency)
    decision_factors        JSONB NOT NULL,                  -- Detailed scoring breakdown
    decision_algorithm      VARCHAR(50),                     -- Which algorithm/version
    human_override          BOOLEAN DEFAULT false,           -- Manual decision override
    overridden_by           UUID REFERENCES core.accounts(account_id),
    
    -- Audit
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    CONSTRAINT valid_event_severity CHECK (event_severity IN ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'))
);

COMMENT ON TABLE ussd.device_risk_events IS 'Transparent risk decision log for GDPR Article 22 compliance';
COMMENT ON COLUMN ussd.device_risk_events.decision_factors IS 'Complete factor breakdown for subject access requests';

-- =============================================================================
-- INDEXES FOR DEVICE FINGERPRINT TABLES
-- =============================================================================

-- device_fingerprints indexes
CREATE INDEX IF NOT EXISTS idx_device_fp_hash ON ussd.device_fingerprints(fingerprint_hash);
CREATE INDEX IF NOT EXISTS idx_device_fp_status ON ussd.device_fingerprints(trust_status, risk_score);
CREATE INDEX IF NOT EXISTS idx_device_fp_risk ON ussd.device_fingerprints(risk_score) WHERE risk_score > 50;
CREATE INDEX IF NOT EXISTS idx_device_fp_blacklist ON ussd.device_fingerprints(is_blacklisted) WHERE is_blacklisted = true;
CREATE INDEX IF NOT EXISTS idx_device_fp_seen ON ussd.device_fingerprints(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_device_fp_country ON ussd.device_fingerprints(network_country);

-- account_device_links indexes
CREATE INDEX IF NOT EXISTS idx_account_device_account ON ussd.account_device_links(account_id, is_trusted);
CREATE INDEX IF NOT EXISTS idx_account_device_fp ON ussd.account_device_links(fingerprint_id, last_used_at);
CREATE INDEX IF NOT EXISTS idx_account_device_blocked ON ussd.account_device_links(is_blocked) WHERE is_blocked = true;
CREATE INDEX IF NOT EXISTS idx_account_device_trusted ON ussd.account_device_links(is_trusted, trusted_at) WHERE is_trusted = true;

-- sim_change_history indexes
CREATE INDEX IF NOT EXISTS idx_sim_change_account ON ussd.sim_change_history(account_id, change_detected_at);
CREATE INDEX IF NOT EXISTS idx_sim_change_monitoring ON ussd.sim_change_history(is_monitoring_active, monitoring_ends_at) 
    WHERE is_monitoring_active = true;
CREATE INDEX IF NOT EXISTS idx_sim_change_risk ON ussd.sim_change_history(risk_level, change_detected_at);
CREATE INDEX IF NOT EXISTS idx_sim_change_fingerprint ON ussd.sim_change_history(fingerprint_id, change_detected_at);

-- device_risk_events indexes
CREATE INDEX IF NOT EXISTS idx_risk_events_fp ON ussd.device_risk_events(fingerprint_id, created_at);
CREATE INDEX IF NOT EXISTS idx_risk_events_category ON ussd.device_risk_events(event_category, created_at);
CREATE INDEX IF NOT EXISTS idx_risk_events_severity ON ussd.device_risk_events(event_severity, created_at);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function: Generate device fingerprint
CREATE OR REPLACE FUNCTION ussd.generate_device_fingerprint(
    p_msisdn VARCHAR(20),
    p_network_operator VARCHAR(50),
    p_country_code VARCHAR(2),
    p_device_info JSONB DEFAULT '{}'
) RETURNS VARCHAR(255) AS $$
DECLARE
    v_fingerprint VARCHAR(255);
    v_seed TEXT;
BEGIN
    -- Create seed from normalized inputs (one-way, irreversible)
    v_seed := COALESCE(p_msisdn, '') || '|' ||
              COALESCE(upper(p_network_operator), '') || '|' ||
              COALESCE(upper(p_country_code), '') || '|' ||
              COALESCE(upper(p_device_info->>'model'), '') || '|' ||
              COALESCE(upper(p_device_info->>'os'), '');
    
    -- Generate SHA-256 hash
    v_fingerprint := encode(digest(v_seed, 'sha256'), 'hex');
    
    RETURN v_fingerprint;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function: Record device usage
CREATE OR REPLACE FUNCTION ussd.record_device_usage(
    p_account_id UUID,
    p_msisdn VARCHAR(20),
    p_network_operator VARCHAR(50),
    p_country_code VARCHAR(2),
    p_device_info JSONB DEFAULT '{}',
    p_imsi_hash VARCHAR(64) DEFAULT NULL,
    p_imei_hash VARCHAR(64) DEFAULT NULL
) RETURNS TABLE (
    fingerprint_id UUID,
    is_new_device BOOLEAN,
    trust_status ussd.device_trust_status,
    risk_score INTEGER,
    sim_swap_detected BOOLEAN,
    requires_verification BOOLEAN
) AS $$
DECLARE
    v_fingerprint_hash VARCHAR(255);
    v_fingerprint_id UUID;
    v_link_id UUID;
    v_is_new_device BOOLEAN := false;
    v_previous_imsi VARCHAR(64);
    v_sim_change BOOLEAN := false;
BEGIN
    -- Generate fingerprint
    v_fingerprint_hash := ussd.generate_device_fingerprint(
        p_msisdn, p_network_operator, p_country_code, p_device_info
    );
    
    -- Find or create fingerprint
    SELECT fp.fingerprint_id INTO v_fingerprint_id
    FROM ussd.device_fingerprints fp
    WHERE fp.fingerprint_hash = v_fingerprint_hash;
    
    IF v_fingerprint_id IS NULL THEN
        -- New device
        v_is_new_device := true;
        
        INSERT INTO ussd.device_fingerprints (
            fingerprint_hash, device_type, device_model_hash, os_type, os_version_hash,
            network_operator, network_country, trust_status, risk_score, risk_factors,
            typical_country, data_retention_until
        ) VALUES (
            v_fingerprint_hash,
            p_device_info->>'type',
            encode(digest(COALESCE(p_device_info->>'model', ''), 'sha256'), 'hex'),
            p_device_info->>'os',
            encode(digest(COALESCE(p_device_info->>'os_version', ''), 'sha256'), 'hex'),
            p_network_operator,
            p_country_code,
            'UNKNOWN',
            10, -- Initial risk for new device
            '{"DEVICE_NEW": 10}'::jsonb,
            p_country_code,
            now() + interval '2 years'
        )
        RETURNING fingerprint_id INTO v_fingerprint_id;
    ELSE
        -- Update existing fingerprint
        UPDATE ussd.device_fingerprints
        SET 
            last_seen_at = now(),
            seen_count = seen_count + 1,
            network_operator = COALESCE(p_network_operator, network_operator),
            network_country = COALESCE(p_country_code, network_country),
            updated_at = now()
        WHERE fingerprint_id = v_fingerprint_id;
    END IF;
    
    -- Check for SIM change
    SELECT current_imsi_hash INTO v_previous_imsi
    FROM ussd.account_device_links
    WHERE account_id = p_account_id AND fingerprint_id = v_fingerprint_id;
    
    IF v_previous_imsi IS NOT NULL AND v_previous_imsi != p_imsi_hash THEN
        v_sim_change := true;
        
        -- Log SIM change
        INSERT INTO ussd.sim_change_history (
            account_id, fingerprint_id, change_type,
            previous_imsi_hash, new_imsi_hash,
            previous_imei_hash, new_imei_hash,
            detection_source, risk_level, is_monitoring_active,
            monitoring_started_at, monitoring_ends_at,
            requires_verification
        ) VALUES (
            p_account_id, v_fingerprint_id, 'SIM_CHANGE',
            v_previous_imsi, p_imsi_hash,
            NULL, p_imei_hash,
            'DEVICE_FP', 'HIGH', true,
            now(), now() + interval '72 hours',
            true
        );
    END IF;
    
    -- Update or create account-device link
    INSERT INTO ussd.account_device_links (
        account_id, fingerprint_id, use_count, last_used_at,
        current_imsi_hash, current_imei_hash,
        new_device_notified
    )
    VALUES (
        p_account_id, v_fingerprint_id, 1, now(),
        p_imsi_hash, p_imei_hash,
        v_is_new_device
    )
    ON CONFLICT (account_id, fingerprint_id)
    DO UPDATE SET
        use_count = ussd.account_device_links.use_count + 1,
        last_used_at = now(),
        current_imsi_hash = EXCLUDED.current_imsi_hash,
        current_imei_hash = EXCLUDED.current_imei_hash;
    
    -- Get current risk info
    SELECT fp.trust_status, fp.risk_score
    INTO trust_status, risk_score
    FROM ussd.device_fingerprints fp
    WHERE fp.fingerprint_id = v_fingerprint_id;
    
    fingerprint_id := v_fingerprint_id;
    is_new_device := v_is_new_device;
    sim_swap_detected := v_sim_change;
    requires_verification := v_sim_change OR v_is_new_device OR risk_score > 50;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Function: Assess device risk
CREATE OR REPLACE FUNCTION ussd.assess_device_risk(
    p_fingerprint_id UUID,
    p_account_id UUID,
    p_transaction_amount NUMERIC DEFAULT 0,
    p_country_code VARCHAR(2) DEFAULT NULL
) RETURNS TABLE (
    risk_score INTEGER,
    risk_level VARCHAR(20),
    risk_factors JSONB,
    trust_status ussd.device_trust_status,
    action_required VARCHAR(50)
) AS $$
DECLARE
    v_score INTEGER := 0;
    v_factors JSONB := '{}';
    v_fp RECORD;
    v_link RECORD;
    v_country_match BOOLEAN;
BEGIN
    -- Get fingerprint details
    SELECT * INTO v_fp FROM ussd.device_fingerprints WHERE fingerprint_id = p_fingerprint_id;
    SELECT * INTO v_link FROM ussd.account_device_links 
    WHERE account_id = p_account_id AND fingerprint_id = p_fingerprint_id;
    
    IF v_fp IS NULL THEN
        risk_score := 100;
        risk_level := 'CRITICAL';
        risk_factors := '{"UNKNOWN_DEVICE": 100}'::jsonb;
        trust_status := 'UNKNOWN';
        action_required := 'BLOCK';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Base risk from device history
    IF v_fp.seen_count = 1 THEN
        v_score := v_score + 15;
        v_factors := v_factors || '{"DEVICE_NEW": 15}'::jsonb;
    ELSIF v_fp.seen_count < 5 THEN
        v_score := v_score + 5;
        v_factors := v_factors || '{"DEVICE_RARE": 5}'::jsonb;
    END IF;
    
    -- Check trust status
    IF v_fp.trust_status = 'TRUSTED' THEN
        v_score := v_score - 10;
        v_factors := v_factors || '{"TRUSTED_DEVICE": -10}'::jsonb;
    ELSIF v_fp.trust_status = 'SUSPICIOUS' THEN
        v_score := v_score + 20;
        v_factors := v_factors || '{"SUSPICIOUS_DEVICE": 20}'::jsonb;
    ELSIF v_fp.trust_status = 'BLOCKED' THEN
        v_score := 100;
        v_factors := v_factors || '{"BLOCKED_DEVICE": 100}'::jsonb;
    END IF;
    
    -- Check account-device relationship
    IF v_link IS NULL THEN
        v_score := v_score + 25;
        v_factors := v_factors || '{"DEVICE_NOT_LINKED": 25}'::jsonb;
    ELSIF v_link.is_trusted THEN
        v_score := v_score - 5;
        v_factors := v_factors || '{"TRUSTED_LINK": -5}'::jsonb;
    ELSIF v_link.is_blocked THEN
        v_score := 100;
        v_factors := v_factors || '{"BLOCKED_LINK": 100}'::jsonb;
    END IF;
    
    -- Geographic check
    IF p_country_code IS NOT NULL AND v_fp.typical_country IS NOT NULL THEN
        IF p_country_code != v_fp.typical_country THEN
            v_score := v_score + 20;
            v_factors := v_factors || '{"GEO_ANOMALY": 20}'::jsonb;
        END IF;
    END IF;
    
    -- Transaction amount check
    IF p_transaction_amount > 1000 THEN
        v_score := v_score + 10;
        v_factors := v_factors || '{"HIGH_AMOUNT": 10}'::jsonb;
    END IF;
    
    -- Velocity check
    IF v_fp.daily_transaction_count > 10 THEN
        v_score := v_score + 15;
        v_factors := v_factors || '{"VELOCITY_EXCEEDED": 15}'::jsonb;
    END IF;
    
    -- Cap score at 100
    v_score := LEAST(v_score, 100);
    v_score := GREATEST(v_score, 0);
    
    -- Determine risk level
    risk_score := v_score;
    risk_factors := v_factors;
    
    IF v_score >= 80 THEN
        risk_level := 'CRITICAL';
        action_required := 'BLOCK';
        trust_status := 'BLOCKED';
    ELSIF v_score >= 50 THEN
        risk_level := 'HIGH';
        action_required := 'CHALLENGE';
        trust_status := 'SUSPICIOUS';
    ELSIF v_score >= 25 THEN
        risk_level := 'MEDIUM';
        action_required := 'VERIFY';
        trust_status := v_fp.trust_status;
    ELSE
        risk_level := 'LOW';
        action_required := 'ALLOW';
        trust_status := COALESCE(v_fp.trust_status, 'UNKNOWN'::ussd.device_trust_status);
    END IF;
    
    -- Log risk assessment
    INSERT INTO ussd.device_risk_events (
        fingerprint_id, event_type, event_category, event_severity,
        new_risk_score, risk_delta, decision_factors,
        account_id, country_code
    ) VALUES (
        p_fingerprint_id, 'RISK_ASSESSMENT', NULL, 
        CASE WHEN risk_level = 'CRITICAL' THEN 'CRITICAL'
             WHEN risk_level = 'HIGH' THEN 'WARNING'
             ELSE 'INFO' END,
        v_score, v_score - v_fp.risk_score, v_factors,
        p_account_id, p_country_code
    );
    
    -- Update fingerprint risk score
    UPDATE ussd.device_fingerprints
    SET 
        risk_score = v_score,
        risk_score_calculated_at = now(),
        risk_factors = v_factors,
        trust_status = CASE 
            WHEN trust_status != trust_status THEN trust_status
            ELSE trust_status
        END,
        updated_at = now()
    WHERE fingerprint_id = p_fingerprint_id;
    
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Function: Verify device for transaction
CREATE OR REPLACE FUNCTION ussd.verify_device_for_transaction(
    p_fingerprint_id UUID,
    p_account_id UUID,
    p_amount NUMERIC,
    p_currency VARCHAR(3)
) RETURNS TABLE (
    allowed BOOLEAN,
    verification_required BOOLEAN,
    verification_type VARCHAR(50),
    risk_score INTEGER,
    reason TEXT
) AS $$
DECLARE
    v_fp RECORD;
    v_link RECORD;
    v_risk_score INTEGER;
BEGIN
    -- Get device info
    SELECT * INTO v_fp FROM ussd.device_fingerprints WHERE fingerprint_id = p_fingerprint_id;
    SELECT * INTO v_link FROM ussd.account_device_links 
    WHERE account_id = p_account_id AND fingerprint_id = p_fingerprint_id;
    
    -- Device blocked
    IF v_fp IS NOT NULL AND v_fp.trust_status = 'BLOCKED' THEN
        allowed := false;
        verification_required := false;
        verification_type := NULL;
        risk_score := 100;
        reason := 'Device is blocked due to security concerns';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Link blocked
    IF v_link IS NOT NULL AND v_link.is_blocked THEN
        allowed := false;
        verification_required := false;
        verification_type := NULL;
        risk_score := 100;
        reason := 'Device access blocked for this account';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- New device
    IF v_link IS NULL OR v_link.use_count < 3 THEN
        allowed := true;
        verification_required := true;
        verification_type := 'PIN';
        risk_score := 30;
        reason := 'New device - additional verification required';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- SIM swap detected in last 72 hours
    IF EXISTS (
        SELECT 1 FROM ussd.sim_change_history
        WHERE account_id = p_account_id
          AND is_monitoring_active = true
          AND change_detected_at > now() - interval '72 hours'
    ) THEN
        allowed := true;
        verification_required := true;
        verification_type := 'MFA';
        risk_score := 60;
        reason := 'Recent SIM change detected - enhanced verification required';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Trusted device
    IF v_link.is_trusted AND v_fp.trust_status = 'TRUSTED' THEN
        allowed := true;
        verification_required := false;
        verification_type := NULL;
        risk_score := 0;
        reason := 'Trusted device - standard authentication';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Default: allow with standard verification
    allowed := true;
    verification_required := true;
    verification_type := 'PIN';
    risk_score := 20;
    reason := 'Standard device verification required';
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Function: Check for SIM swap
CREATE OR REPLACE FUNCTION ussd.check_sim_swap(
    p_account_id UUID,
    p_imsi_hash VARCHAR(64),
    p_imei_hash VARCHAR(64)
) RETURNS TABLE (
    swap_detected BOOLEAN,
    swap_risk_level VARCHAR(20),
    monitoring_active BOOLEAN,
    monitoring_hours_remaining INTEGER,
    requires_action BOOLEAN
) AS $$
DECLARE
    v_recent_change RECORD;
BEGIN
    -- Check for recent SIM change
    SELECT * INTO v_recent_change
    FROM ussd.sim_change_history
    WHERE account_id = p_account_id
      AND (new_imsi_hash = p_imsi_hash OR new_imei_hash = p_imei_hash)
      AND change_detected_at > now() - interval '72 hours'
    ORDER BY change_detected_at DESC
    LIMIT 1;
    
    IF v_recent_change IS NULL THEN
        swap_detected := false;
        swap_risk_level := 'LOW';
        monitoring_active := false;
        monitoring_hours_remaining := 0;
        requires_action := false;
        RETURN NEXT;
        RETURN;
    END IF;
    
    swap_detected := true;
    swap_risk_level := v_recent_change.risk_level;
    monitoring_active := v_recent_change.is_monitoring_active;
    monitoring_hours_remaining := GREATEST(0, 
        extract(epoch from (v_recent_change.monitoring_ends_at - now())) / 3600
    )::integer;
    requires_action := v_recent_change.requires_verification AND NOT v_recent_change.verification_completed;
    
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Function: Update device velocity counters
CREATE OR REPLACE FUNCTION ussd.update_device_velocity(
    p_fingerprint_id UUID,
    p_amount NUMERIC
) RETURNS VOID AS $$
BEGIN
    UPDATE ussd.device_fingerprints
    SET 
        daily_transaction_count = CASE 
            WHEN last_velocity_reset < now() - interval '24 hours' THEN 1
            ELSE daily_transaction_count + 1
        END,
        daily_transaction_amount = CASE 
            WHEN last_velocity_reset < now() - interval '24 hours' THEN p_amount
            ELSE daily_transaction_amount + p_amount
        END,
        last_velocity_reset = CASE 
            WHEN last_velocity_reset < now() - interval '24 hours' THEN now()
            ELSE last_velocity_reset
        END,
        successful_tx_count = successful_tx_count + 1,
        updated_at = now()
    WHERE fingerprint_id = p_fingerprint_id;
END;
$$ LANGUAGE plpgsql;

-- Function: Trust device
CREATE OR REPLACE FUNCTION ussd.trust_device(
    p_fingerprint_id UUID,
    p_account_id UUID,
    p_reason TEXT,
    p_trusted_by UUID
) RETURNS BOOLEAN AS $$
DECLARE
    v_updated INTEGER;
BEGIN
    UPDATE ussd.account_device_links
    SET 
        is_trusted = true,
        trusted_at = now(),
        trusted_reason = p_reason
    WHERE account_id = p_account_id 
      AND fingerprint_id = p_fingerprint_id;
    
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    
    IF v_updated > 0 THEN
        -- Update fingerprint trust
        UPDATE ussd.device_fingerprints
        SET 
            trust_status = 'TRUSTED',
            trust_status_changed_at = now(),
            trust_status_reason = p_reason,
            risk_score = GREATEST(0, risk_score - 10),
            updated_at = now()
        WHERE fingerprint_id = p_fingerprint_id;
        
        -- Log event
        INSERT INTO ussd.device_risk_events (
            fingerprint_id, event_type, event_severity,
            decision_factors, account_id
        ) VALUES (
            p_fingerprint_id, 'DEVICE_TRUSTED', 'INFO',
            jsonb_build_object('reason', p_reason, 'trusted_by', p_trusted_by),
            p_account_id
        );
    END IF;
    
    RETURN v_updated > 0;
END;
$$ LANGUAGE plpgsql;

-- Function: Block device
CREATE OR REPLACE FUNCTION ussd.block_device(
    p_fingerprint_id UUID,
    p_account_id UUID DEFAULT NULL,
    p_reason TEXT,
    p_blocked_by UUID,
    p_duration_hours INTEGER DEFAULT NULL
) RETURNS BOOLEAN AS $$
BEGIN
    -- Block specific link if account provided
    IF p_account_id IS NOT NULL THEN
        UPDATE ussd.account_device_links
        SET 
            is_blocked = true,
            blocked_at = now(),
            block_reason = p_reason,
            blocked_by = p_blocked_by
        WHERE account_id = p_account_id AND fingerprint_id = p_fingerprint_id;
    END IF;
    
    -- Block fingerprint globally
    UPDATE ussd.device_fingerprints
    SET 
        trust_status = 'BLOCKED',
        trust_status_changed_at = now(),
        trust_status_reason = p_reason,
        is_blacklisted = true,
        blacklisted_by = p_blocked_by,
        blacklisted_at = now(),
        blacklist_reason = p_reason,
        blacklist_expires_at = CASE 
            WHEN p_duration_hours IS NOT NULL THEN now() + (p_duration_hours || ' hours')::interval
            ELSE NULL
        END,
        updated_at = now()
    WHERE fingerprint_id = p_fingerprint_id;
    
    -- Log event
    INSERT INTO ussd.device_risk_events (
        fingerprint_id, event_type, event_severity,
        decision_factors
    ) VALUES (
        p_fingerprint_id, 'DEVICE_BLOCKED', 'CRITICAL',
        jsonb_build_object('reason', p_reason, 'blocked_by', p_blocked_by, 'account_specific', p_account_id IS NOT NULL)
    );
    
    RETURN true;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TRIGGER FUNCTIONS
-- =============================================================================

-- Trigger: Update timestamps
CREATE OR REPLACE FUNCTION ussd.trigger_update_device_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_device_fingerprints_update
    BEFORE UPDATE ON ussd.device_fingerprints
    FOR EACH ROW
    EXECUTE FUNCTION ussd.trigger_update_device_timestamp();

CREATE TRIGGER trg_account_device_links_update
    BEFORE UPDATE ON ussd.account_device_links
    FOR EACH ROW
    EXECUTE FUNCTION ussd.trigger_update_device_timestamp();

-- =============================================================================
-- ROW LEVEL SECURITY
-- =============================================================================

ALTER TABLE ussd.device_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.account_device_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.sim_change_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.device_risk_events ENABLE ROW LEVEL SECURITY;

-- Policies
CREATE POLICY device_fp_read ON ussd.device_fingerprints
    FOR SELECT USING (true);  -- Fingerprint hashes are safe to read

CREATE POLICY device_fp_write ON ussd.device_fingerprints
    FOR ALL USING (current_setting('app.current_role', true) = 'ussd_security_role');

CREATE POLICY account_device_account_isolation ON ussd.account_device_links
    FOR ALL USING (
        account_id = current_setting('app.current_account_id', true)::UUID
        OR current_setting('app.current_role', true) = 'ussd_security_role'
    );

-- =============================================================================
-- GRANTS
-- =============================================================================

GRANT SELECT ON ussd.device_fingerprints TO ussd_gateway_role;
GRANT SELECT, INSERT, UPDATE ON ussd.account_device_links TO ussd_gateway_role;
GRANT INSERT ON ussd.sim_change_history TO ussd_gateway_role;
GRANT INSERT ON ussd.device_risk_events TO ussd_gateway_role;
GRANT ALL ON ussd.device_fingerprints TO ussd_security_role;
GRANT ALL ON ussd.sim_change_history TO ussd_security_role;
GRANT ALL ON ussd.device_risk_events TO ussd_security_role;

-- =============================================================================
-- COMPLIANCE NOTES
-- =============================================================================
/*
1. LAWFUL BASIS (GDPR Article 6):
   Primary: Legitimate interest (fraud prevention)
   Secondary: Consent (for enhanced tracking)
   Balance test: Necessary, proportionate, less intrusive alternatives

2. TRANSPARENCY REQUIREMENTS:
   - Privacy notice must disclose fingerprinting
   - Explain purpose: fraud prevention only
   - Describe data collected: hashed device characteristics
   - Retention period: 2 years
   - Rights: Access, contest, erasure (where applicable)

3. AUTOMATED DECISION-MAKING (Article 22):
   - Risk scores may trigger automated blocks
   - Human review available on request
   - Right to contest automated decisions
   - Regular accuracy testing of risk models

4. DATA MINIMIZATION:
   - MSISDN: Included in hash only; never stored
   - Device Model: Hashed; pattern detection only
   - OS Version: Hashed; security patch level inferred
   - Network Operator: Stored; geographic/regulatory info
   - Usage Patterns: Anonymized; statistical analysis only

5. RISK SCORING FACTORS (Transparent):
   - New device (never seen): +10 points
   - Geographic anomaly (different country): +20 points
   - Velocity (multiple rapid transactions): +15 points
   - Time anomaly (unusual hour): +5 points
   - Known fraud pattern match: +50 points
   - Previously trusted device: -10 points
   
   Thresholds:
   - 0-20: Low risk, normal processing
   - 21-50: Medium risk, additional verification
   - 51-79: High risk, enhanced authentication
   - 80+: Critical risk, block or manual review

6. GSMA IR.71 SIM SWAP DETECTION:
   - 72-hour monitoring window
   - Multi-source correlation
   - Automatic risk elevation
   - Enhanced verification requirements

7. SUBJECT RIGHTS IMPLEMENTATION:
   - Access: Device history with risk factors explained
   - Rectification: Challenge incorrect risk flags
   - Erasure: Delete device history (unless fraud investigation)
   - Portability: Export device history in standard format
*/
