-- =============================================================================
-- USSD KERNEL CORE SCHEMA - KYC/AML MONITORING
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    061_core_kyc_aml_monitoring.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      core
-- DESCRIPTION: KYC verification, AML transaction monitoring, sanctions
--              screening, and suspicious activity detection.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Security monitoring
├── A.16.1 Management of information security incidents
└── A.18.1 Compliance - Legal and regulatory requirements

AML/CFT Regulations
├── FATF Recommendations
├── Local AML laws (FICA, POCA, etc.)
├── Transaction monitoring
├── Suspicious Activity Reports (SAR)
└── Sanctions screening

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. REAL-TIME MONITORING
   - Trigger-based detection
   - Velocity checks
   - Pattern analysis

2. RISK SCORING
   - Customer risk rating
   - Transaction risk scoring
   - Alert generation

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

AML SECURITY:
- Immutable alert records
- Audit trail for all screening
- Restricted access to sensitive lists

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- TRANSACTION_SCREENED
- ALERT_GENERATED
- SAR_FILED
- SANCTIONS_MATCH

RETENTION: 7 years (regulatory requirement)
================================================================================
*/

-- =============================================================================
-- KYC VERIFICATION STATUS
-- =============================================================================

CREATE TABLE core.kyc_verifications (
    verification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES core.account_registry(account_id),
    
    -- Verification level
    verification_level VARCHAR(20) NOT NULL DEFAULT 'NONE'
        CHECK (verification_level IN ('NONE', 'BASIC', 'STANDARD', 'ENHANCED')),
    
    -- Document verification
    id_document_type VARCHAR(50),
    id_document_number VARCHAR(100),
    id_verified BOOLEAN DEFAULT FALSE,
    id_verified_at TIMESTAMPTZ,
    
    -- Address verification
    address_verified BOOLEAN DEFAULT FALSE,
    address_verified_at TIMESTAMPTZ,
    
    -- Biometric verification
    biometric_verified BOOLEAN DEFAULT FALSE,
    biometric_verified_at TIMESTAMPTZ,
    
    -- PEP/Sanctions screening
    pep_status VARCHAR(20) CHECK (pep_status IN ('CLEAR', 'MATCH', 'PENDING')),
    sanctions_status VARCHAR(20) CHECK (sanctions_status IN ('CLEAR', 'MATCH', 'PENDING')),
    screened_at TIMESTAMPTZ,
    
    -- Risk rating
    risk_rating VARCHAR(20) DEFAULT 'MEDIUM'
        CHECK (risk_rating IN ('LOW', 'MEDIUM', 'HIGH', 'PROHIBITED')),
    risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    
    -- Validity
    valid_from TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    valid_until TIMESTAMPTZ,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    verified_by UUID,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- AML ALERTS
-- =============================================================================

CREATE TABLE core.aml_alerts (
    alert_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Alert classification
    alert_type VARCHAR(50) NOT NULL
        CHECK (alert_type IN ('VELOCITY', 'THRESHOLD', 'PATTERN', 'SANCTIONS', 'PEP', 'STRUCTURING', 'LAYERING')),
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM'
        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    
    -- Related entities
    account_id UUID REFERENCES core.account_registry(account_id),
    transaction_id BIGINT REFERENCES core.transaction_log(transaction_id),
    
    -- Alert details
    alert_description TEXT NOT NULL,
    triggered_rule VARCHAR(100),
    rule_parameters JSONB,
    
    -- Risk assessment
    risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    risk_factors TEXT[],
    
    -- Status
    status VARCHAR(20) DEFAULT 'OPEN'
        CHECK (status IN ('OPEN', 'UNDER_REVIEW', 'ESCALATED', 'CLOSED_FALSE_POSITIVE', 'CLOSED_CONFIRMED', 'SAR_FILED')),
    
    -- Investigation
    assigned_to UUID,
    investigation_notes TEXT,
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    
    -- SAR filing
    sar_filed BOOLEAN DEFAULT FALSE,
    sar_reference VARCHAR(100),
    sar_filed_at TIMESTAMPTZ,
    sar_filed_by UUID,
    
    -- Timestamps
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    closed_at TIMESTAMPTZ,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- SANCTIONS LISTS
-- =============================================================================

CREATE TABLE core.sanctions_lists (
    list_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    list_name VARCHAR(100) NOT NULL,
    list_authority VARCHAR(100) NOT NULL,  -- UN, OFAC, EU, etc.
    list_type VARCHAR(20) NOT NULL
        CHECK (list_type IN ('INDIVIDUAL', 'ENTITY', 'VESSEL', 'AIRCRAFT', 'COUNTRY')),
    
    -- Entity details
    entity_name VARCHAR(255) NOT NULL,
    entity_aliases TEXT[],
    entity_identifiers JSONB,  -- Passport numbers, registration numbers, etc.
    
    -- Address info
    addresses TEXT[],
    countries TEXT[],
    
    -- List metadata
    list_date DATE,
    reason_for_listing TEXT,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    removed_at TIMESTAMPTZ,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- Sanctions screening results
CREATE TABLE core.sanctions_screenings (
    screening_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- What was screened
    account_id UUID REFERENCES core.account_registry(account_id),
    transaction_id BIGINT REFERENCES core.transaction_log(transaction_id),
    screened_name VARCHAR(255) NOT NULL,
    screened_identifiers JSONB,
    
    -- Match result
    list_id UUID REFERENCES core.sanctions_lists(list_id),
    match_score NUMERIC(5,2),  -- 0-100 match confidence
    match_status VARCHAR(20) CHECK (match_status IN ('NO_MATCH', 'POTENTIAL_MATCH', 'CONFIRMED_MATCH')),
    match_reason TEXT,
    
    -- Review
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    review_decision VARCHAR(20) CHECK (review_decision IN ('FALSE_POSITIVE', 'TRUE_POSITIVE', 'PENDING')),
    
    -- Timestamps
    screened_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    
    -- Audit
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- TRANSACTION MONITORING RULES
-- =============================================================================

CREATE TABLE core.aml_rules (
    rule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_code VARCHAR(50) UNIQUE NOT NULL,
    rule_name VARCHAR(200) NOT NULL,
    rule_description TEXT,
    
    -- Rule configuration
    rule_type VARCHAR(50) NOT NULL
        CHECK (rule_type IN ('VELOCITY', 'AGGREGATE', 'THRESHOLD', 'PATTERN', 'DEVIATION')),
    rule_config JSONB NOT NULL,  -- Flexible rule parameters
    
    -- Thresholds
    threshold_amount NUMERIC(20, 8),
    threshold_count INTEGER,
    threshold_period INTERVAL,
    
    -- Risk scoring
    risk_weight INTEGER DEFAULT 10,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 100,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- KYC indexes
CREATE INDEX idx_kyc_account ON core.kyc_verifications(account_id, valid_until);
CREATE INDEX idx_kyc_risk ON core.kyc_verifications(risk_rating, valid_until) WHERE valid_until IS NULL;
CREATE INDEX idx_kyc_pep ON core.kyc_verifications(pep_status, screened_at);

-- AML alert indexes
CREATE INDEX idx_aml_alerts_status ON core.aml_alerts(status, severity);
CREATE INDEX idx_aml_alerts_account ON core.aml_alerts(account_id, triggered_at DESC);
CREATE INDEX idx_aml_alerts_transaction ON core.aml_alerts(transaction_id);
CREATE INDEX idx_aml_alerts_type ON core.aml_alerts(alert_type, triggered_at);
CREATE INDEX idx_aml_alerts_open ON core.aml_alerts(alert_id) WHERE status = 'OPEN';

-- Sanctions indexes
CREATE INDEX idx_sanctions_name ON core.sanctions_lists USING gin(entity_name gin_trgm_ops);
CREATE INDEX idx_sanctions_active ON core.sanctions_lists(list_authority, is_active);
CREATE INDEX idx_sanctions_screening ON core.sanctions_screenings(account_id, screened_at DESC);

-- =============================================================================
-- IMMUTABILITY TRIGGERS (except sanctions lists which need updates)
-- =============================================================================

CREATE TRIGGER trg_kyc_prevent_update
    BEFORE UPDATE ON core.kyc_verifications
    FOR EACH ROW EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_kyc_prevent_delete
    BEFORE DELETE ON core.kyc_verifications
    FOR EACH ROW EXECUTE FUNCTION core.prevent_delete();

CREATE TRIGGER trg_aml_alerts_prevent_update
    BEFORE UPDATE ON core.aml_alerts
    FOR EACH ROW EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_aml_alerts_prevent_delete
    BEFORE DELETE ON core.aml_alerts
    FOR EACH ROW EXECUTE FUNCTION core.prevent_delete();

CREATE TRIGGER trg_sanctions_screening_prevent_update
    BEFORE UPDATE ON core.sanctions_screenings
    FOR EACH ROW EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_sanctions_screening_prevent_delete
    BEFORE DELETE ON core.sanctions_screenings
    FOR EACH ROW EXECUTE FUNCTION core.prevent_delete();

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

ALTER TABLE core.kyc_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.aml_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.sanctions_lists ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.sanctions_screenings ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.aml_rules ENABLE ROW LEVEL SECURITY;

-- KYC - self or kernel
CREATE POLICY kyc_self_access ON core.kyc_verifications
    FOR SELECT TO ussd_app_user
    USING (account_id = current_setting('app.current_account_id', true)::UUID);

-- AML alerts - compliance officers only (via app layer)
CREATE POLICY aml_alerts_kernel ON core.aml_alerts
    FOR ALL TO ussd_kernel_role USING (true);

-- Sanctions lists - read only for users
CREATE POLICY sanctions_read ON core.sanctions_lists
    FOR SELECT TO ussd_app_user USING (is_active = TRUE);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to calculate transaction risk score
CREATE OR REPLACE FUNCTION core.calculate_transaction_risk(
    p_account_id UUID,
    p_amount NUMERIC,
    p_currency VARCHAR,
    p_transaction_type VARCHAR
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_kyc RECORD;
    v_score INTEGER := 0;
    v_daily_volume NUMERIC;
BEGIN
    -- Get KYC info
    SELECT * INTO v_kyc FROM core.kyc_verifications 
    WHERE account_id = p_account_id AND valid_until IS NULL
    ORDER BY valid_from DESC LIMIT 1;
    
    -- Base risk from KYC
    IF v_kyc.risk_rating = 'HIGH' THEN
        v_score := v_score + 30;
    ELSIF v_kyc.risk_rating = 'PROHIBITED' THEN
        RETURN 100;  -- Immediate block
    END IF;
    
    -- Amount-based risk
    IF p_amount > 100000 THEN
        v_score := v_score + 20;
    ELSIF p_amount > 10000 THEN
        v_score := v_score + 10;
    END IF;
    
    -- Check daily velocity
    SELECT COALESCE(SUM(amount), 0) INTO v_daily_volume
    FROM core.transaction_log
    WHERE initiator_account_id = p_account_id
      AND committed_at >= core.precise_now() - INTERVAL '24 hours';
    
    IF v_daily_volume > 1000000 THEN
        v_score := v_score + 25;
    ELSIF v_daily_volume > 100000 THEN
        v_score := v_score + 15;
    END IF;
    
    -- Transaction type risk
    IF p_transaction_type IN ('CASH_OUT', 'WIRE_TRANSFER') THEN
        v_score := v_score + 10;
    END IF;
    
    RETURN LEAST(v_score, 100);
END;
$$;

-- Function to create AML alert
CREATE OR REPLACE FUNCTION core.create_aml_alert(
    p_alert_type VARCHAR,
    p_severity VARCHAR,
    p_account_id UUID,
    p_transaction_id BIGINT,
    p_description TEXT,
    p_rule_code VARCHAR DEFAULT NULL,
    p_risk_score INTEGER DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_alert_id UUID;
    v_reference VARCHAR(100);
BEGIN
    v_reference := 'AML-' || TO_CHAR(core.precise_now(), 'YYYYMMDD-HH24MISS') || '-' || 
                   SUBSTRING(MD5(RANDOM()::TEXT), 1, 4);
    
    INSERT INTO core.aml_alerts (
        alert_reference,
        alert_type,
        severity,
        account_id,
        transaction_id,
        alert_description,
        triggered_rule,
        risk_score
    ) VALUES (
        v_reference,
        p_alert_type,
        p_severity,
        p_account_id,
        p_transaction_id,
        p_description,
        p_rule_code,
        p_risk_score
    )
    RETURNING alert_id INTO v_alert_id;
    
    RETURN v_alert_id;
END;
$$;

-- Function to screen against sanctions
CREATE OR REPLACE FUNCTION core.screen_sanctions(
    p_name VARCHAR,
    p_identifiers JSONB DEFAULT NULL
)
RETURNS TABLE (
    list_id UUID,
    entity_name VARCHAR,
    match_score NUMERIC,
    match_status VARCHAR
)
LANGUAGE plpgsql
AS $$
BEGIN
    -- Simple name matching (fuzzy matching would be more sophisticated)
    RETURN QUERY
    SELECT 
        sl.list_id,
        sl.entity_name,
        100::NUMERIC as match_score,  -- Placeholder for actual matching algorithm
        'POTENTIAL_MATCH'::VARCHAR as match_status
    FROM core.sanctions_lists sl
    WHERE sl.is_active = TRUE
      AND (sl.entity_name ILIKE '%' || p_name || '%' 
           OR EXISTS (
               SELECT 1 FROM unnest(sl.entity_aliases) alias 
               WHERE alias ILIKE '%' || p_name || '%'
           ));
END;
$$;

-- Function to record sanctions screening
CREATE OR REPLACE FUNCTION core.record_sanctions_screening(
    p_account_id UUID,
    p_transaction_id BIGINT,
    p_screened_name VARCHAR,
    p_list_id UUID,
    p_match_score NUMERIC,
    p_match_status VARCHAR
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_screening_id UUID;
BEGIN
    INSERT INTO core.sanctions_screenings (
        account_id,
        transaction_id,
        screened_name,
        list_id,
        match_score,
        match_status
    ) VALUES (
        p_account_id,
        p_transaction_id,
        p_screened_name,
        p_list_id,
        p_match_score,
        p_match_status
    )
    RETURNING screening_id INTO v_screening_id;
    
    -- If confirmed match, create AML alert
    IF p_match_status = 'CONFIRMED_MATCH' THEN
        PERFORM core.create_aml_alert(
            'SANCTIONS',
            'CRITICAL',
            p_account_id,
            p_transaction_id,
            'Confirmed sanctions match: ' || p_screened_name,
            'SANCTIONS_SCREENING',
            100
        );
    END IF;
    
    RETURN v_screening_id;
END;
$$;

-- =============================================================================
-- INITIAL DATA - Sample AML Rules
-- =============================================================================

INSERT INTO core.aml_rules (rule_code, rule_name, rule_description, rule_type, rule_config, threshold_amount, threshold_count, threshold_period, risk_weight) VALUES
('VEL_HIGH', 'High Velocity', 'More than 50 transactions in 1 hour', 'VELOCITY', '{"window": "1 hour"}', NULL, 50, '1 hour'::INTERVAL, 30),
('AMT_LARGE', 'Large Transaction', 'Single transaction above 100,000', 'THRESHOLD', '{}', 100000, NULL, NULL, 25),
('AGG_DAILY', 'Daily Aggregate', 'Daily aggregate above 1,000,000', 'AGGREGATE', '{"period": "daily"}', 1000000, NULL, '1 day'::INTERVAL, 20),
('PATTERN_STRUCT', 'Structuring Pattern', 'Multiple transactions just below threshold', 'PATTERN', '{"threshold": 10000, "count": 5}', 10000, 5, '24 hours'::INTERVAL, 40),
('DEVIATION', 'Unusual Pattern', 'Deviation from customer profile', 'DEVIATION', '{"deviation_factor": 3}', NULL, NULL, '30 days'::INTERVAL, 15)
ON CONFLICT (rule_code) DO NOTHING;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE core.kyc_verifications IS 'KYC verification status and risk ratings';
COMMENT ON TABLE core.aml_alerts IS 'AML alerts for suspicious activity';
COMMENT ON TABLE core.sanctions_lists IS 'Sanctions lists from various authorities';
COMMENT ON TABLE core.sanctions_screenings IS 'Results of sanctions screening';
COMMENT ON FUNCTION core.calculate_transaction_risk IS 'Calculate risk score for transaction';

-- =============================================================================
-- END OF FILE
-- =============================================================================
