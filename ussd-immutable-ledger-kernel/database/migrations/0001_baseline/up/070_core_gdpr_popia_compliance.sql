-- =============================================================================
-- USSD KERNEL CORE SCHEMA - GDPR/POPIA COMPLIANCE
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    070_core_gdpr_popia_compliance.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      core
-- DESCRIPTION: Data protection compliance for GDPR (EU) and POPIA (South Africa)
--              including data subject rights, consent management, and privacy controls.
-- =============================================================================

/*
================================================================================
GDPR/POPIA COMPLIANCE FRAMEWORK
================================================================================

GDPR (General Data Protection Regulation) - EU/EEA
├── Article 5: Principles (lawfulness, fairness, transparency)
├── Article 6: Lawfulness of processing (consent, contract, legal obligation)
├── Article 7: Conditions for consent
├── Article 15: Right of access
├── Article 16: Right to rectification
├── Article 17: Right to erasure (right to be forgotten)
├── Article 18: Right to restriction of processing
├── Article 20: Right to data portability
├── Article 25: Data protection by design and by default
├── Article 30: Records of processing activities
├── Article 32: Security of processing
├── Article 33: Breach notification (72 hours)
└── Article 35: Data Protection Impact Assessment (DPIA)

POPIA (Protection of Personal Information Act) - South Africa
├── Chapter 3: Conditions for lawful processing
├── Chapter 5: Rights of data subjects
├── Chapter 7: Security measures
└── Chapter 11: Transborder information flows

================================================================================
TECHNICAL IMPLEMENTATION
================================================================================

This migration implements:
1. Data Subject Rights (DSR) tracking
2. Consent management
3. Data inventory and classification
4. Right to erasure (pseudonymization)
5. Data portability
6. Privacy impact assessments
7. Breach notification tracking

================================================================================
*/

-- =============================================================================
-- PERSONAL DATA INVENTORY
-- =============================================================================

CREATE TABLE core.personal_data_inventory (
    data_element_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Data identification
    table_name VARCHAR(100) NOT NULL,
    column_name VARCHAR(100) NOT NULL,
    
    -- Classification
    data_category VARCHAR(50) NOT NULL
        CHECK (data_category IN ('IDENTIFIER', 'CONTACT', 'FINANCIAL', 'BIOMETRIC', 'SENSITIVE', 'SPECIAL_CATEGORY')),
    sensitivity_level VARCHAR(20) NOT NULL 
        CHECK (sensitivity_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    
    -- Processing details
    legal_basis VARCHAR(50) NOT NULL
        CHECK (legal_basis IN ('CONSENT', 'CONTRACT', 'LEGAL_OBLIGATION', 'VITAL_INTEREST', 'PUBLIC_TASK', 'LEGITIMATE_INTEREST')),
    processing_purpose TEXT NOT NULL,
    processing_activity TEXT,
    
    -- Retention
    retention_period INTERVAL NOT NULL,
    retention_justification TEXT,
    deletion_procedure TEXT,
    
    -- Security
    encryption_required BOOLEAN DEFAULT TRUE,
    pseudonymization_possible BOOLEAN DEFAULT FALSE,
    
    -- Jurisdiction
    storage_location VARCHAR(50) DEFAULT 'EU',  -- EU, ZA, US, etc.
    cross_border_transfer BOOLEAN DEFAULT FALSE,
    transfer_safeguard VARCHAR(50),  -- SCC, BCR, Adequacy decision
    
    -- DPIA
    requires_dpia BOOLEAN DEFAULT FALSE,
    dpia_reference VARCHAR(100),
    
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT core.precise_now(),
    last_reviewed_at TIMESTAMPTZ,
    
    UNIQUE(table_name, column_name)
);

-- =============================================================================
-- CONSENT MANAGEMENT
-- =============================================================================

CREATE TABLE core.consent_registry (
    consent_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID REFERENCES core.account_registry(account_id),
    
    -- Consent details
    consent_type VARCHAR(50) NOT NULL
        CHECK (consent_type IN ('MARKETING', 'DATA_SHARING', 'ANALYTICS', 'THIRD_PARTY', 'BIOMETRIC', 'LOCATION')),
    consent_version INTEGER NOT NULL DEFAULT 1,
    
    -- Status
    consent_status VARCHAR(20) NOT NULL DEFAULT 'GRANTED'
        CHECK (consent_status IN ('GRANTED', 'WITHDRAWN', 'EXPIRED', 'PENDING')),
    
    -- Context
    consent_granted_at TIMESTAMPTZ DEFAULT core.precise_now(),
    consent_granted_via VARCHAR(50),  -- 'WEB', 'MOBILE', 'USSD', 'BRANCH'
    consent_granted_ip INET,
    consent_withdrawn_at TIMESTAMPTZ,
    consent_expires_at TIMESTAMPTZ,
    
    -- Legal basis
    legal_basis VARCHAR(50),
    processing_purposes TEXT[],
    
    -- Document
    consent_document_hash VARCHAR(64),
    consent_language VARCHAR(10) DEFAULT 'en',
    
    -- Audit
    created_at TIMESTAMPTZ DEFAULT core.precise_now(),
    updated_at TIMESTAMPTZ DEFAULT core.precise_now(),
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- Consent history (immutable)
CREATE TABLE core.consent_history (
    history_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consent_id UUID REFERENCES core.consent_registry(consent_id),
    
    change_type VARCHAR(20) NOT NULL 
        CHECK (change_type IN ('GRANTED', 'WITHDRAWN', 'UPDATED', 'EXPIRED')),
    previous_status VARCHAR(20),
    new_status VARCHAR(20),
    changed_by UUID,
    changed_at TIMESTAMPTZ DEFAULT core.precise_now(),
    change_reason TEXT,
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- DATA SUBJECT RIGHTS REQUESTS
-- =============================================================================

CREATE TABLE core.data_subject_requests (
    request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID REFERENCES core.account_registry(account_id),
    
    -- Request details
    request_type VARCHAR(20) NOT NULL
        CHECK (request_type IN ('ACCESS', 'RECTIFICATION', 'ERASURE', 'RESTRICTION', 'PORTABILITY', 'OBJECTION')),
    request_status VARCHAR(20) DEFAULT 'PENDING'
        CHECK (request_status IN ('PENDING', 'IN_REVIEW', 'FULFILLED', 'PARTIALLY_FULFILLED', 'REJECTED', 'EXTENDED')),
    
    -- Request content
    request_description TEXT,
    request_evidence JSONB,  -- Supporting documentation
    
    -- GDPR/POPIA deadlines
    request_received_at TIMESTAMPTZ DEFAULT core.precise_now(),
    deadline_at TIMESTAMPTZ,  -- 30 days for GDPR, usually 30-60 for POPIA
    extension_granted BOOLEAN DEFAULT FALSE,
    extension_reason TEXT,
    
    -- Fulfillment
    fulfilled_at TIMESTAMPTZ,
    fulfillment_method VARCHAR(50),  -- 'DOWNLOAD', 'EMAIL', 'PORTAL', 'API'
    data_format VARCHAR(20),  -- 'JSON', 'XML', 'CSV', 'PDF'
    
    -- Rejection (if applicable)
    rejection_reason TEXT,
    rejection_code VARCHAR(20),
    rejected_by UUID,
    rejected_at TIMESTAMPTZ,
    
    -- Appeal
    appeal_filed BOOLEAN DEFAULT FALSE,
    appeal_status VARCHAR(20),
    
    -- Compliance
    supervisory_authority_notified BOOLEAN DEFAULT FALSE,
    authority_reference VARCHAR(100),
    
    -- Audit
    assigned_to UUID,
    created_at TIMESTAMPTZ DEFAULT core.precise_now(),
    updated_at TIMESTAMPTZ DEFAULT core.precise_now(),
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- DSR fulfillment log (what data was provided/modified)
CREATE TABLE core.dsr_fulfillment_log (
    log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID REFERENCES core.data_subject_requests(request_id),
    
    action_taken VARCHAR(50) NOT NULL,
    table_affected VARCHAR(100),
    records_affected INTEGER,
    data_extracted JSONB,  -- For access/portability requests
    
    verified_by UUID,
    verified_at TIMESTAMPTZ,
    
    created_at TIMESTAMPTZ DEFAULT core.precise_now()
);

-- =============================================================================
-- DATA BREACH NOTIFICATION
-- =============================================================================

CREATE TABLE core.data_breach_log (
    breach_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Breach details
    breach_type VARCHAR(50) NOT NULL
        CHECK (breach_type IN ('UNAUTHORIZED_ACCESS', 'DATA_LOSS', 'RANSOMWARE', 'INSIDER_THREAT', 'SYSTEM_COMPROMISE', 'PHYSICAL_LOSS')),
    breach_severity VARCHAR(20) NOT NULL
        CHECK (breach_severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    
    -- Timeline
    detected_at TIMESTAMPTZ NOT NULL,
    occurred_at TIMESTAMPTZ,
    contained_at TIMESTAMPTZ,
    
    -- Impact assessment
    affected_data_categories VARCHAR(50)[],  -- What types of personal data
    affected_individuals_count INTEGER,
    affected_records_count INTEGER,
    
    -- Risk assessment
    likelihood_of_harm VARCHAR(20),
    severity_of_harm VARCHAR(20),
    requires_notification BOOLEAN,
    
    -- Notifications
    supervisory_authority_notified BOOLEAN DEFAULT FALSE,
    authority_notified_at TIMESTAMPTZ,
    authority_notification_ref VARCHAR(100),
    data_subjects_notified BOOLEAN DEFAULT FALSE,
    data_subjects_notified_at TIMESTAMPTZ,
    
    -- Remediation
    root_cause TEXT,
    remedial_actions TEXT[],
    preventive_measures TEXT[],
    
    -- Status
    breach_status VARCHAR(20) DEFAULT 'DETECTED'
        CHECK (breach_status IN ('DETECTED', 'UNDER_INVESTIGATION', 'CONTAINED', 'REMEDIATED', 'CLOSED')),
    
    -- Audit
    reported_by UUID,
    investigated_by UUID[],
    created_at TIMESTAMPTZ DEFAULT core.precise_now(),
    closed_at TIMESTAMPTZ,
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- PRIVACY IMPACT ASSESSMENTS
-- =============================================================================

CREATE TABLE core.privacy_impact_assessments (
    dpia_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Assessment details
    dpia_reference VARCHAR(50) UNIQUE NOT NULL,
    assessment_name VARCHAR(200) NOT NULL,
    assessment_scope TEXT,
    
    -- Status
    assessment_status VARCHAR(20) DEFAULT 'DRAFT'
        CHECK (assessment_status IN ('DRAFT', 'UNDER_REVIEW', 'APPROVED', 'REJECTED', 'SUPERSEDED')),
    
    -- Risk assessment
    high_risk_processing BOOLEAN,
    risks_identified JSONB,
    mitigations_proposed JSONB,
    residual_risk VARCHAR(20),
    
    -- Stakeholders
    data_controller VARCHAR(100),
    data_protection_officer UUID,
    reviewed_by UUID[],
    
    -- Dates
    assessment_date DATE,
    review_date DATE,
    next_review_date DATE,
    
    -- Document
    assessment_document_hash VARCHAR(64),
    
    created_at TIMESTAMPTZ DEFAULT core.precise_now()
);

-- =============================================================================
-- INDEXES
-- =============================================================================

CREATE INDEX idx_personal_data_inventory_table ON core.personal_data_inventory(table_name, sensitivity_level);
CREATE INDEX idx_personal_data_inventory_category ON core.personal_data_inventory(data_category);

CREATE INDEX idx_consent_registry_account ON core.consent_registry(account_id, consent_type, consent_status);
CREATE INDEX idx_consent_registry_status ON core.consent_registry(consent_status, consent_expires_at);

CREATE INDEX idx_dsr_account ON core.data_subject_requests(account_id, request_status);
CREATE INDEX idx_dsr_deadline ON core.data_subject_requests(deadline_at) WHERE request_status IN ('PENDING', 'IN_REVIEW');

CREATE INDEX idx_data_breach_status ON core.data_breach_log(breach_status, detected_at DESC);
CREATE INDEX idx_data_breach_notification ON core.data_breach_log(requires_notification, supervisory_authority_notified);

-- =============================================================================
-- IMMUTABILITY TRIGGERS
-- =============================================================================

CREATE TRIGGER trg_consent_history_prevent_update
    BEFORE UPDATE ON core.consent_history
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_dsr_fulfillment_log_prevent_update
    BEFORE UPDATE ON core.dsr_fulfillment_log
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_data_breach_log_immutable
    BEFORE UPDATE ON core.data_breach_log
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update_except_status();

-- =============================================================================
-- DSR FUNCTIONS
-- =============================================================================

-- Function to submit data subject request
CREATE OR REPLACE FUNCTION core.submit_data_subject_request(
    p_account_id UUID,
    p_request_type VARCHAR,
    p_description TEXT DEFAULT NULL,
    p_evidence JSONB DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_request_id UUID;
    v_deadline TIMESTAMPTZ;
BEGIN
    -- Calculate deadline (30 days from now for GDPR)
    v_deadline := core.precise_now() + INTERVAL '30 days';
    
    INSERT INTO core.data_subject_requests (
        account_id,
        request_type,
        request_description,
        request_evidence,
        deadline_at
    ) VALUES (
        p_account_id,
        p_request_type,
        p_description,
        p_evidence,
        v_deadline
    )
    RETURNING request_id INTO v_request_id;
    
    -- Log for compliance
    INSERT INTO core.audit_trail (
        table_name, record_id, action, performed_by, new_values
    ) VALUES (
        'data_subject_requests',
        v_request_id::TEXT,
        'CREATE',
        p_account_id,
        jsonb_build_object('request_type', p_request_type)
    );
    
    RETURN v_request_id;
END;
$$;

-- Function to fulfill access request (data portability)
CREATE OR REPLACE FUNCTION core.fulfill_access_request(
    p_request_id UUID,
    p_format VARCHAR DEFAULT 'JSON'
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_account_id UUID;
    v_result JSONB;
BEGIN
    SELECT account_id INTO v_account_id
    FROM core.data_subject_requests
    WHERE request_id = p_request_id AND request_type = 'ACCESS';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Request not found or not an access request';
    END IF;
    
    -- Compile personal data
    SELECT jsonb_build_object(
        'account', (
            SELECT jsonb_build_object(
                'unique_identifier', unique_identifier,
                'account_type', account_type,
                'created_at', created_at,
                'kyc_status', kyc_status
            )
            FROM core.account_registry WHERE account_id = v_account_id
        ),
        'transactions', (
            SELECT jsonb_agg(jsonb_build_object(
                'transaction_id', transaction_id,
                'type', transaction_type_id,
                'amount', amount,
                'currency', currency,
                'committed_at', committed_at
            ))
            FROM core.transaction_log 
            WHERE initiator_account_id = v_account_id
            AND committed_at > NOW() - INTERVAL '12 months'
        ),
        'consents', (
            SELECT jsonb_agg(jsonb_build_object(
                'consent_type', consent_type,
                'status', consent_status,
                'granted_at', consent_granted_at,
                'purposes', processing_purposes
            ))
            FROM core.consent_registry WHERE account_id = v_account_id
        ),
        'audit_trail', (
            SELECT jsonb_agg(jsonb_build_object(
                'action', action,
                'table_name', table_name,
                'performed_at', performed_at
            ))
            FROM core.audit_trail 
            WHERE changed_by = v_account_id
            AND performed_at > NOW() - INTERVAL '12 months'
        )
    ) INTO v_result;
    
    -- Log fulfillment
    INSERT INTO core.dsr_fulfillment_log (
        request_id, action_taken, data_extracted, verified_by
    ) VALUES (
        p_request_id, 'DATA_ACCESS', v_result, NULL
    );
    
    -- Update request status
    UPDATE core.data_subject_requests SET
        request_status = 'FULFILLED',
        fulfilled_at = core.precise_now(),
        fulfillment_method = 'PORTAL',
        data_format = p_format
    WHERE request_id = p_request_id;
    
    RETURN v_result;
END;
$$;

-- Function to handle erasure request (pseudonymization due to immutability)
CREATE OR REPLACE FUNCTION core.fulfill_erasure_request(
    p_request_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_account_id UUID;
    v_pseudonym UUID;
    v_count INTEGER := 0;
BEGIN
    SELECT account_id INTO v_account_id
    FROM core.data_subject_requests
    WHERE request_id = p_request_id AND request_type = 'ERASURE';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Request not found or not an erasure request';
    END IF;
    
    -- Generate pseudonym
    v_pseudonym := gen_random_uuid();
    
    -- Pseudonymize account registry
    UPDATE core.account_registry SET
        unique_identifier = 'DELETED-' || v_pseudonym::TEXT,
        metadata = NULL,
        record_hash = encode(digest(v_pseudonym::TEXT, 'sha256'), 'hex')
    WHERE account_id = v_account_id;
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    
    -- Log the pseudonymization
    INSERT INTO core.dsr_fulfillment_log (
        request_id, action_taken, table_affected, records_affected
    ) VALUES (
        p_request_id, 'PSEUDONYMIZATION', 'account_registry', v_count
    );
    
    -- Revoke all consents
    UPDATE core.consent_registry SET
        consent_status = 'WITHDRAWN',
        consent_withdrawn_at = core.precise_now()
    WHERE account_id = v_account_id AND consent_status = 'GRANTED';
    
    -- Update request
    UPDATE core.data_subject_requests SET
        request_status = 'FULFILLED',
        fulfilled_at = core.precise_now(),
        fulfillment_method = 'PSEUDONYMIZATION'
    WHERE request_id = p_request_id;
    
    RETURN TRUE;
END;
$$;

-- Function to record data breach
CREATE OR REPLACE FUNCTION core.report_data_breach(
    p_breach_type VARCHAR,
    p_severity VARCHAR,
    p_detected_at TIMESTAMPTZ,
    p_affected_categories VARCHAR[],
    p_affected_count INTEGER,
    p_description TEXT DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_breach_id UUID;
    v_requires_notification BOOLEAN;
BEGIN
    -- Determine if notification is required
    v_requires_notification := (p_severity IN ('HIGH', 'CRITICAL')) 
        OR (p_affected_count > 500);
    
    INSERT INTO core.data_breach_log (
        breach_type,
        breach_severity,
        detected_at,
        affected_data_categories,
        affected_individuals_count,
        requires_notification,
        breach_status
    ) VALUES (
        p_breach_type,
        p_severity,
        p_detected_at,
        p_affected_categories,
        p_affected_count,
        v_requires_notification,
        'DETECTED'
    )
    RETURNING breach_id INTO v_breach_id;
    
    -- Alert if notification required
    IF v_requires_notification THEN
        RAISE NOTICE 'DATA BREACH REQUIRES NOTIFICATION: Breach ID %, Severity %, Affected count %', 
            v_breach_id, p_severity, p_affected_count;
    END IF;
    
    RETURN v_breach_id;
END;
$$;

-- =============================================================================
-- CONSENT MANAGEMENT FUNCTIONS
-- =============================================================================

-- Function to grant consent
CREATE OR REPLACE FUNCTION core.grant_consent(
    p_account_id UUID,
    p_consent_type VARCHAR,
    p_purposes TEXT[],
    p_granted_via VARCHAR DEFAULT 'USSD',
    p_ip_address INET DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_consent_id UUID;
BEGIN
    -- Check if existing consent
    SELECT consent_id INTO v_consent_id
    FROM core.consent_registry
    WHERE account_id = p_account_id AND consent_type = p_consent_type
    AND consent_status = 'GRANTED';
    
    IF FOUND THEN
        -- Update existing
        UPDATE core.consent_registry SET
            consent_version = consent_version + 1,
            processing_purposes = p_purposes,
            consent_granted_at = core.precise_now(),
            consent_granted_via = p_granted_via,
            consent_granted_ip = p_ip_address,
            consent_expires_at = core.precise_now() + INTERVAL '2 years'
        WHERE consent_id = v_consent_id;
        
        -- Log update
        INSERT INTO core.consent_history (
            consent_id, change_type, previous_status, new_status
        ) SELECT v_consent_id, 'UPDATED', 'GRANTED', 'GRANTED';
    ELSE
        -- Create new
        INSERT INTO core.consent_registry (
            account_id, consent_type, processing_purposes,
            consent_granted_via, consent_granted_ip,
            consent_expires_at
        ) VALUES (
            p_account_id, p_consent_type, p_purposes,
            p_granted_via, p_ip_address,
            core.precise_now() + INTERVAL '2 years'
        )
        RETURNING consent_id INTO v_consent_id;
        
        -- Log grant
        INSERT INTO core.consent_history (
            consent_id, change_type, new_status
        ) VALUES (v_consent_id, 'GRANTED', 'GRANTED');
    END IF;
    
    RETURN v_consent_id;
END;
$$;

-- Function to withdraw consent
CREATE OR REPLACE FUNCTION core.withdraw_consent(
    p_consent_id UUID,
    p_reason TEXT DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.consent_registry SET
        consent_status = 'WITHDRAWN',
        consent_withdrawn_at = core.precise_now()
    WHERE consent_id = p_consent_id;
    
    INSERT INTO core.consent_history (
        consent_id, change_type, previous_status, new_status, change_reason
    ) SELECT p_consent_id, 'WITHDRAWN', 'GRANTED', 'WITHDRAWN', p_reason;
    
    RETURN FOUND;
END;
$$;

-- =============================================================================
-- SEED DATA
-- =============================================================================

INSERT INTO core.personal_data_inventory (
    table_name, column_name, data_category, sensitivity_level,
    legal_basis, processing_purpose, retention_period, encryption_required
)
VALUES 
    ('account_registry', 'unique_identifier', 'IDENTIFIER', 'HIGH', 'CONTRACT', 'Account identification', '7 years', TRUE),
    ('account_registry', 'metadata', 'CONTACT', 'MEDIUM', 'CONSENT', 'Customer communication', '7 years', TRUE),
    ('kyc_verifications', 'identity_document_hash', 'IDENTIFIER', 'CRITICAL', 'LEGAL_OBLIGATION', 'Identity verification', '7 years', TRUE),
    ('transaction_log', 'initiator_account_id', 'IDENTIFIER', 'HIGH', 'CONTRACT', 'Transaction processing', '10 years', FALSE),
    ('ussd_sessions', 'phone_number', 'CONTACT', 'HIGH', 'CONTRACT', 'Session identification', '90 days', TRUE)
ON CONFLICT (table_name, column_name) DO NOTHING;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE core.data_subject_requests IS 
    'GDPR/POPIA data subject rights requests tracking';
COMMENT ON TABLE core.consent_registry IS 
    'Consent management for lawful processing';
COMMENT ON TABLE core.data_breach_log IS 
    'Data breach notification tracking (72-hour GDPR deadline)';
COMMENT ON FUNCTION core.fulfill_erasure_request IS 
    'Right to be forgotten - pseudonymizes data (immutable ledger cannot delete)';

-- =============================================================================
-- END OF FILE
-- =============================================================================
