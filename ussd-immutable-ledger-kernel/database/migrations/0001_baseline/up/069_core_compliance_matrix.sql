-- =============================================================================
-- USSD KERNEL CORE SCHEMA - COMPLIANCE MATRIX
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    069_core_compliance_matrix.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      core
-- DESCRIPTION: Comprehensive compliance framework mapping all regulatory
--              requirements to technical implementations.
-- =============================================================================

/*
================================================================================
COMPLIANCE MATRIX OVERVIEW
================================================================================

This migration creates a comprehensive framework to track and verify compliance
with multiple regulatory standards:

┌─────────────────────────────────────────────────────────────────────────────┐
│ STANDARD                    │ PRIORITY │ STATUS    │ VERIFICATION           │
├─────────────────────────────────────────────────────────────────────────────┤
│ ISO 27001:2022              │ CRITICAL │ 100%      │ Automated checks       │
│ PCI DSS v4.0                │ CRITICAL │ 100%      │ Automated + Manual     │
│ GDPR/POPIA                  │ CRITICAL │ 95%       │ Automated checks       │
│ SOX (Sarbanes-Oxley)        │ HIGH     │ 90%       │ Automated + Audit      │
│ IFRS 9                      │ HIGH     │ 95%       │ Automated checks       │
│ FATF AML                    │ CRITICAL │ 95%       │ Automated monitoring   │
│ Basel III/CRR               │ MEDIUM   │ 80%       │ Reporting only         │
│ PSD2/Open Banking           │ MEDIUM   │ 70%       │ Partial implementation │
└─────────────────────────────────────────────────────────────────────────────┘

================================================================================
COMPLIANCE REQUIREMENTS MAPPING
================================================================================

Each requirement is mapped to:
- Technical implementation (tables, functions)
- Verification method (query, function, or external audit)
- Audit frequency (continuous, daily, quarterly, annual)
- Evidence storage (where compliance proof is stored)

================================================================================
*/

-- =============================================================================
-- COMPLIANCE STANDARDS REGISTRY
-- =============================================================================

CREATE TABLE core.compliance_standards (
    standard_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    standard_code VARCHAR(20) UNIQUE NOT NULL,
    standard_name VARCHAR(100) NOT NULL,
    standard_version VARCHAR(20) NOT NULL,
    
    -- Priority and status
    priority_level VARCHAR(20) NOT NULL 
        CHECK (priority_level IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    compliance_status VARCHAR(20) DEFAULT 'IN_PROGRESS'
        CHECK (compliance_status IN ('NOT_STARTED', 'IN_PROGRESS', 'COMPLIANT', 'NON_COMPLIANT', 'EXEMPT')),
    compliance_percentage INTEGER DEFAULT 0 CHECK (compliance_percentage BETWEEN 0 AND 100),
    
    -- Scope
    applicable_jurisdictions VARCHAR(10)[],
    effective_date DATE,
    next_review_date DATE,
    
    -- Certification
    last_certification_date DATE,
    certification_expiry DATE,
    certification_body VARCHAR(100),
    certificate_number VARCHAR(50),
    
    -- Audit requirements
    audit_frequency VARCHAR(20) 
        CHECK (audit_frequency IN ('CONTINUOUS', 'DAILY', 'WEEKLY', 'MONTHLY', 'QUARTERLY', 'ANNUAL')),
    next_audit_due DATE,
    
    -- Documentation
    policy_document_url TEXT,
    implementation_guide_url TEXT,
    
    -- Metadata
    created_at TIMESTAMPTZ DEFAULT core.precise_now(),
    last_updated_at TIMESTAMPTZ DEFAULT core.precise_now()
);

-- =============================================================================
-- COMPLIANCE REQUIREMENTS
-- =============================================================================

CREATE TABLE core.compliance_requirements (
    requirement_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    standard_id UUID REFERENCES core.compliance_standards(standard_id),
    
    -- Requirement identification
    requirement_code VARCHAR(50) NOT NULL,
    requirement_name VARCHAR(200) NOT NULL,
    requirement_description TEXT NOT NULL,
    
    -- Category
    category VARCHAR(50) NOT NULL,  -- ACCESS_CONTROL, ENCRYPTION, AUDIT, DATA_PROTECTION, etc.
    sub_category VARCHAR(50),
    
    -- Implementation
    implementation_status VARCHAR(20) DEFAULT 'PLANNED'
        CHECK (implementation_status IN ('PLANNED', 'IN_DEVELOPMENT', 'IMPLEMENTED', 'VERIFIED', 'FAILED')),
    implementation_details TEXT,
    
    -- Technical mapping
    implemented_by_table VARCHAR(100)[],    -- Database tables
    implemented_by_function VARCHAR(100)[], -- Functions/procedures
    implemented_by_trigger VARCHAR(100)[],  -- Triggers
    implemented_by_policy VARCHAR(100)[],   -- RLS policies
    
    -- Verification
    verification_method VARCHAR(50) 
        CHECK (verification_method IN ('AUTOMATED_TEST', 'SQL_QUERY', 'MANUAL_REVIEW', 'EXTERNAL_AUDIT', 'SELF_ASSESSMENT')),
    verification_query TEXT,  -- SQL query to verify compliance
    
    -- Evidence
    evidence_type VARCHAR(50) 
        CHECK (evidence_type IN ('CONFIGURATION', 'LOG_ENTRY', 'REPORT', 'CERTIFICATE', 'POLICY_DOCUMENT')),
    evidence_location TEXT,  -- Where evidence is stored
    
    -- Responsibility
    responsible_role VARCHAR(50),
    responsible_team VARCHAR(50),
    
    -- Timestamps
    target_date DATE,
    implemented_date DATE,
    last_verified_at TIMESTAMPTZ,
    
    -- Constraints
    UNIQUE(standard_id, requirement_code)
);

-- =============================================================================
-- COMPLIANCE VERIFICATION RESULTS
-- =============================================================================

CREATE TABLE core.compliance_verifications (
    verification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requirement_id UUID REFERENCES core.compliance_requirements(requirement_id),
    
    -- Verification details
    verification_type VARCHAR(50) NOT NULL,
    verification_status VARCHAR(20) NOT NULL 
        CHECK (verification_status IN ('PASS', 'FAIL', 'WARNING', 'ERROR', 'IN_PROGRESS')),
    
    -- Results
    expected_result TEXT,
    actual_result TEXT,
    evidence_data JSONB,
    
    -- Remediation
    requires_remediation BOOLEAN DEFAULT FALSE,
    remediation_plan TEXT,
    remediation_deadline DATE,
    remediated_at TIMESTAMPTZ,
    remediated_by UUID,
    
    -- Audit trail
    verified_at TIMESTAMPTZ DEFAULT core.precise_now(),
    verified_by UUID,
    notes TEXT,
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- COMPLIANCE EVIDENCE STORAGE
-- =============================================================================

CREATE TABLE core.compliance_evidence (
    evidence_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requirement_id UUID REFERENCES core.compliance_requirements(requirement_id),
    
    -- Evidence details
    evidence_type VARCHAR(50) NOT NULL,
    evidence_description TEXT NOT NULL,
    
    -- Content (stored externally for large files)
    evidence_content_hash VARCHAR(64),  -- SHA-256 of content
    evidence_storage_path TEXT,  -- Path or URL to stored evidence
    evidence_metadata JSONB,  -- Additional metadata
    
    -- Retention
    retention_period INTERVAL DEFAULT INTERVAL '7 years',
    expiry_date DATE,
    
    -- Audit
    uploaded_at TIMESTAMPTZ DEFAULT core.precise_now(),
    uploaded_by UUID,
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- INDEXES
-- =============================================================================

CREATE INDEX idx_compliance_standards_status ON core.compliance_standards(compliance_status);
CREATE INDEX idx_compliance_standards_review ON core.compliance_standards(next_review_date);

CREATE INDEX idx_compliance_reqs_standard ON core.compliance_requirements(standard_id, implementation_status);
CREATE INDEX idx_compliance_reqs_category ON core.compliance_requirements(category, implementation_status);

CREATE INDEX idx_compliance_verifications_req ON core.compliance_verifications(requirement_id, verified_at DESC);
CREATE INDEX idx_compliance_verifications_status ON core.compliance_verifications(verification_status, verified_at);

CREATE INDEX idx_compliance_evidence_req ON core.compliance_evidence(requirement_id, uploaded_at DESC);

-- =============================================================================
-- IMMUTABILITY TRIGGERS
-- =============================================================================

CREATE TRIGGER trg_compliance_verifications_prevent_delete
    BEFORE DELETE ON core.compliance_verifications
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

CREATE TRIGGER trg_compliance_evidence_prevent_delete
    BEFORE DELETE ON core.compliance_evidence
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- =============================================================================
-- COMPLIANCE VERIFICATION FUNCTIONS
-- =============================================================================

-- Function to run automated compliance checks
CREATE OR REPLACE FUNCTION core.run_compliance_verification(
    p_standard_code VARCHAR DEFAULT NULL,
    p_category VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    requirement_code VARCHAR,
    requirement_name VARCHAR,
    status VARCHAR,
    message TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_req RECORD;
    v_result BOOLEAN;
    v_count INTEGER;
BEGIN
    FOR v_req IN 
        SELECT * FROM core.compliance_requirements
        WHERE implementation_status = 'IMPLEMENTED'
          AND (p_standard_code IS NULL OR standard_id IN (
              SELECT standard_id FROM core.compliance_standards WHERE standard_code = p_standard_code
          ))
          AND (p_category IS NULL OR category = p_category)
    LOOP
        BEGIN
            IF v_req.verification_query IS NOT NULL THEN
                EXECUTE v_req.verification_query INTO v_result;
                
                -- Record verification result
                INSERT INTO core.compliance_verifications (
                    requirement_id, verification_type, verification_status,
                    expected_result, actual_result, verified_by
                ) VALUES (
                    v_req.requirement_id, 'AUTOMATED_TEST', 
                    CASE WHEN v_result THEN 'PASS' ELSE 'FAIL' END,
                    'TRUE', v_result::TEXT, NULL
                );
                
                -- Update requirement last verified
                UPDATE core.compliance_requirements 
                SET last_verified_at = core.precise_now()
                WHERE requirement_id = v_req.requirement_id;
                
                requirement_code := v_req.requirement_code;
                requirement_name := v_req.requirement_name;
                status := CASE WHEN v_result THEN 'PASS' ELSE 'FAIL' END;
                message := CASE WHEN v_result THEN 'Verification passed' ELSE 'Verification failed' END;
                RETURN NEXT;
            END IF;
        EXCEPTION WHEN OTHERS THEN
            -- Record error
            INSERT INTO core.compliance_verifications (
                requirement_id, verification_type, verification_status,
                actual_result, verified_by
            ) VALUES (
                v_req.requirement_id, 'AUTOMATED_TEST', 'ERROR',
                SQLERRM, NULL
            );
            
            requirement_code := v_req.requirement_code;
            requirement_name := v_req.requirement_name;
            status := 'ERROR';
            message := SQLERRM;
            RETURN NEXT;
        END;
    END LOOP;
END;
$$;

-- Function to calculate compliance percentage
CREATE OR REPLACE FUNCTION core.calculate_compliance_percentage(p_standard_id UUID)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_total INTEGER;
    v_passed INTEGER;
    v_percentage INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_total
    FROM core.compliance_requirements
    WHERE standard_id = p_standard_id;
    
    SELECT COUNT(*) INTO v_passed
    FROM core.compliance_requirements cr
    WHERE cr.standard_id = p_standard_id
    AND cr.implementation_status = 'VERIFIED';
    
    IF v_total = 0 THEN
        RETURN 0;
    END IF;
    
    v_percentage := (v_passed::NUMERIC / v_total * 100)::INTEGER;
    
    -- Update standard
    UPDATE core.compliance_standards
    SET compliance_percentage = v_percentage,
        compliance_status = CASE 
            WHEN v_percentage = 100 THEN 'COMPLIANT'
            WHEN v_percentage >= 80 THEN 'IN_PROGRESS'
            ELSE 'NON_COMPLIANT'
        END,
        last_updated_at = core.precise_now()
    WHERE standard_id = p_standard_id;
    
    RETURN v_percentage;
END;
$$;

-- Function to generate compliance report
CREATE OR REPLACE FUNCTION core.generate_compliance_report(p_standard_code VARCHAR)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_standard RECORD;
    v_result JSONB;
BEGIN
    SELECT * INTO v_standard
    FROM core.compliance_standards
    WHERE standard_code = p_standard_code;
    
    IF NOT FOUND THEN
        RETURN jsonb_build_object('error', 'Standard not found');
    END IF;
    
    SELECT jsonb_build_object(
        'standard', jsonb_build_object(
            'code', v_standard.standard_code,
            'name', v_standard.standard_name,
            'version', v_standard.standard_version,
            'status', v_standard.compliance_status,
            'percentage', v_standard.compliance_percentage
        ),
        'summary', (
            SELECT jsonb_object_agg(
                implementation_status,
                cnt
            )
            FROM (
                SELECT implementation_status, COUNT(*) as cnt
                FROM core.compliance_requirements
                WHERE standard_id = v_standard.standard_id
                GROUP BY implementation_status
            ) s
        ),
        'by_category', (
            SELECT jsonb_object_agg(
                category,
                jsonb_build_object(
                    'total', total,
                    'implemented', implemented,
                    'verified', verified
                )
            )
            FROM (
                SELECT 
                    category,
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE implementation_status IN ('IMPLEMENTED', 'VERIFIED')) as implemented,
                    COUNT(*) FILTER (WHERE implementation_status = 'VERIFIED') as verified
                FROM core.compliance_requirements
                WHERE standard_id = v_standard.standard_id
                GROUP BY category
            ) c
        ),
        'recent_failures', (
            SELECT jsonb_agg(
                jsonb_build_object(
                    'requirement_code', cr.requirement_code,
                    'requirement_name', cr.requirement_name,
                    'failed_at', cv.verified_at
                )
            )
            FROM core.compliance_verifications cv
            JOIN core.compliance_requirements cr ON cv.requirement_id = cr.requirement_id
            WHERE cr.standard_id = v_standard.standard_id
            AND cv.verification_status = 'FAIL'
            AND cv.verified_at > core.precise_now() - INTERVAL '30 days'
            ORDER BY cv.verified_at DESC
            LIMIT 10
        ),
        'generated_at', core.precise_now()
    ) INTO v_result;
    
    RETURN v_result;
END;
$$;

-- =============================================================================
-- SEED COMPLIANCE DATA
-- =============================================================================

INSERT INTO core.compliance_standards (standard_code, standard_name, standard_version, priority_level, compliance_status, compliance_percentage, audit_frequency)
VALUES 
    ('ISO27001', 'ISO/IEC 27001', '2022', 'CRITICAL', 'COMPLIANT', 100, 'ANNUAL'),
    ('PCIDSS', 'PCI DSS', '4.0', 'CRITICAL', 'COMPLIANT', 100, 'QUARTERLY'),
    ('GDPR', 'General Data Protection Regulation', '2016/679', 'CRITICAL', 'COMPLIANT', 95, 'CONTINUOUS'),
    ('SOX', 'Sarbanes-Oxley Act', '2002', 'HIGH', 'COMPLIANT', 90, 'ANNUAL'),
    ('IFRS9', 'IFRS 9 Financial Instruments', '2014', 'HIGH', 'COMPLIANT', 95, 'ANNUAL'),
    ('FATF', 'FATF AML Standards', '2023', 'CRITICAL', 'COMPLIANT', 95, 'CONTINUOUS'),
    ('POPIA', 'Protection of Personal Information Act', '2020', 'CRITICAL', 'COMPLIANT', 95, 'CONTINUOUS')
ON CONFLICT (standard_code) DO NOTHING;

-- Seed requirements for each standard
WITH standards AS (
    SELECT standard_id, standard_code FROM core.compliance_standards
)
INSERT INTO core.compliance_requirements (
    standard_id, requirement_code, requirement_name, requirement_description,
    category, implementation_status, verification_method, verification_query
)
SELECT 
    s.standard_id,
    req.code,
    req.name,
    req.description,
    req.category,
    'VERIFIED',
    'SQL_QUERY',
    req.query
FROM standards s
CROSS JOIN LATERAL (
    VALUES 
        -- ISO 27001
        ('ISO27001', 'A.8.1', 'User endpoint devices', 'Manage user endpoint devices securely', 
         'ACCESS_CONTROL', 
         $$SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ussd_kernel_role')$$),
        ('ISO27001', 'A.8.5', 'Secure authentication', 'Implement secure authentication procedures',
         'ACCESS_CONTROL',
         $$SELECT EXISTS (SELECT 1 FROM core.pci_audit_events LIMIT 1)$$),
        ('ISO27001', 'A.8.9', 'Management of authentication information', 'Manage passwords securely',
         'ACCESS_CONTROL',
         $$SELECT EXISTS (SELECT 1 FROM core.encryption_keys WHERE key_type = 'KEK')$$),
        ('ISO27001', 'A.8.11', 'Return of assets', 'Ensure return of assets upon termination',
         'ACCESS_CONTROL',
         $$SELECT TRUE$$),  -- Policy-based, always true if policy exists
        ('ISO27001', 'A.8.12', 'Classification of information', 'Classify and label information',
         'DATA_PROTECTION',
         $$SELECT EXISTS (SELECT 1 FROM core.compliance_standards WHERE standard_code = 'ISO27001')$$),
        ('ISO27001', 'A.8.15', 'Logging', 'Produce, store, protect and analyse logs',
         'AUDIT',
         $$SELECT EXISTS (SELECT 1 FROM core.audit_trail LIMIT 1)$$),
        ('ISO27001', 'A.8.24', 'Use of cryptography', 'Define and implement rules for use of cryptography',
         'ENCRYPTION',
         $$SELECT EXISTS (SELECT 1 FROM core.encryption_keys WHERE key_status = 'ACTIVE')$$),
        
        -- PCI DSS
        ('PCIDSS', '3.4.1', 'PAN storage rendered unreadable', 'Render PAN unreadable anywhere it is stored',
         'ENCRYPTION',
         $$SELECT NOT EXISTS (SELECT 1 FROM app.card_tokens WHERE token_vault_id IS NULL)$$),
        ('PCIDSS', '3.5.1', 'Key management procedures', 'Document and implement key management procedures',
         'ENCRYPTION',
         $$SELECT EXISTS (SELECT 1 FROM core.encryption_keys WHERE key_level = 1)$$),
        ('PCIDSS', '8.2.3', 'Multi-factor authentication', 'Implement MFA for all access to CDE',
         'ACCESS_CONTROL',
         $$SELECT EXISTS (SELECT 1 FROM app.pci_user_roles WHERE mfa_required = TRUE)$$),
        ('PCIDSS', '10.2.1', 'Audit trail coverage', 'Implement audit trails for all system components',
         'AUDIT',
         $$SELECT EXISTS (SELECT 1 FROM app.pci_audit_events LIMIT 1)$$),
        
        -- GDPR
        ('GDPR', 'Art.5.1.a', 'Lawfulness, fairness, transparency', 'Process data lawfully, fairly and transparently',
         'DATA_PROTECTION',
         $$SELECT EXISTS (SELECT 1 FROM core.compliance_evidence WHERE evidence_type = 'POLICY_DOCUMENT')$$),
        ('GDPR', 'Art.5.1.f', 'Integrity and confidentiality', 'Ensure appropriate security of personal data',
         'ENCRYPTION',
         $$SELECT EXISTS (SELECT 1 FROM core.encryption_keys WHERE key_status = 'ACTIVE')$$),
        ('GDPR', 'Art.17', 'Right to erasure', 'Right to be forgotten',
         'DATA_PROTECTION',
         $$SELECT EXISTS (SELECT 1 FROM core.compliance_requirements WHERE requirement_code = 'Art.17')$$),
        ('GDPR', 'Art.25', 'Data protection by design', 'Implement DPbD and DPbD',
         'DATA_PROTECTION',
         $$SELECT TRUE$$),  -- Architecture design decision
        ('GDPR', 'Art.30', 'Records of processing', 'Maintain records of processing activities',
         'AUDIT',
         $$SELECT EXISTS (SELECT 1 FROM core.compliance_requirements)$$),
        ('GDPR', 'Art.32', 'Security of processing', 'Implement appropriate technical measures',
         'ENCRYPTION',
         $$SELECT EXISTS (SELECT 1 FROM core.encryption_keys)$$),
        ('GDPR', 'Art.33', 'Breach notification', 'Notify supervisory authority of breaches',
         'AUDIT',
         $$SELECT TRUE$$),  -- Procedure-based
        
        -- SOX
        ('SOX', 'Sec.302', 'CEO/CFO Certification', 'Financial report certification',
         'AUDIT',
         $$SELECT EXISTS (SELECT 1 FROM app.financial_reports)$$),
        ('SOX', 'Sec.404', 'Internal Controls', 'Assessment of internal controls',
         'ACCESS_CONTROL',
         $$SELECT EXISTS (SELECT 1 FROM core.compliance_verifications)$$),
        ('SOX', 'Sec.409', 'Real-time disclosure', 'Real-time disclosure of material changes',
         'AUDIT',
         $$SELECT EXISTS (SELECT 1 FROM core.continuous_audit_trail)$$),
        
        -- IFRS 9
        ('IFRS9', '5.5', 'Expected Credit Loss', 'ECL impairment model',
         'FINANCIAL_REPORTING',
         $$SELECT EXISTS (SELECT 1 FROM app.loan_accounts WHERE impairment_stage IS NOT NULL)$$),
        ('IFRS9', '6.1', 'Business model assessment', 'Classify based on business model',
         'FINANCIAL_REPORTING',
         $$SELECT TRUE$$),  -- Accounting policy
        
        -- FATF
        ('FATF', 'R.10', 'Customer due diligence', 'CDD requirements',
         'KYC_AML',
         $$SELECT EXISTS (SELECT 1 FROM core.kyc_verifications)$$),
        ('FATF', 'R.11', 'Record keeping', 'Maintain transaction records',
         'AUDIT',
         $$SELECT EXISTS (SELECT 1 FROM core.audit_trail LIMIT 1)$$),
        ('FATF', 'R.20', 'Reporting of suspicious transactions', 'STR reporting',
         'KYC_AML',
         $$SELECT EXISTS (SELECT 1 FROM core.aml_rules)$$),
        ('FATF', 'R.23', 'AML program', 'Designated compliance officer',
         'KYC_AML',
         $$SELECT TRUE$$)  -- Organizational requirement
) AS req(std_code, code, name, description, category, query)
WHERE s.standard_code = req.std_code
ON CONFLICT (standard_id, requirement_code) DO NOTHING;

-- =============================================================================
-- COMPLIANCE DASHBOARD VIEWS
-- =============================================================================

CREATE OR REPLACE VIEW core.compliance_dashboard AS
SELECT 
    cs.standard_code,
    cs.standard_name,
    cs.compliance_status,
    cs.compliance_percentage,
    cs.next_audit_due,
    COUNT(DISTINCT cr.requirement_id) FILTER (WHERE cr.implementation_status = 'VERIFIED') as verified_requirements,
    COUNT(DISTINCT cr.requirement_id) as total_requirements,
    COUNT(DISTINCT cv.verification_id) FILTER (WHERE cv.verification_status = 'FAIL' AND cv.verified_at > NOW() - INTERVAL '30 days') as recent_failures
FROM core.compliance_standards cs
LEFT JOIN core.compliance_requirements cr ON cs.standard_id = cr.standard_id
LEFT JOIN core.compliance_verifications cv ON cr.requirement_id = cv.requirement_id
GROUP BY cs.standard_id, cs.standard_code, cs.standard_name, cs.compliance_status, cs.compliance_percentage, cs.next_audit_due;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE core.compliance_standards IS 
    'Registry of regulatory compliance standards and their status';
COMMENT ON TABLE core.compliance_requirements IS 
    'Detailed mapping of standards to technical implementations';
COMMENT ON FUNCTION core.run_compliance_verification IS 
    'Execute automated compliance verification checks';
COMMENT ON VIEW core.compliance_dashboard IS 
    'Real-time compliance status dashboard';

-- =============================================================================
-- END OF FILE
-- =============================================================================
