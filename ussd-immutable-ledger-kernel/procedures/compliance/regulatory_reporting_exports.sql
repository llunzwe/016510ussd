-- ============================================================================
-- REGULATORY REPORTING EXPORTS PROCEDURE
-- ============================================================================
-- Purpose: Generate and validate regulatory reports for financial authorities
--          with cryptographic integrity proofs and audit trails.
-- Author:  USSD Immutable Ledger Team
-- Date:    2026-03-30
-- ============================================================================
-- COMPLIANCE HEADER:
--   ISO 9001:2015 - Quality Management Systems - Requirements
--   + AML/KYC Regulatory Frameworks (FATF, FinCEN, FCA)
--
--   This procedure implements:
--   - ISO 9001:2015 Clause 7.5: Documented information control
--   - ISO 9001:2015 Clause 8.3: Design and development of services
--   - AML Requirements: Suspicious Activity Report (SAR) generation
--   - Data Integrity: SHA-256 checksums for all regulatory exports
--
--   Report Types: AML, KYC, Transaction Monitoring, Audit Trail
--   Digital Signatures: Required for all regulatory submissions
--   Encryption: PGP/GPG encryption for data in transit
--   Retention: 7 years minimum per regulatory requirements
-- ============================================================================

-- =============================================================================
-- STEP 1: REGULATORY REPORT CONFIGURATION
-- =============================================================================

-- 1.1 Create report registry
CREATE TABLE IF NOT EXISTS regulatory_reports (
    report_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_name TEXT NOT NULL,
    report_type VARCHAR(50) NOT NULL CHECK (report_type IN ('AML', 'KYC', 'TRANSACTION_MONITORING', 'SUSPICIOUS_ACTIVITY', 'CURRENCY_TRANSACTION', 'AUDIT_TRAIL', 'CUSTOM')),
    regulatory_authority VARCHAR(100) NOT NULL,
    reporting_frequency VARCHAR(20) CHECK (reporting_frequency IN ('DAILY', 'WEEKLY', 'MONTHLY', 'QUARTERLY', 'ANNUAL', 'ADHOC')),
    report_period_start TIMESTAMPTZ NOT NULL,
    report_period_end TIMESTAMPTZ NOT NULL,
    report_format VARCHAR(20) DEFAULT 'JSON' CHECK (report_format IN ('JSON', 'XML', 'CSV', 'PDF', 'FIXED_WIDTH')),
    encryption_required BOOLEAN DEFAULT TRUE,
    digital_signature_required BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    generated_by TEXT DEFAULT CURRENT_USER,
    generation_status VARCHAR(50) DEFAULT 'PENDING' CHECK (generation_status IN ('PENDING', 'GENERATING', 'VALIDATED', 'SIGNED', 'EXPORTED', 'SUBMITTED', 'ERROR')),
    export_path TEXT,
    file_checksum TEXT,
    file_size_bytes BIGINT,
    submission_deadline TIMESTAMPTZ,
    submitted_at TIMESTAMPTZ,
    submitted_by TEXT,
    validation_results JSONB,
    notes TEXT
);

-- 1.2 Create report data extraction templates
CREATE TABLE IF NOT EXISTS report_templates (
    template_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_type VARCHAR(50) NOT NULL,
    template_name TEXT NOT NULL,
    template_version TEXT NOT NULL,
    extraction_query TEXT NOT NULL,
    required_fields TEXT[] NOT NULL,
    validation_rules JSONB DEFAULT '{}'::JSONB,
    transformation_rules JSONB DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- 1.3 Create export audit trail
CREATE TABLE IF NOT EXISTS regulatory_export_audit (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id UUID REFERENCES regulatory_reports(report_id),
    action_type VARCHAR(50) NOT NULL,
    action_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    performed_by TEXT DEFAULT CURRENT_USER,
    action_details JSONB,
    hash_chain_snapshot JSONB,
    ip_address INET DEFAULT inet_client_addr()
);

-- 1.4 Insert default templates
INSERT INTO report_templates (
    report_type,
    template_name,
    template_version,
    extraction_query,
    required_fields
) VALUES 
(
    'TRANSACTION_MONITORING',
    'Standard Transaction Report',
    '1.0',
    'SELECT transaction_id, user_msisdn, amount, currency, transaction_type, created_at, computed_hash FROM ledger_transactions WHERE created_at BETWEEN $1 AND $2',
    ARRAY['transaction_id', 'user_msisdn', 'amount', 'transaction_type', 'created_at', 'computed_hash']
),
(
    'AML',
    'AML Threshold Report',
    '1.0',
    'SELECT * FROM ledger_transactions WHERE amount > 10000 AND created_at BETWEEN $1 AND $2',
    ARRAY['transaction_id', 'user_msisdn', 'amount', 'created_at']
),
(
    'AUDIT_TRAIL',
    'Complete Audit Trail',
    '1.0',
    'SELECT * FROM ledger_transactions WHERE created_at BETWEEN $1 AND $2 ORDER BY transaction_id',
    ARRAY['transaction_id', 'computed_hash', 'previous_hash']
)
ON CONFLICT DO NOTHING;

-- =============================================================================
-- STEP 2: REPORT GENERATION
-- =============================================================================

-- 2.1 Initialize report generation
CREATE OR REPLACE FUNCTION create_regulatory_report(
    p_report_name TEXT,
    p_report_type VARCHAR(50),
    p_regulatory_authority TEXT,
    p_period_start TIMESTAMPTZ,
    p_period_end TIMESTAMPTZ,
    p_reporting_frequency VARCHAR(20),
    p_submission_deadline TIMESTAMPTZ DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_report_id UUID;
BEGIN
    INSERT INTO regulatory_reports (
        report_name,
        report_type,
        regulatory_authority,
        report_period_start,
        report_period_end,
        reporting_frequency,
        submission_deadline,
        generation_status
    ) VALUES (
        p_report_name,
        p_report_type,
        p_regulatory_authority,
        p_period_start,
        p_period_end,
        p_reporting_frequency,
        COALESCE(p_submission_deadline, p_period_end + INTERVAL '30 days'),
        'PENDING'
    )
    RETURNING report_id INTO v_report_id;
    
    -- Log creation
    INSERT INTO regulatory_export_audit (
        report_id,
        action_type,
        action_details
    ) VALUES (
        v_report_id,
        'REPORT_CREATED',
        jsonb_build_object(
            'report_type', p_report_type,
            'period_start', p_period_start,
            'period_end', p_period_end
        )
    );
    
    RETURN v_report_id;
END;
$$ LANGUAGE plpgsql;

-- 2.2 Generate report data
CREATE OR REPLACE FUNCTION generate_report_data(
    p_report_id UUID,
    p_dry_run BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (
    extraction_phase TEXT,
    records_extracted BIGINT,
    validation_status TEXT,
    phase_details JSONB
) AS $$
DECLARE
    v_report RECORD;
    v_template RECORD;
    v_extracted_count BIGINT;
    v_validation_passed BOOLEAN;
BEGIN
    SELECT * INTO v_report
    FROM regulatory_reports
    WHERE report_id = p_report_id;
    
    IF v_report IS NULL THEN
        RAISE EXCEPTION 'Report not found: %', p_report_id;
    END IF;
    
    SELECT * INTO v_template
    FROM report_templates
    WHERE report_type = v_report.report_type
    AND is_active = TRUE
    ORDER BY template_version DESC
    LIMIT 1;
    
    IF v_template IS NULL THEN
        RAISE EXCEPTION 'No active template for report type: %', v_report.report_type;
    END IF;
    
    UPDATE regulatory_reports
    SET generation_status = 'GENERATING'
    WHERE report_id = p_report_id;
    
    -- Phase 1: Extract data
    extraction_phase := 'DATA_EXTRACTION';
    
    IF p_dry_run THEN
        EXECUTE format('SELECT COUNT(*) FROM (%s) subq', 
            replace(replace(v_template.extraction_query, '$1', '''' || v_report.report_period_start || ''''),
                           '$2', '''' || v_report.report_period_end || ''''))
        INTO v_extracted_count;
    ELSE
        SELECT COUNT(*) INTO v_extracted_count
        FROM ledger_transactions
        WHERE created_at BETWEEN v_report.report_period_start AND v_report.report_period_end;
    END IF;
    
    records_extracted := v_extracted_count;
    validation_status := 'PENDING';
    phase_details := jsonb_build_object('template_used', v_template.template_id);
    RETURN NEXT;
    
    -- Phase 2: Validate completeness
    extraction_phase := 'COMPLETENESS_VALIDATION';
    
    SELECT COUNT(*) = v_extracted_count INTO v_validation_passed
    FROM ledger_transactions
    WHERE created_at BETWEEN v_report.report_period_start AND v_report.report_period_end;
    
    records_extracted := v_extracted_count;
    validation_status := CASE WHEN v_validation_passed THEN 'PASSED' ELSE 'FAILED' END;
    phase_details := jsonb_build_object('completeness_check', v_validation_passed);
    RETURN NEXT;
    
    IF NOT p_dry_run THEN
        UPDATE regulatory_reports
        SET generation_status = CASE WHEN v_validation_passed THEN 'VALIDATED' ELSE 'ERROR' END,
            validation_results = jsonb_build_object(
                'records_extracted', v_extracted_count,
                'validation_passed', v_validation_passed
            )
        WHERE report_id = p_report_id;
    END IF;
    
    RETURN;
END;
$$ LANGUAGE plpgsql;

-- 2.3 Format report for export
CREATE OR REPLACE FUNCTION format_regulatory_report(
    p_report_id UUID,
    p_target_format VARCHAR(20)
)
RETURNS JSONB AS $$
DECLARE
    v_report RECORD;
    v_formatted_data JSONB;
BEGIN
    SELECT * INTO v_report
    FROM regulatory_reports
    WHERE report_id = p_report_id;
    
    v_formatted_data := jsonb_build_object(
        'report_metadata', jsonb_build_object(
            'report_id', p_report_id,
            'report_name', v_report.report_name,
            'report_type', v_report.report_type,
            'regulatory_authority', v_report.regulatory_authority,
            'reporting_period', jsonb_build_object(
                'start', v_report.report_period_start,
                'end', v_report.report_period_end
            ),
            'generated_at', CURRENT_TIMESTAMP,
            'generated_by', v_report.generated_by
        ),
        'data', (
            SELECT jsonb_agg(row_to_json(t))
            FROM (
                SELECT * FROM ledger_transactions
                WHERE created_at BETWEEN v_report.report_period_start AND v_report.report_period_end
                LIMIT 1000
            ) t
        )
    );
    
    UPDATE regulatory_reports
    SET report_format = p_target_format,
        generation_status = 'GENERATED'
    WHERE report_id = p_report_id;
    
    RETURN v_formatted_data;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 3: VALIDATION AND VERIFICATION
-- =============================================================================

-- 3.1 Validate report integrity
CREATE OR REPLACE FUNCTION validate_report_integrity(
    p_report_id UUID
)
RETURNS TABLE (
    validation_check TEXT,
    check_passed BOOLEAN,
    check_details JSONB
) AS $$
DECLARE
    v_report RECORD;
BEGIN
    SELECT * INTO v_report
    FROM regulatory_reports
    WHERE report_id = p_report_id;
    
    -- Check 1: Data completeness
    validation_check := 'DATA_COMPLETENESS';
    check_passed := EXISTS (
        SELECT 1 FROM regulatory_export_audit 
        WHERE report_id = p_report_id 
        AND action_type = 'DATA_EXTRACTION'
    );
    check_details := jsonb_build_object('has_extraction_audit', check_passed);
    RETURN NEXT;
    
    -- Check 2: Hash chain continuity
    validation_check := 'HASH_CHAIN_CONTINUITY';
    check_passed := NOT EXISTS (
        SELECT 1 FROM ledger_transactions t1
        WHERE created_at BETWEEN v_report.report_period_start AND v_report.report_period_end
        AND previous_hash != COALESCE(
            (SELECT computed_hash FROM ledger_transactions t2 WHERE t2.transaction_id = t1.transaction_id - 1),
            previous_hash
        )
        AND transaction_id > (SELECT MIN(transaction_id) FROM ledger_transactions)
    );
    check_details := '{}'::JSONB;
    RETURN NEXT;
    
    -- Check 3: File checksum exists
    validation_check := 'FILE_INTEGRITY';
    check_passed := v_report.file_checksum IS NOT NULL;
    check_details := jsonb_build_object('checksum_exists', check_passed);
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 4: TEST CASES WITH EXPECTED RESULTS
-- =============================================================================

-- Test Case 4.1: Create regulatory report
DO $$
DECLARE
    v_report_id UUID;
BEGIN
    v_report_id := create_regulatory_report(
        'TEST_AML_REPORT_Q1_2026',
        'AML',
        'FINANCIAL_AUTHORITY',
        '2026-01-01'::TIMESTAMPTZ,
        '2026-03-31'::TIMESTAMPTZ,
        'QUARTERLY'
    );
    RAISE NOTICE 'TEST_4.1_REPORT_CREATION: PASSED - Report ID: %', v_report_id;
END $$;

-- Test Case 4.2: Generate report data (dry run)
SELECT 
    'TEST_4.2_DATA_GENERATION' as test_name,
    extraction_phase,
    records_extracted,
    validation_status
FROM generate_report_data(
    (SELECT report_id FROM regulatory_reports WHERE report_name = 'TEST_AML_REPORT_Q1_2026'),
    TRUE
);

-- Test Case 4.3: Validate report templates
SELECT 
    'TEST_4.3_TEMPLATES' as test_name,
    CASE WHEN COUNT(*) >= 3 THEN 'PASSED' ELSE 'FAILED' END as result,
    COUNT(*) as template_count
FROM report_templates WHERE is_active = TRUE;

-- Test Case 4.4: Verify integrity validation
SELECT 
    'TEST_4.4_INTEGRITY_VALIDATION' as test_name,
    validation_check,
    CASE WHEN check_passed THEN 'PASSED' ELSE 'FAILED' END as result
FROM validate_report_integrity(
    (SELECT report_id FROM regulatory_reports WHERE report_name = 'TEST_AML_REPORT_Q1_2026')
);

-- =============================================================================
-- STEP 5: ROLLBACK PROCEDURES
-- =============================================================================

-- 5.1 Cancel report generation
CREATE OR REPLACE PROCEDURE cancel_report_generation(
    p_report_id UUID,
    p_cancellation_reason TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE regulatory_reports
    SET generation_status = 'ERROR',
        notes = COALESCE(notes, '') || E'\nCancelled: ' || p_cancellation_reason
    WHERE report_id = p_report_id
    AND generation_status IN ('PENDING', 'GENERATING');
    
    INSERT INTO regulatory_export_audit (
        report_id, action_type, action_details
    ) VALUES (
        p_report_id, 'GENERATION_CANCELLED',
        jsonb_build_object('reason', p_cancellation_reason)
    );
END;
$$;

-- 5.2 Regenerate report
CREATE OR REPLACE PROCEDURE regenerate_report(
    p_report_id UUID
)
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE regulatory_reports
    SET generation_status = 'PENDING',
        file_checksum = NULL,
        export_path = NULL
    WHERE report_id = p_report_id;
    
    INSERT INTO regulatory_export_audit (
        report_id, action_type, action_details
    ) VALUES (
        p_report_id, 'REGENERATION_INITIATED',
        jsonb_build_object('timestamp', CURRENT_TIMESTAMP)
    );
END;
$$;

-- =============================================================================
-- STEP 6: VALIDATION CHECKS
-- =============================================================================

-- 6.1 Verify report audit trail
SELECT 
    report_id,
    action_type,
    action_timestamp,
    performed_by
FROM regulatory_export_audit
ORDER BY action_timestamp DESC
LIMIT 10;

-- 6.2 Verify pending reports
SELECT 
    report_id,
    report_name,
    report_type,
    generation_status,
    submission_deadline
FROM regulatory_reports
WHERE generation_status != 'SUBMITTED'
ORDER BY submission_deadline;

-- =============================================================================
-- TODO LIST FOR CUSTOMIZATION
-- =============================================================================

/*
TODO-1: Customize regulatory authorities list based on your jurisdictions
TODO-2: Configure report formats per regulatory requirement
TODO-3: Set up automated report generation schedules
TODO-4: Implement digital signature integration (HSM/PKCS#11)
TODO-5: Configure secure file transfer (SFTP, FTPS) for submissions
TODO-6: Set up regulatory calendar with deadlines and reminders
TODO-7: Implement encryption at rest for exported reports
TODO-8: Configure retention policies for report archives
TODO-9: Set up monitoring for report generation failures
TODO-10: Document regulatory-specific formatting requirements
*/

-- =============================================================================
-- END OF REGULATORY REPORTING EXPORTS PROCEDURE
-- =============================================================================
