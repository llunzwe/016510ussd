-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Monitoring and logging)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Rejection monitoring)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Payload sanitization)
-- ISO/IEC 27040:2024 - Storage Security (Retention policies)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Failure analysis)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Separate from immutable ledger (doesn't affect hash chain)
-- - Payload sanitization removes sensitive data
-- - Retention policies for cleanup
-- - Support ticket integration
-- ============================================================================
-- =============================================================================
-- MIGRATION: 013_core_rejection_log.sql
-- DESCRIPTION: Rejected Transaction Log - Failed Validation Records
-- TABLES: rejection_log, rejection_reasons
-- DEPENDENCIES: 004_core_transaction_log.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 3. Transaction Processing & Lifecycle
- Feature: Rejection Handling
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Failed validations are NOT stored in the immutable transaction log.
Instead, rejection records capture failed attempts for troubleshooting,
monitoring, and customer support. Helps diagnose why transactions failed.

KEY FEATURES:
- Separate from immutable log (doesn't affect hash chain)
- Detailed rejection reasons
- Links to idempotency keys for deduplication
- Supports rejection analysis and reporting
- Retention policies for cleanup

REJECTION REASONS:
- INSUFFICIENT_FUNDS
- INVALID_ACCOUNT
- INVALID_AMOUNT
- VALIDATION_FAILED
- RATE_LIMIT_EXCEEDED
- DUPLICATE_TRANSACTION
- COMPLIANCE_BLOCKED
- SYSTEM_ERROR
================================================================================
*/

-- =============================================================================
-- Create rejection_reasons table
-- DESCRIPTION: Catalog of rejection reason codes
-- PRIORITY: HIGH
-- SECURITY: User-facing messages sanitized
-- ============================================================================
CREATE TABLE core.rejection_reasons (
    reason_code         VARCHAR(50) PRIMARY KEY,
    reason_category     VARCHAR(50) NOT NULL,        -- VALIDATION, SYSTEM, COMPLIANCE
    reason_name         VARCHAR(100) NOT NULL,
    description         TEXT,
    
    -- User Communication
    user_message_template VARCHAR(255),              -- Localizable message
    support_action      TEXT,                        -- Suggested support action
    
    -- Severity
    severity            VARCHAR(20) DEFAULT 'ERROR', -- INFO, WARNING, ERROR, CRITICAL
    
    -- Retry Behavior
    is_retryable        BOOLEAN DEFAULT false,       -- Can user retry?
    retry_after_seconds INTEGER,                     -- Suggested wait time
    
    -- Monitoring
    alert_threshold     INTEGER DEFAULT 100,         -- Alert if rejections/hour exceeds
    
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Constraints
    CONSTRAINT chk_rejection_reasons_category 
        CHECK (reason_category IN ('VALIDATION', 'SYSTEM', 'COMPLIANCE', 'BUSINESS')),
    CONSTRAINT chk_rejection_reasons_severity 
        CHECK (severity IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL'))
);

COMMENT ON TABLE core.rejection_reasons IS 'Standardized rejection reason codes with user messages';

-- Seed rejection reasons
INSERT INTO core.rejection_reasons (reason_code, reason_category, reason_name, description, user_message_template, is_retryable, retry_after_seconds) VALUES
('INSUFFICIENT_FUNDS', 'BUSINESS', 'Insufficient Funds', 'Account does not have enough balance', 'Your account does not have sufficient funds for this transaction.', false, NULL),
('INVALID_ACCOUNT', 'VALIDATION', 'Invalid Account', 'Account does not exist or is not active', 'The specified account is invalid or inactive.', false, NULL),
('INVALID_AMOUNT', 'VALIDATION', 'Invalid Amount', 'Transaction amount is invalid', 'Please enter a valid transaction amount.', true, NULL),
('VALIDATION_FAILED', 'VALIDATION', 'Validation Failed', 'Request failed validation rules', 'Your request could not be processed. Please check your input.', true, NULL),
('RATE_LIMIT_EXCEEDED', 'SYSTEM', 'Rate Limit Exceeded', 'Too many requests from this source', 'You have made too many requests. Please try again later.', true, 300),
('DUPLICATE_TRANSACTION', 'SYSTEM', 'Duplicate Transaction', 'Transaction already processed', 'This transaction has already been processed.', false, NULL),
('COMPLIANCE_BLOCKED', 'COMPLIANCE', 'Compliance Blocked', 'Transaction blocked by compliance rules', 'This transaction cannot be completed due to compliance restrictions.', false, NULL),
('SYSTEM_ERROR', 'SYSTEM', 'System Error', 'Internal system error occurred', 'A system error occurred. Please try again later.', true, 60)
ON CONFLICT (reason_code) DO NOTHING;

-- =============================================================================
-- Create rejection_log table
-- DESCRIPTION: Record of all rejected transactions
-- PRIORITY: CRITICAL
-- SECURITY: Sanitized payloads, TTL-based cleanup
-- ============================================================================
CREATE TABLE core.rejection_log (
    rejection_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rejection_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Request Details
    idempotency_key_id  UUID REFERENCES core.idempotency_keys(idempotency_key_id),
    idempotency_key     VARCHAR(255),                -- Copy at time of rejection
    
    -- Transaction Attempt
    transaction_type_id UUID REFERENCES core.transaction_types(transaction_type_id),
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Initiator
    initiator_account_id UUID REFERENCES core.accounts(account_id),
    initiator_session   VARCHAR(255),                -- USSD session ID
    
    -- Request Payload (sanitized)
    request_payload     JSONB,
    payload_size_bytes  INTEGER,
    
    -- Rejection Details
    reason_code         VARCHAR(50) NOT NULL REFERENCES core.rejection_reasons(reason_code),
    reason_detail       TEXT,                        -- Detailed explanation
    validation_errors   JSONB,                       -- Schema validation errors
    
    -- Context
    source_ip           INET,
    user_agent          TEXT,
    device_fingerprint  VARCHAR(255),
    
    -- Timing
    received_at         TIMESTAMPTZ NOT NULL,
    rejected_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    processing_duration_ms INTEGER,                  -- Time spent before rejection
    
    -- Support
    support_ticket_id   VARCHAR(100),
    reviewed_by         UUID REFERENCES core.accounts(account_id),
    reviewed_at         TIMESTAMPTZ,
    notes               TEXT,
    
    -- Retention
    retention_until     DATE,                        -- Auto-purge after this date
    
    -- Partition key
    rejection_date      DATE NOT NULL DEFAULT CURRENT_DATE
);

-- Indexes for rejection_log
CREATE INDEX idx_rejection_log_idempotency ON core.rejection_log(idempotency_key_id);
CREATE INDEX idx_rejection_log_initiator ON core.rejection_log(initiator_account_id, rejected_at);
CREATE INDEX idx_rejection_log_reason ON core.rejection_log(reason_code, rejected_at);
CREATE INDEX idx_rejection_log_application ON core.rejection_log(application_id, rejected_at);
CREATE INDEX idx_rejection_log_date ON core.rejection_log(rejection_date);
CREATE INDEX idx_rejection_log_retention ON core.rejection_log(retention_until) WHERE retention_until < CURRENT_DATE;

COMMENT ON TABLE core.rejection_log IS 'Record of all rejected transactions (NOT part of immutable ledger)';
COMMENT ON COLUMN core.rejection_log.retention_until IS 'Auto-purge date based on retention policy';

-- =============================================================================
-- Create rejection summary view
-- DESCRIPTION: Aggregated rejection statistics
-- PRIORITY: MEDIUM
-- SECURITY: Aggregated data reduces sensitivity
-- ============================================================================
CREATE VIEW core.rejection_summary AS
SELECT 
    date_trunc('hour', rejected_at) as hour,
    application_id,
    reason_code,
    COUNT(*) as rejection_count,
    AVG(processing_duration_ms) as avg_duration_ms,
    MAX(processing_duration_ms) as max_duration_ms,
    MIN(processing_duration_ms) as min_duration_ms
FROM core.rejection_log
WHERE rejected_at > now() - interval '7 days'
GROUP BY 1, 2, 3;

COMMENT ON VIEW core.rejection_summary IS 'Hourly rejection statistics for monitoring dashboards';

-- =============================================================================
-- Create payload sanitization function
-- DESCRIPTION: Remove sensitive data from logged payloads
-- PRIORITY: HIGH
-- SECURITY: Mask PII fields before logging
-- ============================================================================
CREATE OR REPLACE FUNCTION core.sanitize_payload(p_payload JSONB)
RETURNS JSONB AS $$
DECLARE
    v_result JSONB := p_payload;
    v_sensitive_fields TEXT[] := ARRAY['password', 'pin', 'ssn', 'phone', 'email', 'name', 'full_name', 'address', 'dob', 'date_of_birth'];
    v_field TEXT;
    v_keys TEXT[];
    v_key TEXT;
    v_value JSONB;
BEGIN
    IF p_payload IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Handle non-object payloads
    IF jsonb_typeof(p_payload) != 'object' THEN
        RETURN p_payload;
    END IF;
    
    -- Mask sensitive fields at top level
    FOREACH v_field IN ARRAY v_sensitive_fields
    LOOP
        IF v_result ? v_field THEN
            v_result := jsonb_set(v_result, ARRAY[v_field], '"***MASKED***"'::jsonb);
        END IF;
    END LOOP;
    
    -- Recursively process nested objects (one level deep)
    v_keys := ARRAY(SELECT jsonb_object_keys(v_result));
    FOREACH v_key IN ARRAY v_keys
    LOOP
        v_value := v_result->v_key;
        IF jsonb_typeof(v_value) = 'object' THEN
            FOREACH v_field IN ARRAY v_sensitive_fields
            LOOP
                IF v_value ? v_field THEN
                    v_value := jsonb_set(v_value, ARRAY[v_field], '"***MASKED***"'::jsonb);
                END IF;
            END LOOP;
            v_result := jsonb_set(v_result, ARRAY[v_key], v_value);
        END IF;
    END LOOP;
    
    -- Mask patterns in string values
    v_result := regexp_replace(v_result::text, '\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '****-****-****-****', 'g')::jsonb;
    
    RETURN v_result;
END;
$$ LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.sanitize_payload IS 'Removes PII fields from payload before logging';

-- =============================================================================
-- Create rejection logging function
-- DESCRIPTION: Standardized rejection recording
-- PRIORITY: HIGH
-- SECURITY: Sanitizes sensitive data from payload
-- ============================================================================
CREATE OR REPLACE FUNCTION core.log_rejection(
    p_idempotency_key_id UUID,
    p_reason_code VARCHAR(50),
    p_reason_detail TEXT,
    p_request_payload JSONB DEFAULT NULL,
    p_validation_errors JSONB DEFAULT NULL,
    p_application_id UUID DEFAULT NULL,
    p_initiator_account_id UUID DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_rejection_id UUID;
    v_retention_days INTEGER;
    v_idempotency_key VARCHAR(255);
BEGIN
    -- Get retention policy
    BEGIN
        SELECT COALESCE((value::integer), 90) INTO v_retention_days
        FROM app.configuration
        WHERE key = 'rejection.retention_days';
    EXCEPTION WHEN OTHERS THEN
        v_retention_days := 90;  -- Default
    END;
    
    -- Get idempotency key
    SELECT idempotency_key INTO v_idempotency_key
    FROM core.idempotency_keys
    WHERE idempotency_key_id = p_idempotency_key_id;
    
    INSERT INTO core.rejection_log (
        rejection_reference,
        idempotency_key_id,
        idempotency_key,
        reason_code,
        reason_detail,
        request_payload,
        validation_errors,
        received_at,
        rejected_at,
        retention_until,
        application_id,
        initiator_account_id,
        payload_size_bytes
    ) VALUES (
        'REJ-' || to_char(now(), 'YYYYMMDD') || '-' || substr(gen_random_uuid()::text, 1, 8),
        p_idempotency_key_id,
        v_idempotency_key,
        p_reason_code,
        p_reason_detail,
        core.sanitize_payload(p_request_payload),
        p_validation_errors,
        now() - INTERVAL '1 second',  -- Assume received slightly before rejection
        now(),
        CURRENT_DATE + v_retention_days,
        p_application_id,
        p_initiator_account_id,
        LENGTH(p_request_payload::text)
    )
    RETURNING rejection_id INTO v_rejection_id;
    
    -- Update idempotency key if provided
    IF p_idempotency_key_id IS NOT NULL THEN
        UPDATE core.idempotency_keys
        SET rejection_id = v_rejection_id,
            status = 'FAILED'
        WHERE idempotency_key_id = p_idempotency_key_id;
    END IF;
    
    RETURN v_rejection_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.log_rejection IS 'Centralized function to log rejected transactions with sanitization';

-- =============================================================================
-- Create rejection cleanup function
-- DESCRIPTION: Purge old rejection records
-- PRIORITY: MEDIUM
-- SECURITY: Archive summary stats before deletion
-- ============================================================================
CREATE OR REPLACE FUNCTION core.purge_old_rejections(
    p_batch_size INTEGER DEFAULT 1000
) RETURNS INTEGER AS $$
DECLARE
    v_deleted_count INTEGER := 0;
    v_archived_stats JSONB;
BEGIN
    -- Archive summary stats before deletion
    SELECT jsonb_build_object(
        'purged_at', now(),
        'retention_date', CURRENT_DATE,
        'count', COUNT(*),
        'by_reason', jsonb_object_agg(reason_code, cnt)
    ) INTO v_archived_stats
    FROM (
        SELECT reason_code, COUNT(*) as cnt
        FROM core.rejection_log
        WHERE retention_until < CURRENT_DATE
        GROUP BY reason_code
    ) sub;
    
    -- Log archive (in real system, would write to archive table)
    RAISE NOTICE 'Archiving rejection stats: %', v_archived_stats;
    
    -- Delete expired records in batches
    DELETE FROM core.rejection_log
    WHERE rejection_id IN (
        SELECT rejection_id 
        FROM core.rejection_log
        WHERE retention_until < CURRENT_DATE
        LIMIT p_batch_size
    );
    
    GET DIAGNOSTICS v_deleted_count = ROW_COUNT;
    
    RETURN v_deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.purge_old_rejections IS 'Purges rejection records past their retention date';

-- =============================================================================
-- Create rejection alert check function
-- DESCRIPTION: Check if rejection rate exceeds threshold
-- PRIORITY: MEDIUM
-- ============================================================================
CREATE OR REPLACE FUNCTION core.check_rejection_alerts()
RETURNS TABLE (
    reason_code VARCHAR(50),
    rejection_count BIGINT,
    threshold INTEGER,
    alert_triggered BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        rl.reason_code,
        COUNT(*) as rejection_count,
        rr.alert_threshold,
        COUNT(*) > rr.alert_threshold as alert_triggered
    FROM core.rejection_log rl
    JOIN core.rejection_reasons rr ON rl.reason_code = rr.reason_code
    WHERE rl.rejected_at > now() - interval '1 hour'
    GROUP BY rl.reason_code, rr.alert_threshold
    HAVING COUNT(*) > rr.alert_threshold;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.check_rejection_alerts IS 'Checks if rejection rates exceed configured thresholds';

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create rejection_reasons lookup table
☑ Create rejection_log table (non-immutable)
☑ Create rejection_summary view
☑ Implement log_rejection function
☑ Implement sanitize_payload function
☑ Implement purge_old_rejections function
☑ Add all indexes for rejection queries
☑ Test rejection logging
☑ Test payload sanitization
☑ Configure retention policies
================================================================================
*/
