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
-- TODO: Create rejection_reasons table
-- DESCRIPTION: Catalog of rejection reason codes
-- PRIORITY: HIGH
-- SECURITY: User-facing messages sanitized
-- ============================================================================
-- TODO: [REJ-001] Create core.rejection_reasons table
-- INSTRUCTIONS:
--   - Standardized rejection reason codes
--   - Categorized for reporting
--   - Supports user-facing messages
--   - ERROR HANDLING: Prevent duplicate reason codes
-- COMPLIANCE: ISO/IEC 27001 (Standardized Logging)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.rejection_reasons (
--       reason_code         VARCHAR(50) PRIMARY KEY,
--       reason_category     VARCHAR(50) NOT NULL,        -- VALIDATION, SYSTEM, COMPLIANCE
--       reason_name         VARCHAR(100) NOT NULL,
--       description         TEXT,
--       
--       -- User Communication
--       user_message_template VARCHAR(255),              -- Localizable message
--       support_action      TEXT,                        -- Suggested support action
--       
--       -- Severity
--       severity            VARCHAR(20) DEFAULT 'ERROR', -- INFO, WARNING, ERROR, CRITICAL
--       
--       -- Retry Behavior
--       is_retryable        BOOLEAN DEFAULT false,       -- Can user retry?
--       retry_after_seconds INTEGER,                     -- Suggested wait time
--       
--       -- Monitoring
--       alert_threshold     INTEGER DEFAULT 100,         -- Alert if rejections/hour exceeds
--       
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );
--
-- SEED DATA (in 055_seed_data.sql):
--   - INSUFFICIENT_FUNDS, INVALID_ACCOUNT, INVALID_AMOUNT
--   - VALIDATION_FAILED, RATE_LIMIT_EXCEEDED
--   - DUPLICATE_TRANSACTION, COMPLIANCE_BLOCKED
--   - SYSTEM_ERROR, TIMEOUT_ERROR

-- =============================================================================
-- TODO: Create rejection_log table
-- DESCRIPTION: Record of all rejected transactions
-- PRIORITY: CRITICAL
-- SECURITY: Sanitized payloads, TTL-based cleanup
-- ============================================================================
-- TODO: [REJ-002] Create core.rejection_log table
-- INSTRUCTIONS:
--   - NOT part of immutable ledger (can be purged)
--   - Captures request that was rejected
--   - Links to idempotency key for dedup
--   - RLS POLICY: Tenant isolation
--   - ERROR HANDLING: Sanitize all logged payloads
-- COMPLIANCE: ISO/IEC 27018 (PII Sanitization)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.rejection_log (
--       rejection_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       rejection_reference VARCHAR(100) UNIQUE NOT NULL,
--       
--       -- Request Details
--       idempotency_key_id  UUID REFERENCES core.idempotency_keys(idempotency_key_id),
--       idempotency_key     VARCHAR(255),                -- Copy at time of rejection
--       
--       -- Transaction Attempt
--       transaction_type_id UUID REFERENCES core.transaction_types(transaction_type_id),
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Initiator
--       initiator_account_id UUID REFERENCES core.accounts(account_id),
--       initiator_session   VARCHAR(255),                -- USSD session ID
--       
--       -- Request Payload (sanitized)
--       request_payload     JSONB,
--       payload_size_bytes  INTEGER,
--       
--       -- Rejection Details
--       reason_code         VARCHAR(50) NOT NULL REFERENCES core.rejection_reasons(reason_code),
--       reason_detail       TEXT,                        -- Detailed explanation
--       validation_errors   JSONB,                       -- Schema validation errors
--       
--       -- Context
--       source_ip           INET,
--       user_agent          TEXT,
--       device_fingerprint  VARCHAR(255),
--       
--       -- Timing
--       received_at         TIMESTAMPTZ NOT NULL,
--       rejected_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
--       processing_duration_ms INTEGER,                  -- Time spent before rejection
--       
--       -- Support
--       support_ticket_id   VARCHAR(100),
--       reviewed_by         UUID REFERENCES core.accounts(account_id),
--       reviewed_at         TIMESTAMPTZ,
--       notes               TEXT,
--       
--       -- Retention
--       retention_until     DATE,                        -- Auto-purge after this date
--       
--       -- Partition key
--       rejection_date      DATE NOT NULL DEFAULT CURRENT_DATE
--   );

-- =============================================================================
-- TODO: Create rejection summary view
-- DESCRIPTION: Aggregated rejection statistics
-- PRIORITY: MEDIUM
-- SECURITY: Aggregated data reduces sensitivity
-- ============================================================================
-- TODO: [REJ-003] Create rejection_summary view
-- INSTRUCTIONS:
--   - Hourly/daily rejection counts by reason
--   - For monitoring dashboards
--   - Supports alerting threshold detection
--   - RLS POLICY: Apply tenant filter
-- COMPLIANCE: ISO/IEC 27001 (Monitoring)
--
-- VIEW DEFINITION OUTLINE:
--   CREATE VIEW core.rejection_summary AS
--   SELECT 
--       date_trunc('hour', rejected_at) as hour,
--       application_id,
--       reason_code,
--       COUNT(*) as rejection_count,
--       AVG(processing_duration_ms) as avg_duration_ms
--   FROM core.rejection_log
--   WHERE rejected_at > now() - interval '7 days'
--   GROUP BY 1, 2, 3;

-- =============================================================================
-- TODO: Create rejection logging function
-- DESCRIPTION: Standardized rejection recording
-- PRIORITY: HIGH
-- SECURITY: Sanitizes sensitive data from payload
-- ============================================================================
-- TODO: [REJ-004] Create log_rejection function
-- INSTRUCTIONS:
--   - Centralized function to log rejections
--   - Sanitizes sensitive data from payload
--   - Calculates retention date
--   - ERROR HANDLING: Handle NULL payloads gracefully
--   - SEARCH PATH: Explicitly set
-- COMPLIANCE: ISO/IEC 27018 (Sanitization)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.log_rejection(
--       p_idempotency_key_id UUID,
--       p_reason_code VARCHAR(50),
--       p_reason_detail TEXT,
--       p_request_payload JSONB DEFAULT NULL,
--       p_validation_errors JSONB DEFAULT NULL
--   ) RETURNS UUID AS $$
--   DECLARE
--       v_rejection_id UUID;
--       v_retention_days INTEGER;
--   BEGIN
--       -- Get retention policy
--       SELECT COALESCE((value::integer), 90) INTO v_retention_days
--       FROM app.configuration
--       WHERE key = 'rejection.retention_days';
--       
--       INSERT INTO core.rejection_log (
--           rejection_reference,
--           idempotency_key_id,
--           reason_code,
--           reason_detail,
--           request_payload,
--           validation_errors,
--           rejected_at,
--           retention_until
--       ) VALUES (
--           'REJ-' || to_char(now(), 'YYYYMMDD') || '-' || substr(gen_random_uuid()::text, 1, 8),
--           p_idempotency_key_id,
--           p_reason_code,
--           p_reason_detail,
--           core.sanitize_payload(p_request_payload),
--           p_validation_errors,
--           now(),
--           CURRENT_DATE + v_retention_days
--       )
--       RETURNING rejection_id INTO v_rejection_id;
--       
--       RETURN v_rejection_id;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create payload sanitization function
-- DESCRIPTION: Remove sensitive data from logged payloads
-- PRIORITY: HIGH
-- SECURITY: Mask PII fields before logging
-- ============================================================================
-- TODO: [REJ-005] Create sanitize_payload function
-- INSTRUCTIONS:
--   - Remove PII fields (names, phone numbers, etc.)
--   - Mask sensitive financial data
--   - Preserve structure for debugging
--   - ERROR HANDLING: Handle non-object payloads
-- COMPLIANCE: ISO/IEC 27018 (PII Protection)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.sanitize_payload(p_payload JSONB)
--   RETURNS JSONB AS $$
--   DECLARE
--       v_result JSONB := p_payload;
--       v_sensitive_fields TEXT[] := ARRAY['password', 'pin', 'ssn', 'phone', 'email', 'name'];
--       v_field TEXT;
--   BEGIN
--       IF p_payload IS NULL THEN
--           RETURN NULL;
--       END IF;
--       
--       -- Mask sensitive fields
--       FOREACH v_field IN ARRAY v_sensitive_fields
--       LOOP
--           IF v_result ? v_field THEN
--               v_result := jsonb_set(v_result, ARRAY[v_field], '"***MASKED***"'::jsonb);
--           END IF;
--       END LOOP;
--       
--       RETURN v_result;
--   END;
--   $$ LANGUAGE plpgsql IMMUTABLE;

-- =============================================================================
-- TODO: Create rejection cleanup function
-- DESCRIPTION: Purge old rejection records
-- PRIORITY: MEDIUM
-- SECURITY: Archive summary stats before deletion
-- ============================================================================
-- TODO: [REJ-006] Create purge_old_rejections function
-- INSTRUCTIONS:
--   - Called by scheduled job
--   - Delete records past retention_until
--   - Archive summary stats before deletion
--   - ERROR HANDLING: Log deletion count for audit
-- COMPLIANCE: ISO/IEC 27040 (Retention Management)

-- =============================================================================
-- TODO: Create rejection indexes
-- DESCRIPTION: Optimize rejection queries
-- PRIORITY: HIGH
-- SECURITY: Index on retention_until for cleanup
-- ============================================================================
-- TODO: [REJ-007] Create rejection indexes
-- INDEX LIST:
--   - PRIMARY KEY (rejection_id)
--   - UNIQUE (rejection_reference)
--   - INDEX on (idempotency_key_id)
--   - INDEX on (initiator_account_id, rejected_at)
--   - INDEX on (reason_code, rejected_at)
--   - INDEX on (application_id, rejected_at)
--   - INDEX on (rejection_date)  -- For partition pruning
--   - INDEX on (retention_until) WHERE retention_until < CURRENT_DATE

/*
================================================================================
MIGRATION CHECKLIST:
□ Create rejection_reasons lookup table
□ Create rejection_log table (non-immutable)
□ Create rejection_summary view
□ Implement log_rejection function
□ Implement sanitize_payload function
□ Implement purge_old_rejections function
□ Add all indexes for rejection queries
□ Test rejection logging
□ Test payload sanitization
□ Configure retention policies
================================================================================
*/
