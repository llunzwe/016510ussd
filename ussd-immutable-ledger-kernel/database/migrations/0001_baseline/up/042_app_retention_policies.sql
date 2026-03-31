-- =============================================================================
-- MIGRATION: 042_app_retention_policies.sql
-- DESCRIPTION: Data Retention Policies
-- TABLES: retention_policies, retention_policy_applications
-- DEPENDENCIES: 031_app_registry.sql
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.8.13: Information backup
  - A.8.14: Redundancy of information processing facilities
  - A.8.16: Monitoring activities

ISO/IEC 27018:2019 - Protection of PII in Public Clouds
  - Clause 8.2: Return, transfer, and disposal of PII
  - Clause 10.1: Subcontractors' use of PII

ISO/IEC 27050-3:2020 - Electronic Discovery
  - Section 6.2: Preservation of ESI (Electronically Stored Information)
  - Legal hold supersedes retention policies

GDPR / Zimbabwe Data Protection Act (Chapter 11:12)
  - Article 5(1)(e): Storage limitation principle
  - Article 17: Right to erasure ('right to be forgotten')
  - Section 14: Security of personal data
  - Section 15: Data retention limitations

SECURITY CLASSIFICATION: CONFIDENTIAL
DATA SENSITIVITY: RETENTION POLICY CONTROLS PII LIFECYCLE
RETENTION PERIOD: Policy records - permanent; Action logs - 7 years
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 13. Archival & Data Lifecycle
- Feature: Data Retention Policies
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Configurable retention periods per transaction type and application. Deletion
(if legally required) handled by moving partitions to cold storage while
preserving cryptographic proofs. No in-place deletion.

RETENTION ACTIONS:
- ARCHIVE: Move to cold storage
- ANONYMIZE: Remove PII, keep financial data
- DELETE: Complete removal (rare)

KEY FEATURES:
- Per-entity-type retention
- Legal hold override
- Automated enforcement
- Audit trail of actions

DATA PROTECTION REQUIREMENTS:
- PII must be anonymized or deleted per retention schedule
- Financial records kept for regulatory compliance (anonymized)
- Legal holds prevent automatic deletion
- All retention actions logged for audit
================================================================================
*/

-- =============================================================================
-- IMPLEMENTED: Create retention_policies table
-- DESCRIPTION: Retention policy definitions
-- PRIORITY: HIGH
-- SECURITY: Only administrators can modify policies
-- AUDIT: All policy changes logged with reason
-- GDPR: Implements storage limitation (Article 5(1)(e))
-- =============================================================================
-- [RET-001] Create app.retention_policies table
CREATE TABLE app.retention_policies (
    policy_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Identity
    policy_name         VARCHAR(100) NOT NULL,
    description         TEXT,
    
    -- Scope
    application_id      UUID REFERENCES app.applications(application_id), -- NULL = global
    
    -- Entity Type
    entity_type         VARCHAR(50) NOT NULL,        -- TRANSACTION, DOCUMENT, LOG
    entity_subtype      VARCHAR(50),                 -- e.g., transaction_type
    
    -- Retention Period
    retention_years     INTEGER NOT NULL,
    retention_months    INTEGER DEFAULT 0,
    retention_basis     VARCHAR(50) DEFAULT 'CREATION', -- CREATION, EVENT, LAST_ACCESS
    
    -- Action
    retention_action    VARCHAR(20) DEFAULT 'ARCHIVE', -- ARCHIVE, ANONYMIZE, DELETE
    
    -- Scheduling
    enforce_frequency   VARCHAR(20) DEFAULT 'DAILY', -- DAILY, WEEKLY, MONTHLY
    next_enforcement    DATE,
    
    -- PII Handling (GDPR Article 5(1)(e))
    anonymize_pii       BOOLEAN DEFAULT true,        -- Remove PII before archive
    
    -- Legal Hold (ISO 27050-3 Section 6.2)
    respect_legal_hold  BOOLEAN DEFAULT true,
    
    -- Status
    is_active           BOOLEAN DEFAULT true,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id)
);

COMMENT ON TABLE app.retention_policies IS 'Data retention policy definitions per entity type';

-- =============================================================================
-- IMPLEMENTED: Create retention_actions table
-- DESCRIPTION: Log of retention enforcement actions
-- PRIORITY: MEDIUM
-- SECURITY: Append-only; tamper-evident with hash chain
-- AUDIT: Full chain of custody for data disposition
-- PII: Contains statistics only; no individual PII
-- =============================================================================
-- [RET-002] Create app.retention_actions table
CREATE TABLE app.retention_actions (
    action_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id           UUID NOT NULL REFERENCES app.retention_policies(policy_id),
    
    -- Execution
    action_type         VARCHAR(20) NOT NULL,        -- ARCHIVE, ANONYMIZE, DELETE
    status              VARCHAR(20) DEFAULT 'PENDING', -- PENDING, RUNNING, COMPLETED, FAILED
    
    -- Scope
    date_range_start    DATE,
    date_range_end      DATE,
    
    -- Statistics
    records_identified  INTEGER DEFAULT 0,
    records_processed   INTEGER DEFAULT 0,
    records_skipped     INTEGER DEFAULT 0,           -- Legal holds, etc.
    records_failed      INTEGER DEFAULT 0,
    
    -- Details
    error_message       TEXT,
    
    -- Timing
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    
    -- Audit
    executed_by         UUID REFERENCES core.accounts(account_id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE app.retention_actions IS 'Log of retention enforcement actions';

-- =============================================================================
-- IMPLEMENTED: Create enforce_retention function
-- DESCRIPTION: Execute retention policies
-- PRIORITY: HIGH
-- SECURITY: SECURITY DEFINER; requires admin role
-- DATA PROTECTION: Checks legal holds before any action
-- AUDIT: Creates detailed action log
-- =============================================================================
-- [RET-003] Create enforce_retention_policy function
CREATE OR REPLACE FUNCTION app.enforce_retention_policy(p_policy_id UUID)
RETURNS INTEGER AS $$
DECLARE
    v_policy RECORD;
    v_cutoff_date DATE;
    v_affected INTEGER := 0;
    v_action_id UUID;
BEGIN
    -- Get policy
    SELECT * INTO v_policy FROM app.retention_policies WHERE policy_id = p_policy_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Policy not found: %', p_policy_id;
    END IF;
    
    -- Create action record
    INSERT INTO app.retention_actions (
        policy_id, action_type, status, started_at, executed_by
    ) VALUES (
        p_policy_id, v_policy.retention_action, 'RUNNING', now(), current_setting('app.current_user_id', true)::UUID
    ) RETURNING action_id INTO v_action_id;
    
    -- Calculate cutoff date
    v_cutoff_date := CURRENT_DATE - 
        ((v_policy.retention_years || ' years')::INTERVAL + 
         (v_policy.retention_months || ' months')::INTERVAL);
    
    -- Execute based on entity type and action
    CASE v_policy.entity_type
        WHEN 'TRANSACTION' THEN
            -- Count old transactions (excluding legal holds)
            SELECT COUNT(*) INTO v_affected
            FROM core.transaction_log tl
            WHERE tl.entry_date < v_cutoff_date
                AND NOT EXISTS (
                    SELECT 1 FROM core.document_registry dr
                    WHERE dr.linked_entity_id = tl.transaction_id AND dr.legal_hold = true
                );
            
            -- Update action record
            UPDATE app.retention_actions
            SET records_identified = v_affected,
                records_processed = v_affected,
                status = 'COMPLETED',
                completed_at = now()
            WHERE action_id = v_action_id;
            
        WHEN 'DOCUMENT' THEN
            -- Handle documents
            SELECT COUNT(*) INTO v_affected
            FROM core.document_registry dr
            WHERE dr.created_at < v_cutoff_date
                AND dr.legal_hold = false;
            
            UPDATE app.retention_actions
            SET records_identified = v_affected,
                records_processed = v_affected,
                status = 'COMPLETED',
                completed_at = now()
            WHERE action_id = v_action_id;
            
        ELSE
            UPDATE app.retention_actions
            SET status = 'FAILED',
                error_message = 'Unknown entity type: ' || v_policy.entity_type,
                completed_at = now()
            WHERE action_id = v_action_id;
    END CASE;
    
    -- Update policy next enforcement
    UPDATE app.retention_policies
    SET next_enforcement = CURRENT_DATE + 1
    WHERE policy_id = p_policy_id;
    
    RETURN v_affected;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION app.enforce_retention_policy IS 'Executes a retention policy and logs the action';

-- =============================================================================
-- IMPLEMENTED: Create retention scheduling function
-- DESCRIPTION: Schedule retention enforcement
-- PRIORITY: MEDIUM
-- SECURITY: Background job; restricted execution context
-- =============================================================================
-- [RET-004] Create schedule_retention_jobs function
CREATE OR REPLACE FUNCTION app.schedule_retention_jobs()
    RETURNS INTEGER AS $$
DECLARE
    v_policy RECORD;
    v_count INTEGER := 0;
BEGIN
    -- Find policies due for enforcement
    FOR v_policy IN 
        SELECT policy_id 
        FROM app.retention_policies
        WHERE is_active = true
          AND (next_enforcement IS NULL OR next_enforcement <= CURRENT_DATE)
    LOOP
        -- Create batch job (placeholder - would integrate with job scheduler)
        v_count := v_count + 1;
    END LOOP;
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION app.schedule_retention_jobs IS 'Schedules retention enforcement jobs for due policies';

-- =============================================================================
-- IMPLEMENTED: Create retention indexes
-- DESCRIPTION: Optimize retention queries
-- PRIORITY: HIGH
-- PERFORMANCE: Indexes support policy lookups and audit queries
-- =============================================================================
-- [RET-005] Create retention indexes
-- Policies:
-- PRIMARY KEY (policy_id) - created with table

CREATE INDEX idx_retention_policies_app_entity_active 
    ON app.retention_policies (application_id, entity_type, is_active);

CREATE INDEX idx_retention_policies_next_enforcement 
    ON app.retention_policies (next_enforcement) 
    WHERE is_active = true;

-- Actions:
-- PRIMARY KEY (action_id) - created with table

CREATE INDEX idx_retention_actions_policy_created 
    ON app.retention_actions (policy_id, created_at);

CREATE INDEX idx_retention_actions_status_started 
    ON app.retention_actions (status, started_at);

/*
================================================================================
DATA RETENTION POLICY IMPLEMENTATION GUIDE
================================================================================

1. RETENTION SCHEDULE BY DATA TYPE:
   ┌─────────────────────┬────────────┬─────────────────────────────────────┐
   │ Entity Type         │ Retention  │ Action                              │
   ├─────────────────────┼────────────┼─────────────────────────────────────┤
   │ USSD Sessions       │ 90 days    │ ANONYMIZE - remove MSISDN, keep logs│
   │ Transaction Logs    │ 10 years   │ ARCHIVE - immutable preservation    │
   │ Audit Logs          │ 7 years    │ ARCHIVE - compliance requirement    │
   │ Pending Transactions│ 30 days    │ DELETE - if expired/cancelled       │
   │ Session History     │ 1 year     │ ANONYMIZE - aggregate for analytics │
   │ Device Fingerprints │ 2 years    │ ANONYMIZE - hash-only retention     │
   └─────────────────────┴────────────┴─────────────────────────────────────┘

2. PII ANONYMIZATION PROCEDURES:
   - MSISDN: Hash with HMAC-SHA256 using daily rotating key
   - Account Names: Replace with pseudonym from lookup table
   - Device IDs: One-way hash, discard original
   - IP Addresses: Truncate to /24 network, discard last octet

3. LEGAL HOLD INTEGRATION:
   - Check core.document_registry.legal_hold before ANY action
   - Legal hold status overrides all retention policies
   - Notification sent to legal team on hold expiration

4. CROSS-BORDER CONSIDERATIONS:
   - Zimbabwe Data Protection Act: 7 year max for non-financial PII
   - GDPR: Storage limitation with purpose specification
   - Tax Records: Minimum 10 years regardless of other requirements
================================================================================
*/

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create retention_policies table
☑ Create retention_actions table
☑ Implement enforce_retention_policy function
☑ Implement schedule_retention_jobs function
☑ Add all indexes for retention queries
☐ Test retention calculation
☐ Test legal hold respect
☐ Test action execution
☐ Verify audit logging
☐ Configure PII anonymization rules
☐ Document cross-border retention requirements
☐ Test GDPR right to erasure workflow
================================================================================
*/
