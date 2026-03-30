-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (External party management)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Settlement security)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Destination data handling)
-- ISO/IEC 27040:2024 - Storage Security (Settlement integrity)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Settlement recovery)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Multiple settlement methods with validation
-- - Finality tracking for reconciliation
-- - External reference linking
-- - Failure handling and retry logic
-- ============================================================================
-- =============================================================================
-- MIGRATION: 014_core_settlement_instructions.sql
-- DESCRIPTION: External Settlement Instructions
-- TABLES: settlement_instructions, settlement_attempts
-- DEPENDENCIES: 005_core_movement_legs.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 7. Settlement & External Integration
- Feature: Settlement Instructions
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Tracks settlement of movements to external systems (mobile money, bank).
When a user withdraws from a savings group to mobile money, a settlement
instruction records the external payout status.

KEY FEATURES:
- Multiple settlement methods (RTGS, mobile money, wallet)
- Finality tracking for reconciliation
- External reference linking (mobile money tx ID)
- Failure handling and retry logic
- Settlement reconciliation matching

SETTLEMENT METHODS:
- RTGS: Real-time gross settlement
- MOBILE_MONEY: Mobile network operator
- WALLET: Internal wallet transfer
- CASH: Physical cash disbursement
- BANK_TRANSFER: ACH/wire transfer
================================================================================
*/

-- =============================================================================
-- TODO: Create settlement_methods table
-- DESCRIPTION: Catalog of settlement methods
-- PRIORITY: HIGH
-- SECURITY: Validate configuration schema
-- ============================================================================
-- TODO: [SETTLE-001] Create core.settlement_methods table
-- INSTRUCTIONS:
--   - Define available settlement methods per application
--   - Configuration for each method
--   - ERROR HANDLING: Validate config_schema is valid JSON Schema
-- COMPLIANCE: ISO/IEC 27001 (Method Classification)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.settlement_methods (
--       method_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       method_code         VARCHAR(50) NOT NULL,
--       method_name         VARCHAR(100) NOT NULL,
--       description         TEXT,
--       
--       -- Classification
--       method_type         VARCHAR(50) NOT NULL,        -- RTGS, MOBILE_MONEY, etc.
--       direction           VARCHAR(10) NOT NULL,        -- INBOUND, OUTBOUND, BOTH
--       
--       -- Configuration
--       config_schema       JSONB,                       -- Required config fields
--       default_config      JSONB,                       -- Default values
--       
--       -- Limits
--       min_amount          NUMERIC(20, 8),
--       max_amount          NUMERIC(20, 8),
--       
--       -- Timing
--       typical_delay_minutes INTEGER,
--       cutoff_time         TIME,                        -- Daily cutoff
--       
--       -- Application Scope
--       application_id      UUID REFERENCES app.applications(application_id), -- NULL = global
--       
--       is_active           BOOLEAN DEFAULT true,
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create settlement_instructions table
-- DESCRIPTION: Individual settlement records
-- PRIORITY: CRITICAL
-- SECURITY: Encrypt destination details
-- ============================================================================
-- TODO: [SETTLE-002] Create core.settlement_instructions table
-- INSTRUCTIONS:
--   - Links movement to external settlement
--   - Tracks settlement lifecycle
--   - Records finality for reconciliation
--   - RLS POLICY: Tenant isolation
--   - ERROR HANDLING: Validate amount within method limits
-- COMPLIANCE: ISO/IEC 27040 (Settlement Integrity)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.settlement_instructions (
--       instruction_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       instruction_reference VARCHAR(100) UNIQUE NOT NULL,
--       
--       -- Link to Movement
--       movement_id         UUID NOT NULL REFERENCES core.movement_headers(movement_id),
--       leg_id              UUID REFERENCES core.movement_legs(leg_id),
--       
--       -- Settlement Details
--       method_id           UUID NOT NULL REFERENCES core.settlement_methods(method_id),
--       settlement_method   VARCHAR(50) NOT NULL,        -- Denormalized for queries
--       
--       -- Amount
--       amount              NUMERIC(20, 8) NOT NULL,
--       currency            VARCHAR(3) NOT NULL,
--       fees                NUMERIC(20, 8) DEFAULT 0,
--       net_amount          NUMERIC(20, 8) NOT NULL,
--       
--       -- Destination
--       destination_type    VARCHAR(50),                 -- BANK_ACCOUNT, MOBILE_WALLET
--       destination_details JSONB,                       -- Account number, etc.
--       
--       -- Status Workflow
--       status              VARCHAR(20) DEFAULT 'PENDING',
--                           -- PENDING, SUBMITTED, PROCESSING, 
--                           -- COMPLETED, FAILED, CANCELLED, REVERSED
--       
--       -- External Reference
--       external_reference  VARCHAR(255),                -- Provider's transaction ID
--       external_status     VARCHAR(50),                 -- Provider's status
--       
--       -- Finality (for reconciliation)
--       is_final            BOOLEAN DEFAULT false,       -- Irreversible
--       finality_timestamp  TIMESTAMPTZ,                 -- When became final
--       
--       -- Timing
--       requested_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
--       submitted_at        TIMESTAMPTZ,
--       completed_at        TIMESTAMPTZ,
--       expected_completion TIMESTAMPTZ,
--       
--       -- Retry
--       retry_count         INTEGER DEFAULT 0,
--       max_retries         INTEGER DEFAULT 3,
--       next_retry_at       TIMESTAMPTZ,
--       
--       -- Application
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id),
--       updated_at          TIMESTAMPTZ
--   );

-- =============================================================================
-- TODO: Create settlement_attempts table
-- DESCRIPTION: Log of settlement submission attempts
-- PRIORITY: MEDIUM
-- SECURITY: Log raw provider responses for debugging
-- ============================================================================
-- TODO: [SETTLE-003] Create core.settlement_attempts table
-- INSTRUCTIONS:
--   - Records each attempt to submit settlement
--   - Tracks success/failure per attempt
--   - Stores raw provider response
--   - ERROR HANDLING: Handle large response payloads
-- COMPLIANCE: ISO/IEC 27001 (Attempt Logging)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.settlement_attempts (
--       attempt_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       instruction_id      UUID NOT NULL REFERENCES core.settlement_instructions(instruction_id),
--       
--       -- Attempt Details
--       attempt_number      INTEGER NOT NULL,
--       status              VARCHAR(20) NOT NULL,        -- SUCCESS, FAILED, TIMEOUT
--       
--       -- Request/Response
--       request_payload     JSONB,
--       response_payload    JSONB,
--       response_code       VARCHAR(50),
--       error_message       TEXT,
--       
--       -- Timing
--       started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       completed_at        TIMESTAMPTZ,
--       duration_ms         INTEGER,
--       
--       -- Provider
--       provider_reference  VARCHAR(255),
--       
--       -- Audit
--       processed_by        VARCHAR(100)                 -- Service instance
--   );

-- =============================================================================
-- TODO: Create settlement execution function
-- DESCRIPTION: Submit settlement to external provider
-- PRIORITY: CRITICAL
-- SECURITY: Timeout and retry handling
-- ============================================================================
-- TODO: [SETTLE-004] Create execute_settlement function
-- INSTRUCTIONS:
--   - Submit settlement to external provider
--   - Handle synchronous and async responses
--   - Record attempt details
--   - Update instruction status
--   - ERROR HANDLING: Catch and log all provider errors
--   - TRANSACTION ISOLATION: Each attempt in separate transaction
-- COMPLIANCE: ISO/IEC 27031 (External Integration)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.execute_settlement(p_instruction_id UUID)
--   RETURNS VARCHAR AS $$
--   DECLARE
--       v_instruction RECORD;
--       v_attempt_id UUID;
--       v_start_time TIMESTAMPTZ;
--   BEGIN
--       SELECT * INTO v_instruction 
--       FROM core.settlement_instructions 
--       WHERE instruction_id = p_instruction_id;
--       
--       -- Mark as processing
--       UPDATE core.settlement_instructions
--       SET status = 'PROCESSING', submitted_at = now()
--       WHERE instruction_id = p_instruction_id;
--       
--       v_start_time := clock_timestamp();
--       
--       -- Create attempt record
--       INSERT INTO core.settlement_attempts (
--           instruction_id, attempt_number, status, started_at
--       ) VALUES (
--           p_instruction_id, 
--           v_instruction.retry_count + 1,
--           'PENDING',
--           v_start_time
--       )
--       RETURNING attempt_id INTO v_attempt_id;
--       
--       -- Call provider (pseudo-code)
--       -- v_result := settlement_provider.submit(v_instruction);
--       
--       -- Update based on result
--       -- Update settlement_attempts
--       -- Update settlement_instructions
--       
--       RETURN 'PROCESSING';
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create settlement finality check function
-- DESCRIPTION: Verify settlement is irreversible
-- PRIORITY: HIGH
-- SECURITY: Confirm finality before reconciliation
-- ============================================================================
-- TODO: [SETTLE-005] Create check_settlement_finality function
-- INSTRUCTIONS:
--   - Query provider for current status
--   - Update is_final flag when confirmed
--   - Used by reconciliation process
--   - ERROR HANDLING: Handle provider timeouts
-- COMPLIANCE: ISO/IEC 27040 (Finality Verification)

-- =============================================================================
-- TODO: Create settlement failure handling
-- DESCRIPTION: Process failed settlements
-- PRIORITY: HIGH
-- SECURITY: Alert on max retries exceeded
-- ============================================================================
-- TODO: [SETTLE-006] Create handle_settlement_failure function
-- INSTRUCTIONS:
--   - Determine if retry is appropriate
--   - Schedule next retry
--   - Alert operations if max retries exceeded
--   - Create manual intervention queue entry
--   - AUDIT LOGGING: Log all failure handling actions
-- COMPLIANCE: ISO/IEC 27031 (Failure Handling)

-- =============================================================================
-- TODO: Create settlement indexes
-- DESCRIPTION: Optimize settlement queries
-- PRIORITY: HIGH
-- SECURITY: Index on is_final for reconciliation
-- ============================================================================
-- TODO: [SETTLE-007] Create settlement indexes
-- INDEX LIST:
--   - PRIMARY KEY (instruction_id)
--   - UNIQUE (instruction_reference)
--   - INDEX on (movement_id)
--   - INDEX on (status, next_retry_at) WHERE status IN ('PENDING', 'FAILED')
--   - INDEX on (external_reference)
--   - INDEX on (application_id, status)
--   - INDEX on (is_final, finality_timestamp) WHERE is_final = true
--   -- Attempts:
--   - INDEX on (instruction_id, attempt_number)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create settlement_methods table
□ Create settlement_instructions table
□ Create settlement_attempts table
□ Implement execute_settlement function
□ Implement check_settlement_finality function
□ Implement handle_settlement_failure function
□ Add all indexes for settlement queries
□ Test settlement submission flow
□ Test retry logic
□ Verify external reference linking
================================================================================
*/
