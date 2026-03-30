-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Process management)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Distributed transaction security)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Saga data privacy)
-- ISO/IEC 27040:2024 - Storage Security (Saga state integrity)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Compensation)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Saga pattern with compensating transactions
-- - Timeout handling for long-running processes
-- - Event-driven state transitions
-- - Correlation IDs for distributed tracing
-- ============================================================================
-- =============================================================================
-- MIGRATION: 011_core_transaction_sagas.sql
-- DESCRIPTION: Long-Running Transaction Sagas (Compensating Transactions)
-- TABLES: transaction_sagas, saga_participants
-- DEPENDENCIES: 004_core_transaction_log.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 4. Transaction Processing & Lifecycle
- Feature: Transaction Entity (Saga), Saga Pattern
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Supports multi-step operations that may span multiple services or time periods.
If any step fails, compensating transactions reverse previous steps.
Essential for complex USSD workflows like loan disbursement.

KEY FEATURES:
- Saga status workflow: pending → validating → executing → committed/failed/compensating
- Multiple participants (initiator, beneficiary, approver)
- Compensation operations for rollback
- Timeout handling
- Correlation IDs for distributed tracing
- Event-driven state transitions

SAGA EXAMPLE (Loan Disbursement):
1. Check group balance (hold funds)
2. Debit from group account
3. Credit to member account
4. Update loan status
5. Notify member via SMS
If step 3 fails → compensate step 2 (refund group)
================================================================================
*/

-- =============================================================================
-- TODO: Create transaction_sagas table
-- DESCRIPTION: Saga orchestration header
-- PRIORITY: CRITICAL
-- SECURITY: Timeout prevents indefinite resource locks
-- ============================================================================
-- TODO: [SAGA-001] Create core.transaction_sagas table
-- INSTRUCTIONS:
--   - Master table for saga instances
--   - Tracks overall saga status
--   - Records saga definition/metadata
--   - RLS POLICY: Tenant isolation
--   - ERROR HANDLING: Validate timeout_at is in future
-- COMPLIANCE: ISO/IEC 27031 (Timeout Controls)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.transaction_sagas (
--       saga_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       saga_reference      VARCHAR(100) UNIQUE NOT NULL,
--       
--       -- Classification
--       saga_type           VARCHAR(50) NOT NULL,        -- 'LOAN_DISBURSEMENT', etc.
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Participants
--       initiator_account_id UUID NOT NULL REFERENCES core.accounts(account_id),
--       beneficiary_account_id UUID REFERENCES core.accounts(account_id),
--       
--       -- Financial Context
--       amount              NUMERIC(20, 8),
--       currency            VARCHAR(3),
--       
--       -- Status Workflow
--       status              VARCHAR(20) NOT NULL DEFAULT 'PENDING',
--                           -- PENDING, VALIDATING, EXECUTING, 
--                           -- AWAITING_COMPENSATION, COMPENSATING,
--                           -- COMMITTED, FAILED, COMPENSATED
--       
--       -- Timing
--       started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       completed_at        TIMESTAMPTZ,
--       timeout_at          TIMESTAMPTZ,                 -- Auto-fail if not completed
--       
--       -- Result
--       result_payload      JSONB,                       -- Final result data
--       failure_reason      TEXT,
--       failure_step        INTEGER,                     -- Which step failed
--       
--       -- Correlation
--       correlation_id      UUID NOT NULL,               -- Groups related sagas
--       parent_saga_id      UUID REFERENCES core.transaction_sagas(saga_id),
--       
--       -- Context
--       context_data        JSONB DEFAULT '{}',          -- Input parameters
--       
--       -- Idempotency
--       idempotency_key_id  UUID REFERENCES core.idempotency_keys(idempotency_key_id),
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       updated_at          TIMESTAMPTZ
--   );

-- =============================================================================
-- TODO: Create saga_steps table
-- DESCRIPTION: Individual steps within a saga
-- PRIORITY: CRITICAL
-- SECURITY: Compensation parameters validated before execution
-- ============================================================================
-- TODO: [SAGA-002] Create core.saga_steps table
-- INSTRUCTIONS:
--   - Each step represents one operation in the saga
--   - Records execution status and compensation info
--   - Ordered by sequence for deterministic execution
--   - ERROR HANDLING: Validate step_sequence is unique per saga
-- COMPLIANCE: ISO/IEC 27040 (Step Integrity)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.saga_steps (
--       step_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       saga_id             UUID NOT NULL REFERENCES core.transaction_sagas(saga_id),
--       
--       -- Ordering
--       step_sequence       INTEGER NOT NULL,            -- Execution order
--       step_name           VARCHAR(100) NOT NULL,       -- Human-readable name
--       
--       -- Step Definition
--       action_type         VARCHAR(50) NOT NULL,        -- 'MOVEMENT', 'WEBHOOK', 'VALIDATION'
--       action_params       JSONB NOT NULL,              -- Step-specific parameters
--       
--       -- Compensation
--       compensation_type   VARCHAR(50),                 -- Type of compensation
--       compensation_params JSONB,                       -- Compensation parameters
--       
--       -- Execution Status
--       status              VARCHAR(20) DEFAULT 'PENDING',
--                           -- PENDING, EXECUTING, COMPLETED, FAILED, COMPENSATED
--       
--       -- Results
--       result_data         JSONB,                       -- Step output
--       error_message       TEXT,
--       
--       -- Transaction Links
--       movement_id         UUID REFERENCES core.movement_headers(movement_id),
--       transaction_id      UUID REFERENCES core.transaction_log(transaction_id),
--       
--       -- Timing
--       started_at          TIMESTAMPTZ,
--       completed_at        TIMESTAMPTZ,
--       compensated_at      TIMESTAMPTZ,
--       
--       -- Retry
--       retry_count         INTEGER DEFAULT 0,
--       max_retries         INTEGER DEFAULT 3,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );
--
-- CONSTRAINTS:
--   - UNIQUE (saga_id, step_sequence)

-- =============================================================================
-- TODO: Create saga_events table
-- DESCRIPTION: Event log for saga state transitions
-- PRIORITY: MEDIUM
-- SECURITY: Immutable event log for audit
-- ============================================================================
-- TODO: [SAGA-003] Create core.saga_events table
-- INSTRUCTIONS:
--   - Append-only event log for saga state changes
--   - Enables replay and debugging
--   - Immutable once written
--   - AUDIT LOGGING: All state changes logged
-- COMPLIANCE: ISO/IEC 27001 (Event Logging)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.saga_events (
--       event_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       saga_id             UUID NOT NULL REFERENCES core.transaction_sagas(saga_id),
--       step_id             UUID REFERENCES core.saga_steps(step_id),
--       
--       -- Event Details
--       event_type          VARCHAR(50) NOT NULL,        -- 'STEP_STARTED', 'STEP_COMPLETED', etc.
--       event_data          JSONB,
--       
--       -- State Snapshot
--       previous_status     VARCHAR(20),
--       new_status          VARCHAR(20),
--       
--       -- Source
--       source_service      VARCHAR(100),                -- Which service generated event
--       source_instance     VARCHAR(100),                -- Instance/pod identifier
--       
--       -- Timing
--       occurred_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
--       
--       -- Ordering
--       event_sequence      BIGINT                       -- Global sequence for ordering
--   );

-- =============================================================================
-- TODO: Create saga execution function
-- DESCRIPTION: Execute saga steps and handle failures
-- PRIORITY: CRITICAL
-- SECURITY: Compensation on failure prevents partial commits
-- ============================================================================
-- TODO: [SAGA-004] Create execute_saga function
-- INSTRUCTIONS:
--   - Execute steps in sequence
--   - On failure, trigger compensation
--   - Record all events
--   - Handle timeouts
--   - ERROR HANDLING: Exception blocks for each step with compensation
--   - TRANSACTION ISOLATION: Each step in separate transaction
-- COMPLIANCE: ISO/IEC 27031 (Compensation)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.execute_saga(p_saga_id UUID)
--   RETURNS VARCHAR AS $$
--   DECLARE
--       v_saga RECORD;
--       v_step RECORD;
--       v_result JSONB;
--   BEGIN
--       -- Get saga
--       SELECT * INTO v_saga FROM core.transaction_sagas WHERE saga_id = p_saga_id;
--       
--       -- Update status to EXECUTING
--       UPDATE core.transaction_sagas 
--       SET status = 'EXECUTING', updated_at = now()
--       WHERE saga_id = p_saga_id;
--       
--       -- Execute each pending step
--       FOR v_step IN 
--           SELECT * FROM core.saga_steps 
--           WHERE saga_id = p_saga_id AND status = 'PENDING'
--           ORDER BY step_sequence
--       LOOP
--           -- Mark step as executing
--           UPDATE core.saga_steps 
--           SET status = 'EXECUTING', started_at = now()
--           WHERE step_id = v_step.step_id;
--           
--           -- Attempt execution (this is simplified)
--           BEGIN
--               -- Execute based on action_type
--               CASE v_step.action_type
--                   WHEN 'MOVEMENT' THEN
--                       v_result := core.execute_movement_step(v_step.action_params);
--                   WHEN 'WEBHOOK' THEN
--                       v_result := core.execute_webhook_step(v_step.action_params);
--                   -- etc.
--               END CASE;
--               
--               -- Mark completed
--               UPDATE core.saga_steps
--               SET status = 'COMPLETED', 
--                   completed_at = now(),
--                   result_data = v_result
--               WHERE step_id = v_step.step_id;
--               
--           EXCEPTION WHEN OTHERS THEN
--               -- Step failed - trigger compensation
--               PERFORM core.compensate_saga(p_saga_id, v_step.step_sequence);
--               RETURN 'FAILED';
--           END;
--       END LOOP;
--       
--       -- All steps completed
--       UPDATE core.transaction_sagas
--       SET status = 'COMMITTED', completed_at = now()
--       WHERE saga_id = p_saga_id;
--       
--       RETURN 'COMMITTED';
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create saga compensation function
-- DESCRIPTION: Rollback saga steps on failure
-- PRIORITY: CRITICAL
-- SECURITY: Execute compensations in reverse order
-- ============================================================================
-- TODO: [SAGA-005] Create compensate_saga function
-- INSTRUCTIONS:
--   - Execute compensation for completed steps in reverse order
--   - Record compensation transactions
--   - Handle compensation failures (alert operations)
--   - Update saga status to COMPENSATED or COMPENSATION_FAILED
--   - ERROR HANDLING: Alert on compensation failure
-- COMPLIANCE: ISO/IEC 27031 (Rollback)

-- =============================================================================
-- TODO: Create saga timeout check function
-- DESCRIPTION: Process timed-out sagas
-- PRIORITY: MEDIUM
-- SECURITY: Automatic compensation on timeout
-- ============================================================================
-- TODO: [SAGA-006] Create check_saga_timeouts function
-- INSTRUCTIONS:
--   - Called by scheduled job
--   - Find sagas past timeout_at with incomplete status
--   - Trigger compensation
--   - Record timeout event
--   - AUDIT LOGGING: Log all timeout events
-- COMPLIANCE: ISO/IEC 27031 (Timeout Handling)

-- =============================================================================
-- TODO: Create saga indexes
-- DESCRIPTION: Optimize saga queries
-- PRIORITY: HIGH
-- SECURITY: Index on correlation_id for tracing
-- ============================================================================
-- TODO: [SAGA-007] Create saga indexes
-- INDEX LIST:
--   - PRIMARY KEY (saga_id)
--   - UNIQUE (saga_reference)
--   - INDEX on (correlation_id)
--   - INDEX on (initiator_account_id, status)
--   - INDEX on (status, timeout_at) WHERE status IN ('PENDING', 'EXECUTING')
--   - INDEX on (application_id, saga_type)
--   - INDEX on (parent_saga_id)
--   -- For steps:
--   - UNIQUE (saga_id, step_sequence)
--   - INDEX on (saga_id, status)
--   -- For events:
--   - INDEX on (saga_id, event_sequence)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create transaction_sagas table
□ Create saga_steps table with compensation info
□ Create saga_events table for audit trail
□ Implement execute_saga function
□ Implement compensate_saga function
□ Implement timeout checking
□ Add all indexes for saga queries
□ Test saga execution flow
□ Test compensation on failure
□ Verify event logging
================================================================================
*/
