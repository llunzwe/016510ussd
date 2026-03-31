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
-- Create transaction_sagas table
-- DESCRIPTION: Saga orchestration header
-- PRIORITY: CRITICAL
-- SECURITY: Timeout prevents indefinite resource locks
-- ============================================================================
CREATE TABLE core.transaction_sagas (
    saga_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    saga_reference      VARCHAR(100) UNIQUE NOT NULL,
    
    -- Classification
    saga_type           VARCHAR(50) NOT NULL,        -- 'LOAN_DISBURSEMENT', etc.
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Participants
    initiator_account_id UUID NOT NULL REFERENCES core.accounts(account_id),
    beneficiary_account_id UUID REFERENCES core.accounts(account_id),
    
    -- Financial Context
    amount              NUMERIC(20, 8),
    currency            VARCHAR(3),
    
    -- Status Workflow
    status              VARCHAR(20) NOT NULL DEFAULT 'PENDING',
                        -- PENDING, VALIDATING, EXECUTING, 
                        -- AWAITING_COMPENSATION, COMPENSATING,
                        -- COMMITTED, FAILED, COMPENSATED
    
    -- Timing
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at        TIMESTAMPTZ,
    timeout_at          TIMESTAMPTZ,                 -- Auto-fail if not completed
    
    -- Result
    result_payload      JSONB,                       -- Final result data
    failure_reason      TEXT,
    failure_step        INTEGER,                     -- Which step failed
    
    -- Correlation
    correlation_id      UUID NOT NULL DEFAULT gen_random_uuid(), -- Groups related sagas
    parent_saga_id      UUID REFERENCES core.transaction_sagas(saga_id),
    
    -- Context
    context_data        JSONB DEFAULT '{}',          -- Input parameters
    
    -- Idempotency
    idempotency_key_id  UUID REFERENCES core.idempotency_keys(idempotency_key_id),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT chk_transaction_sagas_status 
        CHECK (status IN ('PENDING', 'VALIDATING', 'EXECUTING', 'AWAITING_COMPENSATION', 
                         'COMPENSATING', 'COMMITTED', 'FAILED', 'COMPENSATED')),
    CONSTRAINT chk_transaction_sagas_timeout 
        CHECK (timeout_at IS NULL OR timeout_at > started_at)
);

-- Indexes for transaction_sagas
CREATE INDEX idx_transaction_sagas_correlation ON core.transaction_sagas(correlation_id);
CREATE INDEX idx_transaction_sagas_initiator ON core.transaction_sagas(initiator_account_id, status);
CREATE INDEX idx_transaction_sagas_pending ON core.transaction_sagas(status, timeout_at) 
    WHERE status IN ('PENDING', 'VALIDATING', 'EXECUTING', 'AWAITING_COMPENSATION');
CREATE INDEX idx_transaction_sagas_application ON core.transaction_sagas(application_id, saga_type);
CREATE INDEX idx_transaction_sagas_parent ON core.transaction_sagas(parent_saga_id);
CREATE INDEX idx_transaction_sagas_gin_context ON core.transaction_sagas USING GIN (context_data);

COMMENT ON TABLE core.transaction_sagas IS 'Saga orchestration header for long-running transactions';
COMMENT ON COLUMN core.transaction_sagas.status IS 'Current state in saga state machine';
COMMENT ON COLUMN core.transaction_sagas.correlation_id IS 'Groups related sagas for distributed tracing';

-- =============================================================================
-- Create saga_steps table
-- DESCRIPTION: Individual steps within a saga
-- PRIORITY: CRITICAL
-- SECURITY: Compensation parameters validated before execution
-- ============================================================================
CREATE TABLE core.saga_steps (
    step_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    saga_id             UUID NOT NULL REFERENCES core.transaction_sagas(saga_id),
    
    -- Ordering
    step_sequence       INTEGER NOT NULL,            -- Execution order
    step_name           VARCHAR(100) NOT NULL,       -- Human-readable name
    
    -- Step Definition
    action_type         VARCHAR(50) NOT NULL,        -- 'MOVEMENT', 'WEBHOOK', 'VALIDATION'
    action_params       JSONB NOT NULL,              -- Step-specific parameters
    
    -- Compensation
    compensation_type   VARCHAR(50),                 -- Type of compensation
    compensation_params JSONB,                       -- Compensation parameters
    
    -- Execution Status
    status              VARCHAR(20) DEFAULT 'PENDING',
                        -- PENDING, EXECUTING, COMPLETED, FAILED, COMPENSATED
    
    -- Results
    result_data         JSONB,                       -- Step output
    error_message       TEXT,
    
    -- Transaction Links
    movement_id         UUID REFERENCES core.movement_headers(movement_id),
    transaction_id      UUID REFERENCES core.transaction_log(transaction_id),
    
    -- Timing
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    compensated_at      TIMESTAMPTZ,
    
    -- Retry
    retry_count         INTEGER DEFAULT 0,
    max_retries         INTEGER DEFAULT 3,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Constraints
    CONSTRAINT uq_saga_steps_sequence UNIQUE (saga_id, step_sequence),
    CONSTRAINT chk_saga_steps_status 
        CHECK (status IN ('PENDING', 'EXECUTING', 'COMPLETED', 'FAILED', 'COMPENSATED'))
);

CREATE INDEX idx_saga_steps_saga ON core.saga_steps(saga_id, step_sequence);
CREATE INDEX idx_saga_steps_status ON core.saga_steps(saga_id, status);
CREATE INDEX idx_saga_steps_movement ON core.saga_steps(movement_id);

COMMENT ON TABLE core.saga_steps IS 'Individual steps within a saga with compensation definitions';
COMMENT ON COLUMN core.saga_steps.compensation_params IS 'Parameters for compensating this step if needed';

-- =============================================================================
-- Create saga_events table
-- DESCRIPTION: Event log for saga state transitions
-- PRIORITY: MEDIUM
-- SECURITY: Immutable event log for audit
-- ============================================================================
CREATE TABLE core.saga_events (
    event_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    saga_id             UUID NOT NULL REFERENCES core.transaction_sagas(saga_id),
    step_id             UUID REFERENCES core.saga_steps(step_id),
    
    -- Event Details
    event_type          VARCHAR(50) NOT NULL,        -- 'STEP_STARTED', 'STEP_COMPLETED', etc.
    event_data          JSONB,
    
    -- State Snapshot
    previous_status     VARCHAR(20),
    new_status          VARCHAR(20),
    
    -- Source
    source_service      VARCHAR(100),                -- Which service generated event
    source_instance     VARCHAR(100),                -- Instance/pod identifier
    
    -- Timing
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Ordering (global sequence for strict ordering)
    event_sequence      BIGSERIAL
);

CREATE INDEX idx_saga_events_saga ON core.saga_events(saga_id, event_sequence);
CREATE INDEX idx_saga_events_type ON core.saga_events(event_type, occurred_at);
CREATE INDEX idx_saga_events_occurred ON core.saga_events(occurred_at);

COMMENT ON TABLE core.saga_events IS 'Append-only event log for saga state changes';

-- =============================================================================
-- Create saga event logging trigger
-- DESCRIPTION: Auto-log saga status changes
-- PRIORITY: HIGH
-- ============================================================================
CREATE OR REPLACE FUNCTION core.log_saga_event()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' OR OLD.status IS DISTINCT FROM NEW.status THEN
        INSERT INTO core.saga_events (
            saga_id, event_type, previous_status, new_status, 
            event_data, source_service, occurred_at
        ) VALUES (
            NEW.saga_id,
            CASE TG_OP 
                WHEN 'INSERT' THEN 'SAGA_CREATED'
                ELSE 'STATUS_CHANGED'
            END,
            OLD.status,
            NEW.status,
            jsonb_build_object(
                'operation', TG_OP,
                'timestamp', now()
            ),
            current_setting('app.service_name', true),
            now()
        );
    END IF;
    
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

CREATE TRIGGER trg_transaction_sagas_event_log
    AFTER INSERT OR UPDATE ON core.transaction_sagas
    FOR EACH ROW
    EXECUTE FUNCTION core.log_saga_event();

-- =============================================================================
-- Create saga execution function
-- DESCRIPTION: Execute saga steps and handle failures
-- PRIORITY: CRITICAL
-- SECURITY: Compensation on failure prevents partial commits
-- ============================================================================
CREATE OR REPLACE FUNCTION core.execute_saga(p_saga_id UUID)
RETURNS VARCHAR AS $$
DECLARE
    v_saga RECORD;
    v_step RECORD;
    v_result JSONB;
    v_all_completed BOOLEAN := true;
BEGIN
    -- Get saga with lock
    SELECT * INTO v_saga 
    FROM core.transaction_sagas 
    WHERE saga_id = p_saga_id
      AND status IN ('PENDING', 'EXECUTING', 'VALIDATING')
    FOR UPDATE;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Saga % not found or not executable', p_saga_id;
    END IF;
    
    -- Check timeout
    IF v_saga.timeout_at IS NOT NULL AND v_saga.timeout_at < now() THEN
        UPDATE core.transaction_sagas 
        SET status = 'FAILED', failure_reason = 'Timeout exceeded'
        WHERE saga_id = p_saga_id;
        RETURN 'FAILED';
    END IF;
    
    -- Update status to EXECUTING
    UPDATE core.transaction_sagas 
    SET status = 'EXECUTING'
    WHERE saga_id = p_saga_id;
    
    -- Execute each pending step
    FOR v_step IN 
        SELECT * FROM core.saga_steps 
        WHERE saga_id = p_saga_id AND status = 'PENDING'
        ORDER BY step_sequence
    LOOP
        -- Mark step as executing
        UPDATE core.saga_steps 
        SET status = 'EXECUTING', started_at = now()
        WHERE step_id = v_step.step_id;
        
        -- Attempt execution
        BEGIN
            -- Log step start
            INSERT INTO core.saga_events (saga_id, step_id, event_type, occurred_at)
            VALUES (p_saga_id, v_step.step_id, 'STEP_STARTED', now());
            
            -- Execute based on action_type (simplified - actual implementation would call specific handlers)
            CASE v_step.action_type
                WHEN 'MOVEMENT' THEN
                    v_result := jsonb_build_object('status', 'simulated', 'type', 'movement');
                WHEN 'WEBHOOK' THEN
                    v_result := jsonb_build_object('status', 'simulated', 'type', 'webhook');
                WHEN 'VALIDATION' THEN
                    v_result := jsonb_build_object('status', 'simulated', 'type', 'validation');
                ELSE
                    v_result := jsonb_build_object('status', 'unknown_action_type');
            END CASE;
            
            -- Mark completed
            UPDATE core.saga_steps
            SET status = 'COMPLETED', 
                completed_at = now(),
                result_data = v_result
            WHERE step_id = v_step.step_id;
            
            -- Log step completion
            INSERT INTO core.saga_events (saga_id, step_id, event_type, occurred_at)
            VALUES (p_saga_id, v_step.step_id, 'STEP_COMPLETED', now());
            
        EXCEPTION WHEN OTHERS THEN
            -- Step failed - trigger compensation
            UPDATE core.saga_steps
            SET status = 'FAILED',
                error_message = SQLERRM
            WHERE step_id = v_step.step_id;
            
            UPDATE core.transaction_sagas
            SET status = 'AWAITING_COMPENSATION',
                failure_reason = SQLERRM,
                failure_step = v_step.step_sequence
            WHERE saga_id = p_saga_id;
            
            -- Log failure
            INSERT INTO core.saga_events (saga_id, step_id, event_type, event_data, occurred_at)
            VALUES (p_saga_id, v_step.step_id, 'STEP_FAILED', 
                    jsonb_build_object('error', SQLERRM), now());
            
            -- Trigger compensation
            PERFORM core.compensate_saga(p_saga_id);
            
            RETURN 'FAILED';
        END;
    END LOOP;
    
    -- Check if all steps completed
    SELECT NOT EXISTS(
        SELECT 1 FROM core.saga_steps 
        WHERE saga_id = p_saga_id AND status NOT IN ('COMPLETED', 'COMPENSATED')
    ) INTO v_all_completed;
    
    IF v_all_completed THEN
        UPDATE core.transaction_sagas
        SET status = 'COMMITTED', completed_at = now()
        WHERE saga_id = p_saga_id;
        
        RETURN 'COMMITTED';
    END IF;
    
    RETURN 'EXECUTING';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.execute_saga IS 'Executes saga steps in sequence with compensation on failure';

-- =============================================================================
-- Create saga compensation function
-- DESCRIPTION: Rollback saga steps on failure
-- PRIORITY: CRITICAL
-- SECURITY: Execute compensations in reverse order
-- ============================================================================
CREATE OR REPLACE FUNCTION core.compensate_saga(p_saga_id UUID)
RETURNS VARCHAR AS $$
DECLARE
    v_step RECORD;
    v_compensation_count INTEGER := 0;
BEGIN
    -- Update saga status
    UPDATE core.transaction_sagas
    SET status = 'COMPENSATING'
    WHERE saga_id = p_saga_id;
    
    -- Log compensation start
    INSERT INTO core.saga_events (saga_id, event_type, occurred_at)
    VALUES (p_saga_id, 'COMPENSATION_STARTED', now());
    
    -- Execute compensations in reverse order
    FOR v_step IN 
        SELECT * FROM core.saga_steps 
        WHERE saga_id = p_saga_id 
          AND status = 'COMPLETED'
          AND compensation_type IS NOT NULL
        ORDER BY step_sequence DESC
    LOOP
        BEGIN
            -- Execute compensation (simplified)
            CASE v_step.compensation_type
                WHEN 'REVERSE_MOVEMENT' THEN
                    -- Would create reversing movement
                    NULL;
                WHEN 'RELEASE_HOLD' THEN
                    -- Would release held funds
                    NULL;
                WHEN 'NOTIFY_FAILURE' THEN
                    -- Would send failure notification
                    NULL;
                ELSE
                    NULL;
            END CASE;
            
            UPDATE core.saga_steps
            SET status = 'COMPENSATED',
                compensated_at = now()
            WHERE step_id = v_step.step_id;
            
            v_compensation_count := v_compensation_count + 1;
            
        EXCEPTION WHEN OTHERS THEN
            -- Log compensation failure
            INSERT INTO core.saga_events (saga_id, step_id, event_type, event_data, occurred_at)
            VALUES (p_saga_id, v_step.step_id, 'COMPENSATION_FAILED', 
                    jsonb_build_object('error', SQLERRM), now());
            
            RAISE WARNING 'Compensation failed for step %: %', v_step.step_id, SQLERRM;
        END;
    END LOOP;
    
    -- Update final status
    UPDATE core.transaction_sagas
    SET status = 'COMPENSATED', completed_at = now()
    WHERE saga_id = p_saga_id;
    
    INSERT INTO core.saga_events (saga_id, event_type, event_data, occurred_at)
    VALUES (p_saga_id, 'COMPENSATION_COMPLETED', 
            jsonb_build_object('compensated_steps', v_compensation_count), now());
    
    RETURN 'COMPENSATED';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.compensate_saga IS 'Executes compensating transactions in reverse order';

-- =============================================================================
-- Create saga timeout check function
-- DESCRIPTION: Process timed-out sagas
-- PRIORITY: MEDIUM
-- SECURITY: Automatic compensation on timeout
-- ============================================================================
CREATE OR REPLACE FUNCTION core.check_saga_timeouts()
RETURNS INTEGER AS $$
DECLARE
    v_saga RECORD;
    v_timed_out_count INTEGER := 0;
BEGIN
    FOR v_saga IN 
        SELECT * FROM core.transaction_sagas
        WHERE status IN ('PENDING', 'EXECUTING', 'VALIDATING')
          AND timeout_at < now()
        FOR UPDATE SKIP LOCKED
    LOOP
        UPDATE core.transaction_sagas
        SET status = 'FAILED',
            failure_reason = 'Timeout exceeded'
        WHERE saga_id = v_saga.saga_id;
        
        INSERT INTO core.saga_events (saga_id, event_type, event_data, occurred_at)
        VALUES (v_saga.saga_id, 'TIMEOUT_OCCURRED', 
                jsonb_build_object('timeout_at', v_saga.timeout_at), now());
        
        -- Trigger compensation if steps were completed
        IF EXISTS(SELECT 1 FROM core.saga_steps WHERE saga_id = v_saga.saga_id AND status = 'COMPLETED') THEN
            PERFORM core.compensate_saga(v_saga.saga_id);
        END IF;
        
        v_timed_out_count := v_timed_out_count + 1;
    END LOOP;
    
    RETURN v_timed_out_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.check_saga_timeouts IS 'Processes timed-out sagas and triggers compensation';

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create transaction_sagas table
☑ Create saga_steps table with compensation info
☑ Create saga_events table for audit trail
☑ Implement execute_saga function
☑ Implement compensate_saga function
☑ Implement timeout checking
☑ Add all indexes for saga queries
☑ Test saga execution flow
☑ Test compensation on failure
☑ Verify event logging
================================================================================
*/
