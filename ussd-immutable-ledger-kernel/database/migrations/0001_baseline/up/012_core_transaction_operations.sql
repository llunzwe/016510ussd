-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Operation controls)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Operation isolation)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Operation data handling)
-- ISO/IEC 27040:2024 - Storage Security (Operation integrity)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Operation retry)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Operation templates for reusability
-- - Dependency graph resolution
-- - Timeout and retry logic
-- - Compensation operation definitions
-- ============================================================================
-- =============================================================================
-- MIGRATION: 012_core_transaction_operations.sql
-- DESCRIPTION: Transaction Operations - Individual Processing Steps
-- TABLES: transaction_operations, operation_templates
-- DEPENDENCIES: 011_core_transaction_sagas.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 4. Transaction Processing & Lifecycle
- Feature: Transaction Operations
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Individual steps within a transaction/saga with their own status tracking.
Each operation targets a specific entity and has defined compensation logic.
Supports complex multi-step workflows like loan approval processes.

KEY FEATURES:
- Operation templates for reusability
- Status tracking per operation
- Compensation operation definitions
- Target entity linking
- Progress tracking and retry logic
- Parallel vs sequential execution modes

OPERATION TYPES:
- VALIDATE: Check preconditions
- HOLD: Reserve funds
- MOVE: Transfer value
- RELEASE: Release held funds
- NOTIFY: Send notification
- WEBHOOK: Call external service
- APPROVE: Manual approval step
================================================================================
*/

-- =============================================================================
-- TODO: Create operation_templates table
-- DESCRIPTION: Reusable operation definitions
-- PRIORITY: HIGH
-- SECURITY: JSON schema validation for parameters
-- ============================================================================
-- TODO: [OP-001] Create core.operation_templates table
-- INSTRUCTIONS:
--   - Pre-defined operations that can be instantiated
--   - Defines default parameters and validation rules
--   - Versioned for backward compatibility
--   - ERROR HANDLING: Validate param_schema is valid JSON Schema
-- COMPLIANCE: ISO/IEC 27001 (Standardization)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.operation_templates (
--       template_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       template_code       VARCHAR(50) UNIQUE NOT NULL,
--       template_name       VARCHAR(100) NOT NULL,
--       description         TEXT,
--       
--       -- Classification
--       operation_type      VARCHAR(50) NOT NULL,        -- VALIDATE, HOLD, MOVE, etc.
--       category            VARCHAR(50),                 -- FINANCIAL, NOTIFICATION, etc.
--       
--       -- Default Configuration
--       default_params      JSONB DEFAULT '{}',
--       param_schema        JSONB,                       -- JSON Schema for validation
--       
--       -- Execution
--       is_async            BOOLEAN DEFAULT false,       -- Execute asynchronously
--       timeout_seconds     INTEGER DEFAULT 30,
--       max_retries         INTEGER DEFAULT 3,
--       retry_delay_seconds INTEGER DEFAULT 5,
--       
--       -- Compensation
--       compensation_template_id UUID REFERENCES core.operation_templates(template_id),
--       
--       -- Target Entity
--       target_entity_type  VARCHAR(50),                 -- ACCOUNT, MOVEMENT, etc.
--       
--       -- Scope
--       application_id      UUID REFERENCES app.applications(application_id), -- NULL = global
--       
--       -- Status
--       is_active           BOOLEAN DEFAULT true,
--       version             INTEGER DEFAULT 1,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id)
--   );

-- =============================================================================
-- TODO: Create transaction_operations table
-- DESCRIPTION: Operation instances
-- PRIORITY: CRITICAL
-- SECURITY: Dependency validation prevents deadlocks
-- ============================================================================
-- TODO: [OP-002] Create core.transaction_operations table
-- INSTRUCTIONS:
--   - Individual operation instances
--   - Links to sagas or standalone transactions
--   - Full status lifecycle tracking
--   - RLS POLICY: Tenant isolation
--   - ERROR HANDLING: Validate dependencies form DAG (no cycles)
-- COMPLIANCE: ISO/IEC 27040 (Dependency Integrity)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.transaction_operations (
--       operation_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       operation_reference VARCHAR(100) UNIQUE NOT NULL,
--       
--       -- Template Link
--       template_id         UUID REFERENCES core.operation_templates(template_id),
--       
--       -- Parent Context
--       saga_id             UUID REFERENCES core.transaction_sagas(saga_id),
--       step_id             UUID REFERENCES core.saga_steps(step_id),
--       transaction_id      UUID REFERENCES core.transaction_log(transaction_id),
--       
--       -- Operation Details
--       operation_type      VARCHAR(50) NOT NULL,
--       operation_params    JSONB NOT NULL,
--       
--       -- Target Entity
--       target_entity_type  VARCHAR(50),
--       target_entity_id    UUID,
--       
--       -- Status Workflow
--       status              VARCHAR(20) DEFAULT 'PENDING',
--                           -- PENDING, QUEUED, EXECUTING, COMPLETED, FAILED, CANCELLED
--       
--       -- Execution
--       execution_mode      VARCHAR(20) DEFAULT 'SEQUENTIAL', -- SEQUENTIAL, PARALLEL
--       priority            INTEGER DEFAULT 0,
--       
--       -- Results
--       result_data         JSONB,
--       error_code          VARCHAR(50),
--       error_message       TEXT,
--       
--       -- Timing
--       queued_at           TIMESTAMPTZ,
--       started_at          TIMESTAMPTZ,
--       completed_at        TIMESTAMPTZ,
--       timeout_at          TIMESTAMPTZ,
--       
--       -- Retry
--       retry_count         INTEGER DEFAULT 0,
--       next_retry_at       TIMESTAMPTZ,
--       
--       -- Compensation
--       compensation_of     UUID REFERENCES core.transaction_operations(operation_id),
--       compensated_by      UUID REFERENCES core.transaction_operations(operation_id),
--       
--       -- Correlation
--       correlation_id      UUID,
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
-- TODO: Create operation_dependencies table
-- DESCRIPTION: Define operation execution order
-- PRIORITY: MEDIUM
-- SECURITY: Detect circular dependencies
-- ============================================================================
-- TODO: [OP-003] Create core.operation_dependencies table
-- INSTRUCTIONS:
--   - Define which operations must complete before others start
--   - Supports complex dependency graphs
--   - Detects circular dependencies
--   - ERROR HANDLING: Validate no circular dependencies exist
-- COMPLIANCE: ISO/IEC 27031 (Dependency Management)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.operation_dependencies (
--       dependency_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Operations
--       operation_id        UUID NOT NULL REFERENCES core.transaction_operations(operation_id),
--       depends_on_id       UUID NOT NULL REFERENCES core.transaction_operations(operation_id),
--       
--       -- Dependency Type
--       dependency_type     VARCHAR(20) DEFAULT 'REQUIRED', -- REQUIRED, OPTIONAL
--       
--       -- Condition
--       condition           VARCHAR(20) DEFAULT 'COMPLETED', -- COMPLETED, SUCCESS, FAILURE
--       
--       UNIQUE (operation_id, depends_on_id)
--   );

-- =============================================================================
-- TODO: Create operation execution function
-- DESCRIPTION: Execute a single operation
-- PRIORITY: CRITICAL
-- SECURITY: Timeout enforcement prevents hung operations
-- ============================================================================
-- TODO: [OP-004] Create execute_operation function
-- INSTRUCTIONS:
--   - Execute operation based on type
--   - Handle timeouts and retries
--   - Record results
--   - Trigger compensation on failure
--   - ERROR HANDLING: Exception block with SQLSTATE capture
--   - SEARCH PATH: Explicitly set
-- COMPLIANCE: ISO/IEC 27031 (Execution Control)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.execute_operation(p_operation_id UUID)
--   RETURNS VARCHAR AS $$
--   DECLARE
--       v_op RECORD;
--       v_start_time TIMESTAMPTZ;
--   BEGIN
--       SELECT * INTO v_op FROM core.transaction_operations WHERE operation_id = p_operation_id;
--       
--       -- Check dependencies
--       IF EXISTS (
--           SELECT 1 FROM core.operation_dependencies od
--           WHERE od.operation_id = p_operation_id
--             AND od.dependency_type = 'REQUIRED'
--             AND NOT EXISTS (
--                 SELECT 1 FROM core.transaction_operations dep
--                 WHERE dep.operation_id = od.depends_on_id
--                   AND dep.status = od.condition
--             )
--       ) THEN
--           RETURN 'BLOCKED';
--       END IF;
--       
--       -- Mark as executing
--       UPDATE core.transaction_operations
--       SET status = 'EXECUTING', started_at = now()
--       WHERE operation_id = p_operation_id;
--       
--       v_start_time := clock_timestamp();
--       
--       -- Execute based on type
--       BEGIN
--           CASE v_op.operation_type
--               WHEN 'VALIDATE' THEN
--                   PERFORM core.exec_validate_operation(v_op.operation_params);
--               WHEN 'HOLD' THEN
--                   PERFORM core.exec_hold_operation(v_op.operation_params);
--               WHEN 'MOVE' THEN
--                   PERFORM core.exec_move_operation(v_op.operation_params);
--               WHEN 'NOTIFY' THEN
--                   PERFORM core.exec_notify_operation(v_op.operation_params);
--               WHEN 'WEBHOOK' THEN
--                   PERFORM core.exec_webhook_operation(v_op.operation_params);
--               ELSE
--                   RAISE EXCEPTION 'Unknown operation type: %', v_op.operation_type;
--           END CASE;
--           
--           -- Mark completed
--           UPDATE core.transaction_operations
--           SET status = 'COMPLETED', completed_at = now()
--           WHERE operation_id = p_operation_id;
--           
--           RETURN 'COMPLETED';
--           
--       EXCEPTION WHEN OTHERS THEN
--           -- Handle failure
--           UPDATE core.transaction_operations
--           SET status = 'FAILED', 
--               error_code = SQLSTATE,
--               error_message = SQLERRM,
--               retry_count = retry_count + 1
--           WHERE operation_id = p_operation_id;
--           
--           RETURN 'FAILED';
--       END;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create operation queue function
-- DESCRIPTION: Queue operations for execution
-- PRIORITY: HIGH
-- SECURITY: Priority-based queue prevents starvation
-- ============================================================================
-- TODO: [OP-005] Create queue_operations function
-- INSTRUCTIONS:
--   - Add operations to execution queue
--   - Respect priority and dependencies
--   - Support bulk queuing
--   - ERROR HANDLING: Validate all operations before queueing
-- COMPLIANCE: ISO/IEC 27031 (Queue Management)

-- =============================================================================
-- TODO: Create operation indexes
-- DESCRIPTION: Optimize operation queries
-- PRIORITY: HIGH
-- SECURITY: Index on status for queue polling
-- ============================================================================
-- TODO: [OP-006] Create operation indexes
-- INDEX LIST:
--   - PRIMARY KEY (operation_id)
--   - UNIQUE (operation_reference)
--   - INDEX on (saga_id, status)
--   - INDEX on (transaction_id)
--   - INDEX on (status, priority, queued_at) WHERE status = 'QUEUED'
--   - INDEX on (status, next_retry_at) WHERE status = 'FAILED'
--   - INDEX on (correlation_id)
--   - INDEX on (target_entity_type, target_entity_id)
--   - INDEX on (application_id, operation_type)
--   -- Dependencies:
--   - INDEX on (operation_id)
--   - INDEX on (depends_on_id)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create operation_templates table with reusable definitions
□ Create transaction_operations table for instances
□ Create operation_dependencies table
□ Implement execute_operation function
□ Implement queue_operations function
□ Add dependency checking logic
□ Create all indexes for operation queries
□ Test operation execution flow
□ Test dependency resolution
□ Verify retry logic
================================================================================
*/
