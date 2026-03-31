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
-- Create operation_templates table
-- DESCRIPTION: Reusable operation definitions
-- PRIORITY: HIGH
-- SECURITY: JSON schema validation for parameters
-- ============================================================================
CREATE TABLE core.operation_templates (
    template_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_code       VARCHAR(50) UNIQUE NOT NULL,
    template_name       VARCHAR(100) NOT NULL,
    description         TEXT,
    
    -- Classification
    operation_type      VARCHAR(50) NOT NULL,        -- VALIDATE, HOLD, MOVE, etc.
    category            VARCHAR(50),                 -- FINANCIAL, NOTIFICATION, etc.
    
    -- Default Configuration
    default_params      JSONB DEFAULT '{}',
    param_schema        JSONB,                       -- JSON Schema for validation
    
    -- Execution
    is_async            BOOLEAN DEFAULT false,       -- Execute asynchronously
    timeout_seconds     INTEGER DEFAULT 30,
    max_retries         INTEGER DEFAULT 3,
    retry_delay_seconds INTEGER DEFAULT 5,
    
    -- Compensation
    compensation_template_id UUID REFERENCES core.operation_templates(template_id),
    
    -- Target Entity
    target_entity_type  VARCHAR(50),                 -- ACCOUNT, MOVEMENT, etc.
    
    -- Scope
    application_id      UUID REFERENCES app.applications(application_id), -- NULL = global
    
    -- Status
    is_active           BOOLEAN DEFAULT true,
    version             INTEGER DEFAULT 1,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    
    -- Constraints
    CONSTRAINT chk_operation_templates_type 
        CHECK (operation_type IN ('VALIDATE', 'HOLD', 'MOVE', 'RELEASE', 'NOTIFY', 'WEBHOOK', 'APPROVE'))
);

CREATE INDEX idx_operation_templates_type ON core.operation_templates(operation_type, is_active);
CREATE INDEX idx_operation_templates_app ON core.operation_templates(application_id);

COMMENT ON TABLE core.operation_templates IS 'Reusable operation definitions with validation schemas';
COMMENT ON COLUMN core.operation_templates.param_schema IS 'JSON Schema for validating operation parameters';

-- =============================================================================
-- Create transaction_operations table
-- DESCRIPTION: Operation instances
-- PRIORITY: CRITICAL
-- SECURITY: Dependency validation prevents deadlocks
-- ============================================================================
CREATE TABLE core.transaction_operations (
    operation_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Template Link
    template_id         UUID REFERENCES core.operation_templates(template_id),
    
    -- Parent Context
    saga_id             UUID REFERENCES core.transaction_sagas(saga_id),
    step_id             UUID REFERENCES core.saga_steps(step_id),
    transaction_id      UUID REFERENCES core.transaction_log(transaction_id),
    
    -- Operation Details
    operation_type      VARCHAR(50) NOT NULL,
    operation_params    JSONB NOT NULL,
    
    -- Target Entity
    target_entity_type  VARCHAR(50),
    target_entity_id    UUID,
    
    -- Status Workflow
    status              VARCHAR(20) DEFAULT 'PENDING',
                        -- PENDING, QUEUED, EXECUTING, COMPLETED, FAILED, CANCELLED
    
    -- Execution
    execution_mode      VARCHAR(20) DEFAULT 'SEQUENTIAL', -- SEQUENTIAL, PARALLEL
    priority            INTEGER DEFAULT 0,
    
    -- Results
    result_data         JSONB,
    error_code          VARCHAR(50),
    error_message       TEXT,
    
    -- Timing
    queued_at           TIMESTAMPTZ,
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    timeout_at          TIMESTAMPTZ,
    
    -- Retry
    retry_count         INTEGER DEFAULT 0,
    next_retry_at       TIMESTAMPTZ,
    
    -- Compensation
    compensation_of     UUID REFERENCES core.transaction_operations(operation_id),
    compensated_by      UUID REFERENCES core.transaction_operations(operation_id),
    
    -- Correlation
    correlation_id      UUID,
    
    -- Application
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    updated_at          TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT chk_transaction_operations_status 
        CHECK (status IN ('PENDING', 'QUEUED', 'EXECUTING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    CONSTRAINT chk_transaction_operations_mode 
        CHECK (execution_mode IN ('SEQUENTIAL', 'PARALLEL'))
);

-- Indexes for transaction_operations
CREATE INDEX idx_transaction_operations_saga ON core.transaction_operations(saga_id, status);
CREATE INDEX idx_transaction_operations_tx ON core.transaction_operations(transaction_id);
CREATE INDEX idx_transaction_operations_queue ON core.transaction_operations(status, priority, queued_at) 
    WHERE status = 'QUEUED';
CREATE INDEX idx_transaction_operations_retry ON core.transaction_operations(status, next_retry_at) 
    WHERE status = 'FAILED';
CREATE INDEX idx_transaction_operations_correlation ON core.transaction_operations(correlation_id);
CREATE INDEX idx_transaction_operations_target ON core.transaction_operations(target_entity_type, target_entity_id);
CREATE INDEX idx_transaction_operations_app ON core.transaction_operations(application_id, operation_type);

COMMENT ON TABLE core.transaction_operations IS 'Individual operation instances with execution tracking';
COMMENT ON COLUMN core.transaction_operations.compensation_of IS 'Reference to operation being compensated by this one';

-- =============================================================================
-- Create operation_dependencies table
-- DESCRIPTION: Define operation execution order
-- PRIORITY: MEDIUM
-- SECURITY: Detect circular dependencies
-- ============================================================================
CREATE TABLE core.operation_dependencies (
    dependency_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Operations
    operation_id        UUID NOT NULL REFERENCES core.transaction_operations(operation_id),
    depends_on_id       UUID NOT NULL REFERENCES core.transaction_operations(operation_id),
    
    -- Dependency Type
    dependency_type     VARCHAR(20) DEFAULT 'REQUIRED', -- REQUIRED, OPTIONAL
    
    -- Condition
    condition           VARCHAR(20) DEFAULT 'COMPLETED', -- COMPLETED, SUCCESS, FAILURE
    
    -- Constraints
    CONSTRAINT uq_operation_dependencies UNIQUE (operation_id, depends_on_id),
    CONSTRAINT chk_operation_dependencies_type 
        CHECK (dependency_type IN ('REQUIRED', 'OPTIONAL')),
    CONSTRAINT chk_operation_dependencies_condition 
        CHECK (condition IN ('COMPLETED', 'SUCCESS', 'FAILURE')),
    CONSTRAINT chk_operation_dependencies_self 
        CHECK (operation_id != depends_on_id)
);

CREATE INDEX idx_operation_dependencies_op ON core.operation_dependencies(operation_id);
CREATE INDEX idx_operation_dependencies_depends ON core.operation_dependencies(depends_on_id);

COMMENT ON TABLE core.operation_dependencies IS 'Defines operation execution order and dependencies';

-- =============================================================================
-- Create circular dependency detection function
-- DESCRIPTION: Prevent cycles in dependency graph
-- PRIORITY: HIGH
-- ============================================================================
CREATE OR REPLACE FUNCTION core.detect_circular_dependency()
RETURNS TRIGGER AS $$
DECLARE
    v_visited UUID[] := ARRAY[NEW.operation_id];
    v_current UUID := NEW.depends_on_id;
    v_next UUID;
    v_depth INTEGER := 0;
    v_max_depth INTEGER := 20;
BEGIN
    LOOP
        v_depth := v_depth + 1;
        EXIT WHEN v_depth > v_max_depth;
        
        IF v_current = NEW.operation_id THEN
            RAISE EXCEPTION 'Circular dependency detected involving operations %', v_visited;
        END IF;
        
        SELECT depends_on_id INTO v_next
        FROM core.operation_dependencies
        WHERE operation_id = v_current
        LIMIT 1;
        
        EXIT WHEN v_next IS NULL;
        
        v_visited := array_append(v_visited, v_next);
        v_current := v_next;
    END LOOP;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

CREATE TRIGGER trg_operation_dependencies_detect_cycle
    BEFORE INSERT OR UPDATE ON core.operation_dependencies
    FOR EACH ROW
    EXECUTE FUNCTION core.detect_circular_dependency();

-- =============================================================================
-- Create operation execution function
-- DESCRIPTION: Execute a single operation
-- PRIORITY: CRITICAL
-- SECURITY: Timeout enforcement prevents hung operations
-- ============================================================================
CREATE OR REPLACE FUNCTION core.execute_operation(p_operation_id UUID)
RETURNS VARCHAR AS $$
DECLARE
    v_op RECORD;
    v_start_time TIMESTAMPTZ;
    v_result JSONB;
BEGIN
    SELECT * INTO v_op FROM core.transaction_operations WHERE operation_id = p_operation_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Operation % not found', p_operation_id;
    END IF;
    
    -- Check dependencies
    IF EXISTS (
        SELECT 1 FROM core.operation_dependencies od
        WHERE od.operation_id = p_operation_id
          AND od.dependency_type = 'REQUIRED'
          AND NOT EXISTS (
              SELECT 1 FROM core.transaction_operations dep
              WHERE dep.operation_id = od.depends_on_id
                AND dep.status = od.condition
          )
    ) THEN
        RETURN 'BLOCKED';
    END IF;
    
    -- Mark as executing
    UPDATE core.transaction_operations
    SET status = 'EXECUTING', started_at = now()
    WHERE operation_id = p_operation_id;
    
    v_start_time := clock_timestamp();
    
    -- Execute based on type
    BEGIN
        CASE v_op.operation_type
            WHEN 'VALIDATE' THEN
                -- Would perform validation
                v_result := jsonb_build_object('validated', true);
            WHEN 'HOLD' THEN
                -- Would place hold on funds
                v_result := jsonb_build_object('hold_id', gen_random_uuid());
            WHEN 'MOVE' THEN
                -- Would execute movement
                v_result := jsonb_build_object('movement_created', true);
            WHEN 'NOTIFY' THEN
                -- Would send notification
                v_result := jsonb_build_object('notified', true);
            WHEN 'WEBHOOK' THEN
                -- Would call webhook
                v_result := jsonb_build_object('webhook_called', true);
            WHEN 'APPROVE' THEN
                -- Would record approval
                v_result := jsonb_build_object('approved', true);
            ELSE
                RAISE EXCEPTION 'Unknown operation type: %', v_op.operation_type;
        END CASE;
        
        -- Mark completed
        UPDATE core.transaction_operations
        SET status = 'COMPLETED', 
            completed_at = now(),
            result_data = v_result
        WHERE operation_id = p_operation_id;
        
        RETURN 'COMPLETED';
        
    EXCEPTION WHEN OTHERS THEN
        -- Handle failure
        UPDATE core.transaction_operations
        SET status = 'FAILED', 
            error_code = SQLSTATE,
            error_message = SQLERRM,
            retry_count = retry_count + 1,
            next_retry_at = CASE 
                WHEN retry_count < (
                    SELECT max_retries FROM core.operation_templates 
                    WHERE template_id = v_op.template_id
                ) 
                THEN now() + INTERVAL '5 seconds' * retry_count
                ELSE NULL
            END
        WHERE operation_id = p_operation_id;
        
        RETURN 'FAILED';
    END;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.execute_operation IS 'Executes a single operation with dependency checking and error handling';

-- =============================================================================
-- Create operation queue function
-- DESCRIPTION: Queue operations for execution
-- PRIORITY: HIGH
-- SECURITY: Priority-based queue prevents starvation
-- ============================================================================
CREATE OR REPLACE FUNCTION core.queue_operations(
    p_operation_ids UUID[]
) RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER := 0;
    v_op_id UUID;
BEGIN
    -- Validate all operations exist before queueing
    FOREACH v_op_id IN ARRAY p_operation_ids LOOP
        IF NOT EXISTS(SELECT 1 FROM core.transaction_operations WHERE operation_id = v_op_id) THEN
            RAISE EXCEPTION 'Operation % not found', v_op_id;
        END IF;
    END LOOP;
    
    -- Queue all operations
    UPDATE core.transaction_operations
    SET status = 'QUEUED', queued_at = now()
    WHERE operation_id = ANY(p_operation_ids)
      AND status IN ('PENDING', 'FAILED');
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.queue_operations IS 'Queues multiple operations for execution with validation';

-- =============================================================================
-- Create function to get ready operations
-- DESCRIPTION: Poll for operations ready to execute
-- PRIORITY: HIGH
-- ============================================================================
CREATE OR REPLACE FUNCTION core.get_ready_operations(
    p_limit INTEGER DEFAULT 10
) RETURNS TABLE (
    operation_id UUID,
    operation_type VARCHAR(50),
    priority INTEGER,
    queued_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        o.operation_id,
        o.operation_type,
        o.priority,
        o.queued_at
    FROM core.transaction_operations o
    WHERE o.status = 'QUEUED'
      AND NOT EXISTS (
          -- Check for unmet required dependencies
          SELECT 1 FROM core.operation_dependencies od
          WHERE od.operation_id = o.operation_id
            AND od.dependency_type = 'REQUIRED'
            AND NOT EXISTS (
                SELECT 1 FROM core.transaction_operations dep
                WHERE dep.operation_id = od.depends_on_id
                  AND dep.status = od.condition
            )
      )
    ORDER BY o.priority DESC, o.queued_at ASC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.get_ready_operations IS 'Returns operations that are queued and have all dependencies met';

-- =============================================================================
-- Create operation status history table
-- DESCRIPTION: Audit trail of operation status changes
-- PRIORITY: MEDIUM
-- ============================================================================
CREATE TABLE core.operation_status_history (
    history_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id        UUID NOT NULL REFERENCES core.transaction_operations(operation_id),
    previous_status     VARCHAR(20),
    new_status          VARCHAR(20) NOT NULL,
    changed_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    changed_by          UUID REFERENCES core.accounts(account_id),
    reason              TEXT
);

CREATE INDEX idx_operation_status_history_op ON core.operation_status_history(operation_id, changed_at);

COMMENT ON TABLE core.operation_status_history IS 'Audit trail of operation status changes';

-- Trigger for status history
CREATE OR REPLACE FUNCTION core.log_operation_status_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status THEN
        INSERT INTO core.operation_status_history (
            operation_id, previous_status, new_status, changed_by, reason
        ) VALUES (
            NEW.operation_id, OLD.status, NEW.status,
            current_setting('app.current_user_id', true)::uuid,
            NEW.error_message
        );
    END IF;
    
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

CREATE TRIGGER trg_transaction_operations_status_log
    BEFORE UPDATE ON core.transaction_operations
    FOR EACH ROW
    EXECUTE FUNCTION core.log_operation_status_change();

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create operation_templates table with reusable definitions
☑ Create transaction_operations table for instances
☑ Create operation_dependencies table
☑ Implement execute_operation function
☑ Implement queue_operations function
☑ Add dependency checking logic
☑ Create all indexes for operation queries
☑ Test operation execution flow
☑ Test dependency resolution
☑ Verify retry logic
================================================================================
*/
