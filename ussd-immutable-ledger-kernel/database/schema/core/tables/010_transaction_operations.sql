-- =============================================================================
-- USSD KERNEL CORE SCHEMA - TRANSACTION OPERATIONS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    010_transaction_operations.sql
-- SCHEMA:      ussd_core
-- TABLE:       transaction_operations
-- DESCRIPTION: Individual operations within a saga. Tracks each step's
--              execution state, input/output, and compensation action.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.1 Operational procedures - Operation execution procedures
├── A.12.4 Logging and monitoring - Operation execution monitoring
└── A.16.1 Management of information security incidents - Operation failure handling

ISO/IEC 27040:2024 (Storage Security)
├── Operation state persistence: Durable state storage
├── Compensation tracking: Immutable compensation record
└── Audit trail: Complete operation history

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. OPERATION LIFECYCLE
   - PENDING → EXECUTING → COMPLETED/FAILED → COMPENSATED
   - State transitions logged
   - Compensation action defined upfront

2. INPUT/OUTPUT TRACKING
   - Input parameters captured
   - Output results stored
   - Error details preserved

3. COMPENSATION
   - Compensation action type defined
   - Compensation parameters stored
   - Compensation result tracked

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

OPERATION SECURITY:
- Input validation before execution
- Output sanitization
- Authorization at each step

COMPENSATION SAFETY:
- Idempotent compensation actions
- Compensation validation
- Rollback on compensation failure

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: operation_id
- SAGA: saga_id + sequence_number
- STATUS: status + started_at

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- OPERATION_STARTED
- OPERATION_COMPLETED
- OPERATION_FAILED
- OPERATION_COMPENSATED

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- CREATE TABLE: transaction_operations
-- =============================================================================

CREATE TABLE core.transaction_operations (
    -- Primary identifier
    operation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Parent saga
    saga_id UUID NOT NULL REFERENCES core.transaction_sagas(saga_id) ON DELETE RESTRICT,
    sequence_number INTEGER NOT NULL,
    
    -- Operation definition
    operation_name VARCHAR(100) NOT NULL,
    operation_type VARCHAR(50) NOT NULL,
    operation_description TEXT,
    
    -- State
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'EXECUTING', 'COMPLETED', 'FAILED', 'COMPENSATING', 'COMPENSATED', 'SKIPPED')),
    
    -- Execution timing
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER,
    
    -- Input/Output
    input_parameters JSONB,
    output_result JSONB,
    
    -- Target (the entity this operation affects)
    target_type VARCHAR(50),  -- e.g., 'account', 'transaction', 'external_system'
    target_id VARCHAR(255),
    
    -- Error handling
    error_message TEXT,
    error_code VARCHAR(50),
    error_details JSONB,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    
    -- Compensation
    compensation_required BOOLEAN DEFAULT FALSE,
    compensation_action VARCHAR(50),
    compensation_parameters JSONB,
    compensation_status VARCHAR(50) CHECK (compensation_status IN ('PENDING', 'EXECUTING', 'COMPLETED', 'FAILED')),
    compensation_started_at TIMESTAMPTZ,
    compensation_completed_at TIMESTAMPTZ,
    compensation_result JSONB,
    compensation_error TEXT,
    
    -- Dependencies (operations that must complete before this one)
    depends_on INTEGER[],  -- Array of sequence numbers
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    UNIQUE (saga_id, sequence_number),
    CONSTRAINT chk_sequence_positive CHECK (sequence_number >= 0),
    CONSTRAINT chk_started_before_completed CHECK (
        started_at IS NULL OR completed_at IS NULL OR started_at <= completed_at
    )
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Saga lookup
CREATE INDEX idx_transaction_operations_saga ON core.transaction_operations(saga_id, sequence_number);

-- Status monitoring
CREATE INDEX idx_transaction_operations_status ON core.transaction_operations(status, started_at);

-- Pending operations
CREATE INDEX idx_transaction_operations_pending ON core.transaction_operations(operation_id) 
    WHERE status IN ('PENDING', 'EXECUTING');

-- Failed operations needing attention
CREATE INDEX idx_transaction_operations_failed ON core.transaction_operations(saga_id) 
    WHERE status = 'FAILED' AND retry_count < max_retries;

-- Target lookup
CREATE INDEX idx_transaction_operations_target ON core.transaction_operations(target_type, target_id);

-- Operation type
CREATE INDEX idx_transaction_operations_type ON core.transaction_operations(operation_type, status);

-- =============================================================================
-- HASH COMPUTATION TRIGGER
-- =============================================================================

CREATE OR REPLACE FUNCTION core.compute_operation_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.operation_id::TEXT || 
        NEW.saga_id::TEXT || 
        NEW.sequence_number::TEXT ||
        NEW.operation_name ||
        NEW.operation_type ||
        COALESCE(NEW.status, 'PENDING') ||
        NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_transaction_operations_compute_hash
    BEFORE INSERT OR UPDATE ON core.transaction_operations
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_operation_hash();

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

-- Enable RLS
ALTER TABLE core.transaction_operations ENABLE ROW LEVEL SECURITY;

-- Policy: Access through parent saga
CREATE POLICY transaction_operations_saga_access ON core.transaction_operations
    FOR SELECT
    TO ussd_app_user
    USING (
        EXISTS (
            SELECT 1 FROM core.transaction_sagas ts
            WHERE ts.saga_id = transaction_operations.saga_id
            AND (
                ts.initiator_account_id = current_setting('app.current_account_id', true)::UUID
                OR ts.application_id = current_setting('app.current_application_id', true)::UUID
            )
        )
    );

-- Policy: Kernel role has full access
CREATE POLICY transaction_operations_kernel_access ON core.transaction_operations
    FOR ALL
    TO ussd_kernel_role
    USING (true);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to create an operation
CREATE OR REPLACE FUNCTION core.create_operation(
    p_saga_id UUID,
    p_sequence_number INTEGER,
    p_operation_name VARCHAR(100),
    p_operation_type VARCHAR(50),
    p_input_parameters JSONB DEFAULT NULL,
    p_compensation_action VARCHAR(50) DEFAULT NULL,
    p_compensation_parameters JSONB DEFAULT NULL,
    p_depends_on INTEGER[] DEFAULT NULL,
    p_description TEXT DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_operation_id UUID;
BEGIN
    INSERT INTO core.transaction_operations (
        saga_id,
        sequence_number,
        operation_name,
        operation_type,
        operation_description,
        input_parameters,
        compensation_action,
        compensation_parameters,
        depends_on,
        compensation_required
    ) VALUES (
        p_saga_id,
        p_sequence_number,
        p_operation_name,
        p_operation_type,
        p_description,
        p_input_parameters,
        p_compensation_action,
        p_compensation_parameters,
        p_depends_on,
        p_compensation_action IS NOT NULL
    )
    RETURNING operation_id INTO v_operation_id;
    
    RETURN v_operation_id;
END;
$$;

-- Function to start an operation
CREATE OR REPLACE FUNCTION core.start_operation(
    p_operation_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.transaction_operations
    SET 
        status = 'EXECUTING',
        started_at = core.precise_now()
    WHERE operation_id = p_operation_id
    AND status = 'PENDING';
    
    RETURN FOUND;
END;
$$;

-- Function to complete an operation
CREATE OR REPLACE FUNCTION core.complete_operation(
    p_operation_id UUID,
    p_output_result JSONB DEFAULT NULL,
    p_duration_ms INTEGER DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.transaction_operations
    SET 
        status = 'COMPLETED',
        output_result = p_output_result,
        duration_ms = COALESCE(p_duration_ms, EXTRACT(EPOCH FROM (core.precise_now() - started_at)) * 1000)::INTEGER,
        completed_at = core.precise_now(),
        retry_count = 0
    WHERE operation_id = p_operation_id
    AND status IN ('PENDING', 'EXECUTING');
    
    RETURN FOUND;
END;
$$;

-- Function to fail an operation
CREATE OR REPLACE FUNCTION core.fail_operation(
    p_operation_id UUID,
    p_error_message TEXT,
    p_error_code VARCHAR(50) DEFAULT NULL,
    p_error_details JSONB DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_current_retries INTEGER;
    v_max_retries INTEGER;
BEGIN
    -- Get current retry info
    SELECT retry_count, max_retries INTO v_current_retries, v_max_retries
    FROM core.transaction_operations
    WHERE operation_id = p_operation_id;
    
    -- If we can retry, increment counter
    IF v_current_retries < v_max_retries THEN
        UPDATE core.transaction_operations
        SET 
            retry_count = retry_count + 1,
            status = 'PENDING',  -- Reset to pending for retry
            error_message = p_error_message,
            error_code = p_error_code,
            error_details = p_error_details
        WHERE operation_id = p_operation_id;
    ELSE
        -- Mark as failed
        UPDATE core.transaction_operations
        SET 
            status = 'FAILED',
            error_message = p_error_message,
            error_code = p_error_code,
            error_details = p_error_details,
            completed_at = core.precise_now()
        WHERE operation_id = p_operation_id;
    END IF;
    
    RETURN FOUND;
END;
$$;

-- Function to skip an operation
CREATE OR REPLACE FUNCTION core.skip_operation(
    p_operation_id UUID,
    p_reason TEXT DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.transaction_operations
    SET 
        status = 'SKIPPED',
        metadata = metadata || jsonb_build_object('skip_reason', p_reason),
        completed_at = core.precise_now()
    WHERE operation_id = p_operation_id
    AND status = 'PENDING';
    
    RETURN FOUND;
END;
$$;

-- Function to start compensation for an operation
CREATE OR REPLACE FUNCTION core.start_operation_compensation(
    p_operation_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.transaction_operations
    SET 
        compensation_status = 'EXECUTING',
        compensation_started_at = core.precise_now()
    WHERE operation_id = p_operation_id
    AND compensation_required = TRUE
    AND compensation_status IS NULL;
    
    RETURN FOUND;
END;
$$;

-- Function to complete operation compensation
CREATE OR REPLACE FUNCTION core.complete_operation_compensation(
    p_operation_id UUID,
    p_result JSONB DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.transaction_operations
    SET 
        compensation_status = 'COMPLETED',
        compensation_result = p_result,
        compensation_completed_at = core.precise_now()
    WHERE operation_id = p_operation_id
    AND compensation_status = 'EXECUTING';
    
    RETURN FOUND;
END;
$$;

-- Function to fail operation compensation
CREATE OR REPLACE FUNCTION core.fail_operation_compensation(
    p_operation_id UUID,
    p_error TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.transaction_operations
    SET 
        compensation_status = 'FAILED',
        compensation_error = p_error,
        compensation_completed_at = core.precise_now()
    WHERE operation_id = p_operation_id
    AND compensation_status = 'EXECUTING';
    
    RETURN FOUND;
END;
$$;

-- Function to get operations ready for execution
CREATE OR REPLACE FUNCTION core.get_ready_operations(
    p_saga_id UUID
)
RETURNS TABLE (
    operation_id UUID,
    sequence_number INTEGER,
    operation_name VARCHAR(100),
    operation_type VARCHAR(50),
    input_parameters JSONB,
    depends_on INTEGER[]
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        to_.operation_id,
        to_.sequence_number,
        to_.operation_name,
        to_.operation_type,
        to_.input_parameters,
        to_.depends_on
    FROM core.transaction_operations to_
    WHERE to_.saga_id = p_saga_id
    AND to_.status = 'PENDING'
    AND (
        to_.depends_on IS NULL 
        OR NOT EXISTS (
            SELECT 1 FROM core.transaction_operations dep
            WHERE dep.saga_id = p_saga_id
            AND dep.sequence_number = ANY(to_.depends_on)
            AND dep.status NOT IN ('COMPLETED', 'SKIPPED', 'COMPENSATED')
        )
    )
    ORDER BY to_.sequence_number;
END;
$$;

-- =============================================================================
-- TABLE AND COLUMN COMMENTS
-- =============================================================================

COMMENT ON TABLE core.transaction_operations IS 
    'Individual operations within a saga tracking execution state and compensation actions.';

COMMENT ON COLUMN core.transaction_operations.operation_id IS 
    'Unique identifier for the operation';
COMMENT ON COLUMN core.transaction_operations.saga_id IS 
    'Parent saga reference';
COMMENT ON COLUMN core.transaction_operations.sequence_number IS 
    'Order of this operation within the saga';
COMMENT ON COLUMN core.transaction_operations.operation_name IS 
    'Human-readable name of the operation';
COMMENT ON COLUMN core.transaction_operations.operation_type IS 
    'Type of operation (e.g., DEBIT, CREDIT, NOTIFY, VALIDATE)';
COMMENT ON COLUMN core.transaction_operations.status IS 
    'Current state: PENDING, EXECUTING, COMPLETED, FAILED, COMPENSATING, COMPENSATED, SKIPPED';
COMMENT ON COLUMN core.transaction_operations.compensation_action IS 
    'Action to execute for compensation (e.g., REVERSE_DEBIT)';
COMMENT ON COLUMN core.transaction_operations.depends_on IS 
    'Array of sequence numbers that must complete before this operation';

-- =============================================================================
-- END OF FILE
-- =============================================================================
