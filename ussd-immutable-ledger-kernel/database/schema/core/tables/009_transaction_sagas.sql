-- =============================================================================
-- USSD KERNEL CORE SCHEMA - TRANSACTION SAGAS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    009_transaction_sagas.sql
-- SCHEMA:      ussd_core
-- TABLE:       transaction_sagas
-- DESCRIPTION: Long-running transaction coordination for distributed
--              operations requiring multiple steps and potential compensation.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.1 Operational procedures - Saga coordination procedures
├── A.12.3 Information backup - Saga state persistence
└── A.16.1 Management of information security incidents - Saga failure handling

ISO/IEC 27040:2024 (Storage Security)
├── Saga state persistence: Durable storage of coordination state
├── Compensation tracking: Immutable compensation history
└── Recovery: Saga state reconstruction after failure

ISO/IEC 27031:2025 (Business Continuity ICT Readiness)
├── Saga timeout handling: Graceful degradation
├── Partial completion recovery: Compensation execution
└── State machine persistence: Resume after interruption

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. SAGA PATTERN
   - State machine: PENDING → EXECUTING → COMPLETED/FAILED
   - Compensation: Reverse operations for rollback
   - Idempotency: Duplicate saga detection
   - Timeout: Automatic failure after deadline

2. STATE MANAGEMENT
   - Current state tracked with timestamps
   - Step-by-step progress recorded
   - Compensation state preserved

3. ERROR HANDLING
   - Retry count tracking
   - Exponential backoff
   - Dead letter queue for permanent failures

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

SAGA AUTHORIZATION:
- Saga initiator authentication
- Step-level authorization verification
- Compensation authorization checks

ISOLATION:
- Saga state isolated from transaction data
- Compensating transactions logged separately
- Audit trail for saga lifecycle

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: saga_id
- CORRELATION: correlation_id
- STATUS: status + started_at (monitoring)
- TIMEOUT: timeout_at (timeout processing)

CLEANUP:
- Archive completed sagas after retention period
- Purge old saga data per retention policy

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- SAGA_STARTED
- SAGA_STEP_COMPLETED
- SAGA_STEP_FAILED
- SAGA_COMPENSATION_EXECUTED
- SAGA_COMPLETED
- SAGA_FAILED

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- CREATE TABLE: transaction_sagas
-- =============================================================================

CREATE TABLE core.transaction_sagas (
    -- Primary identifier
    saga_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Correlation
    correlation_id UUID NOT NULL DEFAULT gen_random_uuid(),
    parent_saga_id UUID REFERENCES core.transaction_sagas(saga_id) ON DELETE RESTRICT,
    
    -- Saga definition
    saga_type VARCHAR(100) NOT NULL,
    saga_name VARCHAR(200) NOT NULL,
    saga_version VARCHAR(20) DEFAULT '1.0',
    
    -- State machine
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'EXECUTING', 'COMPLETED', 'FAILED', 'COMPENSATING', 'COMPENSATED', 'CANCELLED')),
    
    -- Progress
    current_step INTEGER DEFAULT 0,
    total_steps INTEGER NOT NULL CHECK (total_steps > 0),
    step_results JSONB DEFAULT '{}',  -- Map of step_number -> result
    failed_step INTEGER,
    
    -- Timing
    started_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    completed_at TIMESTAMPTZ,
    timeout_at TIMESTAMPTZ,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    
    -- Retry handling
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    retry_delay_seconds INTEGER DEFAULT 5,
    
    -- Context
    initiator_account_id UUID NOT NULL REFERENCES core.account_registry(account_id) ON DELETE RESTRICT,
    application_id UUID,
    context JSONB DEFAULT '{}',  -- Saga-specific context data
    
    -- Input/Output
    input_payload JSONB,
    result_data JSONB,
    
    -- Failure tracking
    failure_reason TEXT,
    failure_details JSONB,
    failure_step INTEGER,
    
    -- Compensation
    compensation_required BOOLEAN DEFAULT FALSE,
    compensation_executed BOOLEAN DEFAULT FALSE,
    compensation_started_at TIMESTAMPTZ,
    compensation_completed_at TIMESTAMPTZ,
    compensation_results JSONB,
    
    -- Metadata
    priority INTEGER DEFAULT 100,  -- Lower = higher priority
    metadata JSONB DEFAULT '{}',
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    CONSTRAINT chk_completed_has_completed_at CHECK (
        status NOT IN ('COMPLETED', 'COMPENSATED') OR completed_at IS NOT NULL
    ),
    CONSTRAINT chk_failed_has_reason CHECK (
        status != 'FAILED' OR failure_reason IS NOT NULL
    ),
    CONSTRAINT chk_step_progress CHECK (current_step <= total_steps)
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Correlation ID lookup
CREATE INDEX idx_transaction_sagas_correlation ON core.transaction_sagas(correlation_id);

-- Status monitoring
CREATE INDEX idx_transaction_sagas_status ON core.transaction_sagas(status, started_at);

-- Active sagas
CREATE INDEX idx_transaction_sagas_active ON core.transaction_sagas(saga_id) 
    WHERE status IN ('PENDING', 'EXECUTING', 'COMPENSATING');

-- Timeout processing
CREATE INDEX idx_transaction_sagas_timeout ON core.transaction_sagas(timeout_at) 
    WHERE timeout_at IS NOT NULL AND status IN ('PENDING', 'EXECUTING');

-- Parent saga lookup
CREATE INDEX idx_transaction_sagas_parent ON core.transaction_sagas(parent_saga_id) 
    WHERE parent_saga_id IS NOT NULL;

-- Initiator lookup
CREATE INDEX idx_transaction_sagas_initiator ON core.transaction_sagas(initiator_account_id, started_at DESC);

-- Application lookup
CREATE INDEX idx_transaction_sagas_app ON core.transaction_sagas(application_id, started_at DESC);

-- Type filtering
CREATE INDEX idx_transaction_sagas_type ON core.transaction_sagas(saga_type, status);

-- Priority for processing
CREATE INDEX idx_transaction_sagas_priority ON core.transaction_sagas(priority, started_at) 
    WHERE status IN ('PENDING', 'EXECUTING');

-- Last activity for cleanup
CREATE INDEX idx_transaction_sagas_activity ON core.transaction_sagas(last_activity_at) 
    WHERE status IN ('COMPLETED', 'FAILED', 'COMPENSATED', 'CANCELLED');

-- =============================================================================
-- UPDATE TIMESTAMP TRIGGER
-- =============================================================================

CREATE OR REPLACE FUNCTION core.update_saga_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = core.precise_now();
    NEW.last_activity_at = core.precise_now();
    
    -- Set completed_at when transitioning to terminal state
    IF NEW.status IN ('COMPLETED', 'FAILED', 'COMPENSATED', 'CANCELLED') 
       AND OLD.status NOT IN ('COMPLETED', 'FAILED', 'COMPENSATED', 'CANCELLED') THEN
        NEW.completed_at := core.precise_now();
    END IF;
    
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_transaction_sagas_update_timestamp
    BEFORE UPDATE ON core.transaction_sagas
    FOR EACH ROW
    EXECUTE FUNCTION core.update_saga_timestamp();

-- =============================================================================
-- HASH COMPUTATION TRIGGER
-- =============================================================================

CREATE OR REPLACE FUNCTION core.compute_saga_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.saga_id::TEXT || 
        NEW.correlation_id::TEXT || 
        NEW.saga_type ||
        NEW.initiator_account_id::TEXT ||
        NEW.started_at::TEXT ||
        NEW.status
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_transaction_sagas_compute_hash
    BEFORE INSERT OR UPDATE ON core.transaction_sagas
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_saga_hash();

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

-- Enable RLS
ALTER TABLE core.transaction_sagas ENABLE ROW LEVEL SECURITY;

-- Policy: Initiator can view their own sagas
CREATE POLICY transaction_sagas_initiator_access ON core.transaction_sagas
    FOR SELECT
    TO ussd_app_user
    USING (initiator_account_id = current_setting('app.current_account_id', true)::UUID);

-- Policy: Application-scoped access
CREATE POLICY transaction_sagas_app_access ON core.transaction_sagas
    FOR SELECT
    TO ussd_app_user
    USING (application_id = current_setting('app.current_application_id', true)::UUID);

-- Policy: Kernel role has full access
CREATE POLICY transaction_sagas_kernel_access ON core.transaction_sagas
    FOR ALL
    TO ussd_kernel_role
    USING (true);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to create a saga
CREATE OR REPLACE FUNCTION core.create_saga(
    p_saga_type VARCHAR(100),
    p_saga_name VARCHAR(200),
    p_total_steps INTEGER,
    p_initiator_account_id UUID,
    p_application_id UUID DEFAULT NULL,
    p_input_payload JSONB DEFAULT NULL,
    p_timeout_at TIMESTAMPTZ DEFAULT NULL,
    p_parent_saga_id UUID DEFAULT NULL,
    p_context JSONB DEFAULT '{}'
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_saga_id UUID;
BEGIN
    INSERT INTO core.transaction_sagas (
        saga_type,
        saga_name,
        total_steps,
        initiator_account_id,
        application_id,
        input_payload,
        timeout_at,
        parent_saga_id,
        context
    ) VALUES (
        p_saga_type,
        p_saga_name,
        p_total_steps,
        p_initiator_account_id,
        p_application_id,
        p_input_payload,
        p_timeout_at,
        p_parent_saga_id,
        p_context
    )
    RETURNING saga_id INTO v_saga_id;
    
    RETURN v_saga_id;
END;
$$;

-- Function to update saga progress
CREATE OR REPLACE FUNCTION core.update_saga_progress(
    p_saga_id UUID,
    p_step_number INTEGER,
    p_step_result JSONB,
    p_status VARCHAR(50) DEFAULT 'EXECUTING'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.transaction_sagas
    SET 
        current_step = p_step_number,
        step_results = step_results || jsonb_build_object(p_step_number::TEXT, p_step_result),
        status = p_status,
        retry_count = 0  -- Reset retry count on successful step
    WHERE saga_id = p_saga_id
    AND status IN ('PENDING', 'EXECUTING');
    
    RETURN FOUND;
END;
$$;

-- Function to mark saga step failed
CREATE OR REPLACE FUNCTION core.fail_saga_step(
    p_saga_id UUID,
    p_step_number INTEGER,
    p_failure_reason TEXT,
    p_failure_details JSONB DEFAULT NULL
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
    FROM core.transaction_sagas
    WHERE saga_id = p_saga_id;
    
    -- If we can retry, increment counter and stay in EXECUTING
    IF v_current_retries < v_max_retries THEN
        UPDATE core.transaction_sagas
        SET 
            retry_count = retry_count + 1,
            failed_step = p_step_number,
            failure_reason = p_failure_reason,
            failure_details = p_failure_details
        WHERE saga_id = p_saga_id;
    ELSE
        -- Mark as failed, will trigger compensation
        UPDATE core.transaction_sagas
        SET 
            status = 'FAILED',
            failed_step = p_step_number,
            failure_reason = p_failure_reason,
            failure_details = p_failure_details,
            compensation_required = TRUE
        WHERE saga_id = p_saga_id;
    END IF;
    
    RETURN FOUND;
END;
$$;

-- Function to complete a saga
CREATE OR REPLACE FUNCTION core.complete_saga(
    p_saga_id UUID,
    p_result_data JSONB DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.transaction_sagas
    SET 
        status = 'COMPLETED',
        current_step = total_steps,
        result_data = p_result_data
    WHERE saga_id = p_saga_id
    AND status IN ('PENDING', 'EXECUTING');
    
    RETURN FOUND;
END;
$$;

-- Function to start compensation
CREATE OR REPLACE FUNCTION core.start_saga_compensation(
    p_saga_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.transaction_sagas
    SET 
        status = 'COMPENSATING',
        compensation_required = TRUE,
        compensation_started_at = core.precise_now()
    WHERE saga_id = p_saga_id
    AND status IN ('FAILED', 'CANCELLED');
    
    RETURN FOUND;
END;
$$;

-- Function to complete compensation
CREATE OR REPLACE FUNCTION core.complete_saga_compensation(
    p_saga_id UUID,
    p_compensation_results JSONB
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.transaction_sagas
    SET 
        status = 'COMPENSATED',
        compensation_executed = TRUE,
        compensation_completed_at = core.precise_now(),
        compensation_results = p_compensation_results
    WHERE saga_id = p_saga_id
    AND status = 'COMPENSATING';
    
    RETURN FOUND;
END;
$$;

-- Function to cancel a saga
CREATE OR REPLACE FUNCTION core.cancel_saga(
    p_saga_id UUID,
    p_reason TEXT DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.transaction_sagas
    SET 
        status = 'CANCELLED',
        failure_reason = p_reason,
        compensation_required = TRUE
    WHERE saga_id = p_saga_id
    AND status IN ('PENDING', 'EXECUTING');
    
    RETURN FOUND;
END;
$$;

-- Function to get expired sagas for timeout processing
CREATE OR REPLACE FUNCTION core.get_expired_sagas()
RETURNS TABLE (
    saga_id UUID,
    saga_type VARCHAR(100),
    status VARCHAR(50),
    started_at TIMESTAMPTZ,
    timeout_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ts.saga_id,
        ts.saga_type,
        ts.status,
        ts.started_at,
        ts.timeout_at
    FROM core.transaction_sagas ts
    WHERE ts.timeout_at IS NOT NULL
    AND ts.timeout_at < core.precise_now()
    AND ts.status IN ('PENDING', 'EXECUTING');
END;
$$;

-- =============================================================================
-- TABLE AND COLUMN COMMENTS
-- =============================================================================

COMMENT ON TABLE core.transaction_sagas IS 
    'Long-running transaction coordination for distributed operations with compensation support.';

COMMENT ON COLUMN core.transaction_sagas.saga_id IS 
    'Unique identifier for the saga';
COMMENT ON COLUMN core.transaction_sagas.correlation_id IS 
    'Correlation ID for tracking related operations';
COMMENT ON COLUMN core.transaction_sagas.saga_type IS 
    'Type of saga (e.g., TRANSFER, BATCH_PAYMENT, CROSS_BORDER)';
COMMENT ON COLUMN core.transaction_sagas.status IS 
    'Current state: PENDING, EXECUTING, COMPLETED, FAILED, COMPENSATING, COMPENSATED, CANCELLED';
COMMENT ON COLUMN core.transaction_sagas.current_step IS 
    'Current step number (0-based)';
COMMENT ON COLUMN core.transaction_sagas.total_steps IS 
    'Total number of steps in the saga';
COMMENT ON COLUMN core.transaction_sagas.timeout_at IS 
    'Deadline for saga completion';
COMMENT ON COLUMN core.transaction_sagas.compensation_required IS 
    'Whether compensation is needed due to failure';
COMMENT ON COLUMN core.transaction_sagas.compensation_executed IS 
    'Whether compensation has been executed';

-- =============================================================================
-- END OF FILE
-- =============================================================================
