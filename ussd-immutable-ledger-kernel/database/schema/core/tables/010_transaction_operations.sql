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

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.transaction_operations (
    -- Primary identifier
    operation_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Parent saga
    saga_id UUID NOT NULL REFERENCES ussd_core.transaction_sagas(saga_id),
    sequence_number INTEGER NOT NULL,
    
    -- Operation definition
    operation_name VARCHAR(100) NOT NULL,
    operation_type VARCHAR(50) NOT NULL,
    
    -- State
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'EXECUTING', 'COMPLETED', 'FAILED', 'COMPENSATED')),
    
    -- Execution
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    
    -- Input/Output
    input_parameters JSONB,
    output_result JSONB,
    
    -- Error handling
    error_message TEXT,
    error_code VARCHAR(50),
    retry_count INTEGER DEFAULT 0,
    
    -- Compensation
    compensation_action VARCHAR(50),
    compensation_parameters JSONB,
    compensation_executed_at TIMESTAMPTZ,
    compensation_result JSONB,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    UNIQUE (saga_id, sequence_number)
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
