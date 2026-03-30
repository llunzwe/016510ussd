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

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.transaction_sagas (
    -- Primary identifier
    saga_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Correlation
    correlation_id UUID NOT NULL,
    parent_saga_id UUID REFERENCES ussd_core.transaction_sagas(saga_id),
    
    -- Saga definition
    saga_type VARCHAR(100) NOT NULL,
    saga_name VARCHAR(200) NOT NULL,
    
    -- State machine
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'EXECUTING', 'COMPLETED', 'FAILED', 'COMPENSATING', 'COMPENSATED')),
    
    -- Progress
    current_step INTEGER DEFAULT 0,
    total_steps INTEGER NOT NULL,
    step_results JSONB DEFAULT '{}',
    
    -- Timing
    started_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    completed_at TIMESTAMPTZ,
    timeout_at TIMESTAMPTZ,
    
    -- Retry handling
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    
    -- Context
    initiator_account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    application_id UUID,
    context JSONB,  -- Saga-specific context data
    
    -- Result
    result_data JSONB,
    failure_reason TEXT,
    failure_step INTEGER,
    
    -- Compensation
    compensation_required BOOLEAN DEFAULT FALSE,
    compensation_executed BOOLEAN DEFAULT FALSE,
    compensation_results JSONB,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    record_hash VARCHAR(64) NOT NULL
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
