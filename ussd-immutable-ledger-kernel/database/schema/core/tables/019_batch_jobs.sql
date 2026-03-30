-- =============================================================================
-- USSD KERNEL CORE SCHEMA - BATCH JOBS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    019_batch_jobs.sql
-- SCHEMA:      ussd_core
-- TABLE:       batch_jobs
-- DESCRIPTION: Individual jobs within control batches tracking specific
--              transactions and their processing status.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Job execution monitoring
├── A.12.6 Technical vulnerability management - Job validation
└── A.16.1 Management of information security incidents - Job failure handling

Financial Regulations
├── Transaction traceability: Job-to-transaction linking
├── Audit trail: Complete job history
└── Error handling: Failed job investigation

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. JOB STATES
   - PENDING: Awaiting processing
   - PROCESSING: Currently executing
   - COMPLETED: Successfully processed
   - FAILED: Error occurred
   - RETRYING: Attempting retry

2. RETRY HANDLING
   - Configurable retry count
   - Exponential backoff
   - Dead letter queue for permanent failures

3. IDEMPOTENCY
   - Job idempotency key
   - Duplicate prevention
   - Reconciliation support

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

JOB SECURITY:
- Input validation
- Authorization verification
- Output sanitization

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: job_id
- BATCH: batch_id + status
- STATUS: status + created_at
- IDEMPOTENCY: idempotency_key

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- JOB_CREATED
- JOB_STARTED
- JOB_COMPLETED
- JOB_FAILED
- JOB_RETRIED

RETENTION: 7 years
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.batch_jobs (
    -- Primary identifier
    job_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Parent batch
    batch_id UUID NOT NULL REFERENCES ussd_core.control_batches(batch_id),
    job_sequence INTEGER NOT NULL,
    
    -- Idempotency
    idempotency_key VARCHAR(255) NOT NULL,
    
    -- Job definition
    job_type VARCHAR(50) NOT NULL,
    job_parameters JSONB NOT NULL,
    
    -- Status
    status VARCHAR(50) DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'RETRYING')),
    
    -- Result
    transaction_id UUID,
    result_data JSONB,
    
    -- Error handling
    error_message TEXT,
    error_code VARCHAR(50),
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    
    -- Timing
    scheduled_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    UNIQUE (batch_id, job_sequence),
    UNIQUE (batch_id, idempotency_key)
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
