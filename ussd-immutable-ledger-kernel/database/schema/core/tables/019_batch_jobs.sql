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
-- CREATE TABLE: batch_jobs
-- -----------------------------------------------------------------------------
CREATE TABLE core.batch_jobs (
    -- Primary identifier
    job_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Parent batch
    batch_id UUID NOT NULL REFERENCES core.control_batches(batch_id) ON DELETE RESTRICT,
    job_sequence INTEGER NOT NULL,
    
    -- Idempotency
    idempotency_key VARCHAR(255) NOT NULL,
    
    -- Job definition
    job_type VARCHAR(50) NOT NULL
        CHECK (job_type IN ('PAYMENT', 'TRANSFER', 'FEE', 'INTEREST', 'ADJUSTMENT', 'NOTIFICATION')),
    job_parameters JSONB NOT NULL DEFAULT '{}',
    
    -- Target account (for account-specific jobs)
    account_id UUID REFERENCES core.account_registry(account_id) ON DELETE RESTRICT,
    
    -- Amount information
    amount NUMERIC(20, 8),
    currency VARCHAR(3) CHECK (currency ~ '^[A-Z]{3}$'),
    
    -- Status
    status VARCHAR(50) DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'RETRYING', 'CANCELLED')),
    
    -- Result
    transaction_id UUID,
    result_data JSONB,
    result_code VARCHAR(50),
    result_message TEXT,
    
    -- Error handling
    error_message TEXT,
    error_code VARCHAR(50),
    error_details JSONB,
    retry_count INTEGER DEFAULT 0 CHECK (retry_count >= 0),
    max_retries INTEGER DEFAULT 3,
    
    -- Timing
    scheduled_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    processing_duration_ms INTEGER,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING',
    
    -- Constraints
    UNIQUE (batch_id, job_sequence),
    UNIQUE (batch_id, idempotency_key)
);

-- -----------------------------------------------------------------------------
-- INDEXES
-- -----------------------------------------------------------------------------
-- Batch lookups with status
CREATE INDEX idx_batch_jobs_batch_status 
    ON core.batch_jobs(batch_id, status);

-- Status monitoring
CREATE INDEX idx_batch_jobs_status_date 
    ON core.batch_jobs(status, created_at) 
    WHERE status IN ('PENDING', 'FAILED', 'RETRYING');

-- Account-based queries
CREATE INDEX idx_batch_jobs_account 
    ON core.batch_jobs(account_id, created_at) 
    WHERE account_id IS NOT NULL;

-- Transaction linking
CREATE INDEX idx_batch_jobs_transaction 
    ON core.batch_jobs(transaction_id) 
    WHERE transaction_id IS NOT NULL;

-- Idempotency key lookups
CREATE INDEX idx_batch_jobs_idempotency 
    ON core.batch_jobs(idempotency_key);

-- Job type queries
CREATE INDEX idx_batch_jobs_type_status 
    ON core.batch_jobs(job_type, status);

-- Scheduled jobs
CREATE INDEX idx_batch_jobs_scheduled 
    ON core.batch_jobs(scheduled_at) 
    WHERE status = 'PENDING' AND scheduled_at IS NOT NULL;

-- -----------------------------------------------------------------------------
-- IMMUTABILITY TRIGGERS
-- -----------------------------------------------------------------------------
CREATE TRIGGER trg_batch_jobs_prevent_update
    BEFORE UPDATE ON core.batch_jobs
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_batch_jobs_prevent_delete
    BEFORE DELETE ON core.batch_jobs
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- -----------------------------------------------------------------------------
-- HASH COMPUTATION TRIGGER
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION core.compute_batch_job_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.job_id::TEXT || 
        NEW.job_reference || 
        NEW.batch_id::TEXT ||
        NEW.job_sequence::TEXT ||
        NEW.idempotency_key ||
        NEW.job_type ||
        COALESCE(NEW.account_id::TEXT, '') ||
        COALESCE(NEW.amount::TEXT, '') ||
        COALESCE(NEW.currency, '') ||
        NEW.status ||
        COALESCE(NEW.transaction_id::TEXT, '') ||
        NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_batch_jobs_compute_hash
    BEFORE INSERT ON core.batch_jobs
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_batch_job_hash();

-- -----------------------------------------------------------------------------
-- HELPER FUNCTIONS
-- -----------------------------------------------------------------------------

-- Function to create a batch job
CREATE OR REPLACE FUNCTION core.create_batch_job(
    p_batch_id UUID,
    p_job_type VARCHAR(50),
    p_job_parameters JSONB,
    p_idempotency_key VARCHAR(255),
    p_account_id UUID DEFAULT NULL,
    p_amount NUMERIC DEFAULT NULL,
    p_currency VARCHAR(3) DEFAULT NULL,
    p_scheduled_at TIMESTAMPTZ DEFAULT NULL,
    p_created_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_job_id UUID;
    v_reference VARCHAR(100);
    v_sequence INTEGER;
BEGIN
    -- Get next sequence for batch
    SELECT COALESCE(MAX(job_sequence), 0) + 1 INTO v_sequence 
    FROM core.batch_jobs 
    WHERE batch_id = p_batch_id;
    
    -- Generate reference
    v_reference := 'JOB-' || TO_CHAR(NOW(), 'YYYYMMDD') || '-' || SUBSTRING(MD5(RANDOM()::TEXT), 1, 8);
    
    INSERT INTO core.batch_jobs (
        job_reference,
        batch_id,
        job_sequence,
        idempotency_key,
        job_type,
        job_parameters,
        account_id,
        amount,
        currency,
        scheduled_at,
        created_by
    ) VALUES (
        v_reference,
        p_batch_id,
        v_sequence,
        p_idempotency_key,
        p_job_type,
        p_job_parameters,
        p_account_id,
        p_amount,
        p_currency,
        p_scheduled_at,
        p_created_by
    ) RETURNING job_id INTO v_job_id;
    
    RETURN v_job_id;
END;
$$;

-- Function to get batch job summary
CREATE OR REPLACE FUNCTION core.get_batch_job_summary(
    p_batch_id UUID
)
RETURNS TABLE (
    total_jobs BIGINT,
    pending_jobs BIGINT,
    processing_jobs BIGINT,
    completed_jobs BIGINT,
    failed_jobs BIGINT,
    total_amount NUMERIC,
    completed_amount NUMERIC
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*) as total_jobs,
        COUNT(*) FILTER (WHERE status = 'PENDING') as pending_jobs,
        COUNT(*) FILTER (WHERE status = 'PROCESSING') as processing_jobs,
        COUNT(*) FILTER (WHERE status = 'COMPLETED') as completed_jobs,
        COUNT(*) FILTER (WHERE status = 'FAILED') as failed_jobs,
        SUM(COALESCE(amount, 0)) as total_amount,
        SUM(COALESCE(amount, 0)) FILTER (WHERE status = 'COMPLETED') as completed_amount
    FROM core.batch_jobs
    WHERE batch_id = p_batch_id;
END;
$$;

-- Function to get failed jobs for retry
CREATE OR REPLACE FUNCTION core.get_failed_jobs_for_retry(
    p_batch_id UUID DEFAULT NULL,
    p_max_retries INTEGER DEFAULT 3
)
RETURNS TABLE (
    job_id UUID,
    batch_id UUID,
    job_sequence INTEGER,
    job_type VARCHAR(50),
    retry_count INTEGER,
    error_message TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        bj.job_id,
        bj.batch_id,
        bj.job_sequence,
        bj.job_type,
        bj.retry_count,
        bj.error_message
    FROM core.batch_jobs bj
    WHERE bj.status = 'FAILED'
      AND bj.retry_count < LEAST(bj.max_retries, p_max_retries)
      AND (p_batch_id IS NULL OR bj.batch_id = p_batch_id)
    ORDER BY bj.created_at;
END;
$$;

-- Function to find duplicate jobs by idempotency key
CREATE OR REPLACE FUNCTION core.find_duplicate_batch_jobs(
    p_batch_id UUID
)
RETURNS TABLE (
    idempotency_key VARCHAR(255),
    job_count BIGINT,
    job_ids UUID[]
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        bj.idempotency_key,
        COUNT(*) as job_count,
        ARRAY_AGG(bj.job_id) as job_ids
    FROM core.batch_jobs bj
    WHERE bj.batch_id = p_batch_id
    GROUP BY bj.idempotency_key
    HAVING COUNT(*) > 1;
END;
$$;

-- -----------------------------------------------------------------------------
-- COMMENTS
-- -----------------------------------------------------------------------------
COMMENT ON TABLE core.batch_jobs IS 'Individual jobs within control batches';
COMMENT ON COLUMN core.batch_jobs.job_id IS 'Unique identifier for the job';
COMMENT ON COLUMN core.batch_jobs.idempotency_key IS 'Client-provided key for duplicate prevention';
COMMENT ON COLUMN core.batch_jobs.status IS 'Current processing status';
COMMENT ON COLUMN core.batch_jobs.retry_count IS 'Number of retry attempts made';

-- =============================================================================
-- END OF FILE
-- =============================================================================
