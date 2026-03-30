-- =============================================================================
-- MIGRATION: 021_core_batch_jobs.sql
-- DESCRIPTION: Scheduled and One-off Batch Jobs with Compliance Controls
-- TABLES: batch_jobs, job_executions, job_dependencies
-- DEPENDENCIES: 020_core_control_batches.sql
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems - ISMS)
  - A.5.1: Information security policies
  - A.8.1: User endpoint devices
  - A.8.2: Privileged access rights
  - A.9.2: Access to networks and network services
  - A.12.1: Operational procedures and responsibilities
  - A.12.3: Information backup
  - A.12.4: Logging and monitoring
  - A.12.5: Control of operational software

ISO/IEC 27018:2019 (Protection of PII in Public Clouds)
  - Clause 7: Obligations to the customer
  - Clause 8: Information disclosure and access
  - Annex A: Personally Identifiable Information protection controls
  - PII Classification: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED

ISO/IEC 27040:2024 (Storage Security)
  - Section 5: Storage security architecture
  - Section 6: Data protection and encryption
  - Section 7: Access control and authentication
  - Section 8: Storage security monitoring

ISO 9001:2015 (Quality Management Systems)
  - Clause 7.1: Resources
  - Clause 7.5: Documented information
  - Clause 8.5: Production and service provision
  - Clause 9.1: Monitoring and measurement
  - Clause 10.2: Nonconformity and corrective action

ISO 31000:2018 (Risk Management Guidelines)
  - Principle 4: Integration into organizational processes
  - Principle 6: Based on best available information
  - Risk treatment: Avoid, Mitigate, Transfer, Accept

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

SECURITY BEST PRACTICES:
  [SECURITY-001] SECURITY DEFINER: Functions execute with owner's privileges
                  REQUIRED for: admin functions, cross-schema access, audit logging
  [SECURITY-002] Input validation: All parameters validated before processing
                  Use: CHECK constraints, domain types, function preconditions
  [SECURITY-003] Row-Level Security (RLS): Enabled for tenant isolation
                  Policy: CREATE POLICY tenant_isolation ON table USING (tenant_id = current_tenant())
  [SECURITY-004] Audit logging: All changes recorded in audit trail
                  Trigger: audit_trigger() on all tables logging to audit.audit_log
  [SECURITY-005] Encryption at rest: Sensitive data encrypted with AES-256
                  Use: pgcrypto extension, column-level encryption for PII

FUNCTION VOLATILITY DECLARATIONS:
  [VOLATILITY] IMMUTABLE: Function cannot modify database; returns same result
               for same arguments within single query
               Use for: pure calculations, formatting functions, hash computation
               Example: IMMUTABLE FUNCTION calculate_hash(data TEXT) RETURNS BYTEA
  
  [VOLATILITY] STABLE: Function cannot modify database; returns same result
               for same arguments within single statement
               Use for: lookups, current timestamp, configuration reads
               Example: STABLE FUNCTION get_exchange_rate(from_curr VARCHAR, to_curr VARCHAR)
  
  [VOLATILITY] VOLATILE: Function can modify database; result may vary
               Use for: DML operations, sequence access, random values
               Example: VOLATILE FUNCTION create_transaction(payload JSONB)

ERROR HANDLING PATTERNS:
  [ERROR-001] EXCEPTION WHEN OTHERS THEN: Catch-all error handler
              USE WITH CAUTION - always re-raise or log
              Pattern: EXCEPTION WHEN OTHERS THEN log_error(...); RAISE;
  
  [ERROR-002] RAISE EXCEPTION: Structured error messages with HINT
              Format: RAISE EXCEPTION 'Context: %', param USING HINT = 'Suggestion';
              SQLSTATE: Use custom codes for application errors
  
  [ERROR-003] RAISE NOTICE: Informational messages for debugging
              Use in development only; disable in production
  
  [ERROR-004] SQLSTATE handling: Specific error code catching
              Pattern: EXCEPTION WHEN unique_violation THEN ...
              Common: unique_violation, foreign_key_violation, check_violation

TRANSACTION CONTROL DOCUMENTATION:
  [TRANSACTION] BEGIN/COMMIT/ROLLBACK: Explicit transaction boundaries
                Use for: Multi-statement operations requiring atomicity
  
  [TRANSACTION] SAVEPOINT: Partial rollback capability
                Pattern: SAVEPOINT sp1; ...; ROLLBACK TO SAVEPOINT sp1;
                Use for: Nested operations with selective failure handling
  
  [TRANSACTION] ISOLATION LEVEL: Serializable for critical operations
                Syntax: SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
                Use for: Financial calculations, balance updates, inventory

AUDIT TRAIL INTEGRATION:
  [AUDIT] created_at, created_by: Record creation tracking
          Columns: created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                   created_by UUID REFERENCES core.accounts(account_id)
  
  [AUDIT] updated_at, updated_by: Modification tracking
          Trigger: update_timestamp_trigger() sets updated_at = now()
  
  [AUDIT] superseded_by, valid_from, valid_to: Temporal versioning
          Pattern: Append-only tables, new version supersedes old
          Query: WHERE valid_to IS NULL AND is_current = true
  
  [AUDIT] status, status_reason: State change tracking
          Pattern: status VARCHAR(20), status_reason TEXT, status_changed_at TIMESTAMPTZ

DATA RETENTION COMPLIANCE:
  [RETENTION] retention_until: Automatic purging after retention period
              Policy: DELETE FROM table WHERE retention_until < CURRENT_DATE AND legal_hold = false
              Audit: Log all purges to retention.audit_log
  
  [RETENTION] legal_hold: Override retention for legal requirements
              Flag: legal_hold BOOLEAN DEFAULT false
              Fields: legal_hold_reason TEXT, legal_hold_set_at TIMESTAMPTZ, legal_hold_set_by UUID
              Enforcement: Prevent deletion/purge when legal_hold = true
  
  [RETENTION] archive_manifest: Cold storage tracking
              Table: archive.archive_manifest tracks all archived records
              Fields: storage_provider, storage_bucket, storage_key, content_hash
              Verification: SHA-256 hash verification on restore
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 9. Control & Batch Processing
- Feature: Batch Jobs
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Scheduled or one-off batch jobs with progress tracking, retries, and result
summary. Automates end-of-day interest, monthly fees, data exports. Implements
ISO 27001 controls for automated processing integrity.

KEY FEATURES:
- Schedule configuration with timezone awareness (ISO 27001 A.12.3)
- Job progress tracking and audit trail (ISO 9001 9.1)
- Retry mechanisms with exponential backoff (ISO 31000 risk mitigation)
- Dependency chain validation before execution
- PII data handling compliance (ISO 27018 Clause 7)

JOB TYPES:
- INTEREST_ACCRUAL: Calculate and post interest
- FEE_CALCULATION: Compute monthly fees
- STATEMENT_GENERATION: Generate customer statements (PII handling per ISO 27018)
- DATA_EXPORT: Export to data warehouse (encryption per ISO 27040)
- RECONCILIATION: Run daily reconciliation (integrity per ISO 27001)
- ARCHIVAL: Move old data to cold storage (retention per ISO 27040)
- REPORT_GENERATION: Create management reports

SECURITY CONTROLS:
- [SECURITY-001] Jobs execute under SECURITY DEFINER context
- [SECURITY-002] Input parameters validated against injection attacks
- [SECURITY-005] Job results encrypted at rest (ISO 27040)
================================================================================
*/


-- =============================================================================
-- TODO: Create batch_jobs table
-- DESCRIPTION: Job definitions and scheduling
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [JOB-001] Create core.batch_jobs table
-- INSTRUCTIONS:
--   - Define recurring and one-time jobs
--   - Schedule configuration
--   - Job parameters and dependencies
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.batch_jobs (
--       job_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       job_code            VARCHAR(50) UNIQUE NOT NULL,
--       job_name            VARCHAR(100) NOT NULL,
--       description         TEXT,
--       
--       -- Classification
--       job_type            VARCHAR(50) NOT NULL,        -- INTEREST_ACCRUAL, etc.
--       category            VARCHAR(50),                 -- FINANCIAL, REPORTING, MAINTENANCE
--       
--       -- Schedule
--       schedule_type       VARCHAR(20) NOT NULL,        -- ONCE, RECURRING, CRON
--       cron_expression     VARCHAR(100),                -- For CRON type
--       run_at              TIMESTAMPTZ,                 -- For ONCE type
--       timezone            VARCHAR(50) DEFAULT 'UTC',
--       
--       -- Parameters
--       parameters          JSONB DEFAULT '{}',          -- Job-specific params
--       
--       -- Execution
--       is_active           BOOLEAN DEFAULT true,
--       max_retries         INTEGER DEFAULT 3,
--       timeout_minutes     INTEGER DEFAULT 60,
--       
--       -- Dependencies
--       depends_on_jobs     UUID[],                      -- Must complete first
--       
--       -- Scope
--       application_id      UUID REFERENCES app.applications(application_id),
--       
--       -- Notification
--       notify_on_success   BOOLEAN DEFAULT false,
--       notify_on_failure   BOOLEAN DEFAULT true,
--       notification_emails TEXT[],
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id),
--       updated_at          TIMESTAMPTZ
--   );

-- =============================================================================
-- TODO: Create job_executions table
-- DESCRIPTION: Individual job run instances
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [JOB-002] Create core.job_executions table
-- INSTRUCTIONS:
--   - Records each job execution
--   - Tracks progress through stages
--   - Captures output and errors
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.job_executions (
--       execution_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       job_id              UUID NOT NULL REFERENCES core.batch_jobs(job_id),
--       
--       -- Execution Reference
--       execution_reference VARCHAR(100) UNIQUE NOT NULL,
--       
--       -- Status
--       status              VARCHAR(20) DEFAULT 'PENDING',
--                           -- PENDING, QUEUED, RUNNING, COMPLETED, 
--                           -- FAILED, CANCELLED, TIMEOUT
--       
--       -- Progress
--       progress_pct        INTEGER DEFAULT 0,
--       current_stage       VARCHAR(100),
--       stages_total        INTEGER,
--       stage_completed     INTEGER,
--       
--       -- Statistics
--       records_processed   INTEGER DEFAULT 0,
--       records_failed      INTEGER DEFAULT 0,
--       records_total       INTEGER,
--       
--       -- Results
--       result_summary      JSONB,
--       output_log          TEXT,
--       error_log           TEXT,
--       
--       -- Timing
--       queued_at           TIMESTAMPTZ,
--       started_at          TIMESTAMPTZ,
--       completed_at        TIMESTAMPTZ,
--       
--       -- Retry
--       is_retry            BOOLEAN DEFAULT false,
--       retry_of            UUID REFERENCES core.job_executions(execution_id),
--       retry_count         INTEGER DEFAULT 0,
--       
--       -- Instance
--       executed_by_host    VARCHAR(100),
--       executed_by_process VARCHAR(100),
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create job execution function
-- DESCRIPTION: Execute a batch job
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [JOB-003] Create execute_job function
-- INSTRUCTIONS:
--   - Check dependencies
--   - Update status to RUNNING
--   - Execute job-specific logic
--   - Update progress
--   - Record results
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.execute_job(p_execution_id UUID)
--   RETURNS VARCHAR AS $$
--   DECLARE
--       v_execution RECORD;
--       v_job RECORD;
--   BEGIN
--       -- Get execution and job
--       SELECT * INTO v_execution FROM core.job_executions WHERE execution_id = p_execution_id;
--       SELECT * INTO v_job FROM core.batch_jobs WHERE job_id = v_execution.job_id;
--       
--       -- Check dependencies
--       IF EXISTS (
--           SELECT 1 FROM core.job_executions je
--           WHERE je.job_id = ANY(v_job.depends_on_jobs)
--             AND je.status NOT IN ('COMPLETED')
--             AND je.created_at > v_execution.created_at - interval '1 day'
--       ) THEN
--           UPDATE core.job_executions 
--           SET status = 'PENDING', error_log = 'Dependencies not met'
--           WHERE execution_id = p_execution_id;
--           RETURN 'PENDING';
--       END IF;
--       
--       -- Update status
--       UPDATE core.job_executions 
--       SET status = 'RUNNING', started_at = now()
--       WHERE execution_id = p_execution_id;
--       
--       -- Execute based on job type
--       CASE v_job.job_type
--           WHEN 'INTEREST_ACCRUAL' THEN
--               PERFORM core.execute_interest_accrual(p_execution_id, v_job.parameters);
--           WHEN 'FEE_CALCULATION' THEN
--               PERFORM core.execute_fee_calculation(p_execution_id, v_job.parameters);
--           WHEN 'RECONCILIATION' THEN
--               PERFORM core.execute_reconciliation_job(p_execution_id, v_job.parameters);
--           -- etc.
--       END CASE;
--       
--       -- Update status
--       UPDATE core.job_executions 
--       SET status = 'COMPLETED', completed_at = now(), progress_pct = 100
--       WHERE execution_id = p_execution_id;
--       
--       RETURN 'COMPLETED';
--       
--   EXCEPTION WHEN OTHERS THEN
--       UPDATE core.job_executions 
--       SET status = 'FAILED', 
--           error_log = SQLERRM,
--           completed_at = now()
--       WHERE execution_id = p_execution_id;
--       RETURN 'FAILED';
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create job scheduling function
-- DESCRIPTION: Queue jobs based on schedule
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [JOB-004] Create schedule_jobs function
-- INSTRUCTIONS:
--   - Called by cron/scheduler
--   - Find jobs due to run
--   - Create execution records
--   - Respect job dependencies

-- =============================================================================
-- TODO: Create job progress update function
-- DESCRIPTION: Report job progress
-- PRIORITY: MEDIUM
-- =============================================================================
-- TODO: [JOB-005] Create update_job_progress function
-- INSTRUCTIONS:
--   - Update progress percentage
--   - Update current stage
--   - Increment processed counts

-- =============================================================================
-- TODO: Create job indexes
-- DESCRIPTION: Optimize job queries
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [JOB-006] Create job indexes
-- INDEX LIST:
--   -- Jobs:
--   - PRIMARY KEY (job_id)
--   - UNIQUE (job_code)
--   - INDEX on (is_active, schedule_type)
--   - INDEX on (application_id, job_type)
--   -- Executions:
--   - PRIMARY KEY (execution_id)
--   - UNIQUE (execution_reference)
--   - INDEX on (job_id, status)
--   - INDEX on (status, queued_at) WHERE status = 'PENDING'
--   - INDEX on (created_at)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create batch_jobs table with scheduling
□ Create job_executions table
□ Implement execute_job function
□ Implement schedule_jobs function
□ Implement progress update function
□ Add all indexes for job queries
□ Test job execution flow
□ Test dependency checking
□ Test retry logic
□ Configure job scheduler integration
================================================================================
*/
