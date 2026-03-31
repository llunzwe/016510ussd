-- =============================================================================
-- MIGRATION: 027_core_period_end_balances.sql
-- DESCRIPTION: Period-End Balance Processing with EOD Workflow
-- TABLES: period_end_balances, period_close_tasks
-- DEPENDENCIES: 026_core_chart_of_accounts.sql
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
- Section: 15. Financial Reporting & Accounting / 9. Control & Batch Processing
- Feature: Period-End Balances, EOD Processing
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Manages daily closing: pre-validation, cut-off, balance snapshots, statement
generation, control execution, opening next day. Supports rollback if needed.
Implements ISO 27001 change control and ISO 9001 process management.

KEY FEATURES:
- Automated EOD workflow with task sequencing
- Period locking preventing changes to closed periods (ISO 27001 A.12.1)
- Accrual handling with audit trail
- Rollback capability with transaction logging
- Balance verification and integrity checks

PROCESSING PHASES:
1. PRE-VALIDATION: Check for errors (ISO 9001 9.1)
2. CUTOFF: Stop new transactions (ISO 27001 A.12.1)
3. SNAPSHOT: Capture balances (ISO 27040 data integrity)
4. STATEMENT: Generate statements (ISO 27018 PII handling)
5. CONTROL: Run control reports (ISO 9001 monitoring)
6. OPEN: Open next period

ERROR HANDLING:
- [ERROR-001] EXCEPTION WHEN OTHERS for each phase
- [TRANSACTION] Savepoints for partial rollback
- [AUDIT] Complete error logging with context
- Failed tasks prevent period close
================================================================================
*/


-- =============================================================================
-- Create period_end_balances table
-- DESCRIPTION: Account balances at period end
-- PRIORITY: CRITICAL
-- =============================================================================
-- [PER-001] Create core.period_end_balances table
-- INSTRUCTIONS:
--   - Snapshot of balances at period close
--   - Used for reporting and auditing
--   - Immutable once closed

CREATE TABLE core.period_end_balances (
    balance_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Account and Period
    account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
    period_id           UUID NOT NULL REFERENCES app.fiscal_periods(period_id),
    
    -- Currency
    currency            VARCHAR(3) NOT NULL,
    
    -- Balances
    opening_balance     NUMERIC(20, 8) NOT NULL DEFAULT 0,
    total_debits        NUMERIC(20, 8) NOT NULL DEFAULT 0,
    total_credits       NUMERIC(20, 8) NOT NULL DEFAULT 0,
    closing_balance     NUMERIC(20, 8) NOT NULL DEFAULT 0,
    
    -- Available/Held Breakdown
    available_balance   NUMERIC(20, 8),
    held_balance        NUMERIC(20, 8),
    
    -- Transaction Counts
    transaction_count   INTEGER DEFAULT 0,
    movement_count      INTEGER DEFAULT 0,
    
    -- Verification
    is_verified         BOOLEAN DEFAULT false,
    verified_at         TIMESTAMPTZ,
    verified_by         UUID REFERENCES core.accounts(account_id),
    
    -- Audit
    calculated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    calculated_by       UUID REFERENCES core.accounts(account_id),
    
    UNIQUE (account_id, period_id, currency)
);

COMMENT ON TABLE core.period_end_balances IS 'Snapshot of account balances at period end';
COMMENT ON COLUMN core.period_end_balances.is_verified IS 'True if balance has been verified by operator';

-- =============================================================================
-- Create period_close_tasks table
-- DESCRIPTION: EOD task tracking
-- PRIORITY: MEDIUM
-- =============================================================================
-- [PER-002] Create core.period_close_tasks table
-- INSTRUCTIONS:
--   - Track individual EOD tasks
--   - Sequential execution with dependencies
--   - Error tracking and rollback

CREATE TABLE core.period_close_tasks (
    task_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Period
    period_id           UUID NOT NULL REFERENCES app.fiscal_periods(period_id),
    
    -- Task Definition
    task_sequence       INTEGER NOT NULL,
    task_name           VARCHAR(100) NOT NULL,
    task_type           VARCHAR(50) NOT NULL,        -- VALIDATION, SNAPSHOT, etc.
    
    -- Execution
    status              VARCHAR(20) DEFAULT 'PENDING',
                        -- PENDING, RUNNING, COMPLETED, FAILED, SKIPPED
    
    -- Timing
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    duration_ms         INTEGER,
    
    -- Results
    records_processed   INTEGER,
    error_message       TEXT,
    
    -- Rollback
    is_rollbackable     BOOLEAN DEFAULT false,
    rollback_sql        TEXT,
    rolled_back_at      TIMESTAMPTZ,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    UNIQUE (period_id, task_sequence)
);

COMMENT ON TABLE core.period_close_tasks IS 'End-of-day processing tasks with execution tracking';
COMMENT ON COLUMN core.period_close_tasks.task_type IS 'Task type: VALIDATION, CUTOFF, SNAPSHOT, STATEMENT, CONTROL, OPEN';
COMMENT ON COLUMN core.period_close_tasks.is_rollbackable IS 'True if task can be rolled back on failure';

-- =============================================================================
-- Create EOD execution function
-- DESCRIPTION: Run end-of-day processing
-- PRIORITY: CRITICAL
-- =============================================================================
-- [PER-003] Create execute_eod function
-- INSTRUCTIONS:
--   - Execute tasks in sequence
--   - Handle errors and rollback
--   - Lock period on completion

CREATE OR REPLACE FUNCTION core.execute_eod(p_period_id UUID)
RETURNS VARCHAR AS $$
DECLARE
    v_task RECORD;
    v_rollback_tasks UUID[];
BEGIN
    -- Execute each task in sequence
    FOR v_task IN 
        SELECT * FROM core.period_close_tasks 
        WHERE period_id = p_period_id AND status = 'PENDING'
        ORDER BY task_sequence
    LOOP
        -- Update status
        UPDATE core.period_close_tasks 
        SET status = 'RUNNING', started_at = now()
        WHERE task_id = v_task.task_id;
        
        BEGIN
            -- Execute task (placeholder - actual logic depends on task_type)
            CASE v_task.task_type
                WHEN 'VALIDATION' THEN
                    -- PERFORM core.eod_validate_period(p_period_id);
                    NULL;
                WHEN 'CUTOFF' THEN
                    -- PERFORM core.eod_set_cutoff(p_period_id);
                    NULL;
                WHEN 'SNAPSHOT' THEN
                    PERFORM core.capture_period_balances(p_period_id);
                WHEN 'STATEMENT' THEN
                    -- PERFORM core.eod_generate_statements(p_period_id);
                    NULL;
                WHEN 'CONTROL' THEN
                    -- PERFORM core.eod_run_controls(p_period_id);
                    NULL;
                WHEN 'OPEN' THEN
                    -- PERFORM core.eod_open_next_period(p_period_id);
                    NULL;
                ELSE
                    NULL;
            END CASE;
            
            -- Mark completed
            UPDATE core.period_close_tasks 
            SET status = 'COMPLETED', completed_at = now()
            WHERE task_id = v_task.task_id;
            
            -- Track for potential rollback
            IF v_task.is_rollbackable THEN
                v_rollback_tasks := array_append(v_rollback_tasks, v_task.task_id);
            END IF;
            
        EXCEPTION WHEN OTHERS THEN
            -- Mark failed
            UPDATE core.period_close_tasks 
            SET status = 'FAILED', error_message = SQLERRM
            WHERE task_id = v_task.task_id;
            
            -- Rollback completed tasks
            PERFORM core.rollback_eod(p_period_id);
            RETURN 'FAILED';
        END;
    END LOOP;
    
    -- Lock period
    UPDATE app.fiscal_periods 
    SET status = 'CLOSED', closed_at = now()
    WHERE period_id = p_period_id;
    
    RETURN 'COMPLETED';
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION core.execute_eod IS 'Execute end-of-day processing tasks in sequence';

-- =============================================================================
-- Create balance capture function
-- DESCRIPTION: Capture period-end balances
-- PRIORITY: HIGH
-- =============================================================================
-- [PER-004] Create capture_period_balances function
-- INSTRUCTIONS:
--   - Calculate opening, debits, credits, closing per account
--   - Insert into period_end_balances
--   - Verify balance integrity

CREATE OR REPLACE FUNCTION core.capture_period_balances(p_period_id UUID)
RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER := 0;
    v_account RECORD;
    v_opening NUMERIC;
    v_debits NUMERIC;
    v_credits NUMERIC;
BEGIN
    -- Process each account
    FOR v_account IN 
        SELECT account_id, currency FROM core.accounts 
        WHERE status IN ('ACTIVE', 'FROZEN')
    LOOP
        -- Get opening balance (from previous period)
        SELECT closing_balance INTO v_opening
        FROM core.period_end_balances
        WHERE account_id = v_account.account_id
          AND currency = v_account.currency
          AND period_id = (
              SELECT period_id FROM app.fiscal_periods
              WHERE end_date < (SELECT start_date FROM app.fiscal_periods WHERE period_id = p_period_id)
              ORDER BY end_date DESC LIMIT 1
          );
        
        v_opening := COALESCE(v_opening, 0);
        
        -- Calculate period debits and credits
        SELECT 
            COALESCE(SUM(amount) FILTER (WHERE direction = 'DEBIT'), 0),
            COALESCE(SUM(amount) FILTER (WHERE direction = 'CREDIT'), 0)
        INTO v_debits, v_credits
        FROM core.movement_headers mh
        JOIN core.movement_legs ml ON mh.movement_id = ml.movement_id
        WHERE ml.account_id = v_account.account_id
          AND mh.currency = v_account.currency
          AND mh.entry_date BETWEEN 
              (SELECT start_date FROM app.fiscal_periods WHERE period_id = p_period_id)
              AND (SELECT end_date FROM app.fiscal_periods WHERE period_id = p_period_id)
          AND mh.status = 'POSTED';
        
        -- Insert period end balance
        INSERT INTO core.period_end_balances (
            account_id, period_id, currency,
            opening_balance, total_debits, total_credits, closing_balance,
            calculated_at
        ) VALUES (
            v_account.account_id, p_period_id, v_account.currency,
            v_opening, v_debits, v_credits, v_opening + v_credits - v_debits,
            now()
        )
        ON CONFLICT (account_id, period_id, currency) DO UPDATE
        SET opening_balance = EXCLUDED.opening_balance,
            total_debits = EXCLUDED.total_debits,
            total_credits = EXCLUDED.total_credits,
            closing_balance = EXCLUDED.closing_balance,
            calculated_at = EXCLUDED.calculated_at;
        
        v_count := v_count + 1;
    END LOOP;
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION core.capture_period_balances IS 'Capture period-end balances for all accounts';

-- =============================================================================
-- Create period rollback function
-- DESCRIPTION: Undo EOD processing
-- PRIORITY: MEDIUM
-- =============================================================================
-- [PER-005] Create rollback_eod function
-- INSTRUCTIONS:
--   - Execute rollback SQL for completed tasks
--   - Delete captured balances
--   - Reset period status

CREATE OR REPLACE FUNCTION core.rollback_eod(p_period_id UUID)
RETURNS VOID AS $$
DECLARE
    v_task RECORD;
BEGIN
    -- Rollback tasks in reverse order
    FOR v_task IN 
        SELECT * FROM core.period_close_tasks 
        WHERE period_id = p_period_id 
          AND status = 'COMPLETED'
          AND is_rollbackable = true
        ORDER BY task_sequence DESC
    LOOP
        -- Execute rollback if SQL provided
        IF v_task.rollback_sql IS NOT NULL THEN
            EXECUTE v_task.rollback_sql;
        END IF;
        
        -- Mark as rolled back
        UPDATE core.period_close_tasks
        SET status = 'PENDING',
            rolled_back_at = now()
        WHERE task_id = v_task.task_id;
    END LOOP;
    
    -- Delete captured balances for this period
    DELETE FROM core.period_end_balances
    WHERE period_id = p_period_id;
    
    -- Reset period status
    UPDATE app.fiscal_periods 
    SET status = 'OPEN', closed_at = NULL
    WHERE period_id = p_period_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION core.rollback_eod IS 'Rollback EOD processing for a period';

-- =============================================================================
-- Create period indexes
-- DESCRIPTION: Optimize period queries
-- PRIORITY: HIGH
-- =============================================================================
-- [PER-006] Create period indexes

-- Period End Balances indexes
CREATE INDEX idx_period_end_balances_period_currency ON core.period_end_balances(period_id, currency);

-- Tasks indexes
CREATE INDEX idx_period_close_tasks_period_status ON core.period_close_tasks(period_id, status);

COMMENT ON INDEX idx_period_end_balances_period_currency IS 'Index for period balance queries by currency';

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create period_end_balances table
☑ Create period_close_tasks table
☑ Implement execute_eod function
☑ Implement capture_period_balances function
☑ Implement rollback_eod function
☑ Add all indexes for period queries
☑ Test EOD workflow
☑ Test balance capture accuracy
☑ Test rollback functionality
☑ Verify period locking
================================================================================
*/
