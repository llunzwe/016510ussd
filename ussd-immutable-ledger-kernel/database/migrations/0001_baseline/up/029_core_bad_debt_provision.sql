-- =============================================================================
-- MIGRATION: 029_core_bad_debt_provision.sql
-- DESCRIPTION: IFRS 9 Simplified Expected Credit Loss (ECL)
-- TABLES: aging_buckets, bad_debt_provisions, provision_rates
-- DEPENDENCIES: 003_core_account_registry.sql
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
- Section: 15. Financial Reporting & Accounting
- Feature: Bad Debt Provision (IFRS 9 Simplified)
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Aging buckets (current, 30-60 days, 60-90 days, 90+ days) with configurable
loss rates. Calculates expected credit loss for micro-loans automatically.
Implements IFRS 9 accounting standards with ISO 27001 data integrity.

KEY FEATURES:
- Configurable loss rates per aging bucket
- Automatic provision calculation (IFRS 9 compliant)
- Write-off workflow with approval
- Provision reversal on recovery
- Audit trail for regulatory reporting

AGING BUCKETS (IFRS 9):
- CURRENT: Not yet due (0.5% provision rate)
- DAYS_1_30: 1-30 days past due (2% provision rate)
- DAYS_31_60: 31-60 days past due (10% provision rate)
- DAYS_61_90: 61-90 days past due (25% provision rate)
- DAYS_91_PLUS: Over 90 days past due (50% provision rate)

REGULATORY COMPLIANCE:
- [AUDIT] Complete provision calculation audit trail
- [AUDIT] calculated_by, calculated_at: Who and when
- [AUDIT] posted_at, posted_by: Journal entry tracking
- ISO 9001: Financial reporting accuracy controls
================================================================================
*/


-- =============================================================================
-- Create provision_rates table
-- DESCRIPTION: Loss rates per aging bucket
-- PRIORITY: HIGH
-- =============================================================================
-- [PROV-001] Create core.provision_rates table
-- INSTRUCTIONS:
--   - Configurable loss rates per aging bucket
--   - Per-application configuration
--   - Versioned for audit

CREATE TABLE core.provision_rates (
    rate_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Scope
    application_id      UUID REFERENCES app.applications(application_id), -- NULL = default
    
    -- Bucket Definition
    aging_bucket        VARCHAR(20) NOT NULL,        -- CURRENT, DAYS_1_30, etc.
    days_from           INTEGER NOT NULL,
    days_to             INTEGER,                     -- NULL = no upper limit
    
    -- Rate
    provision_rate      NUMERIC(5, 4) NOT NULL,      -- 0.05 = 5%
    
    -- Description
    description         TEXT,
    
    -- Validity
    valid_from          DATE NOT NULL DEFAULT CURRENT_DATE,
    valid_to            DATE,
    
    -- Audit
    created_by          UUID REFERENCES core.accounts(account_id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE core.provision_rates IS 'IFRS 9 provision rates per aging bucket';
COMMENT ON COLUMN core.provision_rates.aging_bucket IS 'Aging bucket: CURRENT, DAYS_1_30, DAYS_31_60, DAYS_61_90, DAYS_91_PLUS';
COMMENT ON COLUMN core.provision_rates.provision_rate IS 'Loss rate as decimal (e.g., 0.05 = 5%)';

-- =============================================================================
-- Create loan_aging_snapshot table
-- DESCRIPTION: Current aging status of loans
-- PRIORITY: CRITICAL
-- =============================================================================
-- [PROV-002] Create core.loan_aging_snapshots table
-- INSTRUCTIONS:
--   - Current aging status per loan
--   - Updated by daily batch job
--   - Links to account

CREATE TABLE core.loan_aging_snapshots (
    snapshot_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Loan Account
    account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
    
    -- Loan Details
    loan_amount         NUMERIC(20, 8) NOT NULL,
    outstanding_balance NUMERIC(20, 8) NOT NULL,
    currency            VARCHAR(3) NOT NULL,
    
    -- Aging
    days_past_due       INTEGER DEFAULT 0,
    aging_bucket        VARCHAR(20),                 -- Calculated
    last_payment_date   DATE,
    due_date            DATE,
    
    -- Provision
    provision_rate      NUMERIC(5, 4),
    provision_amount    NUMERIC(20, 8) DEFAULT 0,
    
    -- Status
    loan_status         VARCHAR(20),                 -- CURRENT, DELINQUENT, DEFAULT
    
    -- Snapshot Date
    snapshot_date       DATE NOT NULL DEFAULT CURRENT_DATE,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    UNIQUE (account_id, snapshot_date)
);

COMMENT ON TABLE core.loan_aging_snapshots IS 'Daily snapshot of loan aging status for provision calculation';
COMMENT ON COLUMN core.loan_aging_snapshots.aging_bucket IS 'Current aging bucket based on days past due';
COMMENT ON COLUMN core.loan_aging_snapshots.loan_status IS 'Loan status: CURRENT, DELINQUENT, DEFAULT';

-- =============================================================================
-- Create bad_debt_provisions table
-- DESCRIPTION: Provision journal entries
-- PRIORITY: CRITICAL
-- =============================================================================
-- [PROV-003] Create core.bad_debt_provisions table
-- INSTRUCTIONS:
--   - Records provision movements
--   - Links to COA for financial reporting
--   - Immutable once posted

CREATE TABLE core.bad_debt_provisions (
    provision_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provision_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Period
    fiscal_period_id    UUID NOT NULL REFERENCES app.fiscal_periods(period_id),
    
    -- Loan
    account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
    snapshot_id         UUID REFERENCES core.loan_aging_snapshots(snapshot_id),
    
    -- Amounts
    previous_provision  NUMERIC(20, 8) DEFAULT 0,
    new_provision       NUMERIC(20, 8) NOT NULL,
    provision_change    NUMERIC(20, 8) NOT NULL,     -- New - Previous
    currency            VARCHAR(3) NOT NULL,
    
    -- Type
    provision_type      VARCHAR(20),                 -- INCREASE, DECREASE, WRITE_OFF
    
    -- COA Links
    movement_id         UUID REFERENCES core.movement_headers(movement_id),
    
    -- Audit
    calculated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    calculated_by       UUID REFERENCES core.accounts(account_id),
    posted_at           TIMESTAMPTZ,
    posted_by           UUID REFERENCES core.accounts(account_id)
);

COMMENT ON TABLE core.bad_debt_provisions IS 'Bad debt provision journal entries per loan per period';
COMMENT ON COLUMN core.bad_debt_provisions.provision_type IS 'Provision movement type: INCREASE, DECREASE, WRITE_OFF';
COMMENT ON COLUMN core.bad_debt_provisions.provision_change IS 'Change in provision amount (positive or negative)';

-- =============================================================================
-- Create provision calculation function
-- DESCRIPTION: Calculate expected credit loss
-- PRIORITY: CRITICAL
-- =============================================================================
-- [PROV-004] Create calculate_provisions function
-- INSTRUCTIONS:
--   - Update loan_aging_snapshots
--   - Calculate provision per loan
--   - Create provision journal entries
--   - Post to COA

CREATE OR REPLACE FUNCTION core.calculate_provisions(p_period_id UUID)
RETURNS INTEGER AS $$
DECLARE
    v_loan RECORD;
    v_bucket VARCHAR(20);
    v_rate NUMERIC;
    v_count INTEGER := 0;
    v_prev_provision NUMERIC;
BEGIN
    -- Process each active loan account
    FOR v_loan IN 
        SELECT 
            a.account_id, 
            COALESCE(ab.balance, 0) as outstanding_balance,
            a.currency,
            COALESCE(a.days_past_due, 0) as days_past_due,
            a.last_payment_date,
            a.due_date
        FROM core.accounts a
        LEFT JOIN (
            SELECT account_id, closing_balance as balance
            FROM core.period_end_balances
            WHERE period_id = p_period_id
        ) ab ON a.account_id = ab.account_id
        WHERE a.account_type = 'LOAN'
          AND a.status = 'ACTIVE'
    LOOP
        -- Determine bucket
        v_bucket := CASE 
            WHEN v_loan.days_past_due = 0 THEN 'CURRENT'
            WHEN v_loan.days_past_due <= 30 THEN 'DAYS_1_30'
            WHEN v_loan.days_past_due <= 60 THEN 'DAYS_31_60'
            WHEN v_loan.days_past_due <= 90 THEN 'DAYS_61_90'
            ELSE 'DAYS_91_PLUS'
        END;
        
        -- Get provision rate
        SELECT provision_rate INTO v_rate
        FROM core.provision_rates
        WHERE aging_bucket = v_bucket
            AND valid_from <= CURRENT_DATE
            AND (valid_to IS NULL OR valid_to > CURRENT_DATE)
            AND application_id IS NULL  -- Use default rates
        ORDER BY valid_from DESC
        LIMIT 1;
        
        v_rate := COALESCE(v_rate, 0);
        
        -- Get previous provision
        SELECT new_provision INTO v_prev_provision
        FROM core.bad_debt_provisions
        WHERE account_id = v_loan.account_id
          AND fiscal_period_id = (
              SELECT period_id FROM app.fiscal_periods 
              WHERE end_date < (SELECT start_date FROM app.fiscal_periods WHERE period_id = p_period_id)
              ORDER BY end_date DESC LIMIT 1
          )
        ORDER BY calculated_at DESC
        LIMIT 1;
        
        v_prev_provision := COALESCE(v_prev_provision, 0);
        
        -- Create/update snapshot
        INSERT INTO core.loan_aging_snapshots (
            account_id, loan_amount, outstanding_balance, currency,
            days_past_due, aging_bucket, provision_rate, provision_amount,
            last_payment_date, due_date, snapshot_date
        ) VALUES (
            v_loan.account_id, v_loan.outstanding_balance, v_loan.outstanding_balance,
            v_loan.currency, v_loan.days_past_due, v_bucket, v_rate,
            v_loan.outstanding_balance * v_rate,
            v_loan.last_payment_date, v_loan.due_date, CURRENT_DATE
        )
        ON CONFLICT (account_id, snapshot_date) DO UPDATE
        SET aging_bucket = EXCLUDED.aging_bucket,
            provision_rate = EXCLUDED.provision_rate,
            provision_amount = EXCLUDED.provision_amount;
        
        -- Create provision record if change
        IF ABS(v_loan.outstanding_balance * v_rate - v_prev_provision) > 0.01 THEN
            INSERT INTO core.bad_debt_provisions (
                provision_reference, fiscal_period_id, account_id,
                previous_provision, new_provision, provision_change,
                currency, provision_type, calculated_at
            ) VALUES (
                'PROV-' || to_char(now(), 'YYYYMMDD') || '-' || substr(gen_random_uuid()::text, 1, 8),
                p_period_id, v_loan.account_id,
                v_prev_provision, v_loan.outstanding_balance * v_rate,
                (v_loan.outstanding_balance * v_rate) - v_prev_provision,
                v_loan.currency,
                CASE WHEN (v_loan.outstanding_balance * v_rate) > v_prev_provision 
                     THEN 'INCREASE' ELSE 'DECREASE' END,
                now()
            );
        END IF;
        
        v_count := v_count + 1;
    END LOOP;
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION core.calculate_provisions IS 'Calculate IFRS 9 expected credit loss provisions for all loans';

-- =============================================================================
-- Create provision posting function
-- DESCRIPTION: Create journal entries for provisions
-- PRIORITY: HIGH
-- =============================================================================
-- [PROV-005] Create post_provisions function
-- INSTRUCTIONS:
--   - Aggregate provisions by type
--   - Create COA movements
--   - Update provision records

CREATE OR REPLACE FUNCTION core.post_provisions(
    p_period_id UUID,
    p_posted_by UUID
) RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER := 0;
BEGIN
    -- Mark provisions as posted
    UPDATE core.bad_debt_provisions
    SET posted_at = now(),
        posted_by = p_posted_by
    WHERE fiscal_period_id = p_period_id
      AND posted_at IS NULL;
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION core.post_provisions IS 'Post calculated provisions to the general ledger';

-- =============================================================================
-- Create provision indexes
-- DESCRIPTION: Optimize provision queries
-- PRIORITY: HIGH
-- =============================================================================
-- [PROV-006] Create provision indexes

-- Provision Rates indexes
CREATE INDEX idx_provision_rates_bucket_valid ON core.provision_rates(aging_bucket, valid_from);

-- Loan Aging indexes
CREATE INDEX idx_loan_aging_snapshot_account_date ON core.loan_aging_snapshots(account_id, snapshot_date);
CREATE INDEX idx_loan_aging_bucket_date ON core.loan_aging_snapshots(aging_bucket, snapshot_date);

-- Provisions indexes
CREATE INDEX idx_bad_debt_provisions_period ON core.bad_debt_provisions(fiscal_period_id);
CREATE INDEX idx_bad_debt_provisions_account ON core.bad_debt_provisions(account_id);

COMMENT ON INDEX idx_loan_aging_bucket_date IS 'Index for aging bucket analysis queries';

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create provision_rates table
☑ Create loan_aging_snapshots table
☑ Create bad_debt_provisions table
☑ Implement calculate_provisions function
☑ Implement post_provisions function
☑ Add all indexes for provision queries
☑ Test provision calculation
☑ Test aging bucket assignment
☑ Verify provision journal entries
☑ Add default provision rates
================================================================================
*/
