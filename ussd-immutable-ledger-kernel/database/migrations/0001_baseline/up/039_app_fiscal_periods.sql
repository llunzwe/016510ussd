-- =============================================================================
-- MIGRATION: 039_app_fiscal_periods.sql
-- DESCRIPTION: Fiscal Periods and Year-End Closing
-- TABLES: fiscal_years, fiscal_periods, period_status
-- DEPENDENCIES: 038_app_business_calendar.sql
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
- Feature: Fiscal Periods
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Defines months, quarters, years with open/closed status. Closing a period
prevents further changes and runs accruals. Implements ISO 27001 change
control and ISO 9001 financial reporting accuracy.

KEY FEATURES:
- Period locking preventing changes (ISO 27001 A.12.1)
- Accrual handling with audit trail
- Year-end rollover automation
- Multi-year support for long-term reporting
- Period status monitoring

PERIOD TYPES:
- MONTH: Monthly accounting period
- QUARTER: Quarterly reporting period
- YEAR: Fiscal year
- CUSTOM: Special/adjusting periods

STATUS LIFECYCLE:
- OPEN: Transactions allowed
- CLOSING: In process of closing (freeze new transactions)
- CLOSED: Locked, no changes allowed (ISO 27001 control)
- FROZEN: Temporarily locked for audit/reconciliation

CLOSING VALIDATION:
- [SECURITY-002] Verify prior periods closed
- [ERROR-002] Check for unposted transactions
- [AUDIT] closed_by, closed_at: Closing audit trail
- [TRANSACTION] Atomic period close operation
================================================================================
*/


-- =============================================================================
-- IMPLEMENTED: Create fiscal_years table
-- DESCRIPTION: Fiscal year definitions
-- PRIORITY: HIGH
-- =============================================================================
-- [FP-001] Create app.fiscal_years table
CREATE TABLE app.fiscal_years (
    year_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Identity
    year_number         INTEGER NOT NULL,
    year_name           VARCHAR(50) NOT NULL,
    
    -- Scope
    application_id      UUID REFERENCES app.applications(application_id),
    
    -- Dates
    start_date          DATE NOT NULL,
    end_date            DATE NOT NULL,
    
    -- Status
    status              VARCHAR(20) DEFAULT 'OPEN',  -- OPEN, CLOSING, CLOSED
    
    -- Closing
    closed_at           TIMESTAMPTZ,
    closed_by           UUID REFERENCES core.accounts(account_id),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- CONSTRAINTS:
CREATE UNIQUE INDEX idx_fiscal_years_app_number 
    ON app.fiscal_years (application_id, year_number);

ALTER TABLE app.fiscal_years
    ADD CONSTRAINT chk_fiscal_years_dates 
        CHECK (end_date > start_date);

COMMENT ON TABLE app.fiscal_years IS 'Fiscal year definitions per application';

-- =============================================================================
-- IMPLEMENTED: Create fiscal_periods table
-- DESCRIPTION: Individual periods (months, quarters)
-- PRIORITY: CRITICAL
-- =============================================================================
-- [FP-002] Create app.fiscal_periods table
CREATE TABLE app.fiscal_periods (
    period_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Identity
    period_code         VARCHAR(20) NOT NULL,        -- "2024-01", "2024-Q1"
    period_name         VARCHAR(50) NOT NULL,
    
    -- Classification
    period_type         VARCHAR(20) NOT NULL,        -- MONTH, QUARTER, YEAR, CUSTOM
    
    -- Parent
    fiscal_year_id      UUID REFERENCES app.fiscal_years(year_id),
    parent_period_id    UUID REFERENCES app.fiscal_periods(period_id),
    
    -- Scope
    application_id      UUID REFERENCES app.applications(application_id),
    
    -- Dates
    start_date          DATE NOT NULL,
    end_date            DATE NOT NULL,
    
    -- Status
    status              VARCHAR(20) DEFAULT 'OPEN',  -- OPEN, CLOSING, CLOSED, FROZEN
    
    -- Closing
    pre_closed_at       TIMESTAMPTZ,
    closed_at           TIMESTAMPTZ,
    closed_by           UUID REFERENCES core.accounts(account_id),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- CONSTRAINTS:
CREATE UNIQUE INDEX idx_fiscal_periods_app_code 
    ON app.fiscal_periods (application_id, period_code);

ALTER TABLE app.fiscal_periods
    ADD CONSTRAINT chk_fiscal_periods_dates 
        CHECK (end_date > start_date);

COMMENT ON TABLE app.fiscal_periods IS 'Individual fiscal periods (months, quarters) per application';

-- =============================================================================
-- IMPLEMENTED: Create get_current_period function
-- DESCRIPTION: Get current fiscal period
-- PRIORITY: HIGH
-- =============================================================================
-- [FP-003] Create get_current_fiscal_period function
CREATE OR REPLACE FUNCTION app.get_current_fiscal_period(
    p_application_id UUID DEFAULT NULL,
    p_date DATE DEFAULT CURRENT_DATE
) RETURNS UUID AS $$
DECLARE
    v_period_id UUID;
BEGIN
    SELECT period_id INTO v_period_id
    FROM app.fiscal_periods
    WHERE (application_id = p_application_id OR p_application_id IS NULL)
        AND start_date <= p_date AND end_date >= p_date
    ORDER BY start_date DESC
    LIMIT 1;
    
    RETURN v_period_id;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION app.get_current_fiscal_period IS 'Gets the current fiscal period for a date';

-- =============================================================================
-- IMPLEMENTED: Create close_period function
-- DESCRIPTION: Close fiscal period
-- PRIORITY: CRITICAL
-- =============================================================================
-- [FP-004] Create close_fiscal_period function
CREATE OR REPLACE FUNCTION app.close_fiscal_period(
    p_period_id UUID,
    p_closed_by UUID
) RETURNS VARCHAR AS $$
DECLARE
    v_period RECORD;
    v_unposted INTEGER;
BEGIN
    -- Get period
    SELECT * INTO v_period FROM app.fiscal_periods WHERE period_id = p_period_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Period not found: %', p_period_id;
    END IF;
    
    -- Check prior periods
    IF EXISTS (
        SELECT 1 FROM app.fiscal_periods
        WHERE application_id = v_period.application_id
            AND end_date < v_period.start_date
            AND status != 'CLOSED'
    ) THEN
        RAISE EXCEPTION 'Prior periods must be closed first';
    END IF;
    
    -- Check for unposted transactions (using movement_headers if available)
    SELECT COUNT(*) INTO v_unposted
    FROM core.movement_headers
    WHERE accounting_date BETWEEN v_period.start_date AND v_period.end_date
        AND status != 'POSTED';
    
    IF v_unposted > 0 THEN
        RAISE EXCEPTION 'Unposted transactions exist in period';
    END IF;
    
    -- Close period
    UPDATE app.fiscal_periods
    SET status = 'CLOSED', closed_at = now(), closed_by = p_closed_by
    WHERE period_id = p_period_id;
    
    RETURN 'CLOSED';
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION app.close_fiscal_period IS 'Closes a fiscal period after validation';

-- =============================================================================
-- IMPLEMENTED: Create period status view
-- DESCRIPTION: Period status summary
-- PRIORITY: MEDIUM
-- =============================================================================
-- [FP-005] Create period_status view
CREATE VIEW app.period_status AS
SELECT 
    fp.*,
    fy.year_name,
    CASE 
        WHEN fp.status = 'OPEN' THEN 'Transactions allowed'
        WHEN fp.status = 'CLOSING' THEN 'Closing in progress'
        WHEN fp.status = 'CLOSED' THEN 'Period locked'
        WHEN fp.status = 'FROZEN' THEN 'Temporarily frozen'
    END as status_description,
    CURRENT_DATE BETWEEN fp.start_date AND fp.end_date as is_current_period
FROM app.fiscal_periods fp
LEFT JOIN app.fiscal_years fy ON fp.fiscal_year_id = fy.year_id;

COMMENT ON VIEW app.period_status IS 'Fiscal period status summary with year information';

-- =============================================================================
-- IMPLEMENTED: Create fiscal period indexes
-- DESCRIPTION: Optimize period queries
-- PRIORITY: HIGH
-- =============================================================================
-- [FP-006] Create fiscal period indexes
-- Years:
-- PRIMARY KEY (year_id) - created with table
-- UNIQUE (application_id, year_number) - created above

CREATE INDEX idx_fiscal_years_app_status 
    ON app.fiscal_years (application_id, status);

-- Periods:
-- PRIMARY KEY (period_id) - created with table
-- UNIQUE (application_id, period_code) - created above

CREATE INDEX idx_fiscal_periods_app_dates 
    ON app.fiscal_periods (application_id, start_date, end_date);

CREATE INDEX idx_fiscal_periods_year_type 
    ON app.fiscal_periods (fiscal_year_id, period_type);

CREATE INDEX idx_fiscal_periods_status_app 
    ON app.fiscal_periods (status, application_id);

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create fiscal_years table
☑ Create fiscal_periods table
☑ Implement get_current_fiscal_period function
☑ Implement close_fiscal_period function
☑ Create period_status view
☑ Add all indexes for period queries
☐ Test period closing workflow
☐ Test prior period validation
☐ Verify period locking
☐ Add seed fiscal periods
================================================================================
*/
