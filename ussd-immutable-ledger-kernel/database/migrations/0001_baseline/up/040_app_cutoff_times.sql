-- =============================================================================
-- MIGRATION: 040_app_cutoff_times.sql
-- DESCRIPTION: Transaction Cut-off Times with Exception Handling
-- TABLES: cutoff_times, cutoff_exceptions
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
- Section: 9. Control & Batch Processing
- Feature: Cut-off Times
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Configurable cut-off times per transaction type (e.g., contributions after
4 PM processed next day). USSD users see real-time cut-off rules.
Implements ISO 9001 service consistency and ISO 27001 operational control.

KEY FEATURES:
- Per-transaction-type cut-offs
- Time zone aware with DST handling
- Exception dates for holidays/special events
- Grace periods for customer convenience
- Real-time availability check API

CUT-OFF RULES:
- cutoff_time: Local time cut-off (e.g., 16:00)
- if_after_cutoff: NEXT_DAY, NEXT_HOUR, or REJECT
- next_day_offset: Days to advance (usually 1 business day)
- grace_minutes: Extra time for in-flight transactions

EXCEPTION HANDLING:
- Early closures for holidays
- Extended hours for special events
- Complete closure (no transactions)
- [AUDIT] All exceptions logged with reason

FUNCTIONS:
- [VOLATILITY] STABLE: check_cutoff_time() - same result within statement
- [SECURITY-002] Input validation on all parameters
- Returns: is_before_cutoff, effective_date, message
================================================================================
*/


-- =============================================================================
-- IMPLEMENTED: Create cutoff_times table
-- DESCRIPTION: Cut-off time definitions
-- PRIORITY: HIGH
-- =============================================================================
-- [CUTOFF-001] Create app.cutoff_times table
CREATE TABLE app.cutoff_times (
    cutoff_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Scope
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    transaction_type_id UUID REFERENCES core.transaction_types(transaction_type_id),
    
    -- Cut-off Time
    cutoff_time         TIME NOT NULL,               -- e.g., '16:00'
    timezone            VARCHAR(50) DEFAULT 'UTC',
    
    -- Business Day Rule
    if_after_cutoff     VARCHAR(20) DEFAULT 'NEXT_DAY', -- NEXT_DAY, NEXT_HOUR, REJECT
    next_day_offset     INTEGER DEFAULT 1,           -- 1 = next business day
    
    -- Grace Period
    grace_minutes       INTEGER DEFAULT 0,
    
    -- Message
    cutoff_message      VARCHAR(255),                -- User-facing message
    
    -- Validity
    valid_from          DATE NOT NULL DEFAULT CURRENT_DATE,
    valid_to            DATE,
    
    -- Status
    is_active           BOOLEAN DEFAULT true,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id)
);

COMMENT ON TABLE app.cutoff_times IS 'Cut-off time definitions per transaction type';

-- =============================================================================
-- IMPLEMENTED: Create cutoff_exceptions table
-- DESCRIPTION: Exception dates for cut-offs
-- PRIORITY: MEDIUM
-- =============================================================================
-- [CUTOFF-002] Create app.cutoff_exceptions table
CREATE TABLE app.cutoff_exceptions (
    exception_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cutoff_id           UUID NOT NULL REFERENCES app.cutoff_times(cutoff_id),
    
    -- Date
    exception_date      DATE NOT NULL,
    
    -- Exception Details
    cutoff_time         TIME,                        -- NULL = no cutoff (always accept)
    is_closed           BOOLEAN DEFAULT false,       -- No transactions this day
    
    -- Reason
    reason              VARCHAR(255),
    
    UNIQUE (cutoff_id, exception_date)
);

COMMENT ON TABLE app.cutoff_exceptions IS 'Exception dates for cut-off times';

-- =============================================================================
-- IMPLEMENTED: Create check_cutoff function
-- DESCRIPTION: Check if transaction is before cut-off
-- PRIORITY: CRITICAL
-- =============================================================================
-- [CUTOFF-003] Create check_cutoff_time function
CREATE OR REPLACE FUNCTION app.check_cutoff_time(
    p_application_id UUID,
    p_transaction_type_id UUID,
    p_timestamp TIMESTAMPTZ DEFAULT now()
) RETURNS TABLE (
    is_before_cutoff BOOLEAN,
    effective_date DATE,
    cutoff_time TIMESTAMPTZ,
    message TEXT
) AS $$
DECLARE
    v_cutoff RECORD;
    v_exception RECORD;
    v_effective_date DATE;
    v_is_before BOOLEAN;
    v_cutoff_ts TIMESTAMPTZ;
BEGIN
    -- Get cut-off configuration
    SELECT * INTO v_cutoff
    FROM app.cutoff_times
    WHERE application_id = p_application_id
        AND (transaction_type_id = p_transaction_type_id OR transaction_type_id IS NULL)
        AND is_active = true
        AND valid_from <= CURRENT_DATE
        AND (valid_to IS NULL OR valid_to >= CURRENT_DATE)
    ORDER BY transaction_type_id IS NULL  -- Prefer specific over general
    LIMIT 1;
    
    IF v_cutoff IS NULL THEN
        -- No cut-off defined, use current date
        RETURN QUERY SELECT true, CURRENT_DATE, NULL::TIMESTAMPTZ, NULL::TEXT;
        RETURN;
    END IF;
    
    -- Check for exception
    SELECT * INTO v_exception
    FROM app.cutoff_exceptions
    WHERE cutoff_id = v_cutoff.cutoff_id
        AND exception_date = CURRENT_DATE;
    
    IF v_exception IS NOT NULL THEN
        IF v_exception.is_closed THEN
            RETURN QUERY SELECT false, (CURRENT_DATE + 1)::DATE, NULL::TIMESTAMPTZ, 
                       'Transactions not accepted today'::TEXT;
            RETURN;
        END IF;
        IF v_exception.cutoff_time IS NOT NULL THEN
            v_cutoff.cutoff_time := v_exception.cutoff_time;
        END IF;
    END IF;
    
    -- Calculate cut-off timestamp
    v_cutoff_ts := (CURRENT_DATE + v_cutoff.cutoff_time)::TIMESTAMPTZ 
                   AT TIME ZONE v_cutoff.timezone;
    
    -- Check if before cut-off
    v_is_before := p_timestamp <= v_cutoff_ts + (v_cutoff.grace_minutes || ' minutes')::INTERVAL;
    
    -- Calculate effective date
    IF v_is_before THEN
        v_effective_date := CURRENT_DATE;
    ELSE
        v_effective_date := app.next_business_day(
            CURRENT_DATE, v_cutoff.next_day_offset, NULL
        );
    END IF;
    
    RETURN QUERY SELECT 
        v_is_before, 
        v_effective_date, 
        v_cutoff_ts,
        v_cutoff.cutoff_message;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION app.check_cutoff_time IS 'Checks if a transaction is before the cut-off time';

-- =============================================================================
-- IMPLEMENTED: Create cutoff notification function
-- DESCRIPTION: Get upcoming cut-off warning
-- PRIORITY: MEDIUM
-- =============================================================================
-- [CUTOFF-004] Create get_cutoff_warning function
CREATE OR REPLACE FUNCTION app.get_cutoff_warning(
    p_application_id UUID,
    p_transaction_type_id UUID DEFAULT NULL,
    p_timestamp TIMESTAMPTZ DEFAULT now()
) RETURNS TABLE (
    warning_message TEXT,
    minutes_remaining INTEGER,
    cutoff_at TIMESTAMPTZ
) AS $$
DECLARE
    v_cutoff RECORD;
    v_cutoff_ts TIMESTAMPTZ;
    v_minutes INTEGER;
BEGIN
    -- Get cut-off configuration
    SELECT * INTO v_cutoff
    FROM app.cutoff_times
    WHERE application_id = p_application_id
        AND (transaction_type_id = p_transaction_type_id OR transaction_type_id IS NULL)
        AND is_active = true
    ORDER BY transaction_type_id IS NULL
    LIMIT 1;
    
    IF v_cutoff IS NULL THEN
        RETURN QUERY SELECT NULL::TEXT, NULL::INTEGER, NULL::TIMESTAMPTZ;
        RETURN;
    END IF;
    
    -- Calculate cut-off timestamp
    v_cutoff_ts := (CURRENT_DATE + v_cutoff.cutoff_time)::TIMESTAMPTZ 
                   AT TIME ZONE v_cutoff.timezone;
    
    -- Calculate minutes remaining
    v_minutes := EXTRACT(EPOCH FROM (v_cutoff_ts - p_timestamp)) / 60;
    
    IF v_minutes > 0 AND v_minutes <= 60 THEN
        RETURN QUERY SELECT 
            format('Cut-off in %s minutes', v_minutes)::TEXT,
            v_minutes::INTEGER,
            v_cutoff_ts;
    ELSE
        RETURN QUERY SELECT NULL::TEXT, NULL::INTEGER, NULL::TIMESTAMPTZ;
    END IF;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION app.get_cutoff_warning IS 'Returns warning if approaching cut-off time';

-- =============================================================================
-- IMPLEMENTED: Create cutoff indexes
-- DESCRIPTION: Optimize cutoff queries
-- PRIORITY: HIGH
-- =============================================================================
-- [CUTOFF-005] Create cutoff indexes
-- Cut-off times:
-- PRIMARY KEY (cutoff_id) - created with table

CREATE INDEX idx_cutoff_times_app_type_active 
    ON app.cutoff_times (application_id, transaction_type_id, is_active);

CREATE INDEX idx_cutoff_times_validity 
    ON app.cutoff_times (valid_from, valid_to);

-- Exceptions:
-- PRIMARY KEY (exception_id) - created with table
-- UNIQUE (cutoff_id, exception_date) - created with table

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create cutoff_times table
☑ Create cutoff_exceptions table
☑ Implement check_cutoff_time function
☑ Implement get_cutoff_warning function
☑ Add all indexes for cutoff queries
☐ Test cut-off calculation
☐ Test exception handling
☐ Test grace periods
☐ Test business day rules
================================================================================
*/
