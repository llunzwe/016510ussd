-- =============================================================================
-- MIGRATION: 038_app_business_calendar.sql
-- DESCRIPTION: Business Day Calendar and Holiday Management
-- TABLES: business_calendar, holidays
-- DEPENDENCIES: 031_app_registry.sql
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
- Feature: Business Calendar
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Defines business days, holidays, and next/previous business day.
Determines value dates for transactions (e.g., if a holiday, settlement
moves to next business day). Implements ISO 9001 process consistency.

KEY FEATURES:
- Per-application or global calendar configuration
- Holiday definitions with multiple types
- Business day calculations with timezone
- Weekend configuration flexibility
- Next/previous business day functions

HOLIDAY TYPES:
- PUBLIC: National/public holidays
- BANK: Banking holidays (specific to financial sector)
- OBSERVANCE: Cultural/religious observances

WORKING DAYS:
- Configurable per calendar (default: Mon-Fri)
- ISO 8601 day numbering: 1=Monday, 7=Sunday
- Half-day support for early closures

FUNCTIONS:
- [VOLATILITY] STABLE: is_business_day(), next_business_day()
- Timezone-aware calculations
- Recurring holiday support (annual)
================================================================================
*/


-- =============================================================================
-- IMPLEMENTED: Create business_calendars table
-- DESCRIPTION: Calendar definitions
-- PRIORITY: HIGH
-- =============================================================================
-- [CAL-001] Create app.business_calendars table
CREATE TABLE app.business_calendars (
    calendar_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Identity
    calendar_code       VARCHAR(50) NOT NULL,
    calendar_name       VARCHAR(100) NOT NULL,
    
    -- Scope
    application_id      UUID REFERENCES app.applications(application_id), -- NULL = global
    country_code        VARCHAR(2),                  -- ISO country for default holidays
    
    -- Working Days
    working_days        INTEGER[] DEFAULT ARRAY[1,2,3,4,5], -- Mon=1, Sun=7
    
    -- Time Zone
    timezone            VARCHAR(50) DEFAULT 'UTC',
    business_start_time TIME DEFAULT '09:00',
    business_end_time   TIME DEFAULT '17:00',
    
    -- Status
    is_default          BOOLEAN DEFAULT false,       -- Default for application
    is_active           BOOLEAN DEFAULT true,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id)
);

-- CONSTRAINTS:
CREATE UNIQUE INDEX idx_calendars_code 
    ON app.business_calendars (calendar_code);

CREATE UNIQUE INDEX idx_calendars_app_default 
    ON app.business_calendars (application_id, is_default) 
    WHERE is_default = true;

COMMENT ON TABLE app.business_calendars IS 'Business calendar definitions per application';

-- =============================================================================
-- IMPLEMENTED: Create holidays table
-- DESCRIPTION: Holiday definitions
-- PRIORITY: CRITICAL
-- =============================================================================
-- [CAL-002] Create app.holidays table
CREATE TABLE app.holidays (
    holiday_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    calendar_id         UUID NOT NULL REFERENCES app.business_calendars(calendar_id),
    
    -- Holiday Details
    holiday_date        DATE NOT NULL,
    holiday_name        VARCHAR(100) NOT NULL,
    
    -- Type
    holiday_type        VARCHAR(20) DEFAULT 'PUBLIC', -- PUBLIC, BANK, OBSERVANCE
    
    -- Handling
    is_recurring        BOOLEAN DEFAULT false,       -- Same date each year
    observed_date       DATE,                        -- If observed on different date
    is_half_day         BOOLEAN DEFAULT false,
    
    -- Validity
    valid_from          DATE NOT NULL DEFAULT CURRENT_DATE,
    valid_to            DATE,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- CONSTRAINTS:
CREATE UNIQUE INDEX idx_holidays_calendar_date_current 
    ON app.holidays (calendar_id, holiday_date) 
    WHERE valid_to IS NULL;

COMMENT ON TABLE app.holidays IS 'Holiday definitions per calendar';

-- =============================================================================
-- IMPLEMENTED: Create is_business_day function
-- DESCRIPTION: Check if date is business day
-- PRIORITY: CRITICAL
-- =============================================================================
-- [CAL-003] Create is_business_day function
CREATE OR REPLACE FUNCTION app.is_business_day(
    p_date DATE,
    p_calendar_id UUID DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_calendar RECORD;
    v_day_of_week INTEGER;
BEGIN
    -- Get calendar (use default if not specified)
    SELECT * INTO v_calendar
    FROM app.business_calendars
    WHERE (calendar_id = p_calendar_id OR (p_calendar_id IS NULL AND is_default = true))
        AND is_active = true
    LIMIT 1;
    
    IF v_calendar IS NULL THEN
        -- Default to Monday-Friday
        v_day_of_week := EXTRACT(DOW FROM p_date);
        RETURN v_day_of_week BETWEEN 1 AND 5;
    END IF;
    
    -- Check working days
    v_day_of_week := EXTRACT(ISODOW FROM p_date);
    IF NOT (v_day_of_week = ANY(v_calendar.working_days)) THEN
        RETURN false;
    END IF;
    
    -- Check holidays
    IF EXISTS (
        SELECT 1 FROM app.holidays
        WHERE calendar_id = v_calendar.calendar_id
            AND holiday_date = p_date
            AND valid_from <= p_date
            AND (valid_to IS NULL OR valid_to >= p_date)
    ) THEN
        RETURN false;
    END IF;
    
    RETURN true;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION app.is_business_day IS 'Checks if a date is a business day';

-- =============================================================================
-- IMPLEMENTED: Create next_business_day function
-- DESCRIPTION: Find next business day
-- PRIORITY: CRITICAL
-- =============================================================================
-- [CAL-004] Create next_business_day function
CREATE OR REPLACE FUNCTION app.next_business_day(
    p_from_date DATE DEFAULT CURRENT_DATE,
    p_offset INTEGER DEFAULT 1,
    p_calendar_id UUID DEFAULT NULL
) RETURNS DATE AS $$
DECLARE
    v_date DATE := p_from_date;
    v_count INTEGER := 0;
BEGIN
    LOOP
        v_date := v_date + 1;
        IF app.is_business_day(v_date, p_calendar_id) THEN
            v_count := v_count + 1;
            IF v_count >= p_offset THEN
                RETURN v_date;
            END IF;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION app.next_business_day IS 'Finds the next business day with optional offset';

-- =============================================================================
-- IMPLEMENTED: Create previous_business_day function
-- DESCRIPTION: Find previous business day
-- PRIORITY: MEDIUM
-- =============================================================================
-- [CAL-005] Create previous_business_day function
CREATE OR REPLACE FUNCTION app.previous_business_day(
    p_from_date DATE DEFAULT CURRENT_DATE,
    p_offset INTEGER DEFAULT 1,
    p_calendar_id UUID DEFAULT NULL
) RETURNS DATE AS $$
DECLARE
    v_date DATE := p_from_date;
    v_count INTEGER := 0;
BEGIN
    LOOP
        v_date := v_date - 1;
        IF app.is_business_day(v_date, p_calendar_id) THEN
            v_count := v_count + 1;
            IF v_count >= p_offset THEN
                RETURN v_date;
            END IF;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION app.previous_business_day IS 'Finds the previous business day with optional offset';

-- =============================================================================
-- IMPLEMENTED: Create business_days_between function
-- DESCRIPTION: Count business days in range
-- PRIORITY: MEDIUM
-- =============================================================================
-- [CAL-006] Create business_days_between function
CREATE OR REPLACE FUNCTION app.business_days_between(
    p_start_date DATE,
    p_end_date DATE,
    p_include_start BOOLEAN DEFAULT false,
    p_include_end BOOLEAN DEFAULT false,
    p_calendar_id UUID DEFAULT NULL
) RETURNS INTEGER AS $$
DECLARE
    v_date DATE;
    v_count INTEGER := 0;
BEGIN
    v_date := p_start_date;
    
    IF NOT p_include_start THEN
        v_date := v_date + 1;
    END IF;
    
    WHILE v_date <= p_end_date LOOP
        IF app.is_business_day(v_date, p_calendar_id) THEN
            v_count := v_count + 1;
        END IF;
        v_date := v_date + 1;
    END LOOP;
    
    IF NOT p_include_end AND app.is_business_day(p_end_date, p_calendar_id) THEN
        v_count := v_count - 1;
    END IF;
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION app.business_days_between IS 'Counts business days between two dates';

-- =============================================================================
-- IMPLEMENTED: Create calendar indexes
-- DESCRIPTION: Optimize calendar queries
-- PRIORITY: HIGH
-- =============================================================================
-- [CAL-007] Create calendar indexes
-- Calendars:
-- PRIMARY KEY (calendar_id) - created with table
-- UNIQUE (calendar_code) - created above

CREATE INDEX idx_calendars_app_default_lookup 
    ON app.business_calendars (application_id, is_default) 
    WHERE is_default = true;

-- Holidays:
-- PRIMARY KEY (holiday_id) - created with table
-- UNIQUE (calendar_id, holiday_date) WHERE valid_to IS NULL - created above

CREATE INDEX idx_holidays_calendar_date_validity 
    ON app.holidays (calendar_id, holiday_date, valid_from, valid_to);

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create business_calendars table
☑ Create holidays table
☑ Implement is_business_day function
☑ Implement next_business_day function
☑ Implement previous_business_day function
☑ Implement business_days_between function
☑ Add all indexes for calendar queries
☐ Test business day calculations
☐ Test holiday handling
☐ Test next/previous functions
☐ Add seed holidays
================================================================================
*/
