-- =============================================================================
-- MIGRATION: 028_core_exchange_rates.sql
-- DESCRIPTION: Multi-Currency Exchange Rate Management with Bitemporal Validity
-- TABLES: exchange_rates, currency_pairs
-- DEPENDENCIES: 005_core_movement_legs.sql
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
- Feature: Multi-Currency Support
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Exchange rate table with bitemporal validity. Currency conversion function
for USSD apps operating in local currency while ledger uses stable currency.
Implements ISO 27001 data integrity and ISO 9001 accuracy controls.

KEY FEATURES:
- Bitemporal validity (system time vs valid time) for audit
- Rate source tracking for verification
- Automatic conversion function with precision handling
- Historical rate queries for reporting
- Rate change validation and alerting

RATE TYPES:
- SPOT: Current market rate
- AVERAGE: Period average for reporting
- CLOSING: End-of-day rate
- BUY: Rate for buying foreign currency
- SELL: Rate for selling foreign currency

DATA QUALITY (ISO 9001):
- [ERROR-002] RAISE EXCEPTION for missing rates
- [AUDIT] Rate source tracking and timestamp
- [AUDIT] Manual rate entry flagged and logged
- Rate validation against threshold limits

FUNCTION VOLATILITY:
- [VOLATILITY] STABLE: convert_currency() - same result within statement
- [SECURITY-001] SECURITY DEFINER for rate administration
================================================================================
*/


-- =============================================================================
-- TODO: Create currency_pairs table
-- DESCRIPTION: Supported currency combinations
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [FX-001] Create core.currency_pairs table
-- INSTRUCTIONS:
--   - Define supported currency pairs
--   - Precision and rounding rules
--   - Rate source configuration
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.currency_pairs (
--       pair_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Currencies (ISO 4217)
--       from_currency       VARCHAR(3) NOT NULL,
--       to_currency         VARCHAR(3) NOT NULL,
--       
--       -- Configuration
--       display_precision   INTEGER DEFAULT 4,           -- Decimal places to display
--       calculation_precision INTEGER DEFAULT 10,
--       rounding_method     VARCHAR(20) DEFAULT 'HALF_UP',
--       
--       -- Source
--       rate_source         VARCHAR(100),                -- Provider name
--       update_frequency    VARCHAR(20) DEFAULT 'DAILY', -- REALTIME, HOURLY, DAILY
--       
--       -- Status
--       is_active           BOOLEAN DEFAULT true,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       
--       UNIQUE (from_currency, to_currency)
--   );

-- =============================================================================
-- TODO: Create exchange_rates table
-- DESCRIPTION: Historical exchange rates
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [FX-002] Create core.exchange_rates table
-- INSTRUCTIONS:
--   - Bitemporal validity for audit
--   - Multiple rate types per pair
--   - Source and method tracking
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.exchange_rates (
--       rate_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       pair_id             UUID NOT NULL REFERENCES core.currency_pairs(pair_id),
--       
--       -- Rate Details
--       rate_type           VARCHAR(20) NOT NULL,        -- SPOT, AVERAGE, CLOSING, BUY, SELL
--       rate                NUMERIC(20, 10) NOT NULL,
--       
--       -- Inverse Rate (for reverse conversion)
--       inverse_rate        NUMERIC(20, 10),
--       
--       -- Validity Period (bitemporal)
--       valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       valid_to            TIMESTAMPTZ,                 -- NULL = current
--       rate_date           DATE NOT NULL,               -- Business date
--       
--       -- Source
--       source_reference    VARCHAR(255),                -- Feed reference
--       source_timestamp    TIMESTAMPTZ,
--       
--       -- Metadata
--       is_manual           BOOLEAN DEFAULT false,
--       entered_by          UUID REFERENCES core.accounts(account_id),
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       superseded_by       UUID REFERENCES core.exchange_rates(rate_id)
--   );
--
-- CONSTRAINTS:
--   - EXCLUDE USING gist (pair_id WITH =, rate_type WITH =, valid_during WITH &&)
--   - CHECK (rate > 0)

-- =============================================================================
-- TODO: Create currency conversion function
-- DESCRIPTION: Convert amounts between currencies
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [FX-003] Create convert_currency function
-- INSTRUCTIONS:
--   - Look up rate for date
--   - Apply precision and rounding
--   - Handle missing rates
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.convert_currency(
--       p_amount NUMERIC,
--       p_from_currency VARCHAR(3),
--       p_to_currency VARCHAR(3),
--       p_rate_type VARCHAR(20) DEFAULT 'SPOT',
--       p_as_of TIMESTAMPTZ DEFAULT now()
--   ) RETURNS NUMERIC AS $$
--   DECLARE
--       v_rate NUMERIC;
--       v_pair RECORD;
--       v_result NUMERIC;
--   BEGIN
--       -- Same currency
--       IF p_from_currency = p_to_currency THEN
--           RETURN p_amount;
--       END IF;
--       
--       -- Get pair config
--       SELECT * INTO v_pair 
--       FROM core.currency_pairs 
--       WHERE from_currency = p_from_currency AND to_currency = p_to_currency;
--       
--       -- Get rate
--       SELECT rate INTO v_rate
--       FROM core.exchange_rates
--       WHERE pair_id = v_pair.pair_id
--           AND rate_type = p_rate_type
--           AND valid_from <= p_as_of
--           AND (valid_to IS NULL OR valid_to > p_as_of)
--       ORDER BY valid_from DESC
--       LIMIT 1;
--       
--       IF v_rate IS NULL THEN
--           RAISE EXCEPTION 'No rate found for %/% type % as of %', 
--               p_from_currency, p_to_currency, p_rate_type, p_as_of;
--       END IF;
--       
--       -- Convert
--       v_result := p_amount * v_rate;
--       
--       -- Round
--       RETURN ROUND(v_result, v_pair.display_precision);
--   END;
--   $$ LANGUAGE plpgsql STABLE;

-- =============================================================================
-- TODO: Create rate import function
-- DESCRIPTION: Import rates from external feed
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [FX-004] Create import_exchange_rates function
-- INSTRUCTIONS:
--   - Accept rates from external feed
--   - Validate against thresholds
--   - Insert with validity period
--   - Handle rate updates (supersede old rates)

-- =============================================================================
-- TODO: Create rate validation trigger
-- DESCRIPTION: Validate new rates
-- PRIORITY: MEDIUM
-- =============================================================================
-- TODO: [FX-005] Create validate_rate_change trigger
-- INSTRUCTIONS:
--   - Check rate is within acceptable bounds
--   - Alert on large changes
--   - Require approval for manual rates

-- =============================================================================
-- TODO: Create exchange rate indexes
-- DESCRIPTION: Optimize rate queries
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [FX-006] Create exchange rate indexes
-- INDEX LIST:
--   -- Currency Pairs:
--   - PRIMARY KEY (pair_id)
--   - UNIQUE (from_currency, to_currency)
--   -- Exchange Rates:
--   - PRIMARY KEY (rate_id)
--   - INDEX on (pair_id, rate_type, valid_from DESC)
--   - INDEX on (rate_date)
--   - INDEX on (superseded_by)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create currency_pairs table
□ Create exchange_rates table with bitemporal validity
□ Implement convert_currency function
□ Implement import_exchange_rates function
□ Implement rate validation trigger
□ Add all indexes for rate queries
□ Test currency conversion
□ Test bitemporal rate lookup
□ Verify exchange rate calculations
□ Add seed currency pairs
================================================================================
*/
