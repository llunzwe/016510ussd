-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Monitoring and measurement)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Cloud data partitioning)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Balance data privacy)
-- ISO/IEC 27040:2024 - Storage Security (Time-series data protection)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Point-in-time recovery)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - TimescaleDB hypertable for automatic partitioning
-- - Compression policies for storage efficiency
-- - Running balance calculation with advisory locks
-- - Materialized views for performance
-- ============================================================================
-- =============================================================================
-- MIGRATION: 006_core_movement_postings.sql
-- DESCRIPTION: Balance History & Running Balances (Time-Series)
-- TABLES: movement_postings, balance_snapshots
-- DEPENDENCIES: 005_core_movement_legs.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 2. Core Immutable Ledger / 5. Query & Retrieval
- Feature: Movement Postings, Account State Snapshot
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Time-series table recording running balance per container after each movement.
Enables efficient historical balance queries without replaying entire log.
Optimized for TimescaleDB hypertable for time-series performance.

KEY FEATURES:
- TimescaleDB hypertable for automatic partitioning
- Records balance after each movement leg
- Supports point-in-time balance queries
- Enables trend analysis and reporting
- Compressed historical data for storage efficiency

USSD USE CASES:
- "What was my balance on 1st March?"
- Daily balance notifications
- Overdraft protection checks
- Interest calculation basis
================================================================================
*/

-- =============================================================================
-- TODO: Create movement_postings table
-- DESCRIPTION: Time-series of account balances
-- PRIORITY: CRITICAL
-- SECURITY: Hypertable partitioning by time
-- ============================================================================
-- TODO: [POST-001] Create core.movement_postings table
-- INSTRUCTIONS:
--   - Convert to TimescaleDB hypertable after creation
--   - One row per movement leg per account
--   - Captures running balance at posting time
--   - RLS POLICY: Tenant isolation by application_id
--   - ERROR HANDLING: Handle partition boundary violations
-- COMPLIANCE: ISO/IEC 27040 (Time-Series Optimization)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.movement_postings (
--       -- Identity
--       posting_id          UUID NOT NULL DEFAULT gen_random_uuid(),
--       
--       -- Reference to source
--       movement_id         UUID NOT NULL REFERENCES core.movement_headers(movement_id),
--       leg_id              UUID NOT NULL REFERENCES core.movement_legs(leg_id),
--       
--       -- Account
--       account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
--       
--       -- Movement Details
--       direction           VARCHAR(6) NOT NULL,         -- 'DEBIT' or 'CREDIT'
--       amount              NUMERIC(20, 8) NOT NULL,
--       currency            VARCHAR(3) NOT NULL,
--       
--       -- Running Balance (denormalized for query performance)
--       running_balance     NUMERIC(20, 8) NOT NULL,     -- Balance after this posting
--       previous_balance    NUMERIC(20, 8) NOT NULL,     -- Balance before this posting
--       
--       -- Balance Categories
--       available_balance   NUMERIC(20, 8),              -- Available (excluding holds)
--       held_balance        NUMERIC(20, 8) DEFAULT 0,    -- On hold
--       
--       -- Chart of Accounts
--       coa_code            VARCHAR(50),
--       
--       -- Timing (hypertable partition column)
--       posted_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
--       value_date          DATE NOT NULL DEFAULT CURRENT_DATE,
--       accounting_period   VARCHAR(10),                 -- '2024-03', '2024-Q1'
--       
--       -- Application Context
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Correlation
--       correlation_id      UUID,
--       
--       -- Integrity
--       posting_hash        BYTEA NOT NULL,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );
--
-- HYPERTABLE CONVERSION:
--   SELECT create_hypertable('core.movement_postings', 'posted_at', 
--                            chunk_time_interval => INTERVAL '1 day');
--
-- COMPRESSION POLICY:
--   ALTER TABLE core.movement_postings SET (
--       timescaledb.compress,
--       timescaledb.compress_segmentby = 'account_id'
--   );
--   SELECT add_compression_policy('core.movement_postings', INTERVAL '7 days');

-- =============================================================================
-- TODO: Create posting trigger function
-- DESCRIPTION: Auto-generate postings from movement legs
-- PRIORITY: CRITICAL
-- SECURITY: Advisory locks prevent concurrent balance corruption
-- ============================================================================
-- TODO: [POST-002] Create generate_postings function
-- INSTRUCTIONS:
--   - Trigger on movement_legs after insert
--   - Calculate running balance for account
--   - Insert into movement_postings
--   - Handle concurrent updates with advisory locks
--   - ERROR HANDLING: Rollback on balance calculation error
--   - TRANSACTION ISOLATION: Advisory lock per account
-- COMPLIANCE: ISO/IEC 27031 (Consistency)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.generate_posting_from_leg()
--   RETURNS TRIGGER AS $$
--   DECLARE
--       v_prev_balance NUMERIC;
--       v_new_balance NUMERIC;
--       v_account_currency VARCHAR(3);
--       v_app_id UUID;
--   BEGIN
--       -- Get account info
--       SELECT base_currency, application_id 
--       INTO v_account_currency, v_app_id
--       FROM core.accounts 
--       WHERE account_id = NEW.account_id;
--       
--       -- Acquire advisory lock for this account
--       PERFORM pg_advisory_lock(hashtext(NEW.account_id::text));
--       
--       -- Get previous balance
--       SELECT running_balance 
--       INTO v_prev_balance
--       FROM core.movement_postings
--       WHERE account_id = NEW.account_id
--       ORDER BY posted_at DESC
--       LIMIT 1;
--       
--       v_prev_balance := COALESCE(v_prev_balance, 0);
--       
--       -- Calculate new balance
--       IF NEW.direction = 'DEBIT' THEN
--           v_new_balance := v_prev_balance + NEW.amount;
--       ELSE
--           v_new_balance := v_prev_balance - NEW.amount;
--       END IF;
--       
--       -- Insert posting
--       INSERT INTO core.movement_postings (
--           movement_id, leg_id, account_id, direction, amount, currency,
--           running_balance, previous_balance, coa_code, posted_at,
--           application_id, posting_hash
--       ) VALUES (
--           NEW.movement_id, NEW.leg_id, NEW.account_id, NEW.direction,
--           NEW.amount, NEW.currency, v_new_balance, v_prev_balance,
--           NEW.coa_code, now(), v_app_id,
--           core.compute_posting_hash(...)
--       );
--       
--       -- Release lock
--       PERFORM pg_advisory_unlock(hashtext(NEW.account_id::text));
--       
--       RETURN NEW;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create balance snapshot materialized view
-- DESCRIPTION: Current balances for fast lookup
-- PRIORITY: HIGH
-- SECURITY: Refresh requires appropriate privileges
-- ============================================================================
-- TODO: [POST-003] Create current_balances materialized view
-- INSTRUCTIONS:
--   - Materialized view of latest balance per account
--   - Refresh periodically (e.g., every 5 seconds) or on-demand
--   - Used by USSD balance check *99#
--   - SECURITY DEFINER: Use for read-only balance API
-- COMPLIANCE: ISO/IEC 27031 (High Availability)
--
-- VIEW DEFINITION:
--   CREATE MATERIALIZED VIEW core.current_balances AS
--   SELECT DISTINCT ON (account_id)
--       account_id,
--       running_balance as current_balance,
--       available_balance,
--       held_balance,
--       currency,
--       posted_at as last_posted_at,
--       movement_id as last_movement_id
--   FROM core.movement_postings
--   ORDER BY account_id, posted_at DESC;
--
-- INDEXES:
--   CREATE UNIQUE INDEX idx_current_balances_account 
--   ON core.current_balances(account_id);

-- =============================================================================
-- TODO: Create balance as-of function
-- DESCRIPTION: Query balance at specific point in time
-- PRIORITY: HIGH
-- SECURITY: Time-bound queries prevent data exfiltration
-- ============================================================================
-- TODO: [POST-004] Create get_balance_as_of function
-- INSTRUCTIONS:
--   - Return balance for account at specific timestamp
--   - Used for dispute resolution and reporting
--   - ERROR HANDLING: Validate as_of timestamp is not in future
--   - SEARCH PATH: Explicitly set
-- COMPLIANCE: ISO/IEC 27018 (Historical Data Access)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.get_balance_as_of(
--       p_account_id UUID,
--       p_as_of TIMESTAMPTZ
--   ) RETURNS TABLE (
--       balance NUMERIC,
--       available_balance NUMERIC,
--       held_balance NUMERIC,
--       currency VARCHAR(3),
--       last_movement_id UUID
--   ) AS $$
--   BEGIN
--       RETURN QUERY
--       SELECT 
--           mp.running_balance,
--           mp.available_balance,
--           mp.held_balance,
--           mp.currency,
--           mp.movement_id
--       FROM core.movement_postings mp
--       WHERE mp.account_id = p_account_id
--         AND mp.posted_at <= p_as_of
--       ORDER BY mp.posted_at DESC
--       LIMIT 1;
--   END;
--   $$ LANGUAGE plpgsql STABLE;

-- =============================================================================
-- TODO: Create daily balance summary table
-- DESCRIPTION: End-of-day balances for reporting
-- PRIORITY: MEDIUM
-- SECURITY: Aggregated data reduces sensitivity
-- ============================================================================
-- TODO: [POST-005] Create daily_balance_summary table
-- INSTRUCTIONS:
--   - Aggregated daily balances per account
--   - Used for reporting and reconciliation
--   - Populated by EOD batch job
--   - AUDIT LOGGING: Track summary generation
-- COMPLIANCE: ISO/IEC 27001 (Reporting)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.daily_balance_summary (
--       summary_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
--       summary_date        DATE NOT NULL,
--       
--       opening_balance     NUMERIC(20, 8) NOT NULL,
--       closing_balance     NUMERIC(20, 8) NOT NULL,
--       total_debits        NUMERIC(20, 8) DEFAULT 0,
--       total_credits       NUMERIC(20, 8) DEFAULT 0,
--       transaction_count   INTEGER DEFAULT 0,
--       
--       currency            VARCHAR(3) NOT NULL,
--       
--       -- Integrity
--       calculated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
--       calculation_method  VARCHAR(20) DEFAULT 'ACTUAL', -- ACTUAL, PROJECTED
--       
--       UNIQUE (account_id, summary_date)
--   );

-- =============================================================================
-- TODO: Create posting indexes
-- DESCRIPTION: Optimize time-series queries
-- PRIORITY: HIGH
-- SECURITY: Index-only scans reduce data access
-- ============================================================================
-- TODO: [POST-006] Create posting indexes
-- INDEX LIST:
--   - PRIMARY KEY (posting_id, posted_at)  -- Include partition key
--   - INDEX on (account_id, posted_at DESC)
--   - INDEX on (movement_id)
--   - INDEX on (leg_id)
--   - INDEX on (value_date)
--   - INDEX on (accounting_period)
--   - INDEX on (application_id, posted_at)
--   - INDEX on (correlation_id)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create movement_postings table
□ Convert to TimescaleDB hypertable
□ Configure compression policy
□ Create auto-posting trigger from movement legs
□ Create current_balances materialized view
□ Create get_balance_as_of function
□ Create daily_balance_summary table
□ Add all indexes for time-series queries
□ Test concurrent balance updates
□ Verify compression is working
================================================================================
*/
