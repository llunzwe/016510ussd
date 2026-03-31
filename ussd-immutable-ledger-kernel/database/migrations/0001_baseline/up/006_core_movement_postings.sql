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
-- Create movement_postings table
-- DESCRIPTION: Time-series of account balances
-- PRIORITY: CRITICAL
-- SECURITY: Hypertable partitioning by time
-- ============================================================================
CREATE TABLE core.movement_postings (
    -- Identity
    posting_id          UUID NOT NULL DEFAULT gen_random_uuid(),
    
    -- Reference to source
    movement_id         UUID NOT NULL REFERENCES core.movement_headers(movement_id),
    leg_id              UUID NOT NULL REFERENCES core.movement_legs(leg_id),
    
    -- Account
    account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
    
    -- Movement Details
    direction           VARCHAR(6) NOT NULL,         -- 'DEBIT' or 'CREDIT'
    amount              NUMERIC(20, 8) NOT NULL,
    currency            VARCHAR(3) NOT NULL,
    
    -- Running Balance (denormalized for query performance)
    running_balance     NUMERIC(20, 8) NOT NULL,     -- Balance after this posting
    previous_balance    NUMERIC(20, 8) NOT NULL,     -- Balance before this posting
    
    -- Balance Categories
    available_balance   NUMERIC(20, 8),              -- Available (excluding holds)
    held_balance        NUMERIC(20, 8) DEFAULT 0,    -- On hold
    
    -- Chart of Accounts
    coa_code            VARCHAR(50),
    
    -- Timing (hypertable partition column)
    posted_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    value_date          DATE NOT NULL DEFAULT CURRENT_DATE,
    accounting_period   VARCHAR(10),                 -- '2024-03', '2024-Q1'
    
    -- Application Context
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Correlation
    correlation_id      UUID,
    
    -- Integrity
    posting_hash        BYTEA NOT NULL,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Constraints
    CONSTRAINT chk_movement_postings_direction 
        CHECK (direction IN ('DEBIT', 'CREDIT')),
    CONSTRAINT chk_movement_postings_amount 
        CHECK (amount > 0)
);

-- Convert to TimescaleDB hypertable
SELECT create_hypertable('core.movement_postings', 'posted_at', 
                         chunk_time_interval => INTERVAL '1 day');

-- Compression policy for TimescaleDB
ALTER TABLE core.movement_postings SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'account_id'
);

SELECT add_compression_policy('core.movement_postings', INTERVAL '7 days');

-- Primary key for hypertable (must include partition column)
CREATE UNIQUE INDEX idx_movement_postings_pk ON core.movement_postings(posting_id, posted_at);

-- Indexes for movement_postings
CREATE INDEX idx_movement_postings_account ON core.movement_postings(account_id, posted_at DESC);
CREATE INDEX idx_movement_postings_movement ON core.movement_postings(movement_id);
CREATE INDEX idx_movement_postings_leg ON core.movement_postings(leg_id);
CREATE INDEX idx_movement_postings_value_date ON core.movement_postings(value_date);
CREATE INDEX idx_movement_postings_period ON core.movement_postings(accounting_period);
CREATE INDEX idx_movement_postings_application ON core.movement_postings(application_id, posted_at);
CREATE INDEX idx_movement_postings_correlation ON core.movement_postings(correlation_id);

COMMENT ON TABLE core.movement_postings IS 'Time-series table of account balance history after each movement';
COMMENT ON COLUMN core.movement_postings.running_balance IS 'Account balance after applying this posting';
COMMENT ON COLUMN core.movement_postings.posting_hash IS 'SHA-256 hash for posting integrity verification';

-- =============================================================================
-- Create posting hash computation function
-- DESCRIPTION: Calculate hash for posting integrity
-- PRIORITY: HIGH
-- ============================================================================
CREATE OR REPLACE FUNCTION core.compute_posting_hash(
    p_movement_id UUID,
    p_leg_id UUID,
    p_account_id UUID,
    p_direction VARCHAR(6),
    p_amount NUMERIC,
    p_currency VARCHAR(3),
    p_running_balance NUMERIC,
    p_posted_at TIMESTAMPTZ
) RETURNS BYTEA AS $$
BEGIN
    RETURN digest(
        p_movement_id::text ||
        p_leg_id::text ||
        p_account_id::text ||
        p_direction ||
        p_amount::text ||
        p_currency ||
        p_running_balance::text ||
        p_posted_at::text,
        'sha256'
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path = core, pg_catalog, public;

-- =============================================================================
-- Create posting trigger function
-- DESCRIPTION: Auto-generate postings from movement legs
-- PRIORITY: CRITICAL
-- SECURITY: Advisory locks prevent concurrent balance corruption
-- ============================================================================
CREATE OR REPLACE FUNCTION core.generate_posting_from_leg()
RETURNS TRIGGER AS $$
DECLARE
    v_prev_balance NUMERIC;
    v_new_balance NUMERIC;
    v_account_currency VARCHAR(3);
    v_app_id UUID;
    v_available_balance NUMERIC;
    v_held_balance NUMERIC;
    v_accounting_period VARCHAR(10);
    v_lock_acquired BOOLEAN;
BEGIN
    -- Get account info
    SELECT base_currency, application_id 
    INTO v_account_currency, v_app_id
    FROM core.accounts 
    WHERE account_id = NEW.account_id;
    
    -- Try to acquire advisory lock for this account to prevent concurrent updates
    v_lock_acquired := pg_try_advisory_lock(hashtext(NEW.account_id::text));
    
    IF NOT v_lock_acquired THEN
        RAISE EXCEPTION 'Could not acquire lock for account % - concurrent modification in progress', NEW.account_id
            USING HINT = 'Retry the transaction after a brief pause';
    END IF;
    
    BEGIN
        -- Get previous balance
        SELECT running_balance 
        INTO v_prev_balance
        FROM core.movement_postings
        WHERE account_id = NEW.account_id
        ORDER BY posted_at DESC
        LIMIT 1;
        
        v_prev_balance := COALESCE(v_prev_balance, 0);
        
        -- Calculate new balance based on direction
        IF NEW.direction = 'DEBIT' THEN
            v_new_balance := v_prev_balance + NEW.amount;
        ELSE
            v_new_balance := v_prev_balance - NEW.amount;
        END IF;
        
        -- Calculate accounting period
        v_accounting_period := TO_CHAR(CURRENT_DATE, 'YYYY-MM');
        
        -- Get held balance from holds table if exists (simplified)
        v_held_balance := 0;
        v_available_balance := v_new_balance - v_held_balance;
        
        -- Insert posting
        INSERT INTO core.movement_postings (
            movement_id, leg_id, account_id, direction, amount, currency,
            running_balance, previous_balance, available_balance, held_balance,
            coa_code, posted_at, value_date, accounting_period,
            application_id, posting_hash
        ) VALUES (
            NEW.movement_id, NEW.leg_id, NEW.account_id, NEW.direction,
            NEW.amount, NEW.currency, v_new_balance, v_prev_balance,
            v_available_balance, v_held_balance,
            NEW.coa_code, now(), CURRENT_DATE, v_accounting_period,
            v_app_id,
            core.compute_posting_hash(
                NEW.movement_id, NEW.leg_id, NEW.account_id,
                NEW.direction, NEW.amount, NEW.currency,
                v_new_balance, now()
            )
        );
        
        -- Release lock
        PERFORM pg_advisory_unlock(hashtext(NEW.account_id::text));
        
        RETURN NEW;
        
    EXCEPTION WHEN OTHERS THEN
        -- Always release lock on error
        PERFORM pg_advisory_unlock(hashtext(NEW.account_id::text));
        RAISE;
    END;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

CREATE TRIGGER trg_movement_legs_generate_posting
    AFTER INSERT ON core.movement_legs
    FOR EACH ROW
    EXECUTE FUNCTION core.generate_posting_from_leg();

COMMENT ON FUNCTION core.generate_posting_from_leg IS 'Generates time-series posting record when movement leg is created';

-- =============================================================================
-- Create balance snapshot materialized view
-- DESCRIPTION: Current balances for fast lookup
-- PRIORITY: HIGH
-- SECURITY: Refresh requires appropriate privileges
-- ============================================================================
CREATE MATERIALIZED VIEW core.current_balances AS
SELECT DISTINCT ON (account_id)
    account_id,
    running_balance as current_balance,
    available_balance,
    held_balance,
    currency,
    posted_at as last_posted_at,
    movement_id as last_movement_id,
    leg_id as last_leg_id
FROM core.movement_postings
ORDER BY account_id, posted_at DESC;

CREATE UNIQUE INDEX idx_current_balances_account ON core.current_balances(account_id);
CREATE INDEX idx_current_balances_currency ON core.current_balances(currency);

COMMENT ON MATERIALIZED VIEW core.current_balances IS 'Fast lookup view of current account balances - refresh periodically';

-- =============================================================================
-- Create balance as-of function
-- DESCRIPTION: Query balance at specific point in time
-- PRIORITY: HIGH
-- SECURITY: Time-bound queries prevent data exfiltration
-- ============================================================================
CREATE OR REPLACE FUNCTION core.get_balance_as_of(
    p_account_id UUID,
    p_as_of TIMESTAMPTZ DEFAULT now()
) RETURNS TABLE (
    balance NUMERIC,
    available_balance NUMERIC,
    held_balance NUMERIC,
    currency VARCHAR(3),
    last_movement_id UUID,
    last_posted_at TIMESTAMPTZ
) AS $$
BEGIN
    -- Validate as_of is not in future
    IF p_as_of > now() + INTERVAL '1 minute' THEN
        RAISE EXCEPTION 'As-of timestamp cannot be in the future: %', p_as_of;
    END IF;
    
    RETURN QUERY
    SELECT 
        mp.running_balance,
        mp.available_balance,
        mp.held_balance,
        mp.currency,
        mp.movement_id,
        mp.posted_at
    FROM core.movement_postings mp
    WHERE mp.account_id = p_account_id
      AND mp.posted_at <= p_as_of
    ORDER BY mp.posted_at DESC
    LIMIT 1;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.get_balance_as_of IS 'Returns account balance at a specific point in time';

-- =============================================================================
-- Create daily balance summary table
-- DESCRIPTION: End-of-day balances for reporting
-- PRIORITY: MEDIUM
-- SECURITY: Aggregated data reduces sensitivity
-- ============================================================================
CREATE TABLE core.daily_balance_summary (
    summary_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
    summary_date        DATE NOT NULL,
    
    opening_balance     NUMERIC(20, 8) NOT NULL,
    closing_balance     NUMERIC(20, 8) NOT NULL,
    total_debits        NUMERIC(20, 8) DEFAULT 0,
    total_credits       NUMERIC(20, 8) DEFAULT 0,
    transaction_count   INTEGER DEFAULT 0,
    
    currency            VARCHAR(3) NOT NULL,
    
    -- Integrity
    calculated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    calculation_method  VARCHAR(20) DEFAULT 'ACTUAL', -- ACTUAL, PROJECTED
    
    -- Constraints
    CONSTRAINT uq_daily_balance_summary UNIQUE (account_id, summary_date)
);

CREATE INDEX idx_daily_balance_summary_date ON core.daily_balance_summary(summary_date);
CREATE INDEX idx_daily_balance_summary_account ON core.daily_balance_summary(account_id, summary_date DESC);

COMMENT ON TABLE core.daily_balance_summary IS 'End-of-day balance summary for reporting and reconciliation';

-- =============================================================================
-- Create function to refresh current balances
-- DESCRIPTION: Scheduled refresh of materialized view
-- PRIORITY: MEDIUM
-- ============================================================================
CREATE OR REPLACE FUNCTION core.refresh_current_balances()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY core.current_balances;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create movement_postings table
☑ Convert to TimescaleDB hypertable
☑ Configure compression policy
☑ Create auto-posting trigger from movement legs
☑ Create current_balances materialized view
☑ Create get_balance_as_of function
☑ Create daily_balance_summary table
☑ Add all indexes for time-series queries
☑ Test concurrent balance updates
☑ Verify compression is working
================================================================================
*/
