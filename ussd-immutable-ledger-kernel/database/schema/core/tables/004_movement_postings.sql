-- =============================================================================
-- USSD KERNEL CORE SCHEMA - MOVEMENT POSTINGS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    004_movement_postings.sql
-- SCHEMA:      ussd_core
-- TABLE:       movement_postings
-- DESCRIPTION: Posted movement legs representing committed double-entry
--              transactions. Immutable record of all account balance changes.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Posting origin verification
├── A.8.5 Secure authentication - Posting authorization
└── A.12.3 Information backup - Posting backup verification

ISO/IEC 27040:2024 (Storage Security)
├── Immutable storage: Postings write-once
├── Hash verification: Each posting individually hashed
├── Chain integrity: Linked to source movement
└── Retention: 7+ years per financial regulations

Financial Regulations
├── GAAP/IFRS: Double-entry compliance
├── Audit requirements: Complete posting trail
├── Reversal tracking: Compensating postings documented
└── Period-end: Support for financial statements

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. POSTING IMMUTABILITY
   - No updates allowed after posting
   - Reversals via compensating postings
   - Clear audit trail for all changes

2. BALANCE CALCULATION
   - Running balance per account
   - Currency-separated balances
   - Support for multi-currency accounts

3. ACCOUNTING DATE
   - Entry date vs value date distinction
   - Period-end cut-off support
   - Back-dating controls

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

POSTING AUTHORIZATION:
- Multi-level approval for large postings
- Separation of duties (initiator vs approver)
- Automated limit checking

VERIFICATION:
- Hash chain verification per account
- Control total reconciliation
- Exception reporting for mismatches

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: posting_id
- ACCOUNT: account_id + accounting_date (balance queries)
- MOVEMENT: movement_id (source lookup)
- DATE: accounting_date DESC (reporting)

AGGREGATION:
- Materialized view: account_daily_balance
- Real-time balance: account_state_snapshot
- Period-end: Period balance calculations

PARTITIONING:
- Range partition by accounting_date (monthly)
- Archive old partitions to cold storage

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- POSTING_CREATED: New posting recorded
- BALANCE_UPDATED: Running balance changed
- REVERSAL_POSTED: Compensating entry recorded

RETENTION: Permanent (archived after 7 years)
================================================================================
*/

-- =============================================================================
-- CREATE TABLE: movement_postings (partitioned)
-- =============================================================================

CREATE TABLE core.movement_postings (
    -- Primary identifier
    posting_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Source transaction reference
    transaction_id BIGINT NOT NULL,
    partition_date DATE NOT NULL,
    
    -- Source movement leg
    leg_id UUID NOT NULL REFERENCES core.movement_legs(leg_id) ON DELETE RESTRICT,
    
    -- Affected account
    account_id UUID NOT NULL REFERENCES core.account_registry(account_id) ON DELETE RESTRICT,
    
    -- Posting details
    direction VARCHAR(6) NOT NULL CHECK (direction IN ('DEBIT', 'CREDIT')),
    amount NUMERIC(20, 8) NOT NULL CHECK (amount > 0),
    currency VARCHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    
    -- Running balance after this posting
    running_balance NUMERIC(20, 8) NOT NULL,
    
    -- Chart of accounts
    coa_code VARCHAR(50) NOT NULL,  -- References chart_of_accounts
    
    -- Accounting dates
    accounting_date DATE NOT NULL,
    value_date DATE NOT NULL,
    
    -- Narrative
    description TEXT,
    
    -- Reversal tracking
    is_reversal BOOLEAN DEFAULT FALSE,
    reversed_posting_id UUID REFERENCES core.movement_postings(posting_id) ON DELETE RESTRICT,
    
    -- Integrity hash
    posting_hash VARCHAR(64) NOT NULL,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    posted_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    
    -- Audit
    record_hash VARCHAR(64) NOT NULL,
    
    -- Partition key
    partition_date_posting DATE NOT NULL DEFAULT CURRENT_DATE,
    
    -- Constraints
    CONSTRAINT chk_value_date_valid CHECK (value_date >= accounting_date - INTERVAL '30 days'),
    CONSTRAINT chk_no_self_reversal CHECK (reversed_posting_id IS NULL OR reversed_posting_id != posting_id)
) PARTITION BY RANGE (accounting_date);

-- =============================================================================
-- CREATE INITIAL PARTITIONS
-- =============================================================================

-- Create partition for current month
CREATE TABLE core.movement_postings_current 
    PARTITION OF core.movement_postings
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

-- Create partition for next month
CREATE TABLE core.movement_postings_2026_04 
    PARTITION OF core.movement_postings
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

-- Create partition for previous month
CREATE TABLE core.movement_postings_2026_02 
    PARTITION OF core.movement_postings
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Account + date for balance queries (most important)
CREATE INDEX idx_movement_postings_account_date 
    ON core.movement_postings(account_id, accounting_date DESC, posting_id);

-- Account + currency for multi-currency balance
CREATE INDEX idx_movement_postings_account_currency 
    ON core.movement_postings(account_id, currency, accounting_date DESC);

-- Transaction lookup
CREATE INDEX idx_movement_postings_transaction 
    ON core.movement_postings(transaction_id, partition_date);

-- Leg lookup
CREATE INDEX idx_movement_postings_leg 
    ON core.movement_postings(leg_id);

-- Accounting date for period queries
CREATE INDEX idx_movement_postings_accounting_date 
    ON core.movement_postings(accounting_date DESC);

-- Value date queries
CREATE INDEX idx_movement_postings_value_date 
    ON core.movement_postings(value_date DESC);

-- Chart of accounts queries
CREATE INDEX idx_movement_postings_coa 
    ON core.movement_postings(coa_code, accounting_date DESC);

-- Reversal tracking
CREATE INDEX idx_movement_postings_reversal 
    ON core.movement_postings(reversed_posting_id) 
    WHERE reversed_posting_id IS NOT NULL;

-- Reversal flag
CREATE INDEX idx_movement_postings_is_reversal 
    ON core.movement_postings(account_id, accounting_date DESC) 
    WHERE is_reversal = TRUE;

-- =============================================================================
-- IMMUTABILITY TRIGGERS
-- =============================================================================

-- Prevent updates on immutable table
CREATE TRIGGER trg_movement_postings_prevent_update
    BEFORE UPDATE ON core.movement_postings
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

-- Prevent deletes on immutable table
CREATE TRIGGER trg_movement_postings_prevent_delete
    BEFORE DELETE ON core.movement_postings
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- =============================================================================
-- HASH COMPUTATION TRIGGER
-- =============================================================================

CREATE OR REPLACE FUNCTION core.compute_posting_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- Compute posting-specific hash
    NEW.posting_hash := core.generate_hash(
        NEW.posting_id::TEXT || 
        NEW.transaction_id::TEXT ||
        NEW.leg_id::TEXT ||
        NEW.account_id::TEXT ||
        NEW.direction ||
        NEW.amount::TEXT ||
        NEW.currency ||
        NEW.running_balance::TEXT ||
        NEW.accounting_date::TEXT
    );
    
    -- Compute overall record hash
    NEW.record_hash := core.generate_hash(
        NEW.posting_id::TEXT || 
        NEW.posting_hash ||
        NEW.created_at::TEXT
    );
    
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_movement_postings_compute_hash
    BEFORE INSERT ON core.movement_postings
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_posting_hash();

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

-- Enable RLS
ALTER TABLE core.movement_postings ENABLE ROW LEVEL SECURITY;

-- Policy: Accounts can view their own postings
CREATE POLICY movement_postings_account_access ON core.movement_postings
    FOR SELECT
    TO ussd_app_user
    USING (account_id = current_setting('app.current_account_id', true)::UUID);

-- Policy: Application-scoped access
CREATE POLICY movement_postings_app_access ON core.movement_postings
    FOR SELECT
    TO ussd_app_user
    USING (
        EXISTS (
            SELECT 1 FROM core.account_registry ar
            WHERE ar.account_id = movement_postings.account_id
            AND ar.primary_application_id = current_setting('app.current_application_id', true)::UUID
        )
    );

-- Policy: Kernel role has full access
CREATE POLICY movement_postings_kernel_access ON core.movement_postings
    FOR ALL
    TO ussd_kernel_role
    USING (true);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to get current account balance
CREATE OR REPLACE FUNCTION core.get_account_balance(
    p_account_id UUID,
    p_currency VARCHAR(3) DEFAULT NULL
)
RETURNS TABLE (
    currency VARCHAR(3),
    balance NUMERIC(20, 8),
    last_posting_id UUID,
    last_posting_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        mp.currency,
        mp.running_balance,
        mp.posting_id,
        mp.posted_at
    FROM core.movement_postings mp
    WHERE mp.account_id = p_account_id
    AND (p_currency IS NULL OR mp.currency = p_currency)
    ORDER BY mp.accounting_date DESC, mp.posting_id DESC
    LIMIT 1;
END;
$$;

-- Function to get account balance as of a specific date
CREATE OR REPLACE FUNCTION core.get_account_balance_as_of(
    p_account_id UUID,
    p_as_of_date DATE,
    p_currency VARCHAR(3) DEFAULT NULL
)
RETURNS TABLE (
    currency VARCHAR(3),
    balance NUMERIC(20, 8)
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        mp.currency,
        mp.running_balance
    FROM core.movement_postings mp
    WHERE mp.account_id = p_account_id
    AND mp.accounting_date <= p_as_of_date
    AND (p_currency IS NULL OR mp.currency = p_currency)
    ORDER BY mp.accounting_date DESC, mp.posting_id DESC
    LIMIT 1;
END;
$$;

-- Function to get posting history for an account
CREATE OR REPLACE FUNCTION core.get_account_posting_history(
    p_account_id UUID,
    p_start_date DATE,
    p_end_date DATE,
    p_currency VARCHAR(3) DEFAULT NULL
)
RETURNS TABLE (
    posting_id UUID,
    transaction_id BIGINT,
    direction VARCHAR(6),
    amount NUMERIC(20, 8),
    currency VARCHAR(3),
    running_balance NUMERIC(20, 8),
    accounting_date DATE,
    description TEXT,
    posted_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        mp.posting_id,
        mp.transaction_id,
        mp.direction,
        mp.amount,
        mp.currency,
        mp.running_balance,
        mp.accounting_date,
        mp.description,
        mp.posted_at
    FROM core.movement_postings mp
    WHERE mp.account_id = p_account_id
    AND mp.accounting_date BETWEEN p_start_date AND p_end_date
    AND (p_currency IS NULL OR mp.currency = p_currency)
    ORDER BY mp.accounting_date, mp.posting_id;
END;
$$;

-- =============================================================================
-- TABLE AND COLUMN COMMENTS
-- =============================================================================

COMMENT ON TABLE core.movement_postings IS 
    'Posted double-entry movements with running balances. PARTITIONED by accounting_date. Immutable.';

COMMENT ON COLUMN core.movement_postings.posting_id IS 
    'Unique identifier for the posting';
COMMENT ON COLUMN core.movement_postings.transaction_id IS 
    'Reference to parent transaction';
COMMENT ON COLUMN core.movement_postings.leg_id IS 
    'Reference to source movement leg';
COMMENT ON COLUMN core.movement_postings.direction IS 
    'DEBIT or CREDIT';
COMMENT ON COLUMN core.movement_postings.running_balance IS 
    'Account balance after this posting is applied';
COMMENT ON COLUMN core.movement_postings.accounting_date IS 
    'Date for accounting/bookkeeping purposes';
COMMENT ON COLUMN core.movement_postings.value_date IS 
    'Date when funds become available';
COMMENT ON COLUMN core.movement_postings.is_reversal IS 
    'TRUE if this posting reverses a previous posting';
COMMENT ON COLUMN core.movement_postings.reversed_posting_id IS 
    'Reference to the posting being reversed (if applicable)';
COMMENT ON COLUMN core.movement_postings.posting_hash IS 
    'Hash of posting content for integrity';

-- =============================================================================
-- END OF FILE
-- =============================================================================
