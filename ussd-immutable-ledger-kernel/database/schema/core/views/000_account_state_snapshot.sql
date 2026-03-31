-- =============================================================================
-- USSD KERNEL CORE SCHEMA - VIEWS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    000_account_state_snapshot.sql
-- SCHEMA:      core
-- CATEGORY:    Views - Account State
-- DESCRIPTION: Materialized and real-time views of account balances
--              and state for high-performance querying.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Balance query access control
├── A.8.11 Data masking - Balance data protection
└── A.12.4 Logging and monitoring - Balance query monitoring

Financial Regulations
├── Balance accuracy: Reconciled with ledger
├── Availability: Real-time balance provision
├── Audit: Balance query audit trail
└── Reporting: Regulatory balance reporting

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. MATERIALIZED VIEWS
   - Concurrent refresh support
   - Index for fast lookups
   - Periodic refresh schedule
   - Incremental refresh where possible

2. REAL-TIME VIEWS
   - Direct table joins
   - Latest data availability
   - Performance considerations
   - Query optimization

3. SECURITY
   - RLS policy application
   - Data masking
   - Access control

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

VIEW SECURITY:
- RLS policies apply to views
- Data masking for sensitive fields
- Access logging

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

REFRESH STRATEGY:
- On-commit refresh (high consistency)
- Periodic refresh (eventual consistency)
- On-demand refresh (flexibility)

INDEXING:
- Unique index for concurrent refresh
- Query-specific indexes
- Covering indexes

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- SNAPSHOT_REFRESHED
- BALANCE_QUERIED
- SNAPSHOT_ACCESSED

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- MATERIALIZED VIEW: Account state snapshot
-- DESCRIPTION: Pre-computed account balances for fast lookups
-- PRIORITY: CRITICAL
-- =============================================================================
CREATE MATERIALIZED VIEW IF NOT EXISTS core.mv_account_state_snapshot AS
SELECT 
    ar.account_id,
    ar.account_type,
    ar.status AS account_status,
    ar.display_name,
    ar.primary_application_id,
    ar.created_at AS account_created_at,
    -- Balance per currency from movement_postings
    mp.currency,
    mp.running_balance AS current_balance,
    mp.posting_id AS last_posting_id,
    mp.posted_at AS last_activity_at,
    -- Debit/Credit summaries
    COALESCE(debit_totals.total_debits, 0) AS total_debits,
    COALESCE(credit_totals.total_credits, 0) AS total_credits,
    COALESCE(debit_totals.debit_count, 0) AS debit_count,
    COALESCE(credit_totals.credit_count, 0) AS credit_count,
    -- Snapshot timestamp
    NOW() AS snapshot_timestamp
FROM core.account_registry ar
LEFT JOIN LATERAL (
    -- Get the most recent posting for each currency
    SELECT DISTINCT ON (currency)
        currency,
        running_balance,
        posting_id,
        posted_at
    FROM core.movement_postings
    WHERE account_id = ar.account_id
    ORDER BY currency, posted_at DESC, posting_id DESC
) mp ON TRUE
LEFT JOIN (
    -- Calculate total debits per account per currency
    SELECT 
        account_id,
        currency,
        SUM(amount) AS total_debits,
        COUNT(*) AS debit_count
    FROM core.movement_postings
    WHERE direction = 'DEBIT'
    GROUP BY account_id, currency
) debit_totals ON debit_totals.account_id = ar.account_id 
    AND debit_totals.currency = mp.currency
LEFT JOIN (
    -- Calculate total credits per account per currency
    SELECT 
        account_id,
        currency,
        SUM(amount) AS total_credits,
        COUNT(*) AS credit_count
    FROM core.movement_postings
    WHERE direction = 'CREDIT'
    GROUP BY account_id, currency
) credit_totals ON credit_totals.account_id = ar.account_id 
    AND credit_totals.currency = mp.currency
WHERE ar.valid_to IS NULL;  -- Only active account versions

-- =============================================================================
-- INDEXES FOR MATERIALIZED VIEW
-- =============================================================================

-- Unique index for concurrent refresh (required)
CREATE UNIQUE INDEX idx_mv_account_state_pk 
    ON core.mv_account_state_snapshot(account_id, currency);

-- Index for account lookups
CREATE INDEX idx_mv_account_state_account 
    ON core.mv_account_state_snapshot(account_id);

-- Index for application-scoped queries
CREATE INDEX idx_mv_account_state_app 
    ON core.mv_account_state_snapshot(primary_application_id)
    WHERE primary_application_id IS NOT NULL;

-- Index for currency-based queries
CREATE INDEX idx_mv_account_state_currency 
    ON core.mv_account_state_snapshot(currency);

-- Index for status filtering
CREATE INDEX idx_mv_account_state_status 
    ON core.mv_account_state_snapshot(account_status);

-- =============================================================================
-- VIEW: Account state snapshot wrapper
-- DESCRIPTION: Wrapper view for consistent interface
-- =============================================================================
CREATE OR REPLACE VIEW core.account_state_snapshot AS
SELECT 
    account_id,
    account_type,
    account_status,
    display_name,
    primary_application_id,
    account_created_at,
    currency,
    current_balance,
    last_posting_id,
    last_activity_at,
    total_debits,
    total_credits,
    debit_count,
    credit_count,
    snapshot_timestamp
FROM core.mv_account_state_snapshot;

-- =============================================================================
-- VIEW: Account balance by currency
-- DESCRIPTION: Aggregated view of balances grouped by currency
-- =============================================================================
CREATE OR REPLACE VIEW core.account_balance_by_currency AS
SELECT 
    currency,
    COUNT(DISTINCT account_id) AS account_count,
    SUM(current_balance) AS total_balance,
    SUM(total_debits) AS total_debits,
    SUM(total_credits) AS total_credits,
    NOW() AS calculated_at
FROM core.mv_account_state_snapshot
WHERE current_balance IS NOT NULL
GROUP BY currency;

-- =============================================================================
-- VIEW: Pending balance changes
-- DESCRIPTION: Shows accounts with pending/unposted transactions
-- =============================================================================
CREATE OR REPLACE VIEW core.pending_balance_changes AS
SELECT 
    tl.initiator_account_id AS account_id,
    ar.display_name,
    COUNT(*) AS pending_transaction_count,
    SUM(CASE WHEN ml.direction = 'DEBIT' THEN ml.amount ELSE 0 END) AS pending_debits,
    SUM(CASE WHEN ml.direction = 'CREDIT' THEN ml.amount ELSE 0 END) AS pending_credits,
    MIN(tl.committed_at) AS oldest_pending,
    MAX(tl.committed_at) AS newest_pending
FROM core.transaction_log tl
JOIN core.movement_legs ml ON tl.transaction_id = ml.transaction_id 
    AND tl.partition_date = ml.partition_date
JOIN core.account_registry ar ON tl.initiator_account_id = ar.account_id
WHERE tl.status IN ('pending', 'validated')
GROUP BY tl.initiator_account_id, ar.display_name;

-- =============================================================================
-- VIEW: Account daily balance
-- DESCRIPTION: Daily balance history for accounts
-- =============================================================================
CREATE OR REPLACE VIEW core.account_daily_balance AS
WITH daily_postings AS (
    SELECT 
        account_id,
        currency,
        accounting_date,
        direction,
        SUM(amount) AS daily_amount,
        COUNT(*) AS transaction_count
    FROM core.movement_postings
    GROUP BY account_id, currency, accounting_date, direction
),
pivoted AS (
    SELECT 
        account_id,
        currency,
        accounting_date,
        SUM(CASE WHEN direction = 'DEBIT' THEN daily_amount ELSE 0 END) AS daily_debits,
        SUM(CASE WHEN direction = 'CREDIT' THEN daily_amount ELSE 0 END) AS daily_credits,
        SUM(CASE WHEN direction = 'DEBIT' THEN daily_amount ELSE -daily_amount END) AS net_change,
        SUM(transaction_count) AS transaction_count
    FROM daily_postings
    GROUP BY account_id, currency, accounting_date
)
SELECT 
    p.account_id,
    ar.display_name,
    p.currency,
    p.accounting_date,
    p.daily_debits,
    p.daily_credits,
    p.net_change,
    p.transaction_count,
    -- Running balance using window function
    SUM(p.net_change) OVER (
        PARTITION BY p.account_id, p.currency 
        ORDER BY p.accounting_date 
        ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
    ) AS running_balance
FROM pivoted p
JOIN core.account_registry ar ON p.account_id = ar.account_id
ORDER BY p.account_id, p.currency, p.accounting_date;

-- =============================================================================
-- FUNCTION: Refresh account state snapshot
-- Description: Wrapper function to refresh the materialized view
-- =============================================================================
CREATE OR REPLACE FUNCTION core.refresh_account_state_snapshot(
    p_concurrent BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (
    status TEXT,
    duration_ms INTEGER,
    message TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_start_time TIMESTAMPTZ;
BEGIN
    v_start_time := clock_timestamp();
    
    BEGIN
        IF p_concurrent THEN
            REFRESH MATERIALIZED VIEW CONCURRENTLY core.mv_account_state_snapshot;
        ELSE
            REFRESH MATERIALIZED VIEW core.mv_account_state_snapshot;
        END IF;
        
        status := 'SUCCESS';
        duration_ms := EXTRACT(MILLISECOND FROM (clock_timestamp() - v_start_time))::INTEGER;
        message := 'Account state snapshot refreshed successfully';
        
        -- Log the refresh
        INSERT INTO core.audit_trail (
            event_type,
            event_description,
            event_timestamp,
            metadata
        ) VALUES (
            'SNAPSHOT_REFRESHED',
            'Account state snapshot refreshed',
            NOW(),
            jsonb_build_object(
                'concurrent', p_concurrent,
                'duration_ms', duration_ms
            )
        );
        
    EXCEPTION WHEN OTHERS THEN
        status := 'FAILED';
        duration_ms := EXTRACT(MILLISECOND FROM (clock_timestamp() - v_start_time))::INTEGER;
        message := SQLERRM;
    END;
    
    RETURN NEXT;
END;
$$;

-- =============================================================================
-- FUNCTION: Get account balance
-- Description: Real-time balance lookup function
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_account_balance_realtime(
    p_account_id UUID,
    p_currency VARCHAR(3) DEFAULT NULL
)
RETURNS TABLE (
    account_id UUID,
    currency VARCHAR(3),
    current_balance NUMERIC(20, 8),
    last_updated TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT DISTINCT ON (mp.currency)
        mp.account_id,
        mp.currency,
        mp.running_balance AS current_balance,
        mp.posted_at AS last_updated
    FROM core.movement_postings mp
    WHERE mp.account_id = p_account_id
    AND (p_currency IS NULL OR mp.currency = p_currency)
    ORDER BY mp.currency, mp.posted_at DESC, mp.posting_id DESC;
END;
$$;

-- =============================================================================
-- MIGRATION CHECKLIST:
-- □ Create mv_account_state_snapshot materialized view
-- □ Create unique index for concurrent refresh
-- □ Create supporting indexes
-- □ Create account_state_snapshot wrapper view
-- □ Create account_balance_by_currency view
-- □ Create pending_balance_changes view
-- □ Create account_daily_balance view
-- □ Create refresh procedure
-- □ Test concurrent refresh
-- □ Benchmark query performance
-- □ Set up scheduled refresh job
================================================================================

-- =============================================================================
-- END OF FILE
-- =============================================================================
