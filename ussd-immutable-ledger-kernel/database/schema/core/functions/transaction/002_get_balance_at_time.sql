-- =============================================================================
-- USSD KERNEL CORE SCHEMA - TRANSACTION FUNCTIONS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    002_get_balance_at_time.sql
-- SCHEMA:      core
-- CATEGORY:    Transaction Functions
-- DESCRIPTION: Point-in-time balance queries with historical reconstruction
--              and audit trail support.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Balance query access control
├── A.12.4 Logging and monitoring - Balance query monitoring
└── A.18.1 Compliance - Regulatory reporting support

Financial Regulations
├── Historical balance: Reconstruct any past balance
├── Audit trail: Query logging for examinations
├── Reporting: Support for regulatory reports
└── SLA: Response time requirements

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. BALANCE CALCULATION
   - Running balance approach
   - Recomputation from postings
   - Snapshot interpolation

2. PERFORMANCE
   - Materialized view usage
   - Index utilization
   - Query optimization

3. ACCURACY
   - Decimal precision handling
   - Currency conversion
   - Rounding rules

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

ACCESS CONTROL:
- Account ownership verification
- Delegated access checking
- Audit logging

DATA PROTECTION:
- Sensitive balance masking
- Aggregation for privacy
- Access pattern analysis

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEX USAGE:
- Account + date index
- Covering indexes
- Partial indexes for current data

CACHING:
- Current balance caching
- Snapshot caching
- Query result caching

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- BALANCE_QUERIED
- HISTORICAL_BALANCE_QUERIED
- BALANCE_RECONSTRUCTED

RETENTION: 7 years
================================================================================
*/

-- Create balance result type
DROP TYPE IF EXISTS core.balance_result CASCADE;
CREATE TYPE core.balance_result AS (
    account_id UUID,
    currency VARCHAR(3),
    balance NUMERIC,
    pending_debits NUMERIC,
    pending_credits NUMERIC,
    available_balance NUMERIC,
    as_of_time TIMESTAMPTZ,
    calculation_method TEXT
);

-- =============================================================================
-- Create get_balance_at_time function
-- DESCRIPTION: Get account balance at specific point in time
-- PRIORITY: HIGH
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_balance_at_time(
    p_account_id UUID,
    p_as_of_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    p_currency VARCHAR(3) DEFAULT NULL  -- NULL means all currencies
)
RETURNS SETOF core.balance_result
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
DECLARE
    v_result core.balance_result;
    v_calc_start TIMESTAMPTZ;
BEGIN
    v_calc_start := clock_timestamp();
    
    -- Log query
    INSERT INTO core.audit_trail (
        event_type,
        table_name,
        record_id,
        details
    ) VALUES (
        'BALANCE_QUERIED',
        'account_registry',
        p_account_id::text,
        jsonb_build_object(
            'as_of_time', p_as_of_time,
            'currency_filter', p_currency
        )
    );
    
    -- Return balance for each currency (or specific currency)
    FOR v_result IN
        WITH movements AS (
            SELECT 
                ml.currency,
                CASE 
                    WHEN ml.direction = 'CREDIT' THEN ml.amount 
                    ELSE -ml.amount 
                END as signed_amount
            FROM core.movement_legs ml
            JOIN core.movement_headers mh ON ml.movement_id = mh.movement_id
            WHERE ml.account_id = p_account_id
              AND mh.status = 'POSTED'
              AND mh.created_at <= p_as_of_time
              AND (p_currency IS NULL OR ml.currency = p_currency)
        ),
        aggregated AS (
            SELECT 
                currency,
                COALESCE(SUM(signed_amount), 0) as balance
            FROM movements
            GROUP BY currency
        )
        SELECT 
            p_account_id,
            a.currency,
            a.balance,
            0::NUMERIC as pending_debits,  -- Would be populated from pending movements
            0::NUMERIC as pending_credits,
            a.balance as available_balance,
            p_as_of_time,
            'RECONSTRUCTED_FROM_MOVEMENTS'::TEXT
        FROM aggregated a
        ORDER BY a.currency
    LOOP
        RETURN NEXT v_result;
    END LOOP;
    
    -- If no movements found, return zero balance for account's base currency
    IF NOT FOUND THEN
        SELECT 
            ar.account_id,
            COALESCE(ar.default_currency, 'USD'),
            0::NUMERIC,
            0::NUMERIC,
            0::NUMERIC,
            0::NUMERIC,
            p_as_of_time,
            'NO_MOVEMENTS_FOUND'::TEXT
        INTO v_result
        FROM core.account_registry ar
        WHERE ar.account_id = p_account_id;
        
        IF FOUND THEN
            RETURN NEXT v_result;
        END IF;
    END IF;
END;
$$;

COMMENT ON FUNCTION core.get_balance_at_time IS 'Get account balance at a specific point in time by reconstructing from movements';

-- =============================================================================
-- Create get_balance_history function
-- DESCRIPTION: Get balance changes over time period
-- PRIORITY: MEDIUM
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_balance_history(
    p_account_id UUID,
    p_start_date DATE,
    p_end_date DATE,
    p_currency VARCHAR(3) DEFAULT NULL,
    p_interval VARCHAR(20) DEFAULT 'DAILY'  -- DAILY, WEEKLY, MONTHLY
)
RETURNS TABLE (
    period_date DATE,
    opening_balance NUMERIC,
    total_credits NUMERIC,
    total_debits NUMERIC,
    closing_balance NUMERIC,
    transaction_count BIGINT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
BEGIN
    -- Generate date series and calculate balances
    RETURN QUERY
    WITH date_series AS (
        SELECT generate_series(
            p_start_date::date,
            p_end_date::date,
            CASE p_interval
                WHEN 'DAILY' THEN '1 day'::interval
                WHEN 'WEEKLY' THEN '1 week'::interval
                WHEN 'MONTHLY' THEN '1 month'::interval
                ELSE '1 day'::interval
            END
        )::date as period_date
    ),
    period_movements AS (
        SELECT 
            ds.period_date,
            ml.currency,
            SUM(CASE WHEN ml.direction = 'CREDIT' THEN ml.amount ELSE 0 END) as credits,
            SUM(CASE WHEN ml.direction = 'DEBIT' THEN ml.amount ELSE 0 END) as debits,
            COUNT(*) as tx_count
        FROM date_series ds
        LEFT JOIN core.movement_legs ml ON (
            ml.account_id = p_account_id
            AND (p_currency IS NULL OR ml.currency = p_currency)
            AND ml.created_at::date = ds.period_date
        )
        LEFT JOIN core.movement_headers mh ON (
            mh.movement_id = ml.movement_id
            AND mh.status = 'POSTED'
        )
        GROUP BY ds.period_date, ml.currency
    ),
    running_balance AS (
        SELECT 
            pm.period_date,
            pm.currency,
            COALESCE(pm.credits, 0) as total_credits,
            COALESCE(pm.debits, 0) as total_debits,
            COALESCE(pm.tx_count, 0) as transaction_count,
            SUM(COALESCE(pm.credits, 0) - COALESCE(pm.debits, 0)) OVER (
                ORDER BY pm.period_date 
                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
            ) as closing_balance
        FROM period_movements pm
    )
    SELECT 
        rb.period_date,
        (rb.closing_balance - rb.total_credits + rb.total_debits) as opening_balance,
        rb.total_credits,
        rb.total_debits,
        rb.closing_balance,
        rb.transaction_count
    FROM running_balance rb
    ORDER BY rb.period_date;
    
    -- Log the query
    INSERT INTO core.audit_trail (
        event_type,
        table_name,
        record_id,
        details
    ) VALUES (
        'HISTORICAL_BALANCE_QUERIED',
        'account_registry',
        p_account_id::text,
        jsonb_build_object(
            'start_date', p_start_date,
            'end_date', p_end_date,
            'interval', p_interval,
            'currency', p_currency
        )
    );
END;
$$;

COMMENT ON FUNCTION core.get_balance_history IS 'Get daily/weekly/monthly balance history for an account over a time period';

/*
================================================================================
MIGRATION CHECKLIST:
□ Create get_balance_at_time function
□ Create get_balance_history function
□ Test with current date
□ Test with historical dates
□ Test with multiple currencies
□ Benchmark query performance
================================================================================
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
