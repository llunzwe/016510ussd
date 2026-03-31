-- =============================================================================
-- USSD KERNEL CORE SCHEMA - AGING ANALYSIS VIEWS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    003_aging_analysis.sql
-- SCHEMA:      core
-- CATEGORY:    Views - Financial Reporting
-- DESCRIPTION: Accounts receivable/payable aging analysis and overdue
--              tracking for credit risk management.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.11 Data masking - Financial data protection
└── A.18.1 Compliance - Credit risk reporting

Financial Regulations
├── IFRS 9: Credit risk staging
├── Basel: Credit risk reporting
├── Audit: Receivables verification
└── Management: Aging reports

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. AGING BUCKETS
   - Current: Not yet due
   - 1-30 days: Slightly overdue
   - 31-60 days: Moderately overdue
   - 61-90 days: Seriously overdue
   - 90+ days: Critical

2. CALCULATION METHODS
   - Transaction date based
   - Due date based
   - Last payment date based

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

AGING SECURITY:
- RLS policies restrict to authorized accounts
- Aggregation for privacy

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

QUERY OPTIMIZATION:
- Materialized views for large portfolios
- Index on due dates
- Partition-wise aggregation

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- AGING_REPORT_GENERATED
- OVERDUE_ACCIDENT_ACCESSED

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- VIEW: Account aging analysis
-- DESCRIPTION: Shows receivables aging by account
-- =============================================================================
CREATE OR REPLACE VIEW core.account_aging AS
WITH transaction_aging AS (
    SELECT 
        ml.account_id,
        ml.currency,
        ml.transaction_id,
        ml.amount,
        ml.direction,
        mp.accounting_date,
        mp.value_date,
        CURRENT_DATE - mp.accounting_date as days_outstanding,
        CASE 
            WHEN CURRENT_DATE - mp.accounting_date <= 0 THEN 'CURRENT'
            WHEN CURRENT_DATE - mp.accounting_date <= 30 THEN '1-30_DAYS'
            WHEN CURRENT_DATE - mp.accounting_date <= 60 THEN '31-60_DAYS'
            WHEN CURRENT_DATE - mp.accounting_date <= 90 THEN '61-90_DAYS'
            ELSE 'OVER_90_DAYS'
        END as aging_bucket
    FROM core.movement_legs ml
    JOIN core.movement_postings mp ON ml.leg_id = mp.leg_id
    WHERE ml.direction = 'DEBIT'  -- Receivables (amounts owed TO us)
      AND mp.accounting_date >= CURRENT_DATE - INTERVAL '180 days'
),
bucketed_amounts AS (
    SELECT 
        account_id,
        currency,
        aging_bucket,
        SUM(amount) as bucket_amount,
        COUNT(DISTINCT transaction_id) as transaction_count
    FROM transaction_aging
    GROUP BY account_id, currency, aging_bucket
)
SELECT 
    ba.account_id,
    ar.display_name as account_name,
    ar.account_type,
    ba.currency,
    SUM(CASE WHEN ba.aging_bucket = 'CURRENT' THEN ba.bucket_amount ELSE 0 END) as current_amount,
    SUM(CASE WHEN ba.aging_bucket = '1-30_DAYS' THEN ba.bucket_amount ELSE 0 END) as days_1_30,
    SUM(CASE WHEN ba.aging_bucket = '31-60_DAYS' THEN ba.bucket_amount ELSE 0 END) as days_31_60,
    SUM(CASE WHEN ba.aging_bucket = '61-90_DAYS' THEN ba.bucket_amount ELSE 0 END) as days_61_90,
    SUM(CASE WHEN ba.aging_bucket = 'OVER_90_DAYS' THEN ba.bucket_amount ELSE 0 END) as over_90_days,
    SUM(ba.bucket_amount) as total_receivable,
    CASE 
        WHEN SUM(ba.bucket_amount) > 0 
        THEN ROUND((SUM(CASE WHEN ba.aging_bucket != 'CURRENT' THEN ba.bucket_amount ELSE 0 END) / SUM(ba.bucket_amount)) * 100, 2)
        ELSE 0 
    END as percent_overdue,
    NOW() as generated_at
FROM bucketed_amounts ba
JOIN core.account_registry ar ON ba.account_id = ar.account_id
GROUP BY ba.account_id, ar.display_name, ar.account_type, ba.currency;

-- =============================================================================
-- VIEW: Portfolio aging summary
-- DESCRIPTION: Aggregated aging across all accounts
-- =============================================================================
CREATE OR REPLACE VIEW core.portfolio_aging_summary AS
WITH transaction_aging AS (
    SELECT 
        ml.currency,
        ml.amount,
        CURRENT_DATE - mp.accounting_date as days_outstanding,
        CASE 
            WHEN CURRENT_DATE - mp.accounting_date <= 0 THEN 'CURRENT'
            WHEN CURRENT_DATE - mp.accounting_date <= 30 THEN '1-30_DAYS'
            WHEN CURRENT_DATE - mp.accounting_date <= 60 THEN '31-60_DAYS'
            WHEN CURRENT_DATE - mp.accounting_date <= 90 THEN '61-90_DAYS'
            ELSE 'OVER_90_DAYS'
        END as aging_bucket
    FROM core.movement_legs ml
    JOIN core.movement_postings mp ON ml.leg_id = mp.leg_id
    WHERE ml.direction = 'DEBIT'
)
SELECT 
    currency,
    SUM(CASE WHEN aging_bucket = 'CURRENT' THEN amount ELSE 0 END) as current_amount,
    SUM(CASE WHEN aging_bucket = '1-30_DAYS' THEN amount ELSE 0 END) as days_1_30,
    SUM(CASE WHEN aging_bucket = '31-60_DAYS' THEN amount ELSE 0 END) as days_31_60,
    SUM(CASE WHEN aging_bucket = '61-90_DAYS' THEN amount ELSE 0 END) as days_61_90,
    SUM(CASE WHEN aging_bucket = 'OVER_90_DAYS' THEN amount ELSE 0 END) as over_90_days,
    SUM(amount) as total_receivable,
    ROUND((SUM(CASE WHEN aging_bucket != 'CURRENT' THEN amount ELSE 0 END) / NULLIF(SUM(amount), 0)) * 100, 2) as percent_overdue,
    COUNT(DISTINCT CASE WHEN aging_bucket = 'OVER_90_DAYS' THEN amount END) as critical_accounts,
    NOW() as generated_at
FROM transaction_aging
GROUP BY currency;

-- =============================================================================
-- VIEW: Overdue accounts detail
-- DESCRIPTION: Detailed view of overdue accounts for collections
-- =============================================================================
CREATE OR REPLACE VIEW core.overdue_accounts AS
WITH account_overdue AS (
    SELECT 
        ml.account_id,
        ml.currency,
        SUM(CASE WHEN ml.direction = 'DEBIT' THEN ml.amount ELSE 0 END) as total_debits,
        SUM(CASE WHEN ml.direction = 'CREDIT' THEN ml.amount ELSE 0 END) as total_credits,
        MAX(mp.accounting_date) as last_transaction_date,
        MIN(mp.accounting_date) as oldest_transaction_date,
        CURRENT_DATE - MIN(mp.accounting_date) as days_overdue
    FROM core.movement_legs ml
    JOIN core.movement_postings mp ON ml.leg_id = mp.leg_id
    WHERE mp.accounting_date >= CURRENT_DATE - INTERVAL '180 days'
    GROUP BY ml.account_id, ml.currency
    HAVING SUM(CASE WHEN ml.direction = 'DEBIT' THEN ml.amount ELSE 0 END) > 
           SUM(CASE WHEN ml.direction = 'CREDIT' THEN ml.amount ELSE 0 END)
)
SELECT 
    ao.account_id,
    ar.display_name as account_name,
    ar.primary_identifier,
    ar.account_type,
    ao.currency,
    ao.total_debits - ao.total_credits as overdue_balance,
    ao.days_overdue,
    CASE 
        WHEN ao.days_overdue <= 30 THEN 'LOW'
        WHEN ao.days_overdue <= 60 THEN 'MEDIUM'
        WHEN ao.days_overdue <= 90 THEN 'HIGH'
        ELSE 'CRITICAL'
    END as risk_level,
    CASE 
        WHEN ao.days_overdue <= 30 THEN 'STAGE_1'
        WHEN ao.days_overdue <= 90 THEN 'STAGE_2'
        ELSE 'STAGE_3'
    END as ifrs9_stage,
    ao.last_transaction_date,
    ao.oldest_transaction_date,
    NOW() as generated_at
FROM account_overdue ao
JOIN core.account_registry ar ON ao.account_id = ar.account_id
WHERE ao.days_overdue > 0
ORDER BY ao.days_overdue DESC, ao.total_debits - ao.total_credits DESC;

-- =============================================================================
-- FUNCTION: Get aging report for specific account
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_account_aging(
    p_account_id UUID,
    p_as_of_date DATE DEFAULT CURRENT_DATE
)
RETURNS TABLE (
    currency VARCHAR,
    current_amount NUMERIC,
    days_1_30 NUMERIC,
    days_31_60 NUMERIC,
    days_61_90 NUMERIC,
    over_90_days NUMERIC,
    total_receivable NUMERIC,
    percent_overdue NUMERIC,
    risk_level VARCHAR
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    WITH transaction_aging AS (
        SELECT 
            ml.currency,
            ml.amount,
            p_as_of_date - mp.accounting_date as days_outstanding,
            CASE 
                WHEN p_as_of_date - mp.accounting_date <= 0 THEN 'CURRENT'
                WHEN p_as_of_date - mp.accounting_date <= 30 THEN '1-30_DAYS'
                WHEN p_as_of_date - mp.accounting_date <= 60 THEN '31-60_DAYS'
                WHEN p_as_of_date - mp.accounting_date <= 90 THEN '61-90_DAYS'
                ELSE 'OVER_90_DAYS'
            END as aging_bucket
        FROM core.movement_legs ml
        JOIN core.movement_postings mp ON ml.leg_id = mp.leg_id
        WHERE ml.account_id = p_account_id
          AND ml.direction = 'DEBIT'
          AND mp.accounting_date <= p_as_of_date
    )
    SELECT 
        ta.currency,
        SUM(CASE WHEN ta.aging_bucket = 'CURRENT' THEN ta.amount ELSE 0 END) as current_amount,
        SUM(CASE WHEN ta.aging_bucket = '1-30_DAYS' THEN ta.amount ELSE 0 END) as days_1_30,
        SUM(CASE WHEN ta.aging_bucket = '31-60_DAYS' THEN ta.amount ELSE 0 END) as days_31_60,
        SUM(CASE WHEN ta.aging_bucket = '61-90_DAYS' THEN ta.amount ELSE 0 END) as days_61_90,
        SUM(CASE WHEN ta.aging_bucket = 'OVER_90_DAYS' THEN ta.amount ELSE 0 END) as over_90_days,
        SUM(ta.amount) as total_receivable,
        ROUND((SUM(CASE WHEN ta.aging_bucket != 'CURRENT' THEN ta.amount ELSE 0 END) / NULLIF(SUM(ta.amount), 0)) * 100, 2) as percent_overdue,
        CASE 
            WHEN MAX(ta.days_outstanding) <= 30 THEN 'LOW'
            WHEN MAX(ta.days_outstanding) <= 60 THEN 'MEDIUM'
            WHEN MAX(ta.days_outstanding) <= 90 THEN 'HIGH'
            ELSE 'CRITICAL'
        END as risk_level
    FROM transaction_aging ta
    GROUP BY ta.currency;
END;
$$;

-- =============================================================================
-- FUNCTION: Get aging summary by bucket
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_aging_summary(
    p_as_of_date DATE DEFAULT CURRENT_DATE
)
RETURNS TABLE (
    aging_bucket VARCHAR,
    account_count BIGINT,
    total_amount NUMERIC,
    avg_days_overdue NUMERIC,
    max_days_overdue INTEGER
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    WITH account_aging AS (
        SELECT 
            ml.account_id,
            ml.currency,
            SUM(ml.amount) as amount,
            p_as_of_date - MIN(mp.accounting_date) as days_overdue
        FROM core.movement_legs ml
        JOIN core.movement_postings mp ON ml.leg_id = mp.leg_id
        WHERE ml.direction = 'DEBIT'
          AND mp.accounting_date <= p_as_of_date
        GROUP BY ml.account_id, ml.currency
        HAVING SUM(ml.amount) > 0
    ),
    bucketed AS (
        SELECT 
            account_id,
            amount,
            days_overdue,
            CASE 
                WHEN days_overdue <= 0 THEN 'CURRENT'
                WHEN days_overdue <= 30 THEN '1-30_DAYS'
                WHEN days_overdue <= 60 THEN '31-60_DAYS'
                WHEN days_overdue <= 90 THEN '61-90_DAYS'
                ELSE 'OVER_90_DAYS'
            END as bucket
        FROM account_aging
    )
    SELECT 
        b.bucket as aging_bucket,
        COUNT(*) as account_count,
        SUM(b.amount) as total_amount,
        AVG(b.days_overdue)::NUMERIC as avg_days_overdue,
        MAX(b.days_overdue) as max_days_overdue
    FROM bucketed b
    GROUP BY b.bucket
    ORDER BY MIN(b.days_overdue);
END;
$$;

-- =============================================================================
-- FUNCTION: Calculate provision based on aging
-- =============================================================================
CREATE OR REPLACE FUNCTION core.calculate_aging_provision(
    p_account_id UUID,
    p_provision_rates JSONB DEFAULT '{
        "CURRENT": 0.01,
        "1-30_DAYS": 0.05,
        "31-60_DAYS": 0.20,
        "61-90_DAYS": 0.50,
        "OVER_90_DAYS": 1.00
    }'::JSONB
)
RETURNS TABLE (
    currency VARCHAR,
    bucket VARCHAR,
    bucket_amount NUMERIC,
    provision_rate NUMERIC,
    provision_amount NUMERIC,
    total_provision NUMERIC
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    WITH aging_data AS (
        SELECT * FROM core.get_account_aging(p_account_id)
    ),
    unpivoted AS (
        SELECT currency, 'CURRENT'::VARCHAR as bucket, current_amount as amount FROM aging_data
        UNION ALL
        SELECT currency, '1-30_DAYS', days_1_30 FROM aging_data
        UNION ALL
        SELECT currency, '31-60_DAYS', days_31_60 FROM aging_data
        UNION ALL
        SELECT currency, '61-90_DAYS', days_61_90 FROM aging_data
        UNION ALL
        SELECT currency, 'OVER_90_DAYS', over_90_days FROM aging_data
    )
    SELECT 
        u.currency,
        u.bucket,
        u.amount as bucket_amount,
        (p_provision_rates->>u.bucket)::NUMERIC as provision_rate,
        ROUND(u.amount * (p_provision_rates->>u.bucket)::NUMERIC, 2) as provision_amount,
        SUM(ROUND(u.amount * (p_provision_rates->>u.bucket)::NUMERIC, 2)) OVER (PARTITION BY u.currency) as total_provision
    FROM unpivoted u
    WHERE u.amount > 0;
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON VIEW core.account_aging IS 'Accounts receivable aging by account and currency';
COMMENT ON VIEW core.portfolio_aging_summary IS 'Portfolio-wide aging summary';
COMMENT ON VIEW core.overdue_accounts IS 'Detailed view of overdue accounts with risk levels';
COMMENT ON FUNCTION core.calculate_aging_provision IS 'Calculate provision amounts based on aging buckets using configurable rates';

-- =============================================================================
-- END OF FILE
-- =============================================================================
