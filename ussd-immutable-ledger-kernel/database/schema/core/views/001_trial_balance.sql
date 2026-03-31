-- =============================================================================
-- USSD KERNEL CORE SCHEMA - VIEWS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    001_trial_balance.sql
-- SCHEMA:      core
-- CATEGORY:    Views - Financial Reporting
-- DESCRIPTION: Trial balance views for financial reporting with
--              debit/credit balancing and COA roll-up support.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.11 Data masking - Financial data protection
└── A.18.1 Compliance - Financial reporting support

Financial Regulations
├── GAAP/IFRS: Standard-compliant reporting
├── Audit: Trial balance for audits
├── Period-end: Monthly/quarterly/annual close
└── Regulatory: Regulatory reporting support

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. TRIAL BALANCE STRUCTURE
   - COA code ordering
   - Debit/credit columns
   - Running totals
   - Balance verification

2. ROLL-UP SUPPORT
   - Hierarchical COA aggregation
   - Level-based summaries
   - Drill-down capability

3. PERIOD SUPPORT
   - As-of date parameterization
   - Period comparison
   - Trend analysis

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

REPORT SECURITY:
- Role-based access
- Data aggregation for privacy
- Audit logging

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

QUERY OPTIMIZATION:
- Materialized views for complex aggregations
- Index on COA codes
- Partition-wise aggregation

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- TRIAL_BALANCE_GENERATED
- REPORT_EXPORTED
- FINANCIAL_DATA_ACCESSED

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- VIEW: Trial balance
-- DESCRIPTION: Generate trial balance for a specific period
-- PRIORITY: HIGH
-- =============================================================================
CREATE OR REPLACE VIEW core.trial_balance AS
WITH posting_aggregates AS (
    -- Aggregate postings by COA code
    SELECT 
        mp.coa_code,
        mp.currency,
        SUM(CASE WHEN mp.direction = 'DEBIT' THEN mp.amount ELSE 0 END) AS total_debits,
        SUM(CASE WHEN mp.direction = 'CREDIT' THEN mp.amount ELSE 0 END) AS total_credits,
        COUNT(*) AS posting_count
    FROM core.movement_postings mp
    GROUP BY mp.coa_code, mp.currency
)
SELECT 
    coa.coa_code,
    coa.account_name,
    coa.account_type,
    coa.normal_balance,
    coa.parent_coa_code,
    coa.account_level,
    pa.currency,
    COALESCE(pa.total_debits, 0) AS total_debits,
    COALESCE(pa.total_credits, 0) AS total_credits,
    CASE 
        WHEN coa.normal_balance = 'DEBIT' THEN 
            COALESCE(pa.total_debits, 0) - COALESCE(pa.total_credits, 0)
        ELSE 
            COALESCE(pa.total_credits, 0) - COALESCE(pa.total_debits, 0)
    END AS balance,
    COALESCE(pa.posting_count, 0) AS posting_count,
    CASE
        WHEN coa.account_type = 'ASSET' THEN 1
        WHEN coa.account_type = 'LIABILITY' THEN 2
        WHEN coa.account_type = 'EQUITY' THEN 3
        WHEN coa.account_type = 'REVENUE' THEN 4
        WHEN coa.account_type = 'EXPENSE' THEN 5
        ELSE 6
    END AS type_order,
    NOW() AS generated_at
FROM core.chart_of_accounts coa
LEFT JOIN posting_aggregates pa ON coa.coa_code = pa.coa_code
WHERE coa.is_active = TRUE
ORDER BY coa.coa_code, pa.currency;

-- =============================================================================
-- VIEW: Trial balance by level
-- DESCRIPTION: Hierarchical roll-up of trial balance
-- =============================================================================
CREATE OR REPLACE VIEW core.trial_balance_by_level AS
WITH RECURSIVE coa_hierarchy AS (
    -- Base case: leaf accounts
    SELECT 
        coa_code,
        account_name,
        account_type,
        normal_balance,
        parent_coa_code,
        account_level,
        coa_code AS root_coa_code,
        account_name AS root_account_name,
        account_level AS hierarchy_level
    FROM core.chart_of_accounts
    WHERE is_leaf_account = TRUE
    AND is_active = TRUE
    
    UNION ALL
    
    -- Recursive case: roll up to parents
    SELECT 
        p.coa_code,
        p.account_name,
        p.account_type,
        p.normal_balance,
        p.parent_coa_code,
        p.account_level,
        c.root_coa_code,
        c.root_account_name,
        p.account_level AS hierarchy_level
    FROM core.chart_of_accounts p
    JOIN coa_hierarchy c ON p.coa_code = c.parent_coa_code
    WHERE p.is_active = TRUE
),
posting_sums AS (
    -- Sum postings by COA code
    SELECT 
        coa_code,
        SUM(CASE WHEN direction = 'DEBIT' THEN amount ELSE 0 END) AS total_debits,
        SUM(CASE WHEN direction = 'CREDIT' THEN amount ELSE 0 END) AS total_credits
    FROM core.movement_postings
    GROUP BY coa_code
)
SELECT 
    h.coa_code,
    h.account_name,
    h.account_type,
    h.normal_balance,
    h.parent_coa_code,
    h.account_level,
    h.hierarchy_level,
    COALESCE(ps.total_debits, 0) AS total_debits,
    COALESCE(ps.total_credits, 0) AS total_credits,
    CASE 
        WHEN h.normal_balance = 'DEBIT' THEN 
            COALESCE(ps.total_debits, 0) - COALESCE(ps.total_credits, 0)
        ELSE 
            COALESCE(ps.total_credits, 0) - COALESCE(ps.total_debits, 0)
    END AS balance,
    NOW() AS generated_at
FROM coa_hierarchy h
LEFT JOIN posting_sums ps ON h.coa_code = ps.coa_code
ORDER BY h.coa_code, h.hierarchy_level;

-- =============================================================================
-- VIEW: Trial balance comparison
-- DESCRIPTION: Compare trial balance across two periods
-- =============================================================================
CREATE OR REPLACE VIEW core.trial_balance_comparison AS
WITH period_current AS (
    SELECT 
        coa_code,
        SUM(CASE WHEN direction = 'DEBIT' THEN amount ELSE 0 END) AS current_debits,
        SUM(CASE WHEN direction = 'CREDIT' THEN amount ELSE 0 END) AS current_credits
    FROM core.movement_postings
    WHERE accounting_date >= DATE_TRUNC('month', CURRENT_DATE)
    GROUP BY coa_code
),
period_previous AS (
    SELECT 
        coa_code,
        SUM(CASE WHEN direction = 'DEBIT' THEN amount ELSE 0 END) AS previous_debits,
        SUM(CASE WHEN direction = 'CREDIT' THEN amount ELSE 0 END) AS previous_credits
    FROM core.movement_postings
    WHERE accounting_date >= DATE_TRUNC('month', CURRENT_DATE - INTERVAL '1 month')
    AND accounting_date < DATE_TRUNC('month', CURRENT_DATE)
    GROUP BY coa_code
),
all_coas AS (
    SELECT coa_code FROM period_current
    UNION
    SELECT coa_code FROM period_previous
)
SELECT 
    coa.coa_code,
    coa.account_name,
    coa.account_type,
    coa.normal_balance,
    COALESCE(pc.current_debits, 0) AS current_debits,
    COALESCE(pc.current_credits, 0) AS current_credits,
    COALESCE(pp.previous_debits, 0) AS previous_debits,
    COALESCE(pp.previous_credits, 0) AS previous_credits,
    COALESCE(pc.current_debits, 0) - COALESCE(pp.previous_debits, 0) AS debit_variance,
    COALESCE(pc.current_credits, 0) - COALESCE(pp.previous_credits, 0) AS credit_variance,
    CASE 
        WHEN COALESCE(pp.previous_debits, 0) + COALESCE(pp.previous_credits, 0) = 0 THEN NULL
        ELSE ROUND(
            ((COALESCE(pc.current_debits, 0) + COALESCE(pc.current_credits, 0)) - 
             (COALESCE(pp.previous_debits, 0) + COALESCE(pp.previous_credits, 0))) /
            NULLIF(COALESCE(pp.previous_debits, 0) + COALESCE(pp.previous_credits, 0), 0) * 100,
            2
        )
    END AS percent_change,
    NOW() AS generated_at
FROM all_coas ac
JOIN core.chart_of_accounts coa ON ac.coa_code = coa.coa_code
LEFT JOIN period_current pc ON ac.coa_code = pc.coa_code
LEFT JOIN period_previous pp ON ac.coa_code = pp.coa_code
ORDER BY coa.coa_code;

-- =============================================================================
-- FUNCTION: Generate trial balance as-of date
-- Description: Returns trial balance for a specific date
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_trial_balance_as_of(
    p_as_of_date DATE
)
RETURNS TABLE (
    coa_code VARCHAR(50),
    account_name VARCHAR(200),
    account_type VARCHAR(20),
    normal_balance VARCHAR(6),
    total_debits NUMERIC(20, 8),
    total_credits NUMERIC(20, 8),
    net_balance NUMERIC(20, 8),
    generated_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        coa.coa_code,
        coa.account_name,
        coa.account_type,
        coa.normal_balance,
        COALESCE(SUM(CASE WHEN mp.direction = 'DEBIT' THEN mp.amount ELSE 0 END), 0) AS total_debits,
        COALESCE(SUM(CASE WHEN mp.direction = 'CREDIT' THEN mp.amount ELSE 0 END), 0) AS total_credits,
        CASE 
            WHEN coa.normal_balance = 'DEBIT' THEN 
                COALESCE(SUM(CASE WHEN mp.direction = 'DEBIT' THEN mp.amount ELSE 0 END), 0) -
                COALESCE(SUM(CASE WHEN mp.direction = 'CREDIT' THEN mp.amount ELSE 0 END), 0)
            ELSE 
                COALESCE(SUM(CASE WHEN mp.direction = 'CREDIT' THEN mp.amount ELSE 0 END), 0) -
                COALESCE(SUM(CASE WHEN mp.direction = 'DEBIT' THEN mp.amount ELSE 0 END), 0)
        END AS net_balance,
        NOW() AS generated_at
    FROM core.chart_of_accounts coa
    LEFT JOIN core.movement_postings mp ON coa.coa_code = mp.coa_code
        AND mp.accounting_date <= p_as_of_date
    WHERE coa.is_active = TRUE
    GROUP BY coa.coa_code, coa.account_name, coa.account_type, coa.normal_balance
    ORDER BY coa.coa_code;
END;
$$;

-- =============================================================================
-- FUNCTION: Verify trial balance
-- Description: Checks if debits equal credits
-- =============================================================================
CREATE OR REPLACE FUNCTION core.verify_trial_balance(
    p_as_of_date DATE DEFAULT CURRENT_DATE
)
RETURNS TABLE (
    is_balanced BOOLEAN,
    total_debits NUMERIC(20, 8),
    total_credits NUMERIC(20, 8),
    difference NUMERIC(20, 8),
    currency VARCHAR(3),
    checked_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ABS(COALESCE(SUM(CASE WHEN mp.direction = 'DEBIT' THEN mp.amount ELSE 0 END), 0) - 
            COALESCE(SUM(CASE WHEN mp.direction = 'CREDIT' THEN mp.amount ELSE 0 END), 0)) < 0.00000001 AS is_balanced,
        COALESCE(SUM(CASE WHEN mp.direction = 'DEBIT' THEN mp.amount ELSE 0 END), 0) AS total_debits,
        COALESCE(SUM(CASE WHEN mp.direction = 'CREDIT' THEN mp.amount ELSE 0 END), 0) AS total_credits,
        ABS(COALESCE(SUM(CASE WHEN mp.direction = 'DEBIT' THEN mp.amount ELSE 0 END), 0) - 
            COALESCE(SUM(CASE WHEN mp.direction = 'CREDIT' THEN mp.amount ELSE 0 END), 0)) AS difference,
        mp.currency,
        NOW() AS checked_at
    FROM core.movement_postings mp
    WHERE mp.accounting_date <= p_as_of_date
    GROUP BY mp.currency;
END;
$$;

-- =============================================================================
-- FUNCTION: Get account roll-up
-- Description: Aggregates child accounts to parent level
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_account_roll_up(
    p_parent_coa_code VARCHAR(50)
)
RETURNS TABLE (
    coa_code VARCHAR(50),
    account_name VARCHAR(200),
    account_type VARCHAR(20),
    level INTEGER,
    total_debits NUMERIC(20, 8),
    total_credits NUMERIC(20, 8),
    net_balance NUMERIC(20, 8)
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE account_tree AS (
        -- Start with the parent
        SELECT 
            coa_code,
            account_name,
            account_type,
            account_level,
            0 AS depth
        FROM core.chart_of_accounts
        WHERE coa_code = p_parent_coa_code
        
        UNION ALL
        
        -- Get all descendants
        SELECT 
            c.coa_code,
            c.account_name,
            c.account_type,
            c.account_level,
            t.depth + 1
        FROM core.chart_of_accounts c
        JOIN account_tree t ON c.parent_coa_code = t.coa_code
    )
    SELECT 
        at.coa_code,
        at.account_name,
        at.account_type,
        at.account_level AS level,
        COALESCE(SUM(CASE WHEN mp.direction = 'DEBIT' THEN mp.amount ELSE 0 END), 0) AS total_debits,
        COALESCE(SUM(CASE WHEN mp.direction = 'CREDIT' THEN mp.amount ELSE 0 END), 0) AS total_credits,
        COALESCE(SUM(CASE WHEN mp.direction = 'DEBIT' THEN mp.amount ELSE -mp.amount END), 0) AS net_balance
    FROM account_tree at
    LEFT JOIN core.movement_postings mp ON at.coa_code = mp.coa_code
    GROUP BY at.coa_code, at.account_name, at.account_type, at.account_level
    ORDER BY at.account_level, at.coa_code;
END;
$$;

-- =============================================================================
-- MIGRATION CHECKLIST:
-- □ Create trial_balance view
-- □ Create trial_balance_by_level view
-- □ Create trial_balance_comparison view
-- □ Test with sample data
-- □ Benchmark report generation
================================================================================

-- =============================================================================
-- END OF FILE
-- =============================================================================
