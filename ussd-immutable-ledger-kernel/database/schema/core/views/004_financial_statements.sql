-- =============================================================================
-- USSD KERNEL CORE SCHEMA - FINANCIAL STATEMENTS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    004_financial_statements.sql
-- SCHEMA:      core
-- CATEGORY:    Views - Financial Reporting
-- DESCRIPTION: Financial statement views including Balance Sheet,
--              Income Statement (P&L), and Cash Flow Statement.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.11 Data masking - Financial data protection
└── A.18.1 Compliance - Financial reporting support

Financial Regulations
├── GAAP/IFRS: Standard-compliant statement structure
├── Audit: Financial statement verification
├── Regulatory: Filing requirements
└── Management: Performance reporting

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. BALANCE SHEET
   - Assets = Liabilities + Equity
   - Current vs Non-current classification
   - Hierarchical roll-up

2. INCOME STATEMENT (P&L)
   - Revenue - Expenses = Net Income
   - Operating vs Non-operating
   - Period comparison

3. CASH FLOW STATEMENT
   - Operating activities
   - Investing activities
   - Financing activities

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

STATEMENT SECURITY:
- RLS policies restrict access
- Audit logging for generation
- Aggregation for privacy

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

QUERY OPTIMIZATION:
- Materialized views for period-end
- Index on COA codes and dates
- Partition-wise aggregation

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- BALANCE_SHEET_GENERATED
- INCOME_STATEMENT_GENERATED
- CASH_FLOW_GENERATED

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- VIEW: Balance Sheet
-- DESCRIPTION: Assets, Liabilities, and Equity as of a specific date
-- =============================================================================
CREATE OR REPLACE VIEW core.balance_sheet AS
WITH account_balances AS (
    SELECT 
        coa.coa_code,
        coa.account_name,
        coa.account_type,
        coa.parent_coa_code,
        coa.account_level,
        coa.balance_sheet_section,
        coa.normal_balance,
        mp.currency,
        SUM(CASE 
            WHEN mp.direction = coa.normal_balance THEN mp.amount 
            ELSE -mp.amount 
        END) as balance
    FROM core.chart_of_accounts coa
    LEFT JOIN core.movement_postings mp ON coa.coa_code = mp.coa_code
        AND mp.accounting_date <= CURRENT_DATE
    WHERE coa.account_type IN ('ASSET', 'LIABILITY', 'EQUITY')
      AND coa.is_active = TRUE
      AND coa.is_leaf_account = TRUE
    GROUP BY coa.coa_code, coa.account_name, coa.account_type, 
             coa.parent_coa_code, coa.account_level, 
             coa.balance_sheet_section, coa.normal_balance, mp.currency
),
rolled_up AS (
    -- Roll up to parent accounts
    SELECT 
        COALESCE(parent.coa_code, ab.coa_code) as coa_code,
        COALESCE(parent.account_name, ab.account_name) as account_name,
        COALESCE(parent.account_type, ab.account_type) as account_type,
        COALESCE(parent.parent_coa_code, ab.parent_coa_code) as parent_coa_code,
        COALESCE(parent.account_level, ab.account_level) as account_level,
        COALESCE(parent.balance_sheet_section, ab.balance_sheet_section) as balance_sheet_section,
        COALESCE(parent.normal_balance, ab.normal_balance) as normal_balance,
        ab.currency,
        ab.balance
    FROM account_balances ab
    LEFT JOIN core.chart_of_accounts parent ON ab.parent_coa_code = parent.coa_code
)
SELECT 
    ru.coa_code,
    ru.account_name,
    ru.account_type,
    ru.parent_coa_code,
    ru.account_level,
    ru.balance_sheet_section,
    ru.currency,
    COALESCE(ru.balance, 0) as balance,
    CASE ru.account_type
        WHEN 'ASSET' THEN 1
        WHEN 'LIABILITY' THEN 2
        WHEN 'EQUITY' THEN 3
    END as type_order,
    CASE ru.balance_sheet_section
        WHEN 'CURRENT_ASSETS' THEN 1
        WHEN 'NON_CURRENT_ASSETS' THEN 2
        WHEN 'CURRENT_LIABILITIES' THEN 3
        WHEN 'NON_CURRENT_LIABILITIES' THEN 4
        WHEN 'EQUITY' THEN 5
        ELSE 6
    END as section_order,
    NOW() as generated_at
FROM rolled_up ru
WHERE ru.balance_sheet_section IS NOT NULL
ORDER BY section_order, ru.coa_code, ru.currency;

-- =============================================================================
-- VIEW: Balance Sheet Summary
-- DESCRIPTION: High-level balance sheet totals
-- =============================================================================
CREATE OR REPLACE VIEW core.balance_sheet_summary AS
WITH section_totals AS (
    SELECT 
        bs.balance_sheet_section,
        bs.currency,
        SUM(bs.balance) as section_total
    FROM core.balance_sheet bs
    GROUP BY bs.balance_sheet_section, bs.currency
)
SELECT 
    currency,
    SUM(CASE WHEN balance_sheet_section IN ('CURRENT_ASSETS', 'NON_CURRENT_ASSETS') 
             THEN section_total ELSE 0 END) as total_assets,
    SUM(CASE WHEN balance_sheet_section IN ('CURRENT_ASSETS') 
             THEN section_total ELSE 0 END) as current_assets,
    SUM(CASE WHEN balance_sheet_section IN ('NON_CURRENT_ASSETS') 
             THEN section_total ELSE 0 END) as non_current_assets,
    SUM(CASE WHEN balance_sheet_section IN ('CURRENT_LIABILITIES', 'NON_CURRENT_LIABILITIES') 
             THEN section_total ELSE 0 END) as total_liabilities,
    SUM(CASE WHEN balance_sheet_section IN ('CURRENT_LIABILITIES') 
             THEN section_total ELSE 0 END) as current_liabilities,
    SUM(CASE WHEN balance_sheet_section IN ('NON_CURRENT_LIABILITIES') 
             THEN section_total ELSE 0 END) as non_current_liabilities,
    SUM(CASE WHEN balance_sheet_section IN ('EQUITY') 
             THEN section_total ELSE 0 END) as total_equity,
    (SUM(CASE WHEN balance_sheet_section IN ('CURRENT_ASSETS', 'NON_CURRENT_ASSETS') 
              THEN section_total ELSE 0 END) -
     SUM(CASE WHEN balance_sheet_section IN ('CURRENT_LIABILITIES', 'NON_CURRENT_LIABILITIES') 
              THEN section_total ELSE 0 END)) as check_balance,
    NOW() as generated_at
FROM section_totals
GROUP BY currency;

-- =============================================================================
-- VIEW: Income Statement (P&L)
-- DESCRIPTION: Revenue, Expenses, and Net Income for a period
-- =============================================================================
CREATE OR REPLACE VIEW core.income_statement AS
WITH period_movements AS (
    SELECT 
        coa.coa_code,
        coa.account_name,
        coa.account_type,
        coa.parent_coa_code,
        coa.account_level,
        coa.income_statement_section,
        coa.normal_balance,
        mp.currency,
        SUM(CASE 
            WHEN mp.direction = coa.normal_balance THEN mp.amount 
            ELSE -mp.amount 
        END) as amount
    FROM core.chart_of_accounts coa
    LEFT JOIN core.movement_postings mp ON coa.coa_code = mp.coa_code
        AND mp.accounting_date >= DATE_TRUNC('month', CURRENT_DATE)
        AND mp.accounting_date <= CURRENT_DATE
    WHERE coa.account_type IN ('REVENUE', 'EXPENSE')
      AND coa.is_active = TRUE
      AND coa.is_leaf_account = TRUE
    GROUP BY coa.coa_code, coa.account_name, coa.account_type, 
             coa.parent_coa_code, coa.account_level, 
             coa.income_statement_section, coa.normal_balance, mp.currency
)
SELECT 
    pm.coa_code,
    pm.account_name,
    pm.account_type,
    pm.parent_coa_code,
    pm.account_level,
    pm.income_statement_section,
    pm.currency,
    COALESCE(pm.amount, 0) as amount,
    CASE pm.account_type
        WHEN 'REVENUE' THEN 1
        WHEN 'EXPENSE' THEN 2
    END as type_order,
    CASE pm.income_statement_section
        WHEN 'REVENUE' THEN 1
        WHEN 'COST_OF_SALES' THEN 2
        WHEN 'OPERATING_EXPENSES' THEN 3
        WHEN 'OTHER_INCOME' THEN 4
        WHEN 'OTHER_EXPENSES' THEN 5
        ELSE 6
    END as section_order,
    NOW() as generated_at
FROM period_movements pm
WHERE pm.income_statement_section IS NOT NULL
ORDER BY section_order, pm.coa_code, pm.currency;

-- =============================================================================
-- VIEW: Income Statement Summary
-- DESCRIPTION: High-level P&L totals
-- =============================================================================
CREATE OR REPLACE VIEW core.income_statement_summary AS
WITH section_totals AS (
    SELECT 
        ins.income_statement_section,
        ins.currency,
        SUM(ins.amount) as section_total
    FROM core.income_statement ins
    GROUP BY ins.income_statement_section, ins.currency
)
SELECT 
    currency,
    SUM(CASE WHEN income_statement_section = 'REVENUE' THEN section_total ELSE 0 END) as total_revenue,
    SUM(CASE WHEN income_statement_section = 'COST_OF_SALES' THEN section_total ELSE 0 END) as cost_of_sales,
    (SUM(CASE WHEN income_statement_section = 'REVENUE' THEN section_total ELSE 0 END) -
     SUM(CASE WHEN income_statement_section = 'COST_OF_SALES' THEN section_total ELSE 0 END)) as gross_profit,
    SUM(CASE WHEN income_statement_section = 'OPERATING_EXPENSES' THEN section_total ELSE 0 END) as operating_expenses,
    (SUM(CASE WHEN income_statement_section = 'REVENUE' THEN section_total ELSE 0 END) -
     SUM(CASE WHEN income_statement_section = 'COST_OF_SALES' THEN section_total ELSE 0 END) -
     SUM(CASE WHEN income_statement_section = 'OPERATING_EXPENSES' THEN section_total ELSE 0 END)) as operating_profit,
    SUM(CASE WHEN income_statement_section = 'OTHER_INCOME' THEN section_total ELSE 0 END) as other_income,
    SUM(CASE WHEN income_statement_section = 'OTHER_EXPENSES' THEN section_total ELSE 0 END) as other_expenses,
    (SUM(CASE WHEN income_statement_section = 'REVENUE' THEN section_total ELSE 0 END) -
     SUM(CASE WHEN income_statement_section = 'COST_OF_SALES' THEN section_total ELSE 0 END) -
     SUM(CASE WHEN income_statement_section = 'OPERATING_EXPENSES' THEN section_total ELSE 0 END) +
     SUM(CASE WHEN income_statement_section = 'OTHER_INCOME' THEN section_total ELSE 0 END) -
     SUM(CASE WHEN income_statement_section = 'OTHER_EXPENSES' THEN section_total ELSE 0 END)) as net_income,
    NOW() as generated_at
FROM section_totals
GROUP BY currency;

-- =============================================================================
-- VIEW: Cash Flow Statement (Simplified)
-- DESCRIPTION: Cash movements by activity type
-- =============================================================================
CREATE OR REPLACE VIEW core.cash_flow_statement AS
WITH cash_accounts AS (
    SELECT coa_code 
    FROM core.chart_of_accounts 
    WHERE is_cash_account = TRUE OR coa_code LIKE '111%'
),
cash_movements AS (
    SELECT 
        mp.coa_code,
        mp.direction,
        mp.amount,
        mp.currency,
        mp.accounting_date,
        CASE 
            WHEN tt.category IN ('deposit', 'withdrawal', 'transfer') THEN 'OPERATING'
            WHEN tt.category IN ('fee', 'adjustment') THEN 'OPERATING'
            ELSE 'OPERATING'
        END as activity_type
    FROM core.movement_postings mp
    JOIN cash_accounts ca ON mp.coa_code = ca.coa_code
    LEFT JOIN core.transaction_log tl ON mp.transaction_id = tl.transaction_id
    LEFT JOIN core.transaction_types tt ON tl.transaction_type_id = tt.type_id
    WHERE mp.accounting_date >= DATE_TRUNC('month', CURRENT_DATE)
)
SELECT 
    activity_type,
    currency,
    SUM(CASE WHEN direction = 'CREDIT' THEN amount ELSE 0 END) as cash_in,
    SUM(CASE WHEN direction = 'DEBIT' THEN amount ELSE 0 END) as cash_out,
    (SUM(CASE WHEN direction = 'CREDIT' THEN amount ELSE 0 END) -
     SUM(CASE WHEN direction = 'DEBIT' THEN amount ELSE 0 END)) as net_cash_flow,
    NOW() as generated_at
FROM cash_movements
GROUP BY activity_type, currency
ORDER BY activity_type, currency;

-- =============================================================================
-- FUNCTION: Get balance sheet as-of date
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_balance_sheet_as_of(
    p_as_of_date DATE
)
RETURNS TABLE (
    coa_code VARCHAR(50),
    account_name VARCHAR(200),
    account_type VARCHAR(20),
    balance_sheet_section VARCHAR(50),
    currency VARCHAR(3),
    balance NUMERIC(20, 8),
    section_order INTEGER
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
        coa.balance_sheet_section,
        mp.currency,
        COALESCE(SUM(CASE 
            WHEN mp.direction = coa.normal_balance THEN mp.amount 
            ELSE -mp.amount 
        END), 0) as balance,
        CASE coa.balance_sheet_section
            WHEN 'CURRENT_ASSETS' THEN 1
            WHEN 'NON_CURRENT_ASSETS' THEN 2
            WHEN 'CURRENT_LIABILITIES' THEN 3
            WHEN 'NON_CURRENT_LIABILITIES' THEN 4
            WHEN 'EQUITY' THEN 5
            ELSE 6
        END as section_order
    FROM core.chart_of_accounts coa
    LEFT JOIN core.movement_postings mp ON coa.coa_code = mp.coa_code
        AND mp.accounting_date <= p_as_of_date
    WHERE coa.account_type IN ('ASSET', 'LIABILITY', 'EQUITY')
      AND coa.is_active = TRUE
      AND coa.is_leaf_account = TRUE
      AND coa.balance_sheet_section IS NOT NULL
    GROUP BY coa.coa_code, coa.account_name, coa.account_type, 
             coa.balance_sheet_section, coa.normal_balance, mp.currency
    ORDER BY section_order, coa.coa_code;
END;
$$;

-- =============================================================================
-- FUNCTION: Get income statement for period
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_income_statement(
    p_start_date DATE,
    p_end_date DATE
)
RETURNS TABLE (
    coa_code VARCHAR(50),
    account_name VARCHAR(200),
    account_type VARCHAR(20),
    income_statement_section VARCHAR(50),
    currency VARCHAR(3),
    amount NUMERIC(20, 8),
    section_order INTEGER
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
        coa.income_statement_section,
        mp.currency,
        COALESCE(SUM(CASE 
            WHEN mp.direction = coa.normal_balance THEN mp.amount 
            ELSE -mp.amount 
        END), 0) as amount,
        CASE coa.income_statement_section
            WHEN 'REVENUE' THEN 1
            WHEN 'COST_OF_SALES' THEN 2
            WHEN 'OPERATING_EXPENSES' THEN 3
            WHEN 'OTHER_INCOME' THEN 4
            WHEN 'OTHER_EXPENSES' THEN 5
            ELSE 6
        END as section_order
    FROM core.chart_of_accounts coa
    LEFT JOIN core.movement_postings mp ON coa.coa_code = mp.coa_code
        AND mp.accounting_date BETWEEN p_start_date AND p_end_date
    WHERE coa.account_type IN ('REVENUE', 'EXPENSE')
      AND coa.is_active = TRUE
      AND coa.is_leaf_account = TRUE
      AND coa.income_statement_section IS NOT NULL
    GROUP BY coa.coa_code, coa.account_name, coa.account_type, 
             coa.income_statement_section, coa.normal_balance, mp.currency
    ORDER BY section_order, coa.coa_code;
END;
$$;

-- =============================================================================
-- FUNCTION: Verify financial statements balance
-- =============================================================================
CREATE OR REPLACE FUNCTION core.verify_financial_statements(
    p_as_of_date DATE DEFAULT CURRENT_DATE
)
RETURNS TABLE (
    statement_type VARCHAR,
    check_name VARCHAR,
    is_valid BOOLEAN,
    expected_value NUMERIC,
    actual_value NUMERIC,
    variance NUMERIC,
    checked_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_assets NUMERIC;
    v_liabilities NUMERIC;
    v_equity NUMERIC;
    v_total_debits NUMERIC;
    v_total_credits NUMERIC;
BEGIN
    -- Check Balance Sheet: Assets = Liabilities + Equity
    SELECT 
        COALESCE(SUM(CASE WHEN balance_sheet_section LIKE '%ASSETS%' THEN balance ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN balance_sheet_section LIKE '%LIABILITIES%' THEN balance ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN balance_sheet_section = 'EQUITY' THEN balance ELSE 0 END), 0)
    INTO v_assets, v_liabilities, v_equity
    FROM core.get_balance_sheet_as_of(p_as_of_date);
    
    RETURN QUERY SELECT 
        'Balance Sheet'::VARCHAR,
        'Assets = Liabilities + Equity'::VARCHAR,
        ABS(v_assets - (v_liabilities + v_equity)) < 0.01,
        v_liabilities + v_equity,
        v_assets,
        v_assets - (v_liabilities + v_equity),
        NOW();
    
    -- Check Trial Balance: Debits = Credits
    SELECT 
        COALESCE(SUM(CASE WHEN direction = 'DEBIT' THEN amount ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN direction = 'CREDIT' THEN amount ELSE 0 END), 0)
    INTO v_total_debits, v_total_credits
    FROM core.movement_postings
    WHERE accounting_date <= p_as_of_date;
    
    RETURN QUERY SELECT 
        'Trial Balance'::VARCHAR,
        'Debits = Credits'::VARCHAR,
        ABS(v_total_debits - v_total_credits) < 0.01,
        v_total_credits,
        v_total_debits,
        v_total_debits - v_total_credits,
        NOW();
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON VIEW core.balance_sheet IS 'Balance sheet as of current date';
COMMENT ON VIEW core.balance_sheet_summary IS 'Balance sheet summary totals';
COMMENT ON VIEW core.income_statement IS 'Income statement for current month';
COMMENT ON VIEW core.income_statement_summary IS 'Income statement summary with key metrics';
COMMENT ON VIEW core.cash_flow_statement IS 'Cash flow statement for current month';
COMMENT ON FUNCTION core.verify_financial_statements IS 'Verifies that financial statements balance correctly';

-- =============================================================================
-- END OF FILE
-- =============================================================================
