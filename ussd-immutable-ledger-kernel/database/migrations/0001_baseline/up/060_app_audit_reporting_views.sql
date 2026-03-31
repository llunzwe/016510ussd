-- =============================================================================
-- USSD KERNEL APP SCHEMA - AUDIT & REPORTING VIEWS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    060_app_audit_reporting_views.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      app
-- DESCRIPTION: Comprehensive audit views and financial reporting for
--              regulatory compliance and management reporting.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Audit monitoring
├── A.18.1 Compliance - Regulatory reporting
└── A.18.2 Compliance - Audit trail completeness

Financial Regulations
├── IFRS/GAAP: Financial statement reporting
├── Basel: Credit risk reporting
├── Tax: VAT/GST returns
└── Central Bank: Statistical returns

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. MATERIALIZED VIEWS for performance
2. INCREMENTAL REFRESH for large datasets
3. PARTITION-AWARE queries
4. RLS compliance for multi-tenancy

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- REPORT_GENERATED
- FINANCIAL_DATA_EXPORTED
- AUDIT_VIEW_ACCESSED

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- FINANCIAL STATEMENT VIEWS
-- =============================================================================

-- Balance Sheet View
CREATE OR REPLACE VIEW app.v_balance_sheet AS
WITH account_balances AS (
    SELECT 
        ca.app_id,
        ca.account_code,
        ca.account_name,
        ca.account_type,
        ca.balance_sheet_section,
        ca.normal_balance,
        je.currency_code,
        SUM(CASE 
            WHEN je.side = ca.normal_balance THEN je.amount 
            ELSE -je.amount 
        END) as balance
    FROM app.chart_of_accounts ca
    LEFT JOIN app.journal_entries je ON ca.account_id = je.account_id
        AND je.posted_at::DATE <= CURRENT_DATE
        AND je.entry_type != 'REVERSAL'
    WHERE ca.is_active = TRUE
      AND ca.is_leaf_account = TRUE
      AND ca.account_type IN ('ASSET', 'LIABILITY', 'EQUITY')
    GROUP BY ca.app_id, ca.account_code, ca.account_name, ca.account_type, 
             ca.balance_sheet_section, ca.normal_balance, je.currency_code
)
SELECT 
    app_id,
    account_code,
    account_name,
    account_type,
    balance_sheet_section,
    currency_code,
    balance,
    CASE balance_sheet_section
        WHEN 'CURRENT_ASSETS' THEN 1
        WHEN 'NON_CURRENT_ASSETS' THEN 2
        WHEN 'CURRENT_LIABILITIES' THEN 3
        WHEN 'NON_CURRENT_LIABILITIES' THEN 4
        WHEN 'EQUITY' THEN 5
    END as display_order,
    NOW() as generated_at
FROM account_balances
WHERE balance_sheet_section IS NOT NULL;

-- Balance Sheet Summary
CREATE OR REPLACE VIEW app.v_balance_sheet_summary AS
SELECT 
    app_id,
    currency_code,
    SUM(CASE WHEN balance_sheet_section LIKE '%ASSETS%' THEN balance ELSE 0 END) as total_assets,
    SUM(CASE WHEN balance_sheet_section LIKE '%LIABILITIES%' THEN balance ELSE 0 END) as total_liabilities,
    SUM(CASE WHEN balance_sheet_section = 'EQUITY' THEN balance ELSE 0 END) as total_equity,
    NOW() as generated_at
FROM app.v_balance_sheet
GROUP BY app_id, currency_code;

-- Income Statement View
CREATE OR REPLACE VIEW app.v_income_statement AS
WITH period_movements AS (
    SELECT 
        ca.app_id,
        ca.account_code,
        ca.account_name,
        ca.account_type,
        ca.income_statement_section,
        je.currency_code,
        SUM(CASE 
            WHEN je.side = ca.normal_balance THEN je.amount 
            ELSE -je.amount 
        END) as amount
    FROM app.chart_of_accounts ca
    LEFT JOIN app.journal_entries je ON ca.account_id = je.account_id
        AND je.posted_at >= DATE_TRUNC('month', CURRENT_DATE)
        AND je.posted_at < DATE_TRUNC('month', CURRENT_DATE) + INTERVAL '1 month'
        AND je.entry_type != 'REVERSAL'
    WHERE ca.is_active = TRUE
      AND ca.is_leaf_account = TRUE
      AND ca.account_type IN ('REVENUE', 'EXPENSE')
    GROUP BY ca.app_id, ca.account_code, ca.account_name, ca.account_type, 
             ca.income_statement_section, je.currency_code
)
SELECT 
    app_id,
    account_code,
    account_name,
    account_type,
    income_statement_section,
    currency_code,
    amount,
    CASE income_statement_section
        WHEN 'REVENUE' THEN 1
        WHEN 'COST_OF_SALES' THEN 2
        WHEN 'OPERATING_EXPENSES' THEN 3
        WHEN 'OTHER_INCOME' THEN 4
        WHEN 'OTHER_EXPENSES' THEN 5
    END as display_order,
    NOW() as generated_at
FROM period_movements
WHERE income_statement_section IS NOT NULL;

-- Income Statement Summary
CREATE OR REPLACE VIEW app.v_income_statement_summary AS
SELECT 
    app_id,
    currency_code,
    SUM(CASE WHEN income_statement_section = 'REVENUE' THEN amount ELSE 0 END) as total_revenue,
    SUM(CASE WHEN income_statement_section = 'COST_OF_SALES' THEN amount ELSE 0 END) as cost_of_sales,
    SUM(CASE WHEN income_statement_section = 'OPERATING_EXPENSES' THEN amount ELSE 0 END) as operating_expenses,
    SUM(CASE WHEN income_statement_section = 'REVENUE' THEN amount ELSE 0 END) -
    SUM(CASE WHEN income_statement_section IN ('COST_OF_SALES', 'OPERATING_EXPENSES') THEN amount ELSE 0 END) as net_income,
    NOW() as generated_at
FROM app.v_income_statement
GROUP BY app_id, currency_code;

-- =============================================================================
-- TRIAL BALANCE VIEW
-- =============================================================================

CREATE OR REPLACE VIEW app.v_trial_balance AS
SELECT 
    ca.app_id,
    ca.account_code,
    ca.account_name,
    ca.account_type,
    ca.normal_balance,
    je.currency_code,
    COALESCE(SUM(CASE WHEN je.side = 'DEBIT' THEN je.amount ELSE 0 END), 0) as total_debits,
    COALESCE(SUM(CASE WHEN je.side = 'CREDIT' THEN je.amount ELSE 0 END), 0) as total_credits,
    COALESCE(SUM(CASE WHEN je.side = 'DEBIT' THEN je.amount ELSE -je.amount END), 0) as net_balance,
    NOW() as generated_at
FROM app.chart_of_accounts ca
LEFT JOIN app.journal_entries je ON ca.account_id = je.account_id
    AND je.posted_at::DATE <= CURRENT_DATE
    AND je.entry_type != 'REVERSAL'
WHERE ca.is_active = TRUE
  AND ca.is_leaf_account = TRUE
GROUP BY ca.app_id, ca.account_code, ca.account_name, ca.account_type, 
         ca.normal_balance, je.currency_code;

-- =============================================================================
-- AUDIT VIEWS
-- =============================================================================

-- Transaction Audit Trail
CREATE OR REPLACE VIEW app.v_transaction_audit AS
SELECT 
    tl.transaction_id,
    tl.transaction_uuid,
    tl.idempotency_key,
    tt.type_code as transaction_type,
    tl.application_id,
    tl.initiator_account_id,
    ar.display_name as initiator_name,
    tl.amount,
    tl.currency,
    tl.status,
    tl.committed_at,
    tl.client_timestamp,
    tl.payload,
    tl.signature,
    tl.record_hash,
    je.entry_id as journal_entry_id,
    je.account_code,
    je.side,
    je.amount as posted_amount
FROM core.transaction_log tl
LEFT JOIN core.transaction_types tt ON tl.transaction_type_id = tt.type_id
LEFT JOIN core.account_registry ar ON tl.initiator_account_id = ar.account_id
LEFT JOIN app.journal_entries je ON tl.transaction_id = je.core_transaction_id;

-- Financial Activity Summary
CREATE OR REPLACE VIEW app.v_financial_activity AS
SELECT 
    je.app_id,
    DATE_TRUNC('day', je.posted_at)::DATE as activity_date,
    ca.account_type,
    je.entry_type,
    je.currency_code,
    COUNT(*) as transaction_count,
    SUM(CASE WHEN je.side = 'DEBIT' THEN je.amount ELSE 0 END) as total_debits,
    SUM(CASE WHEN je.side = 'CREDIT' THEN je.amount ELSE 0 END) as total_credits,
    NOW() as generated_at
FROM app.journal_entries je
JOIN app.chart_of_accounts ca ON je.account_id = ca.account_id
WHERE je.posted_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY je.app_id, DATE_TRUNC('day', je.posted_at), ca.account_type, je.entry_type, je.currency_code;

-- Fee Revenue Analysis
CREATE OR REPLACE VIEW app.v_fee_revenue_analysis AS
SELECT 
    ft.app_id,
    fs.fee_category,
    DATE_TRUNC('month', ft.calculated_at)::DATE as revenue_month,
    ft.fee_currency as currency,
    COUNT(*) as fee_count,
    SUM(ft.gross_fee) as gross_revenue,
    SUM(ft.tax_amount) as tax_collected,
    SUM(ft.net_fee) as net_revenue,
    SUM(CASE WHEN ft.is_waived THEN ft.gross_fee ELSE 0 END) as waived_amount,
    NOW() as generated_at
FROM app.fee_transactions ft
LEFT JOIN app.fee_schedules fs ON ft.schedule_id = fs.schedule_id
WHERE ft.status = 'POSTED'
GROUP BY ft.app_id, fs.fee_category, DATE_TRUNC('month', ft.calculated_at), ft.fee_currency;

-- Commission Payout Analysis
CREATE OR REPLACE VIEW app.v_commission_analysis AS
SELECT 
    ct.app_id,
    ct.recipient_type,
    DATE_TRUNC('month', ct.calculated_at)::DATE as commission_month,
    ct.commission_currency as currency,
    COUNT(*) as commission_count,
    SUM(ct.gross_commission) as gross_commission,
    SUM(ct.withholding_tax) as tax_withheld,
    SUM(ct.net_commission) as net_payable,
    SUM(CASE WHEN ct.status = 'PAID' THEN ct.net_commission ELSE 0 END) as amount_paid,
    SUM(CASE WHEN ct.status IN ('CALCULATED', 'APPROVED', 'PENDING_PAYMENT') THEN ct.net_commission ELSE 0 END) as pending_payment,
    NOW() as generated_at
FROM app.commission_transactions ct
WHERE ct.is_clawback = FALSE
GROUP BY ct.app_id, ct.recipient_type, DATE_TRUNC('month', ct.calculated_at), ct.commission_currency;

-- =============================================================================
-- REGULATORY REPORTING VIEWS
-- =============================================================================

-- Daily Transaction Summary (for regulatory returns)
CREATE OR REPLACE VIEW app.v_daily_transaction_summary AS
SELECT 
    tl.application_id as app_id,
    tl.entry_date,
    tt.type_code as transaction_type,
    tl.currency,
    COUNT(*) as transaction_count,
    SUM(tl.amount) as total_amount,
    AVG(tl.amount) as avg_amount,
    MIN(tl.amount) as min_amount,
    MAX(tl.amount) as max_amount,
    COUNT(DISTINCT tl.initiator_account_id) as unique_customers,
    NOW() as generated_at
FROM core.transaction_log tl
JOIN core.transaction_types tt ON tl.transaction_type_id = tt.type_id
WHERE tl.status IN ('posted', 'completed')
GROUP BY tl.application_id, tl.entry_date, tt.type_code, tl.currency;

-- FX Transaction Reporting
CREATE OR REPLACE VIEW app.v_fx_transaction_report AS
SELECT 
    je.app_id,
    je.posted_at::DATE as transaction_date,
    je.entry_currency as from_currency,
    je.account_currency as to_currency,
    je.fx_rate,
    COUNT(*) as transaction_count,
    SUM(je.amount) as total_amount,
    SUM(je.amount_in_account_currency) as total_converted,
    NOW() as generated_at
FROM app.journal_entries je
WHERE je.entry_currency != je.account_currency
  AND je.posted_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY je.app_id, je.posted_at::DATE, je.entry_currency, je.account_currency, je.fx_rate;

-- Tax Liability Report
CREATE OR REPLACE VIEW app.v_tax_liability_report AS
SELECT 
    tt.app_id,
    tr.tax_code,
    tr.tax_type,
    tt.tax_direction,
    DATE_TRUNC('month', tt.calculated_at)::DATE as tax_month,
    tt.tax_currency as currency,
    COUNT(*) as transaction_count,
    SUM(tt.basis_amount) as total_basis,
    SUM(tt.tax_amount) as total_tax,
    NOW() as generated_at
FROM app.tax_transactions tt
JOIN app.tax_rates tr ON tt.tax_rate_id = tr.tax_rate_id
WHERE tt.status IN ('CALCULATED', 'REPORTED', 'PAID')
GROUP BY tt.app_id, tr.tax_code, tr.tax_type, tt.tax_direction, 
         DATE_TRUNC('month', tt.calculated_at), tt.tax_currency;

-- =============================================================================
-- RISK & COMPLIANCE VIEWS
-- =============================================================================

-- High Risk Transaction Monitoring
CREATE OR REPLACE VIEW app.v_high_risk_transactions AS
SELECT 
    tl.transaction_id,
    tl.application_id as app_id,
    tl.initiator_account_id,
    ar.display_name as customer_name,
    tt.type_code as transaction_type,
    tl.amount,
    tl.currency,
    tl.status,
    tl.committed_at,
    tt.risk_level,
    CASE 
        WHEN tl.amount > 100000 THEN 'HIGH_VALUE'
        WHEN tt.risk_level = 'high' THEN 'HIGH_RISK_TYPE'
        ELSE 'NORMAL'
    END as risk_category,
    NOW() as flagged_at
FROM core.transaction_log tl
JOIN core.transaction_types tt ON tl.transaction_type_id = tt.type_id
JOIN core.account_registry ar ON tl.initiator_account_id = ar.account_id
WHERE (tl.amount > 100000 OR tt.risk_level IN ('high', 'critical'))
  AND tl.committed_at >= CURRENT_DATE - INTERVAL '7 days';

-- Suspicious Activity Pattern Detection
CREATE OR REPLACE VIEW app.v_velocity_analysis AS
WITH customer_activity AS (
    SELECT 
        application_id as app_id,
        initiator_account_id,
        DATE_TRUNC('hour', committed_at) as activity_hour,
        COUNT(*) as transaction_count,
        SUM(amount) as total_amount,
        COUNT(DISTINCT currency) as currency_count
    FROM core.transaction_log
    WHERE committed_at >= CURRENT_DATE - INTERVAL '24 hours'
      AND status IN ('posted', 'completed')
    GROUP BY application_id, initiator_account_id, DATE_TRUNC('hour', committed_at)
)
SELECT 
    app_id,
    initiator_account_id,
    activity_hour,
    transaction_count,
    total_amount,
    currency_count,
    CASE 
        WHEN transaction_count > 50 THEN 'HIGH_FREQUENCY'
        WHEN total_amount > 1000000 THEN 'HIGH_VALUE'
        WHEN currency_count > 3 THEN 'MULTI_CURRENCY'
        ELSE 'NORMAL'
    END as velocity_flag,
    NOW() as analyzed_at
FROM customer_activity
WHERE transaction_count > 50 OR total_amount > 1000000 OR currency_count > 3;

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to generate financial report for period
CREATE OR REPLACE FUNCTION app.generate_financial_report(
    p_app_id UUID,
    p_start_date DATE,
    p_end_date DATE,
    p_report_type VARCHAR
)
RETURNS TABLE (
    line_item VARCHAR,
    line_code VARCHAR,
    amount NUMERIC,
    currency_code VARCHAR
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    IF p_report_type = 'TRIAL_BALANCE' THEN
        RETURN QUERY
        SELECT 
            ca.account_name::VARCHAR,
            ca.account_code::VARCHAR,
            COALESCE(SUM(CASE WHEN je.side = 'DEBIT' THEN je.amount ELSE -je.amount END), 0)::NUMERIC,
            je.currency_code::VARCHAR
        FROM app.chart_of_accounts ca
        LEFT JOIN app.journal_entries je ON ca.account_id = je.account_id
            AND je.posted_at::DATE BETWEEN p_start_date AND p_end_date
        WHERE ca.app_id = p_app_id
          AND ca.is_active = TRUE
        GROUP BY ca.account_id, ca.account_name, ca.account_code, je.currency_code
        ORDER BY ca.account_code;
        
    ELSIF p_report_type = 'REVENUE_SUMMARY' THEN
        RETURN QUERY
        SELECT 
            fs.fee_category::VARCHAR,
            'REV-' || fs.fee_category::VARCHAR,
            COALESCE(SUM(ft.net_fee), 0)::NUMERIC,
            ft.fee_currency::VARCHAR
        FROM app.fee_schedules fs
        LEFT JOIN app.fee_transactions ft ON fs.schedule_id = ft.schedule_id
            AND ft.calculated_at::DATE BETWEEN p_start_date AND p_end_date
            AND ft.status = 'POSTED'
        WHERE fs.app_id = p_app_id
        GROUP BY fs.fee_category, ft.fee_currency;
    END IF;
END;
$$;

-- Function to export audit trail
CREATE OR REPLACE FUNCTION app.export_audit_trail(
    p_app_id UUID,
    p_start_date DATE,
    p_end_date DATE
)
RETURNS TABLE (
    event_timestamp TIMESTAMPTZ,
    event_type VARCHAR,
    transaction_id BIGINT,
    account_id UUID,
    amount NUMERIC,
    currency VARCHAR,
    status VARCHAR,
    record_hash VARCHAR
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        tl.committed_at as event_timestamp,
        tt.type_code::VARCHAR as event_type,
        tl.transaction_id,
        tl.initiator_account_id as account_id,
        tl.amount,
        tl.currency,
        tl.status::VARCHAR,
        tl.record_hash
    FROM core.transaction_log tl
    JOIN core.transaction_types tt ON tl.transaction_type_id = tt.type_id
    WHERE tl.application_id = p_app_id
      AND tl.committed_at::DATE BETWEEN p_start_date AND p_end_date
    ORDER BY tl.committed_at;
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON VIEW app.v_balance_sheet IS 'Balance sheet view for financial reporting';
COMMENT ON VIEW app.v_income_statement IS 'Income statement (P&L) view';
COMMENT ON VIEW app.v_trial_balance IS 'Trial balance with debit/credit totals';
COMMENT ON VIEW app.v_high_risk_transactions IS 'Flagged high-value and high-risk transactions';
COMMENT ON FUNCTION app.generate_financial_report IS 'Generate financial reports by type and period';

-- =============================================================================
-- END OF FILE
-- =============================================================================
