-- =============================================================================
-- USSD KERNEL CORE SCHEMA - PERIOD END BALANCES
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    025_period_end_balances.sql
-- SCHEMA:      ussd_core
-- TABLE:       period_end_balances
-- DESCRIPTION: Snapshot balances at period ends (day, month, year) for
--              financial reporting and audit trail purposes.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Balance verification
├── A.18.1 Compliance - Financial reporting support
└── A.18.2 Compliance - Audit trail maintenance

Financial Regulations
├── Period-end close: Mandatory balance snapshots
├── Audit trail: Immutable period records
├── Financial statements: Balance support
└── Variance analysis: Period comparison support

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. PERIOD TYPES
   - DAILY: End of day
   - MONTHLY: Month end
   - QUARTERLY: Quarter end
   - YEARLY: Fiscal year end
   - ADJUSTED: Post-adjustment snapshot

2. BALANCE TYPES
   - OPENING: Period start balance
   - CLOSING: Period end balance
   - ADJUSTED: After adjustments

3. RECONCILIATION
   - Opening + Movements = Closing verification
   - Variance analysis support
   - Audit trail linking

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

BALANCE SECURITY:
- Immutable period records
- Hash verification
- Approval workflow for adjustments

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: balance_id
- ACCOUNT: account_id + period_type + period_end_date
- PERIOD: period_type + period_end_date
- COA: coa_code + period_end_date

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- BALANCE_SNAPSHOT_CREATED
- BALANCE_ADJUSTED
- BALANCE_VERIFIED

RETENTION: Permanent
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.period_end_balances (
    -- Primary identifier
    balance_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Account reference
    account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    coa_code VARCHAR(50) NOT NULL REFERENCES ussd_core.chart_of_accounts(coa_code),
    
    -- Period definition
    period_type VARCHAR(20) NOT NULL
        CHECK (period_type IN ('DAILY', 'MONTHLY', 'QUARTERLY', 'YEARLY', 'ADJUSTED')),
    period_start_date DATE NOT NULL,
    period_end_date DATE NOT NULL,
    fiscal_year INTEGER NOT NULL,
    fiscal_period INTEGER NOT NULL,
    
    -- Balance type
    balance_type VARCHAR(20) NOT NULL
        CHECK (balance_type IN ('OPENING', 'CLOSING', 'ADJUSTED')),
    
    -- Currency
    currency VARCHAR(3) NOT NULL,
    
    -- Balances
    debit_balance NUMERIC(20, 8) DEFAULT 0,
    credit_balance NUMERIC(20, 8) DEFAULT 0,
    net_balance NUMERIC(20, 8) DEFAULT 0,
    
    -- Movement summary
    total_debits NUMERIC(20, 8) DEFAULT 0,
    total_credits NUMERIC(20, 8) DEFAULT 0,
    transaction_count INTEGER DEFAULT 0,
    
    -- Verification
    is_verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    verified_by UUID,
    
    -- Adjustment tracking
    is_adjusted BOOLEAN DEFAULT FALSE,
    adjustment_count INTEGER DEFAULT 0,
    adjusted_at TIMESTAMPTZ,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    UNIQUE (account_id, period_type, period_end_date, balance_type, currency)
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
