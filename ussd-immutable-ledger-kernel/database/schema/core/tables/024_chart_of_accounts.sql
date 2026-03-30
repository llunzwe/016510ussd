-- =============================================================================
-- USSD KERNEL CORE SCHEMA - CHART OF ACCOUNTS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    024_chart_of_accounts.sql
-- SCHEMA:      ussd_core
-- TABLE:       chart_of_accounts
-- DESCRIPTION: Master chart of accounts for double-entry bookkeeping
--              supporting hierarchical account structure and multiple
--              accounting standards (GAAP, IFRS).
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.5.9 Information assets - COA inventory
├── A.12.4 Logging and monitoring - COA change monitoring
└── A.18.1 Compliance - Financial reporting compliance

Financial Regulations
├── GAAP/IFRS: Standard-compliant account structure
├── Audit trail: COA change tracking
├── Segregation: Proper account segregation
└── Reporting: Financial statement support

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. ACCOUNT TYPES
   - ASSET: Balance sheet assets
   - LIABILITY: Balance sheet liabilities
   - EQUITY: Owner's equity
   - REVENUE: Income accounts
   - EXPENSE: Expense accounts
   - MEMO: Statistical/memo accounts

2. ACCOUNT CATEGORIES
   - Current vs non-current
   - Operating vs non-operating
   - Restricted vs unrestricted

3. HIERARCHY
   - Parent-child relationships
   - Roll-up structure
   - Level indicators

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

COA SECURITY:
- Immutable account codes
- Versioned account changes
- Approval workflow for modifications

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: coa_code
- TYPE: account_type + coa_code
- PARENT: parent_coa_code
- CATEGORY: account_category

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- ACCOUNT_CREATED
- ACCOUNT_MODIFIED
- ACCOUNT_RETIRED

RETENTION: Permanent
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.chart_of_accounts (
    -- Primary identifier
    coa_code VARCHAR(50) PRIMARY KEY,
    
    -- Account details
    account_name VARCHAR(200) NOT NULL,
    account_name_local VARCHAR(200),
    account_description TEXT,
    
    -- Classification
    account_type VARCHAR(20) NOT NULL
        CHECK (account_type IN ('ASSET', 'LIABILITY', 'EQUITY', 'REVENUE', 'EXPENSE', 'MEMO')),
    account_category VARCHAR(50),
    account_subcategory VARCHAR(50),
    
    -- Hierarchy
    parent_coa_code VARCHAR(50) REFERENCES ussd_core.chart_of_accounts(coa_code),
    account_level INTEGER DEFAULT 1,
    is_leaf_account BOOLEAN DEFAULT TRUE,
    
    -- Normal balance
    normal_balance VARCHAR(6) NOT NULL
        CHECK (normal_balance IN ('DEBIT', 'CREDIT')),
    
    -- Configuration
    is_active BOOLEAN DEFAULT TRUE,
    is_bank_account BOOLEAN DEFAULT FALSE,
    is_cash_account BOOLEAN DEFAULT FALSE,
    requires_cost_center BOOLEAN DEFAULT FALSE,
    requires_project BOOLEAN DEFAULT FALSE,
    
    -- Application scope
    application_id UUID,  -- NULL for system-wide accounts
    
    -- Financial statement mapping
    balance_sheet_section VARCHAR(50),
    income_statement_section VARCHAR(50),
    cash_flow_section VARCHAR(50),
    
    -- Validity period
    valid_from DATE NOT NULL DEFAULT CURRENT_DATE,
    valid_to DATE,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    created_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    record_hash VARCHAR(64) NOT NULL
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
