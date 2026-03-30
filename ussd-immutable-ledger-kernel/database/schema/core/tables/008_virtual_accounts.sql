-- =============================================================================
-- USSD KERNEL CORE SCHEMA - VIRTUAL ACCOUNTS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    008_virtual_accounts.sql
-- SCHEMA:      ussd_core
-- TABLE:       virtual_accounts
-- DESCRIPTION: Sub-accounts for budgeting, savings goals, and temporary holds.
--              Linked to parent accounts but with separate balance tracking.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Virtual account access control
├── A.8.5 Secure authentication - Parent account authentication required
└── A.8.11 Data masking - Virtual account masking

ISO/IEC 27040:2024 (Storage Security)
├── Immutable virtual account history
├── Balance integrity verification
└── Audit trail for all virtual account operations

Financial Regulations
├── Customer funds segregation: Virtual accounts are bookkeeping only
├── No separate legal ownership: Belongs to parent account holder
├── Interest calculation: May be aggregated with parent account
└── Reporting: Virtual account balances reported to parent

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. VIRTUAL ACCOUNT TYPES
   - BUDGET: Spending category budgeting
   - SAVINGS_GOAL: Target-based savings
   - ESCROW: Third-party holding
   - RESERVE: Mandatory reserve
   - TEMPORARY_HOLD: Time-limited hold

2. BALANCE MANAGEMENT
   - Zero or positive balance only (no credit)
   - Parent account guarantees virtual account balance
   - Sweep functionality for savings goals

3. LIFECYCLE
   - Active: Available for transactions
   - Frozen: No debits allowed
   - Closed: Archived, balance swept to parent
   - Matured: Savings goal reached

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

ACCESS CONTROL:
- Parent account holders control virtual accounts
- Delegated access possible via agent_relationships
- API access restricted by virtual account permissions

INTEGRITY:
- Virtual account balances must sum to parent available balance
- Periodic reconciliation with parent account
- Exception reporting for imbalances

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: virtual_account_id
- PARENT: parent_account_id + status
- TYPE: virtual_account_type + status
- GOAL: target_date (for savings goal queries)

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- VIRTUAL_ACCOUNT_CREATED
- VIRTUAL_ACCOUNT_FUNDED
- VIRTUAL_ACCOUNT_DEBITED
- VIRTUAL_ACCOUNT_CLOSED
- GOAL_REACHED

RETENTION: 7 years
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.virtual_accounts (
    -- Primary identifier
    virtual_account_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Parent account
    parent_account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    
    -- Virtual account details
    virtual_account_name VARCHAR(100) NOT NULL,
    virtual_account_type VARCHAR(50) NOT NULL
        CHECK (virtual_account_type IN ('BUDGET', 'SAVINGS_GOAL', 'ESCROW', 'RESERVE', 'TEMPORARY_HOLD')),
    
    -- Purpose/description
    description TEXT,
    purpose_code VARCHAR(50),
    
    -- Balance
    current_balance NUMERIC(20, 8) NOT NULL DEFAULT 0,
    currency VARCHAR(3) NOT NULL,
    
    -- Target (for savings goals)
    target_amount NUMERIC(20, 8),
    target_date DATE,
    
    -- Limits
    minimum_balance NUMERIC(20, 8) DEFAULT 0,
    maximum_balance NUMERIC(20, 8),
    
    -- Rules
    auto_sweep_enabled BOOLEAN DEFAULT FALSE,
    auto_sweep_threshold NUMERIC(20, 8),
    auto_sweep_destination UUID,  -- Another virtual account or parent
    
    -- Status
    status VARCHAR(20) DEFAULT 'active'
        CHECK (status IN ('active', 'frozen', 'closed', 'matured')),
    
    -- Lifecycle
    opened_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    closed_at TIMESTAMPTZ,
    maturity_date DATE,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    record_hash VARCHAR(64) NOT NULL
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
