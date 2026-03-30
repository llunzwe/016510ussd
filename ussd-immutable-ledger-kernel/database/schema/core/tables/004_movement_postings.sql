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

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.movement_postings (
    -- Primary identifier
    posting_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Source movement leg
    movement_id UUID NOT NULL REFERENCES ussd_core.movement_headers(movement_id),
    leg_id UUID NOT NULL REFERENCES ussd_core.movement_legs(leg_id),
    
    -- Affected account
    account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    
    -- Posting details
    direction VARCHAR(6) NOT NULL CHECK (direction IN ('DEBIT', 'CREDIT')),
    amount NUMERIC(20, 8) NOT NULL CHECK (amount > 0),
    currency VARCHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    
    -- Running balance after this posting
    running_balance NUMERIC(20, 8) NOT NULL,
    
    -- Chart of accounts
    coa_code VARCHAR(50) NOT NULL REFERENCES ussd_core.chart_of_accounts(coa_code),
    
    -- Accounting dates
    accounting_date DATE NOT NULL,
    value_date DATE NOT NULL,
    
    -- Narrative
    description TEXT,
    
    -- Integrity hash
    posting_hash VARCHAR(64) NOT NULL,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    
    -- Audit
    record_hash VARCHAR(64) NOT NULL,
    
    -- Partition key
    partition_date DATE NOT NULL DEFAULT CURRENT_DATE
) PARTITION BY RANGE (partition_date);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
