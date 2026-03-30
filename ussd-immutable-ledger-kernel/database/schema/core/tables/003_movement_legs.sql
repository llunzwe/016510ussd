-- =============================================================================
-- USSD KERNEL CORE SCHEMA - MOVEMENT LEGS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    003_movement_legs.sql
-- SCHEMA:      ussd_core
-- TABLE:       movement_legs
-- DESCRIPTION: Individual debit/credit entries forming double-entry movements.
--              Each leg represents one side of an accounting transaction.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Leg origin verification
├── A.8.5 Secure authentication - Movement authorization
└── A.12.3 Information backup - Leg-level backup verification

ISO/IEC 27040:2024 (Storage Security)
├── Immutable storage: Leg records write-once
├── Hash chain: Each leg contributes to movement control hash
├── Tamper detection: Leg hash verification
└── Retention: Aligned with transaction_log retention

GAAP/IFRS Compliance
├── Double-entry bookkeeping: Debits = Credits per movement
├── Audit trail: Complete transaction history preserved
├── Chart of accounts: COA codes tracked per leg
└── Period-end reporting: Legs support balance calculations

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. DOUBLE-ENTRY VALIDATION
   - CHECK constraint: SUM(debits) = SUM(credits) per movement
   - Trigger validation on insert
   - Control hash computation across all legs

2. CURRENCY HANDLING
   - ISO 4217 currency codes (3 characters)
   - Amount precision: NUMERIC(20, 8) for fractional units
   - No currency mixing within a single movement

3. CHART OF ACCOUNTS
   - COA code reference per leg
   - Supports hierarchical account structure
   - Validated against chart_of_accounts table

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

INTEGRITY VERIFICATION:
- Individual leg hash computed on insert
- Control hash aggregates all leg hashes per movement
- Hash algorithm: SHA-256 via pgcrypto

AUTHORIZATION:
- Legs inherit authorization from parent movement
- Account-level RLS policies apply
- Posting restrictions validated

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: leg_id
- MOVEMENT: movement_id (foreign key lookups)
- ACCOUNT: account_id + posted_at (balance calculations)
- COA: coa_code (reporting queries)

AGGREGATION:
- Materialized view for account balances (real-time)
- Periodic refresh of balance snapshots
- BRIN indexes for historical leg data

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- LEG_CREATED: New leg inserted
- LEG_VERIFIED: Hash verification performed
- CONTROL_HASH_COMPUTED: Movement control hash calculated

RETENTION: 7 years (aligned with transaction_log)
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TODO[PRIMARY_KEY]: Define movement legs primary key
-- -----------------------------------------------------------------------------
-- leg_id UUID PRIMARY KEY DEFAULT uuid_generate_v4()

-- -----------------------------------------------------------------------------
-- TODO[FOREIGN_KEYS]: Define referential integrity
-- -----------------------------------------------------------------------------
-- 1. movement_id -> movement_headers(movement_id) ON DELETE RESTRICT
-- 2. account_id -> account_registry(account_id) ON DELETE RESTRICT
-- 3. coa_code -> chart_of_accounts(coa_code) ON DELETE RESTRICT

-- -----------------------------------------------------------------------------
-- TODO[CONSTRAINTS]: Business rule constraints
-- -----------------------------------------------------------------------------
-- 1. CHECK (direction IN ('DEBIT', 'CREDIT'))
-- 2. CHECK (amount > 0)
-- 3. CHECK (currency ~ '^[A-Z]{3}$')  -- ISO 4217 format

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.movement_legs (
    -- Primary identifier
    leg_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Parent movement
    movement_id UUID NOT NULL REFERENCES ussd_core.movement_headers(movement_id),
    leg_sequence INTEGER NOT NULL,  -- Order within movement (0-indexed)
    
    -- Account affected
    account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    
    -- Direction and amount
    direction VARCHAR(6) NOT NULL CHECK (direction IN ('DEBIT', 'CREDIT')),
    amount NUMERIC(20, 8) NOT NULL CHECK (amount > 0),
    currency VARCHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    
    -- Chart of accounts reference
    coa_code VARCHAR(50) NOT NULL REFERENCES ussd_core.chart_of_accounts(coa_code),
    
    -- Narrative
    description TEXT,
    
    -- Hash for integrity
    leg_hash VARCHAR(64) NOT NULL,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    posted_at TIMESTAMPTZ,  -- When movement was posted
    
    -- Audit
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    UNIQUE (movement_id, leg_sequence)
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
