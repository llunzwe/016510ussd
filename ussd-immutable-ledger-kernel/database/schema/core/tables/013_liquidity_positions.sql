-- =============================================================================
-- USSD KERNEL CORE SCHEMA - LIQUIDITY POSITIONS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    013_liquidity_positions.sql
-- SCHEMA:      ussd_core
-- TABLE:       liquidity_positions
-- DESCRIPTION: Tracks held funds, reserves, and liquidity positions for
--              accounts, applications, and system-wide liquidity management.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Position access control
├── A.12.4 Logging and monitoring - Liquidity monitoring
└── A.14.2 Business continuity - Liquidity contingency

ISO/IEC 27040:2024 (Storage Security)
├── Immutable position history
├── Position integrity verification
└── Audit trail for all position changes

Financial Regulations
├── Liquidity coverage ratio (LCR) tracking
├── Net stable funding ratio (NSFR) support
├── Reserve requirement compliance
└── Intraday liquidity monitoring

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. POSITION TYPES
   - HELD: Funds temporarily held (e.g., pending settlement)
   - RESERVED: Regulatory or contractual reserves
   - COLLATERAL: Security for obligations
   - FLOAT: Working capital/float
   - PLEDGED: Pledged to third parties

2. POSITION STATES
   - ACTIVE: Position in effect
   - RELEASED: Position released, funds available
   - EXPIRED: Position auto-released after timeout
   - CONFISCATED: Position seized (regulatory)

3. CURRENCY HANDLING
   - Multi-currency positions
   - Currency-specific limits
   - FX rate tracking

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

POSITION AUTHORIZATION:
- Multi-level approval for large positions
- Separation of duties for position creation/release
- Automated limit checking

MONITORING:
- Real-time position monitoring
- Liquidity threshold alerts
- Stress testing support

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: position_id
- ACCOUNT: account_id + status
- TYPE: position_type + status
- EXPIRY: expires_at (for auto-release)

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- POSITION_CREATED
- POSITION_RELEASED
- POSITION_EXPIRED
- POSITION_EXTENDED

RETENTION: 7 years
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.liquidity_positions (
    -- Primary identifier
    position_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Position owner
    account_id UUID REFERENCES ussd_core.account_registry(account_id),
    application_id UUID,
    
    -- Position classification
    position_type VARCHAR(50) NOT NULL
        CHECK (position_type IN ('HELD', 'RESERVED', 'COLLATERAL', 'FLOAT', 'PLEDGED')),
    
    -- Amount
    amount NUMERIC(20, 8) NOT NULL,
    currency VARCHAR(3) NOT NULL,
    
    -- Status
    status VARCHAR(20) DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'RELEASED', 'EXPIRED', 'CONFISCATED')),
    
    -- Purpose
    purpose_code VARCHAR(50),
    description TEXT,
    
    -- Related transaction
    transaction_id UUID,
    movement_id UUID,
    
    -- Timing
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    expires_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    
    -- Release conditions
    auto_release BOOLEAN DEFAULT TRUE,
    release_conditions JSONB,
    
    -- Audit
    created_by UUID,
    released_by UUID,
    record_hash VARCHAR(64) NOT NULL
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
