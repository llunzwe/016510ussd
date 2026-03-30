-- =============================================================================
-- USSD KERNEL CORE SCHEMA - SETTLEMENT INSTRUCTIONS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    012_settlement_instructions.sql
-- SCHEMA:      ussd_core
-- TABLE:       settlement_instructions
-- DESCRIPTION: Instructions for inter-bank and inter-provider settlement
--              including net settlement calculations and payment schedules.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Settlement authorization
├── A.8.5 Secure authentication - Settlement approval
└── A.12.4 Logging and monitoring - Settlement monitoring

ISO/IEC 27040:2024 (Storage Security)
├── Immutable settlement records
├── Settlement amount integrity
└── Settlement schedule enforcement

Financial Regulations
├── RTGS compliance: Real-time gross settlement requirements
├── Netting regulations: Multi-lateral netting rules
├── Settlement finality: Irrevocable settlement confirmation
└── Liquidity reporting: Settlement obligation reporting

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. SETTLEMENT TYPES
   - RTGS: Real-time gross settlement
   - NET: Net settlement (end of period)
   - BATCH: Scheduled batch settlement
   - IMMEDIATE: Instant settlement

2. SETTLEMENT STATES
   - PENDING: Awaiting settlement date
   - READY: Prepared for settlement
   - EXECUTING: Settlement in progress
   - COMPLETED: Settlement confirmed
   - FAILED: Settlement failed, retry scheduled

3. CURRENCY HANDLING
   - Multi-currency settlement support
   - FX rate tracking for cross-currency
   - Currency-specific settlement accounts

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

SETTLEMENT AUTHORIZATION:
- Multi-level approval for large settlements
- Dual control for settlement execution
- Settlement limit enforcement

VERIFICATION:
- Settlement amount reconciliation
- Counterparty confirmation
- Final settlement confirmation receipt

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: settlement_id
- COUNTERPARTY: counterparty_id + settlement_date
- STATUS: status + scheduled_at
- DATE: settlement_date (range queries)

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- SETTLEMENT_INSTRUCTION_CREATED
- SETTLEMENT_READY
- SETTLEMENT_EXECUTED
- SETTLEMENT_CONFIRMED
- SETTLEMENT_FAILED

RETENTION: 7 years
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.settlement_instructions (
    -- Primary identifier
    settlement_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    settlement_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Settlement parties
    application_id UUID NOT NULL,
    counterparty_id UUID NOT NULL,  -- Bank, MNO, or provider
    
    -- Settlement type and direction
    settlement_type VARCHAR(50) NOT NULL
        CHECK (settlement_type IN ('RTGS', 'NET', 'BATCH', 'IMMEDIATE')),
    direction VARCHAR(20) NOT NULL
        CHECK (direction IN ('PAY', 'RECEIVE')),
    
    -- Amount
    amount NUMERIC(20, 8) NOT NULL,
    currency VARCHAR(3) NOT NULL,
    
    -- Timing
    scheduled_at TIMESTAMPTZ NOT NULL,
    settlement_date DATE NOT NULL,
    executed_at TIMESTAMPTZ,
    
    -- Status
    status VARCHAR(50) DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'READY', 'EXECUTING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    
    -- Settlement details
    settlement_account VARCHAR(100),
    settlement_bank_code VARCHAR(20),
    settlement_channel VARCHAR(50),
    
    -- Counterparty details
    counterparty_account VARCHAR(100),
    counterparty_bank_code VARCHAR(20),
    
    -- Transaction summary
    transaction_count INTEGER,
    gross_amount NUMERIC(20, 8),
    net_amount NUMERIC(20, 8),
    
    -- References
    included_transactions UUID[],
    parent_settlement_id UUID,
    
    -- Confirmation
    confirmation_reference VARCHAR(100),
    confirmed_at TIMESTAMPTZ,
    
    -- Narrative
    description TEXT,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
