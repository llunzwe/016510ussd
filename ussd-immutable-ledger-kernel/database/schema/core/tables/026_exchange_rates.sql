-- =============================================================================
-- USSD KERNEL CORE SCHEMA - EXCHANGE RATES
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    026_exchange_rates.sql
-- SCHEMA:      ussd_core
-- TABLE:       exchange_rates
-- DESCRIPTION: Historical and current exchange rates for multi-currency
--              transactions with source attribution and validity periods.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Rate change monitoring
├── A.14.2 Business continuity - Rate source redundancy
└── A.18.1 Compliance - Regulatory rate reporting

Financial Regulations
├── Rate sourcing: Authorized rate sources only
├── Audit trail: Complete rate history
├── Markup disclosure: Transparent fee structure
└── Reporting: Regulatory rate reporting

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. RATE TYPES
   - SPOT: Current market rate
   - FORWARD: Future delivery rate
   - FIXING: Daily fixing rate
   - INTERNAL: Institution-specific rate

2. RATE SOURCES
   - Central bank rates
   - Market data providers (Reuters, Bloomberg)
   - Internal treasury
   - Correspondent bank rates

3. VALIDITY
   - Valid from/to timestamps
   - Rate expiration
   - Historical rate preservation

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

RATE INTEGRITY:
- Source authentication
- Rate validation ranges
- Tamper detection
- Audit trail

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: rate_id
- CURRENCY: from_currency + to_currency + valid_from
- SOURCE: source + rate_type
- DATE: valid_from DESC

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- RATE_CREATED
- RATE_EXPIRED
- RATE_ACCESSED

RETENTION: 7 years
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.exchange_rates (
    -- Primary identifier
    rate_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Currency pair
    from_currency VARCHAR(3) NOT NULL,
    to_currency VARCHAR(3) NOT NULL,
    
    -- Rate details
    rate_type VARCHAR(20) NOT NULL
        CHECK (rate_type IN ('SPOT', 'FORWARD', 'FIXING', 'INTERNAL')),
    rate_value NUMERIC(20, 10) NOT NULL,
    
    -- Inverse rate (for efficiency)
    inverse_rate NUMERIC(20, 10),
    
    -- Source
    source VARCHAR(100) NOT NULL,
    source_reference VARCHAR(255),
    
    -- Validity period
    valid_from TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    valid_to TIMESTAMPTZ,
    
    -- Rate metadata
    bid_rate NUMERIC(20, 10),
    ask_rate NUMERIC(20, 10),
    mid_rate NUMERIC(20, 10),
    spread_percentage NUMERIC(10, 6),
    
    -- Status
    is_current BOOLEAN DEFAULT TRUE,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    CHECK (from_currency != to_currency),
    CHECK (rate_value > 0),
    UNIQUE (from_currency, to_currency, rate_type, valid_from)
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
