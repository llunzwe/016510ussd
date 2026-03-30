-- =============================================================================
-- USSD KERNEL CORE SCHEMA - IDEMPOTENCY KEYS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    028_idempotency_keys.sql
-- SCHEMA:      ussd_core
-- TABLE:       idempotency_keys
-- DESCRIPTION: Idempotency key registry for exactly-once transaction
--              processing with deduplication and replay protection.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Duplicate detection
├── A.12.6 Technical vulnerability management - Replay attack prevention
└── A.16.1 Management of information security incidents - Duplicate handling

ISO/IEC 27040:2024 (Storage Security)
├── Immutable idempotency records
├── Request hash verification
└── Replay protection audit trail

Financial Regulations
├── Exactly-once: Duplicate transaction prevention
├── Audit trail: Complete request history
└── Fraud prevention: Replay attack mitigation

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. KEY GENERATION
   - Client-generated UUIDs or unique strings
   - Time-bound expiration (default 24 hours)
   - Request hash for content verification

2. LIFECYCLE
   - PENDING: Key allocated, transaction not yet created
   - PROCESSING: Transaction in progress
   - COMPLETED: Transaction completed
   - EXPIRED: Key expired without completion

3. CLEANUP
   - Automatic expiration
   - Periodic purging of old keys
   - Archival of completed keys

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

REPLAY PROTECTION:
- Request hash verification
- Time window enforcement
- Key uniqueness constraints

DUPLICATE DETECTION:
- Unique key constraint
- Request hash comparison
- Client notification of duplicates

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: idempotency_key_id
- KEY: idempotency_key (unique)
- STATUS: status + created_at
- EXPIRY: expires_at (for cleanup)

CLEANUP:
- Partition by created_at
- Auto-purge expired keys

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- KEY_CREATED
- KEY_COMPLETED
- DUPLICATE_DETECTED
- KEY_EXPIRED

RETENTION: 2 years (keys), 7 years (audit log)
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.idempotency_keys (
    -- Primary identifier
    idempotency_key_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Idempotency key (client-provided)
    idempotency_key VARCHAR(255) NOT NULL UNIQUE,
    
    -- Scope
    application_id UUID,
    initiator_account_id UUID REFERENCES ussd_core.account_registry(account_id),
    
    -- Request hash for content verification
    request_hash VARCHAR(64) NOT NULL,
    
    -- Status
    status VARCHAR(20) DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'EXPIRED')),
    
    -- Result reference
    transaction_id UUID,
    transaction_reference VARCHAR(100),
    
    -- Response caching
    response_code INTEGER,
    response_body JSONB,
    
    -- Timing
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    
    -- Client context
    client_ip INET,
    user_agent TEXT,
    
    -- Audit
    record_hash VARCHAR(64) NOT NULL
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
