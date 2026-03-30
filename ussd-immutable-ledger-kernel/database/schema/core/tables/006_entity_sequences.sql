-- =============================================================================
-- USSD KERNEL CORE SCHEMA - ENTITY SEQUENCES
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    006_entity_sequences.sql
-- SCHEMA:      ussd_core
-- TABLE:       entity_sequences
-- DESCRIPTION: Atomic sequence generation for transaction references,
--              account numbers, and other sequential identifiers.
--              Provides gap-free sequences with application isolation.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Sequence generation audit
├── A.10.1 Cryptographic controls - Unpredictable sequence seeds
└── A.12.4 Logging and monitoring - Sequence usage tracking

ISO/IEC 27040:2024 (Storage Security)
├── Sequence integrity: No gaps or duplicates
├── Audit trail: Complete sequence assignment history
└── Recovery: Sequence state preservation

Financial Regulations
├── Audit requirements: Sequential numbering for traceability
├── Gap detection: Missing sequence identification
└── Non-repudiation: Sequence assignment logging

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. SEQUENCE MANAGEMENT
   - Table-based sequences (not PostgreSQL SERIAL)
   - Application-scoped sequences
   - Atomic increment with RETURNING

2. CONCURRENCY
   - Row-level locking on increment
   - Conflict resolution for concurrent access
   - Performance optimization via caching

3. GAP DETECTION
   - Periodic gap analysis
   - Missing sequence reporting
   - Reconciliation procedures

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

SEQUENCE PROTECTION:
- Increment-only (no decrements)
- Audit logging of sequence consumption
- Rate limiting on sequence generation

ACCESS CONTROL:
- Application-scoped access
- Admin-only sequence reset (emergency)
- Audit trail for all modifications

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: sequence_name + application_id (composite)
- LOOKUP: sequence_name (single sequence queries)

CACHING:
- Application-level sequence caching
- Batch allocation for high throughput
- Cache refresh on exhaustion

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- SEQUENCE_INCREMENTED: Value allocated
- SEQUENCE_RESET: Emergency reset (rare)
- GAP_DETECTED: Missing sequence identified

RETENTION: 7 years
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.entity_sequences (
    -- Sequence identifier
    sequence_name VARCHAR(100) NOT NULL,
    
    -- Application scope (NULL for global sequences)
    application_id UUID,
    
    -- Current value
    last_value BIGINT NOT NULL DEFAULT 0,
    
    -- Sequence configuration
    increment_by INTEGER DEFAULT 1,
    max_value BIGINT,
    cycle BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    description TEXT,
    prefix VARCHAR(20),  -- For formatted references
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    
    -- Constraints
    PRIMARY KEY (sequence_name, application_id)
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
