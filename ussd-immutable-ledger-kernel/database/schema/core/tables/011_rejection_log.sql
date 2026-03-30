-- =============================================================================
-- USSD KERNEL CORE SCHEMA - REJECTION LOG
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    011_rejection_log.sql
-- SCHEMA:      ussd_core
-- TABLE:       rejection_log
-- DESCRIPTION: Immutable record of all rejected transactions with detailed
--              rejection reasons for audit, compliance, and debugging.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Transaction rejection monitoring
├── A.16.1 Management of information security incidents - Pattern analysis
└── A.16.2 Assessment and decision - Rejection decision audit trail

ISO/IEC 27040:2024 (Storage Security)
├── Immutable rejection records
├── Tamper-evident rejection log
└── Long-term retention for forensic analysis

Financial Regulations
├── AML: Suspicious rejection pattern analysis
├── Audit: Rejection reason documentation
├── Consumer protection: Rejection explanation requirements
└── Regulatory reporting: Rejection statistics

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. REJECTION CATEGORIES
   - VALIDATION: Schema or business rule violation
   - AUTHORIZATION: Insufficient permissions
   - FUNDS: Insufficient balance
   - LIMIT: Transaction limit exceeded
   - RISK: Risk threshold exceeded
   - SYSTEM: Internal system error
   - COMPLIANCE: Regulatory restriction

2. ERROR CODES
   - Standardized error code taxonomy
   - Hierarchical code structure
   - Localization support

3. RETENTION
   - Minimum 7 years for financial transactions
   - Longer retention for AML-related rejections
   - Secure archival procedures

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

REJECTION MONITORING:
- Real-time rejection rate alerts
- Pattern detection for attacks
- Fraud attempt identification

FORENSICS:
- Complete request context preserved
- Client information captured (GDPR compliant)
- Audit trail for rejection decisions

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: rejection_id
- IDEMPOTENCY: idempotency_key (duplicate detection)
- ACCOUNT: initiator_account_id + rejected_at
- REASON: rejection_code + rejected_at
- TIME: rejected_at DESC (reporting)

ARCHIVAL:
- Partition by rejected_at (monthly)
- Compress old partitions
- Cold storage for > 7 years

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- All rejections automatically logged
- Rejection pattern analysis
- Investigation workflow tracking

RETENTION: 7 years minimum
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.rejection_log (
    -- Primary identifier
    rejection_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Original transaction reference
    idempotency_key VARCHAR(255) NOT NULL,
    idempotency_key_id UUID,
    
    -- Transaction details (as submitted)
    transaction_type_id UUID,
    application_id UUID,
    initiator_account_id UUID,
    beneficiary_account_id UUID,
    amount NUMERIC(20, 8),
    currency VARCHAR(3),
    payload JSONB,
    
    -- Rejection details
    rejection_reason TEXT NOT NULL,
    rejection_code VARCHAR(50) NOT NULL,
    rejection_category VARCHAR(50) NOT NULL
        CHECK (rejection_category IN ('VALIDATION', 'AUTHORIZATION', 'FUNDS', 'LIMIT', 'RISK', 'SYSTEM', 'COMPLIANCE')),
    
    -- Validation errors (if applicable)
    validation_errors JSONB,
    
    -- Client context
    client_ip INET,
    user_agent TEXT,
    session_id TEXT,
    source_ip INET,
    
    -- Timing
    received_at TIMESTAMPTZ NOT NULL,
    rejected_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    processing_duration_ms INTEGER,
    
    -- Processing metadata
    processor_version VARCHAR(20),
    validation_stage VARCHAR(50),
    
    -- Audit
    record_hash VARCHAR(64) NOT NULL,
    
    -- Partition key
    partition_date DATE NOT NULL DEFAULT CURRENT_DATE
) PARTITION BY RANGE (partition_date);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
