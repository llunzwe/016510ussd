-- =============================================================================
-- USSD KERNEL CORE SCHEMA - RECONCILIATION RUNS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    014_reconciliation_runs.sql
-- SCHEMA:      ussd_core
-- TABLE:       reconciliation_runs
-- DESCRIPTION: Master records for reconciliation processes tracking
--              comparison runs between internal and external systems.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Reconciliation monitoring
├── A.16.1 Management of information security incidents - Discrepancy handling
└── A.18.1 Compliance - Regulatory reconciliation requirements

Financial Regulations
├── Daily reconciliation: End-of-day position matching
├── Exception management: Unmatched item investigation
├── Audit trail: Complete reconciliation history
└── Regulatory reporting: Reconciliation status reports

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. RECONCILIATION TYPES
   - INTERNAL: Internal system reconciliation
   - BANK: Bank statement reconciliation
   - CARD: Card scheme reconciliation
   - WALLET: Wallet provider reconciliation
   - AGENT: Agent float reconciliation

2. RUN STATES
   - PENDING: Awaiting execution
   - RUNNING: In progress
   - COMPLETED: Successfully finished
   - FAILED: Error occurred
   - APPROVED: Exceptions approved

3. SCHEDULING
   - Daily automated runs
   - Ad-hoc manual runs
   - Scheduled frequency configuration

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

RECONCILIATION SECURITY:
- Data integrity verification
- External file validation
- Unauthorized modification detection

EXCEPTION HANDLING:
- Investigation workflow
- Approval requirements
- Audit trail for adjustments

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: run_id
- TYPE: reconciliation_type + run_date
- STATUS: status + started_at
- DATE: run_date (reporting)

ARCHIVAL:
- Archive completed runs after 2 years
- Retain summary statistics

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- RECONCILIATION_STARTED
- RECONCILIATION_COMPLETED
- DISCREPANCY_FOUND
- EXCEPTION_APPROVED

RETENTION: 7 years
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.reconciliation_runs (
    -- Primary identifier
    run_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    run_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Reconciliation definition
    reconciliation_type VARCHAR(50) NOT NULL
        CHECK (reconciliation_type IN ('INTERNAL', 'BANK', 'CARD', 'WALLET', 'AGENT')),
    counterparty_id UUID,
    
    -- Period
    run_date DATE NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    
    -- Status
    status VARCHAR(50) DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'APPROVED')),
    
    -- Summary statistics
    internal_record_count INTEGER,
    external_record_count INTEGER,
    matched_count INTEGER,
    unmatched_internal_count INTEGER,
    unmatched_external_count INTEGER,
    discrepancy_count INTEGER,
    
    -- Amounts
    internal_total_amount NUMERIC(20, 8),
    external_total_amount NUMERIC(20, 8),
    discrepancy_amount NUMERIC(20, 8),
    
    -- External reference
    external_file_name VARCHAR(255),
    external_file_hash VARCHAR(64),
    
    -- Timing
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    
    -- Approval
    approved_by UUID,
    approved_at TIMESTAMPTZ,
    approval_notes TEXT,
    
    -- Error handling
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    record_hash VARCHAR(64) NOT NULL
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
