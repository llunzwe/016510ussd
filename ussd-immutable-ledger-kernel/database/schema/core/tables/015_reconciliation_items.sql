-- =============================================================================
-- USSD KERNEL CORE SCHEMA - RECONCILIATION ITEMS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    015_reconciliation_items.sql
-- SCHEMA:      ussd_core
-- TABLE:       reconciliation_items
-- DESCRIPTION: Individual reconciliation items representing matched or
--              unmatched transactions from reconciliation runs.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Item-level monitoring
├── A.16.1 Management of information security incidents - Discrepancy investigation
└── A.18.1 Compliance - Audit trail for adjustments

Financial Regulations
├── Exception investigation: Documented resolution
├── Adjustment authorization: Multi-level approval
└── Audit trail: Complete item history

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. ITEM STATES
   - MATCHED: Successfully matched
   - UNMATCHED_INTERNAL: Internal item with no external match
   - UNMATCHED_EXTERNAL: External item with no internal match
   - DISCREPANCY: Matched but with amount difference
   - ADJUSTED: Adjustment applied
   - APPROVED: Exception approved

2. MATCHING CRITERIA
   - Reference number matching
   - Amount matching (exact or tolerance)
   - Date matching (with tolerance)
   - Multi-field matching logic

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

ITEM SECURITY:
- Immutable item records
- Adjustment authorization required
- Audit trail for all state changes

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: item_id
- RUN: run_id + match_status
- REFERENCE: reference_number
- STATUS: match_status

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- ITEM_MATCHED
- ITEM_UNMATCHED
- DISCREPANCY_FOUND
- ADJUSTMENT_APPLIED
- EXCEPTION_APPROVED

RETENTION: 7 years
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.reconciliation_items (
    -- Primary identifier
    item_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Parent run
    run_id UUID NOT NULL REFERENCES ussd_core.reconciliation_runs(run_id),
    
    -- Match status
    match_status VARCHAR(50) NOT NULL
        CHECK (match_status IN ('MATCHED', 'UNMATCHED_INTERNAL', 'UNMATCHED_EXTERNAL', 'DISCREPANCY', 'ADJUSTED', 'APPROVED')),
    
    -- Internal record details
    internal_record_id UUID,
    internal_reference VARCHAR(100),
    internal_amount NUMERIC(20, 8),
    internal_currency VARCHAR(3),
    internal_date DATE,
    
    -- External record details
    external_record_id VARCHAR(100),
    external_reference VARCHAR(100),
    external_amount NUMERIC(20, 8),
    external_currency VARCHAR(3),
    external_date DATE,
    
    -- Discrepancy details
    discrepancy_type VARCHAR(50),
    discrepancy_amount NUMERIC(20, 8),
    discrepancy_reason TEXT,
    
    -- Matching details
    matched_by VARCHAR(50),  -- Algorithm or manual
    matched_at TIMESTAMPTZ,
    match_confidence NUMERIC(5, 4),  -- For fuzzy matching
    
    -- Resolution
    resolution_action VARCHAR(50),
    resolution_notes TEXT,
    resolved_by UUID,
    resolved_at TIMESTAMPTZ,
    
    -- Related transaction (if adjustment made)
    adjustment_transaction_id UUID,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    record_hash VARCHAR(64) NOT NULL
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
