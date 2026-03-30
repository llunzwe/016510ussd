-- =============================================================================
-- USSD KERNEL CORE SCHEMA - SUSPENSE ITEMS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    016_suspense_items.sql
-- SCHEMA:      ussd_core
-- TABLE:       suspense_items
-- DESCRIPTION: Unmatched or pending items held in suspense accounts
--              awaiting resolution, classification, or routing.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Suspense item access
├── A.12.4 Logging and monitoring - Suspense monitoring
└── A.16.1 Management of information security incidents - Escalation

Financial Regulations
├── Suspense aging: Maximum hold period compliance
├── Escalation: Management notification requirements
└── Resolution audit: Complete resolution trail

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. SUSPENSE CATEGORIES
   - UNIDENTIFIED: Cannot determine proper account
   - PENDING_DOCS: Awaiting documentation
   - DISPUTED: Under dispute
   - INVESTIGATION: Under investigation
   - AWAITING_APPROVAL: Pending approval

2. AGING TRACKING
   - Age in days calculated automatically
   - Escalation thresholds configured
   - Auto-escalation on threshold breach

3. RESOLUTION
   - Classification required
   - Approval workflow
   - Audit trail for resolution

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

SUSPENSE SECURITY:
- Access restricted to authorized personnel
- All access logged
- Modification audit trail

ESCALATION:
- Automated aging reports
- Management notification
- Regulatory reporting for aged items

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: suspense_id
- ACCOUNT: suspense_account_id + status
- CATEGORY: category + status
- AGE: created_at (for aging reports)

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- SUSPENSE_ITEM_CREATED
- SUSPENSE_ITEM_CLASSIFIED
- SUSPENSE_ITEM_RESOLVED
- SUSPENSE_ITEM_ESCALATED

RETENTION: 7 years
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.suspense_items (
    -- Primary identifier
    suspense_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    suspense_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Suspense account
    suspense_account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    
    -- Item details
    category VARCHAR(50) NOT NULL
        CHECK (category IN ('UNIDENTIFIED', 'PENDING_DOCS', 'DISPUTED', 'INVESTIGATION', 'AWAITING_APPROVAL')),
    status VARCHAR(20) DEFAULT 'OPEN'
        CHECK (status IN ('OPEN', 'CLASSIFIED', 'PENDING_APPROVAL', 'RESOLVED', 'WRITTEN_OFF')),
    
    -- Amount
    amount NUMERIC(20, 8) NOT NULL,
    currency VARCHAR(3) NOT NULL,
    
    -- Source
    source_type VARCHAR(50),
    source_reference VARCHAR(100),
    source_date DATE,
    
    -- Identification attempts
    attempted_account_id UUID,
    identification_notes TEXT,
    
    -- Aging
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    age_days INTEGER GENERATED ALWAYS AS (EXTRACT(DAY FROM now() - created_at)) STORED,
    escalation_level INTEGER DEFAULT 0,
    escalated_at TIMESTAMPTZ,
    
    -- Resolution
    resolution_type VARCHAR(50),
    resolution_reference VARCHAR(100),
    resolved_at TIMESTAMPTZ,
    resolved_by UUID,
    resolution_notes TEXT,
    
    -- Audit
    record_hash VARCHAR(64) NOT NULL
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
