-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Exception management)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Suspense security)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Suspense data handling)
-- ISO/IEC 27040:2024 - Storage Security (Suspense integrity)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Suspense recovery)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Aging buckets for prioritization
-- - Assignment tracking for accountability
-- - Root cause documentation
-- - Resolution type classification
-- ============================================================================
-- =============================================================================
-- MIGRATION: 018_core_suspense_items.sql
-- DESCRIPTION: Suspense Items - Unmatched Reconciliation Breaks
-- TABLES: suspense_items, suspense_aging
-- DEPENDENCIES: 016_core_reconciliation_runs.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 8. Reconciliation & Exception Management
- Feature: Suspense Items (Breaks)
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Unmatched reconciliation items go into suspense queue with aging analysis.
Manual review required for resolution. Aging buckets help prioritize older items.

SUSPENSE TYPES:
- UNMATCHED_INTERNAL: We have record, external doesn't
- UNMATCHED_EXTERNAL: External has record, we don't
- AMOUNT_MISMATCH: Amount differs between sources
- DATE_MISMATCH: Date differs beyond tolerance
- DUPLICATE: Potential duplicate transaction

AGING BUCKETS:
- 0-1 days: Current
- 2-7 days: Aging
- 8-30 days: Delinquent
- 31-90 days: Critical
- 90+ days: Write-off candidate
================================================================================
*/

-- =============================================================================
-- TODO: Create suspense_items table
-- DESCRIPTION: Queue of unmatched reconciliation items
-- PRIORITY: CRITICAL
-- SECURITY: Auto-calculated aging for prioritization
-- ============================================================================
-- TODO: [SUSP-001] Create core.suspense_items table
-- INSTRUCTIONS:
--   - Stores items that couldn't be auto-matched
--   - Tracks aging and resolution status
--   - Links to original reconciliation item
--   - RLS POLICY: Tenant isolation
--   - ERROR HANDLING: Validate suspense_type is valid
-- COMPLIANCE: ISO/IEC 27001 (Exception Tracking)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.suspense_items (
--       suspense_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       suspense_reference  VARCHAR(100) UNIQUE NOT NULL,
--       
--       -- Source
--       run_id              UUID NOT NULL REFERENCES core.reconciliation_runs(run_id),
--       item_id             UUID NOT NULL REFERENCES core.reconciliation_items(item_id),
--       
--       -- Classification
--       suspense_type       VARCHAR(50) NOT NULL,        -- UNMATCHED_INTERNAL, etc.
--       category            VARCHAR(50),                 -- For grouping
--       
--       -- Financial
--       amount              NUMERIC(20, 8) NOT NULL,
--       currency            VARCHAR(3) NOT NULL,
--       direction           VARCHAR(10),                 -- DEBIT, CREDIT
--       
--       -- Aging
--       identified_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
--       aging_days          INTEGER GENERATED ALWAYS AS (
--                               EXTRACT(DAY FROM now() - identified_at)
--                           ) STORED,
--       aging_bucket        VARCHAR(20) GENERATED ALWAYS AS (
--                               CASE 
--                                   WHEN EXTRACT(DAY FROM now() - identified_at) <= 1 THEN 'CURRENT'
--                                   WHEN EXTRACT(DAY FROM now() - identified_at) <= 7 THEN 'AGING'
--                                   WHEN EXTRACT(DAY FROM now() - identified_at) <= 30 THEN 'DELINQUENT'
--                                   WHEN EXTRACT(DAY FROM now() - identified_at) <= 90 THEN 'CRITICAL'
--                                   ELSE 'WRITE_OFF'
--                               END
--                           ) STORED,
--       
--       -- Status
--       status              VARCHAR(20) DEFAULT 'OPEN',  -- OPEN, ASSIGNED, PENDING, RESOLVED
--       
--       -- Assignment
--       assigned_to         UUID REFERENCES core.accounts(account_id),
--       assigned_at         TIMESTAMPTZ,
--       
--       -- Priority
--       priority            INTEGER DEFAULT 0,           -- Higher = more urgent
--       
--       -- Investigation
--       investigation_notes TEXT,
--       root_cause          VARCHAR(100),
--       
--       -- Resolution
--       resolved_at         TIMESTAMPTZ,
--       resolved_by         UUID REFERENCES core.accounts(account_id),
--       resolution_type     VARCHAR(50),                 -- MATCH, ADJUST, WRITE_OFF, REFUND
--       
--       -- Application
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       updated_at          TIMESTAMPTZ
--   );

-- =============================================================================
-- TODO: Create suspense_actions table
-- DESCRIPTION: Log of actions taken on suspense items
-- PRIORITY: MEDIUM
-- SECURITY: Immutable audit trail of actions
-- ============================================================================
-- TODO: [SUSP-002] Create core.suspense_actions table
-- INSTRUCTIONS:
--   - Audit trail of all actions on suspense items
--   - Track assignment, investigation, resolution
--   - AUDIT LOGGING: All actions logged with old/new values
-- COMPLIANCE: ISO/IEC 27018 (Action Audit)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.suspense_actions (
--       action_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       suspense_id         UUID NOT NULL REFERENCES core.suspense_items(suspense_id),
--       
--       -- Action Details
--       action_type         VARCHAR(50) NOT NULL,        -- ASSIGN, INVESTIGATE, RESOLVE, etc.
--       action_data         JSONB,                       -- Action-specific data
--       
--       -- Old/New Values
--       previous_status     VARCHAR(20),
--       new_status          VARCHAR(20),
--       
--       -- Audit
--       performed_by        UUID NOT NULL REFERENCES core.accounts(account_id),
--       performed_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
--       notes               TEXT
--   );

-- =============================================================================
-- TODO: Create suspense aging view
-- DESCRIPTION: Summary of suspense by aging bucket
-- PRIORITY: MEDIUM
-- SECURITY: Aggregated view for management reporting
-- ============================================================================
-- TODO: [SUSP-003] Create suspense_aging_summary view
-- INSTRUCTIONS:
--   - Group suspense items by aging bucket
--   - Calculate totals per bucket
--   - For management reporting
--   - RLS POLICY: Tenant isolation
-- COMPLIANCE: ISO/IEC 27031 (Aging Reports)
--
-- VIEW DEFINITION:
--   CREATE VIEW core.suspense_aging_summary AS
--   SELECT 
--       application_id,
--       aging_bucket,
--       suspense_type,
--       COUNT(*) as item_count,
--       SUM(amount) as total_amount,
--       currency
--   FROM core.suspense_items
--   WHERE status != 'RESOLVED'
--   GROUP BY application_id, aging_bucket, suspense_type, currency;

-- =============================================================================
-- TODO: Create suspense assignment function
-- DESCRIPTION: Assign suspense item to operator
-- PRIORITY: MEDIUM
-- SECURITY: Verify operator authorization
-- ============================================================================
-- TODO: [SUSP-004] Create assign_suspense_item function
-- INSTRUCTIONS:
--   - Assign item to operator
--   - Update status to ASSIGNED
--   - Record action
--   - ERROR HANDLING: Verify item is not already resolved
--   - AUDIT LOGGING: Log assignment action
-- COMPLIANCE: ISO/IEC 27001 (Assignment Control)

-- =============================================================================
-- TODO: Create suspense priority calculation
-- DESCRIPTION: Calculate priority based on age and amount
-- PRIORITY: LOW
-- SECURITY: Objective priority calculation
-- ============================================================================
-- TODO: [SUSP-005] Create calculate_suspense_priority function
-- INSTRUCTIONS:
--   - Higher priority for older items
--   - Higher priority for larger amounts
--   - Consider customer tier
--   - ERROR HANDLING: Handle NULL values
-- COMPLIANCE: ISO/IEC 27031 (Priority Management)

-- =============================================================================
-- TODO: Create suspense indexes
-- DESCRIPTION: Optimize suspense queries
-- PRIORITY: HIGH
-- SECURITY: Index on aging_bucket for prioritization
-- ============================================================================
-- TODO: [SUSP-006] Create suspense indexes
-- INDEX LIST:
--   - PRIMARY KEY (suspense_id)
--   - UNIQUE (suspense_reference)
--   - INDEX on (run_id)
--   - INDEX on (item_id)
--   - INDEX on (status, aging_bucket)
--   - INDEX on (assigned_to, status) WHERE status != 'RESOLVED'
--   - INDEX on (application_id, suspense_type, status)
--   -- Actions:
--   - INDEX on (suspense_id, performed_at)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create suspense_items table with aging calculations
□ Create suspense_actions table for audit trail
□ Create suspense_aging_summary view
□ Implement assign_suspense_item function
□ Implement priority calculation
□ Add all indexes for suspense queries
□ Test aging bucket calculations
□ Test assignment workflow
□ Verify suspense statistics
================================================================================
*/
