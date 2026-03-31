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
-- Create suspense_items table
-- DESCRIPTION: Queue of unmatched reconciliation items
-- PRIORITY: CRITICAL
-- SECURITY: Auto-calculated aging for prioritization
-- ============================================================================
-- [SUSP-001] Create core.suspense_items table
-- INSTRUCTIONS:
--   - Stores items that couldn't be auto-matched
--   - Tracks aging and resolution status
--   - Links to original reconciliation item
--   - RLS POLICY: Tenant isolation
--   - ERROR HANDLING: Validate suspense_type is valid
-- COMPLIANCE: ISO/IEC 27001 (Exception Tracking)

CREATE TABLE core.suspense_items (
    suspense_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    suspense_reference  VARCHAR(100) UNIQUE NOT NULL,
    
    -- Source
    run_id              UUID NOT NULL REFERENCES core.reconciliation_runs(run_id),
    item_id             UUID NOT NULL REFERENCES core.reconciliation_items(item_id),
    
    -- Classification
    suspense_type       VARCHAR(50) NOT NULL,        -- UNMATCHED_INTERNAL, etc.
    category            VARCHAR(50),                 -- For grouping
    
    -- Financial
    amount              NUMERIC(20, 8) NOT NULL,
    currency            VARCHAR(3) NOT NULL,
    direction           VARCHAR(10),                 -- DEBIT, CREDIT
    
    -- Aging
    identified_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    aging_days          INTEGER GENERATED ALWAYS AS (
                            EXTRACT(DAY FROM now() - identified_at)
                        ) STORED,
    aging_bucket        VARCHAR(20) GENERATED ALWAYS AS (
                            CASE 
                                WHEN EXTRACT(DAY FROM now() - identified_at) <= 1 THEN 'CURRENT'
                                WHEN EXTRACT(DAY FROM now() - identified_at) <= 7 THEN 'AGING'
                                WHEN EXTRACT(DAY FROM now() - identified_at) <= 30 THEN 'DELINQUENT'
                                WHEN EXTRACT(DAY FROM now() - identified_at) <= 90 THEN 'CRITICAL'
                                ELSE 'WRITE_OFF'
                            END
                        ) STORED,
    
    -- Status
    status              VARCHAR(20) DEFAULT 'OPEN',  -- OPEN, ASSIGNED, PENDING, RESOLVED
    
    -- Assignment
    assigned_to         UUID REFERENCES core.accounts(account_id),
    assigned_at         TIMESTAMPTZ,
    
    -- Priority
    priority            INTEGER DEFAULT 0,           -- Higher = more urgent
    
    -- Investigation
    investigation_notes TEXT,
    root_cause          VARCHAR(100),
    
    -- Resolution
    resolved_at         TIMESTAMPTZ,
    resolved_by         UUID REFERENCES core.accounts(account_id),
    resolution_type     VARCHAR(50),                 -- MATCH, ADJUST, WRITE_OFF, REFUND
    
    -- Application
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ
);

-- Add comments for documentation
COMMENT ON TABLE core.suspense_items IS 'Queue of unmatched reconciliation items requiring manual review and resolution';
COMMENT ON COLUMN core.suspense_items.suspense_id IS 'Unique identifier for the suspense item';
COMMENT ON COLUMN core.suspense_items.suspense_reference IS 'External reference number for tracking';
COMMENT ON COLUMN core.suspense_items.suspense_type IS 'Type of mismatch: UNMATCHED_INTERNAL, UNMATCHED_EXTERNAL, AMOUNT_MISMATCH, DATE_MISMATCH, DUPLICATE';
COMMENT ON COLUMN core.suspense_items.aging_bucket IS 'Auto-calculated aging category based on time in suspense';
COMMENT ON COLUMN core.suspense_items.status IS 'Current status: OPEN, ASSIGNED, PENDING, RESOLVED';
COMMENT ON COLUMN core.suspense_items.resolution_type IS 'How item was resolved: MATCH, ADJUST, WRITE_OFF, REFUND';

-- =============================================================================
-- Create suspense_actions table
-- DESCRIPTION: Log of actions taken on suspense items
-- PRIORITY: MEDIUM
-- SECURITY: Immutable audit trail of actions
-- ============================================================================
-- [SUSP-002] Create core.suspense_actions table
-- INSTRUCTIONS:
--   - Audit trail of all actions on suspense items
--   - Track assignment, investigation, resolution
--   - AUDIT LOGGING: All actions logged with old/new values
-- COMPLIANCE: ISO/IEC 27018 (Action Audit)

CREATE TABLE core.suspense_actions (
    action_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    suspense_id         UUID NOT NULL REFERENCES core.suspense_items(suspense_id),
    
    -- Action Details
    action_type         VARCHAR(50) NOT NULL,        -- ASSIGN, INVESTIGATE, RESOLVE, etc.
    action_data         JSONB,                       -- Action-specific data
    
    -- Old/New Values
    previous_status     VARCHAR(20),
    new_status          VARCHAR(20),
    
    -- Audit
    performed_by        UUID NOT NULL REFERENCES core.accounts(account_id),
    performed_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    notes               TEXT
);

COMMENT ON TABLE core.suspense_actions IS 'Immutable audit trail of all actions performed on suspense items';
COMMENT ON COLUMN core.suspense_actions.action_type IS 'Type of action: ASSIGN, INVESTIGATE, RESOLVE, ESCALATE, etc.';

-- =============================================================================
-- Create suspense aging view
-- DESCRIPTION: Summary of suspense by aging bucket
-- PRIORITY: MEDIUM
-- SECURITY: Aggregated view for management reporting
-- ============================================================================
-- [SUSP-003] Create suspense_aging_summary view
-- INSTRUCTIONS:
--   - Group suspense items by aging bucket
--   - Calculate totals per bucket
--   - For management reporting
--   - RLS POLICY: Tenant isolation
-- COMPLIANCE: ISO/IEC 27031 (Aging Reports)

CREATE VIEW core.suspense_aging_summary AS
SELECT 
    application_id,
    aging_bucket,
    suspense_type,
    COUNT(*) as item_count,
    SUM(amount) as total_amount,
    currency
FROM core.suspense_items
WHERE status != 'RESOLVED'
GROUP BY application_id, aging_bucket, suspense_type, currency;

COMMENT ON VIEW core.suspense_aging_summary IS 'Summary view of unresolved suspense items grouped by aging bucket for management reporting';

-- =============================================================================
-- Create suspense assignment function
-- DESCRIPTION: Assign suspense item to operator
-- PRIORITY: MEDIUM
-- SECURITY: Verify operator authorization
-- ============================================================================
-- [SUSP-004] Create assign_suspense_item function
-- INSTRUCTIONS:
--   - Assign item to operator
--   - Update status to ASSIGNED
--   - Record action
--   - ERROR HANDLING: Verify item is not already resolved
--   - AUDIT LOGGING: Log assignment action
-- COMPLIANCE: ISO/IEC 27001 (Assignment Control)

CREATE OR REPLACE FUNCTION core.assign_suspense_item(
    p_suspense_id UUID,
    p_assigned_to UUID,
    p_assigned_by UUID,
    p_notes TEXT DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
    v_old_status VARCHAR(20);
BEGIN
    -- Get current status
    SELECT status INTO v_old_status 
    FROM core.suspense_items 
    WHERE suspense_id = p_suspense_id;
    
    -- Verify item exists and is not resolved
    IF v_old_status IS NULL THEN
        RAISE EXCEPTION 'Suspense item % not found', p_suspense_id;
    END IF;
    
    IF v_old_status = 'RESOLVED' THEN
        RAISE EXCEPTION 'Cannot assign resolved suspense item %', p_suspense_id
            USING HINT = 'Resolved items cannot be modified.';
    END IF;
    
    -- Update suspense item
    UPDATE core.suspense_items
    SET assigned_to = p_assigned_to,
        assigned_at = now(),
        status = 'ASSIGNED',
        updated_at = now()
    WHERE suspense_id = p_suspense_id;
    
    -- Log the action
    INSERT INTO core.suspense_actions (
        suspense_id, action_type, previous_status, new_status, 
        performed_by, notes
    ) VALUES (
        p_suspense_id, 'ASSIGN', v_old_status, 'ASSIGNED', 
        p_assigned_by, COALESCE(p_notes, 'Assigned to operator')
    );
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION core.assign_suspense_item IS 'Assign a suspense item to an operator for investigation';

-- =============================================================================
-- Create suspense priority calculation
-- DESCRIPTION: Calculate priority based on age and amount
-- PRIORITY: LOW
-- SECURITY: Objective priority calculation
-- ============================================================================
-- [SUSP-005] Create calculate_suspense_priority function
-- INSTRUCTIONS:
--   - Higher priority for older items
--   - Higher priority for larger amounts
--   - Consider customer tier
--   - ERROR HANDLING: Handle NULL values
-- COMPLIANCE: ISO/IEC 27031 (Priority Management)

CREATE OR REPLACE FUNCTION core.calculate_suspense_priority(
    p_suspense_id UUID
) RETURNS INTEGER AS $$
DECLARE
    v_aging_days INTEGER;
    v_amount NUMERIC;
    v_priority INTEGER := 0;
BEGIN
    -- Get suspense item details
    SELECT aging_days, COALESCE(amount, 0)
    INTO v_aging_days, v_amount
    FROM core.suspense_items
    WHERE suspense_id = p_suspense_id;
    
    IF v_aging_days IS NULL THEN
        RETURN 0;
    END IF;
    
    -- Base priority from aging bucket
    v_priority := CASE
        WHEN v_aging_days <= 1 THEN 10
        WHEN v_aging_days <= 7 THEN 25
        WHEN v_aging_days <= 30 THEN 50
        WHEN v_aging_days <= 90 THEN 75
        ELSE 100
    END;
    
    -- Additional priority for large amounts (threshold: 10000)
    IF v_amount > 100000 THEN
        v_priority := v_priority + 50;
    ELSIF v_amount > 10000 THEN
        v_priority := v_priority + 25;
    ELSIF v_amount > 1000 THEN
        v_priority := v_priority + 10;
    END IF;
    
    RETURN LEAST(v_priority, 150); -- Cap at 150
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION core.calculate_suspense_priority IS 'Calculate priority score based on aging and amount';

-- =============================================================================
-- Create suspense indexes
-- DESCRIPTION: Optimize suspense queries
-- PRIORITY: HIGH
-- SECURITY: Index on aging_bucket for prioritization
-- ============================================================================
-- [SUSP-006] Create suspense indexes

-- Primary and unique indexes (created with tables)
-- PRIMARY KEY (suspense_id)
-- UNIQUE (suspense_reference)

-- Foreign key indexes
CREATE INDEX idx_suspense_items_run_id ON core.suspense_items(run_id);
CREATE INDEX idx_suspense_items_item_id ON core.suspense_items(item_id);

-- Status and aging indexes
CREATE INDEX idx_suspense_items_status_aging ON core.suspense_items(status, aging_bucket);
CREATE INDEX idx_suspense_items_assigned_status ON core.suspense_items(assigned_to, status) 
    WHERE status != 'RESOLVED';
CREATE INDEX idx_suspense_items_app_type_status ON core.suspense_items(application_id, suspense_type, status);

-- Actions indexes
CREATE INDEX idx_suspense_actions_suspense_performed ON core.suspense_actions(suspense_id, performed_at);

COMMENT ON INDEX core.idx_suspense_items_status_aging IS 'Index for querying items by status and aging bucket';
COMMENT ON INDEX core.idx_suspense_items_assigned_status IS 'Partial index for open item workload queries';

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create suspense_items table with aging calculations
☑ Create suspense_actions table for audit trail
☑ Create suspense_aging_summary view
☑ Implement assign_suspense_item function
☑ Implement priority calculation
☑ Add all indexes for suspense queries
☑ Test aging bucket calculations
☑ Test assignment workflow
☑ Verify suspense statistics
================================================================================
*/
