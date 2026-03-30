-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Resolution authorization)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Resolution security)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Resolution data handling)
-- ISO/IEC 27040:2024 - Storage Security (Adjustment integrity)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Resolution recovery)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Authorization levels for different resolution types
-- - Approval workflow for large amounts
-- - Full audit trail of resolution
-- - Adjustment journal entries
-- ============================================================================
-- =============================================================================
-- MIGRATION: 019_core_suspense_resolutions.sql
-- DESCRIPTION: Suspense Item Resolution Actions
-- TABLES: suspense_resolutions, suspense_adjustments
-- DEPENDENCIES: 018_core_suspense_items.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 8. Reconciliation & Exception Management
- Feature: Suspense Resolution
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Supports resolution actions: match to movement, adjustment, write-off, refund.
Full audit trail of resolution for compliance.

RESOLUTION TYPES:
- MATCH: Found matching transaction, link them
- ADJUST: Create correcting entry
- WRITE_OFF: Accept loss, remove from suspense
- REFUND: Return funds to originator
- REVERSAL: Reverse original transaction
- DUPLICATE: Mark as duplicate, no action needed
================================================================================
*/

-- =============================================================================
-- TODO: Create suspense_resolutions table
-- DESCRIPTION: Resolution actions taken on suspense items
-- PRIORITY: CRITICAL
-- SECURITY: Approval required for large amounts
-- ============================================================================
-- TODO: [RES-001] Create core.suspense_resolutions table
-- INSTRUCTIONS:
--   - Records final resolution of suspense items
--   - Links to resulting movements/adjustments
--   - Immutable once recorded
--   - RLS POLICY: Tenant isolation
--   - ERROR HANDLING: Validate resolution_type is valid
-- COMPLIANCE: ISO/IEC 27001 (Resolution Control)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.suspense_resolutions (
--       resolution_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       resolution_reference VARCHAR(100) UNIQUE NOT NULL,
--       
--       -- Source
--       suspense_id         UUID NOT NULL REFERENCES core.suspense_items(suspense_id),
--       
--       -- Resolution Details
--       resolution_type     VARCHAR(50) NOT NULL,        -- MATCH, ADJUST, WRITE_OFF, etc.
--       resolution_reason   TEXT NOT NULL,
--       
--       -- Financial Impact
--       amount_resolved     NUMERIC(20, 8) NOT NULL,
--       currency            VARCHAR(3) NOT NULL,
--       
--       -- Links to Resulting Transactions
--       movement_id         UUID REFERENCES core.movement_headers(movement_id),
--       adjustment_id       UUID,                        -- Link to adjustment record
--       
--       -- Authorization
--       resolved_by         UUID NOT NULL REFERENCES core.accounts(account_id),
--       approved_by         UUID REFERENCES core.accounts(account_id), -- For large amounts
--       
--       -- Approval (if required)
--       approval_status     VARCHAR(20) DEFAULT 'NOT_REQUIRED',
--                           -- NOT_REQUIRED, PENDING, APPROVED, REJECTED
--       
--       -- Timing
--       resolved_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
--       approved_at         TIMESTAMPTZ,
--       
--       -- Documentation
--       supporting_docs     UUID[],                      -- References to documents
--       notes               TEXT,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create suspense_adjustments table
-- DESCRIPTION: Financial adjustments for suspense resolution
-- PRIORITY: HIGH
-- SECURITY: Chart of accounts validation
-- ============================================================================
-- TODO: [RES-002] Create core.suspense_adjustments table
-- INSTRUCTIONS:
--   - Records accounting adjustments made during resolution
--   - Links to chart of accounts
--   - Supports multiple adjustment lines
--   - ERROR HANDLING: Validate COA codes exist
-- COMPLIANCE: ISO/IEC 27040 (Adjustment Integrity)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.suspense_adjustments (
--       adjustment_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       adjustment_reference VARCHAR(100) UNIQUE NOT NULL,
--       
--       -- Link to Resolution
--       resolution_id       UUID NOT NULL REFERENCES core.suspense_resolutions(resolution_id),
--       
--       -- Adjustment Details
--       adjustment_type     VARCHAR(50) NOT NULL,        -- CORRECTION, WRITE_OFF, etc.
--       
--       -- COA Impact
--       debit_coa_code      VARCHAR(50) REFERENCES core.chart_of_accounts(coa_code),
--       credit_coa_code     VARCHAR(50) REFERENCES core.chart_of_accounts(coa_code),
--       
--       -- Amount
--       amount              NUMERIC(20, 8) NOT NULL,
--       currency            VARCHAR(3) NOT NULL,
--       
--       -- Description
--       description         TEXT NOT NULL,
--       
--       -- Links to Movement
--       movement_id         UUID REFERENCES core.movement_headers(movement_id),
--       
--       -- Status
--       status              VARCHAR(20) DEFAULT 'PENDING', -- PENDING, POSTED, CANCELLED
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id),
--       posted_at           TIMESTAMPTZ,
--       posted_by           UUID REFERENCES core.accounts(account_id)
--   );

-- =============================================================================
-- TODO: Create resolution workflow function
-- DESCRIPTION: Process suspense resolution
-- PRIORITY: CRITICAL
-- SECURITY: Authorization checks for large amounts
-- ============================================================================
-- TODO: [RES-003] Create resolve_suspense_item function
-- INSTRUCTIONS:
--   - Validate resolution request
--   - Check authorization requirements
--   - Create appropriate records
--   - Update suspense status
--   - ERROR HANDLING: Validate all prerequisites before resolution
--   - TRANSACTION ISOLATION: All-or-nothing resolution
-- COMPLIANCE: ISO/IEC 27031 (Workflow Control)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.resolve_suspense_item(
--       p_suspense_id UUID,
--       p_resolution_type VARCHAR(50),
--       p_resolution_reason TEXT,
--       p_resolved_by UUID,
--       p_amount NUMERIC DEFAULT NULL
--   ) RETURNS UUID AS $$
--   DECLARE
--       v_resolution_id UUID;
--       v_suspense RECORD;
--       v_approval_required BOOLEAN := false;
--   BEGIN
--       -- Get suspense item
--       SELECT * INTO v_suspense FROM core.suspense_items WHERE suspense_id = p_suspense_id;
--       
--       -- Check authorization
--       IF p_amount > 10000 THEN  -- Threshold from config
--           v_approval_required := true;
--       END IF;
--       
--       -- Create resolution record
--       INSERT INTO core.suspense_resolutions (
--           resolution_reference,
--           suspense_id,
--           resolution_type,
--           resolution_reason,
--           amount_resolved,
--           currency,
--           resolved_by,
--           approval_status
--       ) VALUES (
--           'RES-' || to_char(now(), 'YYYYMMDD') || '-' || substr(gen_random_uuid()::text, 1, 8),
--           p_suspense_id,
--           p_resolution_type,
--           p_resolution_reason,
--           COALESCE(p_amount, v_suspense.amount),
--           v_suspense.currency,
--           p_resolved_by,
--           CASE WHEN v_approval_required THEN 'PENDING' ELSE 'NOT_REQUIRED' END
--       )
--       RETURNING resolution_id INTO v_resolution_id;
--       
--       -- Update suspense status
--       UPDATE core.suspense_items
--       SET status = CASE WHEN v_approval_required THEN 'PENDING' ELSE 'RESOLVED' END,
--           resolved_at = CASE WHEN NOT v_approval_required THEN now() ELSE NULL END,
--           resolved_by = CASE WHEN NOT v_approval_required THEN p_resolved_by ELSE NULL END,
--           resolution_type = p_resolution_type
--       WHERE suspense_id = p_suspense_id;
--       
--       RETURN v_resolution_id;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create approval function
-- DESCRIPTION: Approve pending resolution
-- PRIORITY: HIGH
-- SECURITY: Verify approver authorization level
-- ============================================================================
-- TODO: [RES-004] Create approve_resolution function
-- INSTRUCTIONS:
--   - Approve resolution requiring authorization
--   - Execute financial adjustments
--   - Finalize resolution
--   - ERROR HANDLING: Verify approver != resolver (segregation of duties)
-- COMPLIANCE: ISO/IEC 27001 (Segregation of Duties)

-- =============================================================================
-- TODO: Create write-off function
-- DESCRIPTION: Process write-off resolution
-- PRIORITY: HIGH
-- SECURITY: Bad debt provision recording
-- ============================================================================
-- TODO: [RES-005] Create process_write_off function
-- INSTRUCTIONS:
--   - Create write-off journal entry
--   - Update suspense to resolved
--   - Record in bad debt provision if applicable
--   - ERROR HANDLING: Verify write-off authority
-- COMPLIANCE: ISO/IEC 27040 (Write-off Control)

-- =============================================================================
-- TODO: Create resolution indexes
-- DESCRIPTION: Optimize resolution queries
-- PRIORITY: HIGH
-- SECURITY: Index on approval_status for pending approvals
-- ============================================================================
-- TODO: [RES-006] Create resolution indexes
-- INDEX LIST:
--   -- Resolutions:
--   - PRIMARY KEY (resolution_id)
--   - UNIQUE (resolution_reference)
--   - INDEX on (suspense_id)
--   - INDEX on (approval_status)
--   - INDEX on (resolved_by, resolved_at)
--   -- Adjustments:
--   - PRIMARY KEY (adjustment_id)
--   - UNIQUE (adjustment_reference)
--   - INDEX on (resolution_id)
--   - INDEX on (status)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create suspense_resolutions table
□ Create suspense_adjustments table
□ Implement resolve_suspense_item function
□ Implement approve_resolution function
□ Implement process_write_off function
□ Add all indexes for resolution queries
□ Test resolution workflow
□ Test approval process
□ Verify audit trail completeness
================================================================================
*/
