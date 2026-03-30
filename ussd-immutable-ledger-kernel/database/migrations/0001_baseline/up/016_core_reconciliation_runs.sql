-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Monitoring and review)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Reconciliation security)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Reconciliation data)
-- ISO/IEC 27040:2024 - Storage Security (Reconciliation integrity)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Reconciliation recovery)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Period-based reconciliation (daily/weekly)
-- - Multiple data source support
-- - Automated matching rules
-- - Exception queue management
-- ============================================================================
-- =============================================================================
-- MIGRATION: 016_core_reconciliation_runs.sql
-- DESCRIPTION: Reconciliation Run Management
-- TABLES: reconciliation_runs, reconciliation_config
-- DEPENDENCIES: 014_core_settlement_instructions.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 8. Reconciliation & Exception Management
- Feature: Reconciliation Runs
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Matches internal ledger movements against external statements (mobile money
provider, bank). Automatically detects discrepancies between USSD ledger and
external settlement reports.

KEY FEATURES:
- Period-based reconciliation (daily/weekly)
- Multiple data source support
- Automated matching rules
- Exception queue management
- Variance reporting

RECONCILIATION STATUS:
- PENDING: Run initialized
- IMPORTING: Loading external data
- MATCHING: Running auto-match rules
- REVIEW: Pending manual review
- COMPLETED: All items matched
- APPROVED: Variance accepted
================================================================================
*/

-- =============================================================================
-- TODO: Create reconciliation_config table
-- DESCRIPTION: Per-application reconciliation settings
-- PRIORITY: HIGH
-- SECURITY: Validate tolerance thresholds
-- ============================================================================
-- TODO: [RECON-001] Create core.reconciliation_config table
-- INSTRUCTIONS:
--   - Configure reconciliation frequency per application
--   - Define tolerance thresholds
--   - Set matching rule priorities
--   - ERROR HANDLING: Validate matching_rules JSON structure
-- COMPLIANCE: ISO/IEC 27001 (Configuration Management)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.reconciliation_config (
--       config_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Schedule
--       config_name         VARCHAR(100) NOT NULL,
--       frequency           VARCHAR(20) NOT NULL,        -- DAILY, WEEKLY, MONTHLY
--       day_of_week         INTEGER,                     -- 0=Sunday for weekly
--       day_of_month        INTEGER,                     -- 1-31 for monthly
--       
--       -- Data Sources
--       internal_source     VARCHAR(50) NOT NULL,        -- LEDGER, SETTLEMENTS
--       external_source     VARCHAR(50) NOT NULL,        -- Provider name
--       
--       -- Tolerance
--       amount_tolerance    NUMERIC(20, 8) DEFAULT 0.01, -- Acceptable variance
--       date_tolerance_days INTEGER DEFAULT 1,           -- Date matching window
--       
--       -- Matching Rules (ordered)
--       matching_rules      JSONB NOT NULL,              -- [{rule_type, priority, params}]
--       
--       -- Auto-approval
--       auto_approve_if_balanced BOOLEAN DEFAULT false,
--       
--       is_active           BOOLEAN DEFAULT true,
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create reconciliation_runs table
-- DESCRIPTION: Individual reconciliation instances
-- PRIORITY: CRITICAL
-- SECURITY: Track variance for fraud detection
-- ============================================================================
-- TODO: [RECON-002] Create core.reconciliation_runs table
-- INSTRUCTIONS:
--   - Records each reconciliation execution
--   - Tracks progress through stages
--   - Stores summary statistics
--   - RLS POLICY: Tenant isolation
--   - ERROR HANDLING: Validate period_start < period_end
-- COMPLIANCE: ISO/IEC 27040 (Run Integrity)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.reconciliation_runs (
--       run_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       run_reference       VARCHAR(100) UNIQUE NOT NULL,
--       
--       -- Configuration
--       config_id           UUID NOT NULL REFERENCES core.reconciliation_config(config_id),
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Period
--       period_start        DATE NOT NULL,
--       period_end          DATE NOT NULL,
--       
--       -- Status
--       status              VARCHAR(20) DEFAULT 'PENDING',
--                           -- PENDING, IMPORTING, MATCHING, REVIEW, COMPLETED, APPROVED
--       
--       -- Statistics
--       internal_item_count INTEGER DEFAULT 0,
--       external_item_count INTEGER DEFAULT 0,
--       matched_count       INTEGER DEFAULT 0,
--       unmatched_internal  INTEGER DEFAULT 0,
--       unmatched_external  INTEGER DEFAULT 0,
--       
--       -- Financial Summary
--       internal_total      NUMERIC(20, 8) DEFAULT 0,
--       external_total      NUMERIC(20, 8) DEFAULT 0,
--       variance            NUMERIC(20, 8) DEFAULT 0,
--       
--       -- Timing
--       started_at          TIMESTAMPTZ,
--       completed_at        TIMESTAMPTZ,
--       approved_at         TIMESTAMPTZ,
--       approved_by         UUID REFERENCES core.accounts(account_id),
--       
--       -- Results
--       summary_report      JSONB,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id)
--   );

-- =============================================================================
-- TODO: Create reconciliation_items table
-- DESCRIPTION: Individual items to be reconciled
-- PRIORITY: CRITICAL
-- SECURITY: Link to source transactions
-- ============================================================================
-- TODO: [RECON-003] Create core.reconciliation_items table
-- INSTRUCTIONS:
--   - Stores both internal and external items
--   - Records matching results
--   - Links matched pairs
--   - ERROR HANDLING: Validate amount precision
-- COMPLIANCE: ISO/IEC 27040 (Item Integrity)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.reconciliation_items (
--       item_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       run_id              UUID NOT NULL REFERENCES core.reconciliation_runs(run_id),
--       
--       -- Item Source
--       item_type           VARCHAR(20) NOT NULL,        -- INTERNAL, EXTERNAL
--       source_reference    VARCHAR(255) NOT NULL,       -- Tx ID or statement line ref
--       
--       -- Financial
--       amount              NUMERIC(20, 8) NOT NULL,
--       currency            VARCHAR(3) NOT NULL,
--       direction           VARCHAR(10),                 -- DEBIT, CREDIT
--       
--       -- Dates
--       transaction_date    DATE NOT NULL,
--       value_date          DATE,
--       
--       -- Matching
--       match_status        VARCHAR(20) DEFAULT 'UNMATCHED',
--                           -- UNMATCHED, MATCHED, DISPUTED, WRITTEN_OFF
--       matched_item_id     UUID REFERENCES core.reconciliation_items(item_id),
--       match_score         NUMERIC(5, 2),               -- Confidence score
--       matched_by_rule     VARCHAR(50),                 -- Which rule matched
--       matched_at          TIMESTAMPTZ,
--       
--       -- External Data (for external items)
--       raw_data            JSONB,
--       
--       -- Internal Link (for internal items)
--       movement_id         UUID REFERENCES core.movement_headers(movement_id),
--       settlement_id       UUID REFERENCES core.settlement_instructions(instruction_id),
--       
--       -- Description
--       description         TEXT,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create reconciliation execution function
-- DESCRIPTION: Run reconciliation process
-- PRIORITY: CRITICAL
-- SECURITY: Validate data integrity during import
-- ============================================================================
-- TODO: [RECON-004] Create execute_reconciliation function
-- INSTRUCTIONS:
--   - Import internal items from ledger
--   - Import external items from provider
--   - Apply matching rules in priority order
--   - Generate summary statistics
--   - ERROR HANDLING: Log import errors, continue with available data
--   - TRANSACTION ISOLATION: Each phase in separate transaction
-- COMPLIANCE: ISO/IEC 27031 (Process Integrity)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.execute_reconciliation(p_run_id UUID)
--   RETURNS VARCHAR AS $$
--   DECLARE
--       v_run RECORD;
--   BEGIN
--       -- Get run details
--       SELECT * INTO v_run FROM core.reconciliation_runs WHERE run_id = p_run_id;
--       
--       -- Update status
--       UPDATE core.reconciliation_runs 
--       SET status = 'IMPORTING', started_at = now()
--       WHERE run_id = p_run_id;
--       
--       -- Import internal items
--       PERFORM core.import_internal_items(p_run_id, v_run.period_start, v_run.period_end);
--       
--       -- Import external items
--       PERFORM core.import_external_items(p_run_id, v_run.external_source);
--       
--       -- Update status
--       UPDATE core.reconciliation_runs SET status = 'MATCHING' WHERE run_id = p_run_id;
--       
--       -- Run matching rules
--       PERFORM core.run_matching_rules(p_run_id);
--       
--       -- Calculate statistics
--       PERFORM core.calculate_reconciliation_stats(p_run_id);
--       
--       -- Update status
--       UPDATE core.reconciliation_runs 
--       SET status = 'REVIEW', completed_at = now()
--       WHERE run_id = p_run_id;
--       
--       RETURN 'COMPLETED';
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create reconciliation indexes
-- DESCRIPTION: Optimize reconciliation queries
-- PRIORITY: HIGH
-- SECURITY: Index on match_status for unmatched queries
-- ============================================================================
-- TODO: [RECON-005] Create reconciliation indexes
-- INDEX LIST:
--   - PRIMARY KEY (run_id)
--   - UNIQUE (run_reference)
--   - INDEX on (application_id, period_start, period_end)
--   - INDEX on (status, created_at)
--   -- Items:
--   - INDEX on (run_id, item_type)
--   - INDEX on (run_id, match_status)
--   - INDEX on (amount, transaction_date)
--   - INDEX on (matched_item_id)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create reconciliation_config table
□ Create reconciliation_runs table
□ Create reconciliation_items table
□ Implement execute_reconciliation function
□ Implement import functions (internal/external)
□ Implement matching rules engine
□ Add all indexes for reconciliation queries
□ Test reconciliation workflow
□ Test matching rule accuracy
□ Verify variance calculations
================================================================================
*/
