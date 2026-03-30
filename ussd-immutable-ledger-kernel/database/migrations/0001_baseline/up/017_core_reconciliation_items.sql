-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Matching accuracy)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Matching security)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Match data handling)
-- ISO/IEC 27040:2024 - Storage Security (Match integrity)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Matching recovery)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Rule-based auto-matching with confidence scoring
-- - Confidence thresholds for auto-approval
-- - Manual override tracking
-- - Dispute handling workflow
-- ============================================================================
-- =============================================================================
-- MIGRATION: 017_core_reconciliation_items.sql
-- DESCRIPTION: Reconciliation Item Matching and Rules
-- TABLES: matching_rules, reconciliation_matches
-- DEPENDENCIES: 016_core_reconciliation_runs.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 8. Reconciliation & Exception Management
- Feature: Matching Rules
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Rule-based auto-matching with confidence scoring. Matches internal movements
against external statement lines using various strategies.

MATCHING RULES:
- EXACT: Amount, date, and reference match exactly
- FUZZY: Amount matches, date within tolerance, reference similar
- TOLERANCE: Amount within tolerance, other fields match
- REFERENCE_ONLY: Reference matches regardless of amount
- MANUAL: Human-determined match

CONFIDENCE SCORING:
- 100: Exact match on all fields
- 90-99: Amount and date match, reference similar
- 70-89: Amount matches, date within tolerance
- 50-69: Partial match, requires review
- <50: No match
================================================================================
*/

-- =============================================================================
-- TODO: Create matching_rules table
-- DESCRIPTION: Configurable matching rule definitions
-- PRIORITY: HIGH
-- SECURITY: Validate criteria JSON structure
-- ============================================================================
-- TODO: [MATCH-001] Create core.matching_rules table
-- INSTRUCTIONS:
--   - Define matching algorithms and parameters
--   - Order by priority for sequential application
--   - Support custom rule configurations
--   - ERROR HANDLING: Validate min/max confidence range
-- COMPLIANCE: ISO/IEC 27001 (Rule Configuration)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.matching_rules (
--       rule_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Identification
--       rule_code           VARCHAR(50) NOT NULL,
--       rule_name           VARCHAR(100) NOT NULL,
--       description         TEXT,
--       
--       -- Execution Order
--       priority            INTEGER NOT NULL DEFAULT 100,
--       
--       -- Rule Type
--       rule_type           VARCHAR(50) NOT NULL,        -- EXACT, FUZZY, TOLERANCE, REFERENCE
--       
--       -- Matching Criteria
--       criteria            JSONB NOT NULL,              -- Rule-specific parameters
--       -- EXAMPLE for EXACT:
--       -- { "amount_match": true, "date_match": "same_day", "reference_match": true }
--       -- EXAMPLE for TOLERANCE:
--       -- { "amount_tolerance": 0.01, "date_tolerance_days": 1 }
--       
--       -- Confidence Threshold
--       min_confidence      NUMERIC(5, 2) DEFAULT 80.00,
--       max_confidence      NUMERIC(5, 2) DEFAULT 100.00,
--       
--       -- Auto-match settings
--       auto_match          BOOLEAN DEFAULT false,       -- Auto-apply if in range
--       
--       -- Scope
--       application_id      UUID REFERENCES app.applications(application_id),
--       config_id           UUID REFERENCES core.reconciliation_config(config_id),
--       
--       is_active           BOOLEAN DEFAULT true,
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create reconciliation_matches table
-- DESCRIPTION: Record of all match decisions
-- PRIORITY: MEDIUM
-- SECURITY: Audit trail of matching decisions
-- ============================================================================
-- TODO: [MATCH-002] Create core.reconciliation_matches table
-- INSTRUCTIONS:
--   - Audit trail of all matching decisions
--   - Links internal and external items
--   - Records who/what made the match
--   - AUDIT LOGGING: Track manual overrides
-- COMPLIANCE: ISO/IEC 27018 (Match Audit)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.reconciliation_matches (
--       match_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       run_id              UUID NOT NULL REFERENCES core.reconciliation_runs(run_id),
--       
--       -- Matched Items
--       internal_item_id    UUID NOT NULL REFERENCES core.reconciliation_items(item_id),
--       external_item_id    UUID NOT NULL REFERENCES core.reconciliation_items(item_id),
--       
--       -- Match Details
--       match_type          VARCHAR(20) NOT NULL,        -- AUTO, MANUAL, FORCED
--       rule_id             UUID REFERENCES core.matching_rules(rule_id),
--       confidence_score    NUMERIC(5, 2) NOT NULL,
--       
--       -- Match Rationale
--       match_factors       JSONB,                       -- Which fields matched
--       variance_amount     NUMERIC(20, 8) DEFAULT 0,    -- If not exact match
--       
--       -- Manual Override
--       matched_by          UUID REFERENCES core.accounts(account_id),
--       notes               TEXT,
--       
--       -- Timing
--       matched_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       
--       -- Status
--       is_disputed         BOOLEAN DEFAULT false,
--       disputed_by         UUID REFERENCES core.accounts(account_id),
--       disputed_at         TIMESTAMPTZ,
--       dispute_reason      TEXT
--   );

-- =============================================================================
-- TODO: Create match execution function
-- DESCRIPTION: Apply matching rules to unreconciled items
-- PRIORITY: CRITICAL
-- SECURITY: Apply rules in priority order
-- ============================================================================
-- TODO: [MATCH-003] Create run_matching_rules function
-- INSTRUCTIONS:
--   - Iterate through rules by priority
--   - Find candidate matches for each rule
--   - Calculate confidence scores
--   - Apply auto-matches above threshold
--   - ERROR HANDLING: Log rule application errors, continue to next rule
--   - SEARCH PATH: Explicitly set
-- COMPLIANCE: ISO/IEC 27031 (Rule Execution)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.run_matching_rules(p_run_id UUID)
--   RETURNS INTEGER AS $$
--   DECLARE
--       v_rule RECORD;
--       v_match_count INTEGER := 0;
--   BEGIN
--       -- Process rules in priority order
--       FOR v_rule IN 
--           SELECT * FROM core.matching_rules 
--           WHERE is_active = true
--           ORDER BY priority
--       LOOP
--           CASE v_rule.rule_type
--               WHEN 'EXACT' THEN
--                   v_match_count := v_match_count + 
--                       core.apply_exact_match_rule(p_run_id, v_rule);
--               WHEN 'FUZZY' THEN
--                   v_match_count := v_match_count + 
--                       core.apply_fuzzy_match_rule(p_run_id, v_rule);
--               WHEN 'TOLERANCE' THEN
--                   v_match_count := v_match_count + 
--                       core.apply_tolerance_match_rule(p_run_id, v_rule);
--               -- etc.
--           END CASE;
--       END LOOP;
--       
--       RETURN v_match_count;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create exact match rule function
-- DESCRIPTION: Match on exact amount, date, and reference
-- PRIORITY: HIGH
-- SECURITY: Validate exact equality
-- ============================================================================
-- TODO: [MATCH-004] Create apply_exact_match_rule function
-- INSTRUCTIONS:
--   - Find pairs where amount, date, and reference match exactly
--   - Confidence = 100
--   - Auto-apply if rule allows
--   - ERROR HANDLING: Handle NULL values appropriately
-- COMPLIANCE: ISO/IEC 27040 (Exact Matching)

-- =============================================================================
-- TODO: Create manual match function
-- DESCRIPTION: Allow operator to manually match items
-- PRIORITY: HIGH
-- SECURITY: Verify operator authorization
-- ============================================================================
-- TODO: [MATCH-005] Create manual_match_items function
-- INSTRUCTIONS:
--   - Accept manual match from operator
--   - Validate items are unmatched
--   - Record as MANUAL match type
--   - Allow variance explanation
--   - ERROR HANDLING: Raise exception if items already matched
-- COMPLIANCE: ISO/IEC 27001 (Manual Override)

-- =============================================================================
-- TODO: Create unmatch function
-- DESCRIPTION: Undo a match
-- PRIORITY: MEDIUM
-- SECURITY: Log unmatch reason for audit
-- ============================================================================
-- TODO: [MATCH-006] Create unmatch_items function
-- INSTRUCTIONS:
--   - Revert items to UNMATCHED status
--   - Record unmatch reason
--   - Update reconciliation statistics
--   - AUDIT LOGGING: Log all unmatch actions
-- COMPLIANCE: ISO/IEC 27018 (Unmatch Audit)

-- =============================================================================
-- TODO: Create match indexes
-- DESCRIPTION: Optimize match queries
-- PRIORITY: HIGH
-- SECURITY: Index on confidence_score for analysis
-- ============================================================================
-- TODO: [MATCH-007] Create match indexes
-- INDEX LIST:
--   -- Matching rules:
--   - PRIMARY KEY (rule_id)
--   - INDEX on (priority) WHERE is_active = true
--   -- Matches:
--   - PRIMARY KEY (match_id)
--   - UNIQUE (internal_item_id, external_item_id)
--   - INDEX on (run_id, match_type)
--   - INDEX on (confidence_score)
--   - INDEX on (is_disputed)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create matching_rules table with configurable criteria
□ Create reconciliation_matches table
□ Implement run_matching_rules function
□ Implement rule-specific matching functions
□ Implement manual_match_items function
□ Implement unmatch_items function
□ Add all indexes for matching queries
□ Test matching rule execution
□ Test confidence scoring
□ Verify match statistics update
================================================================================
*/
