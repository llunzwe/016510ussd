-- =============================================================================
-- MIGRATION: 044_app_matching_rules.sql
-- DESCRIPTION: Reconciliation Matching Rules
-- TABLES: app_matching_rules, matching_rule_conditions
-- DEPENDENCIES: 016_core_reconciliation_runs.sql
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.8.2: Privileged access rights (financial reconciliation)
  - A.12.3: Information backup (reconciliation evidence)
  - A.14.2.8: System acceptance testing (matching accuracy)

ISO/IEC 27050-3:2020 - Electronic Discovery
  - Section 8: Processing and review
  - Reconciliation records are evidence of financial integrity

GDPR / Zimbabwe Data Protection Act (Chapter 11:12)
  - Article 32: Security of processing (fraud detection)
  - Section 14: Security safeguards for financial systems
  - Matching may reveal patterns requiring PII protection

FINANCIAL REGULATIONS:
  - Prudential guidelines on reconciliation
  - Audit trail requirements for matched/unmatched items
  - Exception reporting for material discrepancies

SECURITY CLASSIFICATION: RESTRICTED
DATA SENSITIVITY: FINANCIAL RECONCILIATION DATA
RETENTION PERIOD: 7 years (financial records)
AUDIT REQUIREMENT: All matches logged with confidence score
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 8. Reconciliation & Exception Management
- Feature: Matching Rules
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Rule-based auto-matching (exact, fuzzy, tolerance) with confidence scoring.
Auto-pair a withdrawal movement with a mobile money debit notification.

RULE TYPES:
- EXACT_MATCH: All fields match exactly
- FUZZY_MATCH: Similar reference, amount matches
- TOLERANCE_MATCH: Amount within tolerance
- REFERENCE_MATCH: Reference matches
- DATE_RANGE_MATCH: Dates within window

KEY FEATURES:
- Configurable matching criteria
- Confidence scoring
- Priority ordering
- Manual override support

SECURITY NOTES:
- Matching rules are privileged configuration
- Override actions require additional authorization
- Confidence thresholds prevent false matches
- All matching actions logged for audit
================================================================================
*/

-- =============================================================================
-- TODO: Create app_matching_rules table
-- DESCRIPTION: Application-level matching rules
-- PRIORITY: HIGH
-- SECURITY: RLS restricted to reconciliation managers
-- AUDIT: Rule changes logged with before/after values
-- DATA INTEGRITY: Rules versioned for reproducibility
-- =============================================================================
-- TODO: [MRULE-001] Create app.app_matching_rules table
-- INSTRUCTIONS:
--   - Extends core matching_rules
--   - Application-specific customizations
--   - Higher priority than default rules
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE app.app_matching_rules (
--       rule_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Core Rule Link (optional)
--       core_rule_id        UUID REFERENCES core.matching_rules(rule_id),
--       
--       -- Identification
--       rule_code           VARCHAR(50) NOT NULL,
--       rule_name           VARCHAR(100) NOT NULL,
--       description         TEXT,
--       
--       -- Scope
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       reconciliation_config_id UUID REFERENCES core.reconciliation_config(config_id),
--       
--       -- Execution
--       priority            INTEGER NOT NULL DEFAULT 100,
--       
--       -- Rule Type
--       rule_type           VARCHAR(50) NOT NULL,        -- EXACT, FUZZY, TOLERANCE
--       
--       -- Matching Criteria
--       match_criteria      JSONB NOT NULL,              -- Field matching rules
--       -- Example:
--       -- {
--       --   "amount": { "match_type": "EXACT" },
--       --   "date": { "match_type": "WITHIN_DAYS", "tolerance": 1 },
--       --   "reference": { "match_type": "FUZZY", "similarity": 0.8 }
--       -- }
--       
--       -- Thresholds
--       min_confidence      NUMERIC(5, 2) DEFAULT 80.00,
--       auto_match          BOOLEAN DEFAULT false,       -- Auto-apply if confident
--       
--       -- Tolerance Settings
--       amount_tolerance    NUMERIC(20, 8),              -- Absolute amount tolerance
--       amount_tolerance_pct NUMERIC(5, 2),              -- Percentage tolerance
--       date_tolerance_days INTEGER DEFAULT 1,
--       
--       -- Status
--       is_active           BOOLEAN DEFAULT true,
--       
--       -- Validity
--       valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       valid_to            TIMESTAMPTZ,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id)
--   );

-- =============================================================================
-- TODO: Create matching_rule_conditions table
-- DESCRIPTION: Conditional matching criteria
-- PRIORITY: MEDIUM
-- SECURITY: Access restricted to rule administrators
-- =============================================================================
-- TODO: [MRULE-002] Create app.matching_rule_conditions table
-- INSTRUCTIONS:
--   - Additional conditions for when to apply rule
--   - Entity type filters
--   - Amount range filters
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE app.matching_rule_conditions (
--       condition_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       rule_id             UUID NOT NULL REFERENCES app.app_matching_rules(rule_id),
--       
--       -- Condition Type
--       condition_type      VARCHAR(50) NOT NULL,        -- ENTITY_TYPE, AMOUNT_RANGE, etc.
--       
--       -- Condition Parameters
--       condition_params    JSONB NOT NULL,
--       -- Example: {"entity_types": ["CONTRIBUTION", "LOAN_REPAYMENT"]}
--       -- Example: {"min_amount": 100, "max_amount": 10000}
--       
--       -- Evaluation
--       evaluation_order    INTEGER DEFAULT 1,
--       
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create evaluate_matching_rule function
-- DESCRIPTION: Score potential match
-- PRIORITY: CRITICAL
-- SECURITY: SECURITY DEFINER; validates access to both items
-- AUDIT: High-confidence matches logged for review
-- DATA PROTECTION: No PII exposed in scoring algorithm
-- =============================================================================
-- TODO: [MRULE-003] Create evaluate_matching_rule function
-- INSTRUCTIONS:
--   - Apply matching criteria
--   - Calculate confidence score
--   - Return match result
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION app.evaluate_matching_rule(
--       p_rule_id UUID,
--       p_internal_item_id UUID,
--       p_external_item_id UUID
--   ) RETURNS TABLE (
--       is_match BOOLEAN,
--       confidence NUMERIC,
--       match_factors JSONB,
--       reason TEXT
--   ) AS $$
--   DECLARE
--       v_rule RECORD;
--       v_internal RECORD;
--       v_external RECORD;
--       v_confidence NUMERIC := 0;
--       v_factors JSONB := '{}';
--       v_matches INTEGER := 0;
--       v_total INTEGER := 0;
--   BEGIN
--       -- Get rule
--       SELECT * INTO v_rule FROM app.app_matching_rules WHERE rule_id = p_rule_id;
--       
--       -- Get items
--       SELECT * INTO v_internal FROM core.reconciliation_items WHERE item_id = p_internal_item_id;
--       SELECT * INTO v_external FROM core.reconciliation_items WHERE item_id = p_external_item_id;
--       
--       -- Evaluate amount
--       IF v_rule.match_criteria->'amount'->>'match_type' = 'EXACT' THEN
--           v_total := v_total + 1;
--           IF v_internal.amount = v_external.amount THEN
--               v_matches := v_matches + 1;
--               v_factors := v_factors || '{"amount": "EXACT"}'::jsonb;
--           ELSIF v_rule.amount_tolerance IS NOT NULL THEN
--               IF ABS(v_internal.amount - v_external.amount) <= v_rule.amount_tolerance THEN
--                   v_matches := v_matches + 0.5;
--                   v_factors := v_factors || '{"amount": "TOLERANCE"}'::jsonb;
--               END IF;
--           END IF;
--       END IF;
--       
--       -- Evaluate date
--       IF v_rule.match_criteria->'date'->>'match_type' = 'WITHIN_DAYS' THEN
--           v_total := v_total + 1;
--           IF ABS(v_internal.transaction_date - v_external.transaction_date) <= v_rule.date_tolerance_days THEN
--               v_matches := v_matches + 1;
--               v_factors := v_factors || '{"date": "WITHIN_TOLERANCE"}'::jsonb;
--           END IF;
--       END IF;
--       
--       -- Calculate confidence
--       IF v_total > 0 THEN
--           v_confidence := (v_matches / v_total) * 100;
--       END IF;
--       
--       RETURN QUERY SELECT 
--           v_confidence >= v_rule.min_confidence,
--           v_confidence,
--           v_factors,
--           CASE 
--               WHEN v_confidence >= v_rule.min_confidence THEN 'Match found'
--               ELSE 'Confidence below threshold'
--           END;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create find_matches function
-- DESCRIPTION: Find potential matches for item
-- PRIORITY: HIGH
-- SECURITY: Respects RLS on source tables
-- =============================================================================
-- TODO: [MRULE-004] Create find_potential_matches function
-- INSTRUCTIONS:
--   - Query for candidate matches
--   - Evaluate each with matching rules
--   - Return ranked results

-- =============================================================================
-- TODO: Create matching rule indexes
-- DESCRIPTION: Optimize matching queries
-- PRIORITY: HIGH
-- PERFORMANCE: Indexes support high-volume reconciliation
-- =============================================================================
-- TODO: [MRULE-005] Create matching rule indexes
-- INDEX LIST:
--   -- App Matching Rules:
--   - PRIMARY KEY (rule_id)
--   - UNIQUE (application_id, rule_code) WHERE valid_to IS NULL
--   - INDEX on (application_id, is_active, priority)
--   -- Conditions:
--   - PRIMARY KEY (condition_id)
--   - INDEX on (rule_id, evaluation_order)

/*
================================================================================
RECONCILIATION SECURITY & AUDIT GUIDE
================================================================================

1. CONFIDENCE SCORING ALGORITHM:
   - Exact match: 100 points per field
   - Tolerance match: 50 points per field
   - Fuzzy match: 25-75 points based on similarity
   - Minimum threshold: 80% for auto-match, 60% for suggestion

2. AUTO-MATCH SAFEGUARDS:
   - Never auto-match amounts > $10,000 without secondary review
   - Flag matches where dates differ by > 7 days
   - Require manual approval for first-time counterparty matches
   - Daily report of all auto-matches for audit review

3. AUDIT TRAIL REQUIREMENTS:
   ┌─────────────────┬─────────────────────────────────────────────────┐
   │ Event           │ Data Captured                                   │
   ├─────────────────┼─────────────────────────────────────────────────┤
   │ Rule Created    │ Who, when, criteria, thresholds                 │
   │ Rule Modified   │ Before/after values, change reason              │
   │ Match Applied   │ Items matched, confidence, rule used, who       │
   │ Match Rejected  │ Items, confidence, rejection reason, who        │
   │ Manual Override │ Original match, new match, justification, auth  │
   └─────────────────┴─────────────────────────────────────────────────┘

4. FRAUD DETECTION INTEGRATION:
   - Unusual matching patterns trigger alert
   - Velocity check: > 100 matches/minute = investigation
   - Cross-reference with device fingerprint for authenticity
   - Flag accounts with high manual override rates

5. DATA PROTECTION:
   - Matching rules don't process PII directly
   - Item references hashed in logs
   - Confidence scores anonymized for analytics
   - Retention: Match logs kept 7 years per financial regulations
================================================================================
*/

/*
================================================================================
MIGRATION CHECKLIST:
□ Create app_matching_rules table
□ Create matching_rule_conditions table
□ Implement evaluate_matching_rule function
□ Implement find_potential_matches function
□ Add all indexes for matching queries
□ Test confidence scoring
□ Test rule conditions
□ Test auto-matching threshold
□ Verify rule priority ordering
□ Configure auto-match safeguards
□ Set up audit logging for matches
□ Document fraud detection integration
================================================================================
*/
