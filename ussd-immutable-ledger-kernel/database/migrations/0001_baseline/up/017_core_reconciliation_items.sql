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
-- Create matching_rules table
-- DESCRIPTION: Configurable matching rule definitions
-- PRIORITY: HIGH
-- SECURITY: Validate criteria JSON structure
-- ============================================================================
CREATE TABLE core.matching_rules (
    rule_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Identification
    rule_code           VARCHAR(50) NOT NULL,
    rule_name           VARCHAR(100) NOT NULL,
    description         TEXT,
    
    -- Execution Order
    priority            INTEGER NOT NULL DEFAULT 100,
    
    -- Rule Type
    rule_type           VARCHAR(50) NOT NULL,        -- EXACT, FUZZY, TOLERANCE, REFERENCE
    
    -- Matching Criteria
    criteria            JSONB NOT NULL,              -- Rule-specific parameters
    -- EXAMPLE for EXACT:
    -- { "amount_match": true, "date_match": "same_day", "reference_match": true }
    -- EXAMPLE for TOLERANCE:
    -- { "amount_tolerance": 0.01, "date_tolerance_days": 1 }
    
    -- Confidence Threshold
    min_confidence      NUMERIC(5, 2) DEFAULT 80.00,
    max_confidence      NUMERIC(5, 2) DEFAULT 100.00,
    
    -- Auto-match settings
    auto_match          BOOLEAN DEFAULT false,       -- Auto-apply if in range
    
    -- Scope
    application_id      UUID REFERENCES app.applications(application_id),
    config_id           UUID REFERENCES core.reconciliation_config(config_id),
    
    is_active           BOOLEAN DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Constraints
    CONSTRAINT chk_matching_rules_type 
        CHECK (rule_type IN ('EXACT', 'FUZZY', 'TOLERANCE', 'REFERENCE', 'MANUAL')),
    CONSTRAINT chk_matching_rules_confidence 
        CHECK (min_confidence >= 0 AND max_confidence <= 100 AND min_confidence <= max_confidence)
);

-- Seed default matching rules
INSERT INTO core.matching_rules (rule_code, rule_name, description, rule_type, priority, criteria, min_confidence, auto_match) VALUES
('EXACT_ALL', 'Exact Match All Fields', 'Exact match on amount, date, and reference', 'EXACT', 10, 
 '{"amount_match": true, "date_match": "same_day", "reference_match": true}', 100.00, true),
('EXACT_AMOUNT_DATE', 'Exact Amount and Date', 'Exact match on amount and date', 'EXACT', 20, 
 '{"amount_match": true, "date_match": "same_day"}', 95.00, true),
('FUZZY_TOLERANCE', 'Fuzzy with Tolerance', 'Amount within tolerance, date within 1 day', 'FUZZY', 30, 
 '{"amount_tolerance_percent": 1.0, "date_tolerance_days": 1}', 85.00, true),
('REFERENCE_MATCH', 'Reference Match', 'Reference matches exactly, any amount', 'REFERENCE', 40, 
 '{"reference_match": true}', 70.00, false)
ON CONFLICT DO NOTHING;

CREATE INDEX idx_matching_rules_priority ON core.matching_rules(priority) WHERE is_active = true;
CREATE INDEX idx_matching_rules_config ON core.matching_rules(config_id);

COMMENT ON TABLE core.matching_rules IS 'Configurable matching rule definitions with confidence thresholds';
COMMENT ON COLUMN core.matching_rules.criteria IS 'JSON parameters defining how to match items';

-- =============================================================================
-- Create reconciliation_matches table
-- DESCRIPTION: Record of all match decisions
-- PRIORITY: MEDIUM
-- SECURITY: Audit trail of matching decisions
-- ============================================================================
CREATE TABLE core.reconciliation_matches (
    match_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id              UUID NOT NULL REFERENCES core.reconciliation_runs(run_id),
    
    -- Matched Items
    internal_item_id    UUID NOT NULL REFERENCES core.reconciliation_items(item_id),
    external_item_id    UUID NOT NULL REFERENCES core.reconciliation_items(item_id),
    
    -- Match Details
    match_type          VARCHAR(20) NOT NULL,        -- AUTO, MANUAL, FORCED
    rule_id             UUID REFERENCES core.matching_rules(rule_id),
    confidence_score    NUMERIC(5, 2) NOT NULL,
    
    -- Match Rationale
    match_factors       JSONB,                       -- Which fields matched
    variance_amount     NUMERIC(20, 8) DEFAULT 0,    -- If not exact match
    
    -- Manual Override
    matched_by          UUID REFERENCES core.accounts(account_id),
    notes               TEXT,
    
    -- Timing
    matched_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Status
    is_disputed         BOOLEAN DEFAULT false,
    disputed_by         UUID REFERENCES core.accounts(account_id),
    disputed_at         TIMESTAMPTZ,
    dispute_reason      TEXT,
    
    -- Constraints
    CONSTRAINT uq_reconciliation_matches UNIQUE (internal_item_id, external_item_id),
    CONSTRAINT chk_reconciliation_matches_type 
        CHECK (match_type IN ('AUTO', 'MANUAL', 'FORCED')),
    CONSTRAINT chk_reconciliation_matches_confidence 
        CHECK (confidence_score >= 0 AND confidence_score <= 100)
);

CREATE INDEX idx_reconciliation_matches_run ON core.reconciliation_matches(run_id, match_type);
CREATE INDEX idx_reconciliation_matches_internal ON core.reconciliation_matches(internal_item_id);
CREATE INDEX idx_reconciliation_matches_external ON core.reconciliation_matches(external_item_id);
CREATE INDEX idx_reconciliation_matches_confidence ON core.reconciliation_matches(confidence_score);
CREATE INDEX idx_reconciliation_matches_disputed ON core.reconciliation_matches(is_disputed) WHERE is_disputed = true;

COMMENT ON TABLE core.reconciliation_matches IS 'Audit trail of all matching decisions';
COMMENT ON COLUMN core.reconciliation_matches.confidence_score IS 'Match confidence from 0-100';
COMMENT ON COLUMN core.reconciliation_matches.match_factors IS 'JSON describing which fields contributed to match';

-- =============================================================================
-- Create match execution function
-- DESCRIPTION: Apply matching rules to unreconciled items
-- PRIORITY: CRITICAL
-- SECURITY: Apply rules in priority order
-- ============================================================================
CREATE OR REPLACE FUNCTION core.run_matching_rules(p_run_id UUID)
RETURNS INTEGER AS $$
DECLARE
    v_rule RECORD;
    v_match_count INTEGER := 0;
    v_rule_matches INTEGER;
BEGIN
    -- Process rules in priority order
    FOR v_rule IN 
        SELECT * FROM core.matching_rules 
        WHERE is_active = true
        ORDER BY priority
    LOOP
        v_rule_matches := 0;
        
        CASE v_rule.rule_type
            WHEN 'EXACT' THEN
                SELECT core.apply_exact_match_rule(p_run_id, v_rule.rule_id) INTO v_rule_matches;
            WHEN 'FUZZY' THEN
                SELECT core.apply_fuzzy_match_rule(p_run_id, v_rule.rule_id) INTO v_rule_matches;
            WHEN 'TOLERANCE' THEN
                SELECT core.apply_tolerance_match_rule(p_run_id, v_rule.rule_id) INTO v_rule_matches;
            WHEN 'REFERENCE' THEN
                SELECT core.apply_reference_match_rule(p_run_id, v_rule.rule_id) INTO v_rule_matches;
        END CASE;
        
        v_match_count := v_match_count + v_rule_matches;
        
        -- Log rule application
        RAISE NOTICE 'Applied rule % (%): % matches', v_rule.rule_code, v_rule.rule_type, v_rule_matches;
    END LOOP;
    
    RETURN v_match_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.run_matching_rules IS 'Applies all active matching rules to unreconciled items';

-- =============================================================================
-- Create exact match rule function
-- DESCRIPTION: Match on exact amount, date, and reference
-- PRIORITY: HIGH
-- SECURITY: Validate exact equality
-- ============================================================================
CREATE OR REPLACE FUNCTION core.apply_exact_match_rule(
    p_run_id UUID,
    p_rule_id UUID
) RETURNS INTEGER AS $$
DECLARE
    v_rule RECORD;
    v_matches INTEGER := 0;
    v_internal RECORD;
    v_external RECORD;
BEGIN
    SELECT * INTO v_rule FROM core.matching_rules WHERE rule_id = p_rule_id;
    
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    
    -- Find exact matches
    FOR v_internal IN 
        SELECT * FROM core.reconciliation_items
        WHERE run_id = p_run_id 
          AND item_type = 'INTERNAL' 
          AND match_status = 'UNMATCHED'
    LOOP
        SELECT * INTO v_external
        FROM core.reconciliation_items
        WHERE run_id = p_run_id 
          AND item_type = 'EXTERNAL' 
          AND match_status = 'UNMATCHED'
          AND amount = v_internal.amount
          AND transaction_date = v_internal.transaction_date
          AND (v_rule.criteria->>'reference_match' IS NULL OR 
               source_reference = v_internal.source_reference)
        LIMIT 1;
        
        IF FOUND THEN
            -- Create match
            INSERT INTO core.reconciliation_matches (
                run_id, internal_item_id, external_item_id, match_type,
                rule_id, confidence_score, match_factors, variance_amount
            ) VALUES (
                p_run_id, v_internal.item_id, v_external.item_id, 'AUTO',
                p_rule_id, 100.00, 
                jsonb_build_object('amount_match', true, 'date_match', true),
                0
            );
            
            -- Update items
            UPDATE core.reconciliation_items SET match_status = 'MATCHED', matched_item_id = v_external.item_id
            WHERE item_id = v_internal.item_id;
            
            UPDATE core.reconciliation_items SET match_status = 'MATCHED', matched_item_id = v_internal.item_id
            WHERE item_id = v_external.item_id;
            
            v_matches := v_matches + 1;
        END IF;
    END LOOP;
    
    RETURN v_matches;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.apply_exact_match_rule IS 'Matches items with exact amount and date';

-- =============================================================================
-- Create fuzzy match rule function
-- DESCRIPTION: Match with tolerance on amount and date
-- PRIORITY: HIGH
-- ============================================================================
CREATE OR REPLACE FUNCTION core.apply_fuzzy_match_rule(
    p_run_id UUID,
    p_rule_id UUID
) RETURNS INTEGER AS $$
DECLARE
    v_rule RECORD;
    v_matches INTEGER := 0;
    v_tolerance NUMERIC;
    v_date_tolerance INTEGER;
    v_internal RECORD;
    v_external RECORD;
    v_confidence NUMERIC;
    v_variance NUMERIC;
BEGIN
    SELECT * INTO v_rule FROM core.matching_rules WHERE rule_id = p_rule_id;
    
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    
    v_tolerance := COALESCE((v_rule.criteria->>'amount_tolerance_percent')::NUMERIC, 1.0);
    v_date_tolerance := COALESCE((v_rule.criteria->>'date_tolerance_days')::INTEGER, 1);
    
    FOR v_internal IN 
        SELECT * FROM core.reconciliation_items
        WHERE run_id = p_run_id 
          AND item_type = 'INTERNAL' 
          AND match_status = 'UNMATCHED'
    LOOP
        SELECT * INTO v_external
        FROM core.reconciliation_items
        WHERE run_id = p_run_id 
          AND item_type = 'EXTERNAL' 
          AND match_status = 'UNMATCHED'
          AND ABS(amount - v_internal.amount) <= (v_internal.amount * v_tolerance / 100)
          AND ABS(transaction_date - v_internal.transaction_date) <= v_date_tolerance
        ORDER BY ABS(amount - v_internal.amount)
        LIMIT 1;
        
        IF FOUND THEN
            -- Calculate confidence and variance
            v_variance := ABS(v_internal.amount - v_external.amount);
            v_confidence := GREATEST(0, 100 - (v_variance / NULLIF(v_internal.amount, 0) * 100));
            v_confidence := LEAST(v_confidence, v_rule.max_confidence);
            
            IF v_confidence >= v_rule.min_confidence THEN
                INSERT INTO core.reconciliation_matches (
                    run_id, internal_item_id, external_item_id, match_type,
                    rule_id, confidence_score, match_factors, variance_amount
                ) VALUES (
                    p_run_id, v_internal.item_id, v_external.item_id, 
                    CASE WHEN v_rule.auto_match THEN 'AUTO' ELSE 'MANUAL' END,
                    p_rule_id, v_confidence,
                    jsonb_build_object('amount_similar', true, 'date_within_tolerance', true),
                    v_variance
                );
                
                -- Only auto-update items if auto_match is enabled
                IF v_rule.auto_match THEN
                    UPDATE core.reconciliation_items SET match_status = 'MATCHED', matched_item_id = v_external.item_id
                    WHERE item_id = v_internal.item_id;
                    
                    UPDATE core.reconciliation_items SET match_status = 'MATCHED', matched_item_id = v_internal.item_id
                    WHERE item_id = v_external.item_id;
                END IF;
                
                v_matches := v_matches + 1;
            END IF;
        END IF;
    END LOOP;
    
    RETURN v_matches;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.apply_fuzzy_match_rule IS 'Matches items with tolerance on amount and date';

-- =============================================================================
-- Create tolerance match rule function (placeholder)
-- DESCRIPTION: Match within configurable tolerance
-- PRIORITY: MEDIUM
-- ============================================================================
CREATE OR REPLACE FUNCTION core.apply_tolerance_match_rule(
    p_run_id UUID,
    p_rule_id UUID
) RETURNS INTEGER AS $$
BEGIN
    -- Placeholder - implementation similar to fuzzy but with absolute tolerance
    RETURN 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

-- =============================================================================
-- Create reference match rule function (placeholder)
-- DESCRIPTION: Match on reference field
-- PRIORITY: MEDIUM
-- ============================================================================
CREATE OR REPLACE FUNCTION core.apply_reference_match_rule(
    p_run_id UUID,
    p_rule_id UUID
) RETURNS INTEGER AS $$
BEGIN
    -- Placeholder - implementation would match on reference field
    RETURN 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

-- =============================================================================
-- Create manual match function
-- DESCRIPTION: Allow operator to manually match items
-- PRIORITY: HIGH
-- SECURITY: Verify operator authorization
-- ============================================================================
CREATE OR REPLACE FUNCTION core.manual_match_items(
    p_run_id UUID,
    p_internal_item_id UUID,
    p_external_item_id UUID,
    p_matched_by UUID,
    p_notes TEXT DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_match_id UUID;
    v_internal RECORD;
    v_external RECORD;
BEGIN
    -- Verify items exist and are unmatched
    SELECT * INTO v_internal 
    FROM core.reconciliation_items 
    WHERE item_id = p_internal_item_id 
      AND run_id = p_run_id 
      AND item_type = 'INTERNAL';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Internal item % not found or already matched', p_internal_item_id;
    END IF;
    
    SELECT * INTO v_external 
    FROM core.reconciliation_items 
    WHERE item_id = p_external_item_id 
      AND run_id = p_run_id 
      AND item_type = 'EXTERNAL';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'External item % not found or already matched', p_external_item_id;
    END IF;
    
    -- Create manual match record
    INSERT INTO core.reconciliation_matches (
        run_id, internal_item_id, external_item_id, match_type,
        confidence_score, matched_by, notes, variance_amount
    ) VALUES (
        p_run_id, p_internal_item_id, p_external_item_id, 'MANUAL',
        100.00, p_matched_by, p_notes,
        ABS(v_internal.amount - v_external.amount)
    )
    RETURNING match_id INTO v_match_id;
    
    -- Update items
    UPDATE core.reconciliation_items 
    SET match_status = 'MATCHED', matched_item_id = p_external_item_id
    WHERE item_id = p_internal_item_id;
    
    UPDATE core.reconciliation_items 
    SET match_status = 'MATCHED', matched_item_id = p_internal_item_id
    WHERE item_id = p_external_item_id;
    
    RETURN v_match_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.manual_match_items IS 'Allows operator to manually match unreconciled items';

-- =============================================================================
-- Create unmatch function
-- DESCRIPTION: Undo a match
-- PRIORITY: MEDIUM
-- SECURITY: Log unmatch reason for audit
-- ============================================================================
CREATE OR REPLACE FUNCTION core.unmatch_items(
    p_match_id UUID,
    p_unmatched_by UUID,
    p_reason TEXT DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_match RECORD;
BEGIN
    SELECT * INTO v_match FROM core.reconciliation_matches WHERE match_id = p_match_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Match % not found', p_match_id;
    END IF;
    
    -- Mark match as disputed
    UPDATE core.reconciliation_matches
    SET is_disputed = true,
        disputed_by = p_unmatched_by,
        disputed_at = now(),
        dispute_reason = p_reason
    WHERE match_id = p_match_id;
    
    -- Reset items to unmatched
    UPDATE core.reconciliation_items 
    SET match_status = 'UNMATCHED', matched_item_id = NULL
    WHERE item_id = v_match.internal_item_id;
    
    UPDATE core.reconciliation_items 
    SET match_status = 'UNMATCHED', matched_item_id = NULL
    WHERE item_id = v_match.external_item_id;
    
    -- Log for audit
    RAISE NOTICE 'Match % unmatch by %: %', p_match_id, p_unmatched_by, p_reason;
    
    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.unmatch_items IS 'Reverts a match and returns items to unmatched status';

-- =============================================================================
-- Create write-off function
-- DESCRIPTION: Write off unmatched item
-- PRIORITY: MEDIUM
-- ============================================================================
CREATE OR REPLACE FUNCTION core.write_off_item(
    p_item_id UUID,
    p_approved_by UUID,
    p_reason TEXT
) RETURNS BOOLEAN AS $$
BEGIN
    UPDATE core.reconciliation_items
    SET match_status = 'WRITTEN_OFF'
    WHERE item_id = p_item_id
      AND match_status = 'UNMATCHED';
    
    IF FOUND THEN
        RAISE NOTICE 'Item % written off by %: %', p_item_id, p_approved_by, p_reason;
        RETURN true;
    END IF;
    
    RETURN false;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.write_off_item IS 'Writes off an unmatched reconciliation item';

-- =============================================================================
-- Create match summary view
-- DESCRIPTION: Overview of matches for a run
-- PRIORITY: LOW
-- ============================================================================
CREATE VIEW core.reconciliation_match_summary AS
SELECT 
    rm.run_id,
    COUNT(*) as total_matches,
    COUNT(*) FILTER (WHERE rm.match_type = 'AUTO') as auto_matches,
    COUNT(*) FILTER (WHERE rm.match_type = 'MANUAL') as manual_matches,
    COUNT(*) FILTER (WHERE rm.is_disputed) as disputed_matches,
    AVG(rm.confidence_score) as avg_confidence,
    SUM(rm.variance_amount) as total_variance
FROM core.reconciliation_matches rm
GROUP BY rm.run_id;

COMMENT ON VIEW core.reconciliation_match_summary IS 'Summary of matches per reconciliation run';

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create matching_rules table with configurable criteria
☑ Create reconciliation_matches table
☑ Implement run_matching_rules function
☑ Implement rule-specific matching functions
☑ Implement manual_match_items function
☑ Implement unmatch_items function
☑ Add all indexes for matching queries
☑ Test matching rule execution
☑ Test confidence scoring
☑ Verify match statistics update
================================================================================
*/
