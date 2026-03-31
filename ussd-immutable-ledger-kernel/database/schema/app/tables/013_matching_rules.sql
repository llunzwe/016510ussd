/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - MATCHING RULES
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-014
 * Feature Name:       Transaction Matching Rules
 * Description:        Transaction matching and reconciliation rules for
 *                     automated matching of entries, payments, and settlements.
 *                     Supports tolerance matching and rule priorities.
 * 
 * Version:            1.0.0
 * Author:             Eng. llunzwe
 * Created:            2026-03-30
 * Last Modified:      2026-03-30
 * 
 * =============================================================================
 * COMPLIANCE & CERTIFICATIONS
 * =============================================================================
 * 
 * ISO/IEC 27001:2022 (ISMS)
 *   - Control A.5.28: Collection of evidence
 *   - Control A.8.1: User endpoint devices
 * 
 * ISO 9001:2015 (Quality Management)
 *   - Section 8.5.1: Production and service provision control
 * 
 * =============================================================================
 * RBAC ENFORCEMENT DOCUMENTATION
 * =============================================================================
 * 
 * REQUIRED PERMISSIONS:
 * 
 * | Operation                    | Required Permission              |
 * |------------------------------|----------------------------------|
 * | CREATE rule                  | app:matching:create              |
 * | READ rule                    | app:matching:read                |
 * | UPDATE rule                  | app:matching:update              |
 * | EXECUTE matching             | app:matching:execute             |
 * | CONFIRM match                | app:matching:confirm             |
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - app.t_application_registry (FK: app_id)
 * 
 * CHANGE LOG:
 *   1.0.0 - Initial schema creation
 * =============================================================================
 */



-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Controls A.5.x - A.9.x)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Multi-tenancy)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds
-- ISO 9001:2015 - Quality Management Systems
-- ISO 31000:2018 - Risk Management Guidelines
-- ============================================================================
-- CODING PRACTICES:
-- - Use parameterized queries to prevent SQL injection
-- - Implement proper error handling with transaction rollback
-- - Use SECURITY DEFINER
-- - Enforce RLS policies for multi-tenant data isolation
-- - Use explicit column lists (avoid SELECT *)
-- - Add audit logging for all security-relevant operations
-- - Use UUIDs for primary identifiers to prevent enumeration
-- - Implement optimistic locking with version columns
-- - Use TIMESTAMPTZ for all timestamp columns
-- - Validate all inputs with CHECK constraints
-- ============================================================================

-- =============================================================================
-- TABLE: app.t_matching_rules
-- =============================================================================
CREATE TABLE IF NOT EXISTS app.t_matching_rules (
    rule_id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    app_id                      UUID NOT NULL,
                                CONSTRAINT fk_match_rule_app 
                                    FOREIGN KEY (app_id) 
                                    REFERENCES app.t_application_registry(app_id)
                                    ON DELETE CASCADE,
    
    rule_code                   VARCHAR(50) NOT NULL,
    
    -- Classification
    rule_type                   VARCHAR(30) NOT NULL DEFAULT 'exact',
                                CONSTRAINT chk_match_rule_type 
                                    CHECK (rule_type IN ('exact', 'tolerance', 'fuzzy', 'manual', 'ml')),
    matching_category           VARCHAR(30) NOT NULL DEFAULT 'payment',
                                -- ENUM: 'payment', 'settlement', 'reconciliation', 'dispute'
    
    -- Entities
    source_entity_type          VARCHAR(50) NOT NULL,
    target_entity_type          VARCHAR(50) NOT NULL,
    bidirectional               BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Match Criteria
    match_criteria              JSONB NOT NULL DEFAULT '{}',
    
    -- Tolerance
    tolerance_absolute          NUMERIC(19,4) DEFAULT 0,
    tolerance_percentage        NUMERIC(5,2) DEFAULT 0,
                                CONSTRAINT chk_tolerance_pct 
                                    CHECK (tolerance_percentage >= 0 AND tolerance_percentage <= 100),
    tolerance_currency          VARCHAR(3),
    
    -- Date Tolerance
    date_tolerance_days         INTEGER DEFAULT 0,
    date_business_days_only     BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Scoring
    minimum_match_score         NUMERIC(5,2) DEFAULT 100.00,
                                CONSTRAINT chk_match_scores 
                                    CHECK (minimum_match_score >= 0 AND minimum_match_score <= 100),
    scoring_weights             JSONB DEFAULT '{}',
    
    -- Actions
    auto_match_enabled          BOOLEAN NOT NULL DEFAULT FALSE,
    auto_match_threshold        NUMERIC(5,2) DEFAULT 100.00,
    manual_review_threshold     NUMERIC(5,2) DEFAULT 80.00,
    on_match_action             JSONB DEFAULT '{}',
    on_mismatch_action          JSONB DEFAULT '{}',
    
    -- Execution
    execution_order             INTEGER NOT NULL DEFAULT 100,
    execution_schedule          VARCHAR(50),
    
    -- Status
    status                      VARCHAR(20) NOT NULL DEFAULT 'active',
                                CONSTRAINT chk_match_rule_status 
                                    CHECK (status IN ('draft', 'active', 'paused', 'deprecated')),
    
    -- Audit
    version                     INTEGER NOT NULL DEFAULT 1  -- [AUDIT] ISO 9001: Optimistic locking for version control,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()  -- [AUDIT] ISO 27001: Non-repudiation timestamp,
    created_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    
    CONSTRAINT uq_app_match_rule_code UNIQUE (app_id, rule_code)
);

-- =============================================================================
-- TABLE: app.t_matching_results
-- =============================================================================
CREATE TABLE IF NOT EXISTS app.t_matching_results (
    match_id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    rule_id                     UUID NOT NULL,
                                CONSTRAINT fk_match_result_rule 
                                    FOREIGN KEY (rule_id) 
                                    REFERENCES app.t_matching_rules(rule_id)
                                    ON DELETE CASCADE,
    
    source_entity_id            UUID NOT NULL,
    target_entity_id            UUID NOT NULL,
    match_score                 NUMERIC(5,2) NOT NULL,
    match_status                VARCHAR(20) NOT NULL,
                                -- ENUM: 'suggested', 'auto_matched', 'confirmed', 'rejected'
    matched_at                  TIMESTAMPTZ,
    matched_by                  UUID,
    match_evidence              JSONB DEFAULT '{}',
    
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()  -- [AUDIT] ISO 27001: Non-repudiation timestamp
);

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON TABLE app.t_matching_rules IS 
    'Transaction matching and reconciliation rules. ' ||
    'Feature: CORE-APP-014. ' ||
    'Supports exact, tolerance, and fuzzy matching.';

-- =============================================================================
-- INDEXES
-- =============================================================================
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_match_rule_app 
    ON app.t_matching_rules(app_id);

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Matching rules support multiple algorithms
-- 2. Tolerance matching for amount/date variance
-- 3. Fuzzy/ML matching for non-exact data
-- 4. Auto-match with confidence thresholds
-- 5. Manual review queue for uncertain matches
-- =============================================================================
