/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - RETENTION POLICIES
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-012
 * Feature Name:       Data Retention Management
 * Description:        Data retention policy definitions for regulatory
 *                     compliance, storage management, and automated archival.
 *                     Supports differentiated retention by data classification.
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
 *   - Control A.5.33: Protection of records
 *   - Control A.5.34: Privacy and protection of PII
 *   - Control A.8.14: Information deletion
 *   - Control A.8.15: Information backup
 * 
 * ISO/IEC 27018:2019 (PII Protection)
 *   - Section 10: Storage limitation
 *   - Section 12: Disclosure to third parties
 * 
 * GDPR
 *   - Article 5(1)(e): Storage limitation principle
 *   - Article 17: Right to erasure
 * 
 * SOX
 *   - Records retention requirements
 * 
 * =============================================================================
 * RBAC ENFORCEMENT DOCUMENTATION
 * =============================================================================
 * 
 * REQUIRED PERMISSIONS:
 * 
 * | Operation                    | Required Permission              |
 * |------------------------------|----------------------------------|
 * | CREATE policy                | app:retention:create             |
 * | READ policy                  | app:retention:read               |
 * | UPDATE policy                | app:retention:update             |
 * | EXECUTE evaluation           | app:retention:execute            |
 * | BYPASS retention             | platform:admin:retention         |
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
-- TABLE: app.t_retention_policies
-- =============================================================================
CREATE TABLE IF NOT EXISTS app.t_retention_policies (
    policy_id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    app_id                      UUID NOT NULL,
                                CONSTRAINT fk_policy_app 
                                    FOREIGN KEY (app_id) 
                                    REFERENCES app.t_application_registry(app_id)
                                    ON DELETE CASCADE,
    
    policy_code                 VARCHAR(50) NOT NULL,
    
    -- Classification
    policy_type                 VARCHAR(30) NOT NULL DEFAULT 'standard',
                                CONSTRAINT chk_policy_type 
                                    CHECK (policy_type IN ('standard', 'regulatory', 'legal', 'operational', 'custom')),
    data_classification         VARCHAR(30) NOT NULL,
                                CONSTRAINT chk_data_class 
                                    CHECK (data_classification IN ('public', 'internal', 'confidential', 'restricted', 'critical')),
    
    -- Target
    target_entity_type          VARCHAR(50) NOT NULL,
    target_data_criteria        JSONB DEFAULT '{}',
    
    -- Retention Periods
    retention_period_years      INTEGER NOT NULL,
    retention_period_months     INTEGER DEFAULT 0,
    retention_period_days       INTEGER DEFAULT 0,
    total_retention_days        INTEGER GENERATED ALWAYS AS (
        (retention_period_years * 365) + (retention_period_months * 30) + retention_period_days
    ) STORED,
    
    -- Actions
    retention_action            VARCHAR(30) NOT NULL DEFAULT 'archive',
                                CONSTRAINT chk_retention_action 
                                    CHECK (retention_action IN ('archive', 'delete', 'anonymize', 'review')),
    post_retention_action       VARCHAR(30),
    
    -- Archival
    archive_destination         VARCHAR(50),
    archive_encryption_required BOOLEAN NOT NULL DEFAULT TRUE,
    archive_verification_required BOOLEAN NOT NULL DEFAULT TRUE,
    archive_retention_years     INTEGER,
    
    -- Legal & Compliance
    regulatory_framework        VARCHAR(50),
                                -- e.g., 'GDPR', 'SOX', 'PCI-DSS', 'HIPAA'
    legal_basis                 TEXT,
    dsr_applicable              BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Automation
    auto_evaluate               BOOLEAN NOT NULL DEFAULT TRUE,
    evaluation_frequency        VARCHAR(20) DEFAULT 'daily',
    evaluation_schedule         VARCHAR(100),
                                -- Cron expression
    notify_before_days          INTEGER DEFAULT 30,
    
    -- Status
    status                      VARCHAR(20) NOT NULL DEFAULT 'active',
                                CONSTRAINT chk_policy_status 
                                    CHECK (status IN ('draft', 'active', 'suspended', 'deprecated')),
    
    -- Audit
    version                     INTEGER NOT NULL DEFAULT 1  -- [AUDIT] ISO 9001: Optimistic locking for version control,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()  -- [AUDIT] ISO 27001: Non-repudiation timestamp,
    created_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    
    CONSTRAINT chk_positive_retention 
        CHECK (retention_period_years >= 0 AND retention_period_months >= 0 AND retention_period_days >= 0),
    CONSTRAINT uq_app_policy_code UNIQUE (app_id, policy_code)
);

-- =============================================================================
-- TABLE: app.t_retention_evaluations
-- =============================================================================
CREATE TABLE IF NOT EXISTS app.t_retention_evaluations (
    evaluation_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    policy_id                   UUID NOT NULL,
                                CONSTRAINT fk_eval_policy 
                                    FOREIGN KEY (policy_id) 
                                    REFERENCES app.t_retention_policies(policy_id)
                                    ON DELETE CASCADE,
    
    evaluation_date             DATE NOT NULL,
    records_evaluated           BIGINT NOT NULL DEFAULT 0,
    records_archived            BIGINT NOT NULL DEFAULT 0,
    records_deleted             BIGINT NOT NULL DEFAULT 0,
    records_held                BIGINT NOT NULL DEFAULT 0,
                                -- Records on legal hold
    errors_encountered          INTEGER DEFAULT 0,
    evaluation_status           VARCHAR(20) NOT NULL DEFAULT 'in_progress',
                                CONSTRAINT chk_eval_status 
                                    CHECK (evaluation_status IN ('in_progress', 'completed', 'failed', 'partial')),
    
    started_at                  TIMESTAMPTZ,
    completed_at                TIMESTAMPTZ
);

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON TABLE app.t_retention_policies IS 
    'Data retention policies for compliance and storage management. ' ||
    'Feature: CORE-APP-012. ' ||
    'Compliance: GDPR Article 5, ISO 27001 A.5.33. ' ||
    'Supports automated evaluation and legal hold integration.';

-- =============================================================================
-- INDEXES
-- =============================================================================
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_retention_app 
    ON app.t_retention_policies(app_id);

CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_retention_target 
    ON app.t_retention_policies(target_entity_type);

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Retention policies support regulatory frameworks
-- 2. Legal holds take precedence over retention
-- 3. Automated evaluation with configurable frequency
-- 4. Actions: archive, delete, anonymize, review
-- 5. Notifications before retention action
-- =============================================================================
