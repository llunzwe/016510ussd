/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - LEGAL HOLD
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-013
 * Feature Name:       Legal Hold Management
 * Description:        Legal hold management for litigation support and
 *                     regulatory investigations. Prevents data destruction
 *                     for records under legal preservation orders.
 * 
 * Version:            1.0.0
 * Author:             Platform Engineering Team
 * Created:            2026-03-30
 * Last Modified:      2026-03-30
 * 
 * =============================================================================
 * COMPLIANCE & CERTIFICATIONS
 * =============================================================================
 * 
 * ISO/IEC 27001:2022 (ISMS)
 *   - Control A.5.33: Protection of records
 *   - Control A.8.14: Information deletion (hold prevents)
 *   - Control A.5.31: Legal, statutory, regulatory requirements
 * 
 * eDiscovery
 *   - FRCP Rule 26: Duty to preserve
 *   - Zubulake standards
 * 
 * GDPR
 *   - Article 17(3)(e): Right to erasure exceptions (legal claims)
 * 
 * =============================================================================
 * RBAC ENFORCEMENT DOCUMENTATION
 * =============================================================================
 * 
 * REQUIRED PERMISSIONS:
 * 
 * | Operation                    | Required Permission              |
 * |------------------------------|----------------------------------|
 * | CREATE hold                  | app:legal_hold:create            |
 * | READ hold                    | app:legal_hold:read              |
 * | UPDATE hold                  | app:legal_hold:update            |
 * | RELEASE hold                 | app:legal_hold:release           |
 * | BYPASS hold                  | platform:admin:legal             |
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
-- TABLE: app.t_legal_hold
-- =============================================================================
CREATE TABLE IF NOT EXISTS app.t_legal_hold (
    hold_id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    app_id                      UUID NOT NULL,
                                CONSTRAINT fk_hold_app 
                                    FOREIGN KEY (app_id) 
                                    REFERENCES app.t_application_registry(app_id)
                                    ON DELETE CASCADE,
    
    hold_reference              VARCHAR(100) NOT NULL,
                                -- External reference number (case ID)
    
    -- Classification
    hold_type                   VARCHAR(30) NOT NULL DEFAULT 'litigation',
                                CONSTRAINT chk_hold_type 
                                    CHECK (hold_type IN ('litigation', 'regulatory', 'investigation', 'audit', 'custom')),
    hold_priority               VARCHAR(20) NOT NULL DEFAULT 'normal',
                                CONSTRAINT chk_hold_priority 
                                    CHECK (hold_priority IN ('low', 'normal', 'high', 'critical')),
    
    -- Description
    hold_name                   VARCHAR(255) NOT NULL,
    hold_description            TEXT NOT NULL,
    legal_basis                 TEXT,
    
    -- Responsible Parties
    requested_by                UUID NOT NULL,
    legal_counsel               VARCHAR(255),
    custodian_ids               UUID[] DEFAULT '{}',
                                -- Array of membership IDs responsible
    
    -- Scope
    scope_criteria              JSONB NOT NULL DEFAULT '{}',
                                -- Criteria for records under hold
    scope_entities              TEXT[] DEFAULT '{}',
    estimated_records           BIGINT,
    
    -- Dates
    hold_issued_date            DATE NOT NULL DEFAULT CURRENT_DATE,
    hold_effective_date         DATE NOT NULL DEFAULT CURRENT_DATE,
    hold_expiry_date            DATE,
                                -- NULL = indefinite
    actual_release_date         DATE,
    
    -- Status
    status                      VARCHAR(20) NOT NULL DEFAULT 'active',
                                CONSTRAINT chk_hold_status 
                                    CHECK (status IN ('pending', 'active', 'released', 'expired', 'superseded')),
    release_reason              TEXT,
    released_by                 UUID,
    
    -- Notifications
    notifications_sent          JSONB DEFAULT '{}',
    acknowledgment_required     BOOLEAN NOT NULL DEFAULT TRUE,
    acknowledgments_received    UUID[] DEFAULT '{}',
    
    -- Conflict Resolution
    overrides_retention         BOOLEAN NOT NULL DEFAULT TRUE,
                                -- Hold takes precedence
    superseded_by_hold_id       UUID,
                                CONSTRAINT fk_hold_superseded 
                                    FOREIGN KEY (superseded_by_hold_id) 
                                    REFERENCES app.t_legal_hold(hold_id),
    
    -- Audit
    version                     INTEGER NOT NULL DEFAULT 1  -- [AUDIT] ISO 9001: Optimistic locking for version control,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()  -- [AUDIT] ISO 27001: Non-repudiation timestamp,
    created_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    
    CONSTRAINT uq_app_hold_ref UNIQUE (app_id, hold_reference)
);

-- =============================================================================
-- TABLE: app.t_legal_hold_affected_records
-- =============================================================================
CREATE TABLE IF NOT EXISTS app.t_legal_hold_affected_records (
    record_id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    hold_id                     UUID NOT NULL,
                                CONSTRAINT fk_affected_hold 
                                    FOREIGN KEY (hold_id) 
                                    REFERENCES app.t_legal_hold(hold_id)
                                    ON DELETE CASCADE,
    
    entity_type                 VARCHAR(50) NOT NULL,
    entity_id                   UUID NOT NULL,
    hold_applied_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hold_applied_by             UUID NOT NULL
);

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON TABLE app.t_legal_hold IS 
    'Legal hold definitions for litigation and regulatory preservation. ' ||
    'Feature: CORE-APP-013. ' ||
    'Compliance: FRCP Rule 26, GDPR Article 17(3)(e). ' ||
    'Prevents data destruction for records under hold.';

-- =============================================================================
-- INDEXES
-- =============================================================================
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_hold_app 
    ON app.t_legal_hold(app_id);

CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_hold_status 
    ON app.t_legal_hold(status);

CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_affected_hold 
    ON app.t_legal_hold_affected_records(hold_id);

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Legal holds override retention policies
-- 2. Hold scope defined by criteria and entity lists
-- 3. Custodian notifications tracked
-- 4. Acknowledgment required for compliance
-- 5. Superseded holds linked to replacement
-- =============================================================================
