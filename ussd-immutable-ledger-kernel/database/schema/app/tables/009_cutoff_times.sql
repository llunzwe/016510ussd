/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - CUTOFF TIMES
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-010
 * Feature Name:       Transaction Cutoff Management
 * Description:        Transaction cutoff time definitions for end-of-day
 *                     processing, settlement deadlines, and batch scheduling.
 *                     Supports timezone-aware cutoffs and multiple profiles.
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
 *   - Control A.5.31: Legal, statutory, regulatory requirements
 *   - Control A.8.1: User endpoint devices (timezone handling)
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
 * | CREATE cutoff                | app:cutoff:create                |
 * | READ cutoff                  | app:cutoff:read                  |
 * | UPDATE cutoff                | app:cutoff:update                |
 * | CREATE override              | app:cutoff:override              |
 * | APPROVE override             | app:cutoff:admin                 |
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - app.t_application_registry (FK: app_id)
 *   - app.t_business_calendar (FK: calendar_id)
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
-- TABLE: app.t_cutoff_times
-- =============================================================================
CREATE TABLE IF NOT EXISTS app.t_cutoff_times (
    cutoff_id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    app_id                      UUID NOT NULL,
                                CONSTRAINT fk_cutoff_app 
                                    FOREIGN KEY (app_id) 
                                    REFERENCES app.t_application_registry(app_id)
                                    ON DELETE CASCADE,
    
    cutoff_code                 VARCHAR(50) NOT NULL,
    
    -- Classification
    cutoff_type                 VARCHAR(30) NOT NULL,
                                CONSTRAINT chk_cutoff_type 
                                    CHECK (cutoff_type IN ('eod', 'settlement', 'reporting', 'batch', 'custom')),
    cutoff_subtype              VARCHAR(50),
    
    -- Time Configuration
    cutoff_time                 TIME NOT NULL,
    timezone                    VARCHAR(50) NOT NULL,
                                -- IANA timezone identifier
    effective_days              SMALLINT[] NOT NULL DEFAULT '{1,2,3,4,5}',
                                -- ISO day numbers
    
    -- Business Calendar
    calendar_id                 UUID,
                                CONSTRAINT fk_cutoff_calendar 
                                    FOREIGN KEY (calendar_id) 
                                    REFERENCES app.t_business_calendar(calendar_id),
    follow_business_day         BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Grace Period
    grace_period_minutes        INTEGER DEFAULT 0,
    grace_period_policy         VARCHAR(20) DEFAULT 'strict',
                                CONSTRAINT chk_grace_policy 
                                    CHECK (grace_period_policy IN ('strict', 'flexible', 'approval_required')),
    
    -- Rollover
    rollover_policy             VARCHAR(20) NOT NULL DEFAULT 'next_business_day',
                                CONSTRAINT chk_rollover_policy 
                                    CHECK (rollover_policy IN ('same_day', 'next_business_day', 'next_calendar_day')),
    rollover_time               TIME,
    
    -- Notifications
    warning_minutes_before      INTEGER[] DEFAULT '{30, 10, 5}',
    notification_channels       JSONB DEFAULT '["in_app", "email"]',
    
    -- Default
    is_default                  BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Validity
    effective_from              DATE NOT NULL DEFAULT CURRENT_DATE,
    effective_until             DATE,
    
    -- Audit
    version                     INTEGER NOT NULL DEFAULT 1  -- [AUDIT] ISO 9001: Optimistic locking for version control,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()  -- [AUDIT] ISO 27001: Non-repudiation timestamp,
    created_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    
    CONSTRAINT uq_app_cutoff_code UNIQUE (app_id, cutoff_code)
);

-- =============================================================================
-- TABLE: app.t_cutoff_overrides
-- =============================================================================
CREATE TABLE IF NOT EXISTS app.t_cutoff_overrides (
    override_id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    cutoff_id                   UUID NOT NULL,
                                CONSTRAINT fk_override_cutoff 
                                    FOREIGN KEY (cutoff_id) 
                                    REFERENCES app.t_cutoff_times(cutoff_id)
                                    ON DELETE CASCADE,
    
    override_date               DATE NOT NULL,
    override_time               TIME,
                                -- NULL = no cutoff (always open)
    override_reason             TEXT NOT NULL,
    approved_by                 UUID,
    effective_from              TIMESTAMPTZ,
    effective_until             TIMESTAMPTZ,
    
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()  -- [AUDIT] ISO 27001: Non-repudiation timestamp,
    created_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    
    CONSTRAINT uq_cutoff_date UNIQUE (cutoff_id, override_date)
);

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON TABLE app.t_cutoff_times IS 
    'Transaction cutoff time definitions. ' ||
    'Feature: CORE-APP-010. ' ||
    'Compliance: ISO 27001, ISO 9001. ' ||
    'Supports timezone-aware cutoffs with grace periods and rollover.';

-- =============================================================================
-- INDEXES
-- =============================================================================
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_cutoff_app 
    ON app.t_cutoff_times(app_id);

CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_cutoff_type 
    ON app.t_cutoff_times(app_id, cutoff_type) WHERE is_default = TRUE;

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Cutoff times support multiple timezones
-- 2. Grace periods allow late submissions
-- 3. Rollover policies handle after-cutoff transactions
-- 4. Overrides require approval
-- 5. Notifications at configurable intervals before cutoff
-- =============================================================================
