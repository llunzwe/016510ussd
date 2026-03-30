/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - FISCAL PERIODS
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-009
 * Feature Name:       Fiscal Period Management
 * Description:        Fiscal year and period definitions for financial
 *                     reporting, accounting closes, and regulatory compliance.
 *                     Supports multiple fiscal calendars and adjustment periods.
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
 *   - Control A.8.1: User endpoint devices
 * 
 * ISO 9001:2015 (Quality Management)
 *   - Section 8.5.1: Production and service provision control
 * 
 * SOX Compliance
 *   - Period-end close controls
 *   - Audit trail for period changes
 * 
 * =============================================================================
 * RBAC ENFORCEMENT DOCUMENTATION
 * =============================================================================
 * 
 * REQUIRED PERMISSIONS:
 * 
 * | Operation                    | Required Permission              |
 * |------------------------------|----------------------------------|
 * | CREATE period                | app:period:create                |
 * | READ period                  | app:period:read                  |
 * | UPDATE period                | app:period:update                |
 * | INITIATE close               | app:period:close                 |
 * | LOCK period                  | app:period:lock                  |
 * | REOPEN period                | app:period:admin                 |
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
-- TABLE: app.t_fiscal_periods
-- =============================================================================
CREATE TABLE IF NOT EXISTS app.t_fiscal_periods (
    period_id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    app_id                      UUID NOT NULL,
                                CONSTRAINT fk_period_app 
                                    FOREIGN KEY (app_id) 
                                    REFERENCES app.t_application_registry(app_id)
                                    ON DELETE CASCADE,
    
    period_code                 VARCHAR(20) NOT NULL,
                                -- Format: FY2026-Q1, FY2026-M01, etc.
    
    -- Hierarchy
    fiscal_year                 INTEGER NOT NULL,
    period_number               INTEGER NOT NULL,
                                -- 1-12 for months, 1-4 for quarters
    period_type                 VARCHAR(20) NOT NULL DEFAULT 'month',
                                CONSTRAINT chk_period_type 
                                    CHECK (period_type IN ('year', 'quarter', 'month', 'week', 'adjustment')),
    parent_period_id            UUID,
                                -- FK to self (e.g., quarter contains months)
                                CONSTRAINT fk_period_parent 
                                    FOREIGN KEY (parent_period_id) 
                                    REFERENCES app.t_fiscal_periods(period_id),
    
    -- Date Range
    period_start_date           DATE NOT NULL,
    period_end_date             DATE NOT NULL,
    calendar_id                 UUID,
                                CONSTRAINT fk_period_calendar 
                                    FOREIGN KEY (calendar_id) 
                                    REFERENCES app.t_business_calendar(calendar_id),
    business_days_in_period     INTEGER,
    
    -- Status & Control
    status                      VARCHAR(20) NOT NULL DEFAULT 'open',
                                CONSTRAINT chk_period_status 
                                    CHECK (status IN ('future', 'open', 'closing', 'closed', 'locked', 'reopened')),
    is_adjustment_period        BOOLEAN NOT NULL DEFAULT FALSE,
    adjustment_for_period_id    UUID,
                                CONSTRAINT fk_period_adjustment 
                                    FOREIGN KEY (adjustment_for_period_id) 
                                    REFERENCES app.t_fiscal_periods(period_id),
    
    -- Close Process
    opened_at                   TIMESTAMPTZ,
    opened_by                   UUID,
    closing_started_at          TIMESTAMPTZ,
    closing_started_by          UUID,
    closed_at                   TIMESTAMPTZ,
    closed_by                   UUID,
    locked_at                   TIMESTAMPTZ,
    locked_by                   UUID,
    reopen_reason               TEXT,
    
    -- Budget & Comparison
    prior_year_period_id        UUID,
                                CONSTRAINT fk_period_prior_year 
                                    FOREIGN KEY (prior_year_period_id) 
                                    REFERENCES app.t_fiscal_periods(period_id),
    budget_reference            VARCHAR(100),
    
    -- Audit
    version                     INTEGER NOT NULL DEFAULT 1  -- [AUDIT] ISO 9001: Optimistic locking for version control,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()  -- [AUDIT] ISO 27001: Non-repudiation timestamp,
    created_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    
    CONSTRAINT chk_date_range CHECK (period_end_date > period_start_date),
    CONSTRAINT uq_app_fy_period UNIQUE (app_id, fiscal_year, period_type, period_number)
);

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON TABLE app.t_fiscal_periods IS 
    'Fiscal periods for accounting closes and financial reporting. ' ||
    'Feature: CORE-APP-009. ' ||
    'Compliance: SOX, ISO 9001. ' ||
    'Status: future -> open -> closing -> closed -> locked';

-- =============================================================================
-- INDEXES
-- =============================================================================
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_period_app 
    ON app.t_fiscal_periods(app_id);

CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_period_status 
    ON app.t_fiscal_periods(status);

CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_period_dates 
    ON app.t_fiscal_periods(period_start_date, period_end_date);

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Period status workflow: future -> open -> closing -> closed -> locked
-- 2. Locked periods require admin to reopen
-- 3. Adjustment periods for year-end corrections
-- 4. Parent-child relationship for period hierarchy
-- 5. All close operations audited
-- =============================================================================
