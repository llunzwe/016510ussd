-- =============================================================================
-- USSD KERNEL CORE SCHEMA - BAD DEBT PROVISION
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    027_bad_debt_provision.sql
-- SCHEMA:      ussd_core
-- TABLE:       bad_debt_provision
-- DESCRIPTION: Bad debt provisioning records for accounting compliance
--              with IFRS 9 expected credit loss (ECL) requirements.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Provision monitoring
├── A.18.1 Compliance - IFRS 9 compliance
└── A.18.2 Compliance - Audit trail

IFRS 9 Compliance
├── ECL calculation: Expected credit loss methodology
├── Staging: 3-stage impairment model
├── Forward-looking: Macroeconomic factors
└── Disclosure: Required provision disclosures

Financial Regulations
├── Capital adequacy: Provision impact on capital
├── Regulatory reporting: Provision reporting
├── Audit: Provision methodology audit
└── Stress testing: Provision scenario analysis

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. STAGES (IFRS 9)
   - STAGE_1: 12-month ECL
   - STAGE_2: Lifetime ECL (significant increase in credit risk)
   - STAGE_3: Lifetime ECL (credit impaired)

2. PROVISION TYPES
   - SPECIFIC: Individual asset provision
   - COLLECTIVE: Portfolio-level provision
   - GENERAL: General reserve

3. CALCULATION
   - PD: Probability of default
   - LGD: Loss given default
   - EAD: Exposure at default
   - ECL: Expected credit loss

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

PROVISION SECURITY:
- Immutable provision records
- Calculation audit trail
- Approval workflow for adjustments

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: provision_id
- ACCOUNT: account_id + calculation_date
- DATE: calculation_date
- STAGE: provision_stage

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- PROVISION_CALCULATED
- PROVISION_ADJUSTED
- PROVISION_RELEASED

RETENTION: 7 years
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.bad_debt_provision (
    -- Primary identifier
    provision_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Account/asset reference
    account_id UUID REFERENCES ussd_core.account_registry(account_id),
    portfolio_segment VARCHAR(100),
    
    -- IFRS 9 Stage
    provision_stage VARCHAR(20) NOT NULL
        CHECK (provision_stage IN ('STAGE_1', 'STAGE_2', 'STAGE_3')),
    
    -- Provision type
    provision_type VARCHAR(20) NOT NULL
        CHECK (provision_type IN ('SPECIFIC', 'COLLECTIVE', 'GENERAL')),
    
    -- Calculation inputs
    exposure_amount NUMERIC(20, 8) NOT NULL,
    probability_of_default NUMERIC(10, 6) NOT NULL,
    loss_given_default NUMERIC(10, 6) NOT NULL,
    time_horizon_months INTEGER NOT NULL,
    discount_rate NUMERIC(10, 6),
    
    -- Calculation result
    provision_amount NUMERIC(20, 8) NOT NULL,
    provision_percentage NUMERIC(10, 6),
    
    -- Calculation context
    calculation_date DATE NOT NULL,
    calculation_method VARCHAR(50),
    macroeconomic_scenario VARCHAR(50),
    
    -- Status
    is_adjusted BOOLEAN DEFAULT FALSE,
    adjustment_reason TEXT,
    
    -- COA posting
    posted_to_coa BOOLEAN DEFAULT FALSE,
    posting_reference VARCHAR(100),
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
