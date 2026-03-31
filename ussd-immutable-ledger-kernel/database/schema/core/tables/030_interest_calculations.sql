-- =============================================================================
-- USSD KERNEL CORE SCHEMA - INTEREST CALCULATIONS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    030_interest_calculations.sql
-- SCHEMA:      ussd_core
-- TABLE:       interest_calculations
-- DESCRIPTION: Framework for interest accrual and calculation supporting
--              multiple interest types and calculation methods.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Interest calculation monitoring
├── A.18.1 Compliance - Financial calculation accuracy
└── A.18.2 Compliance - Audit trail for interest

Financial Regulations
├── IFRS 9: Effective interest rate methodology
├── Accrual accounting: Daily/monthly accrual requirements
├── Disclosure: Interest income/expense reporting
└── Tax: Interest withholding tax calculations

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. INTEREST TYPES
   - SIMPLE: Interest on principal only
   - COMPOUND: Interest on principal + accumulated interest
   - FLAT: Fixed amount regardless of balance
   - TIERED: Different rates for balance bands
   - PENALTY: Late payment/overdue interest

2. CALCULATION METHODS
   - ACTUAL_360: Actual days, 360-day year
   - ACTUAL_365: Actual days, 365-day year
   - ACTUAL_ACTUAL: Actual days, actual year days
   - 30_360: 30-day month, 360-day year
   - EURO_360: European 30/360 variant

3. ACCRUAL FREQUENCY
   - DAILY: Daily accrual
   - MONTHLY: Monthly accrual
   - QUARTERLY: Quarterly accrual
   - ANNUAL: Annual accrual

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

INTEREST SECURITY:
- Immutable calculation records
- Audit trail for rate changes
- Approval workflow for manual adjustments

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: calculation_id
- ACCOUNT: account_id + calculation_date
- PERIOD: period_start + period_end
- STATUS: posting_status

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- INTEREST_CALCULATED
- INTEREST_POSTED
- INTEREST_ADJUSTED
- RATE_CHANGED

RETENTION: 7 years
================================================================================
*/

-- -----------------------------------------------------------------------------
-- CREATE TABLE: interest_rates
-- -----------------------------------------------------------------------------
CREATE TABLE core.interest_rates (
    -- Primary identifier
    rate_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rate_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Rate classification
    rate_type VARCHAR(20) NOT NULL
        CHECK (rate_type IN ('LENDING', 'SAVINGS', 'OVERDUE', 'PENALTY', 'COMMISSION')),
    rate_subtype VARCHAR(50),
    
    -- Rate details
    base_rate NUMERIC(10, 6) NOT NULL CHECK (base_rate >= 0),
    spread NUMERIC(10, 6) DEFAULT 0 CHECK (spread >= 0),
    total_rate NUMERIC(10, 6) GENERATED ALWAYS AS (base_rate + spread) STORED,
    
    -- Tiered rate support
    is_tiered BOOLEAN DEFAULT FALSE,
    tier_minimum NUMERIC(20, 8),
    tier_maximum NUMERIC(20, 8),
    
    -- Calculation parameters
    calculation_method VARCHAR(20) NOT NULL DEFAULT 'ACTUAL_365'
        CHECK (calculation_method IN ('ACTUAL_360', 'ACTUAL_365', 'ACTUAL_ACTUAL', '30_360', 'EURO_360')),
    compounding_frequency VARCHAR(20) DEFAULT 'NONE'
        CHECK (compounding_frequency IN ('NONE', 'DAILY', 'MONTHLY', 'QUARTERLY', 'ANNUAL')),
    accrual_frequency VARCHAR(20) NOT NULL DEFAULT 'DAILY'
        CHECK (accrual_frequency IN ('DAILY', 'MONTHLY', 'QUARTERLY', 'ANNUAL')),
    
    -- Application scope
    application_id UUID,  -- NULL for system-wide rates
    
    -- Effective period
    effective_from DATE NOT NULL DEFAULT CURRENT_DATE,
    effective_until DATE,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    superseded_by UUID REFERENCES core.interest_rates(rate_id),
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- -----------------------------------------------------------------------------
-- INDEXES
-- -----------------------------------------------------------------------------
-- Rate lookups
CREATE INDEX idx_interest_rates_type 
    ON core.interest_rates(rate_type, is_active);

-- Effective date queries
CREATE INDEX idx_interest_rates_effective 
    ON core.interest_rates(effective_from, effective_until) 
    WHERE is_active = TRUE;

-- Tiered rate lookups
CREATE INDEX idx_interest_rates_tier 
    ON core.interest_rates(is_tiered, tier_minimum, tier_maximum) 
    WHERE is_tiered = TRUE;

-- Application-scoped
CREATE INDEX idx_interest_rates_app 
    ON core.interest_rates(application_id, rate_type) 
    WHERE application_id IS NOT NULL;

-- -----------------------------------------------------------------------------
-- CREATE TABLE: interest_calculations
-- -----------------------------------------------------------------------------
CREATE TABLE core.interest_calculations (
    -- Primary identifier
    calculation_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    calculation_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Account reference
    account_id UUID NOT NULL REFERENCES core.account_registry(account_id) ON DELETE RESTRICT,
    
    -- Rate reference
    rate_id UUID REFERENCES core.interest_rates(rate_id),
    applied_rate NUMERIC(10, 6) NOT NULL CHECK (applied_rate >= 0),
    
    -- Calculation period
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    days_in_period INTEGER NOT NULL CHECK (days_in_period > 0),
    year_basis INTEGER NOT NULL CHECK (year_basis IN (360, 365, 366)),
    
    -- Balance information
    opening_balance NUMERIC(20, 8) NOT NULL,
    closing_balance NUMERIC(20, 8) NOT NULL,
    average_balance NUMERIC(20, 8),
    
    -- Calculation details
    interest_type VARCHAR(20) NOT NULL
        CHECK (interest_type IN ('SIMPLE', 'COMPOUND', 'FLAT', 'TIERED', 'PENALTY')),
    calculation_method VARCHAR(20) NOT NULL
        CHECK (calculation_method IN ('ACTUAL_360', 'ACTUAL_365', 'ACTUAL_ACTUAL', '30_360', 'EURO_360')),
    
    -- Calculated amounts
    gross_interest NUMERIC(20, 8) NOT NULL CHECK (gross_interest >= 0),
    tax_deducted NUMERIC(20, 8) DEFAULT 0 CHECK (tax_deducted >= 0),
    net_interest NUMERIC(20, 8) GENERATED ALWAYS AS (gross_interest - tax_deducted) STORED,
    
    -- Currency
    currency VARCHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    
    -- Posting status
    posting_status VARCHAR(20) DEFAULT 'CALCULATED'
        CHECK (posting_status IN ('CALCULATED', 'APPROVED', 'POSTED', 'REVERSED')),
    posted_at TIMESTAMPTZ,
    posted_transaction_id BIGINT,
    
    -- Adjustment tracking
    is_adjustment BOOLEAN DEFAULT FALSE,
    original_calculation_id UUID REFERENCES core.interest_calculations(calculation_id),
    adjustment_reason TEXT,
    
    -- COA posting
    interest_income_coa VARCHAR(50),
    interest_expense_coa VARCHAR(50),
    
    -- Application context
    application_id UUID,
    
    -- Audit
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    calculated_by UUID,
    approved_by UUID,
    approved_at TIMESTAMPTZ,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING',
    
    -- Constraints
    CONSTRAINT chk_period_valid CHECK (period_end >= period_start),
    CONSTRAINT chk_balance_positive CHECK (opening_balance >= 0 AND closing_balance >= 0)
);

-- -----------------------------------------------------------------------------
-- INDEXES
-- -----------------------------------------------------------------------------
-- Account-based lookups
CREATE INDEX idx_interest_calc_account 
    ON core.interest_calculations(account_id, period_end DESC);

-- Period queries
CREATE INDEX idx_interest_calc_period 
    ON core.interest_calculations(period_start, period_end);

-- Posting status
CREATE INDEX idx_interest_calc_status 
    ON core.interest_calculations(posting_status, calculated_at) 
    WHERE posting_status = 'CALCULATED';

-- Rate analysis
CREATE INDEX idx_interest_calc_rate 
    ON core.interest_calculations(rate_id, calculated_at);

-- Currency aggregation
CREATE INDEX idx_interest_calc_currency 
    ON core.interest_calculations(currency, posting_status);

-- -----------------------------------------------------------------------------
-- IMMUTABILITY TRIGGERS
-- -----------------------------------------------------------------------------
CREATE TRIGGER trg_interest_rates_prevent_update
    BEFORE UPDATE ON core.interest_rates
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_interest_rates_prevent_delete
    BEFORE DELETE ON core.interest_rates
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

CREATE TRIGGER trg_interest_calc_prevent_update
    BEFORE UPDATE ON core.interest_calculations
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_interest_calc_prevent_delete
    BEFORE DELETE ON core.interest_calculations
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- -----------------------------------------------------------------------------
-- HASH COMPUTATION TRIGGERS
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION core.compute_interest_rate_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.rate_id::TEXT || 
        NEW.rate_reference || 
        NEW.rate_type ||
        NEW.base_rate::TEXT ||
        NEW.spread::TEXT ||
        NEW.effective_from::TEXT ||
        NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_interest_rates_compute_hash
    BEFORE INSERT ON core.interest_rates
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_interest_rate_hash();

CREATE OR REPLACE FUNCTION core.compute_interest_calc_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.calculation_id::TEXT || 
        NEW.calculation_reference || 
        NEW.account_id::TEXT ||
        NEW.applied_rate::TEXT ||
        NEW.period_start::TEXT ||
        NEW.period_end::TEXT ||
        NEW.gross_interest::TEXT ||
        NEW.calculated_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_interest_calc_compute_hash
    BEFORE INSERT ON core.interest_calculations
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_interest_calc_hash();

-- -----------------------------------------------------------------------------
-- HELPER FUNCTIONS
-- -----------------------------------------------------------------------------

-- Function to calculate simple interest
CREATE OR REPLACE FUNCTION core.calculate_simple_interest(
    p_principal NUMERIC,
    p_rate NUMERIC,
    p_days INTEGER,
    p_year_basis INTEGER DEFAULT 365
)
RETURNS NUMERIC
LANGUAGE plpgsql
AS $$
BEGIN
    -- Simple Interest = P * R * (D/Y)
    RETURN ROUND(p_principal * (p_rate / 100) * (p_days::NUMERIC / p_year_basis), 8);
END;
$$;

-- Function to calculate compound interest
CREATE OR REPLACE FUNCTION core.calculate_compound_interest(
    p_principal NUMERIC,
    p_rate NUMERIC,
    p_days INTEGER,
    p_year_basis INTEGER DEFAULT 365,
    p_compounding_frequency VARCHAR DEFAULT 'ANNUAL'
)
RETURNS NUMERIC
LANGUAGE plpgsql
AS $$
DECLARE
    v_periods_per_year INTEGER;
    v_total_periods NUMERIC;
    v_rate_per_period NUMERIC;
BEGIN
    -- Determine compounding periods per year
    v_periods_per_year := CASE p_compounding_frequency
        WHEN 'DAILY' THEN 365
        WHEN 'MONTHLY' THEN 12
        WHEN 'QUARTERLY' THEN 4
        WHEN 'ANNUAL' THEN 1
        ELSE 1
    END;
    
    -- Calculate total periods and rate per period
    v_total_periods := (p_days::NUMERIC / p_year_basis) * v_periods_per_year;
    v_rate_per_period := (p_rate / 100) / v_periods_per_year;
    
    -- Compound Interest = P * ((1 + r/n)^(n*t) - 1)
    RETURN ROUND(p_principal * (POWER(1 + v_rate_per_period, v_total_periods) - 1), 8);
END;
$$;

-- Function to create interest calculation
CREATE OR REPLACE FUNCTION core.create_interest_calculation(
    p_account_id UUID,
    p_rate_id UUID,
    p_period_start DATE,
    p_period_end DATE,
    p_opening_balance NUMERIC,
    p_closing_balance NUMERIC,
    p_calculation_method VARCHAR DEFAULT 'ACTUAL_365',
    p_interest_type VARCHAR DEFAULT 'SIMPLE',
    p_currency VARCHAR DEFAULT 'USD',
    p_calculated_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_calculation_id UUID;
    v_reference VARCHAR(100);
    v_rate_record RECORD;
    v_days INTEGER;
    v_year_basis INTEGER;
    v_gross_interest NUMERIC;
    v_average_balance NUMERIC;
BEGIN
    -- Get rate details
    SELECT * INTO v_rate_record FROM core.interest_rates WHERE rate_id = p_rate_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Interest rate % not found', p_rate_id;
    END IF;
    
    -- Calculate days and year basis
    v_days := p_period_end - p_period_start + 1;
    v_year_basis := CASE p_calculation_method
        WHEN 'ACTUAL_360' THEN 360
        WHEN '30_360' THEN 360
        WHEN 'EURO_360' THEN 360
        ELSE 365
    END;
    
    -- Calculate average balance (simplified - could use daily balances)
    v_average_balance := (p_opening_balance + p_closing_balance) / 2;
    
    -- Calculate interest based on type
    IF p_interest_type = 'COMPOUND' THEN
        v_gross_interest := core.calculate_compound_interest(
            p_opening_balance, 
            v_rate_record.total_rate, 
            v_days, 
            v_year_basis,
            v_rate_record.compounding_frequency
        );
    ELSE
        v_gross_interest := core.calculate_simple_interest(
            v_average_balance, 
            v_rate_record.total_rate, 
            v_days, 
            v_year_basis
        );
    END IF;
    
    -- Generate reference
    v_reference := 'INT-' || TO_CHAR(p_period_end, 'YYYYMMDD') || '-' || SUBSTRING(MD5(RANDOM()::TEXT), 1, 6);
    
    INSERT INTO core.interest_calculations (
        calculation_reference,
        account_id,
        rate_id,
        applied_rate,
        period_start,
        period_end,
        days_in_period,
        year_basis,
        opening_balance,
        closing_balance,
        average_balance,
        interest_type,
        calculation_method,
        gross_interest,
        currency,
        calculated_by
    ) VALUES (
        v_reference,
        p_account_id,
        p_rate_id,
        v_rate_record.total_rate,
        p_period_start,
        p_period_end,
        v_days,
        v_year_basis,
        p_opening_balance,
        p_closing_balance,
        v_average_balance,
        p_interest_type,
        p_calculation_method,
        v_gross_interest,
        p_currency,
        p_calculated_by
    ) RETURNING calculation_id INTO v_calculation_id;
    
    RETURN v_calculation_id;
END;
$$;

-- Function to get interest summary by period
CREATE OR REPLACE FUNCTION core.get_interest_summary(
    p_period_start DATE,
    p_period_end DATE,
    p_interest_type VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    interest_type VARCHAR,
    currency VARCHAR,
    total_calculations BIGINT,
    total_gross_interest NUMERIC,
    total_tax_deducted NUMERIC,
    total_net_interest NUMERIC,
    avg_rate NUMERIC
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ic.interest_type,
        ic.currency,
        COUNT(*) as total_calculations,
        SUM(ic.gross_interest) as total_gross_interest,
        SUM(ic.tax_deducted) as total_tax_deducted,
        SUM(ic.net_interest) as total_net_interest,
        AVG(ic.applied_rate)::NUMERIC as avg_rate
    FROM core.interest_calculations ic
    WHERE ic.period_start >= p_period_start
      AND ic.period_end <= p_period_end
      AND (p_interest_type IS NULL OR ic.interest_type = p_interest_type)
      AND ic.posting_status != 'REVERSED'
    GROUP BY ic.interest_type, ic.currency
    ORDER BY ic.interest_type, ic.currency;
END;
$$;

-- Function to get year-to-date interest for account
CREATE OR REPLACE FUNCTION core.get_ytd_interest(
    p_account_id UUID,
    p_year INTEGER DEFAULT EXTRACT(YEAR FROM CURRENT_DATE)
)
RETURNS TABLE (
    currency VARCHAR,
    ytd_gross_interest NUMERIC,
    ytd_tax_deducted NUMERIC,
    ytd_net_interest NUMERIC,
    calculation_count BIGINT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ic.currency,
        SUM(ic.gross_interest) as ytd_gross_interest,
        SUM(ic.tax_deducted) as ytd_tax_deducted,
        SUM(ic.net_interest) as ytd_net_interest,
        COUNT(*) as calculation_count
    FROM core.interest_calculations ic
    WHERE ic.account_id = p_account_id
      AND EXTRACT(YEAR FROM ic.period_end) = p_year
      AND ic.posting_status = 'POSTED'
    GROUP BY ic.currency;
END;
$$;

-- -----------------------------------------------------------------------------
-- INITIAL DATA: Sample interest rates
-- -----------------------------------------------------------------------------
INSERT INTO core.interest_rates (
    rate_reference,
    rate_type,
    rate_subtype,
    base_rate,
    spread,
    calculation_method,
    compounding_frequency,
    accrual_frequency,
    effective_from
) VALUES 
-- Savings rates
('SAV-BASE-001', 'SAVINGS', 'STANDARD', 2.50, 0, 'ACTUAL_365', 'MONTHLY', 'MONTHLY', '2026-01-01'),
('SAV-PREM-001', 'SAVINGS', 'PREMIUM', 4.00, 0, 'ACTUAL_365', 'MONTHLY', 'MONTHLY', '2026-01-01'),

-- Lending rates
('LEND-PERS-001', 'LENDING', 'PERSONAL', 18.00, 0, 'ACTUAL_365', 'NONE', 'MONTHLY', '2026-01-01'),
('LEND-MERCH-001', 'LENDING', 'MERCHANT', 12.00, 0, 'ACTUAL_365', 'NONE', 'MONTHLY', '2026-01-01'),

-- Overdue/Penalty rates
('OD-PEN-001', 'OVERDUE', 'STANDARD', 24.00, 0, 'ACTUAL_365', 'NONE', 'DAILY', '2026-01-01'),
('PEN-LATE-001', 'PENALTY', 'LATE_PAYMENT', 5.00, 0, 'ACTUAL_365', 'NONE', 'DAILY', '2026-01-01');

-- -----------------------------------------------------------------------------
-- COMMENTS
-- -----------------------------------------------------------------------------
COMMENT ON TABLE core.interest_rates IS 'Interest rate definitions with calculation parameters';
COMMENT ON TABLE core.interest_calculations IS 'Interest accrual calculations for accounts';
COMMENT ON COLUMN core.interest_calculations.gross_interest IS 'Calculated interest before tax';
COMMENT ON COLUMN core.interest_calculations.net_interest IS 'Interest after tax deduction';

-- =============================================================================
-- END OF FILE
-- =============================================================================
