-- =============================================================================
-- USSD KERNEL APP SCHEMA - FEE, COMMISSION & TAX ENGINE
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    058_app_fee_commission_tax_engine.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      app
-- DESCRIPTION: Comprehensive fee calculation, commission tracking, and tax
--              management for USSD business applications.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Fee/commission monitoring
├── A.18.1 Compliance - Tax reporting requirements
└── A.18.2 Compliance - Revenue recognition audit

Financial Regulations
├── Tax: VAT/GST, withholding tax, sales tax
├── Revenue recognition: ASC 606/IFRS 15
├── Agent banking: Commission disclosure
└── Consumer protection: Fee transparency

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. FEE TYPES
   - Transaction fees (percentage, flat, tiered)
   - Account maintenance fees
   - Service fees
   - Penalty fees

2. COMMISSION TYPES
   - Flat commission
   - Percentage of transaction
   - Tiered by volume
   - Override commissions

3. TAX TYPES
   - VAT/GST (output/input)
   - Withholding tax
   - Sales tax
   - Stamp duty

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

REVENUE SECURITY:
- Immutable fee/commission calculations
- Tax audit trail
- Approval workflows for waivers
- RLS per application

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- Fee schedules by app and transaction type
- Commission by recipient and period
- Tax by jurisdiction and date

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- FEE_CALCULATED
- COMMISSION_POSTED
- TAX_RECORDED
- WAIVER_APPROVED

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- FEE SCHEDULE MANAGEMENT
-- =============================================================================

CREATE TABLE app.fee_schedules (
    schedule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES app.t_application_registry(app_id) ON DELETE CASCADE,
    
    schedule_code VARCHAR(50) NOT NULL,
    schedule_name VARCHAR(200) NOT NULL,
    description TEXT,
    
    -- Fee classification
    fee_type VARCHAR(20) NOT NULL
        CHECK (fee_type IN ('FLAT', 'PERCENTAGE', 'TIERED', 'HYBRID', 'CONDITIONAL')),
    fee_category VARCHAR(50) NOT NULL
        CHECK (fee_category IN ('TRANSACTION', 'MAINTENANCE', 'SERVICE', 'PENALTY', 'OVERDRAFT')),
    
    -- Amounts
    flat_amount NUMERIC(20, 8),
    percentage_rate NUMERIC(10, 6),
    minimum_fee NUMERIC(20, 8) DEFAULT 0,
    maximum_fee NUMERIC(20, 8),
    
    -- Tiered configuration
    tier_config JSONB,  -- [{min_amount, max_amount, rate}, ...]
    
    -- Applicability
    applicable_transaction_types TEXT[],
    applicable_currencies TEXT[],
    minimum_transaction_amount NUMERIC(20, 8) DEFAULT 0,
    maximum_transaction_amount NUMERIC(20, 8),
    
    -- Counterparty types
    applicable_from_account_types TEXT[],
    applicable_to_account_types TEXT[],
    
    -- Conditional rules
    condition_expression TEXT,  -- SQL expression for conditional fees
    
    -- Tax treatment
    is_taxable BOOLEAN DEFAULT TRUE,
    tax_rate_id UUID,
    
    -- Settlement
    revenue_account_id UUID,  -- COA account for revenue recognition
    settlement_frequency VARCHAR(20) DEFAULT 'IMMEDIATE',
    
    -- Validity
    effective_from DATE NOT NULL DEFAULT CURRENT_DATE,
    effective_until DATE,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    version INTEGER DEFAULT 1,
    
    CONSTRAINT uq_app_fee_schedule UNIQUE (app_id, schedule_code)
);

-- Fee transactions (calculated fees)
CREATE TABLE app.fee_transactions (
    fee_transaction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES app.t_application_registry(app_id) ON DELETE CASCADE,
    
    schedule_id UUID REFERENCES app.fee_schedules(schedule_id),
    core_transaction_id BIGINT,
    partition_date DATE,
    
    -- Source
    from_account_id UUID REFERENCES core.account_registry(account_id),
    to_account_id UUID REFERENCES core.account_registry(account_id),
    
    -- Calculation basis
    basis_type VARCHAR(50),  -- 'TRANSACTION_AMOUNT', 'BALANCE', etc.
    basis_amount NUMERIC(20, 8) NOT NULL,
    basis_currency VARCHAR(6) NOT NULL,
    
    -- Calculated fee
    fee_type VARCHAR(20) NOT NULL,
    gross_fee NUMERIC(20, 8) NOT NULL,
    tax_amount NUMERIC(20, 8) DEFAULT 0,
    net_fee NUMERIC(20, 8) GENERATED ALWAYS AS (gross_fee + tax_amount) STORED,
    fee_currency VARCHAR(6) NOT NULL,
    
    -- Calculation details
    calculation_details JSONB,
    
    -- Waiver
    is_waived BOOLEAN DEFAULT FALSE,
    waiver_reason TEXT,
    waived_by UUID,
    waived_at TIMESTAMPTZ,
    waived_approved_by UUID,
    
    -- Status
    status VARCHAR(20) DEFAULT 'CALCULATED'
        CHECK (status IN ('CALCULATED', 'APPROVED', 'POSTED', 'WAIVED', 'REVERSED')),
    posted_at TIMESTAMPTZ,
    journal_entry_id BIGINT,
    
    -- Narrative
    narrative VARCHAR(255),
    
    -- Audit
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    calculated_by UUID,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- COMMISSION MANAGEMENT
-- =============================================================================

CREATE TABLE app.commission_schedules (
    schedule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES app.t_application_registry(app_id) ON DELETE CASCADE,
    
    schedule_code VARCHAR(50) NOT NULL,
    schedule_name VARCHAR(200) NOT NULL,
    
    -- Commission classification
    commission_type VARCHAR(20) NOT NULL
        CHECK (commission_type IN ('FLAT', 'PERCENTAGE', 'TIERED', 'HYBRID', 'OVERRIDE')),
    recipient_type VARCHAR(50) NOT NULL
        CHECK (recipient_type IN ('AGENT', 'MERCHANT', 'REFERRER', 'MASTER_AGENT', 'PARTNER')),
    
    -- Calculation
    flat_amount NUMERIC(20, 8),
    percentage_rate NUMERIC(10, 6),
    percentage_basis VARCHAR(50),  -- 'TRANSACTION_AMOUNT', 'FEE_AMOUNT', etc.
    minimum_commission NUMERIC(20, 8) DEFAULT 0,
    maximum_commission NUMERIC(20, 8),
    
    -- Tiered/override
    tier_config JSONB,
    override_percentage NUMERIC(10, 6),  -- For master agents
    override_levels INTEGER DEFAULT 1,
    
    -- Applicability
    applicable_transaction_types TEXT[],
    
    -- Settlement
    expense_account_id UUID,  -- COA account for commission expense
    settlement_frequency VARCHAR(20) DEFAULT 'DAILY',
    minimum_payout NUMERIC(20, 8) DEFAULT 0,
    
    -- Tax
    withholding_tax_rate NUMERIC(10, 6) DEFAULT 0,
    
    -- Validity
    effective_from DATE NOT NULL DEFAULT CURRENT_DATE,
    effective_until DATE,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    
    CONSTRAINT uq_app_commission_schedule UNIQUE (app_id, schedule_code)
);

-- Commission transactions
CREATE TABLE app.commission_transactions (
    commission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES app.t_application_registry(app_id) ON DELETE CASCADE,
    
    schedule_id UUID REFERENCES app.commission_schedules(schedule_id),
    core_transaction_id BIGINT,
    partition_date DATE,
    
    -- Recipient
    recipient_account_id UUID NOT NULL REFERENCES core.account_registry(account_id),
    recipient_type VARCHAR(50) NOT NULL,
    
    -- Source
    source_account_id UUID REFERENCES core.account_registry(account_id),
    agent_id UUID REFERENCES core.account_registry(account_id),
    parent_agent_id UUID REFERENCES core.account_registry(account_id),
    
    -- Calculation basis
    basis_amount NUMERIC(20, 8) NOT NULL,
    basis_currency VARCHAR(6) NOT NULL,
    
    -- Commission amounts
    gross_commission NUMERIC(20, 8) NOT NULL,
    withholding_tax NUMERIC(20, 8) DEFAULT 0,
    net_commission NUMERIC(20, 8) GENERATED ALWAYS AS (gross_commission - withholding_tax) STORED,
    commission_currency VARCHAR(6) NOT NULL,
    
    -- Override tracking
    is_override BOOLEAN DEFAULT FALSE,
    override_level INTEGER DEFAULT 0,
    original_commission_id UUID REFERENCES app.commission_transactions(commission_id),
    
    -- Status
    status VARCHAR(20) DEFAULT 'CALCULATED'
        CHECK (status IN ('CALCULATED', 'APPROVED', 'PENDING_PAYMENT', 'PAID', 'HELD', 'REVERSED')),
    held_reason TEXT,
    paid_at TIMESTAMPTZ,
    payment_reference VARCHAR(100),
    
    -- Narrative
    narrative VARCHAR(255),
    
    -- Audit
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    calculated_by UUID,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- TAX MANAGEMENT
-- =============================================================================

CREATE TABLE app.tax_rates (
    tax_rate_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES app.t_application_registry(app_id) ON DELETE CASCADE,
    
    tax_code VARCHAR(50) NOT NULL,
    tax_name VARCHAR(200) NOT NULL,
    tax_type VARCHAR(20) NOT NULL
        CHECK (tax_type IN ('VAT', 'GST', 'SALES', 'WITHHOLDING', 'STAMP', 'CUSTOM')),
    
    -- Rate details
    rate_percentage NUMERIC(10, 6) NOT NULL,
    is_compound BOOLEAN DEFAULT FALSE,  -- For compound taxes
    
    -- Jurisdiction
    country_code VARCHAR(2),
    region VARCHAR(50),
    
    -- Applicability
    applicable_transaction_types TEXT[],
    applicable_account_types TEXT[],
    exempt_account_ids UUID[],
    
    -- Accounting
    output_tax_account_id UUID,  -- COA account for tax collected
    input_tax_account_id UUID,   -- COA account for tax paid
    
    -- Validity
    effective_from DATE NOT NULL DEFAULT CURRENT_DATE,
    effective_until DATE,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    
    CONSTRAINT uq_app_tax_rate UNIQUE (app_id, tax_code)
);

-- Tax transactions
CREATE TABLE app.tax_transactions (
    tax_transaction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES app.t_application_registry(app_id) ON DELETE CASCADE,
    
    tax_rate_id UUID REFERENCES app.tax_rates(tax_rate_id),
    core_transaction_id BIGINT,
    partition_date DATE,
    
    -- Tax direction
    tax_direction VARCHAR(20) NOT NULL
        CHECK (tax_direction IN ('OUTPUT', 'INPUT')),  -- Collected or paid
    
    -- Calculation basis
    basis_amount NUMERIC(20, 8) NOT NULL,
    basis_currency VARCHAR(6) NOT NULL,
    tax_rate NUMERIC(10, 6) NOT NULL,
    
    -- Tax amounts
    tax_amount NUMERIC(20, 8) NOT NULL,
    tax_currency VARCHAR(6) NOT NULL,
    
    -- Source
    from_account_id UUID REFERENCES core.account_registry(account_id),
    to_account_id UUID REFERENCES core.account_registry(account_id),
    
    -- Status
    status VARCHAR(20) DEFAULT 'CALCULATED'
        CHECK (status IN ('CALCULATED', 'REPORTED', 'PAID', 'RECLAIMED', 'REVERSED')),
    reported_at TIMESTAMPTZ,
    paid_at TIMESTAMPTZ,
    
    -- Narrative
    narrative VARCHAR(255),
    
    -- Audit
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    calculated_by UUID,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Fee indexes
CREATE INDEX idx_fee_schedules_app ON app.fee_schedules(app_id, is_active);
CREATE INDEX idx_fee_schedules_type ON app.fee_schedules(fee_type, fee_category);
CREATE INDEX idx_fee_trans_app ON app.fee_transactions(app_id, status);
CREATE INDEX idx_fee_trans_schedule ON app.fee_transactions(schedule_id, calculated_at);
CREATE INDEX idx_fee_trans_core ON app.fee_transactions(core_transaction_id, partition_date);
CREATE INDEX idx_fee_trans_waived ON app.fee_transactions(is_waived, waived_at) WHERE is_waived = TRUE;

-- Commission indexes
CREATE INDEX idx_commission_schedules_app ON app.commission_schedules(app_id, is_active);
CREATE INDEX idx_commission_schedules_recipient ON app.commission_schedules(recipient_type);
CREATE INDEX idx_commission_trans_app ON app.commission_transactions(app_id, status);
CREATE INDEX idx_commission_trans_recipient ON app.commission_transactions(recipient_account_id, status);
CREATE INDEX idx_commission_trans_agent ON app.commission_transactions(agent_id, calculated_at);
CREATE INDEX idx_commission_trans_parent ON app.commission_transactions(parent_agent_id) WHERE parent_agent_id IS NOT NULL;

-- Tax indexes
CREATE INDEX idx_tax_rates_app ON app.tax_rates(app_id, is_active);
CREATE INDEX idx_tax_rates_type ON app.tax_rates(tax_type, country_code);
CREATE INDEX idx_tax_trans_app ON app.tax_transactions(app_id, status);
CREATE INDEX idx_tax_trans_rate ON app.tax_transactions(tax_rate_id, calculated_at);
CREATE INDEX idx_tax_trans_direction ON app.tax_transactions(tax_direction, status);

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

ALTER TABLE app.fee_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.fee_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.commission_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.commission_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.tax_rates ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.tax_transactions ENABLE ROW LEVEL SECURITY;

-- Fee schedules
CREATE POLICY fee_schedules_app_isolation ON app.fee_schedules
    FOR ALL TO ussd_app_user
    USING (app_id = current_setting('app.current_application_id', true)::UUID);

CREATE POLICY fee_schedules_kernel ON app.fee_schedules
    FOR ALL TO ussd_kernel_role USING (true);

-- Fee transactions
CREATE POLICY fee_trans_app_isolation ON app.fee_transactions
    FOR ALL TO ussd_app_user
    USING (app_id = current_setting('app.current_application_id', true)::UUID);

CREATE POLICY fee_trans_kernel ON app.fee_transactions
    FOR ALL TO ussd_kernel_role USING (true);

-- Commission schedules
CREATE POLICY commission_schedules_app_isolation ON app.commission_schedules
    FOR ALL TO ussd_app_user
    USING (app_id = current_setting('app.current_application_id', true)::UUID);

-- Commission transactions
CREATE POLICY commission_trans_app_isolation ON app.commission_transactions
    FOR ALL TO ussd_app_user
    USING (app_id = current_setting('app.current_application_id', true)::UUID);

-- Tax rates
CREATE POLICY tax_rates_app_isolation ON app.tax_rates
    FOR ALL TO ussd_app_user
    USING (app_id = current_setting('app.current_application_id', true)::UUID);

-- Tax transactions
CREATE POLICY tax_trans_app_isolation ON app.tax_transactions
    FOR ALL TO ussd_app_user
    USING (app_id = current_setting('app.current_application_id', true)::UUID);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to calculate fee
CREATE OR REPLACE FUNCTION app.calculate_fee(
    p_schedule_id UUID,
    p_basis_amount NUMERIC,
    p_currency VARCHAR,
    p_context JSONB DEFAULT '{}'
)
RETURNS TABLE (
    gross_fee NUMERIC,
    tax_amount NUMERIC,
    net_fee NUMERIC,
    calculation_details JSONB
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_schedule RECORD;
    v_fee NUMERIC := 0;
    v_details JSONB;
    v_tier JSONB;
BEGIN
    SELECT * INTO v_schedule FROM app.fee_schedules WHERE schedule_id = p_schedule_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Fee schedule % not found', p_schedule_id;
    END IF;
    
    CASE v_schedule.fee_type
        WHEN 'FLAT' THEN
            v_fee := v_schedule.flat_amount;
            v_details := jsonb_build_object('type', 'FLAT', 'amount', v_schedule.flat_amount);
            
        WHEN 'PERCENTAGE' THEN
            v_fee := ROUND(p_basis_amount * (v_schedule.percentage_rate / 100), 8);
            v_details := jsonb_build_object('type', 'PERCENTAGE', 'rate', v_schedule.percentage_rate);
            
        WHEN 'TIERED' THEN
            FOR v_tier IN SELECT * FROM jsonb_array_elements(v_schedule.tier_config)
            LOOP
                IF p_basis_amount BETWEEN (v_tier->>'min_amount')::NUMERIC AND (v_tier->>'max_amount')::NUMERIC THEN
                    v_fee := COALESCE((v_tier->>'flat')::NUMERIC, 0);
                    IF v_tier->>'rate' IS NOT NULL THEN
                        v_fee := v_fee + ROUND(p_basis_amount * ((v_tier->>'rate')::NUMERIC / 100), 8);
                    END IF;
                    v_details := jsonb_build_object('type', 'TIERED', 'tier', v_tier);
                    EXIT;
                END IF;
            END LOOP;
            
        WHEN 'HYBRID' THEN
            v_fee := COALESCE(v_schedule.flat_amount, 0);
            IF v_schedule.percentage_rate IS NOT NULL THEN
                v_fee := v_fee + ROUND(p_basis_amount * (v_schedule.percentage_rate / 100), 8);
            END IF;
            v_details := jsonb_build_object('type', 'HYBRID');
    END CASE;
    
    -- Apply min/max
    IF v_schedule.minimum_fee IS NOT NULL AND v_fee < v_schedule.minimum_fee THEN
        v_fee := v_schedule.minimum_fee;
    END IF;
    IF v_schedule.maximum_fee IS NOT NULL AND v_fee > v_schedule.maximum_fee THEN
        v_fee := v_schedule.maximum_fee;
    END IF;
    
    RETURN QUERY SELECT v_fee, 0::NUMERIC, v_fee, v_details;
END;
$$;

-- Function to calculate commission
CREATE OR REPLACE FUNCTION app.calculate_commission(
    p_schedule_id UUID,
    p_basis_amount NUMERIC,
    p_monthly_volume NUMERIC DEFAULT 0
)
RETURNS TABLE (
    gross_commission NUMERIC,
    withholding_tax NUMERIC,
    net_commission NUMERIC,
    calculation_details JSONB
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_schedule RECORD;
    v_commission NUMERIC := 0;
    v_details JSONB;
    v_tier JSONB;
    v_tax NUMERIC := 0;
BEGIN
    SELECT * INTO v_schedule FROM app.commission_schedules WHERE schedule_id = p_schedule_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Commission schedule % not found', p_schedule_id;
    END IF;
    
    CASE v_schedule.commission_type
        WHEN 'FLAT' THEN
            v_commission := v_schedule.flat_amount;
            
        WHEN 'PERCENTAGE' THEN
            v_commission := ROUND(p_basis_amount * (v_schedule.percentage_rate / 100), 8);
            
        WHEN 'TIERED' THEN
            FOR v_tier IN SELECT * FROM jsonb_array_elements(v_schedule.tier_config)
            LOOP
                IF p_monthly_volume BETWEEN (v_tier->>'min_volume')::NUMERIC AND (v_tier->>'max_volume')::NUMERIC THEN
                    v_commission := COALESCE((v_tier->>'flat')::NUMERIC, 0);
                    IF v_tier->>'rate' IS NOT NULL THEN
                        v_commission := v_commission + ROUND(p_basis_amount * ((v_tier->>'rate')::NUMERIC / 100), 8);
                    END IF;
                    EXIT;
                END IF;
            END LOOP;
            
        WHEN 'OVERRIDE' THEN
            v_commission := ROUND(p_basis_amount * (v_schedule.override_percentage / 100), 8);
    END CASE;
    
    -- Apply limits
    IF v_schedule.minimum_commission IS NOT NULL AND v_commission < v_schedule.minimum_commission THEN
        v_commission := v_schedule.minimum_commission;
    END IF;
    IF v_schedule.maximum_commission IS NOT NULL AND v_commission > v_schedule.maximum_commission THEN
        v_commission := v_schedule.maximum_commission;
    END IF;
    
    -- Calculate withholding tax
    IF v_schedule.withholding_tax_rate > 0 THEN
        v_tax := ROUND(v_commission * (v_schedule.withholding_tax_rate / 100), 8);
    END IF;
    
    RETURN QUERY SELECT v_commission, v_tax, v_commission - v_tax, v_details;
END;
$$;

-- Function to calculate tax
CREATE OR REPLACE FUNCTION app.calculate_tax(
    p_tax_rate_id UUID,
    p_basis_amount NUMERIC
)
RETURNS TABLE (
    tax_amount NUMERIC,
    rate_applied NUMERIC,
    calculation_details JSONB
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_rate RECORD;
    v_tax NUMERIC;
BEGIN
    SELECT * INTO v_rate FROM app.tax_rates WHERE tax_rate_id = p_tax_rate_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Tax rate % not found', p_tax_rate_id;
    END IF;
    
    v_tax := ROUND(p_basis_amount * (v_rate.rate_percentage / 100), 8);
    
    RETURN QUERY SELECT v_tax, v_rate.rate_percentage, 
                 jsonb_build_object('tax_code', v_rate.tax_code, 'tax_type', v_rate.tax_type);
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE app.fee_schedules IS 'Configurable fee schedules for transactions';
COMMENT ON TABLE app.fee_transactions IS 'Calculated fee transactions';
COMMENT ON TABLE app.commission_schedules IS 'Commission structures for agents and partners';
COMMENT ON TABLE app.commission_transactions IS 'Calculated commission transactions';
COMMENT ON TABLE app.tax_rates IS 'Tax rate configurations by jurisdiction';
COMMENT ON TABLE app.tax_transactions IS 'Tax calculations for reporting';

-- =============================================================================
-- END OF FILE
-- =============================================================================
