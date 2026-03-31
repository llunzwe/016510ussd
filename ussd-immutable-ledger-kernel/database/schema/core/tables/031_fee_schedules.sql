-- =============================================================================
-- USSD KERNEL CORE SCHEMA - FEE SCHEDULES
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    031_fee_schedules.sql
-- SCHEMA:      ussd_core
-- TABLE:       fee_schedules, fee_transactions
-- DESCRIPTION: Comprehensive fee management supporting tiered fees,
--              percentage-based fees, flat fees, and conditional fees.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Fee calculation monitoring
├── A.18.1 Compliance - Fee disclosure requirements
└── A.18.2 Compliance - Regulatory fee reporting

Financial Regulations
├── Fee transparency: Clear fee disclosure
├── Rate caps: Maximum fee limits
├── Tax: VAT/GST on fees
└── Consumer protection: Fee notification requirements

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. FEE TYPES
   - FLAT: Fixed amount fee
   - PERCENTAGE: Percentage of transaction amount
   - TIERED: Different rates for amount bands
   - HYBRID: Combination of flat + percentage
   - CONDITIONAL: Fee based on conditions

2. FEE CATEGORIES
   - TRANSACTION: Per-transaction fees
   - MAINTENANCE: Account maintenance fees
   - OVERDRAFT: Overdraft fees
   - LATE_PAYMENT: Late payment penalties
   - SERVICE: Service-related fees

3. CALCULATION LOGIC
   - Minimum fee enforcement
   - Maximum fee caps
   - Rounding rules
   - Tax applicability

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

FEE SECURITY:
- Immutable fee schedules
- Version control for rate changes
- Audit trail for fee waivers

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: schedule_id, fee_id
- TYPE: fee_type + category
- ACCOUNT: account_id + transaction_date
- STATUS: posting_status

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- FEE_CALCULATED
- FEE_POSTED
- FEE_WAIVED
- SCHEDULE_CHANGED

RETENTION: 7 years
================================================================================
*/

-- -----------------------------------------------------------------------------
-- CREATE TABLE: fee_schedules
-- -----------------------------------------------------------------------------
CREATE TABLE core.fee_schedules (
    -- Primary identifier
    schedule_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    schedule_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Fee classification
    fee_code VARCHAR(50) NOT NULL,
    fee_name VARCHAR(200) NOT NULL,
    fee_description TEXT,
    fee_category VARCHAR(50) NOT NULL
        CHECK (fee_category IN ('TRANSACTION', 'MAINTENANCE', 'OVERDRAFT', 'LATE_PAYMENT', 'SERVICE', 'PENALTY')),
    fee_type VARCHAR(20) NOT NULL
        CHECK (fee_type IN ('FLAT', 'PERCENTAGE', 'TIERED', 'HYBRID', 'CONDITIONAL')),
    
    -- Fee amounts
    flat_amount NUMERIC(20, 8),
    percentage_rate NUMERIC(10, 6),
    percentage_basis VARCHAR(50),  -- 'TRANSACTION_AMOUNT', 'BALANCE', etc.
    minimum_fee NUMERIC(20, 8) DEFAULT 0,
    maximum_fee NUMERIC(20, 8),
    
    -- Tiered fee configuration (JSON for flexibility)
    tier_configuration JSONB,  -- [{min_amount, max_amount, flat_fee, percentage}, ...]
    
    -- Conditional fee rules
    condition_rules JSONB,  -- {conditions: [...], logic: 'AND/OR'}
    
    -- Tax treatment
    is_taxable BOOLEAN DEFAULT TRUE,
    tax_rate_id UUID,  -- Reference to tax_rates
    
    -- Applicability
    applicable_transaction_types VARCHAR(50)[],
    applicable_account_types VARCHAR(50)[],
    applicable_currencies VARCHAR(3)[],
    
    -- Counterparty exemptions
    exempt_merchant_categories VARCHAR(50)[],
    exempt_account_ids UUID[],
    
    -- Application scope
    application_id UUID,
    
    -- Effective period
    effective_from DATE NOT NULL DEFAULT CURRENT_DATE,
    effective_until DATE,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    superseded_by UUID REFERENCES core.fee_schedules(schedule_id),
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING',
    
    -- Constraints
    CONSTRAINT chk_fee_amounts CHECK (
        (fee_type = 'FLAT' AND flat_amount IS NOT NULL) OR
        (fee_type = 'PERCENTAGE' AND percentage_rate IS NOT NULL) OR
        (fee_type IN ('TIERED', 'HYBRID', 'CONDITIONAL'))
    )
);

-- -----------------------------------------------------------------------------
-- INDEXES
-- -----------------------------------------------------------------------------
CREATE INDEX idx_fee_schedules_code 
    ON core.fee_schedules(fee_code, is_active);

CREATE INDEX idx_fee_schedules_category 
    ON core.fee_schedules(fee_category, fee_type);

CREATE INDEX idx_fee_schedules_effective 
    ON core.fee_schedules(effective_from, effective_until) 
    WHERE is_active = TRUE;

CREATE INDEX idx_fee_schedules_app 
    ON core.fee_schedules(application_id, fee_category);

-- -----------------------------------------------------------------------------
-- CREATE TABLE: fee_transactions
-- -----------------------------------------------------------------------------
CREATE TABLE core.fee_transactions (
    -- Primary identifier
    fee_transaction_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fee_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- References
    schedule_id UUID REFERENCES core.fee_schedules(schedule_id),
    source_transaction_id BIGINT,  -- Links to transaction_log
    partition_date DATE,
    
    -- Account information
    account_id UUID NOT NULL REFERENCES core.account_registry(account_id),
    account_type VARCHAR(50),
    
    -- Fee calculation basis
    basis_amount NUMERIC(20, 8) NOT NULL,  -- Amount fee was calculated on
    basis_currency VARCHAR(3) NOT NULL,
    
    -- Calculated fee
    fee_type VARCHAR(20) NOT NULL,
    calculated_fee NUMERIC(20, 8) NOT NULL,
    fee_currency VARCHAR(3) NOT NULL,
    
    -- Tax
    tax_amount NUMERIC(20, 8) DEFAULT 0,
    total_fee NUMERIC(20, 8) GENERATED ALWAYS AS (calculated_fee + tax_amount) STORED,
    
    -- Calculation details
    calculation_details JSONB,  -- {rate_applied, tier_band, conditions_met, ...}
    
    -- Waiver/Discount
    is_waived BOOLEAN DEFAULT FALSE,
    waiver_reason VARCHAR(100),
    waived_by UUID,
    waived_at TIMESTAMPTZ,
    discount_percentage NUMERIC(5, 2) DEFAULT 0,
    discount_amount NUMERIC(20, 8) DEFAULT 0,
    
    -- Posting status
    posting_status VARCHAR(20) DEFAULT 'CALCULATED'
        CHECK (posting_status IN ('CALCULATED', 'APPROVED', 'POSTED', 'WAIVED', 'REVERSED')),
    posted_at TIMESTAMPTZ,
    posted_transaction_id BIGINT,
    
    -- Narrative
    narrative VARCHAR(255),
    
    -- Application context
    application_id UUID,
    
    -- Audit
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    calculated_by UUID,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- -----------------------------------------------------------------------------
-- INDEXES
-- -----------------------------------------------------------------------------
CREATE INDEX idx_fee_trans_account 
    ON core.fee_transactions(account_id, calculated_at DESC);

CREATE INDEX idx_fee_trans_schedule 
    ON core.fee_transactions(schedule_id, calculated_at);

CREATE INDEX idx_fee_trans_source 
    ON core.fee_transactions(source_transaction_id, partition_date);

CREATE INDEX idx_fee_trans_status 
    ON core.fee_transactions(posting_status, calculated_at) 
    WHERE posting_status = 'CALCULATED';

CREATE INDEX idx_fee_trans_waived 
    ON core.fee_transactions(is_waived, waived_at) 
    WHERE is_waived = TRUE;

CREATE INDEX idx_fee_trans_currency 
    ON core.fee_transactions(fee_currency, posting_status);

-- -----------------------------------------------------------------------------
-- IMMUTABILITY TRIGGERS
-- -----------------------------------------------------------------------------
CREATE TRIGGER trg_fee_schedules_prevent_update
    BEFORE UPDATE ON core.fee_schedules
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_fee_schedules_prevent_delete
    BEFORE DELETE ON core.fee_schedules
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

CREATE TRIGGER trg_fee_trans_prevent_update
    BEFORE UPDATE ON core.fee_transactions
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_fee_trans_prevent_delete
    BEFORE DELETE ON core.fee_transactions
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- -----------------------------------------------------------------------------
-- HASH COMPUTATION TRIGGERS
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION core.compute_fee_schedule_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.schedule_id::TEXT || 
        NEW.schedule_reference || 
        NEW.fee_code ||
        NEW.fee_category ||
        NEW.fee_type ||
        COALESCE(NEW.flat_amount::TEXT, '') ||
        COALESCE(NEW.percentage_rate::TEXT, '') ||
        NEW.effective_from::TEXT ||
        NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_fee_schedules_compute_hash
    BEFORE INSERT ON core.fee_schedules
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_fee_schedule_hash();

CREATE OR REPLACE FUNCTION core.compute_fee_trans_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.fee_transaction_id::TEXT || 
        NEW.fee_reference || 
        NEW.account_id::TEXT ||
        NEW.schedule_id::TEXT ||
        NEW.basis_amount::TEXT ||
        NEW.calculated_fee::TEXT ||
        NEW.calculated_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_fee_trans_compute_hash
    BEFORE INSERT ON core.fee_transactions
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_fee_trans_hash();

-- -----------------------------------------------------------------------------
-- HELPER FUNCTIONS
-- -----------------------------------------------------------------------------

-- Function to calculate fee based on schedule
CREATE OR REPLACE FUNCTION core.calculate_fee(
    p_schedule_id UUID,
    p_basis_amount NUMERIC,
    p_currency VARCHAR(3),
    p_context JSONB DEFAULT '{}'
)
RETURNS TABLE (
    calculated_fee NUMERIC,
    tax_amount NUMERIC,
    total_fee NUMERIC,
    calculation_details JSONB
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_schedule RECORD;
    v_fee NUMERIC := 0;
    v_tax NUMERIC := 0;
    v_details JSONB;
    v_tier JSONB;
    v_tier_found BOOLEAN := FALSE;
BEGIN
    -- Get schedule
    SELECT * INTO v_schedule 
    FROM core.fee_schedules 
    WHERE schedule_id = p_schedule_id AND is_active = TRUE;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Fee schedule % not found or inactive', p_schedule_id;
    END IF;
    
    -- Calculate fee based on type
    CASE v_schedule.fee_type
        WHEN 'FLAT' THEN
            v_fee := v_schedule.flat_amount;
            v_details := jsonb_build_object(
                'type', 'FLAT',
                'flat_amount', v_schedule.flat_amount
            );
            
        WHEN 'PERCENTAGE' THEN
            v_fee := ROUND(p_basis_amount * (v_schedule.percentage_rate / 100), 8);
            v_details := jsonb_build_object(
                'type', 'PERCENTAGE',
                'basis_amount', p_basis_amount,
                'rate', v_schedule.percentage_rate,
                'percentage_basis', v_schedule.percentage_basis
            );
            
        WHEN 'TIERED' THEN
            -- Find applicable tier
            FOR v_tier IN SELECT * FROM jsonb_array_elements(v_schedule.tier_configuration)
            LOOP
                IF (v_tier->>'min_amount')::NUMERIC <= p_basis_amount 
                   AND (v_tier->>'max_amount')::NUMERIC >= p_basis_amount THEN
                    v_fee := COALESCE((v_tier->>'flat_fee')::NUMERIC, 0);
                    IF v_tier->>'percentage' IS NOT NULL THEN
                        v_fee := v_fee + ROUND(p_basis_amount * ((v_tier->>'percentage')::NUMERIC / 100), 8);
                    END IF;
                    v_tier_found := TRUE;
                    v_details := jsonb_build_object(
                        'type', 'TIERED',
                        'tier', v_tier,
                        'basis_amount', p_basis_amount
                    );
                    EXIT;
                END IF;
            END LOOP;
            
            IF NOT v_tier_found THEN
                RAISE EXCEPTION 'No applicable tier found for amount %', p_basis_amount;
            END IF;
            
        WHEN 'HYBRID' THEN
            v_fee := COALESCE(v_schedule.flat_amount, 0);
            IF v_schedule.percentage_rate IS NOT NULL THEN
                v_fee := v_fee + ROUND(p_basis_amount * (v_schedule.percentage_rate / 100), 8);
            END IF;
            v_details := jsonb_build_object(
                'type', 'HYBRID',
                'flat_amount', v_schedule.flat_amount,
                'rate', v_schedule.percentage_rate,
                'basis_amount', p_basis_amount
            );
            
        ELSE
            v_fee := 0;
            v_details := jsonb_build_object('type', 'UNKNOWN');
    END CASE;
    
    -- Apply min/max constraints
    IF v_schedule.minimum_fee IS NOT NULL AND v_fee < v_schedule.minimum_fee THEN
        v_fee := v_schedule.minimum_fee;
        v_details := v_details || jsonb_build_object('minimum_applied', true);
    END IF;
    
    IF v_schedule.maximum_fee IS NOT NULL AND v_fee > v_schedule.maximum_fee THEN
        v_fee := v_schedule.maximum_fee;
        v_details := v_details || jsonb_build_object('maximum_applied', true);
    END IF;
    
    -- Calculate tax if applicable
    IF v_schedule.is_taxable AND v_schedule.tax_rate_id IS NOT NULL THEN
        -- Tax calculation would reference tax_rates table
        v_tax := 0; -- Placeholder
    END IF;
    
    RETURN QUERY SELECT v_fee, v_tax, v_fee + v_tax, v_details;
END;
$$;

-- Function to create fee transaction
CREATE OR REPLACE FUNCTION core.create_fee_transaction(
    p_schedule_id UUID,
    p_account_id UUID,
    p_basis_amount NUMERIC,
    p_currency VARCHAR(3),
    p_source_transaction_id BIGINT DEFAULT NULL,
    p_partition_date DATE DEFAULT NULL,
    p_narrative VARCHAR DEFAULT NULL,
    p_calculated_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_fee_trans_id UUID;
    v_reference VARCHAR(100);
    v_calc_result RECORD;
BEGIN
    -- Calculate fee
    SELECT * INTO v_calc_result 
    FROM core.calculate_fee(p_schedule_id, p_basis_amount, p_currency);
    
    -- Generate reference
    v_reference := 'FEE-' || TO_CHAR(CURRENT_DATE, 'YYYYMMDD') || '-' || SUBSTRING(MD5(RANDOM()::TEXT), 1, 6);
    
    INSERT INTO core.fee_transactions (
        fee_reference,
        schedule_id,
        source_transaction_id,
        partition_date,
        account_id,
        basis_amount,
        basis_currency,
        fee_type,
        calculated_fee,
        fee_currency,
        tax_amount,
        calculation_details,
        narrative,
        calculated_by
    ) VALUES (
        v_reference,
        p_schedule_id,
        p_source_transaction_id,
        p_partition_date,
        p_account_id,
        p_basis_amount,
        p_currency,
        (SELECT fee_type FROM core.fee_schedules WHERE schedule_id = p_schedule_id),
        v_calc_result.calculated_fee,
        p_currency,
        v_calc_result.tax_amount,
        v_calc_result.calculation_details,
        p_narrative,
        p_calculated_by
    ) RETURNING fee_transaction_id INTO v_fee_trans_id;
    
    RETURN v_fee_trans_id;
END;
$$;

-- Function to waive fee
CREATE OR REPLACE FUNCTION core.waive_fee(
    p_fee_transaction_id UUID,
    p_reason VARCHAR,
    p_waived_by UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    -- Since table is immutable, we create a new record with waived status
    INSERT INTO core.fee_transactions (
        fee_reference,
        schedule_id,
        source_transaction_id,
        partition_date,
        account_id,
        basis_amount,
        basis_currency,
        fee_type,
        calculated_fee,
        fee_currency,
        tax_amount,
        is_waived,
        waiver_reason,
        waived_by,
        waived_at,
        posting_status,
        narrative
    )
    SELECT 
        ft.fee_reference || '-W',
        ft.schedule_id,
        ft.source_transaction_id,
        ft.partition_date,
        ft.account_id,
        ft.basis_amount,
        ft.basis_currency,
        ft.fee_type,
        ft.calculated_fee,
        ft.fee_currency,
        ft.tax_amount,
        TRUE,
        p_reason,
        p_waived_by,
        core.precise_now(),
        'WAIVED',
        COALESCE(ft.narrative, '') || ' [WAIVED: ' || p_reason || ']'
    FROM core.fee_transactions ft
    WHERE ft.fee_transaction_id = p_fee_transaction_id
    AND ft.posting_status IN ('CALCULATED', 'APPROVED');
    
    RETURN FOUND;
END;
$$;

-- Function to get fee summary
CREATE OR REPLACE FUNCTION core.get_fee_summary(
    p_start_date DATE,
    p_end_date DATE,
    p_fee_category VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    fee_category VARCHAR,
    fee_type VARCHAR,
    transaction_count BIGINT,
    total_calculated NUMERIC,
    total_tax NUMERIC,
    total_waived NUMERIC,
    net_fees NUMERIC
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        fs.fee_category,
        fs.fee_type,
        COUNT(*) as transaction_count,
        SUM(ft.calculated_fee) as total_calculated,
        SUM(ft.tax_amount) as total_tax,
        SUM(CASE WHEN ft.is_waived THEN ft.calculated_fee ELSE 0 END) as total_waived,
        SUM(CASE WHEN ft.is_waived THEN 0 ELSE ft.total_fee END) as net_fees
    FROM core.fee_transactions ft
    JOIN core.fee_schedules fs ON ft.schedule_id = fs.schedule_id
    WHERE ft.calculated_at::DATE BETWEEN p_start_date AND p_end_date
      AND (p_fee_category IS NULL OR fs.fee_category = p_fee_category)
    GROUP BY fs.fee_category, fs.fee_type
    ORDER BY net_fees DESC;
END;
$$;

-- -----------------------------------------------------------------------------
-- INITIAL DATA: Common fee schedules
-- -----------------------------------------------------------------------------
INSERT INTO core.fee_schedules (
    schedule_reference,
    fee_code,
    fee_name,
    fee_description,
    fee_category,
    fee_type,
    flat_amount,
    percentage_rate,
    minimum_fee,
    maximum_fee,
    applicable_transaction_types,
    effective_from
) VALUES 
-- P2P Transfer fees
('FEE-P2P-STD', 'P2P_FEE', 'P2P Transfer Fee', 'Fee for peer-to-peer transfers', 
 'TRANSACTION', 'TIERED', NULL, NULL, 0.50, 50.00, 
 ARRAY['P2P_TRANSFER'], '2026-01-01'),

-- Cash withdrawal fees
('FEE-CASH-OUT', 'CASH_OUT_FEE', 'Cash Withdrawal Fee', 'Fee for cash withdrawal at agent', 
 'TRANSACTION', 'PERCENTAGE', NULL, 1.00, 1.00, 100.00, 
 ARRAY['CASH_OUT'], '2026-01-01'),

-- Merchant payment fees
('FEE-MERCH-PAY', 'MERCHANT_FEE', 'Merchant Payment Fee', 'Fee charged to merchant for payment acceptance', 
 'TRANSACTION', 'PERCENTAGE', NULL, 1.50, 0.10, NULL, 
 ARRAY['MERCHANT_PAY'], '2026-01-01'),

-- Account maintenance
('FEE-MAINT', 'MAINTENANCE_FEE', 'Account Maintenance', 'Monthly account maintenance fee', 
 'MAINTENANCE', 'FLAT', 2.00, NULL, NULL, NULL, 
 NULL, '2026-01-01'),

-- Overdraft fee
('FEE-OD', 'OVERDRAFT_FEE', 'Overdraft Fee', 'Fee for overdraft usage', 
 'OVERDRAFT', 'PERCENTAGE', NULL, 5.00, 5.00, 100.00, 
 NULL, '2026-01-01');

-- Update P2P tier configuration
UPDATE core.fee_schedules 
SET tier_configuration = '[
    {"min_amount": 0, "max_amount": 100, "flat_fee": 0.50, "percentage": 0},
    {"min_amount": 100.01, "max_amount": 1000, "flat_fee": 1.00, "percentage": 0},
    {"min_amount": 1000.01, "max_amount": 10000, "flat_fee": 2.00, "percentage": 0.5},
    {"min_amount": 10000.01, "max_amount": 999999999, "flat_fee": 5.00, "percentage": 0.3}
]'::JSONB
WHERE fee_code = 'P2P_FEE';

-- -----------------------------------------------------------------------------
-- COMMENTS
-- -----------------------------------------------------------------------------
COMMENT ON TABLE core.fee_schedules IS 'Fee schedule definitions with tiered and conditional support';
COMMENT ON TABLE core.fee_transactions IS 'Individual fee calculations and transactions';
COMMENT ON COLUMN core.fee_transactions.calculated_fee IS 'Fee amount before tax and discounts';
COMMENT ON COLUMN core.fee_transactions.total_fee IS 'Final fee amount including tax';

-- =============================================================================
-- END OF FILE
-- =============================================================================
