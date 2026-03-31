-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: utils/seed/001_default_transaction_types.sql
-- Description: Standard transaction types, categories, and fee structures
--              for the USSD immutable ledger
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: INTERNAL
-- DATA SENSITIVITY: MEDIUM - Transaction Configuration
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.12.1 Operational Procedures
  - Transaction type configuration for business processes
  - Fee structure for service delivery
  
A.8.2 Information Classification
  - Transaction categorization by risk level
  - Approval workflow configuration
================================================================================

================================================================================
PCI DSS 4.0 TRANSACTION REQUIREMENTS
================================================================================
Requirement 3.4: Transaction types for cardholder data processing
Requirement 7: Access control for transaction types
Requirement 10: Audit trail configuration per transaction type
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. ON CONFLICT for idempotent seeding
2. Clear documentation for each transaction type
3. Compliance flags for regulatory requirements
4. Audit trail tracking for all types
================================================================================

================================================================================
TRANSACTION TYPE CLASSIFICATION
================================================================================
High Risk: International transfers, bulk transfers, adjustments, reversals
Medium Risk: Bank transfers, merchant payments, cash operations
Low Risk: Airtime purchases, internal transfers
================================================================================
*/

-- ============================================================================
-- TRANSACTION TYPES
-- ============================================================================

INSERT INTO transaction_types (
    type_code, type_name, type_category, description,
    allowed_source_account_types, allowed_destination_account_types,
    requires_approval, approval_threshold_amount,
    is_reversible, reversal_time_limit_hours,
    default_priority, status
) VALUES
    -- Money Transfer Types
    ('P2P_TRANSFER', 'Peer-to-Peer Transfer', 'transfer', 
     'Transfer between two user accounts',
     ARRAY['individual', 'business'], ARRAY['individual', 'business'],
     FALSE, NULL, TRUE, 24, 'normal', 'active'),
     
    ('BANK_TRANSFER', 'Bank Transfer', 'transfer',
     'Transfer to external bank account',
     ARRAY['individual', 'business'], ARRAY['external'],
     FALSE, 10000.00, TRUE, 48, 'normal', 'active'),
     
    ('INTERNATIONAL_TRANSFER', 'International Transfer', 'transfer',
     'Cross-border money transfer',
     ARRAY['individual', 'business'], ARRAY['external'],
     TRUE, 5000.00, FALSE, NULL, 'high', 'active'),
     
    ('REVERSAL', 'Transaction Reversal', 'reversal',
     'Reversal of previous transaction',
     ARRAY['individual', 'business', 'merchant', 'system'],
     ARRAY['individual', 'business', 'merchant', 'system'],
     TRUE, 0.01, FALSE, NULL, 'critical', 'active'),

    -- Payment Types
    ('MERCHANT_PAYMENT', 'Merchant Payment', 'payment',
     'Payment to merchant for goods/services',
     ARRAY['individual', 'business'], ARRAY['merchant'],
     FALSE, 5000.00, TRUE, 12, 'normal', 'active'),
     
    ('BILL_PAYMENT', 'Bill Payment', 'payment',
     'Payment for utility bills and services',
     ARRAY['individual', 'business'], ARRAY['merchant', 'external'],
     FALSE, NULL, FALSE, NULL, 'normal', 'active'),
     
    ('AIRTIME_PURCHASE', 'Airtime Purchase', 'purchase',
     'Mobile airtime top-up',
     ARRAY['individual', 'business'], ARRAY['system'],
     FALSE, NULL, FALSE, NULL, 'low', 'active'),
     
    ('DATA_BUNDLE', 'Data Bundle Purchase', 'purchase',
     'Mobile data bundle purchase',
     ARRAY['individual', 'business'], ARRAY['system'],
     FALSE, NULL, FALSE, NULL, 'low', 'active'),

    -- Cash Operations
    ('CASH_IN', 'Cash In', 'cash',
     'Deposit cash into digital wallet',
     ARRAY['external'], ARRAY['individual', 'business'],
     FALSE, 5000.00, FALSE, NULL, 'normal', 'active'),
     
    ('CASH_OUT', 'Cash Out', 'cash',
     'Withdraw cash from digital wallet',
     ARRAY['individual', 'business'], ARRAY['external'],
     FALSE, 5000.00, FALSE, NULL, 'normal', 'active'),
     
    ('ATM_WITHDRAWAL', 'ATM Withdrawal', 'cash',
     'Withdraw cash from ATM using wallet',
     ARRAY['individual', 'business'], ARRAY['external'],
     FALSE, 1000.00, FALSE, NULL, 'normal', 'active'),

    -- System Operations
    ('FEE', 'Transaction Fee', 'fee',
     'Fee charged for transaction processing',
     ARRAY['individual', 'business', 'merchant'], ARRAY['system'],
     FALSE, NULL, FALSE, NULL, 'low', 'active'),
     
    ('ADJUSTMENT', 'Account Adjustment', 'adjustment',
     'Manual account adjustment by admin',
     ARRAY['system'], ARRAY['individual', 'business', 'merchant'],
     TRUE, 0.01, FALSE, NULL, 'critical', 'active'),
     
    ('REFUND', 'Refund', 'refund',
     'Refund of previous payment',
     ARRAY['merchant', 'system'], ARRAY['individual', 'business'],
     TRUE, 100.00, FALSE, NULL, 'high', 'active'),

    -- Batch Operations
    ('BULK_TRANSFER', 'Bulk Transfer', 'bulk',
     'Transfer to multiple recipients',
     ARRAY['business'], ARRAY['individual', 'business'],
     TRUE, 10000.00, FALSE, NULL, 'high', 'active'),
     
    ('SALARY_PAYMENT', 'Salary Payment', 'bulk',
     'Bulk salary disbursement',
     ARRAY['business'], ARRAY['individual'],
     TRUE, 50000.00, FALSE, NULL, 'high', 'active'),

    -- Rewards and Incentives
    ('CASHBACK', 'Cashback', 'reward',
     'Cashback reward to user',
     ARRAY['system'], ARRAY['individual', 'business'],
     FALSE, NULL, FALSE, NULL, 'low', 'active'),
     
    ('BONUS', 'Bonus Credit', 'reward',
     'Promotional bonus credit',
     ARRAY['system'], ARRAY['individual', 'business'],
     FALSE, NULL, FALSE, NULL, 'low', 'active')

ON CONFLICT (type_code) DO UPDATE SET
    type_name = EXCLUDED.type_name,
    description = EXCLUDED.description,
    requires_approval = EXCLUDED.requires_approval,
    is_reversible = EXCLUDED.is_reversible;

-- ============================================================================
-- FEE STRUCTURES TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS fee_structures (
    fee_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_type_code VARCHAR(50) NOT NULL REFERENCES transaction_types(type_code) ON DELETE CASCADE,
    fee_name VARCHAR(100) NOT NULL,
    fee_category VARCHAR(50) NOT NULL DEFAULT 'standard',
    
    -- Fee calculation method
    calculation_method VARCHAR(20) NOT NULL DEFAULT 'percentage', -- percentage, flat, tiered, hybrid
    percentage_rate DECIMAL(10, 6),
    flat_amount DECIMAL(18, 4),
    minimum_fee DECIMAL(18, 4) DEFAULT 0,
    maximum_fee DECIMAL(18, 4),
    
    -- Currency and region
    currency_code VARCHAR(3) DEFAULT 'USD',
    region_code VARCHAR(10) DEFAULT 'GLOBAL', -- GLOBAL, specific country codes, or region names
    
    -- Amount thresholds
    applicable_min_amount DECIMAL(18, 4),
    applicable_max_amount DECIMAL(18, 4),
    
    -- Priority and overrides
    priority INTEGER DEFAULT 0, -- Higher priority wins when multiple fees match
    is_default BOOLEAN DEFAULT FALSE,
    
    -- Status and validity
    status VARCHAR(20) DEFAULT 'active',
    valid_from TIMESTAMPTZ DEFAULT NOW(),
    valid_until TIMESTAMPTZ,
    
    -- Metadata
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID,
    
    -- Constraints
    CONSTRAINT valid_calculation_method CHECK (calculation_method IN ('percentage', 'flat', 'tiered', 'hybrid')),
    CONSTRAINT valid_fee_status CHECK (status IN ('active', 'inactive', 'deprecated')),
    CONSTRAINT positive_percentage CHECK (percentage_rate IS NULL OR (percentage_rate >= 0 AND percentage_rate <= 100)),
    CONSTRAINT valid_fee_range CHECK (minimum_fee IS NULL OR maximum_fee IS NULL OR minimum_fee <= maximum_fee)
);

-- Create indexes for efficient fee lookups
CREATE INDEX IF NOT EXISTS idx_fee_structures_type ON fee_structures(transaction_type_code);
CREATE INDEX IF NOT EXISTS idx_fee_structures_region ON fee_structures(region_code);
CREATE INDEX IF NOT EXISTS idx_fee_structures_currency ON fee_structures(currency_code);
CREATE INDEX IF NOT EXISTS idx_fee_structures_status ON fee_structures(status, valid_from, valid_until);
CREATE INDEX IF NOT EXISTS idx_fee_structures_default ON fee_structures(transaction_type_code, is_default) WHERE is_default = TRUE;

-- ============================================================================
-- FEE STRUCTURE SEED DATA
-- ============================================================================

INSERT INTO fee_structures (
    transaction_type_code, fee_name, fee_category, calculation_method,
    percentage_rate, flat_amount, minimum_fee, maximum_fee,
    currency_code, region_code, applicable_min_amount, applicable_max_amount,
    is_default, priority, status, description
) VALUES
    -- P2P Transfer Fees
    ('P2P_TRANSFER', 'P2P Standard Fee', 'standard', 'percentage', 1.000000, NULL, 0.50, 50.00, 'USD', 'GLOBAL', 0.01, NULL, TRUE, 0, 'active', 'Standard P2P transfer fee'),
    ('P2P_TRANSFER', 'P2P Flat Fee', 'flat', 'flat', NULL, 2.00, NULL, NULL, 'USD', 'GLOBAL', 0.01, 200.00, FALSE, 1, 'active', 'Flat fee option for small transfers'),

    -- Bank Transfer Fees
    ('BANK_TRANSFER', 'Bank Transfer Standard', 'standard', 'percentage', 1.500000, NULL, 2.00, 100.00, 'USD', 'GLOBAL', 0.01, NULL, TRUE, 0, 'active', 'Standard bank transfer fee'),
    ('BANK_TRANSFER', 'Bank Transfer Express', 'express', 'percentage', 2.500000, NULL, 5.00, 200.00, 'USD', 'GLOBAL', 0.01, NULL, FALSE, 1, 'active', 'Express bank transfer with faster processing'),

    -- International Transfer Fees
    ('INTERNATIONAL_TRANSFER', 'Intl Transfer Standard', 'standard', 'hybrid', 2.000000, 15.00, 25.00, 500.00, 'USD', 'GLOBAL', 0.01, NULL, TRUE, 0, 'active', 'Standard international transfer fee'),
    ('INTERNATIONAL_TRANSFER', 'Intl Transfer Economy', 'economy', 'percentage', 1.500000, NULL, 20.00, 300.00, 'USD', 'GLOBAL', 1000.00, NULL, FALSE, 1, 'active', 'Economy international transfer'),

    -- Cash Operations Fees
    ('CASH_IN', 'Cash In Free', 'standard', 'flat', NULL, 0.00, NULL, NULL, 'USD', 'GLOBAL', 0.01, NULL, TRUE, 0, 'active', 'Free cash deposits'),
    ('CASH_OUT', 'Cash Out Standard', 'standard', 'percentage', 1.000000, NULL, 1.00, 50.00, 'USD', 'GLOBAL', 0.01, NULL, TRUE, 0, 'active', 'Standard cash withdrawal fee'),
    ('ATM_WITHDRAWAL', 'ATM Withdrawal Fee', 'standard', 'flat', NULL, 2.50, NULL, NULL, 'USD', 'GLOBAL', 0.01, NULL, TRUE, 0, 'active', 'ATM withdrawal convenience fee'),

    -- Merchant Payment Fees (paid by merchant)
    ('MERCHANT_PAYMENT', 'Merchant Fee Standard', 'merchant', 'percentage', 2.500000, NULL, 0.50, NULL, 'USD', 'GLOBAL', 0.01, NULL, TRUE, 0, 'active', 'Standard merchant processing fee'),
    ('MERCHANT_PAYMENT', 'Merchant Fee Premium', 'merchant', 'percentage', 1.800000, NULL, 0.50, NULL, 'USD', 'GLOBAL', 1000.00, NULL, FALSE, 1, 'active', 'Discounted rate for high volume merchants'),

    -- Bill Payment Fees
    ('BILL_PAYMENT', 'Bill Payment Free', 'standard', 'flat', NULL, 0.00, NULL, NULL, 'USD', 'GLOBAL', 0.01, NULL, TRUE, 0, 'active', 'Free bill payments for users'),
    ('BILL_PAYMENT', 'Bill Payment Express', 'express', 'flat', NULL, 2.00, NULL, NULL, 'USD', 'GLOBAL', 0.01, NULL, FALSE, 1, 'active', 'Express bill payment with instant posting'),

    -- Airtime Purchase Fees
    ('AIRTIME_PURCHASE', 'Airtime Standard', 'standard', 'percentage', 3.000000, NULL, 0.10, 5.00, 'USD', 'GLOBAL', 0.01, NULL, TRUE, 0, 'active', 'Airtime purchase commission'),
    ('DATA_BUNDLE', 'Data Bundle Standard', 'standard', 'percentage', 3.000000, NULL, 0.10, 5.00, 'USD', 'GLOBAL', 0.01, NULL, TRUE, 0, 'active', 'Data bundle purchase commission'),

    -- Reversal Fee (charged for reversals)
    ('REVERSAL', 'Reversal Fee', 'penalty', 'flat', NULL, 5.00, NULL, NULL, 'USD', 'GLOBAL', 0.01, NULL, TRUE, 0, 'active', 'Fee charged for transaction reversals'),

    -- Adjustment Fee
    ('ADJUSTMENT', 'Adjustment Fee', 'admin', 'flat', NULL, 0.00, NULL, NULL, 'USD', 'GLOBAL', 0.01, NULL, TRUE, 0, 'active', 'No fee for admin adjustments'),

    -- Bulk Transfer Fees
    ('BULK_TRANSFER', 'Bulk Transfer Standard', 'standard', 'tiered', 0.500000, NULL, 5.00, 500.00, 'USD', 'GLOBAL', 0.01, NULL, TRUE, 0, 'active', 'Reduced fee for bulk transfers'),
    ('SALARY_PAYMENT', 'Salary Payment Fee', 'bulk', 'flat', NULL, 0.50, NULL, NULL, 'USD', 'GLOBAL', 0.01, NULL, TRUE, 0, 'active', 'Per-recipient fee for salary payments')

ON CONFLICT DO NOTHING;

-- ============================================================================
-- REGIONAL FEE VARIATIONS
-- ============================================================================

CREATE TABLE IF NOT EXISTS fee_regional_overrides (
    override_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    base_fee_id UUID NOT NULL REFERENCES fee_structures(fee_id) ON DELETE CASCADE,
    region_code VARCHAR(10) NOT NULL,
    country_code VARCHAR(2),
    percentage_multiplier DECIMAL(5, 4) DEFAULT 1.0000,
    flat_adjustment DECIMAL(18, 4) DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    valid_from TIMESTAMPTZ DEFAULT NOW(),
    valid_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fee_regional_overrides_base ON fee_regional_overrides(base_fee_id);
CREATE INDEX IF NOT EXISTS idx_fee_regional_overrides_region ON fee_regional_overrides(region_code, country_code);

-- Insert sample regional overrides
INSERT INTO fee_regional_overrides (base_fee_id, region_code, country_code, percentage_multiplier, flat_adjustment)
SELECT 
    f.fee_id,
    'AFRICA',
    'KE',
    0.8000,
    -0.20
FROM fee_structures f
WHERE f.transaction_type_code = 'P2P_TRANSFER' AND f.is_default = TRUE
ON CONFLICT DO NOTHING;

-- ============================================================================
-- PROMOTIONAL FEE DISCOUNTS
-- ============================================================================

CREATE TABLE IF NOT EXISTS fee_promotional_discounts (
    discount_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    discount_code VARCHAR(50) UNIQUE NOT NULL,
    discount_name VARCHAR(100) NOT NULL,
    description TEXT,
    
    -- Discount configuration
    discount_type VARCHAR(20) NOT NULL, -- percentage_off, flat_off, free, custom
    discount_value DECIMAL(10, 6),
    maximum_discount_amount DECIMAL(18, 4),
    
    -- Applicability
    applicable_fee_ids UUID[],
    applicable_transaction_types TEXT[],
    applicable_user_types TEXT[],
    applicable_regions TEXT[],
    
    -- Campaign settings
    campaign_start TIMESTAMPTZ NOT NULL,
    campaign_end TIMESTAMPTZ,
    usage_limit_total INTEGER,
    usage_limit_per_user INTEGER DEFAULT 1,
    current_usage_count INTEGER DEFAULT 0,
    
    -- Eligibility criteria
    minimum_transaction_amount DECIMAL(18, 4),
    maximum_transaction_amount DECIMAL(18, 4),
    required_user_tier VARCHAR(20),
    
    -- Status
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID,
    
    CONSTRAINT valid_discount_type CHECK (discount_type IN ('percentage_off', 'flat_off', 'free', 'custom')),
    CONSTRAINT valid_discount_status CHECK (status IN ('active', 'paused', 'expired', 'completed'))
);

CREATE INDEX IF NOT EXISTS idx_fee_promo_discounts_status ON fee_promotional_discounts(status, campaign_start, campaign_end);
CREATE INDEX IF NOT EXISTS idx_fee_promo_discounts_code ON fee_promotional_discounts(discount_code);

-- Insert sample promotional discounts
INSERT INTO fee_promotional_discounts (
    discount_code, discount_name, description, discount_type, discount_value,
    applicable_transaction_types, campaign_start, campaign_end,
    usage_limit_total, usage_limit_per_user, status
) VALUES
    ('WELCOME2024', 'Welcome Discount', '50% off fees for new users first month', 'percentage_off', 50.000000, 
     ARRAY['P2P_TRANSFER', 'CASH_OUT'], NOW(), NOW() + INTERVAL '30 days', 10000, 5, 'active'),
    ('FREEFRIDAY', 'Free Friday', 'No fees on Fridays', 'free', 100.000000,
     ARRAY['P2P_TRANSFER'], NOW(), NOW() + INTERVAL '90 days', 50000, 3, 'active')
ON CONFLICT (discount_code) DO NOTHING;

-- ============================================================================
-- LOYALTY PROGRAM FEE DISCOUNTS
-- ============================================================================

CREATE TABLE IF NOT EXISTS fee_loyalty_tiers (
    tier_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tier_name VARCHAR(50) NOT NULL UNIQUE,
    tier_level INTEGER NOT NULL,
    
    -- Qualification criteria
    min_monthly_transactions INTEGER,
    min_monthly_volume DECIMAL(18, 4),
    min_account_age_months INTEGER,
    
    -- Fee discounts
    fee_discount_percentage DECIMAL(5, 2) DEFAULT 0,
    fee_discount_flat DECIMAL(18, 4) DEFAULT 0,
    
    -- Additional benefits
    free_transactions_per_month INTEGER DEFAULT 0,
    priority_processing BOOLEAN DEFAULT FALSE,
    dedicated_support BOOLEAN DEFAULT FALSE,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert loyalty tiers
INSERT INTO fee_loyalty_tiers (
    tier_name, tier_level, min_monthly_transactions, min_monthly_volume,
    fee_discount_percentage, free_transactions_per_month, priority_processing, dedicated_support
) VALUES
    ('Bronze', 1, 0, 0, 0.00, 0, FALSE, FALSE),
    ('Silver', 2, 5, 500.00, 10.00, 2, FALSE, FALSE),
    ('Gold', 3, 10, 2000.00, 25.00, 5, TRUE, FALSE),
    ('Platinum', 4, 20, 10000.00, 50.00, 10, TRUE, TRUE)
ON CONFLICT (tier_name) DO NOTHING;

-- ============================================================================
-- MERCHANT-SPECIFIC FEE NEGOTIATION TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS fee_merchant_negotiations (
    negotiation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL,
    fee_structure_id UUID NOT NULL REFERENCES fee_structures(fee_id) ON DELETE CASCADE,
    
    -- Negotiated rates
    negotiated_percentage_rate DECIMAL(10, 6),
    negotiated_flat_amount DECIMAL(18, 4),
    negotiated_minimum_fee DECIMAL(18, 4),
    negotiated_maximum_fee DECIMAL(18, 4),
    
    -- Agreement terms
    agreement_start_date TIMESTAMPTZ NOT NULL,
    agreement_end_date TIMESTAMPTZ,
    monthly_minimum_guarantee DECIMAL(18, 4),
    volume_commitment DECIMAL(18, 4),
    
    -- Contract details
    contract_reference VARCHAR(100),
    approved_by UUID,
    approval_date TIMESTAMPTZ,
    
    -- Status
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    CONSTRAINT valid_negotiation_status CHECK (status IN ('pending', 'active', 'expired', 'terminated')),
    CONSTRAINT valid_negotiation_dates CHECK (agreement_end_date IS NULL OR agreement_end_date > agreement_start_date)
);

CREATE INDEX IF NOT EXISTS idx_fee_merchant_merchant ON fee_merchant_negotiations(merchant_id);
CREATE INDEX IF NOT EXISTS idx_fee_merchant_status ON fee_merchant_negotiations(status, agreement_start_date, agreement_end_date);

-- ============================================================================
-- FEE CALCULATION FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION calculate_transaction_fee(
    p_transaction_type VARCHAR(50),
    p_amount DECIMAL(18, 4),
    p_currency_code VARCHAR(3) DEFAULT 'USD',
    p_region_code VARCHAR(10) DEFAULT 'GLOBAL',
    p_user_id UUID DEFAULT NULL,
    p_merchant_id UUID DEFAULT NULL,
    p_discount_code VARCHAR(50) DEFAULT NULL
)
RETURNS TABLE (
    base_fee DECIMAL(18, 4),
    discount_amount DECIMAL(18, 4),
    final_fee DECIMAL(18, 4),
    fee_breakdown JSONB
) AS $$
DECLARE
    v_fee_structure RECORD;
    v_discount RECORD;
    v_negotiated_rate RECORD;
    v_base_fee DECIMAL(18, 4) := 0;
    v_discount_amount DECIMAL(18, 4) := 0;
    v_final_fee DECIMAL(18, 4) := 0;
    v_breakdown JSONB;
BEGIN
    -- Get applicable fee structure
    SELECT * INTO v_fee_structure
    FROM fee_structures
    WHERE transaction_type_code = p_transaction_type
      AND currency_code = p_currency_code
      AND (region_code = p_region_code OR region_code = 'GLOBAL')
      AND status = 'active'
      AND valid_from <= NOW()
      AND (valid_until IS NULL OR valid_until > NOW())
      AND (applicable_min_amount IS NULL OR p_amount >= applicable_min_amount)
      AND (applicable_max_amount IS NULL OR p_amount <= applicable_max_amount)
    ORDER BY 
        CASE WHEN region_code = p_region_code THEN 1 ELSE 2 END,
        priority DESC
    LIMIT 1;
    
    IF v_fee_structure IS NULL THEN
        RETURN QUERY SELECT 0::DECIMAL, 0::DECIMAL, 0::DECIMAL, '{}'::JSONB;
        RETURN;
    END IF;
    
    -- Calculate base fee
    CASE v_fee_structure.calculation_method
        WHEN 'percentage' THEN
            v_base_fee := p_amount * (v_fee_structure.percentage_rate / 100);
        WHEN 'flat' THEN
            v_base_fee := v_fee_structure.flat_amount;
        WHEN 'hybrid' THEN
            v_base_fee := GREATEST(
                v_fee_structure.flat_amount,
                p_amount * (v_fee_structure.percentage_rate / 100)
            );
        WHEN 'tiered' THEN
            -- Simplified tiered calculation
            v_base_fee := p_amount * (v_fee_structure.percentage_rate / 100);
    END CASE;
    
    -- Apply min/max bounds
    IF v_fee_structure.minimum_fee IS NOT NULL THEN
        v_base_fee := GREATEST(v_base_fee, v_fee_structure.minimum_fee);
    END IF;
    IF v_fee_structure.maximum_fee IS NOT NULL THEN
        v_base_fee := LEAST(v_base_fee, v_fee_structure.maximum_fee);
    END IF;
    
    -- Check for merchant negotiated rates
    IF p_merchant_id IS NOT NULL THEN
        SELECT * INTO v_negotiated_rate
        FROM fee_merchant_negotiations
        WHERE merchant_id = p_merchant_id
          AND fee_structure_id = v_fee_structure.fee_id
          AND status = 'active'
          AND agreement_start_date <= NOW()
          AND (agreement_end_date IS NULL OR agreement_end_date > NOW());
        
        IF v_negotiated_rate IS NOT NULL THEN
            IF v_negotiated_rate.negotiated_percentage_rate IS NOT NULL THEN
                v_base_fee := p_amount * (v_negotiated_rate.negotiated_percentage_rate / 100);
            ELSIF v_negotiated_rate.negotiated_flat_amount IS NOT NULL THEN
                v_base_fee := v_negotiated_rate.negotiated_flat_amount;
            END IF;
            
            IF v_negotiated_rate.negotiated_minimum_fee IS NOT NULL THEN
                v_base_fee := GREATEST(v_base_fee, v_negotiated_rate.negotiated_minimum_fee);
            END IF;
            IF v_negotiated_rate.negotiated_maximum_fee IS NOT NULL THEN
                v_base_fee := LEAST(v_base_fee, v_negotiated_rate.negotiated_maximum_fee);
            END IF;
        END IF;
    END IF;
    
    -- Apply promotional discount if code provided
    IF p_discount_code IS NOT NULL THEN
        SELECT * INTO v_discount
        FROM fee_promotional_discounts
        WHERE discount_code = p_discount_code
          AND status = 'active'
          AND campaign_start <= NOW()
          AND (campaign_end IS NULL OR campaign_end > NOW())
          AND (usage_limit_total IS NULL OR current_usage_count < usage_limit_total)
          AND (applicable_transaction_types IS NULL OR p_transaction_type = ANY(applicable_transaction_types))
        LIMIT 1;
        
        IF v_discount IS NOT NULL THEN
            CASE v_discount.discount_type
                WHEN 'percentage_off' THEN
                    v_discount_amount := v_base_fee * (v_discount.discount_value / 100);
                WHEN 'flat_off' THEN
                    v_discount_amount := LEAST(v_base_fee, v_discount.discount_value);
                WHEN 'free' THEN
                    v_discount_amount := v_base_fee;
            END CASE;
            
            IF v_discount.maximum_discount_amount IS NOT NULL THEN
                v_discount_amount := LEAST(v_discount_amount, v_discount.maximum_discount_amount);
            END IF;
        END IF;
    END IF;
    
    v_final_fee := GREATEST(0, v_base_fee - v_discount_amount);
    
    -- Build breakdown
    v_breakdown := jsonb_build_object(
        'fee_structure_id', v_fee_structure.fee_id,
        'calculation_method', v_fee_structure.calculation_method,
        'base_amount', p_amount,
        'applied_discount_code', p_discount_code,
        'merchant_negotiated', v_negotiated_rate IS NOT NULL
    );
    
    RETURN QUERY SELECT v_base_fee, v_discount_amount, v_final_fee, v_breakdown;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- FEE SIMULATION FUNCTION (for transaction preview)
-- ============================================================================

CREATE OR REPLACE FUNCTION simulate_transaction_fees(
    p_transaction_type VARCHAR(50),
    p_amount DECIMAL(18, 4),
    p_currency_code VARCHAR(3) DEFAULT 'USD',
    p_region_code VARCHAR(10) DEFAULT 'GLOBAL'
)
RETURNS TABLE (
    scenario_name TEXT,
    base_fee DECIMAL(18, 4),
    discount_amount DECIMAL(18, 4),
    final_fee DECIMAL(18, 4),
    total_amount DECIMAL(18, 4)
) AS $$
BEGIN
    -- Standard scenario
    RETURN QUERY
    SELECT 
        'Standard'::TEXT,
        (calculate_transaction_fee(p_transaction_type, p_amount, p_currency_code, p_region_code)).base_fee,
        (calculate_transaction_fee(p_transaction_type, p_amount, p_currency_code, p_region_code)).discount_amount,
        (calculate_transaction_fee(p_transaction_type, p_amount, p_currency_code, p_region_code)).final_fee,
        p_amount + (calculate_transaction_fee(p_transaction_type, p_amount, p_currency_code, p_region_code)).final_fee;
    
    -- With best available discount
    RETURN QUERY
    SELECT 
        'With Best Discount'::TEXT,
        (calculate_transaction_fee(p_transaction_type, p_amount, p_currency_code, p_region_code, NULL, NULL, 
            (SELECT discount_code FROM fee_promotional_discounts 
             WHERE status = 'active' AND applicable_transaction_types @> ARRAY[p_transaction_type]
             ORDER BY discount_value DESC LIMIT 1)
        )).base_fee,
        (calculate_transaction_fee(p_transaction_type, p_amount, p_currency_code, p_region_code, NULL, NULL, 
            (SELECT discount_code FROM fee_promotional_discounts 
             WHERE status = 'active' AND applicable_transaction_types @> ARRAY[p_transaction_type]
             ORDER BY discount_value DESC LIMIT 1)
        )).discount_amount,
        (calculate_transaction_fee(p_transaction_type, p_amount, p_currency_code, p_region_code, NULL, NULL, 
            (SELECT discount_code FROM fee_promotional_discounts 
             WHERE status = 'active' AND applicable_transaction_types @> ARRAY[p_transaction_type]
             ORDER BY discount_value DESC LIMIT 1)
        )).final_fee,
        p_amount + (calculate_transaction_fee(p_transaction_type, p_amount, p_currency_code, p_region_code, NULL, NULL, 
            (SELECT discount_code FROM fee_promotional_discounts 
             WHERE status = 'active' AND applicable_transaction_types @> ARRAY[p_transaction_type]
             ORDER BY discount_value DESC LIMIT 1)
        )).final_fee;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE transaction_types IS 'ISO/IEC 27001: Defines all supported transaction types and their properties';
COMMENT ON TABLE fee_structures IS 'PCI DSS: Fee configuration for each transaction type';
COMMENT ON TABLE fee_regional_overrides IS 'Regional fee variations for different markets';
COMMENT ON TABLE fee_promotional_discounts IS 'Campaign-based promotional fee discounts';
COMMENT ON TABLE fee_loyalty_tiers IS 'Loyalty program fee discount tiers';
COMMENT ON TABLE fee_merchant_negotiations IS 'Merchant-specific negotiated fee rates';
COMMENT ON FUNCTION calculate_transaction_fee IS 'Real-time fee calculation API with discount support';
COMMENT ON FUNCTION simulate_transaction_fees IS 'Fee simulation for transaction preview';

-- ============================================================================
-- IMPLEMENTATION COMPLETE
-- ============================================================================
