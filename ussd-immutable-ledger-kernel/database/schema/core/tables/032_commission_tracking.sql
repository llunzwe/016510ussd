-- =============================================================================
-- USSD KERNEL CORE SCHEMA - COMMISSION TRACKING
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    032_commission_tracking.sql
-- SCHEMA:      ussd_core
-- TABLE:       commission_schedules, commission_transactions
-- DESCRIPTION: Commission and override tracking for agents, merchants,
--              and referrers with tiered and conditional structures.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Commission calculation monitoring
├── A.18.1 Compliance - Revenue recognition
└── A.18.2 Compliance - Agent compensation audit

Financial Regulations
├── Agent banking: Commission disclosure requirements
├── Tax: Withholding tax on commissions
├── Revenue recognition: Matching principle
└── Audit: Commission verification

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. COMMISSION TYPES
   - FLAT: Fixed amount per transaction
   - PERCENTAGE: Percentage of transaction/revenue
   - TIERED: Different rates based on volume
   - HYBRID: Combination of flat + percentage
   - OVERRIDE: Override on downline commissions

2. COMMISSION RECIPIENTS
   - AGENT: Transaction agent
   - REFERRER: Account referrer
   - MASTER_AGENT: Parent agent
   - MERCHANT: Merchant acquiring
   - PARTNER: Strategic partner

3. CALCULATION BASES
   - TRANSACTION_AMOUNT: Gross transaction amount
   - FEE_AMOUNT: Fee revenue
   - INTEREST: Interest income
   - SPREAD: FX spread

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

COMMISSION SECURITY:
- Immutable calculation records
- Approval workflow for adjustments
- Audit trail for disputes

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: schedule_id, commission_id
- RECIPIENT: recipient_id + recipient_type
- TRANSACTION: source_transaction_id
- STATUS: payment_status

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- COMMISSION_CALCULATED
- COMMISSION_POSTED
- COMMISSION_PAID
- COMMISSION_DISPUTED

RETENTION: 7 years
================================================================================
*/

-- -----------------------------------------------------------------------------
-- CREATE TABLE: commission_schedules
-- -----------------------------------------------------------------------------
CREATE TABLE core.commission_schedules (
    -- Primary identifier
    schedule_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    schedule_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Commission classification
    commission_code VARCHAR(50) NOT NULL,
    commission_name VARCHAR(200) NOT NULL,
    commission_description TEXT,
    commission_type VARCHAR(20) NOT NULL
        CHECK (commission_type IN ('FLAT', 'PERCENTAGE', 'TIERED', 'HYBRID', 'OVERRIDE')),
    commission_category VARCHAR(50) NOT NULL
        CHECK (commission_category IN ('AGENT', 'REFERRER', 'MASTER_AGENT', 'MERCHANT', 'PARTNER', 'EMPLOYEE')),
    
    -- Commission calculation
    flat_amount NUMERIC(20, 8),
    percentage_rate NUMERIC(10, 6),
    percentage_basis VARCHAR(50)
        CHECK (percentage_basis IN ('TRANSACTION_AMOUNT', 'FEE_AMOUNT', 'INTEREST', 'SPREAD', 'PROFIT')),
    minimum_commission NUMERIC(20, 8) DEFAULT 0,
    maximum_commission NUMERIC(20, 8),
    
    -- Tiered configuration
    tier_configuration JSONB,  -- [{min_volume, max_volume, flat_amount, percentage}, ...]
    
    -- Override configuration (for master agents)
    override_percentage NUMERIC(10, 6),  -- Percentage of downline commission
    override_levels INTEGER DEFAULT 1,  -- How many levels deep
    
    -- Applicability
    applicable_transaction_types VARCHAR(50)[],
    applicable_merchant_categories VARCHAR(50)[],
    minimum_transaction_amount NUMERIC(20, 8) DEFAULT 0,
    maximum_transaction_amount NUMERIC(20, 8),
    
    -- Recipient requirements
    recipient_type VARCHAR(50) NOT NULL
        CHECK (recipient_type IN ('AGENT', 'MERCHANT', 'INDIVIDUAL', 'CORPORATE')),
    recipient_tier VARCHAR(20),  -- Bronze, Silver, Gold, etc.
    
    -- Payment terms
    payment_frequency VARCHAR(20) DEFAULT 'IMMEDIATE'
        CHECK (payment_frequency IN ('IMMEDIATE', 'DAILY', 'WEEKLY', 'MONTHLY', 'QUARTERLY')),
    payment_delay_days INTEGER DEFAULT 0,
    minimum_payout_amount NUMERIC(20, 8) DEFAULT 0,
    
    -- Tax treatment
    is_taxable BOOLEAN DEFAULT TRUE,
    withholding_tax_rate NUMERIC(10, 6) DEFAULT 0,
    
    -- Application scope
    application_id UUID,
    
    -- Effective period
    effective_from DATE NOT NULL DEFAULT CURRENT_DATE,
    effective_until DATE,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    superseded_by UUID REFERENCES core.commission_schedules(schedule_id),
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- -----------------------------------------------------------------------------
-- INDEXES
-- -----------------------------------------------------------------------------
CREATE INDEX idx_commission_schedules_code 
    ON core.commission_schedules(commission_code, is_active);

CREATE INDEX idx_commission_schedules_category 
    ON core.commission_schedules(commission_category, recipient_type);

CREATE INDEX idx_commission_schedules_effective 
    ON core.commission_schedules(effective_from, effective_until) 
    WHERE is_active = TRUE;

CREATE INDEX idx_commission_schedules_app 
    ON core.commission_schedules(application_id, commission_category);

-- -----------------------------------------------------------------------------
-- CREATE TABLE: commission_transactions
-- -----------------------------------------------------------------------------
CREATE TABLE core.commission_transactions (
    -- Primary identifier
    commission_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    commission_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- References
    schedule_id UUID REFERENCES core.commission_schedules(schedule_id),
    source_transaction_id BIGINT,
    partition_date DATE,
    
    -- Recipient information
    recipient_id UUID NOT NULL REFERENCES core.account_registry(account_id),
    recipient_type VARCHAR(50) NOT NULL,
    recipient_tier VARCHAR(20),
    
    -- Source information (who/what generated the commission)
    source_account_id UUID,  -- Customer who did the transaction
    source_merchant_id UUID,  -- Merchant (if applicable)
    agent_id UUID,  -- Agent who processed
    parent_agent_id UUID,  -- Parent agent for override
    
    -- Commission calculation
    commission_type VARCHAR(20) NOT NULL,
    calculation_basis VARCHAR(50) NOT NULL,
    basis_amount NUMERIC(20, 8) NOT NULL,
    basis_currency VARCHAR(3) NOT NULL,
    
    -- Calculated amounts
    gross_commission NUMERIC(20, 8) NOT NULL,
    commission_currency VARCHAR(3) NOT NULL,
    withholding_tax NUMERIC(20, 8) DEFAULT 0,
    net_commission NUMERIC(20, 8) GENERATED ALWAYS AS (gross_commission - withholding_tax) STORED,
    
    -- Calculation details
    calculation_details JSONB,  -- {rate_applied, tier_band, override_level, ...}
    
    -- Payment status
    payment_status VARCHAR(20) DEFAULT 'CALCULATED'
        CHECK (payment_status IN ('CALCULATED', 'APPROVED', 'PENDING_PAYMENT', 'PAID', 'HELD', 'REVERSED')),
    held_reason VARCHAR(100),
    approved_at TIMESTAMPTZ,
    approved_by UUID,
    paid_at TIMESTAMPTZ,
    paid_transaction_id BIGINT,
    payment_reference VARCHAR(100),
    
    -- Clawback/Chargeback
    is_clawback BOOLEAN DEFAULT FALSE,
    clawback_reason VARCHAR(100),
    original_commission_id UUID REFERENCES core.commission_transactions(commission_id),
    
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
CREATE INDEX idx_commission_trans_recipient 
    ON core.commission_transactions(recipient_id, payment_status);

CREATE INDEX idx_commission_trans_schedule 
    ON core.commission_transactions(schedule_id, calculated_at);

CREATE INDEX idx_commission_trans_source 
    ON core.commission_transactions(source_transaction_id, partition_date);

CREATE INDEX idx_commission_trans_status 
    ON core.commission_transactions(payment_status, calculated_at) 
    WHERE payment_status IN ('CALCULATED', 'APPROVED', 'PENDING_PAYMENT');

CREATE INDEX idx_commission_trans_agent 
    ON core.commission_transactions(agent_id, calculated_at DESC);

CREATE INDEX idx_commission_trans_parent 
    ON core.commission_transactions(parent_agent_id, payment_status) 
    WHERE parent_agent_id IS NOT NULL;

-- -----------------------------------------------------------------------------
-- IMMUTABILITY TRIGGERS
-- -----------------------------------------------------------------------------
CREATE TRIGGER trg_commission_schedules_prevent_update
    BEFORE UPDATE ON core.commission_schedules
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_commission_schedules_prevent_delete
    BEFORE DELETE ON core.commission_schedules
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

CREATE TRIGGER trg_commission_trans_prevent_update
    BEFORE UPDATE ON core.commission_transactions
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_commission_trans_prevent_delete
    BEFORE DELETE ON core.commission_transactions
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- -----------------------------------------------------------------------------
-- HASH COMPUTATION TRIGGERS
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION core.compute_commission_schedule_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.schedule_id::TEXT || 
        NEW.schedule_reference || 
        NEW.commission_code ||
        NEW.commission_type ||
        NEW.commission_category ||
        COALESCE(NEW.flat_amount::TEXT, '') ||
        COALESCE(NEW.percentage_rate::TEXT, '') ||
        NEW.effective_from::TEXT ||
        NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_commission_schedules_compute_hash
    BEFORE INSERT ON core.commission_schedules
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_commission_schedule_hash();

CREATE OR REPLACE FUNCTION core.compute_commission_trans_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.commission_id::TEXT || 
        NEW.commission_reference || 
        NEW.recipient_id::TEXT ||
        NEW.schedule_id::TEXT ||
        NEW.basis_amount::TEXT ||
        NEW.gross_commission::TEXT ||
        NEW.calculated_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_commission_trans_compute_hash
    BEFORE INSERT ON core.commission_transactions
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_commission_trans_hash();

-- -----------------------------------------------------------------------------
-- HELPER FUNCTIONS
-- -----------------------------------------------------------------------------

-- Function to calculate commission
CREATE OR REPLACE FUNCTION core.calculate_commission(
    p_schedule_id UUID,
    p_basis_amount NUMERIC,
    p_currency VARCHAR(3),
    p_recipient_tier VARCHAR DEFAULT NULL,
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
    v_tier_found BOOLEAN := FALSE;
    v_tax NUMERIC := 0;
BEGIN
    -- Get schedule
    SELECT * INTO v_schedule 
    FROM core.commission_schedules 
    WHERE schedule_id = p_schedule_id AND is_active = TRUE;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Commission schedule % not found or inactive', p_schedule_id;
    END IF;
    
    -- Calculate commission based on type
    CASE v_schedule.commission_type
        WHEN 'FLAT' THEN
            v_commission := v_schedule.flat_amount;
            v_details := jsonb_build_object(
                'type', 'FLAT',
                'flat_amount', v_schedule.flat_amount
            );
            
        WHEN 'PERCENTAGE' THEN
            v_commission := ROUND(p_basis_amount * (v_schedule.percentage_rate / 100), 8);
            v_details := jsonb_build_object(
                'type', 'PERCENTAGE',
                'basis_amount', p_basis_amount,
                'rate', v_schedule.percentage_rate,
                'percentage_basis', v_schedule.percentage_basis
            );
            
        WHEN 'TIERED' THEN
            -- Find applicable tier based on monthly volume
            FOR v_tier IN SELECT * FROM jsonb_array_elements(v_schedule.tier_configuration)
            LOOP
                IF (v_tier->>'min_volume')::NUMERIC <= p_monthly_volume 
                   AND (v_tier->>'max_volume')::NUMERIC >= p_monthly_volume THEN
                    v_commission := COALESCE((v_tier->>'flat_amount')::NUMERIC, 0);
                    IF v_tier->>'percentage' IS NOT NULL THEN
                        v_commission := v_commission + ROUND(p_basis_amount * ((v_tier->>'percentage')::NUMERIC / 100), 8);
                    END IF;
                    v_tier_found := TRUE;
                    v_details := jsonb_build_object(
                        'type', 'TIERED',
                        'tier', v_tier,
                        'monthly_volume', p_monthly_volume,
                        'basis_amount', p_basis_amount
                    );
                    EXIT;
                END IF;
            END LOOP;
            
            IF NOT v_tier_found THEN
                -- Use first tier as default
                v_tier := v_schedule.tier_configuration->0;
                v_commission := COALESCE((v_tier->>'flat_amount')::NUMERIC, 0);
            END IF;
            
        WHEN 'HYBRID' THEN
            v_commission := COALESCE(v_schedule.flat_amount, 0);
            IF v_schedule.percentage_rate IS NOT NULL THEN
                v_commission := v_commission + ROUND(p_basis_amount * (v_schedule.percentage_rate / 100), 8);
            END IF;
            v_details := jsonb_build_object(
                'type', 'HYBRID',
                'flat_amount', v_schedule.flat_amount,
                'rate', v_schedule.percentage_rate,
                'basis_amount', p_basis_amount
            );
            
        WHEN 'OVERRIDE' THEN
            v_commission := ROUND(p_basis_amount * (v_schedule.override_percentage / 100), 8);
            v_details := jsonb_build_object(
                'type', 'OVERRIDE',
                'override_percentage', v_schedule.override_percentage,
                'override_levels', v_schedule.override_levels,
                'basis_amount', p_basis_amount
            );
            
        ELSE
            v_commission := 0;
            v_details := jsonb_build_object('type', 'UNKNOWN');
    END CASE;
    
    -- Apply min/max constraints
    IF v_schedule.minimum_commission IS NOT NULL AND v_commission < v_schedule.minimum_commission THEN
        v_commission := v_schedule.minimum_commission;
        v_details := v_details || jsonb_build_object('minimum_applied', true);
    END IF;
    
    IF v_schedule.maximum_commission IS NOT NULL AND v_commission > v_schedule.maximum_commission THEN
        v_commission := v_schedule.maximum_commission;
        v_details := v_details || jsonb_build_object('maximum_applied', true);
    END IF;
    
    -- Calculate withholding tax
    IF v_schedule.is_taxable AND v_schedule.withholding_tax_rate > 0 THEN
        v_tax := ROUND(v_commission * (v_schedule.withholding_tax_rate / 100), 8);
    END IF;
    
    RETURN QUERY SELECT v_commission, v_tax, v_commission - v_tax, v_details;
END;
$$;

-- Function to create commission transaction
CREATE OR REPLACE FUNCTION core.create_commission(
    p_schedule_id UUID,
    p_recipient_id UUID,
    p_basis_amount NUMERIC,
    p_currency VARCHAR(3),
    p_source_transaction_id BIGINT DEFAULT NULL,
    p_partition_date DATE DEFAULT NULL,
    p_agent_id UUID DEFAULT NULL,
    p_parent_agent_id UUID DEFAULT NULL,
    p_narrative VARCHAR DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_commission_id UUID;
    v_reference VARCHAR(100);
    v_calc_result RECORD;
    v_schedule RECORD;
BEGIN
    -- Get schedule
    SELECT * INTO v_schedule FROM core.commission_schedules WHERE schedule_id = p_schedule_id;
    
    -- Calculate commission
    SELECT * INTO v_calc_result 
    FROM core.calculate_commission(p_schedule_id, p_basis_amount, p_currency);
    
    -- Generate reference
    v_reference := 'COMM-' || TO_CHAR(CURRENT_DATE, 'YYYYMMDD') || '-' || SUBSTRING(MD5(RANDOM()::TEXT), 1, 6);
    
    INSERT INTO core.commission_transactions (
        commission_reference,
        schedule_id,
        source_transaction_id,
        partition_date,
        recipient_id,
        recipient_type,
        agent_id,
        parent_agent_id,
        commission_type,
        calculation_basis,
        basis_amount,
        basis_currency,
        gross_commission,
        commission_currency,
        withholding_tax,
        calculation_details,
        narrative
    ) VALUES (
        v_reference,
        p_schedule_id,
        p_source_transaction_id,
        p_partition_date,
        p_recipient_id,
        v_schedule.recipient_type,
        p_agent_id,
        p_parent_agent_id,
        v_schedule.commission_type,
        v_schedule.percentage_basis,
        p_basis_amount,
        p_currency,
        v_calc_result.gross_commission,
        p_currency,
        v_calc_result.withholding_tax,
        v_calc_result.calculation_details,
        p_narrative
    ) RETURNING commission_id INTO v_commission_id;
    
    -- If parent agent exists, create override commission
    IF p_parent_agent_id IS NOT NULL AND v_schedule.override_percentage > 0 THEN
        -- Recursive call would go here for multi-level
        NULL;
    END IF;
    
    RETURN v_commission_id;
END;
$$;

-- Function to get commission summary by recipient
CREATE OR REPLACE FUNCTION core.get_commission_summary(
    p_start_date DATE,
    p_end_date DATE,
    p_recipient_id UUID DEFAULT NULL
)
RETURNS TABLE (
    recipient_id UUID,
    recipient_type VARCHAR,
    commission_count BIGINT,
    total_basis_amount NUMERIC,
    total_gross_commission NUMERIC,
    total_withholding_tax NUMERIC,
    total_net_commission NUMERIC,
    paid_amount NUMERIC,
    pending_amount NUMERIC
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ct.recipient_id,
        ct.recipient_type,
        COUNT(*) as commission_count,
        SUM(ct.basis_amount) as total_basis_amount,
        SUM(ct.gross_commission) as total_gross_commission,
        SUM(ct.withholding_tax) as total_withholding_tax,
        SUM(ct.net_commission) as total_net_commission,
        SUM(CASE WHEN ct.payment_status = 'PAID' THEN ct.net_commission ELSE 0 END) as paid_amount,
        SUM(CASE WHEN ct.payment_status IN ('CALCULATED', 'APPROVED', 'PENDING_PAYMENT') 
                 THEN ct.net_commission ELSE 0 END) as pending_amount
    FROM core.commission_transactions ct
    WHERE ct.calculated_at::DATE BETWEEN p_start_date AND p_end_date
      AND (p_recipient_id IS NULL OR ct.recipient_id = p_recipient_id)
      AND ct.is_clawback = FALSE
    GROUP BY ct.recipient_id, ct.recipient_type
    ORDER BY total_net_commission DESC;
END;
$$;

-- Function to get agent commission statement
CREATE OR REPLACE FUNCTION core.get_agent_commission_statement(
    p_agent_id UUID,
    p_start_date DATE,
    p_end_date DATE
)
RETURNS TABLE (
    commission_date DATE,
    commission_reference VARCHAR,
    source_transaction_id BIGINT,
    basis_amount NUMERIC,
    commission_type VARCHAR,
    gross_commission NUMERIC,
    withholding_tax NUMERIC,
    net_commission NUMERIC,
    payment_status VARCHAR,
    narrative VARCHAR
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ct.calculated_at::DATE as commission_date,
        ct.commission_reference,
        ct.source_transaction_id,
        ct.basis_amount,
        ct.commission_type,
        ct.gross_commission,
        ct.withholding_tax,
        ct.net_commission,
        ct.payment_status,
        ct.narrative
    FROM core.commission_transactions ct
    WHERE ct.recipient_id = p_agent_id
      AND ct.calculated_at::DATE BETWEEN p_start_date AND p_end_date
      AND ct.is_clawback = FALSE
    ORDER BY ct.calculated_at;
END;
$$;

-- -----------------------------------------------------------------------------
-- INITIAL DATA: Sample commission schedules
-- -----------------------------------------------------------------------------
INSERT INTO core.commission_schedules (
    schedule_reference,
    commission_code,
    commission_name,
    commission_description,
    commission_type,
    commission_category,
    flat_amount,
    percentage_rate,
    percentage_basis,
    minimum_commission,
    payment_frequency,
    recipient_type,
    effective_from
) VALUES 
-- Agent cash-in commissions
('COMM-AGENT-CI', 'AGENT_CASH_IN', 'Agent Cash In Commission', 'Commission for cash deposit processing',
 'PERCENTAGE', 'AGENT', NULL, 0.50, 'TRANSACTION_AMOUNT', 0.10, 'DAILY', 'AGENT', '2026-01-01'),

-- Agent cash-out commissions
('COMM-AGENT-CO', 'AGENT_CASH_OUT', 'Agent Cash Out Commission', 'Commission for cash withdrawal processing',
 'PERCENTAGE', 'AGENT', NULL, 0.75, 'TRANSACTION_AMOUNT', 0.10, 'DAILY', 'AGENT', '2026-01-01'),

-- Merchant acquiring commission
('COMM-MERCH', 'MERCHANT_ACQUIRING', 'Merchant Commission', 'Commission for merchant payment processing',
 'PERCENTAGE', 'MERCHANT', NULL, 1.50, 'TRANSACTION_AMOUNT', 0, 'MONTHLY', 'MERCHANT', '2026-01-01'),

-- Referrer commission
('COMM-REF', 'REFERRAL', 'Referral Commission', 'Commission for new customer referral',
 'FLAT', 'REFERRER', 5.00, NULL, NULL, 5.00, 'MONTHLY', 'INDIVIDUAL', '2026-01-01'),

-- Master agent override
('COMM-MAST', 'MASTER_OVERRIDE', 'Master Agent Override', 'Override on downline agent commissions',
 'OVERRIDE', 'MASTER_AGENT', NULL, 20.00, 'TRANSACTION_AMOUNT', 0, 'MONTHLY', 'AGENT', '2026-01-01');

-- -----------------------------------------------------------------------------
-- COMMENTS
-- -----------------------------------------------------------------------------
COMMENT ON TABLE core.commission_schedules IS 'Commission schedule definitions for agents, merchants, and partners';
COMMENT ON TABLE core.commission_transactions IS 'Individual commission calculations and payments';
COMMENT ON COLUMN core.commission_transactions.gross_commission IS 'Commission before tax deductions';
COMMENT ON COLUMN core.commission_transactions.net_commission IS 'Commission after withholding tax';

-- =============================================================================
-- END OF FILE
-- =============================================================================
