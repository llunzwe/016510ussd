-- =============================================================================
-- USSD KERNEL APP SCHEMA - INTEREST ACCRUAL & AMORTIZATION
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    059_app_interest_amortization.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      app
-- DESCRIPTION: Interest calculation, accrual, and loan amortization schedules
--              for lending and savings products.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Interest accrual monitoring
├── A.18.1 Compliance - IFRS 9 interest recognition
└── A.18.2 Compliance - Audit trail for interest calculations

Financial Regulations
├── IFRS 9: Effective interest method
├── GAAP: Interest accrual requirements
├── Central Bank: Interest rate reporting
└── Consumer protection: Interest disclosure

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. INTEREST METHODS
   - SIMPLE: Interest on principal only
   - COMPOUND: Interest on principal + accrued interest
   - REDUCING_BALANCE: Interest on outstanding balance
   - FLAT: Fixed interest amount

2. AMORTIZATION METHODS
   - EMI: Equal monthly installments
   - STRAIGHT_LINE: Equal principal payments
   - BULLET: Principal at maturity
   - CUSTOM: Custom schedule

3. ACCRUAL FREQUENCY
   - DAILY
   - MONTHLY
   - QUARTERLY
   - ANNUAL

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

INTEREST SECURITY:
- Immutable accrual records
- Audit trail for rate changes
- Approval for manual adjustments

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- Loan accounts by status
- Accruals by date and account
- Schedules by loan

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- INTEREST_ACCRUED
- AMORTIZATION_SCHEDULED
- REPAYMENT_POSTED
- RATE_CHANGED

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- LOAN ACCOUNT MANAGEMENT
-- =============================================================================

CREATE TABLE app.loan_accounts (
    loan_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES app.t_application_registry(app_id) ON DELETE CASCADE,
    
    -- Link to core account
    account_id UUID NOT NULL REFERENCES core.account_registry(account_id),
    
    -- Loan details
    loan_reference VARCHAR(100) UNIQUE NOT NULL,
    loan_product VARCHAR(50) NOT NULL,
    
    -- Principal
    principal_amount NUMERIC(20, 8) NOT NULL,
    disbursed_amount NUMERIC(20, 8),
    currency_code VARCHAR(6) NOT NULL,
    
    -- Interest
    interest_rate NUMERIC(10, 6) NOT NULL,
    interest_method VARCHAR(20) NOT NULL 
        CHECK (interest_method IN ('SIMPLE', 'COMPOUND', 'REDUCING_BALANCE', 'FLAT')),
    interest_frequency VARCHAR(20) NOT NULL
        CHECK (interest_frequency IN ('DAILY', 'WEEKLY', 'MONTHLY', 'QUARTERLY', 'ANNUAL')),
    annual_percentage_rate NUMERIC(10, 6),
    
    -- Fees
    arrangement_fee NUMERIC(20, 8) DEFAULT 0,
    processing_fee NUMERIC(20, 8) DEFAULT 0,
    
    -- Tenure
    tenure_months INTEGER NOT NULL,
    start_date DATE,
    maturity_date DATE,
    
    -- Repayment
    repayment_frequency VARCHAR(20) DEFAULT 'MONTHLY'
        CHECK (repayment_frequency IN ('WEEKLY', 'BIWEEKLY', 'MONTHLY', 'QUARTERLY')),
    installment_amount NUMERIC(20, 8),
    
    -- Status
    status VARCHAR(20) DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'ACTIVE', 'PAUSED', 'DEFAULTED', 'CLOSED', 'WRITTEN_OFF')),
    
    -- Balances
    outstanding_principal NUMERIC(20, 8) DEFAULT 0,
    outstanding_interest NUMERIC(20, 8) DEFAULT 0,
    outstanding_fees NUMERIC(20, 8) DEFAULT 0,
    total_outstanding NUMERIC(20, 8) GENERATED ALWAYS AS 
        (outstanding_principal + outstanding_interest + outstanding_fees) STORED,
    
    -- Collateral
    collateral_amount NUMERIC(20, 8),
    collateral_type VARCHAR(50),
    
    -- Officer
    loan_officer_id UUID,
    branch_code VARCHAR(50),
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    approved_at TIMESTAMPTZ,
    approved_by UUID,
    disbursed_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ
);

-- =============================================================================
-- AMORTIZATION SCHEDULE
-- =============================================================================

CREATE TABLE app.amortization_schedule (
    schedule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    loan_id UUID NOT NULL REFERENCES app.loan_accounts(loan_id) ON DELETE CASCADE,
    
    -- Schedule details
    installment_number INTEGER NOT NULL,
    due_date DATE NOT NULL,
    
    -- Amounts
    opening_balance NUMERIC(20, 8) NOT NULL,
    principal_amount NUMERIC(20, 8) NOT NULL,
    interest_amount NUMERIC(20, 8) NOT NULL,
    fee_amount NUMERIC(20, 8) DEFAULT 0,
    total_installment NUMERIC(20, 8) NOT NULL,
    closing_balance NUMERIC(20, 8) NOT NULL,
    
    -- Status
    status VARCHAR(20) DEFAULT 'SCHEDULED'
        CHECK (status IN ('SCHEDULED', 'DUE', 'PARTIAL', 'PAID', 'OVERDUE', 'WAIVED')),
    
    -- Payment tracking
    paid_principal NUMERIC(20, 8) DEFAULT 0,
    paid_interest NUMERIC(20, 8) DEFAULT 0,
    paid_fees NUMERIC(20, 8) DEFAULT 0,
    paid_total NUMERIC(20, 8) DEFAULT 0,
    paid_at TIMESTAMPTZ,
    
    -- Core transaction link
    core_transaction_id BIGINT,
    partition_date DATE,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT uq_loan_installment UNIQUE (loan_id, installment_number)
);

-- =============================================================================
-- INTEREST ACCRUAL
-- =============================================================================

CREATE TABLE app.interest_accruals (
    accrual_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES app.t_application_registry(app_id) ON DELETE CASCADE,
    
    -- Account reference
    account_id UUID NOT NULL REFERENCES core.account_registry(account_id),
    loan_id UUID REFERENCES app.loan_accounts(loan_id),
    
    -- Accrual period
    accrual_date DATE NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    days_accrued INTEGER NOT NULL,
    
    -- Balance and rate
    principal_balance NUMERIC(20, 8) NOT NULL,
    interest_rate NUMERIC(10, 6) NOT NULL,
    annual_rate NUMERIC(10, 6) NOT NULL,
    
    -- Calculation
    interest_method VARCHAR(20) NOT NULL,
    day_count_convention VARCHAR(20) DEFAULT 'ACTUAL_365'
        CHECK (day_count_convention IN ('ACTUAL_365', 'ACTUAL_360', '30_360')),
    
    -- Amounts
    accrued_interest NUMERIC(20, 8) NOT NULL,
    currency_code VARCHAR(6) NOT NULL,
    
    -- Status
    status VARCHAR(20) DEFAULT 'ACCRUED'
        CHECK (status IN ('ACCRUED', 'POSTED', 'REVERSED', 'CAPITALIZED')),
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
-- LOAN REPAYMENTS
-- =============================================================================

CREATE TABLE app.loan_repayments (
    repayment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES app.t_application_registry(app_id) ON DELETE CASCADE,
    
    loan_id UUID NOT NULL REFERENCES app.loan_accounts(loan_id),
    
    -- Payment details
    repayment_reference VARCHAR(100) UNIQUE NOT NULL,
    repayment_date DATE NOT NULL,
    
    -- Amounts
    principal_paid NUMERIC(20, 8) NOT NULL DEFAULT 0,
    interest_paid NUMERIC(20, 8) NOT NULL DEFAULT 0,
    fees_paid NUMERIC(20, 8) NOT NULL DEFAULT 0,
    penalty_paid NUMERIC(20, 8) NOT NULL DEFAULT 0,
    total_paid NUMERIC(20, 8) NOT NULL,
    currency_code VARCHAR(6) NOT NULL,
    
    -- Allocation
    allocated_principal NUMERIC(20, 8) DEFAULT 0,
    allocated_interest NUMERIC(20, 8) DEFAULT 0,
    allocated_fees NUMERIC(20, 8) DEFAULT 0,
    
    -- Status
    status VARCHAR(20) DEFAULT 'RECEIVED'
        CHECK (status IN ('RECEIVED', 'ALLOCATED', 'REVERSED')),
    
    -- Core transaction link
    core_transaction_id BIGINT,
    partition_date DATE,
    
    -- Audit
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    received_by UUID,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Loan indexes
CREATE INDEX idx_loan_accounts_app ON app.loan_accounts(app_id, status);
CREATE INDEX idx_loan_accounts_account ON app.loan_accounts(account_id);
CREATE INDEX idx_loan_accounts_status ON app.loan_accounts(status, maturity_date);
CREATE INDEX idx_loan_accounts_officer ON app.loan_accounts(loan_officer_id, status);

-- Amortization indexes
CREATE INDEX idx_amortization_loan ON app.amortization_schedule(loan_id, installment_number);
CREATE INDEX idx_amortization_due ON app.amortization_schedule(due_date, status) 
    WHERE status IN ('SCHEDULED', 'DUE', 'OVERDUE');
CREATE INDEX idx_amortization_status ON app.amortization_schedule(status);

-- Interest accrual indexes
CREATE INDEX idx_interest_accruals_app ON app.interest_accruals(app_id, accrual_date);
CREATE INDEX idx_interest_accruals_account ON app.interest_accruals(account_id, accrual_date DESC);
CREATE INDEX idx_interest_accruals_loan ON app.interest_accruals(loan_id, accrual_date);
CREATE INDEX idx_interest_accruals_status ON app.interest_accruals(status, accrual_date) 
    WHERE status = 'ACCRUED';

-- Repayment indexes
CREATE INDEX idx_loan_repayments_app ON app.loan_repayments(app_id, repayment_date);
CREATE INDEX idx_loan_repayments_loan ON app.loan_repayments(loan_id, repayment_date DESC);
CREATE INDEX idx_loan_repayments_status ON app.loan_repayments(status);

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

ALTER TABLE app.loan_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.amortization_schedule ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.interest_accruals ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.loan_repayments ENABLE ROW LEVEL SECURITY;

-- Loan accounts
CREATE POLICY loan_accounts_app_isolation ON app.loan_accounts
    FOR ALL TO ussd_app_user
    USING (app_id = current_setting('app.current_application_id', true)::UUID);

-- Amortization schedule
CREATE POLICY amortization_app_isolation ON app.amortization_schedule
    FOR ALL TO ussd_app_user
    USING (EXISTS (
        SELECT 1 FROM app.loan_accounts la 
        WHERE la.loan_id = amortization_schedule.loan_id
        AND la.app_id = current_setting('app.current_application_id', true)::UUID
    ));

-- Interest accruals
CREATE POLICY interest_accruals_app_isolation ON app.interest_accruals
    FOR ALL TO ussd_app_user
    USING (app_id = current_setting('app.current_application_id', true)::UUID);

-- Repayments
CREATE POLICY repayments_app_isolation ON app.loan_repayments
    FOR ALL TO ussd_app_user
    USING (app_id = current_setting('app.current_application_id', true)::UUID);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to calculate interest
CREATE OR REPLACE FUNCTION app.calculate_interest(
    p_principal NUMERIC,
    p_rate NUMERIC,
    p_days INTEGER,
    p_method VARCHAR DEFAULT 'REDUCING_BALANCE',
    p_year_basis INTEGER DEFAULT 365
)
RETURNS NUMERIC
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN ROUND(p_principal * (p_rate / 100) * (p_days::NUMERIC / p_year_basis), 8);
END;
$$;

-- Function to generate EMI schedule
CREATE OR REPLACE FUNCTION app.generate_emi_schedule(
    p_loan_id UUID,
    p_principal NUMERIC,
    p_monthly_rate NUMERIC,
    p_tenure_months INTEGER,
    p_start_date DATE
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_emi NUMERIC;
    v_balance NUMERIC;
    v_interest NUMERIC;
    v_principal NUMERIC;
    v_i INTEGER;
    v_due_date DATE;
BEGIN
    -- Calculate EMI using formula: P * r * (1+r)^n / ((1+r)^n - 1)
    v_emi := ROUND(
        p_principal * p_monthly_rate * POWER(1 + p_monthly_rate, p_tenure_months) / 
        (POWER(1 + p_monthly_rate, p_tenure_months) - 1),
        8
    );
    
    v_balance := p_principal;
    
    FOR v_i IN 1..p_tenure_months LOOP
        v_due_date := p_start_date + (v_i || ' months')::INTERVAL;
        
        -- Calculate interest on remaining balance
        v_interest := ROUND(v_balance * p_monthly_rate, 8);
        
        -- Principal portion
        v_principal := v_emi - v_interest;
        
        -- Insert schedule row
        INSERT INTO app.amortization_schedule (
            loan_id, installment_number, due_date, opening_balance,
            principal_amount, interest_amount, total_installment, closing_balance
        ) VALUES (
            p_loan_id, v_i, v_due_date, v_balance,
            v_principal, v_interest, v_emi, v_balance - v_principal
        );
        
        v_balance := v_balance - v_principal;
    END LOOP;
    
    -- Update loan with installment amount
    UPDATE app.loan_accounts 
    SET installment_amount = v_emi
    WHERE loan_id = p_loan_id;
    
    RETURN p_tenure_months;
END;
$$;

-- Function to accrue daily interest
CREATE OR REPLACE FUNCTION app.accrue_daily_interest(
    p_loan_id UUID,
    p_accrual_date DATE
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_loan RECORD;
    v_accrual_id UUID;
    v_interest NUMERIC;
    v_days INTEGER := 1;
BEGIN
    SELECT * INTO v_loan FROM app.loan_accounts 
    WHERE loan_id = p_loan_id AND status = 'ACTIVE';
    
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    
    -- Calculate interest
    v_interest := app.calculate_interest(
        v_loan.outstanding_principal,
        v_loan.interest_rate,
        v_days,
        v_loan.interest_method
    );
    
    INSERT INTO app.interest_accruals (
        app_id, account_id, loan_id, accrual_date, period_start, period_end,
        days_accrued, principal_balance, interest_rate, annual_rate,
        interest_method, accrued_interest, currency_code, narrative
    ) VALUES (
        v_loan.app_id, v_loan.account_id, p_loan_id, p_accrual_date, p_accrual_date, p_accrual_date,
        v_days, v_loan.outstanding_principal, v_loan.interest_rate, v_loan.interest_rate,
        v_loan.interest_method, v_interest, v_loan.currency_code,
        'Daily interest accrual'
    )
    RETURNING accrual_id INTO v_accrual_id;
    
    -- Update loan outstanding interest
    UPDATE app.loan_accounts 
    SET outstanding_interest = outstanding_interest + v_interest
    WHERE loan_id = p_loan_id;
    
    RETURN v_accrual_id;
END;
$$;

-- Function to process repayment allocation
CREATE OR REPLACE FUNCTION app.allocate_repayment(
    p_repayment_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_repayment RECORD;
    v_loan RECORD;
    v_schedule RECORD;
    v_remaining NUMERIC;
BEGIN
    SELECT * INTO v_repayment FROM app.loan_repayments WHERE repayment_id = p_repayment_id;
    SELECT * INTO v_loan FROM app.loan_accounts WHERE loan_id = v_repayment.loan_id;
    
    v_remaining := v_repayment.total_paid;
    
    -- Allocate to outstanding installments
    FOR v_schedule IN 
        SELECT * FROM app.amortization_schedule 
        WHERE loan_id = v_repayment.loan_id 
        AND status IN ('DUE', 'OVERDUE', 'SCHEDULED')
        ORDER BY installment_number
    LOOP
        EXIT WHEN v_remaining <= 0;
        
        -- Allocate interest first, then principal
        IF v_remaining >= v_schedule.interest_amount - v_schedule.paid_interest THEN
            v_schedule.paid_interest := v_schedule.interest_amount;
            v_remaining := v_remaining - (v_schedule.interest_amount - v_schedule.paid_interest);
        ELSE
            v_schedule.paid_interest := v_schedule.paid_interest + v_remaining;
            v_remaining := 0;
        END IF;
        
        IF v_remaining > 0 THEN
            IF v_remaining >= v_schedule.principal_amount - v_schedule.paid_principal THEN
                v_schedule.paid_principal := v_schedule.principal_amount;
                v_remaining := v_remaining - (v_schedule.principal_amount - v_schedule.paid_principal);
            ELSE
                v_schedule.paid_principal := v_schedule.paid_principal + v_remaining;
                v_remaining := 0;
            END IF;
        END IF;
        
        -- Update schedule
        UPDATE app.amortization_schedule SET
            paid_principal = v_schedule.paid_principal,
            paid_interest = v_schedule.paid_interest,
            paid_total = v_schedule.paid_principal + v_schedule.paid_interest,
            status = CASE 
                WHEN v_schedule.paid_principal + v_schedule.paid_interest >= v_schedule.total_installment THEN 'PAID'
                WHEN v_schedule.paid_principal + v_schedule.paid_interest > 0 THEN 'PARTIAL'
                ELSE status
            END,
            paid_at = NOW()
        WHERE schedule_id = v_schedule.schedule_id;
    END LOOP;
    
    -- Update repayment allocation
    UPDATE app.loan_repayments SET
        allocated_interest = v_repayment.total_paid - v_remaining - 
            (SELECT COALESCE(SUM(principal_amount), 0) FROM app.amortization_schedule 
             WHERE loan_id = v_repayment.loan_id AND status = 'PAID'),
        allocated_principal = (SELECT COALESCE(SUM(principal_amount), 0) FROM app.amortization_schedule 
                               WHERE loan_id = v_repayment.loan_id AND status = 'PAID'),
        status = 'ALLOCATED'
    WHERE repayment_id = p_repayment_id;
    
    -- Update loan balances
    UPDATE app.loan_accounts SET
        outstanding_principal = outstanding_principal - v_repayment.allocated_principal,
        outstanding_interest = outstanding_interest - v_repayment.allocated_interest,
        status = CASE 
            WHEN outstanding_principal - v_repayment.allocated_principal <= 0 THEN 'CLOSED'
            ELSE status
        END,
        closed_at = CASE 
            WHEN outstanding_principal - v_repayment.allocated_principal <= 0 THEN NOW()
            ELSE closed_at
        END
    WHERE loan_id = v_repayment.loan_id;
    
    RETURN TRUE;
END;
$$;

-- Function to get loan summary
CREATE OR REPLACE FUNCTION app.get_loan_summary(
    p_loan_id UUID
)
RETURNS TABLE (
    loan_reference VARCHAR,
    principal_amount NUMERIC,
    outstanding_principal NUMERIC,
    outstanding_interest NUMERIC,
    total_outstanding NUMERIC,
    next_due_date DATE,
    next_installment NUMERIC,
    status VARCHAR,
    days_overdue INTEGER
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        la.loan_reference,
        la.principal_amount,
        la.outstanding_principal,
        la.outstanding_interest,
        la.total_outstanding,
        (SELECT MIN(due_date) FROM app.amortization_schedule 
         WHERE loan_id = p_loan_id AND status IN ('DUE', 'OVERDUE', 'SCHEDULED')),
        (SELECT total_installment FROM app.amortization_schedule 
         WHERE loan_id = p_loan_id AND status IN ('DUE', 'OVERDUE', 'SCHEDULED') 
         ORDER BY installment_number LIMIT 1),
        la.status,
        (SELECT EXTRACT(DAY FROM NOW() - due_date) FROM app.amortization_schedule 
         WHERE loan_id = p_loan_id AND status = 'OVERDUE' 
         ORDER BY due_date LIMIT 1)::INTEGER
    FROM app.loan_accounts la
    WHERE la.loan_id = p_loan_id;
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE app.loan_accounts IS 'Loan account management with balance tracking';
COMMENT ON TABLE app.amortization_schedule IS 'EMI repayment schedule for loans';
COMMENT ON TABLE app.interest_accruals IS 'Daily/monthly interest accrual records';
COMMENT ON TABLE app.loan_repayments IS 'Loan repayment transactions with allocation';
COMMENT ON FUNCTION app.generate_emi_schedule IS 'Generate equal monthly installment schedule';
COMMENT ON FUNCTION app.accrue_daily_interest IS 'Calculate and record daily interest accrual';

-- =============================================================================
-- END OF FILE
-- =============================================================================
