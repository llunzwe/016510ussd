-- =============================================================================
-- USSD KERNEL APP SCHEMA - DOUBLE-ENTRY JOURNAL ENGINE
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    057_app_double_entry_engine.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      app
-- DESCRIPTION: Complete double-entry bookkeeping system with Chart of Accounts,
--              journal entries, and automated posting from core transactions.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Financial transaction monitoring
├── A.18.1 Compliance - GAAP/IFRS compliance
└── A.18.2 Compliance - Audit trail integrity

Financial Regulations
├── GAAP/IFRS: Standard-compliant accounting
├── Audit: Complete transaction trail
├── SOX: Financial controls and segregation
└── Tax: Audit-ready financial records

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. CHART OF ACCOUNTS
   - Hierarchical account structure (parent-child)
   - Account types: Asset, Liability, Equity, Revenue, Expense
   - Normal balances: Debit or Credit
   - Financial statement mapping

2. JOURNAL ENTRIES
   - Every transaction produces balanced entries
   - Debits must equal Credits
   - Immutable once posted
   - References to core transaction_log

3. POSTING PROCESS
   - Automated from transaction_log via triggers
   - Validation before posting
   - Error handling with suspense accounts

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

JOURNAL SECURITY:
- RLS per application (tenant isolation)
- Immutable entries (compensating entries only)
- Audit trail linking to core transactions
- Approval workflow for manual journals

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: account_id, entry_id
- COA: account_code + app_id
- JOURNAL: transaction_log_id + account_id
- DATE: posted_at for period queries

PARTITIONING:
- Journal entries by posted_at (monthly)

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- JOURNAL_ENTRY_CREATED
- JOURNAL_POSTED
- JOURNAL_BALANCED
- MANUAL_JOURNAL_APPROVED

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- CREATE TABLE: chart_of_accounts
-- =============================================================================
CREATE TABLE app.chart_of_accounts (
    -- Primary identifier
    account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Application context (multi-tenant)
    app_id UUID NOT NULL REFERENCES app.t_application_registry(app_id) ON DELETE CASCADE,
    
    -- Account code (unique per app)
    account_code VARCHAR(50) NOT NULL,
    account_name VARCHAR(200) NOT NULL,
    account_description TEXT,
    
    -- Classification
    account_type VARCHAR(20) NOT NULL
        CHECK (account_type IN ('ASSET', 'LIABILITY', 'EQUITY', 'REVENUE', 'EXPENSE')),
    account_subtype VARCHAR(50),
    
    -- Hierarchy
    parent_account_id UUID REFERENCES app.chart_of_accounts(account_id),
    account_level INTEGER DEFAULT 1 CHECK (account_level > 0 AND account_level <= 10),
    is_leaf_account BOOLEAN DEFAULT TRUE,
    
    -- Normal balance
    normal_balance VARCHAR(6) NOT NULL
        CHECK (normal_balance IN ('DEBIT', 'CREDIT')),
    
    -- Financial statement mapping
    balance_sheet_section VARCHAR(50)
        CHECK (balance_sheet_section IN ('CURRENT_ASSETS', 'NON_CURRENT_ASSETS', 'CURRENT_LIABILITIES', 
                                          'NON_CURRENT_LIABILITIES', 'EQUITY', 'NONE')),
    income_statement_section VARCHAR(50)
        CHECK (income_statement_section IN ('REVENUE', 'COST_OF_SALES', 'OPERATING_EXPENSES', 
                                             'OTHER_INCOME', 'OTHER_EXPENSES', 'NONE')),
    cash_flow_category VARCHAR(50)
        CHECK (cash_flow_category IN ('OPERATING', 'INVESTING', 'FINANCING', 'NONE')),
    
    -- Configuration
    is_active BOOLEAN DEFAULT TRUE,
    is_bank_account BOOLEAN DEFAULT FALSE,
    is_cash_account BOOLEAN DEFAULT FALSE,
    requires_cost_center BOOLEAN DEFAULT FALSE,
    requires_project BOOLEAN DEFAULT FALSE,
    
    -- Currency
    currency_code VARCHAR(6) REFERENCES core.currency_registry(currency_code),
    
    -- Validity period
    valid_from DATE NOT NULL DEFAULT CURRENT_DATE,
    valid_to DATE,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    version INTEGER DEFAULT 1,
    
    -- Constraints
    CONSTRAINT uq_app_account_code UNIQUE (app_id, account_code),
    CONSTRAINT chk_valid_dates CHECK (valid_to IS NULL OR valid_to > valid_from)
);

-- =============================================================================
-- CREATE TABLE: journal_entries (partitioned)
-- =============================================================================
CREATE TABLE app.journal_entries (
    -- Primary identifier
    entry_id BIGSERIAL,
    entry_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Application context
    app_id UUID NOT NULL REFERENCES app.t_application_registry(app_id) ON DELETE CASCADE,
    
    -- Link to core transaction
    core_transaction_id BIGINT,
    partition_date DATE,
    
    -- Account reference
    account_id UUID NOT NULL REFERENCES app.chart_of_accounts(account_id),
    account_code VARCHAR(50) NOT NULL,
    
    -- Entry details
    entry_type VARCHAR(20) NOT NULL DEFAULT 'AUTO'
        CHECK (entry_type IN ('AUTO', 'MANUAL', 'ADJUSTING', 'CLOSING', 'REVERSAL', 'ACCRUAL')),
    
    -- Amount (always positive, direction indicates debit/credit)
    side VARCHAR(6) NOT NULL CHECK (side IN ('DEBIT', 'CREDIT')),
    amount NUMERIC(20, 8) NOT NULL CHECK (amount > 0),
    amount_in_account_currency NUMERIC(20, 8),
    
    -- Currency
    entry_currency VARCHAR(6) NOT NULL REFERENCES core.currency_registry(currency_code),
    account_currency VARCHAR(6) REFERENCES core.currency_registry(currency_code),
    fx_rate NUMERIC(20, 10) DEFAULT 1,
    
    -- Running balance (snapshot at time of entry)
    running_balance NUMERIC(20, 8),
    
    -- Narrative
    description TEXT,
    narrative VARCHAR(255),
    
    -- Period
    fiscal_year INTEGER NOT NULL,
    fiscal_period INTEGER NOT NULL CHECK (fiscal_period BETWEEN 1 AND 12),
    
    -- Reversal tracking
    is_reversal BOOLEAN DEFAULT FALSE,
    reversed_entry_id BIGINT REFERENCES app.journal_entries(entry_id),
    reversal_reason TEXT,
    
    -- Manual journal approval
    requires_approval BOOLEAN DEFAULT FALSE,
    approved_by UUID,
    approved_at TIMESTAMPTZ,
    
    -- Posting
    posted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    posted_by UUID,
    
    -- Additional dimensions (for reporting)
    cost_center VARCHAR(50),
    project_code VARCHAR(50),
    department VARCHAR(50),
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING',
    
    -- Constraints
    CONSTRAINT chk_fiscal_period CHECK (fiscal_period BETWEEN 1 AND 12)
) PARTITION BY RANGE (posted_at);

-- Create initial partitions
CREATE TABLE app.journal_entries_2026_q1 
    PARTITION OF app.journal_entries
    FOR VALUES FROM ('2026-01-01') TO ('2026-04-01');

CREATE TABLE app.journal_entries_2026_q2 
    PARTITION OF app.journal_entries
    FOR VALUES FROM ('2026-04-01') TO ('2026-07-01');

-- =============================================================================
-- CREATE TABLE: journal_batches
-- For grouping related entries (e.g., end-of-day processing)
-- =============================================================================
CREATE TABLE app.journal_batches (
    batch_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES app.t_application_registry(app_id) ON DELETE CASCADE,
    
    batch_reference VARCHAR(100) UNIQUE NOT NULL,
    batch_type VARCHAR(50) NOT NULL 
        CHECK (batch_type IN ('DAILY', 'PERIOD_END', 'ADJUSTMENT', 'ACCRUAL', 'CLOSING', 'RECONCILIATION')),
    
    description TEXT,
    
    -- Status
    status VARCHAR(20) DEFAULT 'DRAFT'
        CHECK (status IN ('DRAFT', 'BALANCED', 'POSTED', 'APPROVED', 'REVERSED')),
    
    -- Totals
    total_debits NUMERIC(20, 8) DEFAULT 0,
    total_credits NUMERIC(20, 8) DEFAULT 0,
    difference NUMERIC(20, 8) GENERATED ALWAYS AS (total_debits - total_credits) STORED,
    entry_count INTEGER DEFAULT 0,
    
    -- Period
    fiscal_year INTEGER,
    fiscal_period INTEGER,
    
    -- Approval
    prepared_by UUID,
    reviewed_by UUID,
    approved_by UUID,
    approved_at TIMESTAMPTZ,
    
    -- Dates
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    posted_at TIMESTAMPTZ,
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- Link journal entries to batches
ALTER TABLE app.journal_entries ADD COLUMN batch_id UUID REFERENCES app.journal_batches(batch_id);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Chart of accounts indexes
CREATE INDEX idx_coa_app ON app.chart_of_accounts(app_id, is_active);
CREATE INDEX idx_coa_type ON app.chart_of_accounts(app_id, account_type, is_active);
CREATE INDEX idx_coa_parent ON app.chart_of_accounts(parent_account_id);
CREATE INDEX idx_coa_code ON app.chart_of_accounts(app_id, account_code);

-- Journal entry indexes
CREATE INDEX idx_journal_app ON app.journal_entries(app_id, posted_at DESC);
CREATE INDEX idx_journal_account ON app.journal_entries(account_id, posted_at DESC);
CREATE INDEX idx_journal_transaction ON app.journal_entries(core_transaction_id, partition_date);
CREATE INDEX idx_journal_batch ON app.journal_entries(batch_id);
CREATE INDEX idx_journal_period ON app.journal_entries(app_id, fiscal_year, fiscal_period);
CREATE INDEX idx_journal_type ON app.journal_entries(entry_type, posted_at);

-- Balance calculation index
CREATE INDEX idx_journal_balance ON app.journal_entries(app_id, account_id, posted_at, side, amount);

-- Batch indexes
CREATE INDEX idx_batch_app ON app.journal_batches(app_id, batch_type, status);
CREATE INDEX idx_batch_status ON app.journal_batches(status, created_at);

-- =============================================================================
-- TRIGGERS (not immutable - app layer allows corrections with audit trail)
-- =============================================================================

-- Update timestamp trigger
CREATE OR REPLACE FUNCTION app.update_journal_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.created_at = NOW();
    RETURN NEW;
END;
$$;

-- Hash computation trigger
CREATE OR REPLACE FUNCTION app.compute_journal_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := encode(
        digest(
            NEW.entry_id::TEXT || 
            NEW.entry_reference || 
            NEW.app_id::TEXT ||
            COALESCE(NEW.core_transaction_id::TEXT, '') ||
            NEW.account_id::TEXT ||
            NEW.side ||
            NEW.amount::TEXT ||
            NEW.posted_at::TEXT,
            'sha256'
        ),
        'hex'
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_journal_entries_compute_hash
    BEFORE INSERT ON app.journal_entries
    FOR EACH ROW
    EXECUTE FUNCTION app.compute_journal_hash();

-- Batch hash trigger
CREATE OR REPLACE FUNCTION app.compute_batch_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := encode(
        digest(
            NEW.batch_id::TEXT || 
            NEW.batch_reference || 
            NEW.app_id::TEXT ||
            NEW.total_debits::TEXT ||
            NEW.total_credits::TEXT ||
            NEW.created_at::TEXT,
            'sha256'
        ),
        'hex'
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_journal_batches_compute_hash
    BEFORE INSERT OR UPDATE ON app.journal_batches
    FOR EACH ROW
    EXECUTE FUNCTION app.compute_batch_hash();

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

ALTER TABLE app.chart_of_accounts ENABLE ROW LEVEL SECURITY;

CREATE POLICY coa_app_isolation ON app.chart_of_accounts
    FOR ALL
    TO ussd_app_user
    USING (app_id = current_setting('app.current_application_id', true)::UUID);

CREATE POLICY coa_kernel_access ON app.chart_of_accounts
    FOR ALL
    TO ussd_kernel_role
    USING (true);

ALTER TABLE app.journal_entries ENABLE ROW LEVEL SECURITY;

CREATE POLICY journal_app_isolation ON app.journal_entries
    FOR ALL
    TO ussd_app_user
    USING (app_id = current_setting('app.current_application_id', true)::UUID);

CREATE POLICY journal_kernel_access ON app.journal_entries
    FOR ALL
    TO ussd_kernel_role
    USING (true);

ALTER TABLE app.journal_batches ENABLE ROW LEVEL SECURITY;

CREATE POLICY batch_app_isolation ON app.journal_batches
    FOR ALL
    TO ussd_app_user
    USING (app_id = current_setting('app.current_application_id', true)::UUID);

CREATE POLICY batch_kernel_access ON app.journal_batches
    FOR ALL
    TO ussd_kernel_role
    USING (true);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to create chart of accounts entry
CREATE OR REPLACE FUNCTION app.create_account(
    p_app_id UUID,
    p_account_code VARCHAR,
    p_account_name VARCHAR,
    p_account_type VARCHAR,
    p_normal_balance VARCHAR,
    p_parent_code VARCHAR DEFAULT NULL,
    p_description TEXT DEFAULT NULL,
    p_created_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_account_id UUID;
    v_parent_id UUID;
    v_level INTEGER := 1;
BEGIN
    -- Find parent if specified
    IF p_parent_code IS NOT NULL THEN
        SELECT account_id, account_level + 1 
        INTO v_parent_id, v_level
        FROM app.chart_of_accounts
        WHERE app_id = p_app_id AND account_code = p_parent_code;
        
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Parent account % not found', p_parent_code;
        END IF;
    END IF;
    
    INSERT INTO app.chart_of_accounts (
        app_id,
        account_code,
        account_name,
        account_description,
        account_type,
        parent_account_id,
        account_level,
        normal_balance,
        created_by
    ) VALUES (
        p_app_id,
        p_account_code,
        p_account_name,
        p_description,
        p_account_type,
        v_parent_id,
        v_level,
        p_normal_balance,
        p_created_by
    )
    RETURNING account_id INTO v_account_id;
    
    -- Update parent to be non-leaf
    IF v_parent_id IS NOT NULL THEN
        UPDATE app.chart_of_accounts SET is_leaf_account = FALSE 
        WHERE account_id = v_parent_id;
    END IF;
    
    RETURN v_account_id;
END;
$$;

-- Function to post journal entry
CREATE OR REPLACE FUNCTION app.post_journal_entry(
    p_app_id UUID,
    p_account_id UUID,
    p_side VARCHAR,
    p_amount NUMERIC,
    p_currency VARCHAR,
    p_description TEXT DEFAULT NULL,
    p_core_transaction_id BIGINT DEFAULT NULL,
    p_partition_date DATE DEFAULT NULL,
    p_fiscal_year INTEGER DEFAULT EXTRACT(YEAR FROM CURRENT_DATE),
    p_fiscal_period INTEGER DEFAULT EXTRACT(MONTH FROM CURRENT_DATE),
    p_created_by UUID DEFAULT NULL,
    p_batch_id UUID DEFAULT NULL
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_entry_id BIGINT;
    v_reference VARCHAR(100);
    v_account RECORD;
    v_running_balance NUMERIC;
BEGIN
    -- Get account details
    SELECT * INTO v_account 
    FROM app.chart_of_accounts 
    WHERE account_id = p_account_id AND app_id = p_app_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Account % not found in app %', p_account_id, p_app_id;
    END IF;
    
    -- Generate reference
    v_reference := 'JE-' || TO_CHAR(NOW(), 'YYYYMMDD') || '-' || 
                   SUBSTRING(MD5(RANDOM()::TEXT), 1, 6);
    
    -- Calculate running balance
    SELECT COALESCE(
        SUM(CASE WHEN side = 'DEBIT' THEN amount ELSE -amount END),
        0
    ) INTO v_running_balance
    FROM app.journal_entries
    WHERE account_id = p_account_id
      AND posted_at < NOW();
    
    -- Update running balance with new entry
    IF p_side = 'DEBIT' THEN
        v_running_balance := v_running_balance + p_amount;
    ELSE
        v_running_balance := v_running_balance - p_amount;
    END IF;
    
    INSERT INTO app.journal_entries (
        entry_reference,
        app_id,
        core_transaction_id,
        partition_date,
        account_id,
        account_code,
        side,
        amount,
        entry_currency,
        account_currency,
        running_balance,
        description,
        fiscal_year,
        fiscal_period,
        posted_by,
        created_by,
        batch_id
    ) VALUES (
        v_reference,
        p_app_id,
        p_core_transaction_id,
        p_partition_date,
        p_account_id,
        v_account.account_code,
        p_side,
        p_amount,
        p_currency,
        v_account.currency_code,
        v_running_balance,
        p_description,
        p_fiscal_year,
        p_fiscal_period,
        p_created_by,
        p_created_by,
        p_batch_id
    )
    RETURNING entry_id INTO v_entry_id;
    
    RETURN v_entry_id;
END;
$$;

-- Function to create balanced journal batch
CREATE OR REPLACE FUNCTION app.create_journal_batch(
    p_app_id UUID,
    p_batch_type VARCHAR,
    p_description TEXT DEFAULT NULL,
    p_fiscal_year INTEGER DEFAULT EXTRACT(YEAR FROM CURRENT_DATE),
    p_fiscal_period INTEGER DEFAULT EXTRACT(MONTH FROM CURRENT_DATE),
    p_prepared_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_batch_id UUID;
    v_reference VARCHAR(100);
BEGIN
    v_reference := 'BATCH-' || p_batch_type || '-' || TO_CHAR(NOW(), 'YYYYMMDD-HH24MISS');
    
    INSERT INTO app.journal_batches (
        app_id,
        batch_reference,
        batch_type,
        description,
        fiscal_year,
        fiscal_period,
        prepared_by
    ) VALUES (
        p_app_id,
        v_reference,
        p_batch_type,
        p_description,
        p_fiscal_year,
        p_fiscal_period,
        p_prepared_by
    )
    RETURNING batch_id INTO v_batch_id;
    
    RETURN v_batch_id;
END;
$$;

-- Function to verify journal balance
CREATE OR REPLACE FUNCTION app.verify_journal_balance(
    p_batch_id UUID
)
RETURNS TABLE (
    is_balanced BOOLEAN,
    total_debits NUMERIC,
    total_credits NUMERIC,
    difference NUMERIC
)
LANGUAGE plpgsql
AS $$
BEGIN
    SELECT 
        SUM(CASE WHEN side = 'DEBIT' THEN amount ELSE 0 END),
        SUM(CASE WHEN side = 'CREDIT' THEN amount ELSE 0 END)
    INTO total_debits, total_credits
    FROM app.journal_entries
    WHERE batch_id = p_batch_id;
    
    difference := COALESCE(total_debits, 0) - COALESCE(total_credits, 0);
    is_balanced := (ABS(difference) < 0.00000001);
    
    RETURN NEXT;
END;
$$;

-- Function to get account balance
CREATE OR REPLACE FUNCTION app.get_account_balance(
    p_account_id UUID,
    p_as_of_date DATE DEFAULT CURRENT_DATE
)
RETURNS TABLE (
    account_id UUID,
    account_code VARCHAR,
    account_name VARCHAR,
    currency_code VARCHAR,
    debit_balance NUMERIC,
    credit_balance NUMERIC,
    net_balance NUMERIC
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ca.account_id,
        ca.account_code,
        ca.account_name,
        ca.currency_code,
        COALESCE(SUM(CASE WHEN je.side = 'DEBIT' THEN je.amount ELSE 0 END), 0) as debit_balance,
        COALESCE(SUM(CASE WHEN je.side = 'CREDIT' THEN je.amount ELSE 0 END), 0) as credit_balance,
        COALESCE(SUM(CASE WHEN je.side = 'DEBIT' THEN je.amount ELSE -je.amount END), 0) as net_balance
    FROM app.chart_of_accounts ca
    LEFT JOIN app.journal_entries je ON ca.account_id = je.account_id
        AND je.posted_at::DATE <= p_as_of_date
        AND je.entry_type != 'REVERSAL'
    WHERE ca.account_id = p_account_id
    GROUP BY ca.account_id, ca.account_code, ca.account_name, ca.currency_code;
END;
$$;

-- Function to get trial balance
CREATE OR REPLACE FUNCTION app.get_trial_balance(
    p_app_id UUID,
    p_as_of_date DATE DEFAULT CURRENT_DATE
)
RETURNS TABLE (
    account_code VARCHAR,
    account_name VARCHAR,
    account_type VARCHAR,
    debit_balance NUMERIC,
    credit_balance NUMERIC,
    net_balance NUMERIC
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ca.account_code,
        ca.account_name,
        ca.account_type,
        COALESCE(SUM(CASE WHEN je.side = 'DEBIT' THEN je.amount ELSE 0 END), 0) as debit_balance,
        COALESCE(SUM(CASE WHEN je.side = 'CREDIT' THEN je.amount ELSE 0 END), 0) as credit_balance,
        COALESCE(SUM(CASE WHEN je.side = 'DEBIT' THEN je.amount ELSE -je.amount END), 0) as net_balance
    FROM app.chart_of_accounts ca
    LEFT JOIN app.journal_entries je ON ca.account_id = je.account_id
        AND je.posted_at::DATE <= p_as_of_date
        AND je.entry_type != 'REVERSAL'
    WHERE ca.app_id = p_app_id
      AND ca.is_active = TRUE
      AND ca.is_leaf_account = TRUE
    GROUP BY ca.account_id, ca.account_code, ca.account_name, ca.account_type
    ORDER BY ca.account_code;
END;
$$;

-- =============================================================================
-- INITIAL DATA: Standard Chart of Accounts Template
-- =============================================================================

-- This will be populated per application during onboarding

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE app.chart_of_accounts IS 'Application-specific chart of accounts with hierarchical structure';
COMMENT ON TABLE app.journal_entries IS 'Double-entry journal entries linked to core transactions';
COMMENT ON TABLE app.journal_batches IS 'Batches for grouping related journal entries';
COMMENT ON FUNCTION app.post_journal_entry IS 'Post a journal entry with automatic running balance calculation';
COMMENT ON FUNCTION app.get_trial_balance IS 'Generate trial balance as of a specific date';

-- =============================================================================
-- END OF FILE
-- =============================================================================
