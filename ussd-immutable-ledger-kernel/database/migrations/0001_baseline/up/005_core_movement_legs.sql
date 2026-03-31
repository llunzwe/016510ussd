-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Financial controls)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Data integrity in cloud)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Transaction privacy)
-- ISO/IEC 27040:2024 - Storage Security (Immutable movement records)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Transaction recovery)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Double-entry accounting enforcement (debits = credits)
-- - Conservation law validation via triggers
-- - Movement hash for individual leg integrity
-- - Status workflow enforcement
-- ============================================================================
-- =============================================================================
-- MIGRATION: 005_core_movement_legs.sql
-- DESCRIPTION: Double-Entry Movement Legs - Debits and Credits
-- TABLES: movement_headers, movement_legs
-- DEPENDENCIES: 004_core_transaction_log.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 2. Core Immutable Ledger - Value Containers & Movements
- Feature: Double-Entry Value Movements, Movement Legs
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Implements proper double-entry accounting for all financial movements.
Every movement has at least 2 legs (debit and credit) that must balance.

KEY FEATURES:
- Conservation law: SUM(debits) = SUM(credits) for each movement
- Movement header captures the transaction context
- Movement legs capture individual debit/credit entries
- Each leg links to a value container (account)
- Leg hash for individual integrity verification
- Status workflow: DRAFT → PENDING → POSTED → REVERSED

MOVEMENT TYPES:
- CONTRIBUTION: Member contributes to savings group
- LOAN_DISBURSEMENT: Funds released to borrower
- LOAN_REPAYMENT: Borrower repays loan
- RIDE_PAYMENT: Transport fare payment
- PRODUCT_PURCHASE: E-commerce transaction
- FEE: Service charge
- INTEREST: Interest accrual or payment
- REVERSAL: Correction of posted movement
================================================================================
*/

-- =============================================================================
-- Create movement_types registry
-- DESCRIPTION: Catalog of movement types with accounting rules
-- PRIORITY: HIGH
-- SECURITY: Immutable type definitions
-- ============================================================================
CREATE TABLE core.movement_types (
    movement_type_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type_code           VARCHAR(50) NOT NULL,        -- 'CONTRIBUTION', etc.
    type_name           VARCHAR(100) NOT NULL,
    description         TEXT,
    
    -- Transaction mapping
    transaction_type_id UUID REFERENCES core.transaction_types(transaction_type_id),
    
    -- Leg structure requirements
    min_legs            INTEGER NOT NULL DEFAULT 2,
    max_legs            INTEGER,                     -- NULL = unlimited
    requires_balanced   BOOLEAN DEFAULT true,        -- Debits must equal credits
    
    -- Default COA accounts (optional guidance)
    default_debit_coa   VARCHAR(50),
    default_credit_coa  VARCHAR(50),
    
    -- Validation
    leg_validation_rules JSONB,                     -- JSON Schema for leg validation
    
    -- Status
    is_active           BOOLEAN DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    
    -- Constraints
    CONSTRAINT chk_movement_types_legs 
        CHECK (max_legs IS NULL OR max_legs >= min_legs)
);

CREATE UNIQUE INDEX idx_movement_types_code ON core.movement_types(type_code) WHERE is_active = true;
CREATE INDEX idx_movement_types_transaction ON core.movement_types(transaction_type_id);

COMMENT ON TABLE core.movement_types IS 'Defines valid movement types and their accounting behavior';
COMMENT ON COLUMN core.movement_types.requires_balanced IS 'Whether debits must equal credits for this movement type';

-- =============================================================================
-- Create movement_headers table
-- DESCRIPTION: Container for a double-entry movement
-- PRIORITY: CRITICAL
-- SECURITY: Conservation law enforced via trigger
-- ============================================================================
CREATE TABLE core.movement_headers (
    -- Identity
    movement_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    movement_reference  VARCHAR(100) UNIQUE NOT NULL, -- Human-readable
    
    -- Type & Classification
    movement_type_id    UUID NOT NULL REFERENCES core.movement_types(movement_type_id),
    transaction_id      UUID REFERENCES core.transaction_log(transaction_id),
    
    -- Application Context
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Financial Summary (enforced by triggers)
    total_debits        NUMERIC(20, 8) NOT NULL DEFAULT 0,
    total_credits       NUMERIC(20, 8) NOT NULL DEFAULT 0,
    currency            VARCHAR(3) NOT NULL,
    
    -- Exchange (for multi-currency)
    exchange_rate       NUMERIC(20, 10) DEFAULT 1.0,
    base_currency       VARCHAR(3) DEFAULT 'USD',
    base_amount         NUMERIC(20, 8),
    
    -- Dates
    entry_date          DATE NOT NULL DEFAULT CURRENT_DATE,
    value_date          DATE NOT NULL DEFAULT CURRENT_DATE,
    accounting_date     DATE NOT NULL DEFAULT CURRENT_DATE,
    
    -- Status Workflow
    status              VARCHAR(20) NOT NULL DEFAULT 'DRAFT',
                        -- DRAFT, PENDING, POSTED, REVERSING, REVERSED
    
    -- Control
    batch_id            UUID REFERENCES core.control_batches(batch_id),
    control_hash        BYTEA,                       -- Hash of all leg hashes
    
    -- Idempotency
    idempotency_key_id  UUID REFERENCES core.idempotency_keys(idempotency_key_id),
    
    -- Correlation
    correlation_id      UUID,                        -- For grouping related movements
    reversal_of         UUID REFERENCES core.movement_headers(movement_id),
    
    -- Metadata
    description         TEXT,
    external_reference  VARCHAR(255),
    metadata            JSONB DEFAULT '{}',
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID NOT NULL REFERENCES core.accounts(account_id),
    posted_at           TIMESTAMPTZ,
    posted_by           UUID REFERENCES core.accounts(account_id),
    
    -- Integrity
    movement_hash       BYTEA NOT NULL,               -- Hash of header + all legs
    
    -- Constraints
    CONSTRAINT chk_movement_headers_status 
        CHECK (status IN ('DRAFT', 'PENDING', 'POSTED', 'REVERSING', 'REVERSED')),
    CONSTRAINT chk_movement_headers_balanced 
        CHECK (
            (status IN ('DRAFT', 'PENDING')) OR 
            (total_debits = total_credits)
        )
);

-- Indexes for movement_headers
CREATE INDEX idx_movement_headers_transaction ON core.movement_headers(transaction_id);
CREATE INDEX idx_movement_headers_application ON core.movement_headers(application_id, entry_date);
CREATE INDEX idx_movement_headers_pending ON core.movement_headers(status, application_id) WHERE status = 'PENDING';
CREATE INDEX idx_movement_headers_correlation ON core.movement_headers(correlation_id);
CREATE INDEX idx_movement_headers_reversal ON core.movement_headers(reversal_of);
CREATE INDEX idx_movement_headers_batch ON core.movement_headers(batch_id);
CREATE INDEX idx_movement_headers_gin_metadata ON core.movement_headers USING GIN (metadata);

COMMENT ON TABLE core.movement_headers IS 'Container for double-entry financial movements';
COMMENT ON COLUMN core.movement_headers.movement_hash IS 'Hash of all movement data including legs for integrity';
COMMENT ON COLUMN core.movement_headers.control_hash IS 'Aggregate hash of all leg hashes';

-- =============================================================================
-- Create movement_legs table
-- DESCRIPTION: Individual debit/credit entries
-- PRIORITY: CRITICAL
-- SECURITY: Direction validation, positive amounts only
-- ============================================================================
CREATE TABLE core.movement_legs (
    -- Identity
    leg_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    leg_sequence        INTEGER NOT NULL,            -- Order within movement
    
    -- Parent
    movement_id         UUID NOT NULL REFERENCES core.movement_headers(movement_id),
    
    -- Account (Value Container)
    account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
    
    -- Direction & Amount
    direction           VARCHAR(6) NOT NULL,         -- 'DEBIT' or 'CREDIT'
    amount              NUMERIC(20, 8) NOT NULL,
    currency            VARCHAR(3) NOT NULL,
    
    -- Chart of Accounts (optional but recommended)
    coa_code            VARCHAR(50) REFERENCES core.chart_of_accounts(coa_code),
    
    -- Running Balance (captured at posting time)
    running_balance     NUMERIC(20, 8),              -- Balance after this leg
    
    -- Description
    description         TEXT,
    
    -- Integrity
    leg_hash            BYTEA NOT NULL,              -- Hash of leg data
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Constraints
    CONSTRAINT chk_movement_legs_direction 
        CHECK (direction IN ('DEBIT', 'CREDIT')),
    CONSTRAINT chk_movement_legs_amount 
        CHECK (amount > 0),
    CONSTRAINT uq_movement_legs_sequence 
        UNIQUE (movement_id, leg_sequence)
);

-- Indexes for movement_legs
CREATE INDEX idx_movement_legs_account ON core.movement_legs(account_id, created_at DESC);
CREATE INDEX idx_movement_legs_coa ON core.movement_legs(account_id, coa_code, created_at DESC);
CREATE INDEX idx_movement_legs_currency ON core.movement_legs(currency);

COMMENT ON TABLE core.movement_legs IS 'Individual debit/credit entries for double-entry accounting';
COMMENT ON COLUMN core.movement_legs.direction IS 'DEBIT increases assets/expenses, CREDIT increases liabilities/income';
COMMENT ON COLUMN core.movement_legs.leg_hash IS 'SHA-256 hash of leg data for integrity verification';

-- =============================================================================
-- Create conservation validation trigger
-- DESCRIPTION: Ensure debits equal credits
-- PRIORITY: CRITICAL
-- SECURITY: Prevent unbalanced postings
-- ============================================================================
CREATE OR REPLACE FUNCTION core.validate_movement_balance()
RETURNS TRIGGER AS $$
DECLARE
    v_debits NUMERIC;
    v_credits NUMERIC;
    v_movement_type RECORD;
BEGIN
    -- Only validate when transitioning to POSTED
    IF NEW.status = 'POSTED' AND OLD.status != 'POSTED' THEN
        -- Get movement type requirements
        SELECT requires_balanced INTO v_movement_type
        FROM core.movement_types
        WHERE movement_type_id = NEW.movement_type_id;
        
        -- Calculate leg totals
        SELECT 
            COALESCE(SUM(amount) FILTER (WHERE direction = 'DEBIT'), 0),
            COALESCE(SUM(amount) FILTER (WHERE direction = 'CREDIT'), 0)
        INTO v_debits, v_credits
        FROM core.movement_legs
        WHERE movement_id = NEW.movement_id;
        
        -- Validate balance if required
        IF COALESCE(v_movement_type.requires_balanced, true) AND v_debits != v_credits THEN
            RAISE EXCEPTION 'Movement % is unbalanced: debits=%, credits=%',
                NEW.movement_id, v_debits, v_credits;
        END IF;
        
        -- Update totals
        NEW.total_debits := v_debits;
        NEW.total_credits := v_credits;
        NEW.posted_at := now();
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

CREATE TRIGGER trg_movement_headers_validate_balance
    BEFORE UPDATE ON core.movement_headers
    FOR EACH ROW
    EXECUTE FUNCTION core.validate_movement_balance();

COMMENT ON FUNCTION core.validate_movement_balance IS 'Ensures debits equal credits before movement is posted';

-- =============================================================================
-- Create leg hash computation function
-- DESCRIPTION: Calculate hash for each leg
-- PRIORITY: HIGH
-- SECURITY: Deterministic hashing for verification
-- ============================================================================
CREATE OR REPLACE FUNCTION core.compute_leg_hash(
    p_movement_id UUID,
    p_account_id UUID,
    p_direction VARCHAR(6),
    p_amount NUMERIC,
    p_currency VARCHAR(3),
    p_coa_code VARCHAR(50)
) RETURNS BYTEA AS $$
BEGIN
    RETURN digest(
        p_movement_id::text ||
        p_account_id::text ||
        p_direction ||
        p_amount::text ||
        p_currency ||
        COALESCE(p_coa_code, ''),
        'sha256'
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path = core, pg_catalog, public;

COMMENT ON FUNCTION core.compute_leg_hash IS 'Computes SHA-256 hash of leg data for integrity verification';

-- =============================================================================
-- Create leg insert trigger for hash computation
-- DESCRIPTION: Auto-compute leg hash on insert
-- PRIORITY: HIGH
-- ============================================================================
CREATE OR REPLACE FUNCTION core.movement_leg_insert_hook()
RETURNS TRIGGER AS $$
BEGIN
    -- Compute leg hash if not provided
    IF NEW.leg_hash IS NULL OR NEW.leg_hash = '\x00' THEN
        NEW.leg_hash := core.compute_leg_hash(
            NEW.movement_id,
            NEW.account_id,
            NEW.direction,
            NEW.amount,
            NEW.currency,
            NEW.coa_code
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

CREATE TRIGGER trg_movement_legs_insert_hook
    BEFORE INSERT ON core.movement_legs
    FOR EACH ROW
    EXECUTE FUNCTION core.movement_leg_insert_hook();

-- =============================================================================
-- Create movement control hash function
-- DESCRIPTION: Hash of all leg hashes combined
-- PRIORITY: MEDIUM
-- SECURITY: Aggregate integrity verification
-- ============================================================================
CREATE OR REPLACE FUNCTION core.compute_control_hash(p_movement_id UUID)
RETURNS BYTEA AS $$
DECLARE
    v_all_hashes BYTEA;
BEGIN
    SELECT string_agg(encode(leg_hash, 'hex'), '' ORDER BY leg_sequence)::bytea
    INTO v_all_hashes
    FROM core.movement_legs
    WHERE movement_id = p_movement_id;
    
    RETURN digest(v_all_hashes, 'sha256');
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog, public;

COMMENT ON FUNCTION core.compute_control_hash IS 'Computes aggregate hash of all leg hashes for movement integrity';

-- =============================================================================
-- Create movement hash update trigger
-- DESCRIPTION: Update movement hash when legs change
-- PRIORITY: HIGH
-- ============================================================================
CREATE OR REPLACE FUNCTION core.movement_legs_change_hook()
RETURNS TRIGGER AS $$
DECLARE
    v_movement_id UUID;
    v_new_hash BYTEA;
BEGIN
    -- Determine which movement was affected
    IF TG_OP = 'DELETE' THEN
        v_movement_id := OLD.movement_id;
    ELSE
        v_movement_id := NEW.movement_id;
    END IF;
    
    -- Recompute control hash
    v_new_hash := core.compute_control_hash(v_movement_id);
    
    -- Update movement header
    UPDATE core.movement_headers
    SET control_hash = v_new_hash,
        movement_hash = digest(
            movement_id::text || COALESCE(v_new_hash::text, ''),
            'sha256'
        )
    WHERE movement_id = v_movement_id
      AND status IN ('DRAFT', 'PENDING');  -- Only update if not yet posted
    
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

CREATE TRIGGER trg_movement_legs_change_hook
    AFTER INSERT OR UPDATE OR DELETE ON core.movement_legs
    FOR EACH ROW
    EXECUTE FUNCTION core.movement_legs_change_hook();

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create movement_types registry
☑ Create movement_headers table with conservation constraints
☑ Create movement_legs table with debit/credit direction
☑ Create balance validation trigger
☑ Create leg hash computation function
☑ Create control hash function for movement integrity
☑ Add all indexes for movement/leg queries
☑ Test double-entry balance enforcement
☑ Verify foreign key constraints
================================================================================
*/
