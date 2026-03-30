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
-- TODO: Create movement_types registry
-- DESCRIPTION: Catalog of movement types with accounting rules
-- PRIORITY: HIGH
-- SECURITY: Immutable type definitions
-- ============================================================================
-- TODO: [LEG-001] Create core.movement_types table
-- INSTRUCTIONS:
--   - Defines valid movement types and their accounting behavior
--   - Specifies required leg structure (min/max legs)
--   - References transaction_types for validation
--   - ERROR HANDLING: Validate leg counts on movement creation
-- COMPLIANCE: ISO/IEC 27001 (Classification)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.movement_types (
--       movement_type_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       type_code           VARCHAR(50) NOT NULL,        -- 'CONTRIBUTION', etc.
--       type_name           VARCHAR(100) NOT NULL,
--       description         TEXT,
--       
--       -- Transaction mapping
--       transaction_type_id UUID REFERENCES core.transaction_types(transaction_type_id),
--       
--       -- Leg structure requirements
--       min_legs            INTEGER NOT NULL DEFAULT 2,
--       max_legs            INTEGER,                     -- NULL = unlimited
--       requires_balanced   BOOLEAN DEFAULT true,        -- Debits must equal credits
--       
--       -- Default COA accounts (optional guidance)
--       default_debit_coa   VARCHAR(50),
--       default_credit_coa  VARCHAR(50),
--       
--       -- Validation
--       leg_validation_rules JSONB,                     -- JSON Schema for leg validation
--       
--       -- Status
--       is_active           BOOLEAN DEFAULT true,
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id)
--   );

-- =============================================================================
-- TODO: Create movement_headers table
-- DESCRIPTION: Container for a double-entry movement
-- PRIORITY: CRITICAL
-- SECURITY: Conservation law enforced via trigger
-- ============================================================================
-- TODO: [LEG-002] Create core.movement_headers table
-- INSTRUCTIONS:
--   - Represents a single financial event (e.g., a transfer)
--   - Links to originating transaction
--   - Ensures conservation: total_debits = total_credits
--   - RLS POLICY: Tenant isolation by application_id
--   - TRANSACTION ISOLATION: SERIALIZABLE for balance validation
-- COMPLIANCE: ISO/IEC 27040 (Financial Integrity)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.movement_headers (
--       -- Identity
--       movement_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       movement_reference  VARCHAR(100) UNIQUE NOT NULL, -- Human-readable
--       
--       -- Type & Classification
--       movement_type_id    UUID NOT NULL REFERENCES core.movement_types(movement_type_id),
--       transaction_id      UUID REFERENCES core.transaction_log(transaction_id),
--       
--       -- Application Context
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Financial Summary (enforced by triggers)
--       total_debits        NUMERIC(20, 8) NOT NULL DEFAULT 0,
--       total_credits       NUMERIC(20, 8) NOT NULL DEFAULT 0,
--       currency            VARCHAR(3) NOT NULL,
--       
--       -- Exchange (for multi-currency)
--       exchange_rate       NUMERIC(20, 10) DEFAULT 1.0,
--       base_currency       VARCHAR(3) DEFAULT 'USD',
--       base_amount         NUMERIC(20, 8),
--       
--       -- Dates
--       entry_date          DATE NOT NULL DEFAULT CURRENT_DATE,
--       value_date          DATE NOT NULL DEFAULT CURRENT_DATE,
--       accounting_date     DATE NOT NULL DEFAULT CURRENT_DATE,
--       
--       -- Status Workflow
--       status              VARCHAR(20) NOT NULL DEFAULT 'DRAFT',
--                           -- DRAFT, PENDING, POSTED, REVERSING, REVERSED
--       
--       -- Control
--       batch_id            UUID REFERENCES core.control_batches(batch_id),
--       control_hash        BYTEA,                       -- Hash of all leg hashes
--       
--       -- Idempotency
--       idempotency_key_id  UUID REFERENCES core.idempotency_keys(idempotency_key_id),
--       
--       -- Correlation
--       correlation_id      UUID,                        -- For grouping related movements
--       reversal_of         UUID REFERENCES core.movement_headers(movement_id),
--       
--       -- Metadata
--       description         TEXT,
--       external_reference  VARCHAR(255),
--       metadata            JSONB DEFAULT '{}',
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID NOT NULL REFERENCES core.accounts(account_id),
--       posted_at           TIMESTAMPTZ,
--       posted_by           UUID REFERENCES core.accounts(account_id),
--       
--       -- Integrity
--       movement_hash       BYTEA NOT NULL               -- Hash of header + all legs
--   );
--
-- CONSTRAINTS:
--   - CHECK (total_debits = total_credits) WHEN status = 'POSTED'
--   - CHECK (status IN ('DRAFT', 'PENDING', 'POSTED', 'REVERSING', 'REVERSED'))

-- =============================================================================
-- TODO: Create movement_legs table
-- DESCRIPTION: Individual debit/credit entries
-- PRIORITY: CRITICAL
-- SECURITY: Direction validation, positive amounts only
-- ============================================================================
-- TODO: [LEG-003] Create core.movement_legs table
-- INSTRUCTIONS:
--   - Each leg represents a single debit or credit to an account
--   - Must sum to zero (balanced) within each movement
--   - Immutable once posted
--   - ERROR HANDLING: Validate direction and amount constraints
-- COMPLIANCE: ISO/IEC 27040 (Entry Integrity)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.movement_legs (
--       -- Identity
--       leg_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       leg_sequence        INTEGER NOT NULL,            -- Order within movement
--       
--       -- Parent
--       movement_id         UUID NOT NULL REFERENCES core.movement_headers(movement_id),
--       
--       -- Account (Value Container)
--       account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
--       
--       -- Direction & Amount
--       direction           VARCHAR(6) NOT NULL,         -- 'DEBIT' or 'CREDIT'
--       CHECK (direction IN ('DEBIT', 'CREDIT')),
--       
--       amount              NUMERIC(20, 8) NOT NULL CHECK (amount > 0),
--       currency            VARCHAR(3) NOT NULL,
--       
--       -- Chart of Accounts (optional but recommended)
--       coa_code            VARCHAR(50) REFERENCES core.chart_of_accounts(coa_code),
--       
--       -- Running Balance (captured at posting time)
--       running_balance     NUMERIC(20, 8),              -- Balance after this leg
--       
--       -- Description
--       description         TEXT,
--       
--       -- Integrity
--       leg_hash            BYTEA NOT NULL,              -- Hash of leg data
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );
--
-- CONSTRAINTS:
--   - UNIQUE (movement_id, leg_sequence)
--   - Foreign key to accounts
--   - Index on (account_id, created_at) for balance queries

-- =============================================================================
-- TODO: Create conservation validation trigger
-- DESCRIPTION: Ensure debits equal credits
-- PRIORITY: CRITICAL
-- SECURITY: Prevent unbalanced postings
-- ============================================================================
-- TODO: [LEG-004] Create validate_movement_balance trigger
-- INSTRUCTIONS:
--   - BEFORE UPDATE ON movement_headers
--   - WHEN status changes to 'POSTED'
--   - Verify SUM(debits) = SUM(credits) in movement_legs
--   - ERROR HANDLING: Raise exception with details on imbalance
--   - TRANSACTION ISOLATION: Acquire lock on movement before validation
-- COMPLIANCE: ISO/IEC 27001 (Financial Controls)
--
-- TRIGGER FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.validate_movement_balance()
--   RETURNS TRIGGER AS $$
--   DECLARE
--       v_debits NUMERIC;
--       v_credits NUMERIC;
--   BEGIN
--       IF NEW.status = 'POSTED' AND OLD.status != 'POSTED' THEN
--           SELECT 
--               COALESCE(SUM(amount) FILTER (WHERE direction = 'DEBIT'), 0),
--               COALESCE(SUM(amount) FILTER (WHERE direction = 'CREDIT'), 0)
--           INTO v_debits, v_credits
--           FROM core.movement_legs
--           WHERE movement_id = NEW.movement_id;
--           
--           IF v_debits != v_credits THEN
--               RAISE EXCEPTION 'Movement % is unbalanced: debits=%, credits=%',
--                   NEW.movement_id, v_debits, v_credits;
--           END IF;
--           
--           NEW.total_debits := v_debits;
--           NEW.total_credits := v_credits;
--       END IF;
--       RETURN NEW;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create leg hash computation function
-- DESCRIPTION: Calculate hash for each leg
-- PRIORITY: HIGH
-- SECURITY: Deterministic hashing for verification
-- ============================================================================
-- TODO: [LEG-005] Create compute_leg_hash function
-- INSTRUCTIONS:
--   - Hash of movement_id, account_id, direction, amount, currency, coa_code
--   - Used for individual leg integrity verification
--   - SEARCH PATH: Explicitly set
-- COMPLIANCE: ISO/IEC 27040 (Cryptographic Integrity)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.compute_leg_hash(
--       p_movement_id UUID,
--       p_account_id UUID,
--       p_direction VARCHAR(6),
--       p_amount NUMERIC,
--       p_currency VARCHAR(3),
--       p_coa_code VARCHAR(50)
--   ) RETURNS BYTEA AS $$
--   BEGIN
--       RETURN digest(
--           p_movement_id::text ||
--           p_account_id::text ||
--           p_direction ||
--           p_amount::text ||
--           p_currency ||
--           COALESCE(p_coa_code, ''),
--           'sha256'
--       );
--   END;
--   $$ LANGUAGE plpgsql IMMUTABLE;

-- =============================================================================
-- TODO: Create movement control hash function
-- DESCRIPTION: Hash of all leg hashes combined
-- PRIORITY: MEDIUM
-- SECURITY: Aggregate integrity verification
-- ============================================================================
-- TODO: [LEG-006] Create compute_control_hash function
-- INSTRUCTIONS:
--   - Concatenate all leg hashes in sequence order
--   - Compute SHA-256 of concatenation
--   - Store in movement_headers.control_hash
-- COMPLIANCE: ISO/IEC 27040 (Aggregate Integrity)

-- =============================================================================
-- TODO: Create indexes for movement queries
-- DESCRIPTION: Optimize common query patterns
-- PRIORITY: HIGH
-- SECURITY: Index only necessary fields
-- ============================================================================
-- TODO: [LEG-007] Create movement indexes
-- INDEX LIST:
--   - PRIMARY KEY (movement_id)
--   - UNIQUE (movement_reference)
--   - INDEX on (transaction_id)
--   - INDEX on (application_id, entry_date)
--   - INDEX on (status, application_id) WHERE status = 'PENDING'
--   - INDEX on (correlation_id)
--   - INDEX on (reversal_of)
--   - INDEX on (batch_id)
--   - GIN INDEX on metadata
--
-- LEG INDEXES:
--   - PRIMARY KEY (leg_id)
--   - UNIQUE (movement_id, leg_sequence)
--   - INDEX on (account_id, created_at DESC)  -- For account history
--   - INDEX on (account_id, coa_code, created_at DESC)  -- For COA queries

/*
================================================================================
MIGRATION CHECKLIST:
□ Create movement_types registry
□ Create movement_headers table with conservation constraints
□ Create movement_legs table with debit/credit direction
□ Create balance validation trigger
□ Create leg hash computation function
□ Create control hash function for movement integrity
□ Add all indexes for movement/leg queries
□ Test double-entry balance enforcement
□ Verify foreign key constraints
================================================================================
*/
