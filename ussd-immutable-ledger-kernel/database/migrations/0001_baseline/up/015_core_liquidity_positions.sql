-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Capacity management)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Liquidity monitoring)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Agent data handling)
-- ISO/IEC 27040:2024 - Storage Security (Position integrity)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Liquidity alerts)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Real-time position updates with locking
-- - Multi-currency support
-- - Low liquidity alerts
-- - Liquidity reservation for pending transactions
-- ============================================================================
-- =============================================================================
-- MIGRATION: 015_core_liquidity_positions.sql
-- DESCRIPTION: Real-Time Liquidity Position Tracking
-- TABLES: liquidity_positions, liquidity_movements
-- DEPENDENCIES: 003_core_account_registry.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 7. Settlement & External Integration
- Feature: Liquidity Positions (Simplified)
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Real-time tracking of available liquidity per agent/currency across multiple
mobile money wallets or bank accounts. Prevents over-commitment by ensuring
sufficient float before approving withdrawals.

KEY FEATURES:
- Per-agent liquidity tracking
- Multi-currency support
- Real-time position updates
- Low liquidity alerts
- Liquidity reservation for pending transactions

LIQUIDITY TYPES:
- AVAILABLE: Free to use
- RESERVED: Held for pending transactions
- PENDING_IN: Incoming but not confirmed
- TOTAL: Sum of all above
================================================================================
*/

-- =============================================================================
-- TODO: Create liquidity_positions table
-- DESCRIPTION: Current liquidity snapshot per agent/currency
-- PRIORITY: CRITICAL
-- SECURITY: Row-level locking prevents over-commitment
-- ============================================================================
-- TODO: [LIQ-001] Create core.liquidity_positions table
-- INSTRUCTIONS:
--   - Real-time position tracking
--   - Updated on every liquidity movement
--   - Supports alerts on low liquidity
--   - RLS POLICY: Tenant isolation
--   - ERROR HANDLING: Validate available_amount >= 0
-- COMPLIANCE: ISO/IEC 27001 (Resource Monitoring)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.liquidity_positions (
--       position_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Owner
--       agent_account_id    UUID NOT NULL REFERENCES core.accounts(account_id),
--       
--       -- Currency
--       currency            VARCHAR(3) NOT NULL,
--       
--       -- Position Breakdown
--       available_amount    NUMERIC(20, 8) NOT NULL DEFAULT 0,
--       reserved_amount     NUMERIC(20, 8) NOT NULL DEFAULT 0,
--       pending_in_amount   NUMERIC(20, 8) NOT NULL DEFAULT 0,
--       total_amount        NUMERIC(20, 8) NOT NULL DEFAULT 0,
--       
--       -- Limits
--       min_threshold       NUMERIC(20, 8) DEFAULT 0,    -- Alert if below
--       max_capacity        NUMERIC(20, 8),              -- Physical limit
--       
--       -- External Accounts
--       provider_accounts   JSONB DEFAULT '[]',          -- [{provider, account_ref, balance}]
--       
--       -- Status
--       status              VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, LOW, CRITICAL, SUSPENDED
--       
--       -- Timing
--       last_movement_at    TIMESTAMPTZ,
--       last_reconciled_at  TIMESTAMPTZ,
--       
--       -- Application
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );
--
-- CONSTRAINTS:
--   - UNIQUE (agent_account_id, currency)
--   - CHECK (available_amount >= 0)
--   - CHECK (reserved_amount >= 0)
--   - CHECK (total_amount = available_amount + reserved_amount + pending_in_amount)

-- =============================================================================
-- TODO: Create liquidity_movements table
-- DESCRIPTION: Audit trail of liquidity changes
-- PRIORITY: HIGH
-- SECURITY: Immutable record of all changes
-- ============================================================================
-- TODO: [LIQ-002] Create core.liquidity_movements table
-- INSTRUCTIONS:
--   - Immutable record of all liquidity changes
--   - Links to settlement instructions
--   - Supports reconciliation
--   - AUDIT LOGGING: All movements logged
-- COMPLIANCE: ISO/IEC 27040 (Change Tracking)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.liquidity_movements (
--       movement_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Reference
--       position_id         UUID NOT NULL REFERENCES core.liquidity_positions(position_id),
--       
--       -- Movement Details
--       movement_type       VARCHAR(50) NOT NULL,        -- CREDIT, DEBIT, RESERVE, RELEASE
--       amount              NUMERIC(20, 8) NOT NULL,
--       currency            VARCHAR(3) NOT NULL,
--       
--       -- Reason
--       reason_code         VARCHAR(50),                 -- SETTLEMENT, ADJUSTMENT, etc.
--       reference_type      VARCHAR(50),                 -- SETTLEMENT_INSTRUCTION, etc.
--       reference_id        UUID,
--       
--       -- Running Balance
--       balance_before      NUMERIC(20, 8) NOT NULL,
--       balance_after       NUMERIC(20, 8) NOT NULL,
--       
--       -- Description
--       description         TEXT,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id)
--   );

-- =============================================================================
-- TODO: Create liquidity reservation function
-- DESCRIPTION: Reserve liquidity for pending transaction
-- PRIORITY: CRITICAL
-- SECURITY: Atomic reservation prevents over-commitment
-- ============================================================================
-- TODO: [LIQ-003] Create reserve_liquidity function
-- INSTRUCTIONS:
--   - Atomically reserve liquidity
--   - Fail if insufficient available
--   - Record reservation movement
--   - ERROR HANDLING: Return false on insufficient liquidity
--   - TRANSACTION ISOLATION: Row-level lock for atomicity
-- COMPLIANCE: ISO/IEC 27031 (Atomic Reservation)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.reserve_liquidity(
--       p_agent_account_id UUID,
--       p_currency VARCHAR(3),
--       p_amount NUMERIC,
--       p_reference_type VARCHAR(50),
--       p_reference_id UUID
--   ) RETURNS BOOLEAN AS $$
--   DECLARE
--       v_position RECORD;
--   BEGIN
--       -- Lock position row
--       SELECT * INTO v_position
--       FROM core.liquidity_positions
--       WHERE agent_account_id = p_agent_account_id AND currency = p_currency
--       FOR UPDATE;
--       
--       IF NOT FOUND THEN
--           RAISE EXCEPTION 'Liquidity position not found';
--       END IF;
--       
--       -- Check available
--       IF v_position.available_amount < p_amount THEN
--           RETURN false;  -- Insufficient liquidity
--       END IF;
--       
--       -- Update position
--       UPDATE core.liquidity_positions
--       SET available_amount = available_amount - p_amount,
--           reserved_amount = reserved_amount + p_amount,
--           updated_at = now()
--       WHERE position_id = v_position.position_id;
--       
--       -- Record movement
--       INSERT INTO core.liquidity_movements (
--           position_id, movement_type, amount, currency,
--           reason_code, reference_type, reference_id,
--           balance_before, balance_after, description
--       ) VALUES (
--           v_position.position_id, 'RESERVE', p_amount, p_currency,
--           'TRANSACTION_HOLD', p_reference_type, p_reference_id,
--           v_position.available_amount,
--           v_position.available_amount - p_amount,
--           'Reserved for ' || p_reference_type
--       );
--       
--       RETURN true;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create liquidity release function
-- DESCRIPTION: Release reserved liquidity
-- PRIORITY: HIGH
-- SECURITY: Only release existing reservations
-- ============================================================================
-- TODO: [LIQ-004] Create release_liquidity function
-- INSTRUCTIONS:
--   - Return reserved amount to available
--   - Used on transaction failure/cancellation
--   - Record release movement
--   - ERROR HANDLING: Validate reservation exists
-- COMPLIANCE: ISO/IEC 27031 (Release Control)

-- =============================================================================
-- TODO: Create liquidity commit function
-- DESCRIPTION: Convert reservation to actual debit
-- PRIORITY: HIGH
-- SECURITY: Deduct from reserved, update total
-- ============================================================================
-- TODO: [LIQ-005] Create commit_liquidity function
-- INSTRUCTIONS:
--   - Move from reserved to actual deduction
--   - Update total amount
--   - Record debit movement
--   - ERROR HANDLING: Validate sufficient reserved amount
-- COMPLIANCE: ISO/IEC 27040 (Commit Integrity)

-- =============================================================================
-- TODO: Create liquidity check view
-- DESCRIPTION: Quick liquidity status lookup
-- PRIORITY: MEDIUM
-- SECURITY: Calculate alert status dynamically
-- ============================================================================
-- TODO: [LIQ-006] Create liquidity_status view
-- INSTRUCTIONS:
--   - Show all positions with status indicators
--   - Calculate utilization percentage
--   - Flag positions below threshold
--   - RLS POLICY: Tenant isolation
-- COMPLIANCE: ISO/IEC 27031 (Status Monitoring)
--
-- VIEW DEFINITION:
--   CREATE VIEW core.liquidity_status AS
--   SELECT 
--       lp.*,
--       CASE 
--           WHEN available_amount < min_threshold THEN 'CRITICAL'
--           WHEN available_amount < min_threshold * 1.5 THEN 'LOW'
--           ELSE 'NORMAL'
--       END as alert_status,
--       CASE 
--           WHEN max_capacity > 0 THEN (total_amount / max_capacity * 100)
--           ELSE NULL
--       END as utilization_pct
--   FROM core.liquidity_positions lp;

-- =============================================================================
-- TODO: Create liquidity indexes
-- DESCRIPTION: Optimize liquidity queries
-- PRIORITY: HIGH
-- SECURITY: Index on status for alert queries
-- ============================================================================
-- TODO: [LIQ-007] Create liquidity indexes
-- INDEX LIST:
--   - PRIMARY KEY (position_id)
--   - UNIQUE (agent_account_id, currency)
--   - INDEX on (application_id, status)
--   - INDEX on (status) WHERE status IN ('LOW', 'CRITICAL')
--   -- Movements:
--   - INDEX on (position_id, created_at)
--   - INDEX on (reference_type, reference_id)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create liquidity_positions table
□ Create liquidity_movements table
□ Implement reserve_liquidity function
□ Implement release_liquidity function
□ Implement commit_liquidity function
□ Create liquidity_status view
□ Add all indexes for liquidity queries
□ Test reservation/release/commit cycle
□ Test concurrent reservation handling
□ Verify balance consistency constraints
================================================================================
*/
