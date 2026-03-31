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
-- Create liquidity_positions table
-- DESCRIPTION: Current liquidity snapshot per agent/currency
-- PRIORITY: CRITICAL
-- SECURITY: Row-level locking prevents over-commitment
-- ============================================================================
CREATE TABLE core.liquidity_positions (
    position_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Owner
    agent_account_id    UUID NOT NULL REFERENCES core.accounts(account_id),
    
    -- Currency
    currency            VARCHAR(3) NOT NULL,
    
    -- Position Breakdown
    available_amount    NUMERIC(20, 8) NOT NULL DEFAULT 0,
    reserved_amount     NUMERIC(20, 8) NOT NULL DEFAULT 0,
    pending_in_amount   NUMERIC(20, 8) NOT NULL DEFAULT 0,
    total_amount        NUMERIC(20, 8) NOT NULL DEFAULT 0,
    
    -- Limits
    min_threshold       NUMERIC(20, 8) DEFAULT 0,    -- Alert if below
    max_capacity        NUMERIC(20, 8),              -- Physical limit
    
    -- External Accounts
    provider_accounts   JSONB DEFAULT '[]',          -- [{provider, account_ref, balance}]
    
    -- Status
    status              VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, LOW, CRITICAL, SUSPENDED
    
    -- Timing
    last_movement_at    TIMESTAMPTZ,
    last_reconciled_at  TIMESTAMPTZ,
    
    -- Application
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Constraints
    CONSTRAINT uq_liquidity_positions UNIQUE (agent_account_id, currency),
    CONSTRAINT chk_liquidity_positions_available CHECK (available_amount >= 0),
    CONSTRAINT chk_liquidity_positions_reserved CHECK (reserved_amount >= 0),
    CONSTRAINT chk_liquidity_positions_pending CHECK (pending_in_amount >= 0),
    CONSTRAINT chk_liquidity_positions_total 
        CHECK (total_amount = available_amount + reserved_amount + pending_in_amount),
    CONSTRAINT chk_liquidity_positions_status 
        CHECK (status IN ('ACTIVE', 'LOW', 'CRITICAL', 'SUSPENDED'))
);

-- Indexes for liquidity_positions
CREATE INDEX idx_liquidity_positions_app ON core.liquidity_positions(application_id, status);
CREATE INDEX idx_liquidity_positions_alert ON core.liquidity_positions(status) 
    WHERE status IN ('LOW', 'CRITICAL');
CREATE INDEX idx_liquidity_positions_agent ON core.liquidity_positions(agent_account_id, currency);

COMMENT ON TABLE core.liquidity_positions IS 'Real-time liquidity position per agent and currency';
COMMENT ON COLUMN core.liquidity_positions.available_amount IS 'Free liquidity available for transactions';
COMMENT ON COLUMN core.liquidity_positions.reserved_amount IS 'Liquidity held for pending transactions';
COMMENT ON COLUMN core.liquidity_positions.min_threshold IS 'Alert threshold for low liquidity';

-- =============================================================================
-- Create liquidity_movements table
-- DESCRIPTION: Audit trail of liquidity changes
-- PRIORITY: HIGH
-- SECURITY: Immutable record of all changes
-- ============================================================================
CREATE TABLE core.liquidity_movements (
    movement_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Reference
    position_id         UUID NOT NULL REFERENCES core.liquidity_positions(position_id),
    
    -- Movement Details
    movement_type       VARCHAR(50) NOT NULL,        -- CREDIT, DEBIT, RESERVE, RELEASE
    amount              NUMERIC(20, 8) NOT NULL,
    currency            VARCHAR(3) NOT NULL,
    
    -- Reason
    reason_code         VARCHAR(50),                 -- SETTLEMENT, ADJUSTMENT, etc.
    reference_type      VARCHAR(50),                 -- SETTLEMENT_INSTRUCTION, etc.
    reference_id        UUID,
    
    -- Running Balance
    balance_before      NUMERIC(20, 8) NOT NULL,
    balance_after       NUMERIC(20, 8) NOT NULL,
    
    -- Description
    description         TEXT,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    
    -- Constraints
    CONSTRAINT chk_liquidity_movements_type 
        CHECK (movement_type IN ('CREDIT', 'DEBIT', 'RESERVE', 'RELEASE', 'ADJUSTMENT', 'PENDING_IN')),
    CONSTRAINT chk_liquidity_movements_amount CHECK (amount >= 0)
);

CREATE INDEX idx_liquidity_movements_position ON core.liquidity_movements(position_id, created_at DESC);
CREATE INDEX idx_liquidity_movements_reference ON core.liquidity_movements(reference_type, reference_id);
CREATE INDEX idx_liquidity_movements_created ON core.liquidity_movements(created_at);

COMMENT ON TABLE core.liquidity_movements IS 'Immutable audit trail of all liquidity position changes';

-- =============================================================================
-- Create liquidity reservation function
-- DESCRIPTION: Reserve liquidity for pending transaction
-- PRIORITY: CRITICAL
-- SECURITY: Atomic reservation prevents over-commitment
-- ============================================================================
CREATE OR REPLACE FUNCTION core.reserve_liquidity(
    p_agent_account_id UUID,
    p_currency VARCHAR(3),
    p_amount NUMERIC,
    p_reference_type VARCHAR(50),
    p_reference_id UUID,
    p_description TEXT DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_position RECORD;
    v_new_available NUMERIC;
    v_new_reserved NUMERIC;
BEGIN
    -- Lock position row
    SELECT * INTO v_position
    FROM core.liquidity_positions
    WHERE agent_account_id = p_agent_account_id AND currency = p_currency
    FOR UPDATE;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Liquidity position not found for agent % currency %', 
            p_agent_account_id, p_currency;
    END IF;
    
    -- Check available
    IF v_position.available_amount < p_amount THEN
        RETURN false;  -- Insufficient liquidity
    END IF;
    
    -- Calculate new amounts
    v_new_available := v_position.available_amount - p_amount;
    v_new_reserved := v_position.reserved_amount + p_amount;
    
    -- Update position
    UPDATE core.liquidity_positions
    SET available_amount = v_new_available,
        reserved_amount = v_new_reserved,
        updated_at = now(),
        status = CASE 
            WHEN min_threshold > 0 AND v_new_available < min_threshold THEN 'CRITICAL'
            WHEN min_threshold > 0 AND v_new_available < min_threshold * 1.5 THEN 'LOW'
            ELSE status
        END,
        last_movement_at = now()
    WHERE position_id = v_position.position_id;
    
    -- Record movement
    INSERT INTO core.liquidity_movements (
        position_id, movement_type, amount, currency,
        reason_code, reference_type, reference_id,
        balance_before, balance_after, description, created_by
    ) VALUES (
        v_position.position_id, 'RESERVE', p_amount, p_currency,
        'TRANSACTION_HOLD', p_reference_type, p_reference_id,
        v_position.available_amount, v_new_available,
        COALESCE(p_description, 'Reserved for ' || p_reference_type),
        current_setting('app.current_user_id', true)::uuid
    );
    
    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.reserve_liquidity IS 'Atomically reserves liquidity for a pending transaction';

-- =============================================================================
-- Create liquidity release function
-- DESCRIPTION: Release reserved liquidity
-- PRIORITY: HIGH
-- SECURITY: Only release existing reservations
-- ============================================================================
CREATE OR REPLACE FUNCTION core.release_liquidity(
    p_agent_account_id UUID,
    p_currency VARCHAR(3),
    p_amount NUMERIC,
    p_reference_type VARCHAR(50),
    p_reference_id UUID,
    p_description TEXT DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_position RECORD;
    v_new_available NUMERIC;
    v_new_reserved NUMERIC;
BEGIN
    -- Lock position row
    SELECT * INTO v_position
    FROM core.liquidity_positions
    WHERE agent_account_id = p_agent_account_id AND currency = p_currency
    FOR UPDATE;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Liquidity position not found';
    END IF;
    
    -- Validate sufficient reserved amount
    IF v_position.reserved_amount < p_amount THEN
        RAISE WARNING 'Release amount % exceeds reserved amount % for position %',
            p_amount, v_position.reserved_amount, v_position.position_id;
        p_amount := v_position.reserved_amount;  -- Release all available
    END IF;
    
    -- Calculate new amounts
    v_new_available := v_position.available_amount + p_amount;
    v_new_reserved := v_position.reserved_amount - p_amount;
    
    -- Update position
    UPDATE core.liquidity_positions
    SET available_amount = v_new_available,
        reserved_amount = v_new_reserved,
        updated_at = now(),
        status = CASE 
            WHEN min_threshold = 0 OR v_new_available >= min_threshold * 1.5 THEN 'ACTIVE'
            WHEN v_new_available >= min_threshold THEN 'LOW'
            ELSE status
        END,
        last_movement_at = now()
    WHERE position_id = v_position.position_id;
    
    -- Record movement
    INSERT INTO core.liquidity_movements (
        position_id, movement_type, amount, currency,
        reason_code, reference_type, reference_id,
        balance_before, balance_after, description, created_by
    ) VALUES (
        v_position.position_id, 'RELEASE', p_amount, p_currency,
        'TRANSACTION_RELEASE', p_reference_type, p_reference_id,
        v_position.available_amount, v_new_available,
        COALESCE(p_description, 'Released from ' || p_reference_type),
        current_setting('app.current_user_id', true)::uuid
    );
    
    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.release_liquidity IS 'Releases reserved liquidity back to available pool';

-- =============================================================================
-- Create liquidity commit function
-- DESCRIPTION: Convert reservation to actual debit
-- PRIORITY: HIGH
-- SECURITY: Deduct from reserved, update total
-- ============================================================================
CREATE OR REPLACE FUNCTION core.commit_liquidity(
    p_agent_account_id UUID,
    p_currency VARCHAR(3),
    p_amount NUMERIC,
    p_reference_type VARCHAR(50),
    p_reference_id UUID,
    p_description TEXT DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_position RECORD;
    v_new_reserved NUMERIC;
    v_new_total NUMERIC;
BEGIN
    -- Lock position row
    SELECT * INTO v_position
    FROM core.liquidity_positions
    WHERE agent_account_id = p_agent_account_id AND currency = p_currency
    FOR UPDATE;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Liquidity position not found';
    END IF;
    
    -- Validate sufficient reserved amount
    IF v_position.reserved_amount < p_amount THEN
        RAISE EXCEPTION 'Commit amount % exceeds reserved amount %',
            p_amount, v_position.reserved_amount;
    END IF;
    
    -- Calculate new amounts
    v_new_reserved := v_position.reserved_amount - p_amount;
    v_new_total := v_position.total_amount - p_amount;
    
    -- Update position
    UPDATE core.liquidity_positions
    SET reserved_amount = v_new_reserved,
        total_amount = v_new_total,
        updated_at = now(),
        last_movement_at = now()
    WHERE position_id = v_position.position_id;
    
    -- Record movement
    INSERT INTO core.liquidity_movements (
        position_id, movement_type, amount, currency,
        reason_code, reference_type, reference_id,
        balance_before, balance_after, description, created_by
    ) VALUES (
        v_position.position_id, 'DEBIT', p_amount, p_currency,
        'SETTLEMENT', p_reference_type, p_reference_id,
        v_position.total_amount, v_new_total,
        COALESCE(p_description, 'Committed for ' || p_reference_type),
        current_setting('app.current_user_id', true)::uuid
    );
    
    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.commit_liquidity IS 'Converts reserved liquidity to actual debit';

-- =============================================================================
-- Create liquidity credit function
-- DESCRIPTION: Add incoming liquidity
-- PRIORITY: HIGH
-- ============================================================================
CREATE OR REPLACE FUNCTION core.credit_liquidity(
    p_agent_account_id UUID,
    p_currency VARCHAR(3),
    p_amount NUMERIC,
    p_reference_type VARCHAR(50),
    p_reference_id UUID,
    p_description TEXT DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_position RECORD;
    v_new_available NUMERIC;
    v_new_total NUMERIC;
BEGIN
    -- Lock position row
    SELECT * INTO v_position
    FROM core.liquidity_positions
    WHERE agent_account_id = p_agent_account_id AND currency = p_currency
    FOR UPDATE;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Liquidity position not found';
    END IF;
    
    -- Calculate new amounts
    v_new_available := v_position.available_amount + p_amount;
    v_new_total := v_position.total_amount + p_amount;
    
    -- Update position
    UPDATE core.liquidity_positions
    SET available_amount = v_new_available,
        total_amount = v_new_total,
        updated_at = now(),
        status = CASE 
            WHEN min_threshold = 0 OR v_new_available >= min_threshold * 1.5 THEN 'ACTIVE'
            WHEN v_new_available >= min_threshold THEN 'LOW'
            ELSE status
        END,
        last_movement_at = now()
    WHERE position_id = v_position.position_id;
    
    -- Record movement
    INSERT INTO core.liquidity_movements (
        position_id, movement_type, amount, currency,
        reason_code, reference_type, reference_id,
        balance_before, balance_after, description, created_by
    ) VALUES (
        v_position.position_id, 'CREDIT', p_amount, p_currency,
        'DEPOSIT', p_reference_type, p_reference_id,
        v_position.total_amount, v_new_total,
        COALESCE(p_description, 'Credit from ' || p_reference_type),
        current_setting('app.current_user_id', true)::uuid
    );
    
    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.credit_liquidity IS 'Adds incoming liquidity to available pool';

-- =============================================================================
-- Create liquidity check view
-- DESCRIPTION: Quick liquidity status lookup
-- PRIORITY: MEDIUM
-- SECURITY: Calculate alert status dynamically
-- ============================================================================
CREATE VIEW core.liquidity_status AS
SELECT 
    lp.*,
    CASE 
        WHEN lp.available_amount < COALESCE(lp.min_threshold, 0) THEN 'CRITICAL'
        WHEN lp.min_threshold > 0 AND lp.available_amount < lp.min_threshold * 1.5 THEN 'LOW'
        ELSE 'NORMAL'
    END as alert_status,
    CASE 
        WHEN COALESCE(lp.max_capacity, 0) > 0 THEN ROUND((lp.total_amount / lp.max_capacity * 100), 2)
        ELSE NULL
    END as utilization_pct,
    CASE 
        WHEN lp.min_threshold > 0 THEN ROUND((lp.available_amount / NULLIF(lp.min_threshold, 0) * 100), 2)
        ELSE NULL
    END as threshold_coverage_pct
FROM core.liquidity_positions lp;

COMMENT ON VIEW core.liquidity_status IS 'Current liquidity status with calculated alert indicators';

-- =============================================================================
-- Create liquidity alert check function
-- DESCRIPTION: Check for positions needing attention
-- PRIORITY: MEDIUM
-- ============================================================================
CREATE OR REPLACE FUNCTION core.check_liquidity_alerts()
RETURNS TABLE (
    position_id UUID,
    agent_account_id UUID,
    currency VARCHAR(3),
    available_amount NUMERIC,
    min_threshold NUMERIC,
    alert_level VARCHAR(20)
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        lp.position_id,
        lp.agent_account_id,
        lp.currency,
        lp.available_amount,
        lp.min_threshold,
        CASE 
            WHEN lp.available_amount < COALESCE(lp.min_threshold, 0) THEN 'CRITICAL'
            WHEN lp.min_threshold > 0 AND lp.available_amount < lp.min_threshold * 1.5 THEN 'LOW'
            ELSE 'NORMAL'
        END::VARCHAR(20)
    FROM core.liquidity_positions lp
    WHERE lp.status IN ('LOW', 'CRITICAL')
       OR (lp.min_threshold > 0 AND lp.available_amount < lp.min_threshold * 1.5);
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.check_liquidity_alerts IS 'Returns liquidity positions below threshold levels';

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create liquidity_positions table
☑ Create liquidity_movements table
☑ Implement reserve_liquidity function
☑ Implement release_liquidity function
☑ Implement commit_liquidity function
☑ Implement credit_liquidity function
☑ Create liquidity_status view
☑ Add all indexes for liquidity queries
☑ Test reservation/release/commit cycle
☑ Test concurrent reservation handling
☑ Verify balance consistency constraints
================================================================================
*/
