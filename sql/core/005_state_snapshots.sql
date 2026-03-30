-- ============================================================================
-- USSD KERNEL CORE SCHEMA - STATE SNAPSHOTS
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Materialized views and derived state from the transaction log.
--              These are NOT sources of truth - they can be rebuilt entirely
--              from the immutable transaction log.
-- Immutability: Derived/Rebuildable - Refreshed periodically
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. ACCOUNT STATE SNAPSHOT TABLE (Balances, nonces, etc.)
-- ----------------------------------------------------------------------------
-- This is a persistent cache that can be rebuilt from the transaction log
CREATE TABLE ussd_core.account_state_snapshots (
    snapshot_id BIGSERIAL PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    
    -- Computed state
    current_balance NUMERIC(20, 8) DEFAULT 0,
    available_balance NUMERIC(20, 8) DEFAULT 0,  -- After holds/reserves
    hold_balance NUMERIC(20, 8) DEFAULT 0,  -- Reserved amounts
    
    -- Transaction tracking
    last_transaction_id BIGINT,
    last_transaction_hash VARCHAR(64),
    transaction_count BIGINT DEFAULT 0,
    
    -- Sequence for idempotency/ordering
    last_sequence_number BIGINT DEFAULT 0,
    
    -- Metadata from latest transaction
    last_activity_at TIMESTAMPTZ,
    
    -- Computed at
    computed_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    computed_from_block BIGINT,  -- For incremental updates
    
    -- Version for optimistic locking
    version BIGINT DEFAULT 1,
    
    UNIQUE(account_id)
);

-- ----------------------------------------------------------------------------
-- 2. ACCOUNT STATE HISTORY (Point-in-time recovery)
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_core.account_state_history (
    history_id BIGSERIAL PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    
    -- State at this point
    balance NUMERIC(20, 8),
    transaction_id BIGINT,  -- Up to this transaction
    
    -- When this state was recorded
    recorded_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    
    -- For daily closing snapshots
    snapshot_date DATE,
    
    UNIQUE(account_id, snapshot_date)
);

-- ----------------------------------------------------------------------------
-- 3. APPLICATION STATE AGGREGATES
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_core.application_state_snapshots (
    snapshot_id BIGSERIAL PRIMARY KEY,
    application_id UUID NOT NULL,
    
    -- Aggregate metrics
    total_transactions BIGINT DEFAULT 0,
    total_volume NUMERIC(20, 8) DEFAULT 0,
    unique_accounts INTEGER DEFAULT 0,
    
    -- Transaction type breakdown (stored as JSONB)
    type_breakdown JSONB DEFAULT '{}',
    
    -- Time range
    from_transaction_id BIGINT,
    to_transaction_id BIGINT,
    from_time TIMESTAMPTZ,
    to_time TIMESTAMPTZ,
    
    -- Computed at
    computed_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    
    UNIQUE(application_id)
);

-- ----------------------------------------------------------------------------
-- 4. INDEXES
-- ----------------------------------------------------------------------------

-- Account state indexes
CREATE INDEX idx_account_state_account ON ussd_core.account_state_snapshots(account_id);
CREATE INDEX idx_account_state_balance ON ussd_core.account_state_snapshots(current_balance) 
    WHERE current_balance != 0;
CREATE INDEX idx_account_state_activity ON ussd_core.account_state_snapshots(last_activity_at DESC);

-- History indexes
CREATE INDEX idx_state_history_account ON ussd_core.account_state_history(account_id);
CREATE INDEX idx_state_history_date ON ussd_core.account_state_history(snapshot_date);

-- Application state indexes
CREATE INDEX idx_app_state_application ON ussd_core.application_state_snapshots(application_id);
CREATE INDEX idx_app_state_computed ON ussd_core.application_state_snapshots(computed_at DESC);

-- ----------------------------------------------------------------------------
-- 5. STATE COMPUTATION FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to compute account state from transaction log
CREATE OR REPLACE FUNCTION ussd_core.compute_account_state(
    p_account_id UUID,
    p_up_to_transaction_id BIGINT DEFAULT NULL
)
RETURNS TABLE (
    current_balance NUMERIC,
    transaction_count BIGINT,
    last_transaction_id BIGINT,
    last_transaction_hash VARCHAR(64),
    last_activity_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    WITH account_transactions AS (
        SELECT 
            t.transaction_id,
            t.transaction_hash,
            t.committed_at,
            t.payload,
            tt.type_code
        FROM ussd_core.transactions t
        JOIN ussd_core.transaction_types tt ON t.transaction_type_id = tt.type_id
        WHERE t.initiator_account_id = p_account_id
          AND t.status = 'committed'
          AND (p_up_to_transaction_id IS NULL OR t.transaction_id <= p_up_to_transaction_id)
        ORDER BY t.committed_at, t.transaction_id
    )
    SELECT 
        COALESCE(SUM(
            CASE 
                -- Debit transactions (outgoing)
                WHEN at.type_code IN ('TRANSFER', 'PAYMENT', 'FEE_COLLECTION', 'WITHDRAWAL') 
                    THEN -COALESCE((at.payload->>'amount')::NUMERIC, 0)
                -- Credit transactions (incoming)
                WHEN at.type_code IN ('DEPOSIT', 'REFUND', 'CASHBACK', 'INTEREST') 
                    THEN COALESCE((at.payload->>'amount')::NUMERIC, 0)
                -- Transfer to self (net zero, but we track it)
                WHEN at.type_code = 'TRANSFER' AND (at.payload->>'to_account_id')::UUID = p_account_id
                    THEN COALESCE((at.payload->>'amount')::NUMERIC, 0)
                ELSE 0
            END
        ), 0) as current_balance,
        COUNT(*)::BIGINT as transaction_count,
        MAX(at.transaction_id) as last_transaction_id,
        MAX(at.transaction_hash) as last_transaction_hash,
        MAX(at.committed_at) as last_activity_at
    FROM account_transactions at;
END;
$$;

-- Function to refresh a single account state
CREATE OR REPLACE FUNCTION ussd_core.refresh_account_state(p_account_id UUID)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_state RECORD;
    v_current_version BIGINT;
BEGIN
    -- Get current version for optimistic locking
    SELECT version INTO v_current_version
    FROM ussd_core.account_state_snapshots
    WHERE account_id = p_account_id;
    
    -- Compute new state
    SELECT * INTO v_state FROM ussd_core.compute_account_state(p_account_id);
    
    IF v_current_version IS NULL THEN
        -- Insert new
        INSERT INTO ussd_core.account_state_snapshots (
            account_id, current_balance, available_balance,
            last_transaction_id, last_transaction_hash, transaction_count,
            last_activity_at, version
        ) VALUES (
            p_account_id, v_state.current_balance, v_state.current_balance,
            v_state.last_transaction_id, v_state.last_transaction_hash, v_state.transaction_count,
            v_state.last_activity_at, 1
        );
    ELSE
        -- Update existing
        UPDATE ussd_core.account_state_snapshots
        SET current_balance = v_state.current_balance,
            available_balance = v_state.current_balance - hold_balance,
            last_transaction_id = v_state.last_transaction_id,
            last_transaction_hash = v_state.last_transaction_hash,
            transaction_count = v_state.transaction_count,
            last_activity_at = v_state.last_activity_at,
            computed_at = ussd_core.precise_now(),
            version = version + 1
        WHERE account_id = p_account_id
          AND version = v_current_version;  -- Optimistic lock
        
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Concurrent modification detected for account %', p_account_id;
        END IF;
    END IF;
END;
$$;

-- Function to refresh all account states (batch)
CREATE OR REPLACE FUNCTION ussd_core.refresh_all_account_states(
    p_batch_size INTEGER DEFAULT 1000
)
RETURNS TABLE (accounts_processed INTEGER, errors TEXT[])
LANGUAGE plpgsql
AS $$
DECLARE
    v_account_id UUID;
    v_count INTEGER := 0;
    v_errors TEXT[] := '{}';
BEGIN
    FOR v_account_id IN 
        SELECT DISTINCT initiator_account_id 
        FROM ussd_core.transactions 
        WHERE committed_at > NOW() - INTERVAL '1 hour'
        LIMIT p_batch_size
    LOOP
        BEGIN
            PERFORM ussd_core.refresh_account_state(v_account_id);
            v_count := v_count + 1;
        EXCEPTION WHEN OTHERS THEN
            v_errors := array_append(v_errors, v_account_id::TEXT || ': ' || SQLERRM);
        END;
    END LOOP;
    
    RETURN QUERY SELECT v_count, v_errors;
END;
$$;

-- Function to compute application aggregates
CREATE OR REPLACE FUNCTION ussd_core.compute_application_state(p_application_id UUID)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO ussd_core.application_state_snapshots (
        application_id,
        total_transactions,
        total_volume,
        unique_accounts,
        type_breakdown,
        from_transaction_id,
        to_transaction_id,
        from_time,
        to_time,
        computed_at
    )
    SELECT 
        p_application_id,
        COUNT(*)::BIGINT as total_transactions,
        COALESCE(SUM((t.payload->>'amount')::NUMERIC), 0) as total_volume,
        COUNT(DISTINCT t.initiator_account_id)::INTEGER as unique_accounts,
        jsonb_object_agg(tt.type_code, cnt) as type_breakdown,
        MIN(t.transaction_id) as from_transaction_id,
        MAX(t.transaction_id) as to_transaction_id,
        MIN(t.committed_at) as from_time,
        MAX(t.committed_at) as to_time,
        ussd_core.precise_now()
    FROM ussd_core.transactions t
    JOIN ussd_core.transaction_types tt ON t.transaction_type_id = tt.type_id
    JOIN (
        SELECT transaction_type_id, COUNT(*) as cnt
        FROM ussd_core.transactions
        WHERE application_id = p_application_id
        GROUP BY transaction_type_id
    ) tc ON t.transaction_type_id = tc.transaction_type_id
    WHERE t.application_id = p_application_id
      AND t.status = 'committed'
    ON CONFLICT (application_id) DO UPDATE
    SET total_transactions = EXCLUDED.total_transactions,
        total_volume = EXCLUDED.total_volume,
        unique_accounts = EXCLUDED.unique_accounts,
        type_breakdown = EXCLUDED.type_breakdown,
        from_transaction_id = EXCLUDED.from_transaction_id,
        to_transaction_id = EXCLUDED.to_transaction_id,
        from_time = EXCLUDED.from_time,
        to_time = EXCLUDED.to_time,
        computed_at = EXCLUDED.computed_at;
END;
$$;

-- ----------------------------------------------------------------------------
-- 6. POINT-IN-TIME QUERY FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to get account state at a specific time
CREATE OR REPLACE FUNCTION ussd_core.get_account_state_at_time(
    p_account_id UUID,
    p_at_time TIMESTAMPTZ
)
RETURNS TABLE (
    current_balance NUMERIC,
    transaction_count BIGINT,
    last_transaction_id BIGINT,
    computed_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    -- First check if we have a historical snapshot
    RETURN QUERY
    SELECT 
        h.balance,
        (SELECT COUNT(*) FROM ussd_core.transactions 
         WHERE initiator_account_id = p_account_id 
           AND committed_at <= p_at_time)::BIGINT,
        h.transaction_id,
        h.recorded_at
    FROM ussd_core.account_state_history h
    WHERE h.account_id = p_account_id
      AND h.snapshot_date <= p_at_time::DATE
    ORDER BY h.snapshot_date DESC
    LIMIT 1;
    
    -- If no history, compute from scratch
    IF NOT FOUND THEN
        RETURN QUERY
        SELECT * FROM ussd_core.compute_account_state(
            p_account_id,
            (SELECT MAX(transaction_id) FROM ussd_core.transactions 
             WHERE initiator_account_id = p_account_id 
               AND committed_at <= p_at_time)
        );
    END IF;
END;
$$;

-- Function to replay transactions for an account
CREATE OR REPLACE FUNCTION ussd_core.replay_account_transactions(
    p_account_id UUID,
    p_from_time TIMESTAMPTZ DEFAULT NULL,
    p_to_time TIMESTAMPTZ DEFAULT NULL
)
RETURNS TABLE (
    transaction_id BIGINT,
    committed_at TIMESTAMPTZ,
    type_code VARCHAR(50),
    amount NUMERIC,
    running_balance NUMERIC
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_running_balance NUMERIC := 0;
    v_tx RECORD;
BEGIN
    FOR v_tx IN 
        SELECT 
            t.transaction_id,
            t.committed_at,
            tt.type_code,
            COALESCE((t.payload->>'amount')::NUMERIC, 0) as amount,
            t.payload
        FROM ussd_core.transactions t
        JOIN ussd_core.transaction_types tt ON t.transaction_type_id = tt.type_id
        WHERE t.initiator_account_id = p_account_id
          AND t.status = 'committed'
          AND (p_from_time IS NULL OR t.committed_at >= p_from_time)
          AND (p_to_time IS NULL OR t.committed_at <= p_to_time)
        ORDER BY t.committed_at, t.transaction_id
    LOOP
        -- Calculate balance change
        v_running_balance := v_running_balance + CASE 
            WHEN v_tx.type_code IN ('TRANSFER', 'PAYMENT', 'FEE_COLLECTION', 'WITHDRAWAL') 
                THEN -v_tx.amount
            WHEN v_tx.type_code IN ('DEPOSIT', 'REFUND', 'CASHBACK') 
                THEN v_tx.amount
            ELSE 0
        END;
        
        transaction_id := v_tx.transaction_id;
        committed_at := v_tx.committed_at;
        type_code := v_tx.type_code;
        amount := v_tx.amount;
        running_balance := v_running_balance;
        RETURN NEXT;
    END LOOP;
END;
$$;

-- ----------------------------------------------------------------------------
-- 7. DAILY SNAPSHOT ARCHIVAL
-- ----------------------------------------------------------------------------

-- Function to create end-of-day snapshots
CREATE OR REPLACE FUNCTION ussd_core.create_daily_snapshot(
    p_snapshot_date DATE DEFAULT CURRENT_DATE - 1
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_account_id UUID;
    v_count INTEGER := 0;
    v_state RECORD;
BEGIN
    FOR v_account_id IN 
        SELECT DISTINCT initiator_account_id 
        FROM ussd_core.transactions 
        WHERE committed_at::DATE <= p_snapshot_date
          AND committed_at::DATE > p_snapshot_date - INTERVAL '30 days'  -- Recent activity only
    LOOP
        SELECT * INTO v_state FROM ussd_core.compute_account_state(v_account_id);
        
        INSERT INTO ussd_core.account_state_history (
            account_id, balance, transaction_id, snapshot_date, recorded_at
        ) VALUES (
            v_account_id, v_state.current_balance, v_state.last_transaction_id,
            p_snapshot_date, ussd_core.precise_now()
        )
        ON CONFLICT (account_id, snapshot_date) DO UPDATE
        SET balance = EXCLUDED.balance,
            transaction_id = EXCLUDED.transaction_id,
            recorded_at = EXCLUDED.recorded_at;
        
        v_count := v_count + 1;
    END LOOP;
    
    RETURN v_count;
END;
$$;

-- ----------------------------------------------------------------------------
-- 8. CONSISTENCY VERIFICATION
-- ----------------------------------------------------------------------------

-- Function to verify snapshot consistency against transaction log
CREATE OR REPLACE FUNCTION ussd_core.verify_snapshot_consistency(
    p_sample_size INTEGER DEFAULT 100
)
RETURNS TABLE (
    account_id UUID,
    snapshot_balance NUMERIC,
    computed_balance NUMERIC,
    is_consistent BOOLEAN,
    discrepancy NUMERIC
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_sample UUID[];
BEGIN
    -- Get random sample of accounts with snapshots
    SELECT array_agg(account_id) INTO v_sample
    FROM (
        SELECT account_id 
        FROM ussd_core.account_state_snapshots 
        WHERE current_balance != 0
        ORDER BY random() 
        LIMIT p_sample_size
    ) s;
    
    RETURN QUERY
    WITH computed AS (
        SELECT 
            s.account_id,
            s.current_balance as snapshot_balance,
            (ussd_core.compute_account_state(s.account_id)).current_balance as computed_balance
        FROM ussd_core.account_state_snapshots s
        WHERE s.account_id = ANY(v_sample)
    )
    SELECT 
        c.account_id,
        c.snapshot_balance,
        c.computed_balance,
        (c.snapshot_balance = c.computed_balance) as is_consistent,
        (c.snapshot_balance - c.computed_balance) as discrepancy
    FROM computed c;
END;
$$;

-- ----------------------------------------------------------------------------
-- 9. VIEWS
-- ----------------------------------------------------------------------------

-- Current account states with account info
CREATE VIEW ussd_core.account_balances AS
SELECT 
    ar.account_id,
    ar.display_name,
    ar.account_type,
    ar.status as account_status,
    s.current_balance,
    s.available_balance,
    s.hold_balance,
    s.last_transaction_id,
    s.transaction_count,
    s.last_activity_at,
    s.computed_at
FROM ussd_core.account_registry ar
LEFT JOIN ussd_core.account_state_snapshots s ON ar.account_id = s.account_id
WHERE ar.valid_to IS NULL;

-- Active accounts with recent activity
CREATE VIEW ussd_core.recently_active_accounts AS
SELECT *
FROM ussd_core.account_balances
WHERE last_activity_at > NOW() - INTERVAL '30 days'
ORDER BY last_activity_at DESC;

-- Application statistics view
CREATE VIEW ussd_core.application_statistics AS
SELECT 
    s.*,
    a.name as application_name,
    a.status as application_status
FROM ussd_core.application_state_snapshots s
LEFT JOIN ussd_app.applications a ON s.application_id = a.application_id;

-- ----------------------------------------------------------------------------
-- 10. ROW LEVEL SECURITY
-- ----------------------------------------------------------------------------
ALTER TABLE ussd_core.account_state_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd_core.account_state_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd_core.application_state_snapshots ENABLE ROW LEVEL SECURITY;

CREATE POLICY account_state_own ON ussd_core.account_state_snapshots
    FOR SELECT USING (account_id = NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID);

CREATE POLICY account_state_app ON ussd_core.account_state_snapshots
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM ussd_app.account_memberships am
            WHERE am.account_id = ussd_core.account_state_snapshots.account_id
              AND am.application_id = NULLIF(current_setting('app.application_id', TRUE), '')::UUID
        )
    );

-- ----------------------------------------------------------------------------
-- 11. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_core.account_state_snapshots IS 
    'Derived state cache of account balances - can be rebuilt from transaction log';
COMMENT ON TABLE ussd_core.account_state_history IS 
    'Historical point-in-time snapshots for audit and reporting';
COMMENT ON FUNCTION ussd_core.compute_account_state IS 
    'Recomputes account state from immutable transaction log';
COMMENT ON FUNCTION ussd_core.verify_snapshot_consistency IS 
    'Verifies that snapshot balances match recomputed values from transaction log';
