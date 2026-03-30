-- =============================================================================
-- Cron Job: Reconciliation Runs
-- =============================================================================
-- Description: Performs periodic reconciliation between:
--              - Internal ledger balances
--              - External system feeds
--              - Payment gateway settlements
--              - Bank statement matching
-- Schedule: Every 15 minutes (high frequency) + hourly full reconciliation
-- =============================================================================

-- =============================================================================
-- COMPLIANCE FRAMEWORK ALIGNMENT
-- =============================================================================
-- ISO/IEC 27001:2022
--   A.12.3 (Backup)       - Reconciliation validates backup data consistency
--   A.12.4 (Logging)      - All reconciliations logged with discrepancies
--   A.5.24 (Compliance)   - Financial reconciliation for regulatory compliance
--   A.6.1 (Screening)     - Regular checks detect anomalous transactions
--
-- ISO/IEC 27031:2025
--   Business Continuity   - Detects data drift during normal operations
--   ICT Readiness         - Identifies issues before they impact availability
--   Recovery Validation   - Post-recovery reconciliation ensures data integrity
--
-- ISO/IEC 27040:2024
--   Storage Security      - Detects unauthorized data modifications
--   Data Integrity        - Cross-system validation of stored data
--   Verification Controls - Continuous integrity monitoring
-- =============================================================================

-- TODO: Ensure pg_cron extension is installed
-- CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Reconciliation configuration
CREATE TABLE IF NOT EXISTS ledger.reconciliation_config (
    config_id SERIAL PRIMARY KEY,
    reconciliation_type TEXT NOT NULL UNIQUE,
    source_system TEXT NOT NULL,
    target_system TEXT NOT NULL,
    frequency_minutes INT NOT NULL,
    tolerance_amount NUMERIC(20,8) DEFAULT 0.00000001,
    auto_resolve BOOLEAN DEFAULT FALSE,
    is_enabled BOOLEAN DEFAULT TRUE,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Initialize reconciliation configs
INSERT INTO ledger.reconciliation_config (
    reconciliation_type, source_system, target_system, frequency_minutes, tolerance_amount
)
VALUES 
    ('INTERNAL_LEDGER', 'transaction_log', 'account_balances', 5, 0),
    ('PAYMENT_GATEWAY', 'ledger', 'stripe', 15, 0.01),
    ('BANK_SETTLEMENT', 'ledger', 'bank_feed', 60, 0),
    ('INTER_SYSTEM', 'ledger_primary', 'ledger_replica', 10, 0)
ON CONFLICT (reconciliation_type) DO NOTHING;

-- Reconciliation run log
CREATE TABLE IF NOT EXISTS ledger.reconciliation_run_log (
    run_id BIGSERIAL PRIMARY KEY,
    reconciliation_type TEXT NOT NULL,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    period_start TIMESTAMPTZ,
    period_end TIMESTAMPTZ,
    status TEXT DEFAULT 'RUNNING', -- RUNNING, COMPLETED, DISCREPANCIES_FOUND, FAILED
    source_total NUMERIC(30,8),
    target_total NUMERIC(30,8),
    difference_amount NUMERIC(30,8),
    discrepancy_count INT DEFAULT 0,
    error_message TEXT
);

-- Discrepancy details
CREATE TABLE IF NOT EXISTS ledger.reconciliation_discrepancies (
    discrepancy_id BIGSERIAL PRIMARY KEY,
    run_id BIGINT REFERENCES ledger.reconciliation_run_log(run_id),
    discrepancy_type TEXT NOT NULL, -- MISSING_SOURCE, MISSING_TARGET, AMOUNT_MISMATCH
    source_id TEXT,
    target_id TEXT,
    source_amount NUMERIC(30,8),
    target_amount NUMERIC(30,8),
    difference NUMERIC(30,8),
    status TEXT DEFAULT 'OPEN', -- OPEN, INVESTIGATING, RESOLVED, WRITTEN_OFF
    resolution_notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

-- Main reconciliation scheduler
CREATE OR REPLACE FUNCTION ledger.schedule_reconciliations()
RETURNS TABLE(reconciliation_type TEXT, executed BOOLEAN)
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
BEGIN
    FOR v_config IN 
        SELECT c.* 
        FROM ledger.reconciliation_config c
        WHERE c.is_enabled = TRUE
          AND (c.next_run_at IS NULL OR c.next_run_at <= NOW())
        ORDER BY c.frequency_minutes
    LOOP
        BEGIN
            -- Execute the reconciliation
            PERFORM ledger.execute_reconciliation(v_config.reconciliation_type);
            
            -- Update next run time
            UPDATE ledger.reconciliation_config
            SET last_run_at = NOW(),
                next_run_at = NOW() + (frequency_minutes || ' minutes')::INTERVAL
            WHERE config_id = v_config.config_id;
            
            reconciliation_type := v_config.reconciliation_type;
            executed := TRUE;
            RETURN NEXT;
            
        EXCEPTION WHEN OTHERS THEN
            reconciliation_type := v_config.reconciliation_type;
            executed := FALSE;
            RETURN NEXT;
            
            -- Log error
            INSERT INTO ledger.error_log (
                error_type, error_message, context, created_at
            ) VALUES (
                'RECONCILIATION_FAILED',
                SQLERRM,
                jsonb_build_object('type', v_config.reconciliation_type),
                NOW()
            );
        END;
    END LOOP;
END;
$$;

-- Execute specific reconciliation
CREATE OR REPLACE FUNCTION ledger.execute_reconciliation(p_type TEXT)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
    v_run_id BIGINT;
    v_period_start TIMESTAMPTZ;
    v_period_end TIMESTAMPTZ;
    v_result JSONB;
BEGIN
    SELECT * INTO v_config
    FROM ledger.reconciliation_config
    WHERE reconciliation_type = p_type;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown reconciliation type: %', p_type;
    END IF;
    
    -- Define reconciliation period
    v_period_end := NOW();
    v_period_start := COALESCE(
        v_config.last_run_at,
        v_period_end - INTERVAL '1 hour'
    );
    
    -- Create run log
    INSERT INTO ledger.reconciliation_run_log (
        reconciliation_type, period_start, period_end
    ) VALUES (p_type, v_period_start, v_period_end)
    RETURNING run_id INTO v_run_id;
    
    -- Execute type-specific reconciliation
    v_result := CASE p_type
        WHEN 'INTERNAL_LEDGER' THEN 
            ledger.reconcile_internal_ledger(v_run_id, v_period_start, v_period_end)
        WHEN 'PAYMENT_GATEWAY' THEN 
            ledger.reconcile_payment_gateway(v_run_id, v_period_start, v_period_end)
        WHEN 'BANK_SETTLEMENT' THEN 
            ledger.reconcile_bank_settlement(v_run_id, v_period_start, v_period_end)
        WHEN 'INTER_SYSTEM' THEN 
            ledger.reconcile_inter_system(v_run_id, v_period_start, v_period_end)
        ELSE 
            jsonb_build_object('error', 'Unknown reconciliation type')
    END;
    
    -- Update run log with results
    UPDATE ledger.reconciliation_run_log
    SET completed_at = NOW(),
        status = CASE 
            WHEN (v_result->>'discrepancy_count')::INT > 0 THEN 'DISCREPANCIES_FOUND'
            ELSE 'COMPLETED'
        END,
        source_total = (v_result->>'source_total')::NUMERIC,
        target_total = (v_result->>'target_total')::NUMERIC,
        difference_amount = (v_result->>'difference')::NUMERIC,
        discrepancy_count = (v_result->>'discrepancy_count')::INT
    WHERE run_id = v_run_id;
    
    RETURN v_run_id;
END;
$$;

-- Internal ledger reconciliation
CREATE OR REPLACE FUNCTION ledger.reconcile_internal_ledger(
    p_run_id BIGINT, p_start TIMESTAMPTZ, p_end TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_source_total NUMERIC;
    v_target_total NUMERIC;
    v_discrepancy_count INT := 0;
BEGIN
    -- Calculate from transaction log
    SELECT COALESCE(SUM(amount), 0) INTO v_source_total
    FROM ledger.transactions
    WHERE created_at BETWEEN p_start AND p_end;
    
    -- Calculate from account balance changes
    SELECT COALESCE(SUM(closing_balance - opening_balance), 0) INTO v_target_total
    FROM ledger.daily_balance_snapshots
    WHERE snapshot_date BETWEEN DATE(p_start) AND DATE(p_end);
    
    -- Check for discrepancies
    IF ABS(v_source_total - v_target_total) > 0.00000001 THEN
        v_discrepancy_count := 1;
        
        INSERT INTO ledger.reconciliation_discrepancies (
            run_id, discrepancy_type, source_amount, target_amount, difference
        ) VALUES (
            p_run_id, 'AMOUNT_MISMATCH', v_source_total, v_target_total,
            v_source_total - v_target_total
        );
    END IF;
    
    RETURN jsonb_build_object(
        'source_total', v_source_total,
        'target_total', v_target_total,
        'difference', v_source_total - v_target_total,
        'discrepancy_count', v_discrepancy_count
    );
END;
$$;

-- Payment gateway reconciliation (placeholder)
CREATE OR REPLACE FUNCTION ledger.reconcile_payment_gateway(
    p_run_id BIGINT, p_start TIMESTAMPTZ, p_end TIMESTAMPTZ
)
RETURNS JSONB AS $$
BEGIN
    -- TODO: Implement Stripe/payment gateway API integration
    RETURN jsonb_build_object(
        'source_total', 0,
        'target_total', 0,
        'difference', 0,
        'discrepancy_count', 0,
        'status', 'NOT_IMPLEMENTED'
    );
END;
$$ LANGUAGE plpgsql;

-- Bank settlement reconciliation (placeholder)
CREATE OR REPLACE FUNCTION ledger.reconcile_bank_settlement(
    p_run_id BIGINT, p_start TIMESTAMPTZ, p_end TIMESTAMPTZ
)
RETURNS JSONB AS $$
BEGIN
    -- TODO: Implement bank feed SFTP/API integration
    RETURN jsonb_build_object(
        'source_total', 0,
        'target_total', 0,
        'difference', 0,
        'discrepancy_count', 0,
        'status', 'NOT_IMPLEMENTED'
    );
END;
$$ LANGUAGE plpgsql;

-- Inter-system reconciliation (placeholder)
CREATE OR REPLACE FUNCTION ledger.reconcile_inter_system(
    p_run_id BIGINT, p_start TIMESTAMPTZ, p_end TIMESTAMPTZ
)
RETURNS JSONB AS $$
BEGIN
    -- TODO: Implement cross-datacenter consistency checks
    RETURN jsonb_build_object(
        'source_total', 0,
        'target_total', 0,
        'difference', 0,
        'discrepancy_count', 0,
        'status', 'NOT_IMPLEMENTED'
    );
END;
$$ LANGUAGE plpgsql;

-- Reconciliation statistics
CREATE OR REPLACE FUNCTION ledger.reconciliation_stats(
    p_hours INT DEFAULT 24
)
RETURNS TABLE(
    reconciliation_type TEXT,
    runs_completed BIGINT,
    discrepancies_found BIGINT,
    avg_difference NUMERIC,
    unresolved_discrepancies BIGINT
)
LANGUAGE SQL
AS $$
    SELECT 
        r.reconciliation_type,
        COUNT(*) FILTER (WHERE r.status = 'COMPLETED') as runs_completed,
        COUNT(*) FILTER (WHERE r.status = 'DISCREPANCIES_FOUND') as discrepancies_found,
        AVG(ABS(r.difference_amount)) as avg_difference,
        (SELECT COUNT(*) FROM ledger.reconciliation_discrepancies 
         WHERE status = 'OPEN' AND created_at > NOW() - (p_hours || ' hours')::INTERVAL)
            as unresolved_discrepancies
    FROM ledger.reconciliation_run_log r
    WHERE r.started_at > NOW() - (p_hours || ' hours')::INTERVAL
    GROUP BY r.reconciliation_type;
$$;

-- Manual discrepancy resolution
CREATE OR REPLACE FUNCTION ledger.resolve_discrepancy(
    p_discrepancy_id BIGINT,
    p_resolution TEXT,
    p_notes TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE ledger.reconciliation_discrepancies
    SET status = p_resolution,
        resolution_notes = p_notes,
        resolved_at = NOW()
    WHERE discrepancy_id = p_discrepancy_id;
    
    RETURN FOUND;
END;
$$;

-- TODO: Schedule reconciliation jobs via pg_cron
-- SELECT cron.schedule('reconciliation-scheduler', '*/15 * * * *', 'SELECT * FROM ledger.schedule_reconciliations()');

-- TODO: Implement external API integrations (Stripe, bank feeds)
-- TODO: Add automatic discrepancy resolution rules
-- TODO: Create alerting for unresolved discrepancies > threshold
