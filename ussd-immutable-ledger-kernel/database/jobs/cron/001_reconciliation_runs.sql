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

-- Ensure pg_cron extension is installed
CREATE EXTENSION IF NOT EXISTS pg_cron;

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

-- Payment gateway reconciliation (Stripe implementation)
-- PCI DSS: Validate payment processor totals match internal ledger
CREATE OR REPLACE FUNCTION ledger.reconcile_payment_gateway(
    p_run_id BIGINT, p_start TIMESTAMPTZ, p_end TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_source_total NUMERIC := 0;
    v_target_total NUMERIC := 0;
    v_discrepancy_count INT := 0;
    v_stripe_record RECORD;
    v_ledger_record RECORD;
BEGIN
    -- Calculate internal ledger totals for gateway transactions
    SELECT 
        COALESCE(SUM(amount), 0),
        COUNT(*)
    INTO v_source_total
    FROM ledger.transactions t
    JOIN ledger.payment_methods pm ON t.payment_method_id = pm.method_id
    WHERE t.created_at BETWEEN p_start AND p_end
      AND pm.gateway_name = 'STRIPE'
      AND t.status IN ('COMPLETED', 'SETTLED');
    
    -- Query Stripe settlement records (from external_feeds table)
    SELECT 
        COALESCE(SUM(settlement_amount), 0),
        COUNT(*)
    INTO v_target_total
    FROM ledger.external_gateway_settlements
    WHERE gateway_name = 'STRIPE'
      AND settlement_date BETWEEN DATE(p_start) AND DATE(p_end)
      AND status = 'SETTLED';
    
    -- Check for transaction-level discrepancies
    FOR v_ledger_record IN
        SELECT 
            t.transaction_id,
            t.external_reference,
            t.amount,
            t.fee,
            t.net_amount
        FROM ledger.transactions t
        JOIN ledger.payment_methods pm ON t.payment_method_id = pm.method_id
        WHERE t.created_at BETWEEN p_start AND p_end
          AND pm.gateway_name = 'STRIPE'
          AND t.status IN ('COMPLETED', 'SETTLED')
    LOOP
        -- Check if exists in Stripe settlements
        IF NOT EXISTS (
            SELECT 1 FROM ledger.external_gateway_settlements s
            WHERE s.gateway_reference = v_ledger_record.external_reference
        ) THEN
            v_discrepancy_count := v_discrepancy_count + 1;
            
            INSERT INTO ledger.reconciliation_discrepancies (
                run_id, discrepancy_type, source_id, source_amount, difference
            ) VALUES (
                p_run_id, 'MISSING_TARGET', v_ledger_record.transaction_id::TEXT, 
                v_ledger_record.amount, v_ledger_record.amount
            );
        END IF;
    END LOOP;
    
    -- Check for orphaned Stripe records (not in our ledger)
    FOR v_stripe_record IN
        SELECT 
            s.gateway_reference,
            s.settlement_amount
        FROM ledger.external_gateway_settlements s
        WHERE s.gateway_name = 'STRIPE'
          AND s.settlement_date BETWEEN DATE(p_start) AND DATE(p_end)
          AND NOT EXISTS (
              SELECT 1 FROM ledger.transactions t
              WHERE t.external_reference = s.gateway_reference
          )
    LOOP
        v_discrepancy_count := v_discrepancy_count + 1;
        
        INSERT INTO ledger.reconciliation_discrepancies (
            run_id, discrepancy_type, target_id, target_amount, difference
        ) VALUES (
            p_run_id, 'MISSING_SOURCE', v_stripe_record.gateway_reference,
            v_stripe_record.settlement_amount, -v_stripe_record.settlement_amount
        );
    END LOOP;
    
    -- Check for amount mismatches
    INSERT INTO ledger.reconciliation_discrepancies (
        run_id, discrepancy_type, source_id, target_id, 
        source_amount, target_amount, difference
    )
    SELECT 
        p_run_id,
        'AMOUNT_MISMATCH',
        t.transaction_id::TEXT,
        s.gateway_reference,
        t.net_amount,
        s.settlement_amount,
        t.net_amount - s.settlement_amount
    FROM ledger.transactions t
    JOIN ledger.payment_methods pm ON t.payment_method_id = pm.method_id
    JOIN ledger.external_gateway_settlements s ON t.external_reference = s.gateway_reference
    WHERE t.created_at BETWEEN p_start AND p_end
      AND pm.gateway_name = 'STRIPE'
      AND ABS(t.net_amount - s.settlement_amount) > 0.01;
    
    GET DIAGNOSTICS v_discrepancy_count = ROW_COUNT;
    
    RETURN jsonb_build_object(
        'source_total', v_source_total,
        'target_total', v_target_total,
        'difference', v_source_total - v_target_total,
        'discrepancy_count', v_discrepancy_count,
        'status', CASE WHEN v_discrepancy_count = 0 THEN 'MATCHED' ELSE 'DISCREPANCIES' END
    );
END;
$$;

-- Bank settlement reconciliation
-- ISO/IEC 27001 A.12.4: Validate external financial records
CREATE OR REPLACE FUNCTION ledger.reconcile_bank_settlement(
    p_run_id BIGINT, p_start TIMESTAMPTZ, p_end TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_source_total NUMERIC := 0;
    v_target_total NUMERIC := 0;
    v_discrepancy_count INT := 0;
    v_bank_record RECORD;
    v_ledger_record RECORD;
BEGIN
    -- Calculate internal ledger bank-related totals
    SELECT 
        COALESCE(SUM(
            CASE 
                WHEN transaction_type = 'BANK_DEPOSIT' THEN amount
                WHEN transaction_type = 'BANK_WITHDRAWAL' THEN -amount
                ELSE 0
            END
        ), 0)
    INTO v_source_total
    FROM ledger.transactions
    WHERE created_at BETWEEN p_start AND p_end
      AND transaction_type IN ('BANK_DEPOSIT', 'BANK_WITHDRAWAL')
      AND status = 'COMPLETED';
    
    -- Get bank statement totals from imported feed
    SELECT 
        COALESCE(SUM(
            CASE 
                WHEN transaction_type = 'CREDIT' THEN amount
                WHEN transaction_type = 'DEBIT' THEN -amount
                ELSE 0
            END
        ), 0)
    INTO v_target_total
    FROM ledger.bank_statement_lines
    WHERE transaction_date BETWEEN DATE(p_start) AND DATE(p_end)
      AND reconciliation_status != 'EXCLUDED';
    
    -- Match transactions by amount and approximate date
    FOR v_ledger_record IN
        SELECT 
            t.transaction_id,
            t.amount,
            t.created_at,
            t.reference_number
        FROM ledger.transactions t
        WHERE t.created_at BETWEEN p_start AND p_end
          AND t.transaction_type IN ('BANK_DEPOSIT', 'BANK_WITHDRAWAL')
          AND t.status = 'COMPLETED'
          AND NOT EXISTS (
              SELECT 1 FROM ledger.reconciliation_matches m
              WHERE m.ledger_transaction_id = t.transaction_id
                AND m.reconciliation_type = 'BANK_SETTLEMENT'
          )
    LOOP
        -- Look for matching bank statement line
        SELECT * INTO v_bank_record
        FROM ledger.bank_statement_lines b
        WHERE b.transaction_date BETWEEN DATE(v_ledger_record.created_at - INTERVAL '3 days')
                                     AND DATE(v_ledger_record.created_at + INTERVAL '3 days')
          AND ABS(b.amount - v_ledger_record.amount) < 0.01
          AND b.reconciliation_status = 'UNRECONCILED'
        ORDER BY ABS(EXTRACT(EPOCH FROM (b.transaction_date::TIMESTAMPTZ - v_ledger_record.created_at)))
        LIMIT 1;
        
        IF FOUND THEN
            -- Create match
            INSERT INTO ledger.reconciliation_matches (
                reconciliation_type,
                ledger_transaction_id,
                external_reference,
                match_amount,
                matched_at
            ) VALUES (
                'BANK_SETTLEMENT',
                v_ledger_record.transaction_id,
                v_bank_record.statement_line_id::TEXT,
                v_ledger_record.amount,
                NOW()
            );
            
            -- Update bank statement line status
            UPDATE ledger.bank_statement_lines
            SET reconciliation_status = 'RECONCILED',
                reconciled_transaction_id = v_ledger_record.transaction_id
            WHERE statement_line_id = v_bank_record.statement_line_id;
        ELSE
            -- Record discrepancy
            v_discrepancy_count := v_discrepancy_count + 1;
            
            INSERT INTO ledger.reconciliation_discrepancies (
                run_id, discrepancy_type, source_id, source_amount, difference
            ) VALUES (
                p_run_id, 'MISSING_TARGET', v_ledger_record.transaction_id::TEXT,
                v_ledger_record.amount, v_ledger_record.amount
            );
        END IF;
    END LOOP;
    
    -- Count unreconciled bank statement lines as discrepancies
    SELECT COUNT(*) INTO v_discrepancy_count
    FROM ledger.bank_statement_lines
    WHERE transaction_date BETWEEN DATE(p_start) AND DATE(p_end)
      AND reconciliation_status = 'UNRECONCILED';
    
    RETURN jsonb_build_object(
        'source_total', v_source_total,
        'target_total', v_target_total,
        'difference', v_source_total - v_target_total,
        'discrepancy_count', v_discrepancy_count,
        'status', CASE WHEN v_discrepancy_count = 0 THEN 'MATCHED' ELSE 'DISCREPANCIES' END
    );
END;
$$;

-- Inter-system reconciliation
-- ISO/IEC 27031: Cross-datacenter consistency validation
CREATE OR REPLACE FUNCTION ledger.reconcile_inter_system(
    p_run_id BIGINT, p_start TIMESTAMPTZ, p_end TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_primary_hash TEXT;
    v_replica_hash TEXT;
    v_source_total NUMERIC;
    v_target_total NUMERIC;
    v_mismatched_records INT := 0;
    v_primary_record RECORD;
BEGIN
    -- Calculate hash of primary system transactions
    SELECT 
        MD5(string_agg(
            transaction_id::TEXT || amount::TEXT || status::TEXT, 
            ',' ORDER BY transaction_id
        )),
        COUNT(*),
        COALESCE(SUM(amount), 0)
    INTO v_primary_hash, v_source_total
    FROM ledger.transactions
    WHERE created_at BETWEEN p_start AND p_end
      AND status IN ('COMPLETED', 'SETTLED');
    
    -- Calculate hash of replica system (using foreign table or dblink)
    -- Note: This assumes a foreign table 'ledger.transactions_replica' exists
    SELECT 
        MD5(string_agg(
            transaction_id::TEXT || amount::TEXT || status::TEXT, 
            ',' ORDER BY transaction_id
        )),
        COUNT(*),
        COALESCE(SUM(amount), 0)
    INTO v_replica_hash, v_target_total
    FROM ledger.transactions_replica
    WHERE created_at BETWEEN p_start AND p_end
      AND status IN ('COMPLETED', 'SETTLED');
    
    -- Compare hashes
    IF v_primary_hash != v_replica_hash THEN
        -- Find specific mismatched records
        FOR v_primary_record IN
            SELECT transaction_id, amount, status, hash
            FROM (
                SELECT 
                    t.*,
                    MD5(t.transaction_id::TEXT || t.amount::TEXT || t.status::TEXT) as hash
                FROM ledger.transactions t
                WHERE t.created_at BETWEEN p_start AND p_end
            ) primary_data
            WHERE NOT EXISTS (
                SELECT 1 FROM (
                    SELECT 
                        r.*,
                        MD5(r.transaction_id::TEXT || r.amount::TEXT || r.status::TEXT) as hash
                    FROM ledger.transactions_replica r
                    WHERE r.created_at BETWEEN p_start AND p_end
                ) replica_data
                WHERE replica_data.transaction_id = primary_data.transaction_id
                  AND replica_data.hash = primary_data.hash
            )
            LIMIT 100 -- Limit to prevent overwhelming
        LOOP
            v_mismatched_records := v_mismatched_records + 1;
            
            INSERT INTO ledger.reconciliation_discrepancies (
                run_id, discrepancy_type, source_id, source_amount
            ) VALUES (
                p_run_id, 'REPLICA_MISMATCH', v_primary_record.transaction_id::TEXT,
                v_primary_record.amount
            );
        END LOOP;
    END IF;
    
    -- Log replication lag if applicable
    INSERT INTO ledger.replication_metrics (
        measured_at,
        primary_position,
        replica_position,
        lag_bytes,
        lag_seconds
    )
    SELECT 
        NOW(),
        pg_current_wal_lsn(),
        NULL, -- Would come from replica
        NULL,
        EXTRACT(EPOCH FROM (NOW() - MAX(created_at)))
    FROM ledger.transactions_replica;
    
    RETURN jsonb_build_object(
        'source_total', v_source_total,
        'target_total', v_target_total,
        'difference', v_source_total - v_target_total,
        'discrepancy_count', v_mismatched_records,
        'hash_match', v_primary_hash = v_replica_hash,
        'status', CASE WHEN v_mismatched_records = 0 THEN 'MATCHED' ELSE 'DISCREPANCIES' END
    );
END;
$$;

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

-- Schedule reconciliation jobs via pg_cron
-- Run reconciliation scheduler every 15 minutes
DO $$
BEGIN
    PERFORM cron.schedule('reconciliation-scheduler', '*/15 * * * *', 'SELECT * FROM ledger.schedule_reconciliations()');
    RAISE NOTICE 'Reconciliation scheduler scheduled via pg_cron';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Could not schedule reconciliation: %', SQLERRM;
END;
$$;

-- Schedule full reconciliation hourly
DO $$
BEGIN
    PERFORM cron.schedule('full-reconciliation', '0 * * * *', 
        'SELECT ledger.execute_reconciliation(''INTERNAL_LEDGER'')');
    RAISE NOTICE 'Full reconciliation scheduled via pg_cron';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Could not schedule full reconciliation: %', SQLERRM;
END;
$$;

-- Supporting tables for reconciliation
CREATE TABLE IF NOT EXISTS ledger.external_gateway_settlements (
    settlement_id BIGSERIAL PRIMARY KEY,
    gateway_name TEXT NOT NULL,
    gateway_reference TEXT NOT NULL,
    settlement_date DATE NOT NULL,
    gross_amount NUMERIC(20,8) NOT NULL,
    fees NUMERIC(20,8) NOT NULL DEFAULT 0,
    settlement_amount NUMERIC(20,8) NOT NULL,
    currency TEXT DEFAULT 'USD',
    status TEXT DEFAULT 'PENDING',
    imported_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(gateway_name, gateway_reference)
);

CREATE TABLE IF NOT EXISTS ledger.bank_statement_lines (
    statement_line_id BIGSERIAL PRIMARY KEY,
    statement_id BIGINT NOT NULL,
    transaction_date DATE NOT NULL,
    description TEXT,
    reference_number TEXT,
    amount NUMERIC(20,8) NOT NULL,
    transaction_type TEXT, -- CREDIT, DEBIT
    reconciliation_status TEXT DEFAULT 'UNRECONCILED',
    reconciled_transaction_id BIGINT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ledger.reconciliation_matches (
    match_id BIGSERIAL PRIMARY KEY,
    reconciliation_type TEXT NOT NULL,
    ledger_transaction_id BIGINT NOT NULL,
    external_reference TEXT NOT NULL,
    match_amount NUMERIC(20,8) NOT NULL,
    matched_at TIMESTAMPTZ DEFAULT NOW(),
    matched_by TEXT DEFAULT current_user,
    UNIQUE(reconciliation_type, ledger_transaction_id, external_reference)
);

CREATE TABLE IF NOT EXISTS ledger.replication_metrics (
    metric_id BIGSERIAL PRIMARY KEY,
    measured_at TIMESTAMPTZ DEFAULT NOW(),
    primary_position PG_LSN,
    replica_position PG_LSN,
    lag_bytes BIGINT,
    lag_seconds NUMERIC
);

-- Automatic discrepancy resolution rules
CREATE TABLE IF NOT EXISTS ledger.auto_resolution_rules (
    rule_id SERIAL PRIMARY KEY,
    reconciliation_type TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    rule_condition JSONB NOT NULL,
    auto_resolve BOOLEAN DEFAULT FALSE,
    resolution_action TEXT, -- CREATE_ADJUSTMENT, MARK_RECONCILED, FLAG_REVIEW
    max_auto_resolve_amount NUMERIC(20,8) DEFAULT 1.00,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Default auto-resolution rules
INSERT INTO ledger.auto_resolution_rules (
    reconciliation_type, rule_name, rule_condition, auto_resolve, 
    resolution_action, max_auto_resolve_amount
) VALUES 
    ('INTERNAL_LEDGER', 'Rounding Differences', 
     '{"difference_type": "AMOUNT_MISMATCH", "max_abs_difference": 0.01}'::JSONB,
     TRUE, 'MARK_RECONCILED', 0.01),
    ('PAYMENT_GATEWAY', 'Pending Settlement', 
     '{"difference_type": "MISSING_TARGET", "max_age_hours": 72}'::JSONB,
     FALSE, 'FLAG_REVIEW', 0),
    ('BANK_SETTLEMENT', 'Timing Difference', 
     '{"difference_type": "MISSING_TARGET", "max_date_diff_days": 3}'::JSONB,
     FALSE, 'FLAG_REVIEW', 0)
ON CONFLICT DO NOTHING;

-- Function to apply automatic resolution rules
CREATE OR REPLACE FUNCTION ledger.apply_auto_resolution(p_run_id BIGINT)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_rule RECORD;
    v_discrepancy RECORD;
    v_resolved_count INT := 0;
BEGIN
    FOR v_rule IN 
        SELECT * FROM ledger.auto_resolution_rules 
        WHERE is_active = TRUE AND auto_resolve = TRUE
    LOOP
        FOR v_discrepancy IN
            SELECT * FROM ledger.reconciliation_discrepancies
            WHERE run_id = p_run_id
              AND status = 'OPEN'
              AND discrepancy_type = v_rule.rule_condition->>'difference_type'
              AND ABS(difference) <= COALESCE((v_rule.rule_condition->>'max_abs_difference')::NUMERIC, v_rule.max_auto_resolve_amount)
        LOOP
            -- Apply resolution
            UPDATE ledger.reconciliation_discrepancies
            SET status = 'AUTO_RESOLVED',
                resolution_notes = 'Auto-resolved by rule: ' || v_rule.rule_name,
                resolved_at = NOW()
            WHERE discrepancy_id = v_discrepancy.discrepancy_id;
            
            v_resolved_count := v_resolved_count + 1;
        END LOOP;
    END LOOP;
    
    RETURN jsonb_build_object(
        'run_id', p_run_id,
        'auto_resolved_count', v_resolved_count,
        'status', 'COMPLETED'
    );
END;
$$;

-- Alerting function for unresolved discrepancies
CREATE OR REPLACE FUNCTION ledger.check_discrepancy_alerts()
RETURNS TABLE(
    alert_type TEXT,
    reconciliation_type TEXT,
    discrepancy_count BIGINT,
    total_amount NUMERIC,
    alert_severity TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_threshold_amount NUMERIC := 1000.00;
    v_threshold_count INT := 10;
BEGIN
    RETURN QUERY
    SELECT 
        'UNRESOLVED_DISCREPANCIES'::TEXT,
        d.discrepancy_type::TEXT,
        COUNT(*)::BIGINT,
        COALESCE(SUM(ABS(d.difference)), 0)::NUMERIC,
        CASE 
            WHEN COUNT(*) > v_threshold_count * 10 OR COALESCE(SUM(ABS(d.difference)), 0) > v_threshold_amount * 10 THEN 'CRITICAL'
            WHEN COUNT(*) > v_threshold_count OR COALESCE(SUM(ABS(d.difference)), 0) > v_threshold_amount THEN 'HIGH'
            ELSE 'MEDIUM'
        END::TEXT
    FROM ledger.reconciliation_discrepancies d
    WHERE d.status = 'OPEN'
      AND d.created_at > NOW() - INTERVAL '24 hours'
    GROUP BY d.discrepancy_type
    HAVING COUNT(*) > 5;
END;
$$;

-- Schedule discrepancy alert check
DO $$
BEGIN
    PERFORM cron.schedule('discrepancy-alerts', '0 */6 * * *', 
        'SELECT * FROM ledger.check_discrepancy_alerts()');
    RAISE NOTICE 'Discrepancy alerts scheduled via pg_cron';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Could not schedule discrepancy alerts: %', SQLERRM;
END;
$$;
