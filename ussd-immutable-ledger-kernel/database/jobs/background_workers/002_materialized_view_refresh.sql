-- =============================================================================
-- Background Worker: Materialized View Refresh
-- =============================================================================
-- Description: Manages refresh of materialized views for reporting and analytics
--              with incremental refresh capabilities and dependency management
-- Schedule: Configurable per view (real-time, hourly, daily)
-- =============================================================================

-- =============================================================================
-- COMPLIANCE FRAMEWORK ALIGNMENT
-- =============================================================================
-- ISO/IEC 27001:2022
--   A.12.3 (Backup)       - Refresh scheduling ensures data availability
--   A.12.4 (Logging)      - All refresh operations logged with timing
--   A.8.1 (Asset Mgmt)    - Analytics views support information asset tracking
--
-- ISO/IEC 27031:2025
--   Business Continuity   - Stale views indicate potential system issues
--   Recovery Objectives   - Refresh schedules align with RPO requirements
--
-- ISO/IEC 27040:2024
--   Storage Security      - View refresh logs track data access patterns
--   Data Availability     - Ensures reporting data is current and accurate
-- =============================================================================

-- TODO: Install required extensions
-- CREATE EXTENSION IF NOT EXISTS pg_cron;

-- View refresh configuration and state tracking
CREATE TABLE IF NOT EXISTS ledger.mv_refresh_config (
    view_name TEXT PRIMARY KEY,
    refresh_type TEXT NOT NULL DEFAULT 'FULL', -- FULL, INCREMENTAL, CONCURRENT
    refresh_interval INTERVAL NOT NULL,
    last_refresh_at TIMESTAMPTZ,
    next_refresh_at TIMESTAMPTZ,
    avg_refresh_duration_ms NUMERIC,
    priority INT DEFAULT 5,
    dependencies TEXT[] DEFAULT '{}',
    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Refresh history logging
CREATE TABLE IF NOT EXISTS ledger.mv_refresh_log (
    log_id BIGSERIAL PRIMARY KEY,
    view_name TEXT NOT NULL,
    refresh_type TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    duration_ms NUMERIC,
    rows_affected BIGINT,
    status TEXT NOT NULL, -- STARTED, COMPLETED, FAILED
    error_message TEXT
);

-- Initialize default configurations for ledger views
INSERT INTO ledger.mv_refresh_config (view_name, refresh_type, refresh_interval, priority, dependencies)
VALUES 
    ('ledger.mv_daily_transaction_summary', 'CONCURRENT', '5 minutes', 1, '{}'),
    ('ledger.mv_account_balance_history', 'INCREMENTAL', '1 minute', 1, '{}'),
    ('ledger.mv_block_statistics', 'FULL', '1 hour', 2, '{}'),
    ('ledger.mv_top_accounts_by_volume', 'CONCURRENT', '15 minutes', 3, '{}'),
    ('ledger.mv_transaction_patterns', 'FULL', '1 day', 5, '{}'),
    ('ledger.mv_audit_trail_summary', 'INCREMENTAL', '30 seconds', 1, '{ledger.mv_daily_transaction_summary}'),
    ('ledger.mv_compliance_risk_scores', 'FULL', '1 hour', 4, '{ledger.mv_transaction_patterns}')
ON CONFLICT (view_name) DO NOTHING;

-- Main refresh scheduler
CREATE OR REPLACE FUNCTION ledger.schedule_mv_refreshes()
RETURNS TABLE(view_name TEXT, scheduled BOOLEAN)
LANGUAGE plpgsql
AS $$
DECLARE
    v_view RECORD;
    v_can_refresh BOOLEAN;
    v_dependency_met BOOLEAN;
BEGIN
    FOR v_view IN 
        SELECT c.* 
        FROM ledger.mv_refresh_config c
        WHERE c.is_enabled = TRUE
          AND (c.next_refresh_at IS NULL OR c.next_refresh_at <= NOW())
        ORDER BY c.priority ASC, c.next_refresh_at ASC NULLS FIRST
    LOOP
        -- Check if dependencies are met
        SELECT bool_and(
            last_refresh_at IS NOT NULL 
            AND last_refresh_at > NOW() - refresh_interval
        )
        INTO v_dependency_met
        FROM ledger.mv_refresh_config
        WHERE view_name = ANY(v_view.dependencies);
        
        v_dependency_met := COALESCE(v_dependency_met, TRUE);
        
        IF NOT v_dependency_met THEN
            view_name := v_view.view_name;
            scheduled := FALSE;
            RETURN NEXT;
            CONTINUE;
        END IF;
        
        -- Schedule the refresh
        BEGIN
            CASE v_view.refresh_type
                WHEN 'CONCURRENT' THEN
                    EXECUTE format('REFRESH MATERIALIZED VIEW CONCURRENTLY %I', v_view.view_name);
                WHEN 'INCREMENTAL' THEN
                    PERFORM ledger.incremental_mv_refresh(v_view.view_name);
                ELSE
                    EXECUTE format('REFRESH MATERIALIZED VIEW %I', v_view.view_name);
            END CASE;
            
            -- Update config
            UPDATE ledger.mv_refresh_config
            SET last_refresh_at = NOW(),
                next_refresh_at = NOW() + refresh_interval,
                updated_at = NOW()
            WHERE view_name = v_view.view_name;
            
            -- Log success
            INSERT INTO ledger.mv_refresh_log (
                view_name, refresh_type, started_at, completed_at, 
                duration_ms, status
            ) VALUES (
                v_view.view_name, v_view.refresh_type, NOW(), NOW(),
                0, 'COMPLETED'
            );
            
            view_name := v_view.view_name;
            scheduled := TRUE;
            
        EXCEPTION WHEN OTHERS THEN
            -- Log failure
            INSERT INTO ledger.mv_refresh_log (
                view_name, refresh_type, started_at, 
                status, error_message
            ) VALUES (
                v_view.view_name, v_view.refresh_type, NOW(),
                'FAILED', SQLERRM
            );
            
            view_name := v_view.view_name;
            scheduled := FALSE;
        END;
        
        RETURN NEXT;
    END LOOP;
END;
$$;

-- Incremental refresh function for supported views
CREATE OR REPLACE FUNCTION ledger.incremental_mv_refresh(p_view_name TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_last_refresh TIMESTAMPTZ;
    v_refresh_log_id BIGINT;
BEGIN
    -- Get last refresh time
    SELECT last_refresh_at INTO v_last_refresh
    FROM ledger.mv_refresh_config
    WHERE view_name = p_view_name;
    
    -- Log start
    INSERT INTO ledger.mv_refresh_log (view_name, refresh_type, started_at, status)
    VALUES (p_view_name, 'INCREMENTAL', NOW(), 'STARTED')
    RETURNING log_id INTO v_refresh_log_id;
    
    -- View-specific incremental logic
    CASE p_view_name
        WHEN 'ledger.mv_account_balance_history' THEN
            -- Delete old records for accounts with new transactions
            DELETE FROM ledger.mv_account_balance_history
            WHERE account_id IN (
                SELECT DISTINCT account_id 
                FROM ledger.transactions 
                WHERE created_at > v_last_refresh
            );
            
            -- Insert updated records
            INSERT INTO ledger.mv_account_balance_history
            SELECT account_id, balance, updated_at
            FROM ledger.accounts
            WHERE updated_at > v_last_refresh;
            
        WHEN 'ledger.mv_audit_trail_summary' THEN
            -- Append only new audit records
            INSERT INTO ledger.mv_audit_trail_summary
            SELECT * FROM ledger.audit_trail at2
            WHERE at2.created_at > v_last_refresh
              AND NOT EXISTS (
                  SELECT 1 FROM ledger.mv_audit_trail_summary mv
                  WHERE mv.audit_id = at2.audit_id
              );
              
        ELSE
            -- Fall back to full refresh for unsupported views
            EXECUTE format('REFRESH MATERIALIZED VIEW %I', p_view_name);
    END CASE;
    
    -- Update log
    UPDATE ledger.mv_refresh_log
    SET completed_at = NOW(),
        duration_ms = EXTRACT(EPOCH FROM (NOW() - started_at)) * 1000,
        status = 'COMPLETED'
    WHERE log_id = v_refresh_log_id;
    
EXCEPTION WHEN OTHERS THEN
    UPDATE ledger.mv_refresh_log
    SET status = 'FAILED',
        error_message = SQLERRM
    WHERE log_id = v_refresh_log_id;
    RAISE;
END;
$$;

-- Create index on refresh log for performance
CREATE INDEX IF NOT EXISTS idx_mv_refresh_log_view_time 
ON ledger.mv_refresh_log(view_name, started_at DESC);

-- Statistics function for monitoring
CREATE OR REPLACE FUNCTION ledger.mv_refresh_statistics(
    p_hours INT DEFAULT 24
)
RETURNS TABLE(
    view_name TEXT,
    total_refreshes BIGINT,
    successful_refreshes BIGINT,
    failed_refreshes BIGINT,
    avg_duration_ms NUMERIC,
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ
)
LANGUAGE SQL
AS $$
    SELECT 
        l.view_name,
        COUNT(*) as total_refreshes,
        COUNT(*) FILTER (WHERE status = 'COMPLETED') as successful_refreshes,
        COUNT(*) FILTER (WHERE status = 'FAILED') as failed_refreshes,
        AVG(duration_ms) FILTER (WHERE status = 'COMPLETED') as avg_duration_ms,
        MAX(completed_at) FILTER (WHERE status = 'COMPLETED') as last_success_at,
        MAX(completed_at) FILTER (WHERE status = 'FAILED') as last_failure_at
    FROM ledger.mv_refresh_log l
    WHERE started_at > NOW() - (p_hours || ' hours')::INTERVAL
    GROUP BY l.view_name;
$$;

-- TODO: Create actual materialized views (examples)
/*
CREATE MATERIALIZED VIEW ledger.mv_daily_transaction_summary AS
SELECT 
    DATE(created_at) as transaction_date,
    COUNT(*) as transaction_count,
    SUM(amount) as total_volume,
    COUNT(DISTINCT from_account) as unique_senders,
    COUNT(DISTINCT to_account) as unique_receivers
FROM ledger.transactions
WHERE created_at > NOW() - INTERVAL '90 days'
GROUP BY DATE(created_at);

CREATE UNIQUE INDEX idx_mv_daily_tx_summary_date 
ON ledger.mv_daily_transaction_summary(transaction_date);

CREATE MATERIALIZED VIEW ledger.mv_account_balance_history AS
SELECT account_id, balance, updated_at
FROM ledger.accounts;

CREATE UNIQUE INDEX idx_mv_acct_bal_hist_id 
ON ledger.mv_account_balance_history(account_id);
*/

-- TODO: Schedule via pg_cron
-- SELECT cron.schedule('mv-refresh-scheduler', '*/30 * * * *', 'SELECT * FROM ledger.schedule_mv_refreshes()');

-- TODO: Implement parallel refresh for independent views
-- TODO: Add refresh progress tracking for long-running refreshes
-- TODO: Implement automatic retry with exponential backoff for failed refreshes
