-- =============================================================================
-- USSD KERNEL CORE SCHEMA - CONTINUOUS AGGREGATES
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    066_core_continuous_aggregates.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      core
-- DESCRIPTION: TimescaleDB continuous aggregates for real-time analytics,
--              compliance reporting, and operational dashboards.
-- =============================================================================

/*
================================================================================
CONTINUOUS AGGREGATES RATIONALE
================================================================================

Why Continuous Aggregates:
- Pre-computed summary statistics for fast queries
- Automatic refresh (real-time or scheduled)
- Minimal storage overhead (only aggregates, not raw data)
- Perfect for compliance reports and dashboards
- Works with compressed chunks (no decompression needed)

Aggregates Created:
1. Transaction volume summaries (hourly, daily, monthly)
2. Account activity summaries
3. Application usage statistics
4. Compliance metrics (AML, velocity)
5. Financial summaries (revenue, volume by currency)

================================================================================
REFRESH POLICIES
================================================================================

Real-time: Every 5 minutes for operational dashboards
Daily: Every hour for compliance reports
Monthly: Daily for regulatory submissions

================================================================================
PERFORMANCE EXPECTATIONS
================================================================================

Without Continuous Aggregates:
- "Daily transaction volume for last 30 days" = 30+ second query on 100M rows

With Continuous Aggregates:
- Same query = < 100ms on pre-computed aggregates
- 99%+ query time reduction

================================================================================
*/

-- =============================================================================
-- HOURLY TRANSACTION SUMMARY
-- =============================================================================

CREATE MATERIALIZED VIEW core.hourly_transaction_summary
WITH (timescaledb.continuous) AS
SELECT 
    time_bucket('1 hour', committed_at) as bucket,
    application_id,
    transaction_type_id,
    currency,
    status,
    
    -- Volume metrics
    COUNT(*) as transaction_count,
    SUM(amount) as total_amount,
    AVG(amount) as avg_amount,
    MIN(amount) as min_amount,
    MAX(amount) as max_amount,
    
    -- Unique users
    COUNT(DISTINCT initiator_account_id) as unique_users,
    
    -- Performance
    AVG(processing_duration_ms) as avg_processing_time,
    
    -- Metadata
    MIN(committed_at) as first_transaction,
    MAX(committed_at) as last_transaction
FROM core.transaction_log
GROUP BY 
    time_bucket('1 hour', committed_at),
    application_id,
    transaction_type_id,
    currency,
    status
WITH NO DATA;

-- Create index on continuous aggregate
CREATE INDEX idx_hourly_summary_bucket 
    ON core.hourly_transaction_summary(bucket DESC);

CREATE INDEX idx_hourly_summary_app 
    ON core.hourly_transaction_summary(application_id, bucket DESC);

-- Add refresh policy (every 5 minutes for near real-time)
SELECT add_continuous_aggregate_policy(
    'core.hourly_transaction_summary',
    start_offset => INTERVAL '1 month',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '5 minutes',
    if_not_exists => TRUE
);

-- =============================================================================
-- DAILY APPLICATION METRICS
-- =============================================================================

CREATE MATERIALIZED VIEW core.daily_application_metrics
WITH (timescaledb.continuous) AS
SELECT 
    time_bucket('1 day', committed_at) as day,
    application_id,
    currency,
    
    -- Transaction counts
    COUNT(*) as total_transactions,
    COUNT(*) FILTER (WHERE status = 'completed') as completed_count,
    COUNT(*) FILTER (WHERE status = 'failed') as failed_count,
    COUNT(*) FILTER (WHERE status = 'reversed') as reversed_count,
    
    -- Amounts
    SUM(amount) FILTER (WHERE status = 'completed') as completed_volume,
    SUM(amount) FILTER (WHERE status = 'failed') as failed_volume,
    
    -- User metrics
    COUNT(DISTINCT initiator_account_id) as active_users,
    COUNT(DISTINCT beneficiary_account_id) as unique_beneficiaries,
    
    -- Risk metrics
    COUNT(*) FILTER (WHERE amount > 100000) as high_value_count,
    SUM(amount) FILTER (WHERE amount > 100000) as high_value_volume,
    
    -- Timing
    AVG(processing_duration_ms) as avg_response_time,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY processing_duration_ms) as p95_response_time
FROM core.transaction_log
GROUP BY 
    time_bucket('1 day', committed_at),
    application_id,
    currency
WITH NO DATA;

CREATE INDEX idx_daily_metrics_day 
    ON core.daily_application_metrics(day DESC);

CREATE INDEX idx_daily_metrics_app 
    ON core.daily_application_metrics(application_id, day DESC);

-- Refresh every hour
SELECT add_continuous_aggregate_policy(
    'core.daily_application_metrics',
    start_offset => INTERVAL '3 months',
    end_offset => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

-- =============================================================================
-- MONTHLY FINANCIAL SUMMARY (for regulatory reports)
-- =============================================================================

CREATE MATERIALIZED VIEW core.monthly_financial_summary
WITH (timescaledb.continuous) AS
SELECT 
    time_bucket('1 month', committed_at) as month,
    application_id,
    currency,
    transaction_type_id,
    
    -- Volume
    COUNT(*) as transaction_count,
    SUM(amount) as total_volume,
    
    -- Average transaction size
    AVG(amount) as avg_transaction_size,
    STDDEV(amount) as stddev_transaction_size,
    
    -- Daily averages
    COUNT(DISTINCT time_bucket('1 day', committed_at)) as active_days,
    COUNT(*)::NUMERIC / NULLIF(COUNT(DISTINCT time_bucket('1 day', committed_at)), 0) as avg_daily_transactions,
    
    -- User engagement
    COUNT(DISTINCT initiator_account_id) as unique_users,
    SUM(amount) / NULLIF(COUNT(DISTINCT initiator_account_id), 0) as volume_per_user,
    
    -- Success rate
    COUNT(*) FILTER (WHERE status = 'completed')::NUMERIC / 
        NULLIF(COUNT(*), 0) * 100 as success_rate_pct
FROM core.transaction_log
GROUP BY 
    time_bucket('1 month', committed_at),
    application_id,
    currency,
    transaction_type_id
WITH NO DATA;

CREATE INDEX idx_monthly_summary_month 
    ON core.monthly_financial_summary(month DESC);

-- Refresh daily at midnight
SELECT add_continuous_aggregate_policy(
    'core.monthly_financial_summary',
    start_offset => INTERVAL '5 years',
    end_offset => INTERVAL '1 month',
    schedule_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- =============================================================================
-- ACCOUNT ACTIVITY SUMMARY (for KYC/AML)
-- =============================================================================

CREATE MATERIALIZED VIEW core.account_activity_summary
WITH (timescaledb.continuous) AS
SELECT 
    time_bucket('1 day', committed_at) as day,
    initiator_account_id as account_id,
    application_id,
    
    -- Transaction counts
    COUNT(*) as total_transactions,
    COUNT(*) FILTER (WHERE status = 'completed') as successful_transactions,
    
    -- Volume
    SUM(amount) as total_volume,
    SUM(amount) FILTER (WHERE status = 'completed') as successful_volume,
    
    -- Counterparties
    COUNT(DISTINCT beneficiary_account_id) as unique_counterparties,
    
    -- Velocity (transactions per hour)
    COUNT(*)::NUMERIC / 24 as hourly_velocity,
    
    -- Currency diversity
    COUNT(DISTINCT currency) as currency_count,
    
    -- Timing patterns
    MODE() WITHIN GROUP (ORDER BY EXTRACT(HOUR FROM committed_at)) as peak_hour,
    
    -- Risk indicators
    MAX(amount) as max_single_transaction,
    COUNT(*) FILTER (WHERE amount > 10000) as large_transaction_count
FROM core.transaction_log
GROUP BY 
    time_bucket('1 day', committed_at),
    initiator_account_id,
    application_id
WITH NO DATA;

CREATE INDEX idx_account_activity_day 
    ON core.account_activity_summary(day DESC);

CREATE INDEX idx_account_activity_account 
    ON core.account_activity_summary(account_id, day DESC);

-- Refresh every 15 minutes for AML monitoring
SELECT add_continuous_aggregate_policy(
    'core.account_activity_summary',
    start_offset => INTERVAL '3 months',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '15 minutes',
    if_not_exists => TRUE
);

-- =============================================================================
-- CURRENCY FLOW SUMMARY (for FX and treasury)
-- =============================================================================

CREATE MATERIALIZED VIEW core.currency_flow_summary
WITH (timescaledb.continuous) AS
SELECT 
    time_bucket('1 day', committed_at) as day,
    currency,
    application_id,
    
    -- Inflows (credits to system)
    COUNT(*) FILTER (WHERE status = 'completed') as completed_transactions,
    SUM(amount) FILTER (WHERE status = 'completed') as completed_volume,
    
    -- Transaction types breakdown
    COUNT(*) FILTER (WHERE transaction_type_id IN (
        SELECT type_id FROM core.transaction_types WHERE type_code = 'CASH_IN'
    )) as cash_in_count,
    SUM(amount) FILTER (WHERE transaction_type_id IN (
        SELECT type_id FROM core.transaction_types WHERE type_code = 'CASH_IN'
    )) as cash_in_volume,
    
    COUNT(*) FILTER (WHERE transaction_type_id IN (
        SELECT type_id FROM core.transaction_types WHERE type_code = 'CASH_OUT'
    )) as cash_out_count,
    SUM(amount) FILTER (WHERE transaction_type_id IN (
        SELECT type_id FROM core.transaction_types WHERE type_code = 'CASH_OUT'
    )) as cash_out_volume,
    
    COUNT(*) FILTER (WHERE transaction_type_id IN (
        SELECT type_id FROM core.transaction_types WHERE type_code = 'P2P_TRANSFER'
    )) as p2p_count,
    SUM(amount) FILTER (WHERE transaction_type_id IN (
        SELECT type_id FROM core.transaction_types WHERE type_code = 'P2P_TRANSFER'
    )) as p2p_volume,
    
    -- Net flow (positive = more cash in, negative = more cash out)
    COALESCE(SUM(amount) FILTER (WHERE transaction_type_id IN (
        SELECT type_id FROM core.transaction_types WHERE type_code = 'CASH_IN'
    )), 0) -
    COALESCE(SUM(amount) FILTER (WHERE transaction_type_id IN (
        SELECT type_id FROM core.transaction_types WHERE type_code = 'CASH_OUT'
    )), 0) as net_flow
FROM core.transaction_log
GROUP BY 
    time_bucket('1 day', committed_at),
    currency,
    application_id
WITH NO DATA;

CREATE INDEX idx_currency_flow_day 
    ON core.currency_flow_summary(day DESC);

-- Refresh every hour
SELECT add_continuous_aggregate_policy(
    'core.currency_flow_summary',
    start_offset => INTERVAL '1 year',
    end_offset => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

-- =============================================================================
-- BLOCKCHAIN/VERIFICATION SUMMARY (for audit)
-- =============================================================================

CREATE MATERIALIZED VIEW core.blockchain_verification_summary
WITH (timescaledb.continuous) AS
SELECT 
    time_bucket('1 day', b.created_at) as day,
    b.application_id,
    
    -- Block stats
    COUNT(DISTINCT b.block_id) as blocks_created,
    AVG(b.transaction_count) as avg_txns_per_block,
    SUM(b.transaction_count) as total_txns_blocked,
    
    -- Merkle tree stats
    COUNT(DISTINCT mt.merkle_root) as merkle_roots,
    
    -- Verification stats
    COUNT(*) FILTER (WHERE b.verified_at IS NOT NULL) as verified_blocks,
    AVG(b.verification_time_ms) as avg_verification_time
FROM core.blocks b
LEFT JOIN core.merkle_trees mt ON b.block_id = mt.block_id
GROUP BY 
    time_bucket('1 day', b.created_at),
    b.application_id
WITH NO DATA;

-- Refresh daily
SELECT add_continuous_aggregate_policy(
    'core.blockchain_verification_summary',
    start_offset => INTERVAL '2 years',
    end_offset => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- =============================================================================
-- QUERY FUNCTIONS FOR DASHBOARDS
-- =============================================================================

-- Function to get real-time transaction volume
CREATE OR REPLACE FUNCTION core.get_realtime_volume(
    p_hours INTEGER DEFAULT 24
)
RETURNS TABLE (
    hour TIMESTAMPTZ,
    transaction_count BIGINT,
    total_volume NUMERIC,
    unique_users BIGINT
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        hs.bucket as hour,
        hs.transaction_count,
        hs.total_amount as total_volume,
        hs.unique_users
    FROM core.hourly_transaction_summary hs
    WHERE hs.bucket >= core.precise_now() - (p_hours || ' hours')::INTERVAL
    ORDER BY hs.bucket DESC;
END;
$$;

-- Function to get compliance metrics
CREATE OR REPLACE FUNCTION core.get_compliance_metrics(
    p_start_date DATE,
    p_end_date DATE
)
RETURNS TABLE (
    metric_date DATE,
    total_transactions BIGINT,
    high_value_count BIGINT,
    unique_users BIGINT,
    success_rate NUMERIC
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        dm.day::DATE as metric_date,
        dm.total_transactions,
        dm.high_value_count,
        dm.active_users as unique_users,
        ROUND(
            dm.completed_count::NUMERIC / 
            NULLIF(dm.total_transactions, 0) * 100,
            2
        ) as success_rate
    FROM core.daily_application_metrics dm
    WHERE dm.day BETWEEN p_start_date AND p_end_date
    ORDER BY dm.day;
END;
$$;

-- Function to get account velocity (for AML)
CREATE OR REPLACE FUNCTION core.get_account_velocity(
    p_account_id UUID,
    p_days INTEGER DEFAULT 30
)
RETURNS TABLE (
    day DATE,
    transaction_count BIGINT,
    total_volume NUMERIC,
    unique_counterparties BIGINT,
    large_transaction_count BIGINT
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        aas.day::DATE,
        aas.total_transactions,
        aas.total_volume,
        aas.unique_counterparties,
        aas.large_transaction_count
    FROM core.account_activity_summary aas
    WHERE aas.account_id = p_account_id
      AND aas.day >= CURRENT_DATE - p_days
    ORDER BY aas.day DESC;
END;
$$;

-- =============================================================================
-- REGISTER CONTINUOUS AGGREGATES IN CONFIG
-- =============================================================================

UPDATE core.timescaledb_config SET
    has_continuous_aggregates = TRUE,
    last_modified_at = core.precise_now()
WHERE schema_name = 'core' AND table_name = 'transaction_log';

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON MATERIALIZED VIEW core.hourly_transaction_summary IS 
    'Real-time hourly transaction metrics (5-min refresh)';
COMMENT ON MATERIALIZED VIEW core.daily_application_metrics IS 
    'Daily application usage metrics (hourly refresh)';
COMMENT ON MATERIALIZED VIEW core.monthly_financial_summary IS 
    'Monthly financial summary for regulatory reporting (daily refresh)';
COMMENT ON MATERIALIZED VIEW core.account_activity_summary IS 
    'Per-account activity for KYC/AML monitoring (15-min refresh)';

-- =============================================================================
-- END OF FILE
-- =============================================================================
