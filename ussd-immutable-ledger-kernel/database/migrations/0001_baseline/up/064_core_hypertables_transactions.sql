-- =============================================================================
-- USSD KERNEL CORE SCHEMA - TIMESCALEDB HYPERTABLES (TRANSACTIONS)
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    064_core_hypertables_transactions.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      core
-- DESCRIPTION: Convert core transaction tables to TimescaleDB hypertables
--              for production-scale USSD workload (millions of txns/day).
-- =============================================================================

/*
================================================================================
SCALING RATIONALE
================================================================================

Zimbabwe Scale Assumptions:
- Population: 15-16 million
- Active USSD users: 2-10 million
- Daily transactions: 500,000 - 5,000,000
- Monthly transactions: 15-150 million rows
- Retention: 7-10 years (regulatory requirement)

Without TimescaleDB:
- Vanilla PostgreSQL struggles after 50-100 million rows
- Query performance degrades significantly
- Storage costs explode without compression
- Maintenance (VACUUM, REINDEX) becomes operational nightmare

With TimescaleDB Hypertables:
- 5-10× insert throughput improvement
- 80-95% storage reduction via compression
- Sub-second queries on time ranges via chunk pruning
- Automated retention and archival

================================================================================
HYPERTABLE CONFIGURATION
================================================================================

transaction_log:
- Chunk interval: 1 day (optimal for daily batch processing)
- Partitioning: By application_id (multi-tenant isolation)
- Compression: After 7 days
- Retention: 10 years (with legal-hold support)

blocks:
- Chunk interval: 1 day
- Compression: After 7 days
- Retention: 10 years

merkle_trees:
- Chunk interval: 1 week (fewer records)
- Compression: After 30 days
- Retention: 10 years

================================================================================
*/

-- =============================================================================
-- CONVERT transaction_log TO HYPERTABLE
-- =============================================================================

-- First, ensure the partition_date column exists and is used for time dimension
-- (If the table was created with a different time column, adjust accordingly)

-- Check if already a hypertable
DO $$
DECLARE
    v_is_hypertable BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM timescaledb_information.hypertables
        WHERE hypertable_schema = 'core' AND hypertable_name = 'transaction_log'
    ) INTO v_is_hypertable;
    
    IF v_is_hypertable THEN
        RAISE NOTICE 'transaction_log is already a hypertable';
        RETURN;
    END IF;
    
    -- Convert to hypertable
    PERFORM create_hypertable(
        'core.transaction_log',
        'committed_at',  -- Time dimension column
        chunk_time_interval => INTERVAL '1 day',
        if_not_exists => TRUE,
        migrate_data => TRUE  -- Safe for existing data
    );
    
    RAISE NOTICE 'transaction_log converted to hypertable successfully';
END;
$$;

-- =============================================================================
-- OPTIMIZE INDEXES FOR HYPERTABLE
-- =============================================================================

-- Drop and recreate indexes optimized for chunk pruning
DROP INDEX IF EXISTS idx_transaction_log_committed_at;

-- BRIN index for time-range scans (much smaller than B-tree for append-only)
CREATE INDEX idx_transaction_log_committed_at_brin 
    ON core.transaction_log USING BRIN (committed_at)
    WITH (pages_per_range = 128);

-- B-tree index for exact lookups (preserved)
-- (Existing indexes like idx_transaction_log_uuid, idx_transaction_log_idempotency remain)

-- Partition-aware index for application queries
CREATE INDEX idx_transaction_log_app_time 
    ON core.transaction_log (application_id, committed_at DESC);

-- =============================================================================
-- CONVERT blocks TO HYPERTABLE
-- =============================================================================

DO $$
DECLARE
    v_is_hypertable BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM timescaledb_information.hypertables
        WHERE hypertable_schema = 'core' AND hypertable_name = 'blocks'
    ) INTO v_is_hypertable;
    
    IF v_is_hypertable THEN
        RAISE NOTICE 'blocks is already a hypertable';
        RETURN;
    END IF;
    
    PERFORM create_hypertable(
        'core.blocks',
        'created_at',
        chunk_time_interval => INTERVAL '1 day',
        if_not_exists => TRUE,
        migrate_data => TRUE
    );
    
    RAISE NOTICE 'blocks converted to hypertable successfully';
END;
$$;

-- Optimize blocks indexes
CREATE INDEX idx_blocks_created_at_brin 
    ON core.blocks USING BRIN (created_at)
    WITH (pages_per_range = 128);

-- =============================================================================
-- CONVERT merkle_trees TO HYPERTABLE (if applicable)
-- =============================================================================

-- Note: merkle_trees may have lower volume, but still benefits from partitioning
DO $$
DECLARE
    v_table_exists BOOLEAN;
    v_is_hypertable BOOLEAN;
BEGIN
    -- Check if table exists
    SELECT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'core' AND table_name = 'merkle_trees'
    ) INTO v_table_exists;
    
    IF NOT v_table_exists THEN
        RAISE NOTICE 'merkle_trees table does not exist, skipping';
        RETURN;
    END IF;
    
    -- Check if already hypertable
    SELECT EXISTS (
        SELECT 1 FROM timescaledb_information.hypertables
        WHERE hypertable_schema = 'core' AND hypertable_name = 'merkle_trees'
    ) INTO v_is_hypertable;
    
    IF v_is_hypertable THEN
        RAISE NOTICE 'merkle_trees is already a hypertable';
        RETURN;
    END IF;
    
    -- Weekly chunks for lower-volume table
    PERFORM create_hypertable(
        'core.merkle_trees',
        'created_at',
        chunk_time_interval => INTERVAL '1 week',
        if_not_exists => TRUE,
        migrate_data => TRUE
    );
    
    RAISE NOTICE 'merkle_trees converted to hypertable successfully';
END;
$$;

-- =============================================================================
-- CONVERT movement_postings TO HYPERTABLE
-- =============================================================================

DO $$
DECLARE
    v_is_hypertable BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM timescaledb_information.hypertables
        WHERE hypertable_schema = 'core' AND hypertable_name = 'movement_postings'
    ) INTO v_is_hypertable;
    
    IF v_is_hypertable THEN
        RAISE NOTICE 'movement_postings is already a hypertable';
        RETURN;
    END IF;
    
    PERFORM create_hypertable(
        'core.movement_postings',
        'posted_at',
        chunk_time_interval => INTERVAL '1 day',
        if_not_exists => TRUE,
        migrate_data => TRUE
    );
    
    RAISE NOTICE 'movement_postings converted to hypertable successfully';
END;
$$;

-- Optimize indexes
CREATE INDEX idx_movement_postings_posted_brin 
    ON core.movement_postings USING BRIN (posted_at)
    WITH (pages_per_range = 128);

-- =============================================================================
-- REGISTER CONFIGURATIONS
-- =============================================================================

-- Register all hypertables in config table
SELECT core.register_hypertable_config(
    'core', 'transaction_log', 'committed_at', INTERVAL '1 day',
    NULL, FALSE, NULL, NULL, NULL, FALSE, NULL, FALSE, NULL
);

SELECT core.register_hypertable_config(
    'core', 'blocks', 'created_at', INTERVAL '1 day',
    NULL, FALSE, NULL, NULL, NULL, FALSE, NULL, FALSE, NULL
);

SELECT core.register_hypertable_config(
    'core', 'movement_postings', 'posted_at', INTERVAL '1 day',
    NULL, FALSE, NULL, NULL, NULL, FALSE, NULL, FALSE, NULL
);

-- =============================================================================
-- VERIFY HYPERTABLE CREATION
-- =============================================================================

DO $$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_count
    FROM timescaledb_information.hypertables
    WHERE hypertable_schema = 'core';
    
    RAISE NOTICE 'TimescaleDB hypertables created in core schema: %', v_count;
    
    -- List all hypertables
    FOR v_count IN 
        SELECT 1 FROM timescaledb_information.hypertables 
        WHERE hypertable_schema = 'core'
    LOOP
        RAISE NOTICE '  - Hypertable: core.%', 
            (SELECT hypertable_name FROM timescaledb_information.hypertables 
             WHERE hypertable_schema = 'core' LIMIT 1 OFFSET v_count-1);
    END LOOP;
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE core.transaction_log IS 'Immutable transaction log as TimescaleDB hypertable (1-day chunks)';
COMMENT ON TABLE core.blocks IS 'Merkle tree blocks as TimescaleDB hypertable (1-day chunks)';
COMMENT ON TABLE core.movement_postings IS 'Double-entry postings as TimescaleDB hypertable (1-day chunks)';

-- =============================================================================
-- END OF FILE
-- =============================================================================
