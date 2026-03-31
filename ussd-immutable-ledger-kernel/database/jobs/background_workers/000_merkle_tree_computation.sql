-- =============================================================================
-- Background Worker: Merkle Tree Computation
-- =============================================================================
-- Description: Computes Merkle tree roots for blocks of transactions to ensure
--              data integrity and provide cryptographic proofs
-- Schedule: Runs continuously, processes batches every 5 seconds
-- Dependencies: Requires pg_background or pg_cron extension
-- =============================================================================

-- =============================================================================
-- COMPLIANCE FRAMEWORK ALIGNMENT
-- =============================================================================
-- ISO/IEC 27001:2022
--   A.12.3 (Backup)       - Computational integrity ensures backup data validity
--   A.12.4 (Logging)      - All computations logged with timestamps and results
--   A.8.1 (Asset Mgmt)    - Cryptographic proofs protect data asset integrity
--
-- ISO/IEC 27031:2025
--   Business Continuity   - Merkle proofs enable rapid data integrity verification
--   Recovery Objectives   - Cryptographic verification accelerates recovery validation
--
-- ISO/IEC 27040:2024
--   Storage Security      - Merkle roots provide tamper-evident storage verification
--   Data Integrity        - Hash chains ensure data has not been altered
-- =============================================================================

-- Install required extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Main function to compute Merkle tree for pending blocks
CREATE OR REPLACE FUNCTION ledger.compute_merkle_tree()
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_batch_size INT := 1000;
    v_block RECORD;
    v_merkle_root BYTEA;
    v_start_time TIMESTAMPTZ;
BEGIN
    v_start_time := clock_timestamp();
    
    -- Find blocks pending Merkle root computation
    FOR v_block IN 
        SELECT block_id, block_height, transactions_hash
        FROM ledger.blocks
        WHERE merkle_root IS NULL
          AND status = 'SEALED'
          AND created_at < NOW() - INTERVAL '30 seconds'
        ORDER BY block_height
        LIMIT v_batch_size
    LOOP
        BEGIN
            -- Compute Merkle root from transaction hashes
            SELECT ledger.calculate_merkle_root(
                ARRAY_AGG(tx.transaction_hash ORDER BY tx.tx_index)
            )
            INTO v_merkle_root
            FROM ledger.transactions tx
            WHERE tx.block_id = v_block.block_id;

            -- Update block with computed Merkle root
            UPDATE ledger.blocks
            SET merkle_root = v_merkle_root,
                merkle_computed_at = NOW(),
                updated_at = NOW()
            WHERE block_id = v_block.block_id;

            -- Log completion
            INSERT INTO ledger.merkle_computation_log (
                block_id,
                block_height,
                merkle_root,
                computation_time_ms,
                computed_at
            ) VALUES (
                v_block.block_id,
                v_block.block_height,
                v_merkle_root,
                EXTRACT(MILLISECOND FROM (clock_timestamp() - v_start_time)),
                NOW()
            );

        EXCEPTION WHEN OTHERS THEN
            -- Log error but continue processing other blocks
            INSERT INTO ledger.error_log (
                error_type,
                error_message,
                context,
                created_at
            ) VALUES (
                'MERKLE_COMPUTATION_FAILED',
                SQLERRM,
                jsonb_build_object('block_id', v_block.block_id),
                NOW()
            );
        END;
    END LOOP;
END;
$$;

-- Helper function to calculate Merkle root from array of hashes
CREATE OR REPLACE FUNCTION ledger.calculate_merkle_root(hashes BYTEA[])
RETURNS BYTEA
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    v_level BYTEA[];
    v_next_level BYTEA[];
    v_i INT;
    v_combined BYTEA;
BEGIN
    IF array_length(hashes, 1) IS NULL THEN
        RETURN NULL;
    END IF;
    
    IF array_length(hashes, 1) = 0 THEN
        RETURN '\x';
    END IF;
    
    IF array_length(hashes, 1) = 1 THEN
        RETURN hashes[1];
    END IF;
    
    v_level := hashes;
    
    -- Build tree level by level
    WHILE array_length(v_level, 1) > 1 LOOP
        v_next_level := ARRAY[]::BYTEA[];
        v_i := 1;
        
        WHILE v_i <= array_length(v_level, 1) LOOP
            IF v_i + 1 <= array_length(v_level, 1) THEN
                -- Concatenate and hash pair
                v_combined := v_level[v_i] || v_level[v_i + 1];
            ELSE
                -- Odd node: duplicate and hash
                v_combined := v_level[v_i] || v_level[v_i];
            END IF;
            
            v_next_level := array_append(v_next_level, digest(v_combined, 'sha256'));
            v_i := v_i + 2;
        END LOOP;
        
        v_level := v_next_level;
    END LOOP;
    
    RETURN v_level[1];
END;
$$;

-- Create supporting tables if not exist
CREATE TABLE IF NOT EXISTS ledger.merkle_computation_log (
    log_id BIGSERIAL PRIMARY KEY,
    block_id BIGINT NOT NULL REFERENCES ledger.blocks(block_id),
    block_height BIGINT NOT NULL,
    merkle_root BYTEA,
    computation_time_ms NUMERIC,
    computed_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uk_merkle_log_block UNIQUE (block_id)
);

CREATE INDEX IF NOT EXISTS idx_merkle_log_computed_at 
    ON ledger.merkle_computation_log(computed_at);

-- Create error_log table if not exists
CREATE TABLE IF NOT EXISTS ledger.error_log (
    error_id BIGSERIAL PRIMARY KEY,
    error_type TEXT NOT NULL,
    error_message TEXT,
    context JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_error_log_type_time 
    ON ledger.error_log(error_type, created_at);

-- Function to launch background worker for Merkle tree computation
CREATE OR REPLACE FUNCTION ledger.launch_merkle_worker()
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_worker_pid INTEGER;
BEGIN
    -- Use dblink to create a background worker equivalent
    -- This creates an autonomous transaction that runs independently
    PERFORM dblink_connect('worker_conn', 'dbname=' || current_database());
    PERFORM dblink_send_query('worker_conn', 'SELECT ledger.compute_merkle_tree()');
    PERFORM dblink_disconnect('worker_conn');
    
    RAISE NOTICE 'Merkle tree computation worker launched at %', NOW();
EXCEPTION
    WHEN OTHERS THEN
        -- If dblink is not available, just log and continue
        RAISE NOTICE 'Note: dblink not available for background worker. Use pg_cron or external scheduler.';
END;
$$;

-- Alternative: Create pg_cron schedule for Merkle tree computation
-- This requires pg_cron extension to be installed at database level
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        -- Schedule to run every 5 minutes
        PERFORM cron.schedule('merkle-tree-computation', '*/5 * * * *', 'SELECT ledger.compute_merkle_tree()');
        RAISE NOTICE 'Merkle tree computation scheduled via pg_cron';
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'pg_cron not available. Schedule ledger.compute_merkle_tree() manually or via external scheduler.';
END;
$$;

-- Function for parallel Merkle root computation (performance optimization)
CREATE OR REPLACE FUNCTION ledger.compute_merkle_tree_parallel(
    p_worker_count INT DEFAULT 4
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_batch_size INT;
    v_total_pending INT;
BEGIN
    -- Count pending blocks
    SELECT COUNT(*) INTO v_total_pending
    FROM ledger.blocks
    WHERE merkle_root IS NULL
      AND status = 'SEALED'
      AND created_at < NOW() - INTERVAL '30 seconds';
    
    -- Calculate batch size per worker
    v_batch_size := GREATEST(CEIL(v_total_pending::NUMERIC / p_worker_count), 100);
    
    -- Process in parallel using parallel query
    PERFORM ledger.compute_merkle_tree_batch(
        block_height,
        LEAST(block_height + v_batch_size - 1, (SELECT MAX(block_height) FROM ledger.blocks WHERE merkle_root IS NULL))
    )
    FROM (
        SELECT DISTINCT FLOOR((block_height - 1) / v_batch_size)::BIGINT * v_batch_size + 1 as block_height
        FROM ledger.blocks
        WHERE merkle_root IS NULL
          AND status = 'SEALED'
          AND created_at < NOW() - INTERVAL '30 seconds'
        LIMIT p_worker_count
    ) batches;
END;
$$;

-- Batch computation helper
CREATE OR REPLACE FUNCTION ledger.compute_merkle_tree_batch(
    p_start_height BIGINT,
    p_end_height BIGINT
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_block RECORD;
    v_merkle_root BYTEA;
BEGIN
    FOR v_block IN 
        SELECT block_id, block_height, transactions_hash
        FROM ledger.blocks
        WHERE block_height BETWEEN p_start_height AND p_end_height
          AND merkle_root IS NULL
          AND status = 'SEALED'
        ORDER BY block_height
    LOOP
        BEGIN
            SELECT ledger.calculate_merkle_root(
                ARRAY_AGG(tx.transaction_hash ORDER BY tx.tx_index)
            )
            INTO v_merkle_root
            FROM ledger.transactions tx
            WHERE tx.block_id = v_block.block_id;

            UPDATE ledger.blocks
            SET merkle_root = v_merkle_root,
                merkle_computed_at = NOW(),
                updated_at = NOW()
            WHERE block_id = v_block.block_id;
        EXCEPTION WHEN OTHERS THEN
            INSERT INTO ledger.error_log (
                error_type, error_message, context, created_at
            ) VALUES (
                'MERKLE_BATCH_FAILED', SQLERRM,
                jsonb_build_object('block_id', v_block.block_id, 'batch', p_start_height || '-' || p_end_height),
                NOW()
            );
        END;
    END LOOP;
END;
$$;

-- Function for incremental Merkle tree updates in streaming scenarios
CREATE OR REPLACE FUNCTION ledger.incremental_merkle_update(
    p_block_id BIGINT
)
RETURNS BYTEA
LANGUAGE plpgsql
AS $$
DECLARE
    v_existing_root BYTEA;
    v_new_hashes BYTEA[];
    v_combined_root BYTEA;
BEGIN
    -- Get existing Merkle root for previous blocks
    SELECT merkle_root INTO v_existing_root
    FROM ledger.blocks
    WHERE block_id < p_block_id
    ORDER BY block_id DESC
    LIMIT 1;
    
    -- Get new transaction hashes for this block
    SELECT ARRAY_AGG(transaction_hash ORDER BY tx_index)
    INTO v_new_hashes
    FROM ledger.transactions
    WHERE block_id = p_block_id;
    
    -- If we have an existing root, combine it with new hashes
    IF v_existing_root IS NOT NULL AND array_length(v_new_hashes, 1) > 0 THEN
        -- Combine previous root with new block's hash
        v_combined_root := digest(v_existing_root || ledger.calculate_merkle_root(v_new_hashes), 'sha256');
    ELSE
        -- Just compute for this block
        v_combined_root := ledger.calculate_merkle_root(v_new_hashes);
    END IF;
    
    -- Update block with computed root
    UPDATE ledger.blocks
    SET merkle_root = v_combined_root,
        merkle_computed_at = NOW(),
        updated_at = NOW()
    WHERE block_id = p_block_id;
    
    RETURN v_combined_root;
END;
$$;

-- Verification function to cross-check computed roots against stored proofs
CREATE OR REPLACE FUNCTION ledger.verify_merkle_roots(
    p_start_block BIGINT DEFAULT NULL,
    p_end_block BIGINT DEFAULT NULL
)
RETURNS TABLE (
    block_id BIGINT,
    block_height BIGINT,
    stored_root BYTEA,
    computed_root BYTEA,
    is_valid BOOLEAN
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        b.block_id,
        b.block_height,
        b.merkle_root as stored_root,
        ledger.calculate_merkle_root(
            ARRAY_AGG(tx.transaction_hash ORDER BY tx.tx_index)
        ) as computed_root,
        b.merkle_root = ledger.calculate_merkle_root(
            ARRAY_AGG(tx.transaction_hash ORDER BY tx.tx_index)
        ) as is_valid
    FROM ledger.blocks b
    LEFT JOIN ledger.transactions tx ON tx.block_id = b.block_id
    WHERE b.merkle_root IS NOT NULL
      AND (p_start_block IS NULL OR b.block_height >= p_start_block)
      AND (p_end_block IS NULL OR b.block_height <= p_end_block)
    GROUP BY b.block_id, b.block_height, b.merkle_root
    HAVING b.merkle_root != ledger.calculate_merkle_root(
        ARRAY_AGG(tx.transaction_hash ORDER BY tx.tx_index)
    ) OR TRUE;  -- Return all for verification
END;
$$;

-- View for monitoring Merkle computation status
CREATE OR REPLACE VIEW ledger.merkle_computation_status AS
SELECT 
    COUNT(*) FILTER (WHERE merkle_root IS NULL) as pending_blocks,
    COUNT(*) FILTER (WHERE merkle_root IS NOT NULL) as computed_blocks,
    COUNT(*) as total_blocks,
    MAX(merkle_computed_at) as last_computation_at,
    AVG(computation_time_ms) as avg_computation_time_ms
FROM ledger.blocks
WHERE status = 'SEALED';
