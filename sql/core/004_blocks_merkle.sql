-- ============================================================================
-- USSD KERNEL CORE SCHEMA - BLOCKS AND MERKLE TREES
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Aggregates transactions into cryptographic blocks with Merkle
--              tree roots for efficient inclusion proofs and external anchoring.
-- Immutability: 100% - Blocks are sealed and become immutable
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. BLOCKS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_core.blocks (
    -- Primary identifier
    block_id BIGSERIAL PRIMARY KEY,
    
    -- Block numbering (like blockchain height)
    block_height BIGINT NOT NULL UNIQUE,
    
    -- Block identification
    block_uuid UUID NOT NULL DEFAULT uuid_generate_v4(),
    block_name VARCHAR(100),  -- Human-readable identifier (optional)
    
    -- Scope: Global or application-specific
    application_id UUID,  -- NULL = global block, includes all apps
    
    -- Status lifecycle
    status ussd_core.block_status DEFAULT 'open',
    
    -- Time boundaries
    opened_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    sealed_at TIMESTAMPTZ,
    anchored_at TIMESTAMPTZ,
    
    -- Transaction range (for quick reference)
    first_transaction_id BIGINT,
    last_transaction_id BIGINT,
    transaction_count INTEGER DEFAULT 0,
    
    -- Merkle tree root (critical for integrity)
    merkle_root VARCHAR(64),
    
    -- Previous block reference (for block chain)
    previous_block_hash VARCHAR(64),
    block_hash VARCHAR(64),  -- Hash of this block header
    
    -- External anchoring (blockchain integration)
    anchor_type VARCHAR(50),  -- e.g., 'ethereum', 'stellar', 'bitcoin'
    anchor_transaction_hash TEXT,  -- TX hash on external chain
    anchor_block_number BIGINT,  -- Block number on external chain
    anchor_confirmations INTEGER DEFAULT 0,
    
    -- Digital signature (kernel signs the block)
    kernel_signature TEXT,
    kernel_key_id VARCHAR(100),  -- Reference to signing key
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    -- Record hash for integrity
    record_hash VARCHAR(64) NOT NULL
);

-- ----------------------------------------------------------------------------
-- 2. MERKLE TREE STRUCTURE TABLE
-- ----------------------------------------------------------------------------
-- Stores the Merkle tree nodes for each block to enable inclusion proofs
CREATE TABLE ussd_core.merkle_trees (
    tree_id BIGSERIAL PRIMARY KEY,
    block_id BIGINT NOT NULL REFERENCES ussd_core.blocks(block_id),
    
    -- Node information
    node_level INTEGER NOT NULL,  -- 0 = leaf (transaction hash), >0 = internal node
    node_index INTEGER NOT NULL,  -- Position at this level
    
    -- Hash value
    node_hash VARCHAR(64) NOT NULL,
    
    -- For leaves only: reference to transaction
    transaction_id BIGINT,
    transaction_hash VARCHAR(64),
    
    -- For internal nodes: references to children
    left_child_hash VARCHAR(64),
    right_child_hash VARCHAR(64),
    
    -- Unique constraint per block/level/index
    UNIQUE(block_id, node_level, node_index)
);

-- ----------------------------------------------------------------------------
-- 3. BLOCK TRANSACTION MAPPING (Explicit many-to-many)
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_core.block_transactions (
    block_id BIGINT NOT NULL REFERENCES ussd_core.blocks(block_id),
    transaction_id BIGINT NOT NULL,
    partition_date DATE NOT NULL,
    sequence_number INTEGER NOT NULL,  -- Position within block
    transaction_hash VARCHAR(64) NOT NULL,  -- Denormalized for verification
    
    PRIMARY KEY (block_id, transaction_id),
    FOREIGN KEY (transaction_id, partition_date) 
        REFERENCES ussd_core.transactions(transaction_id, partition_date)
);

-- ----------------------------------------------------------------------------
-- 4. INDEXES
-- ----------------------------------------------------------------------------

-- Block indexes
CREATE INDEX idx_blocks_status ON ussd_core.blocks(status);
CREATE INDEX idx_blocks_application ON ussd_core.blocks(application_id);
CREATE INDEX idx_blocks_time_range ON ussd_core.blocks(opened_at, sealed_at);
CREATE INDEX idx_blocks_anchor ON ussd_core.blocks(anchor_type, anchor_transaction_hash) 
    WHERE anchor_transaction_hash IS NOT NULL;

-- Merkle tree indexes
CREATE INDEX idx_merkle_block ON ussd_core.merkle_trees(block_id);
CREATE INDEX idx_merkle_block_level ON ussd_core.merkle_trees(block_id, node_level);
CREATE INDEX idx_merkle_transaction ON ussd_core.merkle_trees(transaction_id) 
    WHERE transaction_id IS NOT NULL;

-- Block transactions indexes
CREATE INDEX idx_block_tx_block ON ussd_core.block_transactions(block_id);
CREATE INDEX idx_block_tx_transaction ON ussd_core.block_transactions(transaction_id);

-- ----------------------------------------------------------------------------
-- 5. IMMUTABILITY TRIGGERS (Blocks are immutable once sealed)
-- ----------------------------------------------------------------------------

-- Allow updates only while block is open/sealing
CREATE OR REPLACE FUNCTION ussd_core.enforce_block_immutability()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status IN ('sealed', 'anchored') THEN
        RAISE EXCEPTION 'BLOCK_IMMUTABLE: Block % is already sealed and cannot be modified',
            OLD.block_id
            USING ERRCODE = 'P0001';
    END IF;
    
    -- Allow status transitions: open -> sealing -> sealed -> anchored
    IF OLD.status = 'open' AND NEW.status NOT IN ('open', 'sealing') THEN
        RAISE EXCEPTION 'INVALID_STATUS_TRANSITION: Cannot transition from open to %', NEW.status;
    END IF;
    
    IF OLD.status = 'sealing' AND NEW.status NOT IN ('sealing', 'sealed') THEN
        RAISE EXCEPTION 'INVALID_STATUS_TRANSITION: Cannot transition from sealing to %', NEW.status;
    END IF;
    
    IF OLD.status = 'sealed' AND NEW.status NOT IN ('sealed', 'anchored') THEN
        RAISE EXCEPTION 'INVALID_STATUS_TRANSITION: Cannot transition from sealed to %', NEW.status;
    END IF;
    
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_blocks_enforce_immutability
    BEFORE UPDATE ON ussd_core.blocks
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.enforce_block_immutability();

-- Prevent deletion of blocks
CREATE TRIGGER trg_blocks_prevent_delete
    BEFORE DELETE ON ussd_core.blocks
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_delete();

-- Merkle tree is immutable always
CREATE TRIGGER trg_merkle_prevent_update
    BEFORE UPDATE ON ussd_core.merkle_trees
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_update();

CREATE TRIGGER trg_merkle_prevent_delete
    BEFORE DELETE ON ussd_core.merkle_trees
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_delete();

-- Block transactions are immutable
CREATE TRIGGER trg_block_tx_prevent_update
    BEFORE UPDATE ON ussd_core.block_transactions
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_update();

CREATE TRIGGER trg_block_tx_prevent_delete
    BEFORE DELETE ON ussd_core.block_transactions
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_delete();

-- ----------------------------------------------------------------------------
-- 6. HASH COMPUTATION
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ussd_core.compute_block_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_data TEXT;
BEGIN
    IF NEW.status = 'sealed' AND NEW.block_hash IS NULL THEN
        -- Compute block hash from header data
        v_data := NEW.block_id::TEXT || 
                  NEW.block_height::TEXT ||
                  COALESCE(NEW.application_id::TEXT, '') ||
                  COALESCE(NEW.merkle_root, '') ||
                  COALESCE(NEW.previous_block_hash, '') ||
                  NEW.opened_at::TEXT ||
                  COALESCE(NEW.sealed_at::TEXT, '') ||
                  NEW.transaction_count::TEXT;
        
        NEW.block_hash := ussd_core.generate_hash(v_data);
        
        -- Compute record hash
        NEW.record_hash := ussd_core.generate_hash(
            NEW.block_hash || NEW.block_uuid::TEXT
        );
    END IF;
    
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_blocks_compute_hash
    BEFORE UPDATE ON ussd_core.blocks
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.compute_block_hash();

-- ----------------------------------------------------------------------------
-- 7. MERKLE TREE FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to compute Merkle root from array of transaction hashes
CREATE OR REPLACE FUNCTION ussd_core.compute_merkle_root(
    p_hashes TEXT[]
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    v_level TEXT[];
    v_next_level TEXT[];
    v_i INTEGER;
    v_combined TEXT;
BEGIN
    IF array_length(p_hashes, 1) IS NULL THEN
        RETURN NULL;
    END IF;
    
    IF array_length(p_hashes, 1) = 0 THEN
        RETURN ussd_core.generate_hash('');
    END IF;
    
    v_level := p_hashes;
    
    -- Build tree level by level
    WHILE array_length(v_level, 1) > 1 LOOP
        v_next_level := '{}';
        v_i := 1;
        
        WHILE v_i <= array_length(v_level, 1) LOOP
            IF v_i + 1 <= array_length(v_level, 1) THEN
                -- Combine two hashes
                v_combined := v_level[v_i] || v_level[v_i + 1];
            ELSE
                -- Odd number of nodes: duplicate the last one
                v_combined := v_level[v_i] || v_level[v_i];
            END IF;
            
            v_next_level := array_append(v_next_level, ussd_core.generate_hash(v_combined));
            v_i := v_i + 2;
        END LOOP;
        
        v_level := v_next_level;
    END LOOP;
    
    RETURN v_level[1];
END;
$$;

-- Function to build complete Merkle tree for a block
CREATE OR REPLACE FUNCTION ussd_core.build_merkle_tree(p_block_id BIGINT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_tx_hashes TEXT[];
    v_tx_ids BIGINT[];
    v_block_record ussd_core.blocks%ROWTYPE;
    v_level INTEGER := 0;
    v_level_hashes TEXT[];
    v_next_level TEXT[];
    v_i INTEGER;
    v_node_index INTEGER;
    v_combined TEXT;
BEGIN
    -- Get block info
    SELECT * INTO v_block_record FROM ussd_core.blocks WHERE block_id = p_block_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Block not found: %', p_block_id;
    END IF;
    
    -- Get transaction hashes for this block in order
    SELECT 
        array_agg(transaction_hash ORDER BY sequence_number),
        array_agg(transaction_id ORDER BY sequence_number)
    INTO v_tx_hashes, v_tx_ids
    FROM ussd_core.block_transactions
    WHERE block_id = p_block_id;
    
    IF array_length(v_tx_hashes, 1) IS NULL THEN
        RAISE EXCEPTION 'No transactions in block %', p_block_id;
    END IF;
    
    -- Clear existing tree
    DELETE FROM ussd_core.merkle_trees WHERE block_id = p_block_id;
    
    -- Build tree bottom-up
    v_level_hashes := v_tx_hashes;
    v_node_index := 0;
    
    -- Store leaf nodes (level 0)
    FOR v_i IN 1..array_length(v_tx_hashes, 1) LOOP
        INSERT INTO ussd_core.merkle_trees (
            block_id, node_level, node_index, node_hash,
            transaction_id, transaction_hash
        ) VALUES (
            p_block_id, 0, v_i - 1, v_tx_hashes[v_i],
            v_tx_ids[v_i], v_tx_hashes[v_i]
        );
    END LOOP;
    
    -- Build internal nodes
    WHILE array_length(v_level_hashes, 1) > 1 LOOP
        v_level := v_level + 1;
        v_next_level := '{}';
        v_node_index := 0;
        v_i := 1;
        
        WHILE v_i <= array_length(v_level_hashes, 1) LOOP
            IF v_i + 1 <= array_length(v_level_hashes, 1) THEN
                v_combined := v_level_hashes[v_i] || v_level_hashes[v_i + 1];
                INSERT INTO ussd_core.merkle_trees (
                    block_id, node_level, node_index, node_hash,
                    left_child_hash, right_child_hash
                ) VALUES (
                    p_block_id, v_level, v_node_index, 
                    ussd_core.generate_hash(v_combined),
                    v_level_hashes[v_i], v_level_hashes[v_i + 1]
                );
            ELSE
                -- Odd node: duplicate
                v_combined := v_level_hashes[v_i] || v_level_hashes[v_i];
                INSERT INTO ussd_core.merkle_trees (
                    block_id, node_level, node_index, node_hash,
                    left_child_hash, right_child_hash
                ) VALUES (
                    p_block_id, v_level, v_node_index,
                    ussd_core.generate_hash(v_combined),
                    v_level_hashes[v_i], v_level_hashes[v_i]
                );
            END IF;
            
            v_next_level := array_append(v_next_level, ussd_core.generate_hash(v_combined));
            v_i := v_i + 2;
            v_node_index := v_node_index + 1;
        END LOOP;
        
        v_level_hashes := v_next_level;
    END LOOP;
    
    -- Update block with merkle root
    UPDATE ussd_core.blocks
    SET merkle_root = v_level_hashes[1],
        status = 'sealed',
        sealed_at = ussd_core.precise_now()
    WHERE block_id = p_block_id;
    
END;
$$;

-- ----------------------------------------------------------------------------
-- 8. BLOCK MANAGEMENT FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to create a new block
CREATE OR REPLACE FUNCTION ussd_core.create_block(
    p_application_id UUID DEFAULT NULL,
    p_block_name VARCHAR DEFAULT NULL
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_block_id BIGINT;
    v_height BIGINT;
    v_previous_hash VARCHAR(64);
BEGIN
    -- Get next block height
    SELECT COALESCE(MAX(block_height), 0) + 1 INTO v_height FROM ussd_core.blocks;
    
    -- Get previous block hash
    SELECT block_hash INTO v_previous_hash
    FROM ussd_core.blocks
    WHERE block_height = v_height - 1;
    
    INSERT INTO ussd_core.blocks (
        block_height,
        block_name,
        application_id,
        status,
        previous_block_hash
    ) VALUES (
        v_height,
        p_block_name,
        p_application_id,
        'open',
        v_previous_hash
    )
    RETURNING block_id INTO v_block_id;
    
    RETURN v_block_id;
END;
$$;

-- Function to add transaction to block
CREATE OR REPLACE FUNCTION ussd_core.add_transaction_to_block(
    p_transaction_id BIGINT,
    p_block_id BIGINT
)
RETURNS INTEGER  -- Returns sequence number within block
LANGUAGE plpgsql
AS $$
DECLARE
    v_sequence INTEGER;
    v_transaction_hash VARCHAR(64);
    v_partition_date DATE;
BEGIN
    -- Verify block is open
    IF NOT EXISTS (
        SELECT 1 FROM ussd_core.blocks 
        WHERE block_id = p_block_id AND status = 'open'
    ) THEN
        RAISE EXCEPTION 'Block % is not open', p_block_id;
    END IF;
    
    -- Get transaction info
    SELECT transaction_hash, partition_date 
    INTO v_transaction_hash, v_partition_date
    FROM ussd_core.transactions 
    WHERE transaction_id = p_transaction_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction % not found', p_transaction_id;
    END IF;
    
    -- Get next sequence number
    SELECT COALESCE(MAX(sequence_number), -1) + 1 INTO v_sequence
    FROM ussd_core.block_transactions
    WHERE block_id = p_block_id;
    
    -- Add to block
    INSERT INTO ussd_core.block_transactions (
        block_id, transaction_id, partition_date, 
        sequence_number, transaction_hash
    ) VALUES (
        p_block_id, p_transaction_id, v_partition_date,
        v_sequence, v_transaction_hash
    );
    
    -- Update block stats
    UPDATE ussd_core.blocks
    SET transaction_count = transaction_count + 1,
        first_transaction_id = COALESCE(first_transaction_id, p_transaction_id),
        last_transaction_id = p_transaction_id
    WHERE block_id = p_block_id;
    
    -- Update transaction
    UPDATE ussd_core.transactions
    SET block_id = p_block_id,
        block_sequence = v_sequence
    WHERE transaction_id = p_transaction_id;
    
    RETURN v_sequence;
END;
$$;

-- Function to seal a block (compute Merkle root, make immutable)
CREATE OR REPLACE FUNCTION ussd_core.seal_block(p_block_id BIGINT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_block ussd_core.blocks%ROWTYPE;
BEGIN
    SELECT * INTO v_block FROM ussd_core.blocks WHERE block_id = p_block_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Block % not found', p_block_id;
    END IF;
    
    IF v_block.status != 'open' THEN
        RAISE EXCEPTION 'Block % is not open (status: %)', p_block_id, v_block.status;
    END IF;
    
    IF v_block.transaction_count = 0 THEN
        RAISE EXCEPTION 'Cannot seal empty block %', p_block_id;
    END IF;
    
    -- Set to sealing (prevents new transactions)
    UPDATE ussd_core.blocks SET status = 'sealing' WHERE block_id = p_block_id;
    
    -- Build Merkle tree (this also updates status to sealed)
    PERFORM ussd_core.build_merkle_tree(p_block_id);
    
END;
$$;

-- ----------------------------------------------------------------------------
-- 9. INCLUSION PROOF FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to generate Merkle proof for a transaction
CREATE OR REPLACE FUNCTION ussd_core.generate_merkle_proof(
    p_transaction_id BIGINT
)
RETURNS TABLE (
    block_id BIGINT,
    merkle_root VARCHAR(64),
    transaction_index INTEGER,
    proof_path JSONB  -- Array of {position: 'left'|'right', hash: string}
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_block_id BIGINT;
    v_merkle_root VARCHAR(64);
    v_tx_index INTEGER;
    v_proof JSONB := '[]'::JSONB;
    v_current_level INTEGER := 0;
    v_current_index INTEGER;
    v_sibling RECORD;
BEGIN
    -- Get transaction's block and index
    SELECT bt.block_id, bt.sequence_number, b.merkle_root
    INTO v_block_id, v_tx_index, v_merkle_root
    FROM ussd_core.block_transactions bt
    JOIN ussd_core.blocks b ON bt.block_id = b.block_id
    WHERE bt.transaction_id = p_transaction_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction % not found in any block', p_transaction_id;
    END IF;
    
    v_current_index := v_tx_index;
    
    -- Build proof path from leaf to root
    WHILE EXISTS (
        SELECT 1 FROM ussd_core.merkle_trees 
        WHERE block_id = v_block_id AND node_level = v_current_level + 1
    ) LOOP
        -- Find sibling
        IF v_current_index % 2 = 0 THEN
            -- Current is left child, sibling is right
            SELECT node_hash, node_index INTO v_sibling
            FROM ussd_core.merkle_trees
            WHERE block_id = v_block_id 
              AND node_level = v_current_level
              AND node_index = v_current_index + 1;
            
            IF FOUND THEN
                v_proof := v_proof || jsonb_build_object('position', 'right', 'hash', v_sibling.node_hash);
            ELSE
                -- No right sibling, duplicate self
                SELECT node_hash INTO v_sibling
                FROM ussd_core.merkle_trees
                WHERE block_id = v_block_id 
                  AND node_level = v_current_level
                  AND node_index = v_current_index;
                v_proof := v_proof || jsonb_build_object('position', 'right', 'hash', v_sibling.node_hash);
            END IF;
        ELSE
            -- Current is right child, sibling is left
            SELECT node_hash, node_index INTO v_sibling
            FROM ussd_core.merkle_trees
            WHERE block_id = v_block_id 
              AND node_level = v_current_level
              AND node_index = v_current_index - 1;
            
            v_proof := v_proof || jsonb_build_object('position', 'left', 'hash', v_sibling.node_hash);
        END IF;
        
        v_current_index := v_current_index / 2;
        v_current_level := v_current_level + 1;
    END LOOP;
    
    RETURN QUERY SELECT v_block_id, v_merkle_root, v_tx_index, v_proof;
END;
$$;

-- Function to verify Merkle proof
CREATE OR REPLACE FUNCTION ussd_core.verify_merkle_proof(
    p_transaction_hash VARCHAR(64),
    p_merkle_root VARCHAR(64),
    p_proof_path JSONB
)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    v_current_hash VARCHAR(64) := p_transaction_hash;
    v_proof_element JSONB;
    v_combined TEXT;
BEGIN
    FOR v_proof_element IN SELECT * FROM jsonb_array_elements(p_proof_path)
    LOOP
        IF v_proof_element->>'position' = 'left' THEN
            v_combined := v_proof_element->>'hash' || v_current_hash;
        ELSE
            v_combined := v_current_hash || v_proof_element->>'hash';
        END IF;
        
        v_current_hash := ussd_core.generate_hash(v_combined);
    END LOOP;
    
    RETURN v_current_hash = p_merkle_root;
END;
$$;

-- ----------------------------------------------------------------------------
-- 10. ROW LEVEL SECURITY
-- ----------------------------------------------------------------------------
ALTER TABLE ussd_core.blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd_core.merkle_trees ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd_core.block_transactions ENABLE ROW LEVEL SECURITY;

CREATE POLICY blocks_read ON ussd_core.blocks FOR SELECT USING (TRUE);
CREATE POLICY merkle_read ON ussd_core.merkle_trees FOR SELECT USING (TRUE);
CREATE POLICY block_tx_read ON ussd_core.block_transactions FOR SELECT USING (TRUE);

-- ----------------------------------------------------------------------------
-- 11. VIEWS
-- ----------------------------------------------------------------------------

-- Sealed blocks ready for anchoring
CREATE VIEW ussd_core.blocks_ready_for_anchoring AS
SELECT *
FROM ussd_core.blocks
WHERE status = 'sealed'
  AND anchor_transaction_hash IS NULL
ORDER BY block_height;

-- Block statistics
CREATE VIEW ussd_core.block_statistics AS
SELECT 
    b.block_id,
    b.block_height,
    b.block_name,
    b.application_id,
    b.status,
    b.opened_at,
    b.sealed_at,
    b.anchored_at,
    b.transaction_count,
    b.merkle_root,
    b.anchor_type,
    EXTRACT(EPOCH FROM (b.sealed_at - b.opened_at)) as seal_duration_seconds,
    CASE 
        WHEN b.anchor_transaction_hash IS NOT NULL THEN TRUE
        ELSE FALSE
    END as is_anchored
FROM ussd_core.blocks b
ORDER BY b.block_height DESC;

-- ----------------------------------------------------------------------------
-- 12. INITIAL BLOCK (Genesis)
-- ----------------------------------------------------------------------------
INSERT INTO ussd_core.blocks (
    block_id,
    block_height,
    block_name,
    status,
    opened_at,
    sealed_at,
    merkle_root,
    block_hash,
    transaction_count,
    record_hash
) VALUES (
    0,  -- Special genesis block ID
    0,  -- Genesis height
    'Genesis Block',
    'sealed',
    '2024-01-01 00:00:00+00',
    '2024-01-01 00:00:00+00',
    '0000000000000000000000000000000000000000000000000000000000000000',
    ussd_core.generate_hash('GENESIS_BLOCK_USSD_KERNEL_v1.0.0'),
    0,
    ussd_core.generate_hash('GENESIS')
);

-- ----------------------------------------------------------------------------
-- 13. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_core.blocks IS 
    'Blocks aggregate transactions with Merkle tree roots for cryptographic batching';
COMMENT ON TABLE ussd_core.merkle_trees IS 
    'Complete Merkle tree structure enabling inclusion proofs';
COMMENT ON TABLE ussd_core.block_transactions IS 
    'Mapping between blocks and transactions with sequence ordering';
COMMENT ON FUNCTION ussd_core.generate_merkle_proof IS 
    'Generates a Merkle proof path for verifying transaction inclusion';
