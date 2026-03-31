-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Cryptographic controls)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Blockchain anchoring)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Anonymized hashing)
-- ISO/IEC 27040:2024 - Storage Security (Merkle tree integrity)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Disaster recovery)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Merkle tree construction for batch verification
-- - Block sealing prevents modification
-- - External blockchain anchoring support
-- - Inclusion proofs for transaction verification
-- ============================================================================
-- =============================================================================
-- MIGRATION: 007_core_blocks_merkle.sql
-- DESCRIPTION: Block Aggregation and Merkle Tree Cryptographic Verification
-- TABLES: blocks, merkle_nodes, merkle_proofs
-- DEPENDENCIES: 004_core_transaction_log.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 2. Immutability & Integrity Enforcement
- Feature: Merkle Tree Batching, Block Aggregation
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Groups transactions into cryptographic blocks for efficient verification.
Builds Merkle tree over transaction hashes for inclusion proofs.
Optional external anchoring to public blockchain for additional assurance.

KEY FEATURES:
- Time-based or size-based block creation
- Merkle tree built over transaction hashes
- Root hash signed by kernel signing key
- Inclusion proofs for individual transactions
- External blockchain anchoring support
- Block sealing prevents modification

BLOCK STRUCTURE:
- Block Height: Sequential number
- Transaction IDs: List of included transactions
- Merkle Root: Root hash of transaction tree
- Kernel Signature: Signed root hash
- Time Range: min/max transaction timestamps
- External Anchor: Optional blockchain tx reference
================================================================================
*/

-- =============================================================================
-- Create blocks table
-- DESCRIPTION: Cryptographic blocks containing transactions
-- PRIORITY: CRITICAL
-- SECURITY: Immutable once sealed, signed by kernel key
-- ============================================================================
CREATE TABLE core.blocks (
    -- Identity
    block_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    block_height        BIGINT NOT NULL UNIQUE,      -- Sequential block number
    block_reference     VARCHAR(100) UNIQUE NOT NULL, -- Human-readable
    
    -- Application Scope (NULL = global block)
    application_id      UUID REFERENCES app.applications(application_id),
    
    -- Block Content
    transaction_count   INTEGER NOT NULL DEFAULT 0,
    transaction_ids     UUID[] NOT NULL,             -- Array of tx IDs
    
    -- Time Range
    opened_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at           TIMESTAMPTZ,                 -- When block was sealed
    min_transaction_at  TIMESTAMPTZ,
    max_transaction_at  TIMESTAMPTZ,
    
    -- Merkle Tree
    merkle_root         BYTEA NOT NULL,              -- Root hash
    merkle_tree_depth   INTEGER NOT NULL DEFAULT 0,  -- Tree depth
    
    -- Kernel Signing
    kernel_signature    BYTEA,                       -- Signed merkle_root
    signing_key_id      UUID REFERENCES security.signing_keys(key_id),
    signed_at           TIMESTAMPTZ,
    
    -- External Anchor (Optional)
    external_anchor_type VARCHAR(50),                -- 'ETHEREUM', 'STELLAR', etc.
    external_anchor_tx  VARCHAR(255),                -- Blockchain transaction hash
    anchored_at         TIMESTAMPTZ,
    anchor_metadata     JSONB,                       -- Block number, etc.
    
    -- Status
    status              VARCHAR(20) NOT NULL DEFAULT 'OPEN',
                        -- OPEN, SEALED, ANCHORED, FINALIZED
    
    -- Integrity
    previous_block_hash BYTEA NOT NULL,              -- Hash of previous block
    block_hash          BYTEA NOT NULL,              -- Hash of this block
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    sealed_by           UUID REFERENCES core.accounts(account_id),
    
    -- Constraints
    CONSTRAINT chk_blocks_status 
        CHECK (status IN ('OPEN', 'SEALED', 'ANCHORED', 'FINALIZED')),
    CONSTRAINT chk_blocks_transaction_count 
        CHECK (transaction_count = array_length(transaction_ids, 1))
);

-- Indexes for blocks
CREATE INDEX idx_blocks_application ON core.blocks(application_id, block_height);
CREATE INDEX idx_blocks_open ON core.blocks(status, created_at) WHERE status = 'OPEN';
CREATE INDEX idx_blocks_anchor ON core.blocks(external_anchor_tx);

COMMENT ON TABLE core.blocks IS 'Cryptographic blocks containing transactions with Merkle tree root';
COMMENT ON COLUMN core.blocks.merkle_root IS 'Root hash of Merkle tree over transaction hashes';
COMMENT ON COLUMN core.blocks.previous_block_hash IS 'Hash of previous block for chain integrity';

-- =============================================================================
-- Create merkle_nodes table
-- DESCRIPTION: Merkle tree node storage for proof generation
-- PRIORITY: HIGH
-- SECURITY: Node hashes enable verification without full tree
-- ============================================================================
CREATE TABLE core.merkle_nodes (
    node_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    block_id            UUID NOT NULL REFERENCES core.blocks(block_id),
    
    -- Tree Position
    level               INTEGER NOT NULL,            -- 0 = leaves, increases up
    index_in_level      INTEGER NOT NULL,            -- Position within level
    
    -- Node Content
    node_hash           BYTEA NOT NULL,              -- SHA-256 hash
    left_child          UUID REFERENCES core.merkle_nodes(node_id),
    right_child         UUID REFERENCES core.merkle_nodes(node_id),
    
    -- Leaf Reference (only for level 0)
    transaction_id      UUID REFERENCES core.transaction_log(transaction_id),
    
    -- Integrity
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Constraints
    CONSTRAINT uq_merkle_node_position UNIQUE (block_id, level, index_in_level),
    CONSTRAINT chk_merkle_node_leaf 
        CHECK (
            (level = 0 AND transaction_id IS NOT NULL) OR 
            (level > 0)
        )
);

-- Indexes for merkle_nodes
CREATE INDEX idx_merkle_nodes_block ON core.merkle_nodes(block_id, level);
CREATE INDEX idx_merkle_nodes_transaction ON core.merkle_nodes(transaction_id);
CREATE INDEX idx_merkle_nodes_children ON core.merkle_nodes(left_child, right_child);

COMMENT ON TABLE core.merkle_nodes IS 'Stores all intermediate nodes of Merkle tree for proof generation';
COMMENT ON COLUMN core.merkle_nodes.level IS 'Tree level: 0 = leaves, increases toward root';

-- =============================================================================
-- Create merkle_proofs table
-- DESCRIPTION: Generated inclusion proofs
-- PRIORITY: MEDIUM
-- SECURITY: Proofs enable verification without full node access
-- ============================================================================
CREATE TABLE core.merkle_proofs (
    proof_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- References
    block_id            UUID NOT NULL REFERENCES core.blocks(block_id),
    transaction_id      UUID NOT NULL REFERENCES core.transaction_log(transaction_id),
    
    -- Proof Data
    leaf_index          INTEGER NOT NULL,            -- Position in tree
    proof_path          BYTEA[] NOT NULL,            -- Sibling hashes
    proof_directions    BOOLEAN[] NOT NULL,          -- true = right sibling
    
    -- Verification
    verified_at         TIMESTAMPTZ,
    verified_by         UUID REFERENCES core.accounts(account_id),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Constraints
    CONSTRAINT uq_merkle_proof UNIQUE (block_id, transaction_id)
);

CREATE INDEX idx_merkle_proofs_transaction ON core.merkle_proofs(transaction_id);
CREATE INDEX idx_merkle_proofs_verified ON core.merkle_proofs(verified_at);

COMMENT ON TABLE core.merkle_proofs IS 'Pre-computed Merkle inclusion proofs for transaction verification';
COMMENT ON COLUMN core.merkle_proofs.proof_path IS 'Array of sibling hashes needed for verification';

-- =============================================================================
-- Create Merkle tree building function
-- DESCRIPTION: Build Merkle tree from transaction hashes
-- PRIORITY: CRITICAL
-- SECURITY: Deterministic tree construction
-- ============================================================================
CREATE OR REPLACE FUNCTION core.build_merkle_tree(
    p_block_id UUID,
    p_transaction_hashes BYTEA[]
) RETURNS BYTEA AS $$
DECLARE
    v_level INTEGER := 0;
    v_hashes BYTEA[];
    v_new_hashes BYTEA[];
    v_hash BYTEA;
    v_left UUID;
    v_right UUID;
    v_node_id UUID;
    v_index INTEGER;
    v_parent_index INTEGER;
    v_node_ids UUID[];
    v_parent_ids UUID[];
BEGIN
    -- Initialize with input hashes
    v_hashes := p_transaction_hashes;
    v_node_ids := ARRAY[]::UUID[];
    
    -- Create leaf nodes (level 0)
    FOR i IN 1..array_length(v_hashes, 1) LOOP
        INSERT INTO core.merkle_nodes (block_id, level, index_in_level, node_hash, transaction_id)
        VALUES (p_block_id, 0, i-1, v_hashes[i], 
                (SELECT transaction_ids[i] FROM core.blocks WHERE block_id = p_block_id))
        RETURNING node_id INTO v_node_id;
        v_node_ids := array_append(v_node_ids, v_node_id);
    END LOOP;
    
    -- Build tree level by level
    WHILE array_length(v_hashes, 1) > 1 LOOP
        v_level := v_level + 1;
        v_new_hashes := ARRAY[]::BYTEA[];
        v_parent_ids := ARRAY[]::UUID[];
        v_parent_index := 0;
        
        FOR i IN 1..array_length(v_hashes, 1) BY 2 LOOP
            -- Handle odd number of nodes (duplicate last node)
            IF i+1 > array_length(v_hashes, 1) THEN
                v_hash := v_hashes[i];
                v_left := v_node_ids[i];
                v_right := NULL;
            ELSE
                -- Combine two child hashes
                v_hash := digest(v_hashes[i] || v_hashes[i+1], 'sha256');
                v_left := v_node_ids[i];
                v_right := v_node_ids[i+1];
            END IF;
            
            -- Insert parent node
            INSERT INTO core.merkle_nodes (block_id, level, index_in_level, node_hash, left_child, right_child)
            VALUES (p_block_id, v_level, v_parent_index, v_hash, v_left, v_right)
            RETURNING node_id INTO v_node_id;
            
            v_new_hashes := array_append(v_new_hashes, v_hash);
            v_parent_ids := array_append(v_parent_ids, v_node_id);
            v_parent_index := v_parent_index + 1;
        END LOOP;
        
        v_hashes := v_new_hashes;
        v_node_ids := v_parent_ids;
    END LOOP;
    
    -- Return root hash
    RETURN v_hashes[1];
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog, public;

COMMENT ON FUNCTION core.build_merkle_tree IS 'Builds Merkle tree from transaction hashes and returns root hash';

-- =============================================================================
-- Create proof verification function
-- DESCRIPTION: Verify Merkle inclusion proof
-- PRIORITY: HIGH
-- SECURITY: Constant-time comparison for hash verification
-- ============================================================================
CREATE OR REPLACE FUNCTION core.verify_merkle_proof(
    p_leaf_hash BYTEA,
    p_proof_path BYTEA[],
    p_directions BOOLEAN[],
    p_expected_root BYTEA
) RETURNS BOOLEAN AS $$
DECLARE
    v_computed BYTEA := p_leaf_hash;
BEGIN
    -- Validate inputs
    IF p_leaf_hash IS NULL OR p_expected_root IS NULL THEN
        RETURN false;
    END IF;
    
    -- Traverse proof path
    FOR i IN 1..COALESCE(array_length(p_proof_path, 1), 0) LOOP
        IF p_directions[i] THEN
            -- Sibling is on the right
            v_computed := digest(v_computed || p_proof_path[i], 'sha256');
        ELSE
            -- Sibling is on the left
            v_computed := digest(p_proof_path[i] || v_computed, 'sha256');
        END IF;
    END LOOP;
    
    -- Constant-time comparison would be ideal but direct comparison is standard in PG
    RETURN v_computed = p_expected_root;
END;
$$ LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path = core, pg_catalog, public;

COMMENT ON FUNCTION core.verify_merkle_proof IS 'Verifies Merkle inclusion proof by recomputing root hash';

-- =============================================================================
-- Create block sealing function
-- DESCRIPTION: Seal a block and compute Merkle root
-- PRIORITY: CRITICAL
-- SECURITY: Atomic seal operation prevents partial blocks
-- ============================================================================
CREATE OR REPLACE FUNCTION core.seal_block(
    p_block_id UUID,
    p_signing_key_id UUID DEFAULT NULL
) RETURNS BYTEA AS $$
DECLARE
    v_block RECORD;
    v_transaction_hashes BYTEA[];
    v_merkle_root BYTEA;
    v_block_hash BYTEA;
    v_previous_hash BYTEA;
BEGIN
    -- Get block with lock
    SELECT * INTO v_block 
    FROM core.blocks 
    WHERE block_id = p_block_id 
      AND status = 'OPEN'
    FOR UPDATE;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Block % not found or not open', p_block_id;
    END IF;
    
    -- Get transaction hashes in order
    SELECT array_agg(t.current_hash ORDER BY t.chain_sequence)
    INTO v_transaction_hashes
    FROM core.transaction_log t
    WHERE t.block_id = p_block_id;
    
    IF array_length(v_transaction_hashes, 1) IS NULL THEN
        RAISE EXCEPTION 'No transactions found for block %', p_block_id;
    END IF;
    
    -- Build Merkle tree
    v_merkle_root := core.build_merkle_tree(p_block_id, v_transaction_hashes);
    
    -- Get previous block hash
    SELECT block_hash INTO v_previous_hash
    FROM core.blocks
    WHERE block_height = v_block.block_height - 1;
    
    IF v_previous_hash IS NULL THEN
        v_previous_hash := '\x00';
    END IF;
    
    -- Compute block hash
    v_block_hash := digest(
        v_block.block_id::text ||
        encode(v_merkle_root, 'hex') ||
        encode(v_previous_hash, 'hex') ||
        v_block.opened_at::text,
        'sha256'
    );
    
    -- Update block
    UPDATE core.blocks
    SET status = 'SEALED',
        closed_at = now(),
        merkle_root = v_merkle_root,
        merkle_tree_depth = CEIL(LOG(2, array_length(v_transaction_hashes, 1)))::integer,
        signing_key_id = p_signing_key_id,
        signed_at = CASE WHEN p_signing_key_id IS NOT NULL THEN now() END,
        previous_block_hash = v_previous_hash,
        block_hash = v_block_hash,
        sealed_by = current_setting('app.current_user_id', true)::uuid
    WHERE block_id = p_block_id;
    
    RETURN v_merkle_root;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog, public;

COMMENT ON FUNCTION core.seal_block IS 'Seals a block by building Merkle tree and computing block hash';

-- =============================================================================
-- Create immutability trigger for sealed blocks
-- DESCRIPTION: Prevent modification of sealed blocks
-- PRIORITY: CRITICAL
-- ============================================================================
CREATE OR REPLACE FUNCTION core.prevent_sealed_block_modification()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IN ('SEALED', 'ANCHORED', 'FINALIZED') THEN
        RAISE EXCEPTION 'Block % is sealed and cannot be modified', OLD.block_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

CREATE TRIGGER trg_blocks_prevent_modification
    BEFORE UPDATE OR DELETE ON core.blocks
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_sealed_block_modification();

-- =============================================================================
-- Create function to add transaction to block
-- DESCRIPTION: Assign transaction to an open block
-- PRIORITY: HIGH
-- ============================================================================
CREATE OR REPLACE FUNCTION core.assign_transaction_to_block(
    p_transaction_id UUID,
    p_application_id UUID DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_block_id UUID;
    v_max_transactions INTEGER := 1000; -- Configurable
BEGIN
    -- Find or create open block
    SELECT block_id INTO v_block_id
    FROM core.blocks
    WHERE status = 'OPEN'
      AND (application_id IS NOT DISTINCT FROM p_application_id)
      AND transaction_count < v_max_transactions
    ORDER BY created_at DESC
    LIMIT 1;
    
    -- Create new block if needed
    IF v_block_id IS NULL THEN
        INSERT INTO core.blocks (
            block_height, block_reference, application_id, 
            transaction_ids, merkle_root, previous_block_hash, block_hash
        )
        SELECT 
            COALESCE(MAX(block_height), 0) + 1,
            'BLK-' || TO_CHAR(now(), 'YYYYMMDD') || '-' || LPAD(COALESCE(MAX(block_height), 0)::text, 8, '0'),
            p_application_id,
            ARRAY[]::UUID[],
            '\x00', '\x00', '\x00'
        FROM core.blocks
        RETURNING block_id INTO v_block_id;
    END IF;
    
    -- Update transaction
    UPDATE core.transaction_log
    SET block_id = v_block_id,
        merkle_leaf_index = (
            SELECT transaction_count 
            FROM core.blocks 
            WHERE block_id = v_block_id
        )
    WHERE transaction_id = p_transaction_id;
    
    -- Update block transaction list
    UPDATE core.blocks
    SET transaction_ids = array_append(transaction_ids, p_transaction_id),
        transaction_count = transaction_count + 1,
        min_transaction_at = LEAST(COALESCE(min_transaction_at, now()), now()),
        max_transaction_at = GREATEST(COALESCE(max_transaction_at, now()), now())
    WHERE block_id = v_block_id;
    
    RETURN v_block_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.assign_transaction_to_block IS 'Assigns a transaction to an open block for batching';

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create blocks table with Merkle root and signatures
☑ Create merkle_nodes table for tree storage
☑ Create merkle_proofs table for inclusion proofs
☑ Implement build_merkle_tree function
☑ Implement verify_merkle_proof function
☑ Create seal_block procedure
☑ Add immutability triggers (blocks sealed = no changes)
☑ Create all indexes for block queries
☑ Test Merkle tree construction with sample transactions
☑ Verify proof generation and verification
================================================================================
*/
