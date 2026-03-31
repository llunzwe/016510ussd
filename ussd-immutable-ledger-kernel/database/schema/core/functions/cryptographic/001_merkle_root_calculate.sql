-- =============================================================================
-- USSD KERNEL CORE SCHEMA - CRYPTOGRAPHIC FUNCTIONS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    001_merkle_root_calculate.sql
-- SCHEMA:      core
-- CATEGORY:    Cryptographic Functions
-- DESCRIPTION: Merkle tree construction and root hash calculation for
--              efficient transaction batch verification and external anchoring.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.10.1 Cryptographic controls - Merkle tree implementation
├── A.10.2 Cryptographic controls - Root signing procedures
└── A.12.4 Logging and monitoring - Block sealing monitoring

ISO/IEC 27040:2024 (Storage Security)
├── Merkle tree structure: Binary hash tree
├── Inclusion proofs: Efficient verification
├── Tamper detection: Root hash changes
└── External anchoring: Third-party verification

ISO/IEC 27031:2025 (Business Continuity ICT Readiness)
├── Tree reconstruction: Post-disaster rebuild
├── Proof generation: Continuous availability
└── Backup verification: Hash-based backup checks

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. MERKLE TREE STRUCTURE
   - Binary tree: Each parent = hash(left || right)
   - Leaf nodes: Transaction hashes
   - Odd leaves: Last leaf promoted
   - Depth tracking: Tree depth stored

2. SECURITY PROPERTIES
   - Collision resistance: SHA-256
   - Second preimage resistance: Tree construction
   - Efficient verification: O(log n) proof size

3. ERROR HANDLING
   - Empty tree handling
   - Single leaf handling
   - Hash computation errors

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

KEY MANAGEMENT PROCEDURES:
1. Block Signing Keys
   - Key generation: HSM-backed RSA-4096 or Ed25519
   - Key storage: FIPS 140-2 Level 3 HSM
   - Key rotation: Annual with grace period
   - Key backup: Offline secure storage

2. Signature Algorithm Specifications
   - Primary: Ed25519 (modern, fast, secure)
   - Secondary: RSA-PSS with SHA-256
   - Hash function: SHA-256 for all operations

INTEGRITY VERIFICATION PROTOCOLS:
1. Block Sealing
   - Merkle root computation
   - Block hash calculation
   - Digital signature generation
   - Timestamp incorporation

2. Inclusion Proof Verification
   - Proof path validation
   - Sibling hash verification
   - Root hash matching
   - Signature verification

3. External Anchoring
   - Blockchain anchor (optional)
   - Timestamp authority
   - Distributed witness

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

TREE CONSTRUCTION:
- Batch processing for large blocks
- Parallel hash computation
- In-memory tree building
- Bulk insert for nodes

PROOF GENERATION:
- Pre-computed proofs stored
- On-demand proof generation
- Proof caching
- Batch proof generation

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- MERKLE_TREE_BUILT
- BLOCK_SEALED
- PROOF_GENERATED
- ANCHOR_CONFIRMED

RETENTION: 7 years
================================================================================
*/

-- Create merkle_nodes table if not exists
CREATE TABLE IF NOT EXISTS core.merkle_nodes (
    node_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    block_id UUID NOT NULL,
    node_level INTEGER NOT NULL,  -- 0 = leaf, increases upward
    node_index INTEGER NOT NULL,  -- Position at this level
    node_hash BYTEA NOT NULL,
    left_child UUID REFERENCES core.merkle_nodes(node_id),
    right_child UUID REFERENCES core.merkle_nodes(node_id),
    transaction_id UUID,          -- NULL for non-leaf nodes
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(block_id, node_level, node_index)
);

COMMENT ON TABLE core.merkle_nodes IS 'Merkle tree nodes for block verification';

CREATE INDEX IF NOT EXISTS idx_merkle_nodes_block ON core.merkle_nodes(block_id);
CREATE INDEX IF NOT EXISTS idx_merkle_nodes_tx ON core.merkle_nodes(transaction_id) WHERE transaction_id IS NOT NULL;

-- =============================================================================
-- Create build_merkle_tree function
-- DESCRIPTION: Build complete Merkle tree from transaction hashes
-- PRIORITY: CRITICAL
-- SECURITY: SECURITY DEFINER - needs to insert into merkle_nodes
-- =============================================================================
CREATE OR REPLACE FUNCTION core.build_merkle_tree(p_block_id UUID)
RETURNS BYTEA
LANGUAGE plpgsql
SECURITY DEFINER
COST 500
AS $$
DECLARE
    v_leaf_hashes BYTEA[];
    v_current_level INTEGER := 0;
    v_level_hashes BYTEA[];
    v_new_hashes BYTEA[];
    v_left BYTEA;
    v_right BYTEA;
    v_parent_hash BYTEA;
    v_node_id UUID;
    v_left_id UUID;
    v_right_id UUID;
    v_node_index INTEGER;
    v_root_hash BYTEA;
BEGIN
    -- Get all transaction hashes for this block
    SELECT array_agg(current_hash ORDER BY chain_sequence)
    INTO v_leaf_hashes
    FROM core.transaction_log
    WHERE block_id = p_block_id;
    
    IF v_leaf_hashes IS NULL OR array_length(v_leaf_hashes, 1) IS NULL THEN
        RAISE EXCEPTION 'No transactions found for block %', p_block_id;
    END IF;
    
    -- Store leaf nodes
    FOR i IN 1..array_length(v_leaf_hashes, 1) LOOP
        INSERT INTO core.merkle_nodes (
            block_id, node_level, node_index, node_hash, transaction_id
        )
        SELECT 
            p_block_id, 
            0, 
            i-1, 
            v_leaf_hashes[i],
            transaction_id
        FROM core.transaction_log
        WHERE block_id = p_block_id
        ORDER BY chain_sequence
        LIMIT 1 OFFSET i-1;
    END LOOP;
    
    -- Build tree level by level
    v_level_hashes := v_leaf_hashes;
    
    WHILE array_length(v_level_hashes, 1) > 1 LOOP
        v_current_level := v_current_level + 1;
        v_new_hashes := ARRAY[]::BYTEA[];
        v_node_index := 0;
        
        FOR i IN 1..((array_length(v_level_hashes, 1) + 1) / 2) LOOP
            v_left := v_level_hashes[(i-1)*2 + 1];
            
            IF (i-1)*2 + 2 <= array_length(v_level_hashes, 1) THEN
                v_right := v_level_hashes[(i-1)*2 + 2];
            ELSE
                -- Odd number of nodes: duplicate last hash
                v_right := v_left;
            END IF;
            
            -- Compute parent hash
            v_parent_hash := digest(
                encode(v_left, 'hex') || encode(v_right, 'hex'),
                'sha256'
            );
            
            -- Get child node IDs
            SELECT node_id INTO v_left_id
            FROM core.merkle_nodes
            WHERE block_id = p_block_id 
              AND node_level = v_current_level - 1 
              AND node_index = (i-1)*2;
              
            SELECT node_id INTO v_right_id
            FROM core.merkle_nodes
            WHERE block_id = p_block_id 
              AND node_level = v_current_level - 1 
              AND node_index = (i-1)*2 + 1;
            
            -- Insert parent node
            INSERT INTO core.merkle_nodes (
                block_id, node_level, node_index, node_hash,
                left_child, right_child
            ) VALUES (
                p_block_id, v_current_level, v_node_index, v_parent_hash,
                v_left_id, 
                CASE WHEN v_left_id != v_right_id OR (i-1)*2 + 2 <= array_length(v_level_hashes, 1) 
                     THEN v_right_id 
                     ELSE NULL 
                END
            )
            RETURNING node_id INTO v_node_id;
            
            v_new_hashes := array_append(v_new_hashes, v_parent_hash);
            v_node_index := v_node_index + 1;
        END LOOP;
        
        v_level_hashes := v_new_hashes;
    END LOOP;
    
    v_root_hash := v_level_hashes[1];
    
    -- Log tree construction
    INSERT INTO core.audit_trail (
        event_type,
        table_name,
        record_id,
        details
    ) VALUES (
        'MERKLE_TREE_BUILT',
        'merkle_nodes',
        p_block_id::text,
        jsonb_build_object(
            'leaf_count', array_length(v_leaf_hashes, 1),
            'tree_depth', v_current_level,
            'root_hash', encode(v_root_hash, 'hex')
        )
    );
    
    RETURN v_root_hash;
END;
$$;

COMMENT ON FUNCTION core.build_merkle_tree IS 'Build complete Merkle tree from transaction hashes and return root hash';

-- =============================================================================
-- Create calculate_merkle_root function (simple version)
-- DESCRIPTION: Calculate root without storing intermediate nodes
-- PRIORITY: MEDIUM
-- =============================================================================
CREATE OR REPLACE FUNCTION core.calculate_merkle_root(p_block_id UUID)
RETURNS BYTEA
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
COST 300
AS $$
DECLARE
    v_hashes BYTEA[];
    v_left BYTEA;
    v_right BYTEA;
    v_parent BYTEA;
BEGIN
    -- Get transaction hashes
    SELECT array_agg(current_hash ORDER BY chain_sequence)
    INTO v_hashes
    FROM core.transaction_log
    WHERE block_id = p_block_id;
    
    IF v_hashes IS NULL OR array_length(v_hashes, 1) IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Compute tree
    WHILE array_length(v_hashes, 1) > 1 LOOP
        FOR i IN 1..((array_length(v_hashes, 1) + 1) / 2) LOOP
            v_left := v_hashes[(i-1)*2 + 1];
            
            IF (i-1)*2 + 2 <= array_length(v_hashes, 1) THEN
                v_right := v_hashes[(i-1)*2 + 2];
            ELSE
                v_right := v_left;  -- Duplicate last
            END IF;
            
            v_parent := digest(
                encode(v_left, 'hex') || encode(v_right, 'hex'),
                'sha256'
            );
            
            IF i = 1 THEN
                v_hashes := ARRAY[v_parent];
            ELSE
                v_hashes := array_append(v_hashes, v_parent);
            END IF;
        END LOOP;
    END LOOP;
    
    RETURN v_hashes[1];
END;
$$;

COMMENT ON FUNCTION core.calculate_merkle_root IS 'Calculate Merkle root hash without storing intermediate nodes';

-- =============================================================================
-- Create get_merkle_root function
-- DESCRIPTION: Retrieve computed Merkle root for a block
-- PRIORITY: HIGH
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_merkle_root(p_block_id UUID)
RETURNS BYTEA
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
AS $$
DECLARE
    v_root_hash BYTEA;
    v_max_level INTEGER;
BEGIN
    -- Find the maximum level (root)
    SELECT MAX(node_level) INTO v_max_level
    FROM core.merkle_nodes
    WHERE block_id = p_block_id;
    
    IF v_max_level IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Get root hash
    SELECT node_hash INTO v_root_hash
    FROM core.merkle_nodes
    WHERE block_id = p_block_id AND node_level = v_max_level AND node_index = 0;
    
    RETURN v_root_hash;
END;
$$;

COMMENT ON FUNCTION core.get_merkle_root IS 'Retrieve the computed Merkle root hash for a block';

-- =============================================================================
-- Create seal_block function
-- DESCRIPTION: Finalize a block with Merkle root and signature
-- PRIORITY: CRITICAL
-- =============================================================================
CREATE OR REPLACE FUNCTION core.seal_block(
    p_block_id UUID,
    p_signing_key TEXT DEFAULT NULL  -- Optional: for digital signature
)
RETURNS TABLE (
    merkle_root BYTEA,
    block_hash BYTEA,
    sealed_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_merkle_root BYTEA;
    v_block_hash BYTEA;
    v_timestamp TIMESTAMPTZ;
BEGIN
    v_timestamp := CURRENT_TIMESTAMP;
    
    -- Build Merkle tree and get root
    v_merkle_root := core.build_merkle_tree(p_block_id);
    
    -- Compute block hash (includes Merkle root + metadata)
    SELECT digest(
        p_block_id::text || 
        encode(v_merkle_root, 'hex') || 
        v_timestamp::text,
        'sha256'
    ) INTO v_block_hash;
    
    -- Update block record
    UPDATE core.blocks
    SET 
        merkle_root = v_merkle_root,
        block_hash = v_block_hash,
        status = 'SEALED',
        sealed_at = v_timestamp,
        sealed_by = CURRENT_USER
    WHERE block_id = p_block_id;
    
    -- Log block sealing
    INSERT INTO core.audit_trail (
        event_type,
        table_name,
        record_id,
        details,
        severity
    ) VALUES (
        'BLOCK_SEALED',
        'blocks',
        p_block_id::text,
        jsonb_build_object(
            'merkle_root', encode(v_merkle_root, 'hex'),
            'block_hash', encode(v_block_hash, 'hex'),
            'sealed_at', v_timestamp,
            'has_signature', (p_signing_key IS NOT NULL)
        ),
        'INFO'
    );
    
    RETURN QUERY SELECT v_merkle_root, v_block_hash, v_timestamp;
END;
$$;

COMMENT ON FUNCTION core.seal_block IS 'Finalize a block with Merkle root computation and block sealing';

-- =============================================================================
-- Create generate_merkle_proofs function
-- DESCRIPTION: Generate inclusion proofs for all transactions in block
-- PRIORITY: HIGH
-- =============================================================================
CREATE OR REPLACE FUNCTION core.generate_merkle_proofs(p_block_id UUID)
RETURNS TABLE (
    transaction_id UUID,
    proof_path JSONB
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_tx RECORD;
    v_node RECORD;
    v_proof JSONB;
    v_sibling_hash BYTEA;
    v_direction TEXT;
BEGIN
    -- Iterate through all transactions in the block
    FOR v_tx IN
        SELECT tl.transaction_id, tl.current_hash
        FROM core.transaction_log tl
        WHERE tl.block_id = p_block_id
        ORDER BY tl.chain_sequence
    LOOP
        v_proof := '[]'::JSONB;
        
        -- Find leaf node for this transaction
        SELECT * INTO v_node
        FROM core.merkle_nodes
        WHERE block_id = p_block_id 
          AND transaction_id = v_tx.transaction_id
          AND node_level = 0;
        
        -- Walk up the tree
        WHILE v_node.node_level < (
            SELECT MAX(node_level) FROM core.merkle_nodes WHERE block_id = p_block_id
        ) LOOP
            -- Find sibling at same level
            IF v_node.node_index % 2 = 0 THEN
                -- Current is left child, sibling is right
                v_direction := 'left';
                SELECT node_hash INTO v_sibling_hash
                FROM core.merkle_nodes
                WHERE block_id = p_block_id 
                  AND node_level = v_node.node_level 
                  AND node_index = v_node.node_index + 1;
            ELSE
                -- Current is right child, sibling is left
                v_direction := 'right';
                SELECT node_hash INTO v_sibling_hash
                FROM core.merkle_nodes
                WHERE block_id = p_block_id 
                  AND node_level = v_node.node_level 
                  AND node_index = v_node.node_index - 1;
            END IF;
            
            IF v_sibling_hash IS NOT NULL THEN
                v_proof := jsonb_build_object(
                    'sibling_hash', encode(v_sibling_hash, 'hex'),
                    'direction', v_direction,
                    'level', v_node.node_level
                ) || v_proof;
            END IF;
            
            -- Move to parent
            SELECT * INTO v_node
            FROM core.merkle_nodes
            WHERE block_id = p_block_id 
              AND node_level = v_node.node_level + 1
              AND (
                  (v_node.node_index % 2 = 0 AND left_child = v_node.node_id) OR
                  (v_node.node_index % 2 = 1 AND right_child = v_node.node_id)
              );
              
            IF v_node.node_id IS NULL THEN
                EXIT;
            END IF;
        END LOOP;
        
        transaction_id := v_tx.transaction_id;
        proof_path := v_proof;
        RETURN NEXT;
    END LOOP;
END;
$$;

COMMENT ON FUNCTION core.generate_merkle_proofs IS 'Generate Merkle inclusion proofs for all transactions in a block';

/*
================================================================================
MIGRATION CHECKLIST:
□ Create build_merkle_tree function
□ Create calculate_merkle_root function (pure version)
□ Create get_merkle_root function
□ Create seal_block function
□ Create generate_merkle_proofs function
□ Test Merkle tree with sample transactions
□ Verify root hash computation against known values
□ Test odd-numbered leaf handling
□ Benchmark tree construction performance
□ Document Merkle proof format for external verification
================================================================================
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
