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
-- TODO: Create blocks table
-- DESCRIPTION: Cryptographic blocks containing transactions
-- PRIORITY: CRITICAL
-- SECURITY: Immutable once sealed, signed by kernel key
-- ============================================================================
-- TODO: [BLOCK-001] Create core.blocks table
-- INSTRUCTIONS:
--   - Immutable once sealed
--   - Aggregates transactions into verifiable units
--   - Supports external blockchain anchoring
--   - RLS POLICY: Read-only after sealing
--   - ERROR HANDLING: Prevent modifications to sealed blocks
-- COMPLIANCE: ISO/IEC 27040 (Cryptographic Aggregation)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.blocks (
--       -- Identity
--       block_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       block_height        BIGINT NOT NULL UNIQUE,      -- Sequential block number
--       block_reference     VARCHAR(100) UNIQUE NOT NULL, -- Human-readable
--       
--       -- Application Scope (NULL = global block)
--       application_id      UUID REFERENCES app.applications(application_id),
--       
--       -- Block Content
--       transaction_count   INTEGER NOT NULL DEFAULT 0,
--       transaction_ids     UUID[] NOT NULL,             -- Array of tx IDs
--       
--       -- Time Range
--       opened_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
--       closed_at           TIMESTAMPTZ,                 -- When block was sealed
--       min_transaction_at  TIMESTAMPTZ,
--       max_transaction_at  TIMESTAMPTZ,
--       
--       -- Merkle Tree
--       merkle_root         BYTEA NOT NULL,              -- Root hash
--       merkle_tree_depth   INTEGER NOT NULL,            -- Tree depth
--       
--       -- Kernel Signing
--       kernel_signature    BYTEA,                       -- Signed merkle_root
--       signing_key_id      UUID REFERENCES security.signing_keys(key_id),
--       signed_at           TIMESTAMPTZ,
--       
--       -- External Anchor (Optional)
--       external_anchor_type VARCHAR(50),                -- 'ETHEREUM', 'STELLAR', etc.
--       external_anchor_tx  VARCHAR(255),                -- Blockchain transaction hash
--       anchored_at         TIMESTAMPTZ,
--       anchor_metadata     JSONB,                       -- Block number, etc.
--       
--       -- Status
--       status              VARCHAR(20) NOT NULL DEFAULT 'OPEN',
--                           -- OPEN, SEALED, ANCHORED, FINALIZED
--       
--       -- Integrity
--       previous_block_hash BYTEA NOT NULL,              -- Hash of previous block
--       block_hash          BYTEA NOT NULL,              -- Hash of this block
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id),
--       sealed_by           UUID REFERENCES core.accounts(account_id)
--   );
--
-- CONSTRAINTS:
--   - CHECK (status IN ('OPEN', 'SEALED', 'ANCHORED', 'FINALIZED'))
--   - CHECK (transaction_count = array_length(transaction_ids, 1))

-- =============================================================================
-- TODO: Create merkle_nodes table
-- DESCRIPTION: Merkle tree node storage for proof generation
-- PRIORITY: HIGH
-- SECURITY: Node hashes enable verification without full tree
-- ============================================================================
-- TODO: [BLOCK-002] Create core.merkle_nodes table
-- INSTRUCTIONS:
--   - Stores all intermediate nodes of Merkle tree
--   - Enables efficient proof generation
--   - Prunable after block is anchored (optional)
--   - ERROR HANDLING: Validate node hash on insert
-- COMPLIANCE: ISO/IEC 27040 (Tree Structure Integrity)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.merkle_nodes (
--       node_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       block_id            UUID NOT NULL REFERENCES core.blocks(block_id),
--       
--       -- Tree Position
--       level               INTEGER NOT NULL,            -- 0 = leaves, increases up
--       index_in_level      INTEGER NOT NULL,            -- Position within level
--       
--       -- Node Content
--       node_hash           BYTEA NOT NULL,              -- SHA-256 hash
--       left_child          UUID REFERENCES core.merkle_nodes(node_id),
--       right_child         UUID REFERENCES core.merkle_nodes(node_id),
--       
--       -- Leaf Reference (only for level 0)
--       transaction_id      UUID REFERENCES core.transaction_log(transaction_id),
--       
--       -- Integrity
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );
--
-- CONSTRAINTS:
--   - UNIQUE (block_id, level, index_in_level)
--   - CHECK: leaf nodes have transaction_id, internal nodes have children

-- =============================================================================
-- TODO: Create merkle_proofs table
-- DESCRIPTION: Generated inclusion proofs
-- PRIORITY: MEDIUM
-- SECURITY: Proofs enable verification without full node access
-- ============================================================================
-- TODO: [BLOCK-003] Create core.merkle_proofs table
-- INSTRUCTIONS:
--   - Stores pre-computed inclusion proofs
--   - Enables auditors to verify transaction existence
--   - Contains path from leaf to root
--   - AUDIT LOGGING: Track proof generation and verification
-- COMPLIANCE: ISO/IEC 27040 (Proof Generation)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.merkle_proofs (
--       proof_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- References
--       block_id            UUID NOT NULL REFERENCES core.blocks(block_id),
--       transaction_id      UUID NOT NULL REFERENCES core.transaction_log(transaction_id),
--       
--       -- Proof Data
--       leaf_index          INTEGER NOT NULL,            -- Position in tree
--       proof_path          BYTEA[] NOT NULL,            -- Sibling hashes
--       proof_directions    BOOLEAN[] NOT NULL,          -- true = right sibling
--       
--       -- Verification
--       verified_at         TIMESTAMPTZ,
--       verified_by         UUID REFERENCES core.accounts(account_id),
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );
--
-- CONSTRAINTS:
--   - UNIQUE (block_id, transaction_id)

-- =============================================================================
-- TODO: Create Merkle tree building function
-- DESCRIPTION: Build Merkle tree from transaction hashes
-- PRIORITY: CRITICAL
-- SECURITY: Deterministic tree construction
-- ============================================================================
-- TODO: [BLOCK-004] Create build_merkle_tree function
-- INSTRUCTIONS:
--   - Input: array of transaction hashes
--   - Output: merkle root hash
--   - Side effect: Populate merkle_nodes table
--   - ERROR HANDLING: Handle odd number of leaves (duplicate last)
--   - SEARCH PATH: Explicitly set
-- COMPLIANCE: ISO/IEC 27040 (Merkle Construction)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.build_merkle_tree(
--       p_block_id UUID,
--       p_transaction_hashes BYTEA[]
--   ) RETURNS BYTEA AS $$
--   DECLARE
--       v_level INTEGER := 0;
--       v_hashes BYTEA[];
--       v_new_hashes BYTEA[];
--       v_hash BYTEA;
--       v_left UUID;
--       v_right UUID;
--       v_node_id UUID;
--   BEGIN
--       -- Create leaf nodes (level 0)
--       FOR i IN 1..array_length(p_transaction_hashes, 1) LOOP
--           INSERT INTO core.merkle_nodes (block_id, level, index_in_level, node_hash)
--           VALUES (p_block_id, 0, i-1, p_transaction_hashes[i])
--           RETURNING node_id INTO v_node_id;
--           v_hashes := array_append(v_hashes, p_transaction_hashes[i]);
--       END LOOP;
--       
--       -- Build tree level by level
--       WHILE array_length(v_hashes, 1) > 1 LOOP
--           v_level := v_level + 1;
--           v_new_hashes := ARRAY[]::BYTEA[];
--           
--           FOR i IN 1..array_length(v_hashes, 1) BY 2 LOOP
--               -- Handle odd number of nodes
--               IF i+1 > array_length(v_hashes, 1) THEN
--                   v_hash := v_hashes[i];  -- Promote last node
--               ELSE
--                   -- Combine two child hashes
--                   v_hash := digest(v_hashes[i] || v_hashes[i+1], 'sha256');
--               END IF;
--               
--               v_new_hashes := array_append(v_new_hashes, v_hash);
--           END LOOP;
--           
--           v_hashes := v_new_hashes;
--       END LOOP;
--       
--       RETURN v_hashes[1];  -- Root hash
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create proof verification function
-- DESCRIPTION: Verify Merkle inclusion proof
-- PRIORITY: HIGH
-- SECURITY: Constant-time comparison for hash verification
-- ============================================================================
-- TODO: [BLOCK-005] Create verify_merkle_proof function
-- INSTRUCTIONS:
--   - Recompute root hash from leaf hash and proof path
--   - Compare with stored merkle_root in blocks table
--   - Return boolean verification result
--   - ERROR HANDLING: Handle invalid proof structure
-- COMPLIANCE: ISO/IEC 27040 (Proof Verification)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.verify_merkle_proof(
--       p_leaf_hash BYTEA,
--       p_proof_path BYTEA[],
--       p_directions BOOLEAN[],
--       p_expected_root BYTEA
--   ) RETURNS BOOLEAN AS $$
--   DECLARE
--       v_computed BYTEA := p_leaf_hash;
--   BEGIN
--       FOR i IN 1..array_length(p_proof_path, 1) LOOP
--           IF p_directions[i] THEN
--               -- Sibling is on the right
--               v_computed := digest(v_computed || p_proof_path[i], 'sha256');
--           ELSE
--               -- Sibling is on the left
--               v_computed := digest(p_proof_path[i] || v_computed, 'sha256');
--           END IF;
--       END LOOP;
--       
--       RETURN v_computed = p_expected_root;
--   END;
--   $$ LANGUAGE plpgsql IMMUTABLE;

-- =============================================================================
-- TODO: Create block sealing function
-- DESCRIPTION: Seal a block and compute Merkle root
-- PRIORITY: CRITICAL
-- SECURITY: Atomic seal operation prevents partial blocks
-- ============================================================================
-- TODO: [BLOCK-006] Create seal_block function
-- INSTRUCTIONS:
--   - Called when block reaches size or time threshold
--   - Build Merkle tree from transaction hashes
--   - Sign root with kernel key
--   - Update block status to SEALED
--   - TRANSACTION ISOLATION: SERIALIZABLE for atomic seal
-- COMPLIANCE: ISO/IEC 27040 (Block Sealing)

-- =============================================================================
-- TODO: Create block indexes
-- DESCRIPTION: Optimize block queries
-- PRIORITY: MEDIUM
-- SECURITY: Index on status for open block queries
-- ============================================================================
-- TODO: [BLOCK-007] Create block indexes
-- INDEX LIST:
--   - PRIMARY KEY (block_id)
--   - UNIQUE (block_height)
--   - UNIQUE (block_reference)
--   - INDEX on (application_id, block_height)
--   - INDEX on (status, created_at) WHERE status = 'OPEN'
--   - INDEX on (external_anchor_tx)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create blocks table with Merkle root and signatures
□ Create merkle_nodes table for tree storage
□ Create merkle_proofs table for inclusion proofs
□ Implement build_merkle_tree function
□ Implement verify_merkle_proof function
□ Create seal_block procedure
□ Add immutability triggers (blocks sealed = no changes)
□ Create all indexes for block queries
□ Test Merkle tree construction with sample transactions
□ Verify proof generation and verification
================================================================================
*/
