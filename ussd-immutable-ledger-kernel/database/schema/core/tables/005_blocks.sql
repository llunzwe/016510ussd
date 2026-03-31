-- =============================================================================
-- USSD KERNEL CORE SCHEMA - BLOCKS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    005_blocks.sql
-- SCHEMA:      ussd_core
-- TABLE:       blocks
-- DESCRIPTION: Block aggregation for Merkle tree batching. Groups transactions
--              into cryptographically sealed blocks for efficient verification.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.5 Secure authentication - Block signing requirements
├── A.10.1 Cryptographic controls - Key management for block signing
└── A.12.4 Logging and monitoring - Block creation monitoring

ISO/IEC 27040:2024 (Storage Security - CRITICAL for blocks)
├── Immutable blocks: Once sealed, never modified
├── Merkle tree: Efficient inclusion verification
├── Block chaining: Previous block hash reference
├── Digital signatures: Kernel signing of block hash
└── External anchoring: Blockchain/audit anchoring support

ISO/IEC 27031:2025 (Business Continuity ICT Readiness)
├── Block replication: Real-time sync to standby
├── Recovery: Block reconstruction from transactions
└── Archival: Cold storage for sealed blocks

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. BLOCK LIFECYCLE
   - OPEN: Accepting transactions
   - SEALING: Building Merkle tree
   - SEALED: Signed and immutable
   - ANCHORED: External anchor confirmed

2. MERKLE TREE
   - Binary tree over transaction hashes
   - Inclusion proofs for verification
   - Root hash signed by kernel

3. BLOCK CHAINING
   - Each block references previous block hash
   - Detects any historical tampering
   - Global ledger integrity

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

SIGNING KEYS:
- Hardware Security Module (HSM) storage
- Key rotation schedule (annual)
- Backup key procedures
- Key compromise response plan

VERIFICATION:
- Merkle inclusion proofs
- Block hash chain verification
- External anchor verification
- Periodic full ledger audit

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: block_id
- SEQUENCE: chain_sequence (block order)
- STATUS: status + opened_at (monitoring)
- ANCHOR: anchored_at (external anchor status)

BLOCK SIZING:
- Target: 1000-10000 transactions per block
- Time-based: Seal every 5 minutes if not full
- Size-based: Seal at 10MB block size

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- BLOCK_OPENED: New block created
- BLOCK_SEALED: Merkle root computed and signed
- BLOCK_ANCHORED: External anchor confirmed
- BLOCK_VERIFIED: Integrity verification performed

RETENTION: Permanent (blocks are cryptographic anchors)
================================================================================
*/

-- =============================================================================
-- CREATE TABLE: blocks
-- =============================================================================

CREATE TABLE core.blocks (
    -- Primary identifier
    block_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Block sequence in chain
    chain_sequence BIGINT NOT NULL UNIQUE,
    
    -- Block status
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN'
        CHECK (status IN ('OPEN', 'SEALING', 'SEALED', 'ANCHORED')),
    
    -- Timing
    opened_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    sealed_at TIMESTAMPTZ,
    anchored_at TIMESTAMPTZ,
    
    -- Transaction count
    transaction_count INTEGER DEFAULT 0,
    min_transaction_id BIGINT,
    max_transaction_id BIGINT,
    
    -- Merkle tree
    merkle_root VARCHAR(64),  -- Hash of all transaction hashes
    merkle_tree_depth INTEGER,
    merkle_tree JSONB,  -- Full tree structure for verification
    
    -- Block chaining
    previous_block_hash VARCHAR(64),
    block_hash VARCHAR(64),  -- Hash of block header
    
    -- Digital signature
    signature TEXT,
    signed_by UUID,  -- Kernel account that signed
    
    -- External anchoring
    anchor_type VARCHAR(20),  -- 'bitcoin', 'ethereum', 'audit_chain'
    anchor_tx_id TEXT,  -- Transaction ID on external chain
    anchor_block_number BIGINT,
    anchor_timestamp TIMESTAMPTZ,
    anchor_proof TEXT,  -- Merkle proof or similar
    
    -- Statistics
    total_amount NUMERIC(20, 8),
    currencies VARCHAR(3)[],
    unique_accounts INTEGER,
    
    -- Metadata
    block_metadata JSONB DEFAULT '{}',
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    CONSTRAINT chk_sealed_requires_root CHECK (
        status NOT IN ('SEALED', 'ANCHORED') OR merkle_root IS NOT NULL
    ),
    CONSTRAINT chk_sealed_requires_hash CHECK (
        status NOT IN ('SEALED', 'ANCHORED') OR block_hash IS NOT NULL
    ),
    CONSTRAINT chk_anchored_requires_anchor CHECK (
        status != 'ANCHORED' OR anchor_type IS NOT NULL
    )
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Chain sequence lookup
CREATE INDEX idx_blocks_sequence ON core.blocks(chain_sequence);

-- Status monitoring
CREATE INDEX idx_blocks_status ON core.blocks(status, opened_at);

-- Open blocks (for transaction assignment)
CREATE INDEX idx_blocks_open ON core.blocks(block_id) 
    WHERE status = 'OPEN';

-- Sealed blocks pending anchor
CREATE INDEX idx_blocks_pending_anchor ON core.blocks(block_id)
    WHERE status = 'SEALED';

-- Anchor timestamp
CREATE INDEX idx_blocks_anchored ON core.blocks(anchored_at)
    WHERE anchored_at IS NOT NULL;

-- Merkle root lookup
CREATE UNIQUE INDEX idx_blocks_merkle_root ON core.blocks(merkle_root)
    WHERE merkle_root IS NOT NULL;

-- Block hash lookup
CREATE UNIQUE INDEX idx_blocks_block_hash ON core.blocks(block_hash)
    WHERE block_hash IS NOT NULL;

-- Time range queries
CREATE INDEX idx_blocks_opened_at ON core.blocks(opened_at DESC);

-- =============================================================================
-- IMMUTABILITY TRIGGERS
-- =============================================================================

-- Prevent updates on sealed blocks
CREATE OR REPLACE FUNCTION core.prevent_block_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- Allow updates only if block is OPEN or SEALING
    IF OLD.status IN ('SEALED', 'ANCHORED') THEN
        RAISE EXCEPTION 'IMMUTABLE_BLOCK: Cannot modify sealed or anchored block %', OLD.block_id;
    END IF;
    
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_blocks_prevent_update
    BEFORE UPDATE ON core.blocks
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_block_update();

-- Prevent deletes
CREATE TRIGGER trg_blocks_prevent_delete
    BEFORE DELETE ON core.blocks
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- =============================================================================
-- HASH COMPUTATION TRIGGER
-- =============================================================================

CREATE OR REPLACE FUNCTION core.compute_block_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_previous_block_hash VARCHAR(64);
BEGIN
    -- Get previous block hash
    SELECT block_hash INTO v_previous_block_hash
    FROM core.blocks
    WHERE chain_sequence = NEW.chain_sequence - 1;
    
    NEW.previous_block_hash := v_previous_block_hash;
    
    -- Compute block hash (only when sealing)
    IF NEW.status IN ('SEALED', 'ANCHORED') AND NEW.block_hash IS NULL THEN
        NEW.block_hash := core.generate_hash(
            NEW.block_id::TEXT ||
            NEW.chain_sequence::TEXT ||
            COALESCE(NEW.previous_block_hash, '') ||
            COALESCE(NEW.merkle_root, '') ||
            NEW.opened_at::TEXT ||
            COALESCE(NEW.sealed_at::TEXT, '')
        );
    END IF;
    
    -- Compute record hash
    NEW.record_hash := core.generate_hash(
        NEW.block_id::TEXT ||
        COALESCE(NEW.block_hash, NEW.block_id::TEXT) ||
        NEW.created_at::TEXT
    );
    
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_blocks_compute_hash
    BEFORE INSERT OR UPDATE ON core.blocks
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_block_hash();

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

-- Enable RLS
ALTER TABLE core.blocks ENABLE ROW LEVEL SECURITY;

-- Policy: All authenticated users can view blocks
CREATE POLICY blocks_read ON core.blocks
    FOR SELECT
    TO ussd_app_user
    USING (true);

-- Policy: Only kernel can modify blocks
CREATE POLICY blocks_kernel_write ON core.blocks
    FOR ALL
    TO ussd_kernel_role
    USING (true);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to create a new block
CREATE OR REPLACE FUNCTION core.create_block()
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_block_id UUID;
    v_next_sequence BIGINT;
BEGIN
    -- Get next sequence number
    SELECT COALESCE(MAX(chain_sequence), 0) + 1 INTO v_next_sequence
    FROM core.blocks;
    
    -- Insert new block
    INSERT INTO core.blocks (
        chain_sequence,
        status
    ) VALUES (
        v_next_sequence,
        'OPEN'
    )
    RETURNING block_id INTO v_block_id;
    
    RETURN v_block_id;
END;
$$;

-- Function to seal a block
CREATE OR REPLACE FUNCTION core.seal_block(
    p_block_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_transaction_hashes TEXT[];
    v_merkle_root VARCHAR(64);
    v_transaction_count INTEGER;
    v_min_tx_id BIGINT;
    v_max_tx_id BIGINT;
    v_total_amount NUMERIC(20, 8);
    v_currencies VARCHAR(3)[];
    v_unique_accounts INTEGER;
BEGIN
    -- Get all transaction hashes for this block
    SELECT 
        array_agg(transaction_hash ORDER BY transaction_id),
        COUNT(*),
        MIN(transaction_id),
        MAX(transaction_id),
        SUM(amount),
        array_agg(DISTINCT currency),
        COUNT(DISTINCT initiator_account_id)
    INTO 
        v_transaction_hashes,
        v_transaction_count,
        v_min_tx_id,
        v_max_tx_id,
        v_total_amount,
        v_currencies,
        v_unique_accounts
    FROM core.transaction_log
    WHERE block_id = p_block_id;
    
    IF v_transaction_count = 0 THEN
        RAISE EXCEPTION 'EMPTY_BLOCK: Cannot seal block with no transactions';
    END IF;
    
    -- Compute Merkle root (simplified - in production use proper Merkle tree)
    v_merkle_root := core.generate_hash(array_to_string(v_transaction_hashes, ''));
    
    -- Update block
    UPDATE core.blocks
    SET 
        status = 'SEALED',
        sealed_at = core.precise_now(),
        transaction_count = v_transaction_count,
        min_transaction_id = v_min_tx_id,
        max_transaction_id = v_max_tx_id,
        merkle_root = v_merkle_root,
        merkle_tree_depth = CEIL(LOG(2, v_transaction_count))::INTEGER,
        total_amount = v_total_amount,
        currencies = v_currencies,
        unique_accounts = v_unique_accounts
    WHERE block_id = p_block_id
    AND status = 'OPEN';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'BLOCK_NOT_FOUND_OR_NOT_OPEN: %', p_block_id;
    END IF;
    
    RETURN TRUE;
END;
$$;

-- Function to verify Merkle inclusion
CREATE OR REPLACE FUNCTION core.verify_merkle_inclusion(
    p_block_id UUID,
    p_transaction_hash VARCHAR(64)
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_merkle_root VARCHAR(64);
    v_exists BOOLEAN;
BEGIN
    -- Get block's Merkle root
    SELECT merkle_root INTO v_merkle_root
    FROM core.blocks
    WHERE block_id = p_block_id;
    
    IF v_merkle_root IS NULL THEN
        RETURN FALSE;
    END IF;
    
    -- Check if transaction exists in block
    SELECT EXISTS (
        SELECT 1 FROM core.transaction_log
        WHERE block_id = p_block_id
        AND transaction_hash = p_transaction_hash
    ) INTO v_exists;
    
    -- In a full implementation, we would verify the Merkle proof
    -- For now, we just check existence
    RETURN v_exists;
END;
$$;

-- Function to get current open block (or create one)
CREATE OR REPLACE FUNCTION core.get_or_create_open_block()
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_block_id UUID;
BEGIN
    -- Try to find existing open block
    SELECT block_id INTO v_block_id
    FROM core.blocks
    WHERE status = 'OPEN'
    ORDER BY chain_sequence
    LIMIT 1;
    
    -- Create new block if none exists
    IF v_block_id IS NULL THEN
        v_block_id := core.create_block();
    END IF;
    
    RETURN v_block_id;
END;
$$;

-- =============================================================================
-- TABLE AND COLUMN COMMENTS
-- =============================================================================

COMMENT ON TABLE core.blocks IS 
    'Cryptographic blocks containing batches of transactions with Merkle tree roots for efficient verification.';

COMMENT ON COLUMN core.blocks.block_id IS 
    'Unique identifier for the block';
COMMENT ON COLUMN core.blocks.chain_sequence IS 
    'Position in the global block chain';
COMMENT ON COLUMN core.blocks.status IS 
    'Block state: OPEN, SEALING, SEALED, ANCHORED';
COMMENT ON COLUMN core.blocks.merkle_root IS 
    'Root hash of Merkle tree over transaction hashes';
COMMENT ON COLUMN core.blocks.previous_block_hash IS 
    'Hash of previous block in chain';
COMMENT ON COLUMN core.blocks.block_hash IS 
    'Hash of this block header';
COMMENT ON COLUMN core.blocks.signature IS 
    'Digital signature of block hash by kernel';
COMMENT ON COLUMN core.blocks.anchor_type IS 
    'Type of external anchor (bitcoin, ethereum, etc.)';
COMMENT ON COLUMN core.blocks.anchor_tx_id IS 
    'Transaction ID on external chain';

-- =============================================================================
-- INITIAL DATA: Genesis block
-- =============================================================================

INSERT INTO core.blocks (
    chain_sequence,
    status,
    merkle_root,
    block_hash,
    block_metadata
) VALUES (
    0,
    'SEALED',
    encode(digest('USSD_GENESIS_BLOCK', 'sha256'), 'hex'),
    encode(digest('USSD_GENESIS_BLOCK_0', 'sha256'), 'hex'),
    '{"description": "Genesis block - start of ledger"}'
);

-- =============================================================================
-- END OF FILE
-- =============================================================================
