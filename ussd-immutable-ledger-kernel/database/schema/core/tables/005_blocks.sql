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

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.blocks (
    -- Primary identifier
    block_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Block sequence in chain
    chain_sequence BIGINT NOT NULL UNIQUE,
    
    -- Block status
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN'
        CHECK (status IN ('OPEN', 'SEALING', 'SEALED', 'ANCHORED')),
    
    -- Timing
    opened_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    sealed_at TIMESTAMPTZ,
    anchored_at TIMESTAMPTZ,
    
    -- Transaction count
    transaction_count INTEGER DEFAULT 0,
    
    -- Merkle tree
    merkle_root VARCHAR(64),  -- Hash of all transaction hashes
    merkle_tree_depth INTEGER,
    
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
    
    -- Statistics
    total_amount NUMERIC(20, 8),
    currencies VARCHAR(3)[],
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    record_hash VARCHAR(64) NOT NULL
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
