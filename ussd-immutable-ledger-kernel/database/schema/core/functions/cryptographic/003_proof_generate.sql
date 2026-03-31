-- =============================================================================
-- USSD KERNEL CORE SCHEMA - CRYPTOGRAPHIC FUNCTIONS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    003_proof_generate.sql
-- SCHEMA:      core
-- CATEGORY:    Cryptographic Functions
-- DESCRIPTION: Proof generation functions for Merkle inclusion proofs,
--              zero-knowledge proofs (future), and audit proofs.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.10.1 Cryptographic controls - Proof generation procedures
├── A.12.4 Logging and monitoring - Proof generation logging
└── A.18.1 Compliance - Audit proof requirements

ISO/IEC 27040:2024 (Storage Security)
├── Proof integrity: Tamper-evident proof structure
├── Proof availability: Guaranteed proof generation
└── Proof verification: Independent verification support

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. PROOF STRUCTURES
   - Merkle inclusion proofs
   - Range proofs (future)
   - Zero-knowledge proofs (future)
   - Audit proofs

2. OUTPUT FORMATS
   - JSON for API consumption
   - Binary for efficiency
   - Base64 for transport

3. PERFORMANCE
   - Cached proofs for sealed blocks
   - On-demand generation for pending
   - Batch generation support

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

KEY MANAGEMENT PROCEDURES:
1. Proof Signing (if applicable)
   - Separate signing key for proofs
   - Key rotation schedule
   - Timestamp integration

INTEGRITY VERIFICATION PROTOCOLS:
1. Proof Structure
   - Leaf hash
   - Sibling hashes
   - Direction flags
   - Root hash reference

2. Proof Validation
   - Structure validation
   - Hash chain verification
   - Signature verification (if signed)

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

PROOF CACHING:
- Pre-compute proofs for sealed blocks
- Cache frequently requested proofs
- Invalidate on reorganization (rare)

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- PROOF_GENERATED
- PROOF_VERIFIED
- PROOF_REQUESTED (by whom)

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- Create generate_merkle_inclusion_proof function
-- DESCRIPTION: Generate Merkle inclusion proof for a transaction
-- PRIORITY: HIGH
-- =============================================================================
CREATE OR REPLACE FUNCTION core.generate_merkle_inclusion_proof(
    p_transaction_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
DECLARE
    v_tx RECORD;
    v_leaf_node RECORD;
    v_current_node RECORD;
    v_sibling_node RECORD;
    v_proof JSONB := '[]'::JSONB;
    v_block_id UUID;
    v_root_hash BYTEA;
BEGIN
    -- Get transaction details
    SELECT transaction_id, current_hash, block_id
    INTO v_tx
    FROM core.transaction_log
    WHERE transaction_id = p_transaction_id;
    
    IF v_tx IS NULL THEN
        RAISE EXCEPTION 'Transaction not found: %', p_transaction_id;
    END IF;
    
    v_block_id := v_tx.block_id;
    
    -- If not in a block yet, can't generate proof
    IF v_block_id IS NULL THEN
        RETURN jsonb_build_object(
            'status', 'PENDING',
            'message', 'Transaction not yet included in a sealed block'
        );
    END IF;
    
    -- Get the leaf node
    SELECT * INTO v_leaf_node
    FROM core.merkle_nodes
    WHERE transaction_id = p_transaction_id AND node_level = 0;
    
    IF v_leaf_node IS NULL THEN
        -- Build tree if needed
        PERFORM core.build_merkle_tree(v_block_id);
        
        -- Try again
        SELECT * INTO v_leaf_node
        FROM core.merkle_nodes
        WHERE transaction_id = p_transaction_id AND node_level = 0;
        
        IF v_leaf_node IS NULL THEN
            RAISE EXCEPTION 'Merkle leaf not found for transaction %', p_transaction_id;
        END IF;
    END IF;
    
    -- Walk up the tree building the proof
    v_current_node := v_leaf_node;
    
    WHILE v_current_node.node_level < (
        SELECT MAX(node_level) FROM core.merkle_nodes WHERE block_id = v_block_id
    ) LOOP
        -- Find sibling
        IF v_current_node.node_index % 2 = 0 THEN
            -- Current is left child
            SELECT * INTO v_sibling_node
            FROM core.merkle_nodes
            WHERE block_id = v_block_id 
              AND node_level = v_current_node.node_level 
              AND node_index = v_current_node.node_index + 1;
        ELSE
            -- Current is right child
            SELECT * INTO v_sibling_node
            FROM core.merkle_nodes
            WHERE block_id = v_block_id 
              AND node_level = v_current_node.node_level 
              AND node_index = v_current_node.node_index - 1;
        END IF;
        
        IF v_sibling_node.node_id IS NOT NULL THEN
            v_proof := v_proof || jsonb_build_object(
                'hash', encode(v_sibling_node.node_hash, 'hex'),
                'position', CASE WHEN v_current_node.node_index % 2 = 0 THEN 'right' ELSE 'left' END,
                'level', v_current_node.node_level
            );
        END IF;
        
        -- Move to parent
        SELECT * INTO v_current_node
        FROM core.merkle_nodes
        WHERE node_id = (
            SELECT node_id FROM core.merkle_nodes
            WHERE block_id = v_block_id 
              AND node_level = v_current_node.node_level + 1
              AND (left_child = v_current_node.node_id OR right_child = v_current_node.node_id)
            LIMIT 1
        );
        
        EXIT WHEN v_current_node.node_id IS NULL;
    END LOOP;
    
    -- Get root hash
    SELECT node_hash INTO v_root_hash
    FROM core.merkle_nodes
    WHERE block_id = v_block_id
    ORDER BY node_level DESC, node_index ASC
    LIMIT 1;
    
    -- Log proof generation
    INSERT INTO core.audit_trail (
        event_type,
        table_name,
        record_id,
        details
    ) VALUES (
        'PROOF_GENERATED',
        'transaction_log',
        p_transaction_id::text,
        jsonb_build_object(
            'block_id', v_block_id,
            'proof_length', jsonb_array_length(v_proof),
            'generated_at', CURRENT_TIMESTAMP
        )
    );
    
    RETURN jsonb_build_object(
        'transaction_id', p_transaction_id,
        'transaction_hash', encode(v_tx.current_hash, 'hex'),
        'block_id', v_block_id,
        'merkle_root', encode(v_root_hash, 'hex'),
        'proof_path', v_proof,
        'proof_algorithm', 'SHA-256',
        'generated_at', CURRENT_TIMESTAMP
    );
END;
$$;

COMMENT ON FUNCTION core.generate_merkle_inclusion_proof IS 'Generate a Merkle inclusion proof for a specific transaction';

-- =============================================================================
-- Create generate_audit_proof function
-- DESCRIPTION: Generate proof for audit purposes
-- PRIORITY: MEDIUM
-- =============================================================================
CREATE OR REPLACE FUNCTION core.generate_audit_proof(
    p_start_date TIMESTAMPTZ,
    p_end_date TIMESTAMPTZ,
    p_account_id UUID DEFAULT NULL,
    p_application_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
DECLARE
    v_proof JSONB;
    v_tx_count INTEGER;
    v_blocks UUID[];
    v_start_hash BYTEA;
    v_end_hash BYTEA;
BEGIN
    -- Count transactions in range
    SELECT COUNT(*) INTO v_tx_count
    FROM core.transaction_log
    WHERE created_at BETWEEN p_start_date AND p_end_date
      AND (p_account_id IS NULL OR initiator_account_id = p_account_id)
      AND (p_application_id IS NULL OR application_id = p_application_id);
    
    -- Get blocks in range
    SELECT array_agg(DISTINCT block_id) INTO v_blocks
    FROM core.transaction_log
    WHERE created_at BETWEEN p_start_date AND p_end_date
      AND block_id IS NOT NULL
      AND (p_account_id IS NULL OR initiator_account_id = p_account_id)
      AND (p_application_id IS NULL OR application_id = p_application_id);
    
    -- Get boundary hashes
    SELECT current_hash INTO v_start_hash
    FROM core.transaction_log
    WHERE created_at >= p_start_date
      AND (p_account_id IS NULL OR initiator_account_id = p_account_id)
      AND (p_application_id IS NULL OR application_id = p_application_id)
    ORDER BY chain_sequence
    LIMIT 1;
    
    SELECT current_hash INTO v_end_hash
    FROM core.transaction_log
    WHERE created_at <= p_end_date
      AND (p_account_id IS NULL OR initiator_account_id = p_account_id)
      AND (p_application_id IS NULL OR application_id = p_application_id)
    ORDER BY chain_sequence DESC
    LIMIT 1;
    
    -- Build comprehensive proof
    v_proof := jsonb_build_object(
        'proof_type', 'AUDIT_PROOF',
        'generated_at', CURRENT_TIMESTAMP,
        'generated_by', CURRENT_USER,
        'parameters', jsonb_build_object(
            'start_date', p_start_date,
            'end_date', p_end_date,
            'account_id', p_account_id,
            'application_id', p_application_id
        ),
        'summary', jsonb_build_object(
            'transaction_count', v_tx_count,
            'blocks_affected', v_blocks,
            'start_hash', encode(v_start_hash, 'hex'),
            'end_hash', encode(v_end_hash, 'hex')
        ),
        'verification_instructions', jsonb_build_object(
            'method', 'core.verify_hash_chain',
            'parameters', jsonb_build_object(
                'account_id', p_account_id,
                'start_hash', encode(v_start_hash, 'hex'),
                'end_hash', encode(v_end_hash, 'hex')
            )
        ),
        'block_merkle_roots', (
            SELECT jsonb_agg(
                jsonb_build_object(
                    'block_id', block_id,
                    'merkle_root', encode(merkle_root, 'hex'),
                    'block_hash', encode(block_hash, 'hex'),
                    'sealed_at', sealed_at
                )
            )
            FROM core.blocks
            WHERE block_id = ANY(v_blocks)
        )
    );
    
    -- Log audit proof generation
    INSERT INTO core.audit_trail (
        event_type,
        record_id,
        details,
        severity
    ) VALUES (
        'AUDIT_PROOF_GENERATED',
        COALESCE(p_account_id::text, 'GLOBAL'),
        jsonb_build_object(
            'start_date', p_start_date,
            'end_date', p_end_date,
            'transaction_count', v_tx_count,
            'blocks_count', COALESCE(array_length(v_blocks, 1), 0)
        ),
        'INFO'
    );
    
    RETURN v_proof;
END;
$$;

COMMENT ON FUNCTION core.generate_audit_proof IS 'Generate a comprehensive audit proof for a time period and optional account';

/*
================================================================================
MIGRATION CHECKLIST:
□ Create generate_merkle_inclusion_proof function
□ Create generate_audit_proof function
□ Test proof generation
□ Test proof verification
□ Benchmark proof generation performance
□ Document proof format
================================================================================
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
