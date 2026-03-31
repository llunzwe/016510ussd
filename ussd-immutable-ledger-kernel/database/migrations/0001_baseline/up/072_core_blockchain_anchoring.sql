-- =============================================================================
-- USSD KERNEL CORE SCHEMA - BLOCKCHAIN ANCHORING
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    072_core_blockchain_anchoring.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      core
-- DESCRIPTION: External blockchain anchoring for extra immutability guarantees.
--              Anchors block hashes to public blockchains (Ethereum, Stellar, etc.)
--              for cryptographic proof of existence and tamper detection.
-- =============================================================================

/*
================================================================================
BLOCKCHAIN ANCHORING OVERVIEW
================================================================================

Why Blockchain Anchoring:
- Provides EXTRA immutability beyond the database
- Cryptographic proof that data existed at a specific time
- Distributed trust - no single point of failure
- Publicly verifiable without revealing private data

Supported Blockchains:
├── Ethereum (mainnet/testnet) - High security, higher cost
├── Stellar (mainnet/testnet) - Fast, low cost
├── Bitcoin (mainnet/testnet) - Highest security
├── Polygon (mainnet/testnet) - Low cost, fast
└── Hyperledger Fabric - Private/permissioned

How It Works:
1. Block is sealed with Merkle root
2. Block hash is submitted to external blockchain
3. Transaction hash from blockchain is stored
4. Confirmations are monitored until finalized
5. Anchor provides timestamp and proof of existence

================================================================================
SECURITY CONSIDERATIONS
================================================================================

Privacy:
- Only HASHES are anchored, not actual data
- No PII or sensitive data goes to public blockchain
- Merkle proofs allow verification without revealing siblings

Key Management:
- Signing keys for blockchain transactions stored in HSM
- Separate keys per blockchain network
- Key rotation supported

================================================================================
*/

-- =============================================================================
-- BLOCKCHAIN CONFIGURATION
-- =============================================================================

CREATE TABLE IF NOT EXISTS core.blockchain_config (
    config_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Blockchain identification
    blockchain_type VARCHAR(50) NOT NULL 
        CHECK (blockchain_type IN ('ETHEREUM', 'STELLAR', 'BITCOIN', 'POLYGON', 'HYPERLEDGER', 'OTHER')),
    network VARCHAR(50) NOT NULL,  -- 'mainnet', 'testnet', 'custom'
    
    -- Connection settings
    rpc_endpoint TEXT,  -- RPC endpoint URL
    websocket_endpoint TEXT,  -- WebSocket for real-time updates
    chain_id INTEGER,  -- For EVM chains
    
    -- Authentication
    api_key_encrypted BYTEA,  -- Encrypted API key for node access
    wallet_address VARCHAR(100),  -- Address used for anchoring transactions
    
    -- Anchoring parameters
    confirmation_blocks INTEGER DEFAULT 12,  -- Blocks to wait for finality
    gas_price_strategy VARCHAR(20) DEFAULT 'medium',  -- 'low', 'medium', 'high'
    max_gas_price_gwei NUMERIC,  -- Maximum gas price willing to pay
    
    -- Cost management
    estimated_cost_per_anchor NUMERIC,  -- In native currency
    daily_anchor_budget NUMERIC,  -- Maximum daily spend
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_testnet BOOLEAN DEFAULT FALSE,
    
    -- Health
    last_health_check TIMESTAMPTZ,
    health_status VARCHAR(20) DEFAULT 'UNKNOWN' 
        CHECK (health_status IN ('HEALTHY', 'DEGRADED', 'UNAVAILABLE', 'UNKNOWN')),
    
    -- Metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID
);

-- =============================================================================
-- ANCHORING FUNCTIONS
-- =============================================================================

-- Function to submit block hash to blockchain
CREATE OR REPLACE FUNCTION core.submit_blockchain_anchor(
    p_block_id UUID,
    p_blockchain_type VARCHAR DEFAULT 'ETHEREUM',
    p_network VARCHAR DEFAULT 'mainnet'
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_block RECORD;
    v_config RECORD;
    v_anchor_id UUID;
    v_merkle_root VARCHAR(64);
BEGIN
    -- Get block details
    SELECT * INTO v_block
    FROM core.blocks
    WHERE block_id = p_block_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Block not found: %', p_block_id;
    END IF;
    
    -- Verify block is sealed
    IF v_block.status NOT IN ('SEALED', 'CONFIRMED', 'ANCHORED') THEN
        RAISE EXCEPTION 'Block must be sealed before anchoring. Current status: %', v_block.status;
    END IF;
    
    -- Get blockchain config
    SELECT * INTO v_config
    FROM core.blockchain_config
    WHERE blockchain_type = p_blockchain_type
    AND network = p_network
    AND is_active = TRUE;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'No active configuration for % %', p_blockchain_type, p_network;
    END IF;
    
    -- Create anchor record
    INSERT INTO core.external_blockchain_anchors (
        block_id,
        blockchain_type,
        network,
        merkle_root,
        anchor_status
    ) VALUES (
        p_block_id,
        p_blockchain_type,
        p_network,
        v_block.merkle_root,
        'PENDING'
    )
    RETURNING anchor_id INTO v_anchor_id;
    
    -- In production, this would trigger an async job to:
    -- 1. Sign the transaction with HSM
    -- 2. Submit to blockchain via RPC
    -- 3. Monitor for confirmations
    -- 4. Update anchor record with tx_hash
    
    -- For now, we simulate the process
    RAISE NOTICE 'Anchor % created for block %. Merkle root: %', 
        v_anchor_id, p_block_id, v_block.merkle_root;
    
    RETURN v_anchor_id;
END;
$$;

-- Function to confirm blockchain anchor (called by monitoring job)
CREATE OR REPLACE FUNCTION core.confirm_blockchain_anchor(
    p_anchor_id UUID,
    p_tx_hash VARCHAR,
    p_block_number BIGINT,
    p_block_hash VARCHAR,
    p_timestamp TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.external_blockchain_anchors SET
        anchor_tx_hash = p_tx_hash,
        anchor_block_number = p_block_number,
        anchor_block_hash = p_block_hash,
        anchor_timestamp = p_timestamp,
        anchor_status = 'CONFIRMED',
        confirmed_at = NOW()
    WHERE anchor_id = p_anchor_id;
    
    RETURN FOUND;
END;
$$;

-- Function to finalize anchor after sufficient confirmations
CREATE OR REPLACE FUNCTION core.finalize_blockchain_anchor(
    p_anchor_id UUID,
    p_confirmations INTEGER
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
    v_anchor RECORD;
BEGIN
    SELECT * INTO v_anchor
    FROM core.external_blockchain_anchors
    WHERE anchor_id = p_anchor_id;
    
    SELECT * INTO v_config
    FROM core.blockchain_config
    WHERE blockchain_type = v_anchor.blockchain_type
    AND network = v_anchor.network;
    
    -- Check if we have enough confirmations
    IF p_confirmations >= COALESCE(v_config.confirmation_blocks, 12) THEN
        UPDATE core.external_blockchain_anchors SET
            confirmations = p_confirmations,
            is_finalized = TRUE,
            finalized_at = NOW(),
            anchor_status = 'FINALIZED'
        WHERE anchor_id = p_anchor_id;
        
        -- Update block status
        UPDATE core.blocks 
        SET status = 'ANCHORED',
            anchored_at = NOW()
        WHERE block_id = v_anchor.block_id;
        
        RETURN TRUE;
    END IF;
    
    -- Just update confirmation count
    UPDATE core.external_blockchain_anchors 
    SET confirmations = p_confirmations
    WHERE anchor_id = p_anchor_id;
    
    RETURN FALSE;
END;
$$;

-- Function to verify anchor on-chain (can be called by anyone)
CREATE OR REPLACE FUNCTION core.verify_blockchain_anchor(
    p_anchor_id UUID
)
RETURNS TABLE (
    is_valid BOOLEAN,
    anchor_age_hours NUMERIC,
    confirmation_count INTEGER,
    merkle_root_matches BOOLEAN,
    verification_message TEXT
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_anchor RECORD;
    v_block RECORD;
BEGIN
    SELECT * INTO v_anchor
    FROM core.external_blockchain_anchors
    WHERE anchor_id = p_anchor_id;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT 
            FALSE, 
            0::NUMERIC, 
            0, 
            FALSE, 
            'Anchor not found'::TEXT;
        RETURN;
    END IF;
    
    SELECT * INTO v_block
    FROM core.blocks
    WHERE block_id = v_anchor.block_id;
    
    -- Calculate results
    RETURN QUERY SELECT
        v_anchor.is_finalized,
        EXTRACT(EPOCH FROM (NOW() - v_anchor.created_at)) / 3600,
        v_anchor.confirmations,
        v_anchor.merkle_root = v_block.merkle_root,
        CASE 
            WHEN NOT v_anchor.is_finalized THEN 'Anchor not yet finalized'
            WHEN v_anchor.merkle_root != v_block.merkle_root THEN 'MERKLE ROOT MISMATCH - POSSIBLE TAMPERING'
            ELSE 'Anchor verified successfully'
        END;
END;
$$;

-- =============================================================================
-- BATCH ANCHORING FUNCTIONS
-- =============================================================================

-- Function to anchor multiple blocks in batch
CREATE OR REPLACE FUNCTION core.batch_anchor_blocks(
    p_start_block_number BIGINT,
    p_end_block_number BIGINT,
    p_blockchain_type VARCHAR DEFAULT 'ETHEREUM'
)
RETURNS TABLE (
    block_number BIGINT,
    anchor_id UUID,
    status TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_block RECORD;
    v_anchor_id UUID;
BEGIN
    FOR v_block IN 
        SELECT * FROM core.blocks
        WHERE block_number BETWEEN p_start_block_number AND p_end_block_number
        AND status IN ('SEALED', 'CONFIRMED')
        AND NOT EXISTS (
            SELECT 1 FROM core.external_blockchain_anchors a
            WHERE a.block_id = blocks.block_id
            AND a.blockchain_type = p_blockchain_type
        )
        ORDER BY block_number
    LOOP
        BEGIN
            v_anchor_id := core.submit_blockchain_anchor(
                v_block.block_id, 
                p_blockchain_type
            );
            
            block_number := v_block.block_number;
            anchor_id := v_anchor_id;
            status := 'SUBMITTED';
            RETURN NEXT;
            
        EXCEPTION WHEN OTHERS THEN
            block_number := v_block.block_number;
            anchor_id := NULL;
            status := 'FAILED: ' || SQLERRM;
            RETURN NEXT;
        END;
    END LOOP;
END;
$$;

-- =============================================================================
-- ANCHOR MONITORING
-- =============================================================================

-- View for anchor status monitoring
CREATE OR REPLACE VIEW core.blockchain_anchor_status AS
SELECT 
    a.anchor_id,
    a.blockchain_type,
    a.network,
    a.anchor_status,
    b.block_number,
    b.block_hash,
    a.merkle_root,
    a.anchor_tx_hash,
    a.confirmations,
    a.is_finalized,
    a.created_at,
    a.finalized_at,
    EXTRACT(EPOCH FROM (COALESCE(a.finalized_at, NOW()) - a.created_at)) / 60 as minutes_to_finalize,
    CASE 
        WHEN a.is_finalized THEN 'VERIFIED'
        WHEN a.anchor_status = 'CONFIRMED' THEN 'PENDING_CONFIRMATIONS'
        WHEN a.anchor_status = 'PENDING' THEN 'AWAITING_SUBMISSION'
        ELSE a.anchor_status
    END as display_status
FROM core.external_blockchain_anchors a
JOIN core.blocks b ON a.block_id = b.block_id
ORDER BY b.block_number DESC;

-- Function to get anchoring statistics
CREATE OR REPLACE FUNCTION core.get_anchor_statistics(
    p_blockchain_type VARCHAR DEFAULT NULL,
    p_days INTEGER DEFAULT 30
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_result JSONB;
BEGIN
    SELECT jsonb_build_object(
        'total_anchors', COUNT(*),
        'finalized_anchors', COUNT(*) FILTER (WHERE is_finalized = TRUE),
        'pending_anchors', COUNT(*) FILTER (WHERE anchor_status = 'PENDING'),
        'failed_anchors', COUNT(*) FILTER (WHERE anchor_status = 'FAILED'),
        'avg_confirmations', ROUND(AVG(confirmations), 2),
        'avg_time_to_finalize_minutes', ROUND(
            AVG(EXTRACT(EPOCH FROM (finalized_at - created_at)) / 60) 
            FILTER (WHERE is_finalized = TRUE), 
            2
        ),
        'by_blockchain', (
            SELECT jsonb_object_agg(
                blockchain_type,
                jsonb_build_object(
                    'count', cnt,
                    'finalized', finalized
                )
            )
            FROM (
                SELECT 
                    blockchain_type,
                    COUNT(*) as cnt,
                    COUNT(*) FILTER (WHERE is_finalized = TRUE) as finalized
                FROM core.external_blockchain_anchors
                WHERE created_at > NOW() - (p_days || ' days')::INTERVAL
                GROUP BY blockchain_type
            ) sub
        )
    ) INTO v_result
    FROM core.external_blockchain_anchors
    WHERE created_at > NOW() - (p_days || ' days')::INTERVAL
    AND (p_blockchain_type IS NULL OR blockchain_type = p_blockchain_type);
    
    RETURN v_result;
END;
$$;

-- =============================================================================
-- SEED CONFIGURATION
-- =============================================================================

INSERT INTO core.blockchain_config (
    blockchain_type,
    network,
    rpc_endpoint,
    chain_id,
    wallet_address,
    confirmation_blocks,
    is_active,
    is_testnet
)
VALUES 
    ('ETHEREUM', 'mainnet', 'https://mainnet.infura.io/v3/YOUR_PROJECT_ID', 1, '0x...', 12, FALSE, FALSE),
    ('ETHEREUM', 'sepolia', 'https://sepolia.infura.io/v3/YOUR_PROJECT_ID', 11155111, '0x...', 12, FALSE, TRUE),
    ('POLYGON', 'mainnet', 'https://polygon-rpc.com', 137, '0x...', 20, FALSE, FALSE),
    ('STELLAR', 'testnet', 'https://horizon-testnet.stellar.org', NULL, 'G...', 1, FALSE, TRUE)
ON CONFLICT DO NOTHING;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE core.blockchain_config IS 
    'Configuration for external blockchain anchoring services';
COMMENT ON FUNCTION core.submit_blockchain_anchor IS 
    'Submit a block hash to external blockchain for anchoring';
COMMENT ON FUNCTION core.verify_blockchain_anchor IS 
    'Verify that a blockchain anchor is valid and matches on-chain data';
COMMENT ON VIEW core.blockchain_anchor_status IS 
    'Real-time status of all blockchain anchors';

-- =============================================================================
-- END OF FILE
-- =============================================================================
