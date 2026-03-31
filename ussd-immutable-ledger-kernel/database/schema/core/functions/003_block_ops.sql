-- ============================================================================
-- Block Operations for Immutable Ledger
-- ============================================================================

-- Function: Create new block
CREATE OR REPLACE FUNCTION core.create_block(
    p_block_number BIGINT DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_block_id UUID;
    v_previous_hash VARCHAR(64);
    v_previous_number BIGINT;
    v_merkle_root VARCHAR(64);
    v_transaction_hashes TEXT[];
BEGIN
    -- Get previous block info
    SELECT block_number, current_hash 
    INTO v_previous_number, v_previous_hash
    FROM core.blocks
    ORDER BY block_number DESC
    LIMIT 1;

    v_previous_number := COALESCE(v_previous_number, 0);
    v_previous_hash := COALESCE(v_previous_hash, '0' || repeat('0', 63));

    -- Determine block number
    IF p_block_number IS NULL THEN
        p_block_number := v_previous_number + 1;
    END IF;

    -- Get unblocked transaction hashes
    SELECT array_agg(t.current_hash)
    INTO v_transaction_hashes
    FROM core.transactions t
    LEFT JOIN core.block_transactions bt ON t.transaction_id = bt.transaction_id
    WHERE bt.transaction_id IS NULL
    AND t.created_at < now() - interval '5 minutes';

    -- Calculate Merkle root (simplified)
    IF v_transaction_hashes IS NOT NULL AND array_length(v_transaction_hashes, 1) > 0 THEN
        v_merkle_root := encode(
            digest(array_to_string(v_transaction_hashes, ''), 'sha256'),
            'hex'
        );
    ELSE
        v_merkle_root := encode(digest('empty', 'sha256'), 'hex');
    END IF;

    -- Create block
    v_block_id := gen_random_uuid();
    
    INSERT INTO core.blocks (
        block_id,
        block_number,
        previous_hash,
        current_hash,
        merkle_root,
        transaction_count,
        created_at,
        created_by
    ) VALUES (
        v_block_id,
        p_block_number,
        v_previous_hash,
        encode(
            digest(
                v_previous_hash || p_block_number::text || v_merkle_root || now()::text,
                'sha256'
            ),
            'hex'
        ),
        v_merkle_root,
        COALESCE(array_length(v_transaction_hashes, 1), 0),
        now(),
        current_user
    );

    -- Link transactions to block
    INSERT INTO core.block_transactions (block_id, transaction_id, transaction_order)
    SELECT v_block_id, t.transaction_id, row_number() OVER (ORDER BY t.created_at)
    FROM core.transactions t
    LEFT JOIN core.block_transactions bt ON t.transaction_id = bt.transaction_id
    WHERE bt.transaction_id IS NULL
    AND t.created_at < now() - interval '5 minutes';

    RETURN v_block_id;
END;
$$;

COMMENT ON FUNCTION core.create_block IS 'Creates a new block with unconfirmed transactions';

-- Function: Verify block integrity
CREATE OR REPLACE FUNCTION core.verify_block(
    p_block_id UUID
)
RETURNS TABLE (
    is_valid BOOLEAN,
    error_message TEXT
)
LANGUAGE plpgsql
STABLE
SET search_path = core, public
AS $$
DECLARE
    v_block RECORD;
    v_prev_block RECORD;
    v_calculated_hash VARCHAR(64);
BEGIN
    -- Get block
    SELECT * INTO v_block
    FROM core.blocks
    WHERE block_id = p_block_id;

    IF v_block IS NULL THEN
        RETURN QUERY SELECT FALSE, 'Block not found'::TEXT;
        RETURN;
    END IF;

    -- Verify previous hash chain
    IF v_block.block_number > 1 THEN
        SELECT * INTO v_prev_block
        FROM core.blocks
        WHERE block_number = v_block.block_number - 1;

        IF v_prev_block IS NULL THEN
            RETURN QUERY SELECT FALSE, 'Previous block not found'::TEXT;
            RETURN;
        END IF;

        IF v_block.previous_hash != v_prev_block.current_hash THEN
            RETURN QUERY SELECT FALSE, 'Previous hash mismatch'::TEXT;
            RETURN;
        END IF;
    END IF;

    -- Recalculate hash
    v_calculated_hash := encode(
        digest(
            v_block.previous_hash || v_block.block_number::text || v_block.merkle_root || v_block.created_at::text,
            'sha256'
        ),
        'hex'
    );

    IF v_calculated_hash != v_block.current_hash THEN
        RETURN QUERY SELECT FALSE, 'Hash verification failed'::TEXT;
        RETURN;
    END IF;

    RETURN QUERY SELECT TRUE, 'Block verified'::TEXT;
END;
$$;

COMMENT ON FUNCTION core.verify_block IS 'Verifies integrity of a specific block';

-- Function: Get block by number
CREATE OR REPLACE FUNCTION core.get_block(
    p_block_number BIGINT
)
RETURNS TABLE (
    block_id UUID,
    block_number BIGINT,
    current_hash VARCHAR(64),
    merkle_root VARCHAR(64),
    transaction_count INTEGER,
    created_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
SET search_path = core, public
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        b.block_id,
        b.block_number,
        b.current_hash,
        b.merkle_root,
        b.transaction_count,
        b.created_at
    FROM core.blocks b
    WHERE b.block_number = p_block_number;
END;
$$;

COMMENT ON FUNCTION core.get_block IS 'Retrieves block by its number';
