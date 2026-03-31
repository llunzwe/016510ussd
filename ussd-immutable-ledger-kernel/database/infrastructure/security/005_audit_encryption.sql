-- =============================================================================
-- AUDIT ENCRYPTION
-- Tamper-evident encrypted audit logging
-- =============================================================================

-- =============================================================================
-- AUDIT ENCRYPTION SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS audit_encryption;

COMMENT ON SCHEMA audit_encryption IS 'Tamper-evident encrypted audit logging';

-- =============================================================================
-- AUDIT MASTER KEYS
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_encryption.master_keys (
    id SERIAL PRIMARY KEY,
    key_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    key_version INTEGER NOT NULL DEFAULT 1,
    
    -- Key identification
    key_scope VARCHAR(100) NOT NULL, -- GLOBAL, TABLE, PARTITION
    scope_target VARCHAR(200), -- Specific table or partition
    
    -- Key material reference (stored in external HSM/Vault)
    key_reference VARCHAR(500) NOT NULL,
    key_fingerprint VARCHAR(64) NOT NULL,
    
    -- State
    key_state VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, ROTATING, ARCHIVED
    
    -- Lifecycle
    created_at TIMESTAMPTZ DEFAULT NOW(),
    activated_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    
    -- Rotation settings
    auto_rotation_enabled BOOLEAN DEFAULT TRUE,
    rotation_interval_days INTEGER DEFAULT 365
);

CREATE INDEX IF NOT EXISTS idx_audit_keys_scope 
ON audit_encryption.master_keys(key_scope, scope_target) 
WHERE key_state = 'ACTIVE';

-- =============================================================================
-- AUDIT CHAIN TABLE (Blockchain-like structure)
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_encryption.audit_chain (
    id BIGSERIAL PRIMARY KEY,
    block_number BIGINT NOT NULL,
    block_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Previous block hash (creates chain)
    previous_hash BYTEA NOT NULL,
    
    -- Current block data
    block_data JSONB NOT NULL,
    
    -- Block hash (hash of all fields)
    block_hash BYTEA NOT NULL,
    
    -- Signature by audit authority
    signature BYTEA,
    
    -- Key used for encryption
    key_id UUID REFERENCES audit_encryption.master_keys(key_id),
    
    -- Verification
    verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    
    UNIQUE(block_number)
);

CREATE INDEX IF NOT EXISTS idx_audit_chain_number 
ON audit_encryption.audit_chain(block_number);

CREATE INDEX IF NOT EXISTS idx_audit_chain_hash 
ON audit_encryption.audit_chain USING HASH (block_hash);

-- =============================================================================
-- AUDIT ENTRY ENCRYPTION MAP
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_encryption.entry_encryption_map (
    id BIGSERIAL PRIMARY KEY,
    source_schema VARCHAR(63) NOT NULL,
    source_table VARCHAR(63) NOT NULL,
    source_entry_id BIGINT NOT NULL,
    
    -- Encryption details
    chain_block_number BIGINT REFERENCES audit_encryption.audit_chain(block_number),
    encrypted_data BYTEA,
    
    -- Verification
    integrity_hash BYTEA NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_entry_map_source 
ON audit_encryption.entry_encryption_map(source_schema, source_table, source_entry_id);

-- =============================================================================
-- INTEGRITY VERIFICATION LOG
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_encryption.verification_log (
    id BIGSERIAL PRIMARY KEY,
    verification_type VARCHAR(50) NOT NULL, -- FULL, INCREMENTAL, BLOCK, ENTRY
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    
    -- Scope
    block_start BIGINT,
    block_end BIGINT,
    
    -- Results
    entries_checked BIGINT,
    entries_valid BIGINT,
    entries_invalid BIGINT,
    first_invalid_block BIGINT,
    
    -- Status
    status VARCHAR(20) DEFAULT 'RUNNING', -- RUNNING, VALID, INVALID, ERROR
    error_message TEXT,
    
    performed_by VARCHAR(100) DEFAULT current_user
);

-- =============================================================================
-- INITIALIZE GENESIS BLOCK
-- =============================================================================
INSERT INTO audit_encryption.audit_chain (
    block_number, previous_hash, block_data, block_hash
)
SELECT 
    0,
    '\x0000000000000000000000000000000000000000000000000000000000000000'::BYTEA,
    jsonb_build_object(
        'genesis', TRUE,
        'created_at', NOW(),
        'version', '1.0.0'
    ),
    digest('genesis_block_' || NOW()::TEXT, 'sha256')
WHERE NOT EXISTS (
    SELECT 1 FROM audit_encryption.audit_chain WHERE block_number = 0
);

-- =============================================================================
-- FUNCTION: Get next block number
-- =============================================================================
CREATE OR REPLACE FUNCTION audit_encryption.get_next_block_number()
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_max BIGINT;
BEGIN
    SELECT COALESCE(MAX(block_number), 0) + 1 INTO v_max
    FROM audit_encryption.audit_chain;
    
    RETURN v_max;
END;
$$;

-- =============================================================================
-- FUNCTION: Get previous block hash
-- =============================================================================
CREATE OR REPLACE FUNCTION audit_encryption.get_previous_hash()
RETURNS BYTEA
LANGUAGE plpgsql
AS $$
DECLARE
    v_hash BYTEA;
BEGIN
    SELECT block_hash INTO v_hash
    FROM audit_encryption.audit_chain
    ORDER BY block_number DESC
    LIMIT 1;
    
    RETURN COALESCE(v_hash, '\x00'::BYTEA);
END;
$$;

-- =============================================================================
-- FUNCTION: Calculate block hash
-- =============================================================================
CREATE OR REPLACE FUNCTION audit_encryption.calculate_block_hash(
    p_block_number BIGINT,
    p_previous_hash BYTEA,
    p_block_data JSONB,
    p_timestamp TIMESTAMPTZ
)
RETURNS BYTEA
LANGUAGE plpgsql
AS $$
DECLARE
    v_data TEXT;
BEGIN
    v_data := format('%s:%s:%s:%s',
        p_block_number,
        encode(p_previous_hash, 'hex'),
        p_block_data::TEXT,
        p_timestamp::TEXT
    );
    
    RETURN digest(v_data, 'sha256');
END;
$$;

-- =============================================================================
-- FUNCTION: Create new audit block
-- =============================================================================
CREATE OR REPLACE FUNCTION audit_encryption.create_audit_block(
    p_block_data JSONB,
    p_key_id UUID DEFAULT NULL
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_block_number BIGINT;
    v_previous_hash BYTEA;
    v_block_hash BYTEA;
BEGIN
    -- Get next block number
    v_block_number := audit_encryption.get_next_block_number();
    
    -- Get previous hash
    v_previous_hash := audit_encryption.get_previous_hash();
    
    -- Calculate block hash
    v_block_hash := audit_encryption.calculate_block_hash(
        v_block_number,
        v_previous_hash,
        p_block_data,
        NOW()
    );
    
    -- Insert block
    INSERT INTO audit_encryption.audit_chain (
        block_number, previous_hash, block_data, block_hash, key_id
    ) VALUES (
        v_block_number, v_previous_hash, p_block_data, v_block_hash, p_key_id
    );
    
    RETURN v_block_number;
END;
$$;

-- =============================================================================
-- FUNCTION: Verify chain integrity
-- =============================================================================
CREATE OR REPLACE FUNCTION audit_encryption.verify_chain(
    p_start_block BIGINT DEFAULT 0,
    p_end_block BIGINT DEFAULT NULL
)
RETURNS TABLE(
    block_number BIGINT,
    is_valid BOOLEAN,
    error_message TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_current RECORD;
    v_previous RECORD;
    v_expected_hash BYTEA;
    v_end BIGINT;
BEGIN
    v_end := COALESCE(p_end_block, audit_encryption.get_next_block_number() - 1);
    
    FOR v_current IN 
        SELECT * FROM audit_encryption.audit_chain
        WHERE block_number >= p_start_block 
          AND block_number <= v_end
        ORDER BY block_number
    LOOP
        block_number := v_current.block_number;
        
        -- Skip genesis block verification
        IF v_current.block_number = 0 THEN
            is_valid := TRUE;
            error_message := 'Genesis block - no verification needed';
            RETURN NEXT;
            CONTINUE;
        END IF;
        
        -- Get previous block
        SELECT * INTO v_previous
        FROM audit_encryption.audit_chain
        WHERE block_number = v_current.block_number - 1;
        
        IF NOT FOUND THEN
            is_valid := FALSE;
            error_message := 'Previous block not found';
            RETURN NEXT;
            CONTINUE;
        END IF;
        
        -- Verify previous hash linkage
        IF v_current.previous_hash != v_previous.block_hash THEN
            is_valid := FALSE;
            error_message := 'Previous hash mismatch - chain broken';
            RETURN NEXT;
            CONTINUE;
        END IF;
        
        -- Verify block hash
        v_expected_hash := audit_encryption.calculate_block_hash(
            v_current.block_number,
            v_current.previous_hash,
            v_current.block_data,
            v_current.block_timestamp
        );
        
        IF v_current.block_hash != v_expected_hash THEN
            is_valid := FALSE;
            error_message := 'Block hash mismatch - data tampered';
            RETURN NEXT;
            CONTINUE;
        END IF;
        
        -- Block is valid
        is_valid := TRUE;
        error_message := NULL;
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Full chain verification with logging
-- =============================================================================
CREATE OR REPLACE FUNCTION audit_encryption.perform_full_verification()
RETURNS TABLE(
    status TEXT,
    blocks_checked BIGINT,
    blocks_valid BIGINT,
    blocks_invalid BIGINT,
    first_invalid_block BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_log_id BIGINT;
    v_total BIGINT;
    v_valid BIGINT;
    v_invalid BIGINT;
    v_first_invalid BIGINT;
    v_result RECORD;
BEGIN
    -- Create log entry
    INSERT INTO audit_encryption.verification_log (
        verification_type, status, block_start, block_end
    ) VALUES (
        'FULL', 'RUNNING', 0, audit_encryption.get_next_block_number() - 1
    )
    RETURNING id INTO v_log_id;
    
    -- Count totals
    v_total := 0;
    v_valid := 0;
    v_invalid := 0;
    v_first_invalid := NULL;
    
    FOR v_result IN SELECT * FROM audit_encryption.verify_chain() LOOP
        v_total := v_total + 1;
        
        IF v_result.is_valid THEN
            v_valid := v_valid + 1;
        ELSE
            v_invalid := v_invalid + 1;
            IF v_first_invalid IS NULL THEN
                v_first_invalid := v_result.block_number;
            END IF;
        END IF;
    END LOOP;
    
    -- Update log
    UPDATE audit_encryption.verification_log
    SET completed_at = NOW(),
        entries_checked = v_total,
        entries_valid = v_valid,
        entries_invalid = v_invalid,
        first_invalid_block = v_first_invalid,
        status = CASE WHEN v_invalid = 0 THEN 'VALID' ELSE 'INVALID' END
    WHERE id = v_log_id;
    
    -- Mark verified blocks
    IF v_invalid = 0 THEN
        UPDATE audit_encryption.audit_chain
        SET verified = TRUE,
            verified_at = NOW()
        WHERE verified = FALSE;
    END IF;
    
    status := CASE WHEN v_invalid = 0 THEN 'VALID' ELSE 'INVALID' END;
    blocks_checked := v_total;
    blocks_valid := v_valid;
    blocks_invalid := v_invalid;
    first_invalid_block := v_first_invalid;
    
    RETURN NEXT;
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Encrypt audit entry
-- =============================================================================
CREATE OR REPLACE FUNCTION audit_encryption.encrypt_audit_entry(
    p_schema_name VARCHAR,
    p_table_name VARCHAR,
    p_entry_id BIGINT,
    p_data JSONB,
    p_key_id UUID DEFAULT NULL
)
RETURNS BYTEA
LANGUAGE plpgsql
AS $$
DECLARE
    v_key_ref VARCHAR(500);
    v_encrypted BYTEA;
    v_hash BYTEA;
    v_block_number BIGINT;
BEGIN
    -- Get key reference
    IF p_key_id IS NULL THEN
        SELECT key_reference INTO v_key_ref
        FROM audit_encryption.master_keys
        WHERE key_scope = 'GLOBAL' AND key_state = 'ACTIVE'
        LIMIT 1;
    ELSE
        SELECT key_reference INTO v_key_ref
        FROM audit_encryption.master_keys
        WHERE key_id = p_key_id;
    END IF;
    
    -- In production, this would use actual encryption
    -- For now, calculate hash as integrity verification
    v_hash := digest(p_data::TEXT, 'sha256');
    v_encrypted := v_hash; -- Placeholder for actual encryption
    
    -- Create audit block for this entry
    v_block_number := audit_encryption.create_audit_block(
        jsonb_build_object(
            'schema', p_schema_name,
            'table', p_table_name,
            'entry_id', p_entry_id,
            'data_hash', encode(v_hash, 'hex')
        ),
        p_key_id
    );
    
    -- Store encryption map
    INSERT INTO audit_encryption.entry_encryption_map (
        source_schema, source_table, source_entry_id,
        chain_block_number, encrypted_data, integrity_hash
    ) VALUES (
        p_schema_name, p_table_name, p_entry_id,
        v_block_number, v_encrypted, v_hash
    );
    
    RETURN v_encrypted;
END;
$$;

-- =============================================================================
-- VIEW: Chain status
-- =============================================================================
CREATE OR REPLACE VIEW audit_encryption.chain_status AS
SELECT 
    COUNT(*) as total_blocks,
    COUNT(*) FILTER (WHERE verified) as verified_blocks,
    COUNT(*) FILTER (WHERE NOT verified) as unverified_blocks,
    MIN(block_timestamp) as genesis_time,
    MAX(block_timestamp) as last_block_time,
    MAX(block_number) as latest_block_number,
    (SELECT encode(block_hash, 'hex') FROM audit_encryption.audit_chain 
     ORDER BY block_number DESC LIMIT 1) as latest_block_hash
FROM audit_encryption.audit_chain;

-- =============================================================================
-- VIEW: Recent verification results
-- =============================================================================
CREATE OR REPLACE VIEW audit_encryption.verification_results AS
SELECT 
    verification_type,
    started_at,
    completed_at,
    EXTRACT(EPOCH FROM (completed_at - started_at))::INTEGER as duration_seconds,
    block_start,
    block_end,
    entries_checked,
    entries_valid,
    entries_invalid,
    first_invalid_block,
    status,
    performed_by
FROM audit_encryption.verification_log
ORDER BY started_at DESC
LIMIT 100;

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA audit_encryption TO audit_admin;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA audit_encryption TO audit_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA audit_encryption TO audit_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA audit_encryption TO audit_admin;
