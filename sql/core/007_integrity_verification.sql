-- ============================================================================
-- USSD KERNEL CORE SCHEMA - INTEGRITY VERIFICATION SERVICE
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Continuous integrity verification of hash chains, Merkle trees,
--              and overall ledger consistency. Provides APIs for auditors.
-- Immutability: N/A (Verification/Monitoring Service)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. VERIFICATION RESULTS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_core.integrity_verification_results (
    verification_id BIGSERIAL PRIMARY KEY,
    
    -- What was verified
    verification_type VARCHAR(50) NOT NULL,  -- 'hash_chain', 'merkle_tree', 'block_sequence', 'full_audit'
    scope VARCHAR(100),  -- 'global', 'account:xxx', 'block:xxx', 'application:xxx'
    
    -- Time range verified
    from_transaction_id BIGINT,
    to_transaction_id BIGINT,
    from_time TIMESTAMPTZ,
    to_time TIMESTAMPTZ,
    
    -- Result
    is_valid BOOLEAN NOT NULL,
    issues_found INTEGER DEFAULT 0,
    
    -- Details (if issues found)
    details JSONB DEFAULT '{}',
    
    -- Verification metadata
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    duration_ms INTEGER,
    verified_by VARCHAR(100) DEFAULT current_user,
    
    -- For scheduled verifications
    is_scheduled BOOLEAN DEFAULT FALSE,
    schedule_name VARCHAR(100)
);

-- ----------------------------------------------------------------------------
-- 2. INTEGRITY ISSUES TABLE (Critical alerts)
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_core.integrity_issues (
    issue_id BIGSERIAL PRIMARY KEY,
    
    -- Issue classification
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    issue_type VARCHAR(50) NOT NULL,  -- 'hash_mismatch', 'missing_transaction', 'merkle_root_invalid', etc.
    
    -- Affected entities
    transaction_id BIGINT,
    block_id BIGINT,
    account_id UUID,
    
    -- Description
    description TEXT NOT NULL,
    expected_value TEXT,
    actual_value TEXT,
    
    -- Status tracking
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
    
    -- Timestamps
    detected_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT,
    
    -- Assignment
    assigned_to VARCHAR(100),
    
    -- Link to verification run
    verification_id BIGINT REFERENCES ussd_core.integrity_verification_results(verification_id)
);

-- ----------------------------------------------------------------------------
-- 3. VERIFICATION SCHEDULE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_core.verification_schedules (
    schedule_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    schedule_name VARCHAR(100) NOT NULL UNIQUE,
    schedule_type VARCHAR(50) NOT NULL,  -- 'continuous', 'hourly', 'daily', 'weekly'
    
    -- What to verify
    verification_type VARCHAR(50) NOT NULL,
    scope VARCHAR(100),
    
    -- Schedule
    cron_expression VARCHAR(100),  -- For cron-based schedules
    interval_minutes INTEGER,  -- For interval-based schedules
    
    -- Last run info
    last_run_at TIMESTAMPTZ,
    last_run_result BOOLEAN,
    last_run_issue_count INTEGER DEFAULT 0,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    created_by UUID
);

-- ----------------------------------------------------------------------------
-- 4. VERIFICATION FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to verify hash chain for an account
CREATE OR REPLACE FUNCTION ussd_core.verify_account_hash_chain(
    p_account_id UUID,
    p_from_transaction_id BIGINT DEFAULT NULL,
    p_to_transaction_id BIGINT DEFAULT NULL
)
RETURNS TABLE (
    is_valid BOOLEAN,
    broken_at_transaction_id BIGINT,
    expected_hash VARCHAR(64),
    actual_hash VARCHAR(64),
    checked_count INTEGER
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_prev_hash VARCHAR(64) := NULL;
    v_tx RECORD;
    v_count INTEGER := 0;
    v_broken_tx_id BIGINT := NULL;
    v_expected VARCHAR(64) := NULL;
    v_actual VARCHAR(64) := NULL;
BEGIN
    FOR v_tx IN 
        SELECT 
            t.transaction_id,
            t.previous_hash,
            t.transaction_hash,
            t.transaction_uuid,
            t.transaction_type_id,
            t.initiator_account_id,
            t.payload,
            t.committed_at
        FROM ussd_core.transactions t
        WHERE t.initiator_account_id = p_account_id
          AND t.status = 'committed'
          AND (p_from_transaction_id IS NULL OR t.transaction_id >= p_from_transaction_id)
          AND (p_to_transaction_id IS NULL OR t.transaction_id <= p_to_transaction_id)
        ORDER BY t.committed_at, t.transaction_id
    LOOP
        v_count := v_count + 1;
        
        -- Check previous hash matches
        IF v_prev_hash IS DISTINCT FROM v_tx.previous_hash THEN
            v_broken_tx_id := v_tx.transaction_id;
            v_expected := v_prev_hash;
            v_actual := v_tx.previous_hash;
            
            RETURN QUERY SELECT FALSE, v_broken_tx_id, v_expected, v_actual, v_count;
            RETURN;
        END IF;
        
        -- Verify current transaction hash
        IF v_tx.transaction_hash != ussd_core.compute_transaction_hash(
            v_tx.previous_hash,
            (SELECT type_code FROM ussd_core.transaction_types WHERE type_id = v_tx.transaction_type_id),
            v_tx.payload,
            v_tx.committed_at,
            v_tx.initiator_account_id,
            v_tx.transaction_uuid::TEXT
        ) THEN
            v_broken_tx_id := v_tx.transaction_id;
            v_expected := 'computed_hash';
            v_actual := v_tx.transaction_hash;
            
            RETURN QUERY SELECT FALSE, v_broken_tx_id, v_expected, v_actual, v_count;
            RETURN;
        END IF;
        
        v_prev_hash := v_tx.transaction_hash;
    END LOOP;
    
    RETURN QUERY SELECT TRUE, NULL::BIGINT, NULL::VARCHAR, NULL::VARCHAR, v_count;
END;
$$;

-- Function to verify Merkle root for a block
CREATE OR REPLACE FUNCTION ussd_core.verify_block_merkle_root(
    p_block_id BIGINT
)
RETURNS TABLE (
    is_valid BOOLEAN,
    expected_root VARCHAR(64),
    computed_root VARCHAR(64),
    transaction_count INTEGER
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_block_merkle_root VARCHAR(64);
    v_tx_hashes TEXT[];
    v_computed_root VARCHAR(64);
    v_count INTEGER;
BEGIN
    -- Get stored Merkle root
    SELECT merkle_root INTO v_block_merkle_root
    FROM ussd_core.blocks
    WHERE block_id = p_block_id AND status IN ('sealed', 'anchored');
    
    IF v_block_merkle_root IS NULL THEN
        RETURN QUERY SELECT FALSE, NULL::VARCHAR, NULL::VARCHAR, 0;
        RETURN;
    END IF;
    
    -- Get transaction hashes
    SELECT 
        array_agg(transaction_hash ORDER BY sequence_number),
        COUNT(*)::INTEGER
    INTO v_tx_hashes, v_count
    FROM ussd_core.block_transactions
    WHERE block_id = p_block_id;
    
    -- Compute expected root
    v_computed_root := ussd_core.compute_merkle_root(v_tx_hashes);
    
    RETURN QUERY SELECT 
        (v_block_merkle_root = v_computed_root),
        v_block_merkle_root,
        v_computed_root,
        v_count;
END;
$$;

-- Function to verify global block sequence
CREATE OR REPLACE FUNCTION ussd_core.verify_block_sequence()
RETURNS TABLE (
    is_valid BOOLEAN,
    broken_at_block_id BIGINT,
    expected_previous_hash VARCHAR(64),
    actual_previous_hash VARCHAR(64)
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_prev_block_hash VARCHAR(64) := NULL;
    v_block RECORD;
BEGIN
    FOR v_block IN 
        SELECT block_id, block_height, previous_block_hash, block_hash
        FROM ussd_core.blocks
        WHERE status IN ('sealed', 'anchored')
        ORDER BY block_height
    LOOP
        IF v_block.previous_block_hash IS DISTINCT FROM v_prev_block_hash THEN
            RETURN QUERY SELECT 
                FALSE, 
                v_block.block_id, 
                v_prev_block_hash, 
                v_block.previous_block_hash;
            RETURN;
        END IF;
        
        v_prev_block_hash := v_block.block_hash;
    END LOOP;
    
    RETURN QUERY SELECT TRUE, NULL::BIGINT, NULL::VARCHAR, NULL::VARCHAR;
END;
$$;

-- Function to run full integrity verification
CREATE OR REPLACE FUNCTION ussd_core.run_full_verification(
    p_scope VARCHAR DEFAULT 'global'
)
RETURNS BIGINT  -- Returns verification_id
LANGUAGE plpgsql
AS $$
DECLARE
    v_verification_id BIGINT;
    v_start_time TIMESTAMPTZ;
    v_is_valid BOOLEAN := TRUE;
    v_issues JSONB := '[]'::JSONB;
    v_issue_count INTEGER := 0;
    v_result RECORD;
    v_account RECORD;
    v_block RECORD;
BEGIN
    v_start_time := ussd_core.precise_now();
    
    -- Create verification record
    INSERT INTO ussd_core.integrity_verification_results (
        verification_type, scope, started_at, is_scheduled
    ) VALUES (
        'full_audit', p_scope, v_start_time, FALSE
    )
    RETURNING verification_id INTO v_verification_id;
    
    -- Verify block sequence
    SELECT * INTO v_result FROM ussd_core.verify_block_sequence();
    IF NOT v_result.is_valid THEN
        v_is_valid := FALSE;
        v_issue_count := v_issue_count + 1;
        v_issues := v_issues || jsonb_build_object(
            'type', 'block_sequence_break',
            'block_id', v_result.broken_at_block_id,
            'expected', v_result.expected_previous_hash,
            'actual', v_result.actual_previous_hash
        );
        
        INSERT INTO ussd_core.integrity_issues (
            severity, issue_type, block_id, description,
            expected_value, actual_value, verification_id
        ) VALUES (
            'critical', 'block_sequence_break', v_result.broken_at_block_id,
            'Block chain sequence broken - previous hash mismatch',
            v_result.expected_previous_hash, v_result.actual_previous_hash,
            v_verification_id
        );
    END IF;
    
    -- Verify Merkle roots for all sealed blocks
    FOR v_block IN 
        SELECT block_id FROM ussd_core.blocks 
        WHERE status IN ('sealed', 'anchored')
        AND (p_scope = 'global' OR p_scope = 'block:' || block_id::TEXT)
    LOOP
        SELECT * INTO v_result FROM ussd_core.verify_block_merkle_root(v_block.block_id);
        IF NOT v_result.is_valid THEN
            v_is_valid := FALSE;
            v_issue_count := v_issue_count + 1;
            v_issues := v_issues || jsonb_build_object(
                'type', 'merkle_root_mismatch',
                'block_id', v_block.block_id,
                'expected', v_result.expected_root,
                'actual', v_result.computed_root
            );
            
            INSERT INTO ussd_core.integrity_issues (
                severity, issue_type, block_id, description,
                expected_value, actual_value, verification_id
            ) VALUES (
                'critical', 'merkle_root_mismatch', v_block.block_id,
                'Merkle root does not match computed value',
                v_result.expected_root, v_result.computed_root,
                v_verification_id
            );
        END IF;
    END LOOP;
    
    -- Sample hash chain verification for active accounts (5% sample)
    FOR v_account IN 
        SELECT account_id FROM ussd_core.active_accounts
        WHERE random() < 0.05
        LIMIT 100
    LOOP
        SELECT * INTO v_result FROM ussd_core.verify_account_hash_chain(v_account.account_id);
        IF NOT v_result.is_valid THEN
            v_is_valid := FALSE;
            v_issue_count := v_issue_count + 1;
            v_issues := v_issues || jsonb_build_object(
                'type', 'hash_chain_break',
                'account_id', v_account.account_id,
                'transaction_id', v_result.broken_at_transaction_id
            );
            
            INSERT INTO ussd_core.integrity_issues (
                severity, issue_type, account_id, transaction_id, description,
                expected_value, actual_value, verification_id
            ) VALUES (
                'critical', 'hash_chain_break', v_account.account_id, v_result.broken_at_transaction_id,
                'Transaction hash chain broken for account',
                v_result.expected_hash, v_result.actual_hash,
                v_verification_id
            );
        END IF;
    END LOOP;
    
    -- Update verification record
    UPDATE ussd_core.integrity_verification_results
    SET is_valid = v_is_valid,
        issues_found = v_issue_count,
        details = v_issues,
        completed_at = ussd_core.precise_now(),
        duration_ms = EXTRACT(EPOCH FROM (ussd_core.precise_now() - v_start_time)) * 1000
    WHERE verification_id = v_verification_id;
    
    RETURN v_verification_id;
END;
$$;

-- ----------------------------------------------------------------------------
-- 5. PROOF GENERATION FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to generate full proof of existence for a transaction
CREATE OR REPLACE FUNCTION ussd_core.generate_existence_proof(
    p_transaction_id BIGINT
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_tx RECORD;
    v_block RECORD;
    v_proof JSONB;
    v_merkle_proof JSONB;
BEGIN
    -- Get transaction details
    SELECT * INTO v_tx
    FROM ussd_core.transactions
    WHERE transaction_id = p_transaction_id;
    
    IF NOT FOUND THEN
        RETURN jsonb_build_object('error', 'Transaction not found');
    END IF;
    
    -- Get block details
    SELECT * INTO v_block
    FROM ussd_core.blocks
    WHERE block_id = v_tx.block_id;
    
    -- Get Merkle proof
    SELECT proof_path INTO v_merkle_proof
    FROM ussd_core.generate_merkle_proof(p_transaction_id);
    
    -- Build complete proof
    v_proof := jsonb_build_object(
        'transaction', jsonb_build_object(
            'transaction_id', v_tx.transaction_id,
            'transaction_uuid', v_tx.transaction_uuid,
            'transaction_hash', v_tx.transaction_hash,
            'previous_hash', v_tx.previous_hash,
            'committed_at', v_tx.committed_at,
            'payload', v_tx.payload
        ),
        'block', CASE WHEN v_block.block_id IS NOT NULL THEN
            jsonb_build_object(
                'block_id', v_block.block_id,
                'block_height', v_block.block_height,
                'block_hash', v_block.block_hash,
                'merkle_root', v_block.merkle_root,
                'sealed_at', v_block.sealed_at
            )
        ELSE NULL END,
        'merkle_proof', v_merkle_proof,
        'generated_at', ussd_core.precise_now(),
        'kernel_version', (SELECT config_value FROM ussd_core.kernel_config WHERE config_key = 'kernel.version')
    );
    
    RETURN v_proof;
END;
$$;

-- Function to verify a complete existence proof
CREATE OR REPLACE FUNCTION ussd_core.verify_existence_proof(
    p_proof JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    v_result JSONB := '{}'::JSONB;
    v_merkle_valid BOOLEAN;
    v_hash_valid BOOLEAN;
BEGIN
    -- Verify Merkle proof
    IF p_proof->'merkle_proof' IS NOT NULL THEN
        v_merkle_valid := ussd_core.verify_merkle_proof(
            p_proof->'transaction'->>'transaction_hash',
            p_proof->'block'->>'merkle_root',
            p_proof->'merkle_proof'
        );
        v_result := v_result || jsonb_build_object('merkle_proof_valid', v_merkle_valid);
    END IF;
    
    -- Verify transaction hash
    v_hash_valid := ussd_core.generate_hash(
        COALESCE(p_proof->'transaction'->>'previous_hash', '') ||
        p_proof->'transaction'->>'transaction_uuid' ||
        p_proof->'transaction'->>'committed_at'
    ) = p_proof->'transaction'->>'transaction_hash';
    
    v_result := v_result || jsonb_build_object(
        'hash_chain_valid', v_hash_valid,
        'overall_valid', v_merkle_valid AND v_hash_valid,
        'verified_at', clock_timestamp()
    );
    
    RETURN v_result;
END;
$$;

-- ----------------------------------------------------------------------------
-- 6. INDEXES AND VIEWS
-- ----------------------------------------------------------------------------

CREATE INDEX idx_verification_type ON ussd_core.integrity_verification_results(verification_type);
CREATE INDEX idx_verification_time ON ussd_core.integrity_verification_results(completed_at DESC);
CREATE INDEX idx_verification_valid ON ussd_core.integrity_verification_results(is_valid) WHERE is_valid = FALSE;

CREATE INDEX idx_integrity_issues_severity ON ussd_core.integrity_issues(severity);
CREATE INDEX idx_integrity_issues_status ON ussd_core.integrity_issues(status) WHERE status = 'open';
CREATE INDEX idx_integrity_issues_type ON ussd_core.integrity_issues(issue_type);

-- View: Latest verification results
CREATE VIEW ussd_core.latest_verification_results AS
SELECT *
FROM ussd_core.integrity_verification_results
WHERE verification_id IN (
    SELECT MAX(verification_id)
    FROM ussd_core.integrity_verification_results
    GROUP BY verification_type, scope
)
ORDER BY completed_at DESC;

-- View: Open integrity issues
CREATE VIEW ussd_core.open_integrity_issues AS
SELECT 
    i.*,
    v.verification_type as found_in_verification_type,
    v.completed_at as found_at
FROM ussd_core.integrity_issues i
JOIN ussd_core.integrity_verification_results v ON i.verification_id = v.verification_id
WHERE i.status = 'open'
ORDER BY 
    CASE i.severity 
        WHEN 'critical' THEN 1 
        WHEN 'high' THEN 2 
        WHEN 'medium' THEN 3 
        ELSE 4 
    END,
    i.detected_at DESC;

-- View: Verification health dashboard
CREATE VIEW ussd_core.verification_health_dashboard AS
SELECT 
    (SELECT COUNT(*) FROM ussd_core.open_integrity_issues WHERE severity = 'critical') as critical_issues,
    (SELECT COUNT(*) FROM ussd_core.open_integrity_issues WHERE severity = 'high') as high_issues,
    (SELECT COUNT(*) FROM ussd_core.open_integrity_issues) as total_open_issues,
    (SELECT is_valid FROM ussd_core.latest_verification_results 
     WHERE verification_type = 'full_audit' ORDER BY completed_at DESC LIMIT 1) as last_full_audit_passed,
    (SELECT completed_at FROM ussd_core.latest_verification_results 
     WHERE verification_type = 'full_audit' ORDER BY completed_at DESC LIMIT 1) as last_full_audit_at,
    (SELECT COUNT(*) FROM ussd_core.blocks WHERE status IN ('sealed', 'anchored')) as total_sealed_blocks,
    (SELECT COUNT(*) FROM ussd_core.transactions WHERE status = 'committed') as total_committed_transactions;

-- ----------------------------------------------------------------------------
-- 7. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_core.integrity_verification_results IS 
    'Results of integrity verification runs on the ledger';
COMMENT ON TABLE ussd_core.integrity_issues IS 
    'Critical integrity issues requiring investigation';
COMMENT ON FUNCTION ussd_core.run_full_verification IS 
    'Runs comprehensive integrity verification and logs results';
COMMENT ON FUNCTION ussd_core.generate_existence_proof IS 
    'Generates cryptographic proof of transaction existence for auditors';
