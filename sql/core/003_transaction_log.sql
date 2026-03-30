-- ============================================================================
-- USSD KERNEL CORE SCHEMA - TRANSACTION LOG
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: The central immutable table where every state change is recorded
--              as an append-only row with cryptographic hash chaining.
-- Immutability: 100% - No updates or deletes allowed EVER
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. TRANSACTION LOG TABLE (Partitioned)
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_core.transactions (
    -- Primary identifier
    transaction_id BIGSERIAL,
    
    -- External reference (UUID for global uniqueness)
    transaction_uuid UUID NOT NULL DEFAULT uuid_generate_v4(),
    
    -- Idempotency key (client-provided, globally unique)
    idempotency_key VARCHAR(255) NOT NULL,
    
    -- Hash chain fields (cryptographic integrity)
    previous_hash VARCHAR(64),  -- Hash of previous transaction in chain
    transaction_hash VARCHAR(64) NOT NULL,  -- Hash of this transaction
    
    -- Transaction classification
    transaction_type_id UUID NOT NULL REFERENCES ussd_core.transaction_types(type_id),
    application_id UUID,  -- NULL for system/global transactions
    
    -- Actor information
    initiator_account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    -- For transactions on behalf of another account
    on_behalf_of_account_id UUID REFERENCES ussd_core.account_registry(account_id),
    
    -- Payload (the actual transaction data)
    payload JSONB NOT NULL,
    payload_encrypted BOOLEAN DEFAULT FALSE,  -- If payload contains encrypted fields
    
    -- Amount information (extracted from payload for indexing)
    amount NUMERIC(20, 8),
    currency VARCHAR(3),
    
    -- Status tracking
    status ussd_core.transaction_status DEFAULT 'pending',
    
    -- Block assignment (for Merkle tree batching)
    block_id BIGINT,  -- References blocks table
    block_sequence INTEGER,  -- Position within block (0-indexed)
    
    -- Digital signature (if transaction is signed)
    signature TEXT,  -- Base64 encoded signature
    signature_algorithm VARCHAR(20),  -- e.g., 'ed25519', 'secp256k1'
    
    -- Approval tracking (for multi-sig or approval workflows)
    required_approvals INTEGER DEFAULT 0,
    current_approvals INTEGER DEFAULT 0,
    approvers UUID[] DEFAULT '{}',  -- Array of account IDs who approved
    
    -- Related transactions
    parent_transaction_id BIGINT,  -- For child transactions (e.g., fees)
    related_transactions BIGINT[] DEFAULT '{}',  -- Array of related tx IDs
    
    -- Timing
    client_timestamp TIMESTAMPTZ,  -- Timestamp from client device
    committed_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    
    -- Audit and trace
    session_id TEXT,
    client_ip INET,
    user_agent TEXT,
    
    -- Processing metadata
    processing_duration_ms INTEGER,  -- Time taken to process
    processor_version VARCHAR(20),  -- Version of processing code
    
    -- Rejection/failure info (if status != committed)
    rejection_reason TEXT,
    rejection_code VARCHAR(50),
    
    -- Partition key (derived)
    partition_date DATE NOT NULL DEFAULT CURRENT_DATE,
    
    -- Record hash for row-level integrity
    record_hash VARCHAR(64) NOT NULL
) PARTITION BY RANGE (partition_date);

-- ----------------------------------------------------------------------------
-- 2. CREATE INITIAL PARTITIONS
-- ----------------------------------------------------------------------------
-- Create partitions for current and upcoming months
CREATE TABLE ussd_core.transactions_2024_01 
    PARTITION OF ussd_core.transactions
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

CREATE TABLE ussd_core.transactions_2024_02 
    PARTITION OF ussd_core.transactions
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');

CREATE TABLE ussd_core.transactions_2024_03 
    PARTITION OF ussd_core.transactions
    FOR VALUES FROM ('2024-03-01') TO ('2024-04-01');

-- Default partition for overflow
CREATE TABLE ussd_core.transactions_default 
    PARTITION OF ussd_core.transactions DEFAULT;

-- ----------------------------------------------------------------------------
-- 3. PRIMARY KEY AND INDEXES (Per Partition)
-- ----------------------------------------------------------------------------

-- Note: Primary key includes partition key for partition-local uniqueness
ALTER TABLE ussd_core.transactions 
    ADD CONSTRAINT pk_transactions PRIMARY KEY (transaction_id, partition_date);

-- Unique constraints
CREATE UNIQUE INDEX idx_transactions_uuid 
    ON ussd_core.transactions(transaction_uuid);

CREATE UNIQUE INDEX idx_transactions_idempotency 
    ON ussd_core.transactions(idempotency_key);

-- Hash chain index
CREATE INDEX idx_transactions_hash ON ussd_core.transactions(transaction_hash);
CREATE INDEX idx_transactions_prev_hash ON ussd_core.transactions(previous_hash);

-- Chain per account (for account-specific hash chains)
CREATE INDEX idx_transactions_initiator_chain 
    ON ussd_core.transactions(initiator_account_id, committed_at, transaction_hash);

-- Query performance indexes
CREATE INDEX idx_transactions_type ON ussd_core.transactions(transaction_type_id);
CREATE INDEX idx_transactions_app ON ussd_core.transactions(application_id);
CREATE INDEX idx_transactions_status ON ussd_core.transactions(status);
CREATE INDEX idx_transactions_block ON ussd_core.transactions(block_id);
CREATE INDEX idx_transactions_initiator ON ussd_core.transactions(initiator_account_id);
CREATE INDEX idx_transactions_behalf ON ussd_core.transactions(on_behalf_of_account_id);
CREATE INDEX idx_transactions_parent ON ussd_core.transactions(parent_transaction_id);

-- Time-based queries
CREATE INDEX idx_transactions_committed_at 
    ON ussd_core.transactions(committed_at DESC);

-- Financial queries
CREATE INDEX idx_transactions_amount ON ussd_core.transactions(amount, currency) 
    WHERE amount IS NOT NULL;

-- JSONB payload search
CREATE INDEX idx_transactions_payload_gin ON ussd_core.transactions USING gin(payload);

-- Compound index for common query patterns
CREATE INDEX idx_transactions_app_type_time 
    ON ussd_core.transactions(application_id, transaction_type_id, committed_at DESC);

CREATE INDEX idx_transactions_initiator_time 
    ON ussd_core.transactions(initiator_account_id, committed_at DESC);

-- Full-text search on payload (if payload contains searchable text)
-- This requires a generated column or expression index
CREATE INDEX idx_transactions_payload_text 
    ON ussd_core.transactions USING gin((payload::text) gin_trgm_ops);

-- ----------------------------------------------------------------------------
-- 4. IMMUTABILITY TRIGGERS (CRITICAL)
-- ----------------------------------------------------------------------------
CREATE TRIGGER trg_transactions_prevent_update
    BEFORE UPDATE ON ussd_core.transactions
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_update();

CREATE TRIGGER trg_transactions_prevent_delete
    BEFORE DELETE ON ussd_core.transactions
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_delete();

-- ----------------------------------------------------------------------------
-- 5. HASH COMPUTATION AND CHAINING
-- ----------------------------------------------------------------------------

-- Function to get the previous hash for an account chain
CREATE OR REPLACE FUNCTION ussd_core.get_last_transaction_hash(
    p_account_id UUID
)
RETURNS VARCHAR(64)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_last_hash VARCHAR(64);
BEGIN
    SELECT transaction_hash INTO v_last_hash
    FROM ussd_core.transactions
    WHERE initiator_account_id = p_account_id
    ORDER BY committed_at DESC, transaction_id DESC
    LIMIT 1;
    
    RETURN v_last_hash;
END;
$$;

-- Function to compute transaction hash with chaining
CREATE OR REPLACE FUNCTION ussd_core.compute_transaction_record_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_previous_hash VARCHAR(64);
    v_data TEXT;
BEGIN
    -- Get previous hash in the account chain
    v_previous_hash := ussd_core.get_last_transaction_hash(NEW.initiator_account_id);
    
    -- Store previous hash
    NEW.previous_hash := v_previous_hash;
    
    -- Compute current transaction hash
    v_data := COALESCE(v_previous_hash, '') || 
              NEW.transaction_uuid::TEXT || 
              NEW.transaction_type_id::TEXT || 
              NEW.initiator_account_id::TEXT || 
              COALESCE(NEW.on_behalf_of_account_id::TEXT, '') ||
              COALESCE(NEW.payload::TEXT, '{}') || 
              NEW.committed_at::TEXT ||
              NEW.idempotency_key;
    
    NEW.transaction_hash := ussd_core.generate_hash(v_data);
    
    -- Also compute row-level record hash
    NEW.record_hash := ussd_core.generate_hash(
        NEW.transaction_id::TEXT || NEW.transaction_hash || NEW.committed_at::TEXT
    );
    
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_transactions_compute_hash
    BEFORE INSERT ON ussd_core.transactions
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.compute_transaction_record_hash();

-- ----------------------------------------------------------------------------
-- 6. IDEMPOTENCY CHECK
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ussd_core.check_idempotency()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_existing ussd_core.transactions%ROWTYPE;
BEGIN
    -- Check if idempotency key already exists
    SELECT * INTO v_existing
    FROM ussd_core.transactions
    WHERE idempotency_key = NEW.idempotency_key;
    
    IF FOUND THEN
        RAISE EXCEPTION 'IDEMPOTENCY_VIOLATION: Transaction with idempotency key % already exists (transaction_id: %)',
            NEW.idempotency_key, v_existing.transaction_id
            USING ERRCODE = 'P0002';
    END IF;
    
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_transactions_check_idempotency
    BEFORE INSERT ON ussd_core.transactions
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.check_idempotency();

-- ----------------------------------------------------------------------------
-- 7. REJECTION LOG (For failed transactions - outside core immutability)
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_audit.rejected_transactions (
    rejection_id BIGSERIAL PRIMARY KEY,
    idempotency_key VARCHAR(255) NOT NULL,
    transaction_type_id UUID,
    application_id UUID,
    initiator_account_id UUID,
    payload JSONB,
    rejection_reason TEXT NOT NULL,
    rejection_code VARCHAR(50),
    rejected_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    client_ip INET,
    session_id TEXT
);

CREATE INDEX idx_rejected_idempotency ON ussd_audit.rejected_transactions(idempotency_key);
CREATE INDEX idx_rejected_initiator ON ussd_audit.rejected_transactions(initiator_account_id);
CREATE INDEX idx_rejected_time ON ussd_audit.rejected_transactions(rejected_at);

-- Function to log rejected transaction
CREATE OR REPLACE FUNCTION ussd_core.log_rejected_transaction(
    p_idempotency_key VARCHAR,
    p_transaction_type_id UUID,
    p_application_id UUID,
    p_initiator_account_id UUID,
    p_payload JSONB,
    p_rejection_reason TEXT,
    p_rejection_code VARCHAR DEFAULT NULL
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_rejection_id BIGINT;
BEGIN
    INSERT INTO ussd_audit.rejected_transactions (
        idempotency_key,
        transaction_type_id,
        application_id,
        initiator_account_id,
        payload,
        rejection_reason,
        rejection_code,
        client_ip,
        session_id
    ) VALUES (
        p_idempotency_key,
        p_transaction_type_id,
        p_application_id,
        p_initiator_account_id,
        p_payload,
        p_rejection_reason,
        p_rejection_code,
        NULLIF(current_setting('app.client_ip', TRUE), '')::INET,
        current_setting('app.session_id', TRUE)
    )
    RETURNING rejection_id INTO v_rejection_id;
    
    RETURN v_rejection_id;
END;
$$;

-- ----------------------------------------------------------------------------
-- 8. SUBMIT TRANSACTION FUNCTION (Main Entry Point)
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ussd_core.submit_transaction(
    p_idempotency_key VARCHAR,
    p_transaction_type_code VARCHAR,
    p_initiator_account_id UUID,
    p_payload JSONB,
    p_application_id UUID DEFAULT NULL,
    p_on_behalf_of UUID DEFAULT NULL,
    p_client_timestamp TIMESTAMPTZ DEFAULT NULL,
    p_signature TEXT DEFAULT NULL
)
RETURNS TABLE (
    transaction_id BIGINT,
    transaction_uuid UUID,
    status ussd_core.transaction_status,
    transaction_hash VARCHAR(64),
    committed_at TIMESTAMPTZ
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_type_id UUID;
    v_type_record ussd_core.transaction_types%ROWTYPE;
    v_tx_id BIGINT;
    v_tx_uuid UUID;
    v_tx_hash VARCHAR(64);
    v_committed_at TIMESTAMPTZ;
    v_validation_result RECORD;
    v_can_execute RECORD;
BEGIN
    -- Look up transaction type
    SELECT * INTO v_type_record
    FROM ussd_core.transaction_types
    WHERE type_code = p_transaction_type_code AND valid_to IS NULL;
    
    IF NOT FOUND THEN
        PERFORM ussd_core.log_rejected_transaction(
            p_idempotency_key, NULL, p_application_id, p_initiator_account_id,
            p_payload, 'Transaction type not found: ' || p_transaction_type_code, 'TYPE_NOT_FOUND'
        );
        RAISE EXCEPTION 'Transaction type not found: %', p_transaction_type_code;
    END IF;
    
    v_type_id := v_type_record.type_id;
    
    -- Check if account can execute this type
    SELECT * INTO v_can_execute FROM ussd_core.can_execute_type(p_initiator_account_id, v_type_id);
    IF NOT v_can_execute.allowed THEN
        PERFORM ussd_core.log_rejected_transaction(
            p_idempotency_key, v_type_id, p_application_id, p_initiator_account_id,
            p_payload, v_can_execute.reason, 'NOT_AUTHORIZED'
        );
        RAISE EXCEPTION 'Not authorized: %', v_can_execute.reason;
    END IF;
    
    -- Validate payload
    SELECT * INTO v_validation_result FROM ussd_core.validate_payload(p_payload, v_type_id);
    IF NOT v_validation_result.is_valid THEN
        PERFORM ussd_core.log_rejected_transaction(
            p_idempotency_key, v_type_id, p_application_id, p_initiator_account_id,
            p_payload, array_to_string(v_validation_result.errors, '; '), 'VALIDATION_FAILED'
        );
        RAISE EXCEPTION 'Payload validation failed: %', array_to_string(v_validation_result.errors, '; ');
    END IF;
    
    -- Extract amount and currency from payload if present
    -- This assumes standard field names, can be customized per type
    
    -- Insert the transaction
    INSERT INTO ussd_core.transactions (
        idempotency_key,
        transaction_type_id,
        application_id,
        initiator_account_id,
        on_behalf_of_account_id,
        payload,
        amount,
        currency,
        status,
        client_timestamp,
        session_id,
        client_ip,
        signature,
        partition_date
    ) VALUES (
        p_idempotency_key,
        v_type_id,
        p_application_id,
        p_initiator_account_id,
        p_on_behalf_of,
        p_payload,
        (p_payload->>'amount')::NUMERIC,
        p_payload->>'currency',
        'committed',
        p_client_timestamp,
        current_setting('app.session_id', TRUE),
        NULLIF(current_setting('app.client_ip', TRUE), '')::INET,
        p_signature,
        CURRENT_DATE
    )
    RETURNING transactions.transaction_id, transactions.transaction_uuid, 
              transactions.transaction_hash, transactions.committed_at
    INTO v_tx_id, v_tx_uuid, v_tx_hash, v_committed_at;
    
    RETURN QUERY SELECT v_tx_id, v_tx_uuid, 'committed'::ussd_core.transaction_status, 
                        v_tx_hash, v_committed_at;
END;
$$;

-- ----------------------------------------------------------------------------
-- 9. ROW LEVEL SECURITY
-- ----------------------------------------------------------------------------
ALTER TABLE ussd_core.transactions ENABLE ROW LEVEL SECURITY;

-- Policy: Can see own transactions
CREATE POLICY transactions_own_access ON ussd_core.transactions
    FOR SELECT
    USING (
        initiator_account_id = NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID
        OR on_behalf_of_account_id = NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID
    );

-- Policy: Application-scoped access
CREATE POLICY transactions_app_access ON ussd_core.transactions
    FOR SELECT
    USING (
        application_id = NULLIF(current_setting('app.application_id', TRUE), '')::UUID
    );

-- Policy: Admin access
CREATE POLICY transactions_admin_access ON ussd_core.transactions
    FOR ALL
    USING (
        NULLIF(current_setting('app.is_admin', TRUE), '')::BOOLEAN = TRUE
    );

-- ----------------------------------------------------------------------------
-- 10. VIEWS
-- ----------------------------------------------------------------------------

-- Recent transactions view
CREATE VIEW ussd_core.recent_transactions AS
SELECT *
FROM ussd_core.transactions
WHERE committed_at > NOW() - INTERVAL '24 hours'
ORDER BY committed_at DESC;

-- Transactions by application (for multi-tenant queries)
CREATE VIEW ussd_core.application_transactions AS
SELECT 
    t.*,
    tt.type_code,
    tt.category,
    tt.name as type_name
FROM ussd_core.transactions t
JOIN ussd_core.transaction_types tt ON t.transaction_type_id = tt.type_id
WHERE t.application_id IS NOT NULL;

-- Transaction chain view (for verification)
CREATE VIEW ussd_core.transaction_chains AS
WITH chain AS (
    SELECT 
        t.*,
        LAG(t.transaction_hash) OVER (
            PARTITION BY t.initiator_account_id 
            ORDER BY t.committed_at, t.transaction_id
        ) as expected_previous_hash
    FROM ussd_core.transactions t
)
SELECT 
    c.*,
    CASE 
        WHEN c.previous_hash IS NULL AND c.expected_previous_hash IS NULL THEN TRUE
        WHEN c.previous_hash = c.expected_previous_hash THEN TRUE
        ELSE FALSE
    END as chain_valid
FROM chain c;

-- ----------------------------------------------------------------------------
-- 11. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_core.transactions IS 
    'IMMUTABLE: The core transaction log - append only, cryptographically chained. NO UPDATES OR DELETES ALLOWED.';
COMMENT ON COLUMN ussd_core.transactions.previous_hash IS 
    'Hash of previous transaction for this account - creates tamper-evident chain';
COMMENT ON COLUMN ussd_core.transactions.transaction_hash IS 
    'Cryptographic hash of this transaction including previous_hash';
COMMENT ON COLUMN ussd_core.transactions.record_hash IS 
    'Row-level integrity hash for verification';
COMMENT ON COLUMN ussd_core.transactions.block_id IS 
    'Reference to block for Merkle tree batching';
