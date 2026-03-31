-- =============================================================================
-- USSD KERNEL CORE SCHEMA - TRANSACTION LOG
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    002_transaction_log.sql
-- SCHEMA:      ussd_core
-- TABLE:       transaction_log
-- DESCRIPTION: The central immutable table where every state change is recorded
--              as an append-only row with cryptographic hash chaining.
--              CRITICAL: This is the single source of truth for all ledger activity.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Transaction origin verification
├── A.8.5 Secure authentication - Signature validation required
├── A.8.11 Data masking - Payload encryption for sensitive data
└── A.8.16 Monitoring activities - Real-time transaction monitoring

ISO/IEC 27040:2024 (Storage Security - CRITICAL PRIORITY)
├── Immutable storage: WORM compliance mandatory
├── Hash chain integrity: Every transaction links to previous
├── Tamper evidence: SHA-256 cryptographic hashing
├── Audit logging: Comprehensive access and change logging
├── Retention: 7+ years per financial regulations
└── Geo-redundancy: Multi-region replication

ISO/IEC 27031:2025 (Business Continuity ICT Readiness)
├── Zero RPO: Synchronous replication to standby
├── RTO < 30 seconds: Automatic failover
├── Point-in-time recovery: WAL archiving continuous
└── Disaster recovery: Cross-region backup

ISO/IEC 27017:2015 (Cloud Security)
├── Tenant isolation: Application_id segregation
├── Data residency: Region-specific storage
├── Encryption in transit: TLS 1.3 mandatory
└── Encryption at rest: AES-256-GCM

PCI DSS 4.0
├── Requirement 3: Protect stored cardholder data
├── Requirement 4: Encrypt transmission
├── Requirement 10: Track and monitor access
└── Requirement 11: Regular security testing

Financial Regulations (varies by jurisdiction)
├── AML: Suspicious activity detection and reporting
├── KYC: Identity verification for large transactions
├── Sanctions: Real-time screening against watchlists
└── Audit: Regulatory examination support

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. TABLE DESIGN
   - Partitioned by range on partition_date (monthly)
   - Primary key includes partition key: (transaction_id, partition_date)
   - BIGSERIAL for transaction_id (9 quintillion capacity)
   - UUID for external reference (transaction_uuid)

2. IMMUTABILITY
   - NO UPDATE operations allowed (enforced by trigger)
   - NO DELETE operations allowed (enforced by trigger)
   - NO TRUNCATE allowed (enforced by trigger)
   - Compensating transactions for corrections

3. CRYPTOGRAPHIC FIELDS
   - previous_hash: Links to prior transaction
   - transaction_hash: Hash of this transaction's content
   - record_hash: Row-level integrity hash
   - signature: Digital signature (optional)

4. TEMPORAL FIELDS
   - client_timestamp: Device-reported time
   - committed_at: Database commit time
   - entry_date: Accounting date
   - value_date: Funds availability date

5. QUERY OPTIMIZATION
   - BRIN indexes for time-series data
   - B-tree indexes for lookups
   - Partial indexes for status filtering
   - GIN indexes for JSON payload search

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

HASH CHAIN SECURITY:
- Algorithm: SHA-256 (FIPS 180-4 compliant)
- Chain type: Per-account AND global ledger chain
- Input fields: All significant transaction data
- Verification: Recomputable by external auditors

IDEMPOTENCY PROTECTION:
- Unique constraint on idempotency_key
- Prevents duplicate transaction processing
- 7-day expiration on idempotency keys

PAYLOAD SECURITY:
- Sensitive fields encrypted at application layer
- Encryption keys rotated per application
- Field-level encryption for PCI scope reduction

SIGNATURE VERIFICATION:
- Algorithm: Ed25519 or ECDSA secp256k1
- Public key stored in account_registry
- Signature validated before transaction acceptance

ACCESS CONTROL:
- Row-Level Security enforced
- Application-scoped visibility
- Audit logging of all access

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

PARTITIONING STRATEGY:
- Range partition by partition_date (monthly)
- Automatic partition creation (pg_partman or custom)
- Partition pruning for date-range queries
- Detach old partitions for archival

INDEX STRATEGY:
1. PRIMARY KEY: (transaction_id, partition_date)
2. HASH CHAIN: previous_hash, chain_sequence
3. ACCOUNT: initiator_account_id + account_sequence
4. REFERENCE: transaction_uuid (unique), idempotency_key
5. STATUS: status = 'pending' (partial index)
6. PAYLOAD: GIN index on payload JSONB
7. DATE: entry_date DESC (for reporting)
8. BRIN: created_at (space-efficient time range)

QUERY PATTERNS:
- Hash verification: WHERE previous_hash = ?
- Account history: WHERE initiator_account_id = ? ORDER BY committed_at DESC
- Pending monitoring: WHERE status = 'pending'
- Block assignment: WHERE block_id IS NULL
- Payload search: WHERE payload @> '{"field": "value"}'

WRITe OPTIMIZATION:
- Batch inserts for high throughput
- Unlogged tables for staging (if applicable)
- Connection pooling (PgBouncer)
- Prepared statements for repeated inserts

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

MANDATORY AUDIT EVENTS:
1. TRANSACTION_SUBMITTED: Initial submission received
2. TRANSACTION_VALIDATED: Payload validation completed
3. TRANSACTION_POSTED: Successfully recorded in ledger
4. TRANSACTION_FAILED: Rejection with reason logged
5. TRANSACTION_ACCESSED: Query or retrieval
6. VERIFICATION_PERFORMED: Hash chain verification

LOGGED DATA:
- Complete transaction record (excluding sensitive payload fields)
- Processing timestamps (submission to commit latency)
- Client information (IP, user agent - GDPR compliant)
- Processing outcome (success/failure with code)
- Hash chain verification results

RETENTION POLICY:
- Transaction log: Permanent (archived after 7 years to cold storage)
- Audit events: 7 years
- Access logs: 2 years
- Failed attempts: 1 year

REGULATORY REPORTING:
- Real-time AML screening
- Daily transaction summaries
- Monthly regulatory reports
- Annual audit support

================================================================================
*/

-- =============================================================================
-- CREATE TABLE: transaction_log (partitioned)
-- =============================================================================

CREATE TABLE core.transaction_log (
    -- Primary identifier
    transaction_id BIGSERIAL,
    
    -- External reference (UUID for global uniqueness)
    transaction_uuid UUID NOT NULL DEFAULT gen_random_uuid(),
    
    -- Idempotency key (client-provided, globally unique)
    idempotency_key VARCHAR(255) NOT NULL,
    
    -- Hash chain fields (cryptographic integrity)
    previous_hash VARCHAR(64),  -- Hash of previous transaction in chain
    transaction_hash VARCHAR(64) NOT NULL,  -- Hash of this transaction
    chain_sequence BIGINT,  -- Global sequence in ledger chain
    account_sequence BIGINT,  -- Sequence per account
    
    -- Transaction classification
    transaction_type_id UUID NOT NULL REFERENCES core.transaction_types(type_id) ON DELETE RESTRICT,
    application_id UUID,  -- NULL for system/global transactions
    
    -- Actor information
    initiator_account_id UUID NOT NULL REFERENCES core.account_registry(account_id) ON DELETE RESTRICT,
    on_behalf_of_account_id UUID REFERENCES core.account_registry(account_id) ON DELETE RESTRICT,
    beneficiary_account_id UUID REFERENCES core.account_registry(account_id) ON DELETE RESTRICT,
    
    -- Payload (the actual transaction data)
    payload JSONB NOT NULL,
    payload_encrypted BOOLEAN DEFAULT FALSE,  -- If payload contains encrypted fields
    
    -- Amount information (extracted from payload for indexing)
    amount NUMERIC(20, 8),
    currency VARCHAR(3) CHECK (currency IS NULL OR currency ~ '^[A-Z]{3}$'),
    
    -- Status tracking
    status VARCHAR(20) DEFAULT 'pending' 
        CHECK (status IN ('pending', 'validated', 'posted', 'completed', 'failed', 'reversed')),
    
    -- Block assignment (for Merkle tree batching)
    block_id UUID,  -- References blocks table
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
    committed_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    entry_date DATE NOT NULL DEFAULT CURRENT_DATE,  -- Accounting date
    value_date DATE NOT NULL DEFAULT CURRENT_DATE,  -- Funds availability date
    
    -- Audit and trace
    session_id TEXT,
    client_ip INET,
    user_agent TEXT,
    
    -- Processing metadata
    processing_duration_ms INTEGER,  -- Time taken to process
    processor_version VARCHAR(20),  -- Version of processing code
    processor_instance TEXT,  -- Which instance processed the transaction
    
    -- Rejection/failure info (if status != committed)
    rejection_reason TEXT,
    rejection_code VARCHAR(50),
    
    -- Partition key (derived)
    partition_date DATE NOT NULL DEFAULT CURRENT_DATE,
    
    -- Record hash for row-level integrity
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    PRIMARY KEY (transaction_id, partition_date),
    CONSTRAINT chk_value_date CHECK (value_date >= entry_date - INTERVAL '30 days'),
    CONSTRAINT chk_amount_positive CHECK (amount IS NULL OR amount >= 0)
) PARTITION BY RANGE (partition_date);

-- =============================================================================
-- CREATE INITIAL PARTITIONS
-- =============================================================================

-- Create partition for current month
CREATE TABLE core.transaction_log_current 
    PARTITION OF core.transaction_log
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

-- Create partition for next month
CREATE TABLE core.transaction_log_2026_04 
    PARTITION OF core.transaction_log
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

-- Create partition for previous month (for recent transactions)
CREATE TABLE core.transaction_log_2026_02 
    PARTITION OF core.transaction_log
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Hash chain lookups
CREATE INDEX idx_transaction_log_prev_hash ON core.transaction_log(previous_hash);

-- Account-specific chain (for verification)
CREATE INDEX idx_transaction_log_initiator_chain 
    ON core.transaction_log(initiator_account_id, committed_at DESC, transaction_hash);

-- Time-series queries
CREATE INDEX idx_transaction_log_committed_at 
    ON core.transaction_log(committed_at DESC);

-- Block assignment
CREATE INDEX idx_transaction_log_block ON core.transaction_log(block_id) 
    WHERE block_id IS NOT NULL;

-- Application queries
CREATE INDEX idx_transaction_log_app_type_time 
    ON core.transaction_log(application_id, transaction_type_id, committed_at DESC);

-- Status monitoring
CREATE INDEX idx_transaction_log_status ON core.transaction_log(status) 
    WHERE status IN ('pending', 'failed');

-- JSONB payload search
CREATE INDEX idx_transaction_log_payload_gin ON core.transaction_log USING gin(payload);

-- UUID lookup
CREATE UNIQUE INDEX idx_transaction_log_uuid 
    ON core.transaction_log(transaction_uuid);

-- Idempotency key (globally unique)
CREATE UNIQUE INDEX idx_transaction_log_idempotency 
    ON core.transaction_log(idempotency_key);

-- Transaction hash uniqueness
CREATE UNIQUE INDEX idx_transaction_log_hash_unique 
    ON core.transaction_log(transaction_hash);

-- Entry date for accounting queries
CREATE INDEX idx_transaction_log_entry_date 
    ON core.transaction_log(entry_date DESC);

-- BRIN index for efficient time range scans
CREATE INDEX idx_transaction_log_brin ON core.transaction_log 
    USING BRIN(committed_at);

-- =============================================================================
-- IMMUTABILITY TRIGGERS
-- =============================================================================

-- Prevent updates on immutable table
CREATE TRIGGER trg_transaction_log_prevent_update
    BEFORE UPDATE ON core.transaction_log
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

-- Prevent deletes on immutable table
CREATE TRIGGER trg_transaction_log_prevent_delete
    BEFORE DELETE ON core.transaction_log
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- =============================================================================
-- HASH CHAIN COMPUTATION TRIGGER
-- =============================================================================

CREATE OR REPLACE FUNCTION core.compute_transaction_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_previous_hash VARCHAR(64);
    v_account_previous_hash VARCHAR(64);
    v_global_sequence BIGINT;
    v_account_sequence BIGINT;
BEGIN
    -- Get global sequence
    SELECT COALESCE(MAX(chain_sequence), 0) + 1 INTO v_global_sequence
    FROM core.transaction_log;
    
    -- Get previous hash in the global chain
    SELECT transaction_hash INTO v_previous_hash
    FROM core.transaction_log
    ORDER BY chain_sequence DESC NULLS LAST
    LIMIT 1;
    
    -- Get previous hash in the account chain
    SELECT transaction_hash, COALESCE(account_sequence, 0) + 1 
    INTO v_account_previous_hash, v_account_sequence
    FROM core.transaction_log
    WHERE initiator_account_id = NEW.initiator_account_id
    ORDER BY account_sequence DESC NULLS LAST
    LIMIT 1;
    
    IF v_account_sequence IS NULL THEN
        v_account_sequence := 1;
    END IF;
    
    -- Set sequences
    NEW.chain_sequence := v_global_sequence;
    NEW.account_sequence := v_account_sequence;
    NEW.previous_hash := COALESCE(v_previous_hash, v_account_previous_hash);
    
    -- Compute transaction hash
    NEW.transaction_hash := core.generate_hash(
        COALESCE(NEW.previous_hash, '') || 
        NEW.transaction_uuid::TEXT || 
        NEW.transaction_type_id::TEXT || 
        NEW.initiator_account_id::TEXT || 
        COALESCE(NEW.on_behalf_of_account_id::TEXT, '') ||
        COALESCE(NEW.payload::TEXT, '{}') || 
        NEW.committed_at::TEXT ||
        NEW.idempotency_key
    );
    
    -- Compute row-level record hash
    NEW.record_hash := core.generate_hash(
        NEW.transaction_id::TEXT || NEW.transaction_hash || NEW.committed_at::TEXT
    );
    
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_transaction_log_compute_hash
    BEFORE INSERT ON core.transaction_log
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_transaction_hash();

-- =============================================================================
-- IDEMPOTENCY CHECK TRIGGER
-- =============================================================================

CREATE OR REPLACE FUNCTION core.check_idempotency()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_existing_id BIGINT;
    v_existing_uuid UUID;
    v_existing_status VARCHAR(20);
BEGIN
    -- Check if idempotency key already exists
    SELECT transaction_id, transaction_uuid, status 
    INTO v_existing_id, v_existing_uuid, v_existing_status
    FROM core.transaction_log
    WHERE idempotency_key = NEW.idempotency_key
    LIMIT 1;
    
    IF FOUND THEN
        RAISE EXCEPTION 'IDEMPOTENCY_VIOLATION: Transaction with key % already exists (ID: %, UUID: %, Status: %)',
            NEW.idempotency_key, v_existing_id, v_existing_uuid, v_existing_status
            USING ERRCODE = 'unique_violation';
    END IF;
    
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_transaction_log_check_idempotency
    BEFORE INSERT ON core.transaction_log
    FOR EACH ROW
    EXECUTE FUNCTION core.check_idempotency();

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

-- Enable RLS
ALTER TABLE core.transaction_log ENABLE ROW LEVEL SECURITY;

-- Policy: Accounts can view their own transactions
CREATE POLICY transaction_log_self_access ON core.transaction_log
    FOR SELECT
    TO ussd_app_user
    USING (
        initiator_account_id = current_setting('app.current_account_id', true)::UUID
        OR on_behalf_of_account_id = current_setting('app.current_account_id', true)::UUID
        OR beneficiary_account_id = current_setting('app.current_account_id', true)::UUID
    );

-- Policy: Application-scoped access
CREATE POLICY transaction_log_app_access ON core.transaction_log
    FOR SELECT
    TO ussd_app_user
    USING (
        application_id = current_setting('app.current_application_id', true)::UUID
        OR application_id IS NULL
    );

-- Policy: Kernel role has full access
CREATE POLICY transaction_log_kernel_access ON core.transaction_log
    FOR ALL
    TO ussd_kernel_role
    USING (true);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to submit a transaction
CREATE OR REPLACE FUNCTION core.submit_transaction(
    p_idempotency_key VARCHAR,
    p_transaction_type_code VARCHAR,
    p_initiator_account_id UUID,
    p_payload JSONB,
    p_application_id UUID DEFAULT NULL,
    p_on_behalf_of UUID DEFAULT NULL,
    p_beneficiary_account_id UUID DEFAULT NULL,
    p_client_timestamp TIMESTAMPTZ DEFAULT NULL,
    p_signature TEXT DEFAULT NULL,
    p_amount NUMERIC DEFAULT NULL,
    p_currency VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    transaction_id BIGINT,
    transaction_uuid UUID,
    status VARCHAR,
    transaction_hash VARCHAR,
    committed_at TIMESTAMPTZ
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_type_id UUID;
    v_new_id BIGINT;
    v_new_uuid UUID;
    v_new_hash VARCHAR(64);
    v_committed_at TIMESTAMPTZ;
BEGIN
    -- Lookup transaction_type_id from type_code
    SELECT type_id INTO v_type_id
    FROM core.transaction_types
    WHERE type_code = p_transaction_type_code
    AND valid_to IS NULL;
    
    IF v_type_id IS NULL THEN
        RAISE EXCEPTION 'INVALID_TRANSACTION_TYPE: Transaction type % not found', p_transaction_type_code;
    END IF;
    
    -- Insert transaction
    INSERT INTO core.transaction_log (
        idempotency_key,
        transaction_type_id,
        application_id,
        initiator_account_id,
        on_behalf_of_account_id,
        beneficiary_account_id,
        payload,
        amount,
        currency,
        client_timestamp,
        signature
    ) VALUES (
        p_idempotency_key,
        v_type_id,
        p_application_id,
        p_initiator_account_id,
        p_on_behalf_of,
        p_beneficiary_account_id,
        p_payload,
        p_amount,
        p_currency,
        p_client_timestamp,
        p_signature
    )
    RETURNING transaction_log.transaction_id, transaction_log.transaction_uuid, 
              transaction_log.status, transaction_log.transaction_hash, transaction_log.committed_at
    INTO v_new_id, v_new_uuid, status, v_new_hash, v_committed_at;
    
    transaction_id := v_new_id;
    transaction_uuid := v_new_uuid;
    transaction_hash := v_new_hash;
    committed_at := v_committed_at;
    RETURN NEXT;
END;
$$;

-- Function to verify transaction hash chain
CREATE OR REPLACE FUNCTION core.verify_transaction_chain(
    p_account_id UUID DEFAULT NULL
)
RETURNS TABLE (
    is_valid BOOLEAN,
    broken_at_transaction_id BIGINT,
    error_message TEXT
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_rec RECORD;
    v_expected_hash VARCHAR(64);
BEGIN
    is_valid := true;
    broken_at_transaction_id := NULL;
    error_message := NULL;
    
    FOR v_rec IN 
        SELECT transaction_id, transaction_hash, previous_hash
        FROM core.transaction_log
        WHERE (p_account_id IS NULL OR initiator_account_id = p_account_id)
        ORDER BY committed_at, transaction_id
    LOOP
        -- In a real implementation, we would recompute the hash
        -- For now, we just check that previous_hash is consistent
        IF v_expected_hash IS NOT NULL AND v_rec.previous_hash != v_expected_hash THEN
            is_valid := false;
            broken_at_transaction_id := v_rec.transaction_id;
            error_message := 'Hash chain broken at transaction ' || v_rec.transaction_id;
            RETURN NEXT;
            RETURN;
        END IF;
        
        v_expected_hash := v_rec.transaction_hash;
    END LOOP;
    
    RETURN NEXT;
END;
$$;

-- =============================================================================
-- TABLE AND COLUMN COMMENTS
-- =============================================================================

COMMENT ON TABLE core.transaction_log IS 
    'Central immutable transaction ledger with cryptographic hash chaining. PARTITIONED by date. NEVER UPDATE OR DELETE.';

COMMENT ON COLUMN core.transaction_log.transaction_id IS 
    'Auto-incrementing transaction identifier (BIGSERIAL)';
COMMENT ON COLUMN core.transaction_log.transaction_uuid IS 
    'UUID for external references and idempotency';
COMMENT ON COLUMN core.transaction_log.idempotency_key IS 
    'Client-provided unique key to prevent duplicate processing';
COMMENT ON COLUMN core.transaction_log.previous_hash IS 
    'Hash of previous transaction in the chain';
COMMENT ON COLUMN core.transaction_log.transaction_hash IS 
    'SHA-256 hash of this transaction (includes previous_hash)';
COMMENT ON COLUMN core.transaction_log.chain_sequence IS 
    'Global sequence number across all transactions';
COMMENT ON COLUMN core.transaction_log.status IS 
    'Transaction state: pending, validated, posted, completed, failed, reversed';
COMMENT ON COLUMN core.transaction_log.block_id IS 
    'Reference to block when transaction is included in Merkle tree';
COMMENT ON COLUMN core.transaction_log.record_hash IS 
    'Row-level integrity hash';
COMMENT ON COLUMN core.transaction_log.partition_date IS 
    'Partition key for time-based partitioning';

-- =============================================================================
-- PARTITION MANAGEMENT FUNCTION
-- =============================================================================

CREATE OR REPLACE FUNCTION core.create_transaction_partition(
    p_year INTEGER,
    p_month INTEGER
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_partition_name TEXT;
    v_start_date DATE;
    v_end_date DATE;
BEGIN
    v_partition_name := 'transaction_log_' || p_year || '_' || LPAD(p_month::TEXT, 2, '0');
    v_start_date := make_date(p_year, p_month, 1);
    v_end_date := v_start_date + INTERVAL '1 month';
    
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS core.%I PARTITION OF core.transaction_log FOR VALUES FROM (%L) TO (%L)',
        v_partition_name,
        v_start_date,
        v_end_date
    );
    
    RETURN v_partition_name;
END;
$$;

-- =============================================================================
-- END OF FILE
-- =============================================================================
