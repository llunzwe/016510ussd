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

-- -----------------------------------------------------------------------------
-- TODO[PRIMARY_KEY]: Define composite primary key for partitioned table
-- -----------------------------------------------------------------------------
-- DECISION: Must include partition key (partition_date) for partition-local uniqueness
-- IMPLEMENTATION:
--   transaction_id BIGSERIAL,  -- Global unique across partitions
--   partition_date DATE NOT NULL DEFAULT CURRENT_DATE,
--   PRIMARY KEY (transaction_id, partition_date)
--
-- NOTE: Use BIGSERIAL for transaction_id to handle high volume (9 quintillion max)

-- -----------------------------------------------------------------------------
-- TODO[FOREIGN_KEYS]: Define referential integrity
-- -----------------------------------------------------------------------------
-- 1. transaction_type_id -> ussd_core.transaction_types(type_id)
--    ON DELETE RESTRICT (never delete transaction types)
--
-- 2. initiator_account_id -> ussd_core.account_registry(account_id)
--    ON DELETE RESTRICT
--
-- 3. on_behalf_of_account_id -> ussd_core.account_registry(account_id) [nullable]
--    ON DELETE RESTRICT
--
-- 4. parent_transaction_id -> self-reference (transaction_id, partition_date)
--    No FK possible for partitioned self-reference; enforce via trigger or app
--
-- 5. block_id -> ussd_core.blocks(block_id) [nullable, set after block creation]

-- -----------------------------------------------------------------------------
-- TODO[UNIQUE_CONSTRAINTS]: Ensure data integrity
-- -----------------------------------------------------------------------------
-- 1. Idempotency key (globally unique):
--    CREATE UNIQUE INDEX idx_transactions_idempotency 
--        ON ussd_core.transactions(idempotency_key);
--
-- 2. Transaction UUID (for external references):
--    CREATE UNIQUE INDEX idx_transactions_uuid 
--        ON ussd_core.transactions(transaction_uuid);
--
-- 3. Hash chain integrity (hash must be unique):
--    CREATE UNIQUE INDEX idx_transactions_hash_unique 
--        ON ussd_core.transactions(transaction_hash);

-- -----------------------------------------------------------------------------
-- TODO[INDEXES]: Performance-critical indexes
-- -----------------------------------------------------------------------------
-- 1. Hash chain lookups:
--    CREATE INDEX idx_transactions_prev_hash ON ussd_core.transactions(previous_hash);
--
-- 2. Account-specific chain (for verification):
--    CREATE INDEX idx_transactions_initiator_chain 
--        ON ussd_core.transactions(initiator_account_id, committed_at, transaction_hash);
--
-- 3. Time-series queries:
--    CREATE INDEX idx_transactions_committed_at 
--        ON ussd_core.transactions(committed_at DESC);
--
-- 4. Block assignment:
--    CREATE INDEX idx_transactions_block ON ussd_core.transactions(block_id) 
--        WHERE block_id IS NOT NULL;
--
-- 5. Application queries:
--    CREATE INDEX idx_transactions_app_type_time 
--        ON ussd_core.transactions(application_id, transaction_type_id, committed_at DESC);
--
-- 6. Status monitoring:
--    CREATE INDEX idx_transactions_status ON ussd_core.transactions(status) 
--        WHERE status IN ('pending', 'failed');
--
-- 7. JSONB payload search:
--    CREATE INDEX idx_transactions_payload_gin ON ussd_core.transactions USING gin(payload);

-- -----------------------------------------------------------------------------
-- TODO[PARTITIONING]: Setup range partitioning by date
-- -----------------------------------------------------------------------------
-- CREATE TABLE ussd_core.transactions (
--     ...columns...
-- ) PARTITION BY RANGE (partition_date);
--
-- Create monthly partitions:
-- CREATE TABLE ussd_core.transactions_2024_01 
--     PARTITION OF ussd_core.transactions
--     FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
--
-- TODO: Create partition management function for automated partition creation

-- -----------------------------------------------------------------------------
-- TODO[HYPERTABLE]: Convert to TimescaleDB hypertable (optional)
-- -----------------------------------------------------------------------------
-- IF using TimescaleDB extension:
--   SELECT create_hypertable('ussd_core.transactions', 'partition_date', 
--                            chunk_time_interval => INTERVAL '1 month');
--
-- BENEFITS: Automatic partitioning, compression, continuous aggregates
-- REQUIREMENTS: TimescaleDB extension installation

-- -----------------------------------------------------------------------------
-- TODO[IMMUTABILITY_TRIGGERS]: STRICT prevention of updates/deletes
-- -----------------------------------------------------------------------------
-- CRITICAL: These triggers must be created IMMEDIATELY after table creation
--
-- CREATE TRIGGER trg_transactions_prevent_update
--     BEFORE UPDATE ON ussd_core.transactions
--     FOR EACH ROW
--     EXECUTE FUNCTION ussd_core.prevent_update();
--
-- CREATE TRIGGER trg_transactions_prevent_delete
--     BEFORE DELETE ON ussd_core.transactions
--     FOR EACH ROW
--     EXECUTE FUNCTION ussd_core.prevent_delete();

-- -----------------------------------------------------------------------------
-- TODO[IDEMPOTENCY_CHECK]: Prevent duplicate submissions
-- -----------------------------------------------------------------------------
-- CREATE OR REPLACE FUNCTION ussd_core.check_idempotency()
-- RETURNS TRIGGER
-- LANGUAGE plpgsql
-- AS $$
-- BEGIN
--     IF EXISTS (SELECT 1 FROM ussd_core.transactions WHERE idempotency_key = NEW.idempotency_key) THEN
--         RAISE EXCEPTION 'IDEMPOTENCY_VIOLATION: Transaction with key % already exists',
--             NEW.idempotency_key USING ERRCODE = 'P0002';
--     END IF;
--     RETURN NEW;
-- END;
-- $$;
--
-- CREATE TRIGGER trg_transactions_check_idempotency
--     BEFORE INSERT ON ussd_core.transactions
--     FOR EACH ROW
--     EXECUTE FUNCTION ussd_core.check_idempotency();

-- -----------------------------------------------------------------------------
-- TODO[HASH_CHAINING]: Cryptographic hash computation
-- -----------------------------------------------------------------------------
-- CREATE OR REPLACE FUNCTION ussd_core.compute_transaction_record_hash()
-- RETURNS TRIGGER
-- LANGUAGE plpgsql
-- AS $$
-- DECLARE
--     v_previous_hash VARCHAR(64);
-- BEGIN
--     -- Get previous hash in the account chain
--     SELECT transaction_hash INTO v_previous_hash
--     FROM ussd_core.transactions
--     WHERE initiator_account_id = NEW.initiator_account_id
--     ORDER BY committed_at DESC, transaction_id DESC
--     LIMIT 1;
--     
--     NEW.previous_hash := v_previous_hash;
--     
--     -- Compute transaction hash
--     NEW.transaction_hash := ussd_core.generate_hash(
--         COALESCE(v_previous_hash, '') || 
--         NEW.transaction_uuid::TEXT || 
--         NEW.transaction_type_id::TEXT || 
--         NEW.initiator_account_id::TEXT || 
--         COALESCE(NEW.on_behalf_of_account_id::TEXT, '') ||
--         COALESCE(NEW.payload::TEXT, '{}') || 
--         NEW.committed_at::TEXT ||
--         NEW.idempotency_key
--     );
--     
--     -- Compute row-level record hash
--     NEW.record_hash := ussd_core.generate_hash(
--         NEW.transaction_id::TEXT || NEW.transaction_hash || NEW.committed_at::TEXT
--     );
--     
--     RETURN NEW;
-- END;
-- $$;

-- -----------------------------------------------------------------------------
-- TODO[SUBMIT_FUNCTION]: Main transaction submission entry point
-- -----------------------------------------------------------------------------
-- ussd_core.submit_transaction(
--     p_idempotency_key VARCHAR,
--     p_transaction_type_code VARCHAR,
--     p_initiator_account_id UUID,
--     p_payload JSONB,
--     p_application_id UUID DEFAULT NULL,
--     p_on_behalf_of UUID DEFAULT NULL,
--     p_client_timestamp TIMESTAMPTZ DEFAULT NULL,
--     p_signature TEXT DEFAULT NULL
-- ) RETURNS TABLE (transaction_id, transaction_uuid, status, transaction_hash, committed_at)
--
-- Implementation steps:
-- 1. Lookup transaction_type_id from type_code
-- 2. Validate payload against transaction type schema
-- 3. Check account can execute this type (membership, limits)
-- 4. Insert transaction record
-- 5. Return transaction details

-- -----------------------------------------------------------------------------
-- TODO[REJECTION_LOG]: Separate table for rejected transactions
-- -----------------------------------------------------------------------------
-- CREATE TABLE ussd_audit.rejected_transactions (
--     rejection_id BIGSERIAL PRIMARY KEY,
--     idempotency_key VARCHAR(255) NOT NULL,
--     transaction_type_id UUID,
--     application_id UUID,
--     initiator_account_id UUID,
--     payload JSONB,
--     rejection_reason TEXT NOT NULL,
--     rejection_code VARCHAR(50),
--     rejected_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
--     client_ip INET,
--     session_id TEXT
-- );

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
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
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    PRIMARY KEY (transaction_id, partition_date)
) PARTITION BY RANGE (partition_date);
*/

-- -----------------------------------------------------------------------------
-- IMPLEMENTATION NOTES
-- -----------------------------------------------------------------------------
-- 1. PARTITION MANAGEMENT: Automate partition creation with pg_partman or custom cron
-- 2. ARCHIVAL: Old partitions can be detached and archived to cold storage
-- 3. COMPRESSION: Consider TimescaleDB compression for partitions > 6 months old
-- 4. RETENTION: Implement retention policy (7 years typical for financial data)
-- 5. VERIFICATION: Regular hash chain verification via transaction_chains view
-- 6. BACKUPS: Transaction log is the MOST CRITICAL table - ensure WAL archiving

-- =============================================================================
-- END OF FILE
-- =============================================================================
