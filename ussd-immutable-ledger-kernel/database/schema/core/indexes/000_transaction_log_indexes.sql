-- =============================================================================
-- USSD KERNEL CORE SCHEMA - INDEXES
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    000_transaction_log_indexes.sql
-- SCHEMA:      core
-- CATEGORY:    Indexes - Transaction Log
-- DESCRIPTION: Performance indexes for transaction_log table with
--              hash chain, account lookup, and time-series optimization.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Query performance monitoring
└── A.14.2 Business continuity - Performance requirements

ISO/IEC 27040:2024 (Storage Security)
├── Index integrity: Consistent with data
├── Query performance: Audit query support
└── Verification performance: Hash chain verification speed

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. INDEX TYPES
   - B-tree: Default, good for equality and range
   - GIN: JSONB and array indexing
   - BRIN: Block range for time-series
   - Partial: Conditional indexing
   - Covering: Include columns for index-only scans

2. INDEX NAMING
   - idx_{table}_{column}_{type}
   - Descriptive and consistent
   - Type suffix for special indexes

3. INDEX MAINTENANCE
   - Regular REINDEX
   - Bloat monitoring
   - Usage statistics review

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

INDEX SECURITY:
- Indexes inherit table RLS
   - No sensitive data in indexes
   - Access via table policies

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEX SELECTION:
1. Hash Chain Indexes
   - previous_hash: Chain verification
   - current_hash: Direct lookup
   - chain_sequence: Global ordering

2. Account Indexes
   - initiator_account_id + account_sequence: Account history
   - beneficiary_account_id: Incoming transactions

3. Time Indexes
   - committed_at DESC: Recent queries
   - partition_date: Partition pruning

4. Status Indexes
   - Partial index on pending: Monitoring queries

5. JSONB Indexes
   - GIN on payload: Payload search

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- INDEX_CREATED
   - INDEX_DROPPED
   - INDEX_REINDEXED

RETENTION: 2 years
================================================================================
*/

-- =============================================================================
-- PRIMARY KEY INDEX
-- Description: Partition-local unique identifier
-- Status: IMPLEMENTED (defined in table creation)
-- =============================================================================
-- Note: Primary key is defined in table creation as (transaction_id, partition_date)
-- This is a composite key that includes the partition key for proper partition pruning

COMMENT ON CONSTRAINT transaction_log_pkey ON core.transaction_log IS 
    'Primary key on (transaction_id, partition_date) for partition-local uniqueness';

-- =============================================================================
-- HASH CHAIN INDEXES
-- Description: Support hash chain verification
-- Status: IMPLEMENTED (indexes created below)
-- =============================================================================

-- Index on previous_hash for chain verification
-- This is critical for verifying the integrity of the hash chain
CREATE INDEX IF NOT EXISTS idx_transaction_log_previous_hash 
    ON core.transaction_log(previous_hash)
    WHERE previous_hash IS NOT NULL;

COMMENT ON INDEX core.idx_transaction_log_previous_hash IS 
    'Hash chain verification: Find transaction by previous_hash';

-- Index on transaction_hash for direct lookup
CREATE UNIQUE INDEX IF NOT EXISTS idx_transaction_log_transaction_hash 
    ON core.transaction_log(transaction_hash);

COMMENT ON INDEX core.idx_transaction_log_transaction_hash IS 
    'Unique index on transaction_hash for direct hash lookups';

-- Index on chain_sequence for global ordering
CREATE UNIQUE INDEX IF NOT EXISTS idx_transaction_log_chain_sequence 
    ON core.transaction_log(chain_sequence)
    WHERE chain_sequence IS NOT NULL;

COMMENT ON INDEX core.idx_transaction_log_chain_sequence IS 
    'Global transaction ordering by chain_sequence';

-- Index on account_sequence for per-account ordering
CREATE INDEX IF NOT EXISTS idx_transaction_log_account_sequence 
    ON core.transaction_log(initiator_account_id, account_sequence)
    WHERE account_sequence IS NOT NULL;

COMMENT ON INDEX core.idx_transaction_log_account_sequence IS 
    'Per-account transaction ordering by account_sequence';

-- =============================================================================
-- ACCOUNT LOOKUP INDEXES
-- Description: Support account-based queries
-- =============================================================================

-- Index for initiator account queries (most common)
CREATE INDEX IF NOT EXISTS idx_transaction_log_initiator 
    ON core.transaction_log(initiator_account_id, committed_at DESC, transaction_id);

COMMENT ON INDEX core.idx_transaction_log_initiator IS 
    'Account history queries: initiator transactions ordered by time';

-- Index for beneficiary account queries (incoming transactions)
CREATE INDEX IF NOT EXISTS idx_transaction_log_beneficiary 
    ON core.transaction_log(beneficiary_account_id, committed_at DESC)
    WHERE beneficiary_account_id IS NOT NULL;

COMMENT ON INDEX core.idx_transaction_log_beneficiary IS 
    'Incoming transaction queries: beneficiary transactions';

-- Index for on_behalf_of queries (delegated transactions)
CREATE INDEX IF NOT EXISTS idx_transaction_log_on_behalf 
    ON core.transaction_log(on_behalf_of_account_id, committed_at DESC)
    WHERE on_behalf_of_account_id IS NOT NULL;

COMMENT ON INDEX core.idx_transaction_log_on_behalf IS 
    'Delegated transaction queries: on_behalf_of transactions';

-- Combined index for any-party queries
CREATE INDEX IF NOT EXISTS idx_transaction_log_any_party 
    ON core.transaction_log(initiator_account_id, beneficiary_account_id, committed_at DESC);

COMMENT ON INDEX core.idx_transaction_log_any_party IS 
    'Multi-party transaction queries';

-- =============================================================================
-- REFERENCE INDEXES
-- Description: Support external reference lookups
-- =============================================================================

-- Unique index on transaction_uuid
CREATE UNIQUE INDEX IF NOT EXISTS idx_transaction_log_uuid 
    ON core.transaction_log(transaction_uuid);

COMMENT ON INDEX core.idx_transaction_log_uuid IS 
    'External reference lookup by transaction_uuid';

-- Unique index on idempotency_key
CREATE UNIQUE INDEX IF NOT EXISTS idx_transaction_log_idempotency 
    ON core.transaction_log(idempotency_key);

COMMENT ON INDEX core.idx_transaction_log_idempotency IS 
    'Idempotency check: prevent duplicate transaction processing';

-- Index on parent_transaction_id for related transactions
CREATE INDEX IF NOT EXISTS idx_transaction_log_parent 
    ON core.transaction_log(parent_transaction_id)
    WHERE parent_transaction_id IS NOT NULL;

COMMENT ON INDEX core.idx_transaction_log_parent IS 
    'Child transaction lookups by parent_transaction_id';

-- =============================================================================
-- STATUS INDEXES
-- Description: Support status-based monitoring queries
-- =============================================================================

-- Partial index on pending transactions
CREATE INDEX IF NOT EXISTS idx_transaction_log_pending 
    ON core.transaction_log(status, committed_at)
    WHERE status = 'pending';

COMMENT ON INDEX core.idx_transaction_log_pending IS 
    'Pending transaction monitoring (partial index for efficiency)';

-- Partial index on failed/reversed transactions
CREATE INDEX IF NOT EXISTS idx_transaction_log_exceptions 
    ON core.transaction_log(status, committed_at)
    WHERE status IN ('failed', 'reversed');

COMMENT ON INDEX core.idx_transaction_log_exceptions IS 
    'Exception monitoring: failed and reversed transactions';

-- Index on status for general queries
CREATE INDEX IF NOT EXISTS idx_transaction_log_status 
    ON core.transaction_log(status, committed_at DESC);

COMMENT ON INDEX core.idx_transaction_log_status IS 
    'Status-based transaction queries';

-- =============================================================================
-- BLOCK INDEXES
-- Description: Support block assignment queries
-- =============================================================================

-- Index on block_id for block membership queries
CREATE INDEX IF NOT EXISTS idx_transaction_log_block 
    ON core.transaction_log(block_id, block_sequence)
    WHERE block_id IS NOT NULL;

COMMENT ON INDEX core.idx_transaction_log_block IS 
    'Block membership queries: transactions in a block';

-- Index for unblocked transactions
CREATE INDEX IF NOT EXISTS idx_transaction_log_unblocked 
    ON core.transaction_log(transaction_id, partition_date)
    WHERE block_id IS NULL;

COMMENT ON INDEX core.idx_transaction_log_unblocked IS 
    'Find transactions not yet assigned to a block';

-- =============================================================================
-- DATE/TIME INDEXES
-- Description: Support time-series queries
-- =============================================================================

-- Index on committed_at for time-based queries
CREATE INDEX IF NOT EXISTS idx_transaction_log_committed_at 
    ON core.transaction_log(committed_at DESC);

COMMENT ON INDEX core.idx_transaction_log_committed_at IS 
    'Time-series queries by commit time';

-- Index on entry_date for accounting date queries
CREATE INDEX IF NOT EXISTS idx_transaction_log_entry_date 
    ON core.transaction_log(entry_date DESC);

COMMENT ON INDEX core.idx_transaction_log_entry_date IS 
    'Accounting date queries (entry_date)';

-- Index on value_date for funds availability queries
CREATE INDEX IF NOT EXISTS idx_transaction_log_value_date 
    ON core.transaction_log(value_date DESC);

COMMENT ON INDEX core.idx_transaction_log_value_date IS 
    'Funds availability queries by value_date';

-- Combined time range index
CREATE INDEX IF NOT EXISTS idx_transaction_log_date_range 
    ON core.transaction_log(entry_date, value_date, committed_at DESC);

COMMENT ON INDEX core.idx_transaction_log_date_range IS 
    'Date range queries spanning entry and value dates';

-- BRIN index for efficient time range scans on large tables
CREATE INDEX IF NOT EXISTS idx_transaction_log_committed_brin 
    ON core.transaction_log USING BRIN(committed_at)
    WITH (pages_per_range = 128);

COMMENT ON INDEX core.idx_transaction_log_committed_brin IS 
    'BRIN index for efficient large time range scans (space-efficient)';

-- =============================================================================
-- PAYLOAD INDEXES
-- Description: Support JSONB payload queries
-- =============================================================================

-- GIN index on payload for flexible JSONB queries
CREATE INDEX IF NOT EXISTS idx_transaction_log_payload_gin 
    ON core.transaction_log USING GIN(payload jsonb_path_ops);

COMMENT ON INDEX core.idx_transaction_log_payload_gin IS 
    'JSONB payload search using GIN index';

-- Partial GIN index for specific payload types (if commonly queried)
CREATE INDEX IF NOT EXISTS idx_transaction_log_payload_reference 
    ON core.transaction_log USING GIN((payload->'reference'))
    WHERE payload ? 'reference';

COMMENT ON INDEX core.idx_transaction_log_payload_reference IS 
    'Partial index for payload reference lookups';

-- =============================================================================
-- TYPE AND AMOUNT INDEXES
-- Description: Support transaction classification and amount queries
-- =============================================================================

-- Index on transaction_type_id
CREATE INDEX IF NOT EXISTS idx_transaction_log_type 
    ON core.transaction_log(transaction_type_id, committed_at DESC);

COMMENT ON INDEX core.idx_transaction_log_type IS 
    'Transaction type queries with time ordering';

-- Index on application_id
CREATE INDEX IF NOT EXISTS idx_transaction_log_application 
    ON core.transaction_log(application_id, committed_at DESC)
    WHERE application_id IS NOT NULL;

COMMENT ON INDEX core.idx_transaction_log_application IS 
    'Application-scoped transaction queries';

-- Combined index for type + application queries
CREATE INDEX IF NOT EXISTS idx_transaction_log_type_app 
    ON core.transaction_log(transaction_type_id, application_id, committed_at DESC);

COMMENT ON INDEX core.idx_transaction_log_type_app IS 
    'Transaction type queries filtered by application';

-- Index on amount for range queries
CREATE INDEX IF NOT EXISTS idx_transaction_log_amount 
    ON core.transaction_log(amount, currency, committed_at DESC)
    WHERE amount IS NOT NULL;

COMMENT ON INDEX core.idx_transaction_log_amount IS 
    'Amount range queries (e.g., large transactions)';

-- Index on currency
CREATE INDEX IF NOT EXISTS idx_transaction_log_currency 
    ON core.transaction_log(currency, committed_at DESC)
    WHERE currency IS NOT NULL;

COMMENT ON INDEX core.idx_transaction_log_currency IS 
    'Currency-specific transaction queries';

-- =============================================================================
-- COVERING INDEXES
-- Description: Support index-only scans for common queries
-- =============================================================================

-- Covering index for account history queries (includes commonly selected columns)
CREATE INDEX IF NOT EXISTS idx_transaction_log_account_covering 
    ON core.transaction_log(initiator_account_id, committed_at DESC, transaction_id, 
        transaction_uuid, status, amount, currency)
    INCLUDE (transaction_hash, block_id);

COMMENT ON INDEX core.idx_transaction_log_account_covering IS 
    'Covering index for account history (enables index-only scans)';

-- =============================================================================
-- DIGITAL SIGNATURE INDEXES
-- Description: Support signature verification queries
-- =============================================================================

-- Index on signed transactions
CREATE INDEX IF NOT EXISTS idx_transaction_log_signed 
    ON core.transaction_log(initiator_account_id, committed_at DESC)
    WHERE signature IS NOT NULL;

COMMENT ON INDEX core.idx_transaction_log_signed IS 
    'Query signed transactions';

-- =============================================================================
-- REPLICATION/SYNC INDEXES
-- Description: Support replication and CDC
-- =============================================================================

-- Index on chain_sequence for replication ordering
CREATE INDEX IF NOT EXISTS idx_transaction_log_replication 
    ON core.transaction_log(chain_sequence, committed_at)
    WHERE chain_sequence IS NOT NULL;

COMMENT ON INDEX core.idx_transaction_log_replication IS 
    'Replication ordering by chain_sequence';

/*
================================================================================
INDEX CREATION ORDER:
1. Primary key first (required for foreign keys)
2. Unique indexes
3. Foreign key indexes
4. Query performance indexes
5. Partial indexes (WHERE clauses)
6. BRIN indexes (if applicable)

PERFORMANCE CONSIDERATIONS:
- Index maintenance adds overhead to INSERTs
- Partial indexes save space for sparse data
- GIN indexes are larger but enable flexible queries
- BRIN indexes are small but only work for sorted data

MIGRATION CHECKLIST:
□ Create primary key (including partition key)
□ Create hash chain indexes
□ Create account lookup indexes
□ Create reference indexes
□ Create status indexes
□ Create block indexes
□ Create date indexes
□ Create payload GIN indexes
□ Create type and amount indexes
□ Create BRIN indexes (optional)
□ Verify index usage with EXPLAIN ANALYZE
□ Monitor index bloat
□ Document index purposes
================================================================================
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
