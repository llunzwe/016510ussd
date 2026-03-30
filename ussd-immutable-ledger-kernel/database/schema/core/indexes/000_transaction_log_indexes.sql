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
-- TODO: [TX_IDX-001] Create primary key
-- =============================================================================
-- [Existing content preserved...]

-- =============================================================================
-- HASH CHAIN INDEXES
-- Description: Support hash chain verification
-- TODO: [TX_IDX-002] Create hash chain indexes
-- =============================================================================
-- [Existing content preserved...]

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
