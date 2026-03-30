-- =============================================================================
-- USSD KERNEL CORE SCHEMA - INDEXES
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    001_account_registry_indexes.sql
-- SCHEMA:      core
-- CATEGORY:    Indexes - Account Registry
-- DESCRIPTION: Performance indexes for account_registry table with
--              lookup, hierarchy, and search optimization.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Account lookup performance
└── A.12.4 Logging and monitoring - Query monitoring

ISO/IEC 27040:2024 (Storage Security)
├── Lookup performance: Fast account identification
└── Search performance: Compliance search support

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. LOOKUP INDEXES
   - Primary key: account_id
   - Identifier hash: Hashed lookup
   - Natural key: account_number

2. HIERARCHY INDEXES
   - LTREE GIST: Tree traversal
   - Parent: Parent-child queries

3. SEARCH INDEXES
   - Trigram GIN: Fuzzy search
   - Full-text: Text search

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

INDEX PROTECTION:
- Indexes follow table RLS policies
   - No direct index access

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEX STRATEGY:
1. Primary Lookup
   - account_id: Primary key
   - primary_identifier_hash: Unique lookup

2. Application Scope
   - primary_application_id: Application queries

3. Hierarchy
   - account_path: GIST for LTREE

4. Status
   - Partial index on active accounts

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- INDEX_CREATED
   - INDEX_USAGE_ANALYZED

RETENTION: 2 years
================================================================================
*/

-- =============================================================================
-- PRIMARY KEY INDEX
-- =============================================================================
-- ALTER TABLE core.account_registry
--     ADD CONSTRAINT pk_account_registry PRIMARY KEY (account_id);

-- =============================================================================
-- LOOKUP INDEXES
-- =============================================================================
-- CREATE UNIQUE INDEX idx_account_identifier_hash
--     ON core.account_registry(primary_identifier_hash)
--     WHERE valid_to IS NULL;

/*
================================================================================
MIGRATION CHECKLIST:
□ Create primary key index
□ Create identifier hash index
□ Create application scope index
□ Create hierarchy index (LTREE)
□ Create status partial index
□ Create search indexes (trigram)
□ Verify index usage
================================================================================
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
