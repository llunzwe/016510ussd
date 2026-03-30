-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Cryptographic controls)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Extension vetting)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Encryption extensions)
-- ISO/IEC 27040:2024 - Storage Security (Data integrity via crypto)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (High availability)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Extension versioning and checksum verification
-- - Schema-scoped extension installation
-- - Cryptographic extension priority loading
-- - Extension capability audit logging
-- ============================================================================
-- =============================================================================
-- MIGRATION: 002_core_extensions.sql
-- DESCRIPTION: Enable required PostgreSQL extensions
-- EXTENSIONS: pgcrypto, uuid-ossp, pg_trgm, btree_gist, timescaledb
-- DEPENDENCIES: 001_create_schemas.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 3. Immutability & Cryptographic Integrity
- Feature: Cryptographic Hashing, UUID Generation, Full-Text Search
- Source: adkjfnwr.md (Core Immutable Ledger)

BUSINESS CONTEXT:
PostgreSQL extensions required for:
- pgcrypto:    SHA-256 hashing for transaction integrity, AEAD encryption for PII
- uuid-ossp:   UUID v4/v7 generation for distributed ID allocation
- pg_trgm:     Full-text search over transaction payloads for customer support
- btree_gist:  Temporal validity periods (valid_from/valid_to)
- timescaledb: Time-series optimization for movement postings and balances
================================================================================
*/

-- =============================================================================
-- TODO: Enable pgcrypto extension
-- DESCRIPTION: Cryptographic functions for hashing and encryption
-- PRIORITY: CRITICAL
-- SECURITY: Provides SHA-256, AES encryption - verify extension signature
-- ============================================================================
-- TODO: [EXT-001] Create pgcrypto extension
-- INSTRUCTIONS:
--   - Required for SHA-256 hash chaining in transaction log
--   - Used for AEAD encryption of sensitive fields (PII)
--   - Required for HMAC signature verification
--   - ERROR HANDLING: Wrap in BEGIN/EXCEPTION for version mismatch
-- COMPLIANCE: ISO/IEC 27040 (Cryptographic Controls)
-- IMPLEMENTATION:
--   CREATE EXTENSION IF NOT EXISTS pgcrypto SCHEMA core;
-- 
-- USAGE EXAMPLES:
--   - Hash chaining: digest(prev_hash || transaction_data, 'sha256')
--   - PII encryption: encrypt(payload, key, 'aes-256-gcm')
--   - Signature: hmac(data, key, 'sha256')

-- =============================================================================
-- TODO: Enable uuid-ossp extension
-- DESCRIPTION: UUID generation functions
-- PRIORITY: CRITICAL
-- SECURITY: Ensure random UUID generation (not predictable)
-- ============================================================================
-- TODO: [EXT-002] Create uuid-ossp extension
-- INSTRUCTIONS:
--   - UUID v4 for random unique identifiers
--   - UUID v7 (if PostgreSQL 16+) for time-sortable identifiers
--   - Prefer UUID over bigserial for distributed systems
--   - NAMING CONVENTION: Use gen_random_uuid() for new implementations
-- COMPLIANCE: ISO/IEC 27001 (Unique Identification)
-- IMPLEMENTATION:
--   CREATE EXTENSION IF NOT EXISTS "uuid-ossp" SCHEMA core;
--
-- ALTERNATIVE for PostgreSQL 16+:
--   Use gen_random_uuid() built-in instead

-- =============================================================================
-- TODO: Enable pg_trgm extension
-- DESCRIPTION: Trigram matching for full-text search
-- PRIORITY: HIGH
-- SECURITY: Sanitize search inputs to prevent regex injection
-- ============================================================================
-- TODO: [EXT-003] Create pg_trgm extension
-- INSTRUCTIONS:
--   - Enable GIN indexes on JSONB payload fields
--   - Support fuzzy matching for reconciliation
--   - Full-text search on transaction references
--   - SEARCH PATH: Install in core schema for centralized access
-- COMPLIANCE: ISO/IEC 27018 (Data Search Controls)
-- IMPLEMENTATION:
--   CREATE EXTENSION IF NOT EXISTS pg_trgm SCHEMA core;
--
-- USE CASES:
--   - Searching transactions by external reference number
--   - Customer support: "Find payment to merchant X"
--   - Reconciliation: Fuzzy matching of transaction descriptions

-- =============================================================================
-- TODO: Enable btree_gist extension
-- DESCRIPTION: GiST operator class for B-tree comparable types
-- PRIORITY: HIGH
-- SECURITY: Prevents temporal data overlap (data integrity)
-- ============================================================================
-- TODO: [EXT-004] Create btree_gist extension
-- INSTRUCTIONS:
--   - Required for temporal validity periods with exclusion constraints
--   - Prevents overlapping time ranges for versioned records
--   - Used by: account memberships, role assignments, exchange rates
--   - TRANSACTION ISOLATION: SERIALIZABLE for temporal constraint validation
-- COMPLIANCE: ISO/IEC 27040 (Data Integrity)
-- IMPLEMENTATION:
--   CREATE EXTENSION IF NOT EXISTS btree_gist SCHEMA core;
--
-- USAGE PATTERN:
--   EXCLUDE USING gist (account_id WITH =, valid_during WITH &&)

-- =============================================================================
-- TODO: Enable timescaledb extension
-- DESCRIPTION: Time-series database optimization
-- PRIORITY: HIGH
-- SECURITY: Separate retention policies for time-series data
-- ============================================================================
-- TODO: [EXT-005] Create timescaledb extension
-- INSTRUCTIONS:
--   - Convert movement_postings to hypertable for efficient time-series queries
--   - Automatic partitioning by time
--   - Compression for historical data
--   - AUDIT LOGGING: Log all retention policy changes
-- COMPLIANCE: ISO/IEC 27040 (Storage Optimization)
-- IMPLEMENTATION:
--   CREATE EXTENSION IF NOT EXISTS timescaledb SCHEMA core;
--
-- HYPERTABLE SETUP (in migration 006):
--   SELECT create_hypertable('core.movement_postings', 'posted_at');

-- =============================================================================
-- TODO: Enable ltree extension
-- DESCRIPTION: Tree-like data structures for hierarchies
-- PRIORITY: HIGH
-- SECURITY: Validate path input to prevent injection
-- ============================================================================
-- TODO: [EXT-006] Create ltree extension
-- INSTRUCTIONS:
--   - Hierarchical account structures (groups, sub-accounts)
--   - Chart of accounts tree structure
--   - Agent relationship hierarchies
--   - ERROR HANDLING: Validate ltree path format before insertion
-- COMPLIANCE: ISO/IEC 27001 (Hierarchical Access Control)
-- IMPLEMENTATION:
--   CREATE EXTENSION IF NOT EXISTS ltree SCHEMA core;
--
-- USE CASES:
--   - Savings group with member sub-accounts
--   - COA hierarchy: Assets.Bank.Cash

-- =============================================================================
-- TODO: Enable pg_stat_statements
-- DESCRIPTION: Query performance monitoring
-- PRIORITY: MEDIUM
-- SECURITY: Contains query text - restrict access to admin roles
-- ============================================================================
-- TODO: [EXT-007] Create pg_stat_statements extension
-- INSTRUCTIONS:
--   - Track slow queries for optimization
--   - Monitor most frequent queries
--   - Required for query performance tuning
--   - RLS POLICY: Restrict pg_stat_statements view to admin roles
-- COMPLIANCE: ISO/IEC 27031 (Performance Monitoring)
-- IMPLEMENTATION:
--   CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- =============================================================================
-- TODO: Extension verification
-- DESCRIPTION: Verify all extensions installed correctly
-- PRIORITY: HIGH
-- ============================================================================
-- TODO: [EXT-008] Verify extension availability
-- INSTRUCTIONS:
--   Query to verify: SELECT * FROM pg_extension WHERE extname IN 
--   ('pgcrypto', 'uuid-ossp', 'pg_trgm', 'btree_gist', 'timescaledb', 'ltree');
--   ERROR HANDLING: Raise exception if critical extensions missing

/*
================================================================================
EXTENSION DEPENDENCIES & ORDER:
1. pgcrypto       - Required for all cryptographic operations
2. uuid-ossp      - Required for ID generation in subsequent tables
3. pg_trgm        - Required for GIN indexes on JSONB
4. btree_gist     - Required for temporal exclusion constraints
5. timescaledb    - Required before creating hypertables
6. ltree          - Required for hierarchical data structures
7. pg_stat_statements - Performance monitoring (optional)

EXTENSION LOCATIONS:
- core:    pgcrypto, uuid-ossp, pg_trgm, btree_gist, timescaledb, ltree
- public:  pg_stat_statements (database-wide)
================================================================================
*/
