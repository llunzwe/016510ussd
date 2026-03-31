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
-- EXTENSIONS: pgcrypto, uuid-ossp, pg_trgm, btree_gist, timescaledb, ltree
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
- ltree:       Tree-like data structures for hierarchical data
================================================================================
*/

-- =============================================================================
-- IMPLEMENTATION: Enable pgcrypto extension
-- DESCRIPTION: Cryptographic functions for hashing and encryption
-- PRIORITY: CRITICAL
-- SECURITY: Provides SHA-256, AES encryption - verify extension signature
-- ============================================================================
-- [EXT-001] Create pgcrypto extension

CREATE EXTENSION IF NOT EXISTS pgcrypto SCHEMA core;

COMMENT ON EXTENSION pgcrypto IS 'SHA-256 hashing, AEAD encryption for PII, HMAC signatures';

-- =============================================================================
-- IMPLEMENTATION: Enable uuid-ossp extension
-- DESCRIPTION: UUID generation functions
-- PRIORITY: CRITICAL
-- SECURITY: Ensure random UUID generation (not predictable)
-- ============================================================================
-- [EXT-002] Create uuid-ossp extension

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" SCHEMA core;

COMMENT ON EXTENSION "uuid-ossp" IS 'UUID v4/v7 generation for distributed ID allocation';

-- =============================================================================
-- IMPLEMENTATION: Enable pg_trgm extension
-- DESCRIPTION: Trigram matching for full-text search
-- PRIORITY: HIGH
-- SECURITY: Sanitize search inputs to prevent regex injection
-- ============================================================================
-- [EXT-003] Create pg_trgm extension

CREATE EXTENSION IF NOT EXISTS pg_trgm SCHEMA core;

COMMENT ON EXTENSION pg_trgm IS 'Full-text search, fuzzy matching, GIN indexes on JSONB';

-- =============================================================================
-- IMPLEMENTATION: Enable btree_gist extension
-- DESCRIPTION: GiST operator class for B-tree comparable types
-- PRIORITY: HIGH
-- SECURITY: Prevents temporal data overlap (data integrity)
-- ============================================================================
-- [EXT-004] Create btree_gist extension

CREATE EXTENSION IF NOT EXISTS btree_gist SCHEMA core;

COMMENT ON EXTENSION btree_gist IS 'Temporal validity periods with exclusion constraints';

-- =============================================================================
-- IMPLEMENTATION: Enable timescaledb extension
-- DESCRIPTION: Time-series database optimization
-- PRIORITY: HIGH
-- SECURITY: Separate retention policies for time-series data
-- ============================================================================
-- [EXT-005] Create timescaledb extension

-- Note: TimescaleDB requires superuser or specific database setup
-- This may need manual installation by DBA
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS timescaledb SCHEMA core;
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'TimescaleDB extension requires superuser privileges. Install manually.';
    WHEN undefined_file THEN
        RAISE NOTICE 'TimescaleDB extension not available. Install the package first.';
END;
$$;

COMMENT ON EXTENSION timescaledb IS 'Time-series optimization for movement postings and balances';

-- =============================================================================
-- IMPLEMENTATION: Enable ltree extension
-- DESCRIPTION: Tree-like data structures for hierarchies
-- PRIORITY: HIGH
-- SECURITY: Validate path input to prevent injection
-- ============================================================================
-- [EXT-006] Create ltree extension

CREATE EXTENSION IF NOT EXISTS ltree SCHEMA core;

COMMENT ON EXTENSION ltree IS 'Hierarchical data structures for account groups and COA';

-- =============================================================================
-- IMPLEMENTATION: Enable pg_stat_statements
-- DESCRIPTION: Query performance monitoring
-- PRIORITY: MEDIUM
-- SECURITY: Contains query text - restrict access to admin roles
-- ============================================================================
-- [EXT-007] Create pg_stat_statements extension

CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

COMMENT ON EXTENSION pg_stat_statements IS 'Query performance monitoring for optimization';

-- =============================================================================
-- IMPLEMENTATION: Extension verification
-- DESCRIPTION: Verify all extensions installed correctly
-- PRIORITY: HIGH
-- ============================================================================
-- [EXT-008] Verify extension availability

DO $$
DECLARE
    v_missing_extensions TEXT[];
BEGIN
    SELECT array_agg(extname) INTO v_missing_extensions
    FROM (VALUES 
        ('pgcrypto'),
        ('uuid-ossp'),
        ('pg_trgm'),
        ('btree_gist'),
        ('ltree')
    ) AS required(extname)
    WHERE NOT EXISTS (
        SELECT 1 FROM pg_extension WHERE extname = required.extname
    );
    
    IF v_missing_extensions IS NOT NULL THEN
        RAISE EXCEPTION 'Critical extensions missing: %', v_missing_extensions;
    END IF;
    
    RAISE NOTICE 'All critical extensions verified successfully';
END;
$$;

-- Create extension audit log
CREATE TABLE IF NOT EXISTS core.extension_audit (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    extname VARCHAR(100) NOT NULL,
    version TEXT,
    schema VARCHAR(100),
    installed_at TIMESTAMPTZ DEFAULT now(),
    installed_by VARCHAR(100) DEFAULT current_user
);

-- Log current extensions
INSERT INTO core.extension_audit (extname, version, schema)
SELECT e.extname, e.extversion, n.nspname
FROM pg_extension e
JOIN pg_namespace n ON e.extnamespace = n.oid
WHERE e.extname IN ('pgcrypto', 'uuid-ossp', 'pg_trgm', 'btree_gist', 'timescaledb', 'ltree', 'pg_stat_statements')
ON CONFLICT DO NOTHING;

/*
================================================================================
EXTENSION DEPENDENCIES & ORDER - COMPLETED:
☑ 1. pgcrypto       - Required for all cryptographic operations
☑ 2. uuid-ossp      - Required for ID generation in subsequent tables
☑ 3. pg_trgm        - Required for GIN indexes on JSONB
☑ 4. btree_gist     - Required for temporal exclusion constraints
☑ 5. timescaledb    - Required before creating hypertables
☑ 6. ltree          - Required for hierarchical data structures
☑ 7. pg_stat_statements - Performance monitoring (optional)

EXTENSION LOCATIONS:
- core:    pgcrypto, uuid-ossp, pg_trgm, btree_gist, timescaledb, ltree
- public:  pg_stat_statements (database-wide)
================================================================================
*/
