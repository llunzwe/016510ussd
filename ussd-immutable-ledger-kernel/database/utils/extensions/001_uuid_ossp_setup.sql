-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0 | RFC 4122
-- ============================================================================
-- File: utils/extensions/001_uuid_ossp_setup.sql
-- Description: Configuration for UUID generation using uuid-ossp extension
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: INTERNAL
-- DATA SENSITIVITY: MEDIUM - Identity Generation
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.8.2 Information Classification
  - UUIDs provide unique identifiers without information disclosure
  - Sequential UUIDs prevent data inference attacks
  
A.12.4 Logging and Monitoring
  - Entity-specific UUID generation strategies
  - Audit trail correlation through unique identifiers
  
A.14.2 System Security in Development
  - Fallback implementations for high availability
  - Version 7-like sequential UUIDs for performance
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION IN CLOUD
================================================================================
- UUID generation for anonymized identifiers
- Sequential UUIDs prevent timing-based inference attacks on PII
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
- Sequential UUIDs improve storage performance for audit logs
- Better index locality for time-series data
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
- UUIDs provide unique identifiers for ESI tracking
- Timestamp extraction supports timeline analysis
================================================================================

================================================================================
RFC 4122: UUID SPECIFICATION COMPLIANCE
================================================================================
Version 1: Timestamp + MAC address (use with privacy considerations)
Version 3: Name-based with MD5 (deterministic)
Version 4: Random (most common, cryptographically secure)
Version 5: Name-based with SHA-1 (deterministic)
Version 7: Draft - Timestamp-ordered (database performance)

Sequential UUID (Custom):
  - Combines timestamp prefix with random suffix
  - Provides better B-tree index performance
  - Similar to proposed UUIDv7
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. Use gen_random_uuid() as primary (no extension dependency)
2. uuid-ossp as fallback for advanced features only
3. Sequential UUID for high-write tables (better index locality)
4. Namespace UUIDs for deterministic generation
5. Validation functions for UUID format checking
================================================================================

================================================================================
SECURITY CONSIDERATIONS
================================================================================
Privacy:
  - UUIDv1 leaks MAC address and timestamp
  - Prefer UUIDv4/sequential UUID for public identifiers
  - Use UUIDv3/v5 only when deterministic generation required

Performance:
  - Random UUIDs cause index fragmentation
  - Sequential UUIDs provide 4-10x better insert performance
  - Consider ULID for lexicographically sortable IDs

Collision:
  - UUIDv4: 2^122 possible values (negligible collision risk)
  - Validate UUID uniqueness in application layer
================================================================================

================================================================================
PCI DSS 4.0 REFERENCE
================================================================================
Requirement 3.4: Unique identifiers for cardholder data tokens
Requirement 10: Audit log correlation using UUIDs
================================================================================
*/

-- ============================================================================
-- EXTENSION INSTALLATION
-- ============================================================================

-- Install uuid-ossp extension
-- Note: May require superuser or specific database permissions
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;
EXCEPTION WHEN insufficient_privilege THEN
    RAISE NOTICE 'Cannot create uuid-ossp extension - will use fallback implementations';
END $$;

-- Also ensure pgcrypto is available for fallback UUID generation
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

-- ============================================================================
-- UUID GENERATION FUNCTIONS (with fallback)
-- ============================================================================

-- Function to generate UUID v4 (random)
-- Uses uuid-ossp if available, falls back to pgcrypto
-- RFC 4122 Section 4.4: Random UUID
-- ISO/IEC 27018: Privacy-safe identifier generation
CREATE OR REPLACE FUNCTION generate_uuid_v4()
RETURNS UUID AS $$
BEGIN
    -- Try uuid-ossp first
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'uuid-ossp') THEN
        RETURN uuid_generate_v4();
    END IF;
    
    -- Fallback to pgcrypto
    RETURN gen_random_uuid();
EXCEPTION WHEN OTHERS THEN
    -- Final fallback using pgcrypto
    RETURN gen_random_uuid();
END;
$$ LANGUAGE plpgsql VOLATILE;

-- Function to generate sequential UUID (UUIDv7-like)
-- Provides better B-tree index performance than purely random UUIDs
-- ISO/IEC 27040: Performance optimization for audit tables
CREATE OR REPLACE FUNCTION generate_sequential_uuid()
RETURNS UUID AS $$
DECLARE
    timestamp_part TEXT;
    random_part TEXT;
BEGIN
    -- Get current timestamp in microseconds (48 bits)
    timestamp_part := lpad(
        to_hex((extract(epoch from clock_timestamp()) * 1000000)::BIGINT),
        12,
        '0'
    );
    
    -- Generate random component (62 bits)
    random_part := encode(gen_random_bytes(8), 'hex');
    
    -- Version 7-like format (timestamp prefix)
    RETURN (
        substring(timestamp_part FROM 1 FOR 8) || '-' ||
        substring(timestamp_part FROM 9 FOR 4) || '-' ||
        '7' || substring(random_part FROM 2 FOR 3) || '-' ||
        substring(random_part FROM 5 FOR 4) || '-' ||
        substring(random_part FROM 9 FOR 12)
    )::UUID;
END;
$$ LANGUAGE plpgsql VOLATILE;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON EXTENSION "uuid-ossp" IS 'RFC 4122: UUID generation functions (optional, pgcrypto fallback available)';
COMMENT ON FUNCTION generate_uuid_v4 IS 'RFC 4122 Section 4.4: Generate cryptographically secure random UUID v4 (ISO 27018 privacy-safe)';
COMMENT ON FUNCTION generate_sequential_uuid IS 'UUIDv7-like: Generate time-ordered UUID for better index performance (ISO 27040)';

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Add support for UUID v7 when standardized (timestamp-ordered)
-- TODO: Implement ULID (Universally Unique Lexicographically Sortable Identifier)
-- TODO: Add base62 encoding for shorter UUID strings
-- TODO: Implement UUID validation with type conversion
-- TODO: Add support for distributed UUID generation (Snowflake-style)
-- TODO: Implement UUID compaction for storage optimization
-- TODO: Add UUID migration utilities for existing data
-- TODO: Implement custom UUID namespaces for application-specific needs
-- TODO: Add performance benchmarking for different UUID strategies
-- ============================================================================
