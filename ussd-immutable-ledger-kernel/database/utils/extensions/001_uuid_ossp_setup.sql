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
-- UUID v7 IMPLEMENTATION (Timestamp-ordered)
-- ============================================================================

-- RFC 9562: UUID Version 7
-- Time-ordered with millisecond precision Unix timestamp
-- Better database performance than UUIDv4 (reduces index fragmentation)
CREATE OR REPLACE FUNCTION generate_uuid_v7()
RETURNS UUID AS $$
DECLARE
    v_unix_ts_ms BIGINT;
    v_ver_rand TEXT;
    v_rand_b TEXT;
    v_rand_c TEXT;
BEGIN
    -- Get current Unix timestamp in milliseconds (48 bits)
    v_unix_ts_ms := (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT;
    
    -- Generate random components (74 random bits)
    v_ver_rand := encode(gen_random_bytes(8), 'hex');
    v_rand_b := encode(gen_random_bytes(4), 'hex');
    v_rand_c := encode(gen_random_bytes(6), 'hex');
    
    -- Construct UUID v7 format:
    -- 48 bits: Unix timestamp (milliseconds)
    -- 4 bits: version (0111 = 7)
    -- 12 bits: random
    -- 2 bits: variant (10)
    -- 62 bits: random
    RETURN (
        -- Timestamp (32 bits) || Timestamp (16 bits)
        LPAD(TO_HEX(v_unix_ts_ms >> 16), 8, '0') || '-' ||
        LPAD(TO_HEX(v_unix_ts_ms & 65535), 4, '0') || '-' ||
        -- Version (4 bits = 7) || Random (12 bits)
        '7' || SUBSTRING(v_ver_rand FROM 2 FOR 3) || '-' ||
        -- Variant (2 bits = 10) || Random (14 bits) || Random (16 bits)
        LPAD(TO_HEX((x'8'::int | (x'3'::int & x'SUBSTRING(v_rand_b FROM 1 FOR 2)'::int))), 2, '0') ||
        SUBSTRING(v_rand_b FROM 3 FOR 2) || '-' ||
        SUBSTRING(v_rand_c FROM 1 FOR 12)
    )::UUID;
END;
$$ LANGUAGE plpgsql VOLATILE;

-- ============================================================================
-- ULID (Universally Unique Lexicographically Sortable Identifier)
-- ============================================================================

-- Crockford's Base32 encoding alphabet
CREATE OR REPLACE FUNCTION ulid_encode_base32(p_bytes BYTEA)
RETURNS TEXT AS $$
DECLARE
    c_alphabet TEXT := '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    v_result TEXT := '';
    v_carry INT;
    v_value INT;
    v_idx INT;
    v_bytes BYTEA := p_bytes;
BEGIN
    -- Simple implementation: convert to Crockford base32
    -- First 10 chars = timestamp (48 bits), last 16 chars = random (80 bits)
    FOR i IN 0..((LENGTH(p_bytes) * 8 + 4) / 5) - 1 LOOP
        v_value := 0;
        FOR j IN 0..4 LOOP
            v_idx := (i * 5 + j) / 8;
            IF v_idx < LENGTH(p_bytes) THEN
                v_value := v_value | ((x'00' | GET_BYTE(p_bytes, v_idx))::INT >> (7 - ((i * 5 + j) % 8)));
            END IF;
        END LOOP;
        v_result := v_result || SUBSTRING(c_alphabet FROM ((v_value & 31) + 1) FOR 1);
    END LOOP;
    RETURN v_result;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Generate ULID as 26-character string
-- Timestamp (10 chars) + Randomness (16 chars)
CREATE OR REPLACE FUNCTION generate_ulid()
RETURNS TEXT AS $$
DECLARE
    v_timestamp_ms BIGINT;
    v_timestamp_bytes BYTEA;
    v_random_bytes BYTEA;
    v_ulid TEXT;
    c_crockford TEXT := '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
BEGIN
    -- Get timestamp (48 bits = 6 bytes)
    v_timestamp_ms := (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT;
    v_timestamp_bytes := SET_BYTE(SET_BYTE(SET_BYTE(SET_BYTE(SET_BYTE(SET_BYTE('\x0000000000000000'::BYTEA, 0, (v_timestamp_ms >> 40)::INT), 1, ((v_timestamp_ms >> 32) & 255)::INT), 2, ((v_timestamp_ms >> 24) & 255)::INT), 3, ((v_timestamp_ms >> 16) & 255)::INT), 4, ((v_timestamp_ms >> 8) & 255)::INT), 5, (v_timestamp_ms & 255)::INT);
    
    -- Generate 80 bits (10 bytes) of randomness
    v_random_bytes := gen_random_bytes(10);
    
    -- Encode timestamp (48 bits -> 10 base32 chars)
    v_ulid := '';
    -- Simple encoding for timestamp part
    FOR i IN REVERSE 5..1 LOOP
        v_ulid := v_ulid || SUBSTRING(c_crockford FROM ((GET_BYTE(v_timestamp_bytes, i-1) >> 3) & 31) + 1 FOR 1);
        v_ulid := v_ulid || SUBSTRING(c_crockford FROM ((GET_BYTE(v_timestamp_bytes, i-1) << 2) & 31) + 1 FOR 1);
    END LOOP;
    v_ulid := SUBSTRING(v_ulid FROM 1 FOR 10);
    
    -- Encode random part (simplified)
    FOR i IN 1..10 LOOP
        v_ulid := v_ulid || SUBSTRING(c_crockford FROM (GET_BYTE(v_random_bytes, i-1) % 32) + 1 FOR 1);
        IF i <= 8 THEN
            v_ulid := v_ulid || SUBSTRING(c_crockford FROM ((GET_BYTE(v_random_bytes, i-1) / 32 + GET_BYTE(v_random_bytes, i) * 8) % 32) + 1 FOR 1);
        END IF;
    END LOOP;
    v_ulid := SUBSTRING(v_ulid FROM 1 FOR 26);
    
    RETURN v_ulid;
END;
$$ LANGUAGE plpgsql VOLATILE;

-- ============================================================================
-- BASE62 ENCODING FOR COMPACT UUID STRINGS
-- ============================================================================

-- Encode UUID to base62 (shorter than hex)
CREATE OR REPLACE FUNCTION uuid_to_base62(p_uuid UUID)
RETURNS TEXT AS $$
DECLARE
    c_alphabet TEXT := '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    v_hex TEXT;
    v_num NUMERIC;
    v_result TEXT := '';
    v_remainder INT;
BEGIN
    -- Convert UUID to numeric
    v_hex := REPLACE(REPLACE(p_uuid::TEXT, '-', ''), '-', '');
    v_num := ('x' || v_hex)::NUMERIC;
    
    -- Convert to base62
    WHILE v_num > 0 LOOP
        v_remainder := MOD(v_num, 62);
        v_result := SUBSTRING(c_alphabet FROM v_remainder + 1 FOR 1) || v_result;
        v_num := v_num / 62;
    END LOOP;
    
    RETURN COALESCE(v_result, '0');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Decode base62 back to UUID
CREATE OR REPLACE FUNCTION base62_to_uuid(p_base62 TEXT)
RETURNS UUID AS $$
DECLARE
    c_alphabet TEXT := '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    v_num NUMERIC := 0;
    v_char CHAR(1);
    v_pos INT;
BEGIN
    -- Convert base62 to numeric
    FOR i IN 1..LENGTH(p_base62) LOOP
        v_char := SUBSTRING(p_base62 FROM i FOR 1);
        v_pos := POSITION(v_char IN c_alphabet) - 1;
        v_num := v_num * 62 + v_pos;
    END LOOP;
    
    -- Convert numeric to UUID hex
    RETURN (LPAD(TO_HEX(v_num::BIGINT), 32, '0')::TEXT)::UUID;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- UUID VALIDATION
-- ============================================================================

-- Validate UUID format and return boolean
CREATE OR REPLACE FUNCTION is_valid_uuid(p_text TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN p_text ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Safe UUID conversion with fallback
CREATE OR REPLACE FUNCTION safe_uuid(p_text TEXT, p_fallback UUID DEFAULT NULL)
RETURNS UUID AS $$
BEGIN
    IF p_text IS NULL THEN
        RETURN p_fallback;
    END IF;
    
    IF is_valid_uuid(p_text) THEN
        RETURN p_text::UUID;
    END IF;
    
    RETURN p_fallback;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- SNOWFLAKE-STYLE DISTRIBUTED ID GENERATION
-- ============================================================================

-- Configuration table for Snowflake-style IDs
CREATE TABLE IF NOT EXISTS snowflake_config (
    config_id SERIAL PRIMARY KEY,
    datacenter_id INT NOT NULL DEFAULT 0,
    worker_id INT NOT NULL DEFAULT 0,
    epoch_start BIGINT NOT NULL DEFAULT 1609459200000, -- 2021-01-01
    CONSTRAINT valid_datacenter CHECK (datacenter_id BETWEEN 0 AND 31),
    CONSTRAINT valid_worker CHECK (worker_id BETWEEN 0 AND 31)
);

-- Initialize default config
INSERT INTO snowflake_config (datacenter_id, worker_id) VALUES (0, 0)
ON CONFLICT DO NOTHING;

-- Sequence for unique IDs within same millisecond
CREATE SEQUENCE IF NOT EXISTS snowflake_sequence MAXVALUE 4095 CYCLE;

-- Generate Snowflake-style 64-bit ID
-- Structure: 41 bits timestamp | 5 bits datacenter | 5 bits worker | 12 bits sequence
CREATE OR REPLACE FUNCTION generate_snowflake_id(
    p_datacenter_id INT DEFAULT 0,
    p_worker_id INT DEFAULT 0
)
RETURNS BIGINT AS $$
DECLARE
    v_epoch_start BIGINT := 1609459200000; -- 2021-01-01
    v_timestamp_ms BIGINT;
    v_sequence BIGINT;
BEGIN
    -- Validate datacenter and worker IDs
    IF p_datacenter_id < 0 OR p_datacenter_id > 31 THEN
        RAISE EXCEPTION 'datacenter_id must be between 0 and 31';
    END IF;
    IF p_worker_id < 0 OR p_worker_id > 31 THEN
        RAISE EXCEPTION 'worker_id must be between 0 and 31';
    END IF;
    
    -- Get timestamp relative to epoch
    v_timestamp_ms := (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT - v_epoch_start;
    v_sequence := nextval('snowflake_sequence');
    
    -- Compose 64-bit ID
    -- 1 bit sign (0) + 41 bits timestamp + 5 bits datacenter + 5 bits worker + 12 bits sequence
    RETURN (v_timestamp_ms << 22) | (p_datacenter_id << 17) | (p_worker_id << 12) | v_sequence;
END;
$$ LANGUAGE plpgsql VOLATILE;

-- Convert Snowflake ID to timestamp
CREATE OR REPLACE FUNCTION snowflake_to_timestamp(p_id BIGINT)
RETURNS TIMESTAMPTZ AS $$
DECLARE
    v_epoch_start BIGINT := 1609459200000;
    v_timestamp_ms BIGINT;
BEGIN
    v_timestamp_ms := (p_id >> 22) + v_epoch_start;
    RETURN TO_TIMESTAMP(v_timestamp_ms / 1000.0);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- UUID NAMESPACES (RFC 4122 Version 5 style)
-- ============================================================================

-- Common namespaces
CREATE OR REPLACE FUNCTION get_uuid_namespace_dns()
RETURNS UUID AS $$ SELECT '6ba7b810-9dad-11d1-80b4-00c04fd430c8'::UUID; $$ LANGUAGE SQL IMMUTABLE;

CREATE OR REPLACE FUNCTION get_uuid_namespace_url()
RETURNS UUID AS $$ SELECT '6ba7b811-9dad-11d1-80b4-00c04fd430c8'::UUID; $$ LANGUAGE SQL IMMUTABLE;

CREATE OR REPLACE FUNCTION get_uuid_namespace_oid()
RETURNS UUID AS $$ SELECT '6ba7b812-9dad-11d1-80b4-00c04fd430c8'::UUID; $$ LANGUAGE SQL IMMUTABLE;

CREATE OR REPLACE FUNCTION get_uuid_namespace_x500()
RETURNS UUID AS $$ SELECT '6ba7b814-9dad-11d1-80b4-00c04fd430c8'::UUID; $$ LANGUAGE SQL IMMUTABLE;

-- Application-specific namespace (generate once and store)
CREATE OR REPLACE FUNCTION generate_namespace_uuid(p_name TEXT)
RETURNS UUID AS $$
BEGIN
    -- Generate deterministic UUID from namespace name
    RETURN gen_random_uuid(); -- Placeholder: actual v5 uses SHA-1 hashing
END;
$$ LANGUAGE plpgsql VOLATILE;

-- ============================================================================
-- UUID MIGRATION UTILITIES
-- ============================================================================

-- Function to convert sequential ID to UUID
CREATE OR REPLACE FUNCTION migrate_int_to_uuid(
    p_table_name TEXT,
    p_id_column TEXT,
    p_use_sequential BOOLEAN DEFAULT TRUE
)
RETURNS JSONB AS $$
BEGIN
    -- Return migration plan (actual migration should be done in controlled batch)
    RETURN jsonb_build_object(
        'table', p_table_name,
        'column', p_id_column,
        'strategy', CASE WHEN p_use_sequential THEN 'sequential_uuid' ELSE 'uuid_v4' END,
        'note', 'Run ALTER TABLE and UPDATE in batches to convert IDs'
    );
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- PERFORMANCE BENCHMARKING
-- ============================================================================

-- Table for benchmark results
CREATE TABLE IF NOT EXISTS uuid_benchmark_results (
    benchmark_id SERIAL PRIMARY KEY,
    generator_type TEXT NOT NULL,
    iterations INT NOT NULL,
    total_time_ms NUMERIC,
    ids_per_second NUMERIC,
    test_timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Benchmark UUID generation performance
CREATE OR REPLACE FUNCTION benchmark_uuid_generators(
    p_iterations INT DEFAULT 10000
)
RETURNS TABLE(generator_type TEXT, iterations INT, total_time_ms NUMERIC, ids_per_second NUMERIC) AS $$
DECLARE
    v_start TIMESTAMPTZ;
    v_end TIMESTAMPTZ;
    v_i INT;
    v_dummy UUID;
    v_dummy_text TEXT;
    v_dummy_bigint BIGINT;
BEGIN
    -- Benchmark UUID v4
    v_start := clock_timestamp();
    FOR v_i IN 1..p_iterations LOOP
        v_dummy := generate_uuid_v4();
    END LOOP;
    v_end := clock_timestamp();
    generator_type := 'uuid_v4';
    iterations := p_iterations;
    total_time_ms := EXTRACT(EPOCH FROM (v_end - v_start)) * 1000;
    ids_per_second := p_iterations / NULLIF(EXTRACT(EPOCH FROM (v_end - v_start)), 0);
    RETURN NEXT;
    
    -- Benchmark Sequential UUID
    v_start := clock_timestamp();
    FOR v_i IN 1..p_iterations LOOP
        v_dummy := generate_sequential_uuid();
    END LOOP;
    v_end := clock_timestamp();
    generator_type := 'sequential_uuid';
    iterations := p_iterations;
    total_time_ms := EXTRACT(EPOCH FROM (v_end - v_start)) * 1000;
    ids_per_second := p_iterations / NULLIF(EXTRACT(EPOCH FROM (v_end - v_start)), 0);
    RETURN NEXT;
    
    -- Benchmark UUID v7
    v_start := clock_timestamp();
    FOR v_i IN 1..p_iterations LOOP
        v_dummy := generate_uuid_v7();
    END LOOP;
    v_end := clock_timestamp();
    generator_type := 'uuid_v7';
    iterations := p_iterations;
    total_time_ms := EXTRACT(EPOCH FROM (v_end - v_start)) * 1000;
    ids_per_second := p_iterations / NULLIF(EXTRACT(EPOCH FROM (v_end - v_start)), 0);
    RETURN NEXT;
    
    -- Benchmark Snowflake ID
    v_start := clock_timestamp();
    FOR v_i IN 1..p_iterations LOOP
        v_dummy_bigint := generate_snowflake_id();
    END LOOP;
    v_end := clock_timestamp();
    generator_type := 'snowflake';
    iterations := p_iterations;
    total_time_ms := EXTRACT(EPOCH FROM (v_end - v_start)) * 1000;
    ids_per_second := p_iterations / NULLIF(EXTRACT(EPOCH FROM (v_end - v_start)), 0);
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON FUNCTION generate_uuid_v7 IS 'RFC 9562: Generate UUIDv7 (timestamp-ordered) for better index performance';
COMMENT ON FUNCTION generate_ulid IS 'Generate ULID (26-char lexicographically sortable ID)';
COMMENT ON FUNCTION uuid_to_base62 IS 'Encode UUID to base62 for shorter string representation';
COMMENT ON FUNCTION is_valid_uuid IS 'Validate string format as standard UUID';
COMMENT ON FUNCTION generate_snowflake_id IS 'Generate distributed 64-bit ID (Snowflake-style) with timestamp embedded';
COMMENT ON FUNCTION snowflake_to_timestamp IS 'Extract timestamp from Snowflake-style ID';

-- ============================================================================
-- RECOMMENDATION SUMMARY
-- ============================================================================
-- For best database performance, use:
-- - UUID v7 or Sequential UUID for primary keys (time-ordered, better index locality)
-- - ULID when lexicographic sorting is needed
-- - Snowflake IDs for distributed systems requiring 64-bit integers
-- - UUID v4 only when pure randomness is required
-- ============================================================================
