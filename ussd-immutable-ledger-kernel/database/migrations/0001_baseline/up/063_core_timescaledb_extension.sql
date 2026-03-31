-- =============================================================================
-- USSD KERNEL CORE SCHEMA - TIMESCALEDB EXTENSION SETUP
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    063_core_timescaledb_extension.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      core
-- DESCRIPTION: TimescaleDB extension installation and validation for
--              production-scale immutable ledger with time-series optimization.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.3 Information backup - Automated archival via retention policies
├── A.12.4 Logging and monitoring - Continuous aggregate monitoring
└── A.18.1 Compliance - Data retention for regulatory requirements

Financial Regulations
├── Data retention: 7-10 years immutable audit trail
├── Performance: Sub-second query SLA for compliance
└── Cost management: Storage optimization via compression

================================================================================
DEPENDENCIES
================================================================================

- TimescaleDB 2.15+ (Community Edition or Enterprise)
- PostgreSQL 16+
- Extension must be available in shared_preload_libraries

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

TimescaleDB Features Enabled:
1. Hypertables - Automatic time-based partitioning
2. Compression - 80-95% storage reduction for immutable data
3. Continuous Aggregates - Real-time materialized views
4. Retention Policies - Automated archival with legal-hold support
5. Chunk Skipping - Fast time-range queries
6. Data Tiering - Hot/warm/cold data management

================================================================================
*/

-- =============================================================================
-- INSTALL TIMESCALEDB EXTENSION
-- =============================================================================

-- Create extension (requires superuser or appropriate privileges)
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Verify installation
DO $$
DECLARE
    v_version TEXT;
    v_edition TEXT;
BEGIN
    -- Check TimescaleDB version
    SELECT extversion INTO v_version
    FROM pg_extension 
    WHERE extname = 'timescaledb';
    
    IF v_version IS NULL THEN
        RAISE EXCEPTION 'TimescaleDB extension not installed. Please install TimescaleDB 2.15+';
    END IF;
    
    -- Check minimum version
    IF v_version < '2.15.0' THEN
        RAISE WARNING 'TimescaleDB version % detected. Version 2.15+ recommended for production.', v_version;
    END IF;
    
    -- Log success
    RAISE NOTICE 'TimescaleDB % installed successfully', v_version;
    
    -- Check if TimescaleDB is properly loaded
    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'create_hypertable') THEN
        RAISE EXCEPTION 'TimescaleDB functions not available. Check shared_preload_libraries.';
    END IF;
END;
$$;

-- =============================================================================
-- CONFIGURE TIMESCALEDB PARAMETERS
-- =============================================================================

-- Set optimal parameters for immutable ledger workload
-- Note: These can also be set in postgresql.conf for persistence

-- Background worker settings for TimescaleDB
ALTER SYSTEM SET timescaledb.max_background_workers = 16;
ALTER SYSTEM SET timescaledb.max_insert_batches = 1000;

-- Compression settings
ALTER SYSTEM SET timescaledb.enable_compression = on;
ALTER SYSTEM SET timescaledb.enable_chunk_skipping = on;

-- Refresh policy for continuous aggregates
ALTER SYSTEM SET timescaledb.materializations_per_refresh_window = 10;

-- Apply configuration changes (requires restart)
-- SELECT pg_reload_conf();

-- =============================================================================
-- CREATE TIMESCALEDB METADATA TABLE
-- =============================================================================

-- Track hypertable configurations for audit and compliance
CREATE TABLE core.timescaledb_config (
    config_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Table reference
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    
    -- Hypertable configuration
    time_column TEXT NOT NULL,
    chunk_time_interval INTERVAL NOT NULL,
    partitioning_columns TEXT[],
    
    -- Compression configuration
    compression_enabled BOOLEAN DEFAULT FALSE,
    compression_after INTERVAL,
    compression_segmentby_columns TEXT[],
    compression_orderby_columns TEXT[],
    
    -- Retention configuration
    retention_enabled BOOLEAN DEFAULT FALSE,
    retention_after INTERVAL,
    legal_hold_supported BOOLEAN DEFAULT TRUE,
    
    -- Continuous aggregates
    has_continuous_aggregates BOOLEAN DEFAULT FALSE,
    
    -- Status
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    created_by UUID,
    last_modified_at TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT uq_hypertable_config UNIQUE (schema_name, table_name)
);

-- Index for config lookups
CREATE INDEX idx_timescaledb_config_lookup 
    ON core.timescaledb_config(schema_name, table_name);

-- =============================================================================
-- HELPER FUNCTION: Register Hypertable Configuration
-- =============================================================================

CREATE OR REPLACE FUNCTION core.register_hypertable_config(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_time_column TEXT,
    p_chunk_interval INTERVAL,
    p_partitioning_columns TEXT[] DEFAULT NULL,
    p_compression_enabled BOOLEAN DEFAULT FALSE,
    p_compression_after INTERVAL DEFAULT NULL,
    p_compression_segmentby TEXT[] DEFAULT NULL,
    p_compression_orderby TEXT[] DEFAULT NULL,
    p_retention_enabled BOOLEAN DEFAULT FALSE,
    p_retention_after INTERVAL DEFAULT NULL,
    p_has_aggregates BOOLEAN DEFAULT FALSE,
    p_created_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_config_id UUID;
BEGIN
    INSERT INTO core.timescaledb_config (
        schema_name,
        table_name,
        time_column,
        chunk_time_interval,
        partitioning_columns,
        compression_enabled,
        compression_after,
        compression_segmentby_columns,
        compression_orderby_columns,
        retention_enabled,
        retention_after,
        has_continuous_aggregates,
        created_by
    ) VALUES (
        p_schema_name,
        p_table_name,
        p_time_column,
        p_chunk_interval,
        p_partitioning_columns,
        p_compression_enabled,
        p_compression_after,
        p_compression_segmentby,
        p_compression_orderby,
        p_retention_enabled,
        p_retention_after,
        p_has_aggregates,
        p_created_by
    )
    RETURNING config_id INTO v_config_id;
    
    RETURN v_config_id;
END;
$$;

-- =============================================================================
-- HELPER FUNCTION: Get Hypertable Statistics
-- =============================================================================

CREATE OR REPLACE FUNCTION core.get_hypertable_stats(
    p_schema_name TEXT DEFAULT NULL,
    p_table_name TEXT DEFAULT NULL
)
RETURNS TABLE (
    hypertable_schema TEXT,
    hypertable_name TEXT,
    num_chunks BIGINT,
    total_size TEXT,
    compressed_size TEXT,
    uncompressed_size TEXT,
    compression_ratio NUMERIC,
    oldest_chunk TIMESTAMPTZ,
    newest_chunk TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        h.schema_name::TEXT as hypertable_schema,
        h.table_name::TEXT as hypertable_name,
        (SELECT COUNT(*) FROM timescaledb_information.chunks c 
         WHERE c.hypertable_schema = h.schema_name 
         AND c.hypertable_name = h.table_name) as num_chunks,
        pg_size_pretty(hs.total_bytes) as total_size,
        pg_size_pretty(hs.compression_total_size) as compressed_size,
        pg_size_pretty(hs.uncompressed_bytes) as uncompressed_size,
        CASE 
            WHEN hs.compression_total_size > 0 
            THEN ROUND(hs.uncompressed_bytes::NUMERIC / hs.compression_total_size, 2)
            ELSE 1.0
        END as compression_ratio,
        (SELECT MIN(c.range_start)::TIMESTAMPTZ FROM timescaledb_information.chunks c 
         WHERE c.hypertable_schema = h.schema_name 
         AND c.hypertable_name = h.table_name) as oldest_chunk,
        (SELECT MAX(c.range_end)::TIMESTAMPTZ FROM timescaledb_information.chunks c 
         WHERE c.hypertable_schema = h.schema_name 
         AND c.hypertable_name = h.table_name) as newest_chunk
    FROM timescaledb_information.hypertables h
    LEFT JOIN timescaledb_information.hypertable_compression_stats hs
        ON h.schema_name = hs.hypertable_schema 
        AND h.table_name = hs.hypertable_name
    WHERE (p_schema_name IS NULL OR h.schema_name = p_schema_name)
      AND (p_table_name IS NULL OR h.table_name = p_table_name);
END;
$$;

-- =============================================================================
-- HELPER FUNCTION: Legal Hold Management
-- =============================================================================

-- Table to track legal holds on chunks
CREATE TABLE core.legal_holds (
    hold_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hold_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- What is being held
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    chunk_name TEXT,  -- NULL means entire table
    
    -- Hold details
    hold_reason TEXT NOT NULL,
    case_reference VARCHAR(100),
    requested_by VARCHAR(255),
    
    -- Timing
    hold_start TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    hold_end TIMESTAMPTZ,  -- NULL = indefinite
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    released_at TIMESTAMPTZ,
    released_by UUID,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    created_by UUID
);

-- Index for active holds
CREATE INDEX idx_legal_holds_active ON core.legal_holds(is_active, schema_name, table_name) 
    WHERE is_active = TRUE;

-- Function to apply legal hold (blocks retention policy)
CREATE OR REPLACE FUNCTION core.apply_legal_hold(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_hold_reason TEXT,
    p_case_reference VARCHAR DEFAULT NULL,
    p_chunk_name TEXT DEFAULT NULL,
    p_hold_end TIMESTAMPTZ DEFAULT NULL,
    p_requested_by VARCHAR DEFAULT NULL,
    p_created_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_hold_id UUID;
    v_reference VARCHAR(100);
BEGIN
    v_reference := 'HOLD-' || TO_CHAR(core.precise_now(), 'YYYYMMDD') || '-' || 
                   SUBSTRING(MD5(RANDOM()::TEXT), 1, 6);
    
    INSERT INTO core.legal_holds (
        hold_reference,
        schema_name,
        table_name,
        chunk_name,
        hold_reason,
        case_reference,
        requested_by,
        hold_end,
        created_by
    ) VALUES (
        v_reference,
        p_schema_name,
        p_table_name,
        p_chunk_name,
        p_hold_reason,
        p_case_reference,
        p_requested_by,
        p_hold_end,
        p_created_by
    )
    RETURNING hold_id INTO v_hold_id;
    
    -- Log the legal hold application
    RAISE NOTICE 'Legal hold % applied to %.%', v_reference, p_schema_name, p_table_name;
    
    RETURN v_hold_id;
END;
$$;

-- Function to check if chunk has legal hold (for retention policy)
CREATE OR REPLACE FUNCTION core.chunk_has_legal_hold(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_chunk_name TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM core.legal_holds
        WHERE is_active = TRUE
          AND (hold_end IS NULL OR hold_end > core.precise_now())
          AND (
              (schema_name = p_schema_name AND table_name = p_table_name AND chunk_name IS NULL)
              OR (schema_name = p_schema_name AND table_name = p_table_name AND chunk_name = p_chunk_name)
          )
    );
END;
$$;

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

ALTER TABLE core.timescaledb_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.legal_holds ENABLE ROW LEVEL SECURITY;

CREATE POLICY timescaledb_config_kernel ON core.timescaledb_config
    FOR ALL TO ussd_kernel_role USING (true);

CREATE POLICY legal_holds_kernel ON core.legal_holds
    FOR ALL TO ussd_kernel_role USING (true);

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON EXTENSION timescaledb IS 'TimescaleDB time-series extension for production-scale immutable ledger';
COMMENT ON TABLE core.timescaledb_config IS 'Audit trail of all hypertable configurations';
COMMENT ON TABLE core.legal_holds IS 'Legal hold records for e-discovery and litigation';
COMMENT ON FUNCTION core.chunk_has_legal_hold IS 'Check if a chunk is under legal hold before retention deletion';

-- =============================================================================
-- END OF FILE
-- =============================================================================
