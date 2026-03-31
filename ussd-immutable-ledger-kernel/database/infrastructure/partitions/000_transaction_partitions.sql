-- =============================================================================
-- TRANSACTION PARTITIONS
-- Implements time-based partitioning for high-volume transaction tables
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pg_partman;

-- =============================================================================
-- PARTITION MANAGEMENT SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS partition_mgmt;

COMMENT ON SCHEMA partition_mgmt IS 'Schema for partition management functions and configuration';

-- =============================================================================
-- PARTITION CONFIGURATION TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS partition_mgmt.partition_config (
    id SERIAL PRIMARY KEY,
    schema_name VARCHAR(63) NOT NULL,
    table_name VARCHAR(63) NOT NULL,
    partition_column VARCHAR(63) NOT NULL,
    partition_type VARCHAR(20) NOT NULL DEFAULT 'RANGE', -- RANGE, LIST, HASH
    partition_interval VARCHAR(50) NOT NULL, -- '1 day', '1 month', etc.
    retention_period VARCHAR(50), -- How long to keep partitions
    archive_after VARCHAR(50), -- When to archive to cold storage
    premake INTEGER DEFAULT 4, -- Number of future partitions to create
    UNIQUE(schema_name, table_name)
);

COMMENT ON TABLE partition_mgmt.partition_config IS 'Configuration for automated partition management';

-- =============================================================================
-- PARTITION METADATA TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS partition_mgmt.partition_metadata (
    id SERIAL PRIMARY KEY,
    parent_schema VARCHAR(63) NOT NULL,
    parent_table VARCHAR(63) NOT NULL,
    partition_name VARCHAR(128) NOT NULL,
    partition_schema VARCHAR(63) NOT NULL,
    range_from TIMESTAMPTZ,
    range_to TIMESTAMPTZ,
    row_count BIGINT,
    size_bytes BIGINT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    is_archived BOOLEAN DEFAULT FALSE,
    archived_at TIMESTAMPTZ,
    UNIQUE(partition_schema, partition_name)
);

CREATE INDEX IF NOT EXISTS idx_partition_metadata_parent 
ON partition_mgmt.partition_metadata(parent_schema, parent_table);

CREATE INDEX IF NOT EXISTS idx_partition_metadata_active 
ON partition_mgmt.partition_metadata(is_active, range_from);

-- =============================================================================
-- FUNCTION: Create transaction partition template
-- =============================================================================
CREATE OR REPLACE FUNCTION partition_mgmt.create_transaction_partition_table(
    p_schema_name VARCHAR,
    p_table_name VARCHAR,
    p_partition_column VARCHAR DEFAULT 'created_at',
    p_partition_interval VARCHAR DEFAULT '1 day'
) RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_full_table_name TEXT;
    v_sql TEXT;
BEGIN
    v_full_table_name := quote_ident(p_schema_name) || '.' || quote_ident(p_table_name);
    
    -- Create partitioned table template
    v_sql := format('
        CREATE TABLE IF NOT EXISTS %s (
            id BIGSERIAL,
            transaction_id UUID NOT NULL,
            ledger_id UUID NOT NULL,
            account_id UUID NOT NULL,
            entry_type VARCHAR(20) NOT NULL CHECK (entry_type IN (''DEBIT'', ''CREDIT'')),
            amount DECIMAL(20, 8) NOT NULL,
            currency_code CHAR(3) NOT NULL,
            %I TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            posted_at TIMESTAMPTZ,
            status VARCHAR(20) DEFAULT ''PENDING'',
            hash_chain BYTEA NOT NULL,
            previous_hash BYTEA,
            signature BYTEA,
            metadata JSONB,
            
            PRIMARY KEY (id, %I)
        ) PARTITION BY RANGE (%I)
    ', v_full_table_name, p_partition_column, p_partition_column, p_partition_column);
    
    EXECUTE v_sql;
    
    -- Add comment
    EXECUTE format('COMMENT ON TABLE %s IS ''Partitioned transaction table''', v_full_table_name);
    
    -- Create indexes on partition key
    EXECUTE format('
        CREATE INDEX IF NOT EXISTS idx_%s_%s 
        ON %s (%I DESC)
    ', p_table_name, p_partition_column, v_full_table_name, p_partition_column);
    
    -- Create index on transaction_id
    EXECUTE format('
        CREATE INDEX IF NOT EXISTS idx_%s_txn_id 
        ON %s (transaction_id)
    ', p_table_name, v_full_table_name);
    
    -- Create index on ledger_id
    EXECUTE format('
        CREATE INDEX IF NOT EXISTS idx_%s_ledger_id 
        ON %s (ledger_id)
    ', p_table_name, v_full_table_name);
    
    -- Create index on account_id
    EXECUTE format('
        CREATE INDEX IF NOT EXISTS idx_%s_account_id 
        ON %s (account_id)
    ', p_table_name, v_full_table_name);
    
    -- Create hash index for integrity verification
    EXECUTE format('
        CREATE INDEX IF NOT EXISTS idx_%s_hash 
        ON %s USING HASH (hash_chain)
    ', p_table_name, v_full_table_name);
    
    -- Register in config
    INSERT INTO partition_mgmt.partition_config (
        schema_name, table_name, partition_column, 
        partition_type, partition_interval, retention_period, premake
    ) VALUES (
        p_schema_name, p_table_name, p_partition_column,
        'RANGE', p_partition_interval, '90 days', 7
    )
    ON CONFLICT (schema_name, table_name) DO UPDATE SET
        partition_column = EXCLUDED.partition_column,
        partition_interval = EXCLUDED.partition_interval;
    
    -- Create initial partitions
    PERFORM partition_mgmt.create_initial_partitions(p_schema_name, p_table_name);
    
    RETURN format('Created partitioned table: %s', v_full_table_name);
END;
$$;

-- =============================================================================
-- FUNCTION: Create initial partitions
-- =============================================================================
CREATE OR REPLACE FUNCTION partition_mgmt.create_initial_partitions(
    p_schema_name VARCHAR,
    p_table_name VARCHAR
)
RETURNS TABLE(partition_name TEXT, created BOOLEAN)
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
    v_parent_table TEXT;
    v_start_date DATE;
    v_end_date DATE;
    v_partition_name TEXT;
    v_partition_tablespace TEXT := 'pg_default';
BEGIN
    SELECT * INTO v_config 
    FROM partition_mgmt.partition_config 
    WHERE schema_name = p_schema_name AND table_name = p_table_name;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Partition config not found for %.%', p_schema_name, p_table_name;
    END IF;
    
    v_parent_table := quote_ident(p_schema_name) || '.' || quote_ident(p_table_name);
    v_start_date := DATE_TRUNC('day', NOW() - INTERVAL '7 days');
    
    -- Create partitions for past 7 days + next 30 days
    FOR i IN -7..30 LOOP
        v_start_date := DATE_TRUNC(
            CASE 
                WHEN v_config.partition_interval = '1 month' THEN 'month'
                WHEN v_config.partition_interval = '1 week' THEN 'week'
                ELSE 'day'
            END,
            NOW() + (i || ' days')::INTERVAL
        );
        
        v_end_date := v_start_date + v_config.partition_interval::INTERVAL;
        v_partition_name := quote_ident(p_schema_name) || '.' || 
                           quote_ident(p_table_name || '_' || TO_CHAR(v_start_date, 'YYYYMMDD'));
        
        BEGIN
            EXECUTE format('
                CREATE TABLE IF NOT EXISTS %s PARTITION OF %s
                FOR VALUES FROM (%L) TO (%L)
                TABLESPACE %s
            ', v_partition_name, v_parent_table, v_start_date, v_end_date, v_partition_tablespace);
            
            -- Track in metadata
            INSERT INTO partition_mgmt.partition_metadata (
                parent_schema, parent_table, partition_name, partition_schema,
                range_from, range_to
            ) VALUES (
                p_schema_name, p_table_name, 
                p_table_name || '_' || TO_CHAR(v_start_date, 'YYYYMMDD'),
                p_schema_name, v_start_date, v_end_date
            )
            ON CONFLICT (partition_schema, partition_name) DO NOTHING;
            
            partition_name := v_partition_name;
            created := TRUE;
            RETURN NEXT;
        EXCEPTION WHEN duplicate_table THEN
            partition_name := v_partition_name;
            created := FALSE;
            RETURN NEXT;
        END;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Create future partition (for cron job)
-- =============================================================================
CREATE OR REPLACE FUNCTION partition_mgmt.create_future_partition(
    p_schema_name VARCHAR,
    p_table_name VARCHAR,
    p_days_ahead INTEGER DEFAULT 7
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
    v_parent_table TEXT;
    v_start_date DATE;
    v_end_date DATE;
    v_partition_name TEXT;
    v_result TEXT;
BEGIN
    SELECT * INTO v_config 
    FROM partition_mgmt.partition_config 
    WHERE schema_name = p_schema_name AND table_name = p_table_name;
    
    IF NOT FOUND THEN
        RETURN format('No config found for %.%', p_schema_name, p_table_name);
    END IF;
    
    v_parent_table := quote_ident(p_schema_name) || '.' || quote_ident(p_table_name);
    v_start_date := DATE_TRUNC(
        CASE 
            WHEN v_config.partition_interval = '1 month' THEN 'month'
            WHEN v_config.partition_interval = '1 week' THEN 'week'
            ELSE 'day'
        END,
        NOW() + (p_days_ahead || ' days')::INTERVAL
    );
    
    v_end_date := v_start_date + v_config.partition_interval::INTERVAL;
    v_partition_name := quote_ident(p_schema_name) || '.' || 
                       quote_ident(p_table_name || '_' || TO_CHAR(v_start_date, 'YYYYMMDD'));
    
    BEGIN
        EXECUTE format('
            CREATE TABLE IF NOT EXISTS %s PARTITION OF %s
            FOR VALUES FROM (%L) TO (%L)
        ', v_partition_name, v_parent_table, v_start_date, v_end_date);
        
        INSERT INTO partition_mgmt.partition_metadata (
            parent_schema, parent_table, partition_name, partition_schema,
            range_from, range_to
        ) VALUES (
            p_schema_name, p_table_name, 
            p_table_name || '_' || TO_CHAR(v_start_date, 'YYYYMMDD'),
            p_schema_name, v_start_date, v_end_date
        )
        ON CONFLICT (partition_schema, partition_name) DO NOTHING;
        
        v_result := format('Created partition: %s', v_partition_name);
    EXCEPTION WHEN duplicate_table THEN
        v_result := format('Partition already exists: %s', v_partition_name);
    END;
    
    RETURN v_result;
END;
$$;

-- =============================================================================
-- FUNCTION: Automated partition maintenance
-- =============================================================================
CREATE OR REPLACE FUNCTION partition_mgmt.maintain_partitions()
RETURNS TABLE(action TEXT, details TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
BEGIN
    FOR v_config IN SELECT * FROM partition_mgmt.partition_config WHERE is_active = TRUE LOOP
        -- Create future partitions
        FOR i IN 1..v_config.premake LOOP
            action := 'CREATE_FUTURE';
            details := partition_mgmt.create_future_partition(
                v_config.schema_name, v_config.table_name, i
            );
            RETURN NEXT;
        END LOOP;
    END LOOP;
    
    RETURN;
END;
$$;

-- Add is_active column if not exists
DO $$
BEGIN
    ALTER TABLE partition_mgmt.partition_config 
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;
EXCEPTION
    WHEN duplicate_column THEN NULL;
END $$;

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA partition_mgmt TO ledger_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA partition_mgmt TO ledger_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA partition_mgmt TO ledger_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA partition_mgmt TO ledger_app;
