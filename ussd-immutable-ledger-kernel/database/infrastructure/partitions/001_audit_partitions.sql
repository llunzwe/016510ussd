-- =============================================================================
-- AUDIT PARTITIONS
-- Implements partitioning for audit log tables
-- =============================================================================

-- =============================================================================
-- AUDIT PARTITION CONFIGURATION
-- =============================================================================

-- Insert audit-specific partition configurations
INSERT INTO partition_mgmt.partition_config (
    schema_name, table_name, partition_column, 
    partition_type, partition_interval, retention_period, archive_after, premake
) VALUES 
    ('audit', 'ledger_audit_log', 'event_timestamp', 'RANGE', '1 day', '365 days', '90 days', 7),
    ('audit', 'transaction_audit_log', 'event_timestamp', 'RANGE', '1 day', '2555 days', '365 days', 7),
    ('audit', 'access_audit_log', 'event_timestamp', 'RANGE', '1 day', '90 days', '30 days', 7),
    ('audit', 'admin_audit_log', 'event_timestamp', 'RANGE', '1 day', '2555 days', '365 days', 7)
ON CONFLICT (schema_name, table_name) DO UPDATE SET
    partition_column = EXCLUDED.partition_column,
    partition_interval = EXCLUDED.partition_interval,
    retention_period = EXCLUDED.retention_period,
    archive_after = EXCLUDED.archive_after;

-- =============================================================================
-- FUNCTION: Create audit log partition table
-- =============================================================================
CREATE OR REPLACE FUNCTION partition_mgmt.create_audit_partition_table(
    p_schema_name VARCHAR DEFAULT 'audit',
    p_table_name VARCHAR DEFAULT 'ledger_audit_log',
    p_partition_column VARCHAR DEFAULT 'event_timestamp'
) RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_full_table_name TEXT;
    v_sql TEXT;
BEGIN
    v_full_table_name := quote_ident(p_schema_name) || '.' || quote_ident(p_table_name);
    
    -- Create schema if not exists
    EXECUTE format('CREATE SCHEMA IF NOT EXISTS %s', quote_ident(p_schema_name));
    
    -- Create partitioned audit table
    v_sql := format('
        CREATE TABLE IF NOT EXISTS %s (
            id BIGSERIAL,
            event_id UUID NOT NULL DEFAULT gen_random_uuid(),
            event_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            event_type VARCHAR(50) NOT NULL,
            event_severity VARCHAR(20) NOT NULL DEFAULT ''INFO'' 
                CHECK (event_severity IN (''DEBUG'', ''INFO'', ''WARN'', ''ERROR'', ''CRITICAL'')),
            entity_type VARCHAR(50) NOT NULL,
            entity_id UUID,
            user_id UUID,
            session_id VARCHAR(255),
            client_ip INET,
            action VARCHAR(100) NOT NULL,
            old_data JSONB,
            new_data JSONB,
            change_summary JSONB,
            integrity_hash BYTEA NOT NULL,
            verification_status VARCHAR(20) DEFAULT ''UNVERIFIED'',
            metadata JSONB,
            
            PRIMARY KEY (id, event_timestamp)
        ) PARTITION BY RANGE (event_timestamp)
    ', v_full_table_name);
    
    EXECUTE v_sql;
    
    -- Add comments
    EXECUTE format('COMMENT ON TABLE %s IS ''Partitioned audit log for immutable ledger events''', v_full_table_name);
    
    -- Create indexes
    EXECUTE format('
        CREATE INDEX IF NOT EXISTS idx_%s_timestamp 
        ON %s (event_timestamp DESC)
    ', p_table_name, v_full_table_name);
    
    EXECUTE format('
        CREATE INDEX IF NOT EXISTS idx_%s_event_type 
        ON %s (event_type, event_timestamp DESC)
    ', p_table_name, v_full_table_name);
    
    EXECUTE format('
        CREATE INDEX IF NOT EXISTS idx_%s_entity 
        ON %s (entity_type, entity_id, event_timestamp DESC)
    ', p_table_name, v_full_table_name);
    
    EXECUTE format('
        CREATE INDEX IF NOT EXISTS idx_%s_user 
        ON %s (user_id, event_timestamp DESC)
    ', p_table_name, v_full_table_name);
    
    EXECUTE format('
        CREATE INDEX IF NOT EXISTS idx_%s_severity 
        ON %s (event_severity, event_timestamp DESC) 
        WHERE event_severity IN (''ERROR'', ''CRITICAL'')
    ', p_table_name, v_full_table_name);
    
    -- Create GIN index for JSONB metadata
    EXECUTE format('
        CREATE INDEX IF NOT EXISTS idx_%s_metadata 
        ON %s USING GIN (metadata)
    ', p_table_name, v_full_table_name);
    
    -- Create hash index for integrity verification
    EXECUTE format('
        CREATE INDEX IF NOT EXISTS idx_%s_integrity 
        ON %s USING HASH (integrity_hash)
    ', p_table_name, v_full_table_name);
    
    RETURN format('Created audit partition table: %s', v_full_table_name);
END;
$$;

-- =============================================================================
-- FUNCTION: Create audit partition for specific date range
-- =============================================================================
CREATE OR REPLACE FUNCTION partition_mgmt.create_audit_partition(
    p_schema_name VARCHAR,
    p_table_name VARCHAR,
    p_start_date DATE,
    p_end_date DATE
) RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_parent_table TEXT;
    v_partition_name TEXT;
    v_suffix TEXT;
BEGIN
    v_parent_table := quote_ident(p_schema_name) || '.' || quote_ident(p_table_name);
    v_suffix := TO_CHAR(p_start_date, 'YYYYMMDD');
    v_partition_name := quote_ident(p_schema_name) || '.' || 
                       quote_ident(p_table_name || '_' || v_suffix);
    
    EXECUTE format('
        CREATE TABLE IF NOT EXISTS %s PARTITION OF %s
        FOR VALUES FROM (%L) TO (%L)
    ', v_partition_name, v_parent_table, p_start_date, p_end_date);
    
    -- Track in metadata
    INSERT INTO partition_mgmt.partition_metadata (
        parent_schema, parent_table, partition_name, partition_schema,
        range_from, range_to
    ) VALUES (
        p_schema_name, p_table_name, 
        p_table_name || '_' || v_suffix,
        p_schema_name, p_start_date, p_end_date
    )
    ON CONFLICT (partition_schema, partition_name) DO NOTHING;
    
    RETURN v_partition_name;
END;
$$;

-- =============================================================================
-- FUNCTION: Initialize all audit partitions
-- =============================================================================
CREATE OR REPLACE FUNCTION partition_mgmt.init_audit_partitions()
RETURNS TABLE(table_name TEXT, partition_created TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
    v_start_date DATE;
    v_end_date DATE;
BEGIN
    FOR v_config IN 
        SELECT * FROM partition_mgmt.partition_config 
        WHERE schema_name = 'audit'
    LOOP
        table_name := v_config.schema_name || '.' || v_config.table_name;
        
        -- Create the partitioned table
        PERFORM partition_mgmt.create_audit_partition_table(
            v_config.schema_name, 
            v_config.table_name
        );
        
        -- Create partitions for configured premake period
        FOR i IN -7..v_config.premake LOOP
            v_start_date := DATE_TRUNC('day', NOW() + (i || ' days')::INTERVAL);
            v_end_date := v_start_date + INTERVAL '1 day';
            
            partition_created := partition_mgmt.create_audit_partition(
                v_config.schema_name,
                v_config.table_name,
                v_start_date,
                v_end_date
            );
            
            RETURN NEXT;
        END LOOP;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- TRIGGER FUNCTION: Auto-create partition on insert
-- =============================================================================
CREATE OR REPLACE FUNCTION partition_mgmt.auto_create_audit_partition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_partition_date DATE;
    v_partition_name TEXT;
    v_parent_table TEXT;
    v_start_date DATE;
    v_end_date DATE;
BEGIN
    v_partition_date := DATE_TRUNC('day', NEW.event_timestamp);
    v_start_date := v_partition_date;
    v_end_date := v_start_date + INTERVAL '1 day';
    v_parent_table := TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
    v_partition_name := TG_TABLE_SCHEMA || '.' || 
                       TG_TABLE_NAME || '_' || TO_CHAR(v_partition_date, 'YYYYMMDD');
    
    -- Try to create partition if it doesn't exist
    BEGIN
        EXECUTE format('
            CREATE TABLE IF NOT EXISTS %I.%I PARTITION OF %s
            FOR VALUES FROM (%L) TO (%L)
        ', TG_TABLE_SCHEMA, TG_TABLE_NAME || '_' || TO_CHAR(v_partition_date, 'YYYYMMDD'),
          v_parent_table, v_start_date, v_end_date);
        
        -- Track in metadata
        INSERT INTO partition_mgmt.partition_metadata (
            parent_schema, parent_table, partition_name, partition_schema,
            range_from, range_to
        ) VALUES (
            TG_TABLE_SCHEMA, TG_TABLE_NAME, 
            TG_TABLE_NAME || '_' || TO_CHAR(v_partition_date, 'YYYYMMDD'),
            TG_TABLE_SCHEMA, v_start_date, v_end_date
        )
        ON CONFLICT (partition_schema, partition_name) DO NOTHING;
        
    EXCEPTION WHEN duplicate_table THEN
        -- Partition already exists, continue
        NULL;
    END;
    
    RETURN NEW;
END;
$$;

-- =============================================================================
-- VIEW: Audit partition status
-- =============================================================================
CREATE OR REPLACE VIEW partition_mgmt.audit_partition_status AS
SELECT 
    pm.parent_schema,
    pm.parent_table,
    pm.partition_name,
    pm.range_from,
    pm.range_to,
    pm.row_count,
    pg_size_pretty(pm.size_bytes) as size_pretty,
    pm.size_bytes,
    pm.is_active,
    pm.is_archived,
    pm.created_at,
    pm.archived_at,
    CASE 
        WHEN pm.range_to < NOW() - INTERVAL '90 days' THEN 'EXPIRED'
        WHEN pm.range_to < NOW() THEN 'PAST'
        WHEN pm.range_from > NOW() THEN 'FUTURE'
        ELSE 'CURRENT'
    END as partition_status
FROM partition_mgmt.partition_metadata pm
WHERE pm.parent_schema = 'audit'
ORDER BY pm.range_from DESC;

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA audit TO audit_reader, audit_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA audit TO audit_reader;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA audit TO audit_writer;
GRANT SELECT ON partition_mgmt.audit_partition_status TO audit_reader;
