-- =============================================================================
-- PUBLICATION CONFIGURATION
-- Logical replication publication setup for immutable ledger
-- =============================================================================

-- =============================================================================
-- REPLICATION SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS replication;

COMMENT ON SCHEMA replication IS 'Logical replication configuration and management';

-- =============================================================================
-- PUBLICATION CONFIGURATION TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS replication.publication_config (
    id SERIAL PRIMARY KEY,
    publication_name VARCHAR(128) NOT NULL UNIQUE,
    schema_name VARCHAR(63) NOT NULL,
    table_pattern VARCHAR(200), -- Regex pattern or 'ALL_TABLES'
    specific_tables TEXT[], -- Specific table names if not using pattern
    
    -- Publication options
    publish_insert BOOLEAN DEFAULT TRUE,
    publish_update BOOLEAN DEFAULT TRUE,
    publish_delete BOOLEAN DEFAULT TRUE,
    publish_truncate BOOLEAN DEFAULT FALSE,
    
    -- Row filtering (WHERE clause)
    row_filter TEXT,
    
    -- Column filtering
    columns_published TEXT[],
    columns_excluded TEXT[],
    
    -- Metadata
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by VARCHAR(100) DEFAULT current_user,
    description TEXT
);

COMMENT ON TABLE replication.publication_config IS 'Configuration for logical replication publications';

-- =============================================================================
-- PUBLICATION STATUS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS replication.publication_status (
    id SERIAL PRIMARY KEY,
    publication_name VARCHAR(128) NOT NULL REFERENCES replication.publication_config(publication_name),
    last_lsn pg_lsn,
    last_published_at TIMESTAMPTZ,
    total_transactions BIGINT DEFAULT 0,
    total_rows_published BIGINT DEFAULT 0,
    current_state VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, PAUSED, ERROR
    error_message TEXT,
    checked_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pub_status_name 
ON replication.publication_status(publication_name);

-- =============================================================================
-- DEFAULT PUBLICATIONS
-- =============================================================================

-- Publication for ledger transactions (immutable - updates only to status)
INSERT INTO replication.publication_config (
    publication_name, schema_name, table_pattern,
    publish_insert, publish_update, publish_delete, publish_truncate,
    row_filter, columns_excluded, description
) VALUES 
(
    'ledger_transactions_pub',
    'ledger',
    'transactions_%',
    TRUE, TRUE, FALSE, FALSE,
    NULL,
    ARRAY['signature', 'metadata->internal_notes'],
    'Publication for ledger transaction tables - inserts and status updates only'
),
(
    'ledger_entries_pub',
    'ledger',
    'ledger_entries%',
    TRUE, FALSE, FALSE, FALSE,
    NULL,
    NULL,
    'Publication for ledger entries - immutable, inserts only'
),
(
    'audit_logs_pub',
    'audit',
    '%audit_log%',
    TRUE, FALSE, FALSE, FALSE,
    NULL,
    NULL,
    'Publication for audit logs - immutable, inserts only'
),
(
    'reference_data_pub',
    'reference',
    'ALL_TABLES',
    TRUE, TRUE, FALSE, FALSE,
    NULL,
    NULL,
    'Publication for reference data - inserts and updates allowed'
)
ON CONFLICT (publication_name) DO UPDATE SET
    schema_name = EXCLUDED.schema_name,
    table_pattern = EXCLUDED.table_pattern,
    description = EXCLUDED.description;

-- =============================================================================
-- FUNCTION: Create publication from config
-- =============================================================================
CREATE OR REPLACE FUNCTION replication.create_publication(
    p_publication_name VARCHAR
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
    v_tables TEXT[];
    v_table_name TEXT;
    v_sql TEXT;
    v_options TEXT[];
BEGIN
    SELECT * INTO v_config 
    FROM replication.publication_config 
    WHERE publication_name = p_publication_name;
    
    IF NOT FOUND THEN
        RETURN format('ERROR: Publication config not found: %s', p_publication_name);
    END IF;
    
    -- Drop existing publication if exists
    BEGIN
        EXECUTE format('DROP PUBLICATION IF EXISTS %I', p_publication_name);
    EXCEPTION WHEN OTHERS THEN
        NULL;
    END;
    
    -- Build options list
    v_options := ARRAY[]::TEXT[];
    IF v_config.publish_insert THEN v_options := array_append(v_options, 'insert'); END IF;
    IF v_config.publish_update THEN v_options := array_append(v_options, 'update'); END IF;
    IF v_config.publish_delete THEN v_options := array_append(v_options, 'delete'); END IF;
    IF v_config.publish_truncate THEN v_options := array_append(v_options, 'truncate'); END IF;
    
    -- Get tables to publish
    IF v_config.table_pattern = 'ALL_TABLES' THEN
        -- Publish all tables in schema
        SELECT array_agg(c.relname::TEXT)
        INTO v_tables
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = v_config.schema_name
          AND c.relkind = 'r'
          AND c.relpersistence = 'p';
    ELSIF v_config.table_pattern LIKE '%\%%' THEN
        -- Pattern match
        SELECT array_agg(c.relname::TEXT)
        INTO v_tables
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = v_config.schema_name
          AND c.relname LIKE v_config.table_pattern
          AND c.relkind = 'r';
    ELSIF v_config.specific_tables IS NOT NULL THEN
        v_tables := v_config.specific_tables;
    ELSE
        RETURN format('ERROR: No table specification for publication: %s', p_publication_name);
    END IF;
    
    IF v_tables IS NULL OR array_length(v_tables, 1) = 0 THEN
        RETURN format('ERROR: No tables found for publication: %s', p_publication_name);
    END IF;
    
    -- Create publication
    v_sql := format('CREATE PUBLICATION %I FOR TABLE ', p_publication_name);
    
    FOREACH v_table_name IN ARRAY v_tables LOOP
        v_sql := v_sql || format('%I.%I, ', v_config.schema_name, v_table_name);
    END LOOP;
    
    -- Remove trailing comma and space
    v_sql := rtrim(v_sql, ', ');
    
    -- Add options
    IF array_length(v_options, 1) > 0 THEN
        v_sql := v_sql || ' WITH (publish = ''' || array_to_string(v_options, ', ') || ''')';
    END IF;
    
    EXECUTE v_sql;
    
    -- Initialize status
    INSERT INTO replication.publication_status (publication_name, current_state)
    VALUES (p_publication_name, 'ACTIVE')
    ON CONFLICT (publication_name) DO UPDATE SET current_state = 'ACTIVE';
    
    RETURN format('SUCCESS: Created publication %s with %s tables', 
                  p_publication_name, array_length(v_tables, 1));
                  
EXCEPTION WHEN OTHERS THEN
    RETURN format('ERROR: %s', SQLERRM);
END;
$$;

-- =============================================================================
-- FUNCTION: Add row filter to publication
-- =============================================================================
CREATE OR REPLACE FUNCTION replication.set_publication_row_filter(
    p_publication_name VARCHAR,
    p_schema_name VARCHAR,
    p_table_name VARCHAR,
    p_where_clause TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    -- Note: Row filtering requires PostgreSQL 15+
    EXECUTE format('
        ALTER PUBLICATION %I SET TABLE %I.%I WHERE (%s)
    ', p_publication_name, p_schema_name, p_table_name, p_where_clause);
    
    -- Update config
    UPDATE replication.publication_config
    SET row_filter = p_where_clause,
        updated_at = NOW()
    WHERE publication_name = p_publication_name;
    
    RETURN format('SUCCESS: Set row filter for %s.%s in publication %s',
                  p_schema_name, p_table_name, p_publication_name);
                  
EXCEPTION WHEN OTHERS THEN
    RETURN format('ERROR: %s', SQLERRM);
END;
$$;

-- =============================================================================
-- FUNCTION: Add column filter to publication
-- =============================================================================
CREATE OR REPLACE FUNCTION replication.set_publication_column_filter(
    p_publication_name VARCHAR,
    p_schema_name VARCHAR,
    p_table_name VARCHAR,
    p_columns TEXT[]
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    -- Note: Column filtering requires PostgreSQL 15+
    EXECUTE format('
        ALTER PUBLICATION %I SET TABLE %I.%I (%s)
    ', p_publication_name, p_schema_name, p_table_name, 
       array_to_string(p_columns, ', '));
    
    -- Update config
    UPDATE replication.publication_config
    SET columns_published = p_columns,
        updated_at = NOW()
    WHERE publication_name = p_publication_name;
    
    RETURN format('SUCCESS: Set column filter for %s.%s in publication %s',
                  p_schema_name, p_table_name, p_publication_name);
                  
EXCEPTION WHEN OTHERS THEN
    RETURN format('ERROR: %s', SQLERRM);
END;
$$;

-- =============================================================================
-- FUNCTION: Initialize all configured publications
-- =============================================================================
CREATE OR REPLACE FUNCTION replication.init_all_publications()
RETURNS TABLE(publication_name TEXT, result TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
BEGIN
    FOR v_config IN 
        SELECT * FROM replication.publication_config WHERE is_active = TRUE
    LOOP
        publication_name := v_config.publication_name;
        result := replication.create_publication(v_config.publication_name);
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Pause publication
-- =============================================================================
CREATE OR REPLACE FUNCTION replication.pause_publication(p_publication_name VARCHAR)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    -- Note: ALTER PUBLICATION ... DISABLE requires PostgreSQL 15+
    -- For older versions, we'll track status manually
    UPDATE replication.publication_status
    SET current_state = 'PAUSED',
        checked_at = NOW()
    WHERE publication_name = p_publication_name;
    
    RETURN format('Publication %s paused', p_publication_name);
END;
$$;

-- =============================================================================
-- FUNCTION: Resume publication
-- =============================================================================
CREATE OR REPLACE FUNCTION replication.resume_publication(p_publication_name VARCHAR)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE replication.publication_status
    SET current_state = 'ACTIVE',
        checked_at = NOW()
    WHERE publication_name = p_publication_name;
    
    RETURN format('Publication %s resumed', p_publication_name);
END;
$$;

-- =============================================================================
-- VIEW: Publication overview
-- =============================================================================
CREATE OR REPLACE VIEW replication.publication_overview AS
SELECT 
    pc.publication_name,
    pc.schema_name,
    pc.table_pattern,
    pc.publish_insert,
    pc.publish_update,
    pc.publish_delete,
    pc.publish_truncate,
    pc.is_active,
    pc.description,
    ps.current_state,
    ps.last_published_at,
    ps.total_transactions,
    ps.total_rows_published,
    ps.checked_at
FROM replication.publication_config pc
LEFT JOIN replication.publication_status ps ON ps.publication_name = pc.publication_name;

-- =============================================================================
-- VIEW: Native publication status
-- =============================================================================
CREATE OR REPLACE VIEW replication.native_publication_status AS
SELECT 
    p.pubname as publication_name,
    p.pubinsert as publish_insert,
    p.pubupdate as publish_update,
    p.pubdelete as publish_delete,
    p.pubtruncate as publish_truncate,
    p.pubviaroot as publish_via_root,
    array_agg(pt.schemaname || '.' || pt.tablename) as published_tables
FROM pg_publication p
LEFT JOIN pg_publication_tables pt ON pt.pubname = p.pubname
GROUP BY p.pubname, p.pubinsert, p.pubupdate, p.pubdelete, p.pubtruncate, p.pubviaroot;

-- =============================================================================
-- TRIGGER: Update timestamp
-- =============================================================================
CREATE OR REPLACE FUNCTION replication.update_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_pub_config_updated
    BEFORE UPDATE ON replication.publication_config
    FOR EACH ROW EXECUTE FUNCTION replication.update_timestamp();

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA replication TO replication_admin;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA replication TO replication_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA replication TO replication_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA replication TO replication_admin;
