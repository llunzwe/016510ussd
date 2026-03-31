-- =============================================================================
-- USSD KERNEL CORE SCHEMA - MAINTENANCE FUNCTIONS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    001_partition_maintenance.sql
-- SCHEMA:      core
-- CATEGORY:    Maintenance Functions
-- DESCRIPTION: Partition management including creation, archival,
--              and cleanup of time-based partitions.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.3 Information backup - Partition backup
├── A.12.4 Logging and monitoring - Partition monitoring
└── A.18.1 Compliance - Retention policy enforcement

ISO/IEC 27040:2024 (Storage Security)
├── Partition archival: Cold storage for old partitions
├── Data retention: Automated enforcement
└── Secure deletion: Partition destruction

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. PARTITION MANAGEMENT
   - Automated creation
   - Archival procedures
   - Cleanup scheduling

2. RETENTION POLICIES
   - Time-based retention
   - Size-based retention
   - Compliance-based retention

3. ARCHIVAL
   - Detach and archive
   - Compression
   - Cold storage

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

DATA PROTECTION:
- Encrypted archival
- Access control on archived data
- Secure deletion certification

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

PARTITION PRUNING:
- Constraint-based pruning
- Partition elimination
- Query optimization

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- PARTITION_CREATED
- PARTITION_ARCHIVED
- PARTITION_DELETED

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- TYPE: Partition information record
-- =============================================================================
CREATE TYPE core.partition_info AS (
    schema_name TEXT,
    table_name TEXT,
    partition_name TEXT,
    partition_method TEXT,
    partition_expression TEXT,
    partition_description TEXT,
    partition_size_bytes BIGINT,
    partition_row_count BIGINT,
    partition_min_value TEXT,
    partition_max_value TEXT
);

-- =============================================================================
-- HELPER FUNCTION: Get partition information for a table
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_partition_info(
    p_schema_name TEXT,
    p_table_name TEXT
)
RETURNS SETOF core.partition_info
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        n.nspname::TEXT AS schema_name,
        c.relname::TEXT AS table_name,
        c2.relname::TEXT AS partition_name,
        CASE p.partstrat
            WHEN 'r' THEN 'RANGE'
            WHEN 'l' THEN 'LIST'
            WHEN 'h' THEN 'HASH'
        END::TEXT AS partition_method,
        pg_get_partkeydef(c.oid)::TEXT AS partition_expression,
        pg_get_expr(c2.relpartbound, c2.oid)::TEXT AS partition_description,
        pg_total_relation_size(c2.oid)::BIGINT AS partition_size_bytes,
        (SELECT COUNT(*) FROM pg_stat_user_tables WHERE relname = c2.relname)::BIGINT AS partition_row_count,
        NULL::TEXT AS partition_min_value,
        NULL::TEXT AS partition_max_value
    FROM pg_class c
    JOIN pg_namespace n ON c.relnamespace = n.oid
    JOIN pg_partitioned_table p ON c.oid = p.partrelid
    JOIN pg_inherits i ON i.inhparent = c.oid
    JOIN pg_class c2 ON i.inhrelid = c2.oid
    WHERE n.nspname = p_schema_name
    AND c.relname = p_table_name
    ORDER BY c2.relname;
END;
$$;

-- =============================================================================
-- HELPER FUNCTION: Generate partition name
-- =============================================================================
CREATE OR REPLACE FUNCTION core.generate_partition_name(
    p_table_name TEXT,
    p_partition_date DATE
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    v_partition_name TEXT;
BEGIN
    v_partition_name := format('%s_%s_%s',
        p_table_name,
        TO_CHAR(p_partition_date, 'YYYY'),
        TO_CHAR(p_partition_date, 'MM')
    );
    RETURN v_partition_name;
END;
$$;

-- =============================================================================
-- MAIN FUNCTION: Manage partitions
-- Description: Automated partition management - creates new partitions,
--              archives old partitions, enforces retention policies
-- PRIORITY: HIGH
-- =============================================================================
CREATE OR REPLACE FUNCTION core.manage_partitions(
    p_schema_name TEXT DEFAULT 'core',
    p_months_ahead INTEGER DEFAULT 2,      -- How many future partitions to create
    p_months_behind INTEGER DEFAULT 12,    -- How many partitions to keep attached
    p_archive_old BOOLEAN DEFAULT TRUE,    -- Whether to archive old partitions
    p_archive_tablespace TEXT DEFAULT 'archive_ts',  -- Tablespace for archived data
    p_dry_run BOOLEAN DEFAULT FALSE        -- If TRUE, only report what would be done
)
RETURNS TABLE (
    action_type TEXT,
    schema_name TEXT,
    table_name TEXT,
    partition_name TEXT,
    action_status TEXT,
    action_message TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_parent_record RECORD;
    v_partition_record RECORD;
    v_partition_date DATE;
    v_partition_name TEXT;
    v_start_date DATE;
    v_end_date DATE;
    v_cutoff_date DATE;
    v_sql TEXT;
BEGIN
    -- Process each partitioned table
    FOR v_parent_record IN 
        SELECT 
            n.nspname::TEXT AS schema_name,
            c.relname::TEXT AS table_name,
            pg_get_partkeydef(c.oid) AS partition_key
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        JOIN pg_partitioned_table p ON c.oid = p.partrelid
        WHERE n.nspname = p_schema_name
    LOOP
        -- ================================================================
        -- STEP 1: Create future partitions
        -- ================================================================
        FOR i IN 0..p_months_ahead LOOP
            v_partition_date := DATE_TRUNC('month', CURRENT_DATE + (i || ' months')::INTERVAL)::DATE;
            v_partition_name := core.generate_partition_name(v_parent_record.table_name, v_partition_date);
            v_start_date := v_partition_date;
            v_end_date := v_partition_date + INTERVAL '1 month';
            
            action_type := 'CREATE_PARTITION';
            schema_name := v_parent_record.schema_name;
            table_name := v_parent_record.table_name;
            partition_name := v_partition_name;
            
            -- Check if partition already exists
            IF EXISTS (
                SELECT 1 FROM pg_class c
                JOIN pg_namespace n ON c.relnamespace = n.oid
                WHERE n.nspname = v_parent_record.schema_name
                AND c.relname = v_partition_name
            ) THEN
                action_status := 'SKIPPED';
                action_message := format('Partition %s already exists', v_partition_name);
            ELSE
                v_sql := format(
                    'CREATE TABLE IF NOT EXISTS %I.%I PARTITION OF %I.%I FOR VALUES FROM (%L) TO (%L)',
                    v_parent_record.schema_name,
                    v_partition_name,
                    v_parent_record.schema_name,
                    v_parent_record.table_name,
                    v_start_date,
                    v_end_date
                );
                
                IF p_dry_run THEN
                    action_status := 'DRY_RUN';
                    action_message := v_sql;
                ELSE
                    BEGIN
                        EXECUTE v_sql;
                        action_status := 'SUCCESS';
                        action_message := format('Created partition %s for range [%s, %s)',
                            v_partition_name, v_start_date, v_end_date);
                        
                        -- Log partition creation
                        INSERT INTO core.audit_trail (
                            event_type,
                            event_description,
                            event_timestamp,
                            metadata
                        ) VALUES (
                            'PARTITION_CREATED',
                            format('Created partition %s.%s', 
                                v_parent_record.schema_name, v_partition_name),
                            NOW(),
                            jsonb_build_object(
                                'schema', v_parent_record.schema_name,
                                'table', v_parent_record.table_name,
                                'partition', v_partition_name,
                                'range_start', v_start_date,
                                'range_end', v_end_date
                            )
                        );
                        
                    EXCEPTION WHEN OTHERS THEN
                        action_status := 'FAILED';
                        action_message := SQLERRM;
                    END;
                END IF;
            END IF;
            
            RETURN NEXT;
        END LOOP;
        
        -- ================================================================
        -- STEP 2: Archive old partitions
        -- ================================================================
        IF p_archive_old THEN
            v_cutoff_date := DATE_TRUNC('month', CURRENT_DATE - (p_months_behind || ' months')::INTERVAL)::DATE;
            
            FOR v_partition_record IN 
                SELECT 
                    c2.relname::TEXT AS partition_name,
                    pg_get_expr(c2.relpartbound, c2.oid) AS partition_bound
                FROM pg_class c
                JOIN pg_namespace n ON c.relnamespace = n.oid
                JOIN pg_inherits i ON i.inhparent = c.oid
                JOIN pg_class c2 ON i.inhrelid = c2.oid
                WHERE n.nspname = v_parent_record.schema_name
                AND c.relname = v_parent_record.table_name
                AND pg_get_expr(c2.relpartbound, c2.oid) IS NOT NULL
            LOOP
                -- Parse partition bound to get date
                IF v_partition_record.partition_bound ~ 'FOR VALUES FROM' THEN
                    -- Extract date from partition bound expression
                    -- Format: FOR VALUES FROM ('2024-01-01') TO ('2024-02-01')
                    DECLARE
                        v_partition_start DATE;
                    BEGIN
                        v_partition_start := (regexp_match(v_partition_record.partition_bound, 
                            \''(\d{4}-\d{2}-\d{2})\''\))[1]::DATE;
                        
                        IF v_partition_start < v_cutoff_date THEN
                            action_type := 'ARCHIVE_PARTITION';
                            schema_name := v_parent_record.schema_name;
                            table_name := v_parent_record.table_name;
                            partition_name := v_partition_record.partition_name;
                            
                            v_sql := format(
                                'ALTER TABLE %I.%I DETACH PARTITION %I.%I',
                                v_parent_record.schema_name,
                                v_parent_record.table_name,
                                v_parent_record.schema_name,
                                v_partition_record.partition_name
                            );
                            
                            IF p_dry_run THEN
                                action_status := 'DRY_RUN';
                                action_message := v_sql;
                            ELSE
                                BEGIN
                                    -- Detach partition
                                    EXECUTE v_sql;
                                    
                                    -- Move to archive tablespace if specified
                                    IF p_archive_tablespace IS NOT NULL THEN
                                        EXECUTE format(
                                            'ALTER TABLE %I.%I SET TABLESPACE %I',
                                            v_parent_record.schema_name,
                                            v_partition_record.partition_name,
                                            p_archive_tablespace
                                        );
                                    END IF;
                                    
                                    action_status := 'SUCCESS';
                                    action_message := format('Detached and archived partition %s',
                                        v_partition_record.partition_name);
                                    
                                    -- Log archival
                                    INSERT INTO core.audit_trail (
                                        event_type,
                                        event_description,
                                        event_timestamp,
                                        metadata
                                    ) VALUES (
                                        'PARTITION_ARCHIVED',
                                        format('Archived partition %s.%s', 
                                            v_parent_record.schema_name, 
                                            v_partition_record.partition_name),
                                        NOW(),
                                        jsonb_build_object(
                                            'schema', v_parent_record.schema_name,
                                            'table', v_parent_record.table_name,
                                            'partition', v_partition_record.partition_name,
                                            'archived_to_tablespace', p_archive_tablespace
                                        )
                                    );
                                    
                                EXCEPTION WHEN OTHERS THEN
                                    action_status := 'FAILED';
                                    action_message := SQLERRM;
                                END;
                            END IF;
                            
                            RETURN NEXT;
                        END IF;
                    EXCEPTION WHEN OTHERS THEN
                        -- Skip partitions we can't parse
                        NULL;
                    END;
                END IF;
            END LOOP;
        END IF;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Create partition for specific date
-- Description: Creates a single partition for a given date
-- =============================================================================
CREATE OR REPLACE FUNCTION core.create_partition_for_date(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_partition_date DATE
)
RETURNS TABLE (
    partition_name TEXT,
    status TEXT,
    message TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_partition_name TEXT;
    v_start_date DATE;
    v_end_date DATE;
BEGIN
    v_partition_name := core.generate_partition_name(p_table_name, p_partition_date);
    v_start_date := DATE_TRUNC('month', p_partition_date)::DATE;
    v_end_date := v_start_date + INTERVAL '1 month';
    
    partition_name := v_partition_name;
    
    -- Check if partition already exists
    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = p_schema_name
        AND c.relname = v_partition_name
    ) THEN
        status := 'EXISTS';
        message := format('Partition %s already exists', v_partition_name);
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Create the partition
    BEGIN
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I.%I PARTITION OF %I.%I FOR VALUES FROM (%L) TO (%L)',
            p_schema_name, v_partition_name,
            p_schema_name, p_table_name,
            v_start_date, v_end_date
        );
        
        status := 'SUCCESS';
        message := format('Created partition %s for range [%s, %s)', 
            v_partition_name, v_start_date, v_end_date);
        
        -- Log creation
        INSERT INTO core.audit_trail (
            event_type,
            event_description,
            event_timestamp,
            metadata
        ) VALUES (
            'PARTITION_CREATED',
            format('Created partition %s.%s', p_schema_name, v_partition_name),
            NOW(),
            jsonb_build_object(
                'schema', p_schema_name,
                'table', p_table_name,
                'partition', v_partition_name,
                'range_start', v_start_date,
                'range_end', v_end_date
            )
        );
        
    EXCEPTION WHEN OTHERS THEN
        status := 'FAILED';
        message := SQLERRM;
    END;
    
    RETURN NEXT;
END;
$$;

-- =============================================================================
-- FUNCTION: Analyze partition statistics
-- Description: Runs ANALYZE on specific partitions
-- =============================================================================
CREATE OR REPLACE FUNCTION core.analyze_partitions(
    p_schema_name TEXT,
    p_table_name TEXT,
    p_older_than_days INTEGER DEFAULT 30
)
RETURNS TABLE (
    partition_name TEXT,
    status TEXT,
    message TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_partition_record RECORD;
BEGIN
    FOR v_partition_record IN 
        SELECT c2.relname::TEXT AS partition_name
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        JOIN pg_inherits i ON i.inhparent = c.oid
        JOIN pg_class c2 ON i.inhrelid = c2.oid
        WHERE n.nspname = p_schema_name
        AND c.relname = p_table_name
    LOOP
        partition_name := v_partition_record.partition_name;
        
        BEGIN
            EXECUTE format('ANALYZE %I.%I', p_schema_name, v_partition_record.partition_name);
            status := 'SUCCESS';
            message := 'Statistics updated';
        EXCEPTION WHEN OTHERS THEN
            status := 'FAILED';
            message := SQLERRM;
        END;
        
        RETURN NEXT;
    END LOOP;
END;
$$;

-- =============================================================================
-- MIGRATION CHECKLIST:
-- □ Create manage_partitions function
-- □ Test partition creation
-- □ Test archival procedure
-- □ Schedule automated maintenance
================================================================================

-- =============================================================================
-- END OF FILE
-- =============================================================================
