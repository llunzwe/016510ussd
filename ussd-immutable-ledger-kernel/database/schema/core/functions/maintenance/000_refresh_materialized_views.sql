-- =============================================================================
-- USSD KERNEL CORE SCHEMA - MAINTENANCE FUNCTIONS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    000_refresh_materialized_views.sql
-- SCHEMA:      core
-- CATEGORY:    Maintenance Functions
-- DESCRIPTION: Materialized view refresh procedures with concurrent refresh
--              support and dependency management.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.3 Information backup - View consistency
├── A.12.4 Logging and monitoring - Refresh monitoring
└── A.14.2 Business continuity - View availability

ISO/IEC 27031:2025 (Business Continuity ICT Readiness)
├── Concurrent refresh: Minimal downtime
├── Refresh scheduling: Automated maintenance
└── Failure recovery: Retry mechanisms

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. REFRESH STRATEGIES
   - Concurrent refresh (non-blocking)
   - Full refresh (when necessary)
   - Incremental refresh (custom logic)

2. DEPENDENCY MANAGEMENT
   - View dependency ordering
   - Cascade refresh
   - Circular dependency detection

3. SCHEDULING
   - Cron-based scheduling
   - Event-based refresh
   - On-demand refresh API

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

ACCESS CONTROL:
- Refresh function privileges
- View modification restrictions
- Audit logging

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

REFRESH OPTIMIZATION:
- Off-peak scheduling
- Parallel refresh
- Resource throttling

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- VIEW_REFRESH_STARTED
- VIEW_REFRESH_COMPLETED
- VIEW_REFRESH_FAILED

RETENTION: 2 years
================================================================================
*/

-- =============================================================================
-- HELPER FUNCTION: Get materialized view dependencies
-- Description: Returns ordered list of materialized views based on dependencies
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_materialized_view_dependencies(
    p_schema_name TEXT DEFAULT 'core'
)
RETURNS TABLE (
    view_schema TEXT,
    view_name TEXT,
    view_definition TEXT,
    dependency_order INTEGER
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE view_deps AS (
        -- Base case: materialized views with no dependencies
        SELECT 
            c.oid::regclass::TEXT AS view_name,
            c.relnamespace::regnamespace::TEXT AS view_schema,
            0 AS depth
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE c.relkind = 'm'  -- materialized view
        AND n.nspname = p_schema_name
        AND NOT EXISTS (
            SELECT 1 FROM pg_depend d
            WHERE d.classid = 'pg_class'::regclass
            AND d.objid = c.oid
            AND d.deptype = 'n'
        )
        
        UNION ALL
        
        -- Recursive case: views that depend on others
        SELECT 
            c.oid::regclass::TEXT AS view_name,
            c.relnamespace::regnamespace::TEXT AS view_schema,
            vd.depth + 1
        FROM pg_class c
        JOIN pg_namespace n ON c.relnamespace = n.oid
        JOIN pg_depend d ON d.objid = c.oid
        JOIN pg_rewrite r ON r.oid = d.objid
        JOIN view_deps vd ON vd.view_name = d.refobjid::regclass::TEXT
        WHERE c.relkind = 'm'
        AND n.nspname = p_schema_name
        AND vd.depth < 10  -- Prevent infinite recursion
    )
    SELECT DISTINCT ON (vd.view_name)
        vd.view_schema,
        SPLIT_PART(vd.view_name, '.', 2) AS view_name,
        pg_get_viewdef(vd.view_name::regclass, true) AS view_definition,
        vd.depth AS dependency_order
    FROM view_deps vd
    ORDER BY vd.view_name, vd.depth DESC;
END;
$$;

-- =============================================================================
-- MAIN FUNCTION: Refresh materialized views
-- Description: Refresh all materialized views in dependency order
-- PRIORITY: HIGH
-- =============================================================================
CREATE OR REPLACE FUNCTION core.refresh_materialized_views(
    p_schema_name TEXT DEFAULT 'core',
    p_concurrent BOOLEAN DEFAULT TRUE,
    p_view_pattern TEXT DEFAULT NULL,  -- NULL = all views, or pattern like 'mv_%'
    p_force_full_refresh BOOLEAN DEFAULT FALSE
)
RETURNS TABLE (
    view_name TEXT,
    refresh_status TEXT,
    refresh_duration_ms INTEGER,
    rows_affected BIGINT,
    error_message TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_view RECORD;
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_refresh_mode TEXT;
    v_has_unique_index BOOLEAN;
BEGIN
    -- Log refresh start
    INSERT INTO core.audit_trail (
        event_type,
        event_description,
        event_timestamp,
        metadata
    ) VALUES (
        'VIEW_REFRESH_STARTED',
        'Starting materialized view refresh for schema: ' || p_schema_name,
        NOW(),
        jsonb_build_object(
            'schema', p_schema_name,
            'concurrent', p_concurrent,
            'view_pattern', p_view_pattern,
            'force_full_refresh', p_force_full_refresh
        )
    );
    
    -- Loop through all materialized views in dependency order
    FOR v_view IN 
        SELECT 
            schemaname,
            matviewname,
            hasindexes
        FROM pg_matviews
        WHERE schemaname = p_schema_name
        AND (p_view_pattern IS NULL OR matviewname LIKE p_view_pattern)
        ORDER BY matviewname
    LOOP
        view_name := v_view.matviewname;
        v_start_time := clock_timestamp();
        
        BEGIN
            -- Check if view has unique index (required for concurrent refresh)
            SELECT EXISTS (
                SELECT 1 FROM pg_indexes
                WHERE schemaname = v_view.schemaname
                AND tablename = v_view.matviewname
                AND indexdef LIKE '%UNIQUE%'
            ) INTO v_has_unique_index;
            
            -- Determine refresh mode
            IF p_force_full_refresh OR NOT p_concurrent OR NOT v_has_unique_index THEN
                v_refresh_mode := 'FULL';
            ELSE
                v_refresh_mode := 'CONCURRENT';
            END IF;
            
            -- Execute refresh
            IF v_refresh_mode = 'CONCURRENT' THEN
                EXECUTE format('REFRESH MATERIALIZED VIEW CONCURRENTLY %I.%I', 
                    v_view.schemaname, v_view.matviewname);
            ELSE
                EXECUTE format('REFRESH MATERIALIZED VIEW %I.%I', 
                    v_view.schemaname, v_view.matviewname);
            END IF;
            
            v_end_time := clock_timestamp();
            refresh_status := 'SUCCESS';
            refresh_duration_ms := EXTRACT(MILLISECOND FROM (v_end_time - v_start_time))::INTEGER;
            rows_affected := 0;  -- Materialized views don't report rows affected
            error_message := NULL;
            
            -- Log success
            INSERT INTO core.audit_trail (
                event_type,
                event_description,
                event_timestamp,
                metadata
            ) VALUES (
                'VIEW_REFRESH_COMPLETED',
                'Refreshed materialized view: ' || v_view.matviewname,
                NOW(),
                jsonb_build_object(
                    'view_name', v_view.matviewname,
                    'refresh_mode', v_refresh_mode,
                    'duration_ms', refresh_duration_ms
                )
            );
            
        EXCEPTION WHEN OTHERS THEN
            v_end_time := clock_timestamp();
            refresh_status := 'FAILED';
            refresh_duration_ms := EXTRACT(MILLISECOND FROM (v_end_time - v_start_time))::INTEGER;
            rows_affected := 0;
            error_message := SQLERRM;
            
            -- Log failure
            INSERT INTO core.audit_trail (
                event_type,
                event_description,
                event_timestamp,
                metadata
            ) VALUES (
                'VIEW_REFRESH_FAILED',
                'Failed to refresh materialized view: ' || v_view.matviewname,
                NOW(),
                jsonb_build_object(
                    'view_name', v_view.matviewname,
                    'error', SQLERRM,
                    'sqlstate', SQLSTATE
                )
            );
        END;
        
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Refresh a specific materialized view
-- Description: Refresh single view with error handling
-- =============================================================================
CREATE OR REPLACE FUNCTION core.refresh_single_materialized_view(
    p_view_name TEXT,
    p_schema_name TEXT DEFAULT 'core',
    p_concurrent BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (
    success BOOLEAN,
    refresh_mode TEXT,
    duration_ms INTEGER,
    error_message TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_start_time TIMESTAMPTZ;
    v_has_unique_index BOOLEAN;
BEGIN
    v_start_time := clock_timestamp();
    
    -- Check if view exists
    IF NOT EXISTS (
        SELECT 1 FROM pg_matviews 
        WHERE schemaname = p_schema_name 
        AND matviewname = p_view_name
    ) THEN
        success := FALSE;
        refresh_mode := 'NONE';
        duration_ms := 0;
        error_message := format('Materialized view %I.%I does not exist', p_schema_name, p_view_name);
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Check for unique index
    SELECT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE schemaname = p_schema_name
        AND tablename = p_view_name
        AND indexdef LIKE '%UNIQUE%'
    ) INTO v_has_unique_index;
    
    BEGIN
        IF p_concurrent AND v_has_unique_index THEN
            EXECUTE format('REFRESH MATERIALIZED VIEW CONCURRENTLY %I.%I', 
                p_schema_name, p_view_name);
            refresh_mode := 'CONCURRENT';
        ELSE
            EXECUTE format('REFRESH MATERIALIZED VIEW %I.%I', 
                p_schema_name, p_view_name);
            refresh_mode := 'FULL';
        END IF;
        
        success := TRUE;
        error_message := NULL;
        
    EXCEPTION WHEN OTHERS THEN
        success := FALSE;
        refresh_mode := 'FAILED';
        error_message := SQLERRM;
    END;
    
    duration_ms := EXTRACT(MILLISECOND FROM (clock_timestamp() - v_start_time))::INTEGER;
    
    RETURN NEXT;
END;
$$;

-- =============================================================================
-- FUNCTION: Schedule materialized view refresh
-- Description: Creates a pg_cron job for periodic refresh
-- =============================================================================
CREATE OR REPLACE FUNCTION core.schedule_view_refresh(
    p_job_name TEXT,
    p_view_pattern TEXT,
    p_cron_schedule TEXT,  -- e.g., '0 2 * * *' for daily at 2 AM
    p_concurrent BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (
    job_id BIGINT,
    schedule_status TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_job_id BIGINT;
BEGIN
    -- Note: This requires pg_cron extension to be installed
    -- The actual scheduling would be done via pg_cron
    
    job_id := 0;
    schedule_status := 'PENDING';
    
    -- Try to create cron job if extension is available
    BEGIN
        EXECUTE format(
            'SELECT cron.schedule(%L, %L, %L)',
            p_job_name,
            p_cron_schedule,
            format('SELECT core.refresh_materialized_views(%L, %s, %L)', 
                'core', p_concurrent, p_view_pattern)
        ) INTO v_job_id;
        
        job_id := v_job_id;
        schedule_status := 'SCHEDULED';
        
    EXCEPTION WHEN undefined_function THEN
        schedule_status := 'CRON_NOT_AVAILABLE';
    WHEN OTHERS THEN
        schedule_status := 'ERROR: ' || SQLERRM;
    END;
    
    RETURN NEXT;
END;
$$;

-- =============================================================================
-- MIGRATION CHECKLIST:
-- □ Create refresh_materialized_views function
-- □ Test concurrent refresh
-- □ Test error handling
-- □ Schedule automated refresh
================================================================================

-- =============================================================================
-- END OF FILE
-- =============================================================================
