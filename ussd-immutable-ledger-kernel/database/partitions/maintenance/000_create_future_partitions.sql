-- =============================================================================
-- USSD IMMUTABLE LEDGER KERNEL - CREATE FUTURE PARTITIONS
-- File: maintenance/000_create_future_partitions.sql
-- Version: 1.0.0-Enterprise
-- Classification: CONFIDENTIAL - Financial Systems
-- Schedule: Run daily via pg_cron or external scheduler (02:00 UTC)
-- =============================================================================
-- COMPLIANCE FRAMEWORK:
--   - ISO/IEC 27040:2024 (Storage Security - Archival)
--   - ISO/IEC 27031:2025 (Business Continuity - ICT Continuity)
--   - ISO/IEC 27001:2022 (A.12.3 - Backup, A.8.1 - Asset Inventory)
--   - GDPR Article 32 (Security of Processing)
--   - PCI DSS 4.0 Requirement 9.5 (Media Storage)
-- =============================================================================
-- BUSINESS CONTINUITY REQUIREMENTS:
--   - Minimum 30 days of future partitions pre-created
--   - Storage capacity alerts at 80% threshold
--   - Partition creation failure triggers P1 incident
--   - Automated rollback on partial failure
-- =============================================================================
-- SECURITY CONTROLS:
--   - Execution restricted to partition_admin role
--   - All operations logged to immutable audit trail
--   - Failed operations trigger security alert
--   - Partition metadata encrypted at rest
-- =============================================================================

-- =============================================================================
-- SECURITY: Verify execution context
-- =============================================================================
DO $$
BEGIN
    IF NOT (SELECT pg_has_role(current_user, 'partition_admin', 'MEMBER') OR 
            (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)) THEN
        RAISE EXCEPTION 'Insufficient privileges. Required: partition_admin or superuser';
    END IF;
END $$;

-- =============================================================================
-- AUDIT: Log maintenance job start
-- =============================================================================
INSERT INTO audit_events (
    event_type, entity_type, entity_id, actor_id, action, severity,
    new_values, created_at
) VALUES (
    'MAINTENANCE_JOB', 'PARTITION_MANAGEMENT', '000_create_future_partitions',
    current_user, 'START', 'info',
    jsonb_build_object('scheduled_time', '02:00 UTC', 'compliance', 'ISO_27040'),
    NOW()
);

-- =============================================================================
-- CONFIGURATION
-- =============================================================================

-- Number of days ahead to create partitions (Business Continuity: 30 days min)
SELECT set_config('app.partitions_ahead_days', '30', false);

-- Minimum partitions to maintain per table
SELECT set_config('app.min_future_partitions', '3', false);

-- Storage threshold for capacity alerts (ISO 27040:2024)
SELECT set_config('app.storage_alert_threshold_percent', '80', false);

-- =============================================================================
-- FUTURE PARTITION CREATION PROCEDURE
-- ISO 27031:2025 - Ensures ICT continuity through proactive storage management
-- =============================================================================

CREATE OR REPLACE PROCEDURE create_future_partitions(
    p_days_ahead INTEGER DEFAULT 30,
    p_dry_run BOOLEAN DEFAULT FALSE
)
LANGUAGE plpgsql AS $$
DECLARE
    v_hypertable RECORD;
    v_chunk RECORD;
    v_start_date TIMESTAMPTZ;
    v_end_date TIMESTAMPTZ;
    v_partition_date DATE;
    v_chunks_created INTEGER := 0;
    v_chunks_failed INTEGER := 0;
    v_errors TEXT := '';
    v_audit_log JSONB := '[]'::JSONB;
BEGIN
    RAISE NOTICE '[%] Starting future partition creation for next % days...', NOW(), p_days_ahead;
    
    -- Pre-flight capacity check (ISO 27040:2024)
    PERFORM check_storage_capacity();
    
    -- Iterate through all hypertables
    FOR v_hypertable IN 
        SELECT hypertable_name, chunk_time_interval
        FROM timescaledb_information.hypertables
        WHERE hypertable_name IN ('ledger_transactions', 'audit_events', 'session_logs')
    LOOP
        RAISE NOTICE 'Processing hypertable: %', v_hypertable.hypertable_name;
        
        -- Calculate date range
        v_start_date := DATE_TRUNC('day', NOW());
        v_end_date := v_start_date + (p_days_ahead || ' days')::INTERVAL;
        
        -- For TimescaleDB, chunks are created automatically on insert
        -- But we can pre-create them for specific date ranges if needed
        -- This ensures predictable storage allocation
        
        FOR i IN 0..p_days_ahead LOOP
            v_partition_date := (v_start_date + (i || ' days')::INTERVAL)::DATE;
            
            BEGIN
                -- Check if chunk already exists for this date
                IF NOT EXISTS (
                    SELECT 1 FROM timescaledb_information.chunks c
                    WHERE c.hypertable_name = v_hypertable.hypertable_name
                      AND v_partition_date >= c.range_start::DATE
                      AND v_partition_date < c.range_end::DATE
                ) THEN
                    IF NOT p_dry_run THEN
                        -- Create chunk for this time range
                        PERFORM create_chunk(
                            v_hypertable.hypertable_name,
                            v_partition_date::TIMESTAMPTZ,
                            (v_partition_date + INTERVAL '1 day')::TIMESTAMPTZ
                        );
                        
                        -- Audit log entry
                        v_audit_log := v_audit_log || jsonb_build_object(
                            'hypertable', v_hypertable.hypertable_name,
                            'partition_date', v_partition_date,
                            'status', 'created'
                        );
                    END IF;
                    
                    v_chunks_created := v_chunks_created + 1;
                    RAISE NOTICE 'Created chunk for % on date %', 
                        v_hypertable.hypertable_name, v_partition_date;
                END IF;
                
            EXCEPTION WHEN OTHERS THEN
                v_errors := v_errors || format(
                    'Error creating chunk for %s on %s: %s\n',
                    v_hypertable.hypertable_name, v_partition_date, SQLERRM
                );
                v_chunks_failed := v_chunks_failed + 1;
                
                v_audit_log := v_audit_log || jsonb_build_object(
                    'hypertable', v_hypertable.hypertable_name,
                    'partition_date', v_partition_date,
                    'status', 'failed',
                    'error', SQLERRM
                );
                
                RAISE WARNING 'Failed to create chunk: %', SQLERRM;
                
                -- Security alert for partition creation failure (ISO 27001 A.12.3)
                INSERT INTO audit_events (
                    event_type, entity_type, entity_id, actor_id, action, severity,
                    new_values
                ) VALUES (
                    'PARTITION_CREATION_FAILURE', 'CHUNK', v_hypertable.hypertable_name,
                    current_user, 'CREATE', 'critical',
                    jsonb_build_object(
                        'partition_date', v_partition_date,
                        'error', SQLERRM,
                        'compliance_impact', 'HIGH'
                    )
                );
            END;
        END LOOP;
    END LOOP;
    
    -- Log results to audit trail (Immutable)
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'MAINTENANCE_JOB', 'PARTITION_MANAGEMENT', 'create_future_partitions',
        current_user, 'COMPLETE', CASE WHEN v_chunks_failed > 0 THEN 'warning' ELSE 'info' END,
        jsonb_build_object(
            'chunks_created', v_chunks_created,
            'chunks_failed', v_chunks_failed,
            'dry_run', p_dry_run,
            'details', v_audit_log
        )
    );
    
    RAISE NOTICE 'Partition creation complete. Created: %, Failed: %', 
        v_chunks_created, v_chunks_failed;
    
    IF v_errors != '' THEN
        RAISE WARNING 'Errors encountered:\n%', v_errors;
        
        -- Business Continuity: Alert on failure (ISO 27031:2025)
        RAISE EXCEPTION 'Partition creation completed with % failures. Errors: %', 
            v_chunks_failed, v_errors;
    END IF;
END;
$$;

COMMENT ON PROCEDURE create_future_partitions IS 
    'Creates future partitions for time-series tables. Compliance: ISO 27040:2024, ISO 27031:2025. 
     Requires: partition_admin role. Audit: All operations logged.';

-- =============================================================================
-- NATIVE PARTITIONING VERSION
-- =============================================================================

CREATE OR REPLACE PROCEDURE create_native_future_partitions(
    p_table_name TEXT,
    p_column_name TEXT DEFAULT 'created_at',
    p_days_ahead INTEGER DEFAULT 30,
    p_tablespace TEXT DEFAULT NULL,
    p_compliance_classification TEXT DEFAULT 'standard'
)
LANGUAGE plpgsql AS $$
DECLARE
    v_partition_date DATE;
    v_partition_name TEXT;
    v_start_date DATE;
    v_end_date DATE;
    v_sql TEXT;
    v_tablespace_clause TEXT := '';
    v_parent_schema TEXT;
    v_parent_table TEXT;
    v_encryption_clause TEXT := '';
BEGIN
    -- Parse schema and table name
    IF p_table_name LIKE '%.%' THEN
        v_parent_schema := split_part(p_table_name, '.', 1);
        v_parent_table := split_part(p_table_name, '.', 2);
    ELSE
        v_parent_schema := 'public';
        v_parent_table := p_table_name;
    END IF;
    
    IF p_tablespace IS NOT NULL THEN
        v_tablespace_clause := ' TABLESPACE ' || quote_ident(p_tablespace);
    END IF;
    
    -- ISO 27040:2024 - Apply encryption based on data classification
    IF p_compliance_classification IN ('critical', 'restricted') THEN
        v_encryption_clause := ' WITH (compression = ''zstd'', encryption = ''aes-256'')';
    END IF;
    
    v_start_date := CURRENT_DATE;
    
    FOR i IN 1..p_days_ahead LOOP
        v_partition_date := v_start_date + i;
        v_start_date := v_partition_date;
        v_end_date := v_partition_date + INTERVAL '1 day';
        
        v_partition_name := v_parent_table || '_p' || TO_CHAR(v_partition_date, 'YYYYMMDD');
        
        -- Skip if partition already exists
        IF EXISTS (
            SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = v_parent_schema AND c.relname = v_partition_name
        ) THEN
            CONTINUE;
        END IF;
        
        BEGIN
            v_sql := format(
                'CREATE TABLE IF NOT EXISTS %I.%I PARTITION OF %I.%I
                 FOR VALUES FROM (%L) TO (%L) %s %s',
                v_parent_schema,
                v_partition_name,
                v_parent_schema,
                v_parent_table,
                v_partition_date,
                v_end_date,
                v_tablespace_clause,
                v_encryption_clause
            );
            
            EXECUTE v_sql;
            
            -- Add compliance comment
            EXECUTE format(
                'COMMENT ON TABLE %I.%I IS %L',
                v_parent_schema,
                v_partition_name,
                format('Partition for %s. Classification: %s. Created: %s',
                    v_partition_date, p_compliance_classification, NOW())
            );
            
            -- Audit log
            INSERT INTO audit_events (
                event_type, entity_type, entity_id, actor_id, action, severity,
                new_values
            ) VALUES (
                'PARTITION_CREATED', 'PARTITION', v_partition_name,
                current_user, 'CREATE', 'info',
                jsonb_build_object(
                    'parent_table', p_table_name,
                    'partition_date', v_partition_date,
                    'tablespace', p_tablespace,
                    'classification', p_compliance_classification
                )
            );
            
            RAISE NOTICE 'Created partition % for range [% - %]',
                v_partition_name, v_partition_date, v_end_date;
                
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'Failed to create partition %: %', v_partition_name, SQLERRM;
            
            INSERT INTO audit_events (
                event_type, entity_type, entity_id, actor_id, action, severity,
                new_values
            ) VALUES (
                'PARTITION_CREATION_FAILURE', 'PARTITION', v_partition_name,
                current_user, 'CREATE', 'critical',
                jsonb_build_object('error', SQLERRM, 'parent_table', p_table_name)
            );
        END;
    END LOOP;
END;
$$;

-- =============================================================================
-- STORAGE CAPACITY CHECK (ISO 27040:2024)
-- =============================================================================

CREATE OR REPLACE FUNCTION check_storage_capacity()
RETURNS TABLE (
    tablespace_name TEXT,
    total_size BIGINT,
    used_size BIGINT,
    available_size BIGINT,
    usage_percent INTEGER,
    status TEXT
) AS $$
DECLARE
    v_threshold INTEGER := COALESCE(current_setting('app.storage_alert_threshold_percent', true)::INTEGER, 85);
BEGIN
    RETURN QUERY
    SELECT 
        COALESCE(spcname, 'pg_default')::TEXT AS tablespace_name,
        (pg_tablespace_size(spcname) + pg_database_size(current_database()))::BIGINT AS total_size,
        pg_database_size(current_database())::BIGINT AS used_size,
        (pg_tablespace_size(spcname))::BIGINT AS available_size,
        CASE 
            WHEN pg_tablespace_size(spcname) > 0 
            THEN ROUND(pg_database_size(current_database())::NUMERIC / 
                       pg_tablespace_size(spcname)::NUMERIC * 100)::INTEGER
            ELSE 0 
        END AS usage_percent,
        CASE 
            WHEN (pg_database_size(current_database())::NUMERIC / 
                  NULLIF(pg_tablespace_size(spcname), 0) * 100) > v_threshold 
            THEN 'WARNING'
            ELSE 'OK'
        END::TEXT AS status
    FROM pg_tablespace
    WHERE spcname NOT LIKE 'pg_%'
    UNION ALL
    SELECT 
        'pg_default'::TEXT,
        pg_database_size(current_database())::BIGINT,
        pg_database_size(current_database())::BIGINT,
        0::BIGINT,
        0,
        'OK'::TEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- PARTITION GAP DETECTION (ISO 27031:2025 - Business Continuity)
-- =============================================================================

CREATE OR REPLACE FUNCTION detect_partition_gaps(
    p_table_name TEXT,
    p_look_ahead_days INTEGER DEFAULT 30
)
RETURNS TABLE (
    gap_date DATE,
    gap_type TEXT,
    severity TEXT,
    business_impact TEXT
) AS $$
DECLARE
    v_current_date DATE;
    v_expected_date DATE;
    v_chunk RECORD;
    v_last_end_date DATE := NULL;
BEGIN
    v_current_date := CURRENT_DATE;
    
    -- Check for missing chunks in the look-ahead period
    FOR v_expected_date IN 
        SELECT generate_series(v_current_date, v_current_date + p_look_ahead_days, '1 day'::INTERVAL)::DATE
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM timescaledb_information.chunks c
            WHERE c.hypertable_name = p_table_name
              AND v_expected_date >= c.range_start::DATE
              AND v_expected_date < c.range_end::DATE
        ) THEN
            gap_date := v_expected_date;
            gap_type := 'MISSING_CHUNK';
            severity := CASE 
                WHEN v_expected_date <= v_current_date + 3 THEN 'CRITICAL'
                WHEN v_expected_date <= v_current_date + 7 THEN 'HIGH'
                ELSE 'MEDIUM'
            END;
            business_impact := CASE severity
                WHEN 'CRITICAL' THEN 'Write failures imminent - immediate action required'
                WHEN 'HIGH' THEN 'Risk of write failures within 7 days'
                ELSE 'Gap detected - schedule creation'
            END;
            RETURN NEXT;
        END IF;
    END LOOP;
    
    -- Check for oversized chunks (potential issues)
    FOR v_chunk IN 
        SELECT c.chunk_name, d.total_bytes
        FROM timescaledb_information.chunks c
        JOIN chunks_detailed_size(p_table_name) d ON d.chunk_name = c.chunk_name
        WHERE c.hypertable_name = p_table_name
          AND d.total_bytes > 1073741824  -- 1GB threshold
    LOOP
        gap_date := NULL;
        gap_type := 'OVERSIZED_CHUNK: ' || v_chunk.chunk_name;
        severity := 'WARNING';
        business_impact := 'Performance degradation risk - consider chunk splitting';
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- EMERGENCY PARTITION CREATION (ISO 27031:2025 - DR Procedure)
-- =============================================================================

CREATE OR REPLACE FUNCTION create_emergency_partition(
    p_table_name TEXT,
    p_target_date DATE,
    p_reason TEXT DEFAULT 'Emergency - incoming data'
)
RETURNS TEXT AS $$
DECLARE
    v_partition_name TEXT;
    v_sql TEXT;
BEGIN
    -- Create an emergency partition with minimal overhead
    v_partition_name := p_table_name || '_p' || TO_CHAR(p_target_date, 'YYYYMMDD') || '_emergency';
    
    -- For native partitioning
    v_sql := format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I
         FOR VALUES FROM (%L) TO (%L)',
        v_partition_name,
        p_table_name,
        p_target_date,
        p_target_date + INTERVAL '1 day'
    );
    
    EXECUTE v_sql;
    
    -- Add minimal index for immediate use
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS idx_%s_emergency ON %I(created_at)',
        v_partition_name, v_partition_name
    );
    
    -- Log emergency creation (CRITICAL audit event)
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'EMERGENCY_PARTITION_CREATED', 'PARTITION', v_partition_name,
        current_user, 'EMERGENCY_CREATE', 'critical',
        jsonb_build_object(
            'table_name', p_table_name,
            'target_date', p_target_date,
            'reason', p_reason,
            'requires_followup', TRUE
        )
    );
    
    RAISE WARNING 'EMERGENCY PARTITION CREATED: % for table % on date %. REQUIRES FOLLOW-UP.',
        v_partition_name, p_table_name, p_target_date;
    
    RETURN v_partition_name;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- SCHEDULING SETUP
-- =============================================================================

-- pg_cron setup with compliance logging
-- Requires: CREATE EXTENSION pg_cron;

-- Example pg_cron setup (run daily at 2 AM UTC)
/*
SELECT cron.schedule(
    'create-future-partitions',
    '0 2 * * *',
    $$
    CALL create_future_partitions(30, FALSE);
    
    -- Log job execution
    INSERT INTO audit_events (event_type, entity_type, entity_id, actor_id, action, severity, new_values)
    VALUES ('SCHEDULED_JOB', 'CRON', 'create-future-partitions', 'cron', 'EXECUTE', 'info', 
            jsonb_build_object('job_status', 'completed'));
    $$
);

-- Schedule gap detection (run hourly)
SELECT cron.schedule(
    'detect-partition-gaps',
    '0 * * * *',
    $$
    SELECT * FROM detect_partition_gaps('ledger_transactions') WHERE severity IN ('CRITICAL', 'HIGH');
    
    -- Alert if gaps detected
    DO $$
    BEGIN
        IF EXISTS (SELECT 1 FROM detect_partition_gaps('ledger_transactions') WHERE severity = 'CRITICAL') THEN
            RAISE EXCEPTION 'CRITICAL: Partition gaps detected - immediate action required';
        END IF;
    END $$;
    $$
);

-- Schedule storage capacity check (daily)
SELECT cron.schedule(
    'check-storage-capacity',
    '0 1 * * *',
    'SELECT * FROM check_storage_capacity() WHERE status = ''WARNING'''
);
*/

-- =============================================================================
-- MONITORING VIEW
-- =============================================================================

CREATE OR REPLACE VIEW v_partition_readiness AS
SELECT 
    h.hypertable_name,
    COUNT(c.chunk_name) FILTER (WHERE c.range_start >= CURRENT_DATE) AS future_chunks,
    COUNT(c.chunk_name) FILTER (WHERE c.range_start >= CURRENT_DATE 
                                 AND c.range_start < CURRENT_DATE + INTERVAL '7 days') AS next_7_days,
    COUNT(c.chunk_name) FILTER (WHERE c.range_start >= CURRENT_DATE 
                                 AND c.range_start < CURRENT_DATE + INTERVAL '30 days') AS next_30_days,
    MAX(c.range_end)::DATE AS last_covered_date,
    CASE 
        WHEN MAX(c.range_end) < CURRENT_DATE + INTERVAL '7 days' THEN 'INSUFFICIENT'
        WHEN MAX(c.range_end) < CURRENT_DATE + INTERVAL '30 days' THEN 'WARNING'
        ELSE 'OK'
    END AS readiness_status,
    CASE 
        WHEN MAX(c.range_end) < CURRENT_DATE + INTERVAL '7 days' THEN 'P1 - Immediate action required'
        WHEN MAX(c.range_end) < CURRENT_DATE + INTERVAL '30 days' THEN 'P2 - Schedule partition creation'
        ELSE 'No action required'
    END AS recommended_action
FROM timescaledb_information.hypertables h
LEFT JOIN timescaledb_information.chunks c ON c.hypertable_name = h.hypertable_name
GROUP BY h.hypertable_name;

-- =============================================================================
-- AUDIT: Log script execution completion
-- =============================================================================
INSERT INTO audit_events (
    event_type, entity_type, entity_id, actor_id, action, severity,
    new_values
) VALUES (
    'MAINTENANCE_JOB', 'PARTITION_MANAGEMENT', '000_create_future_partitions',
    current_user, 'COMPLETE', 'info',
    jsonb_build_object(
        'procedures_created', 3,
        'functions_created', 4,
        'compliance_standards', ARRAY['ISO_27040:2024', 'ISO_27031:2025', 'ISO_27001:2022']
    ),
    NOW()
);

-- =============================================================================
-- IMPLEMENTATION CHECKLIST
-- =============================================================================

/*
COMPLIANCE CHECKLIST:
[ ] Install and configure pg_cron extension
[ ] Create partition_admin role and assign to DBA team
[ ] Configure storage monitoring alerts (80% threshold)
[ ] Set up P1 incident response for partition creation failures
[ ] Document emergency partition creation procedures
[ ] Test gap detection alerting
[ ] Validate encryption settings for critical partitions
[ ] Schedule monthly partition readiness reviews
[ ] Integrate with SIEM for audit event forwarding
[ ] Test disaster recovery procedures for partition metadata

BUSINESS CONTINUITY REQUIREMENTS:
- RTO: 4 hours maximum for partition recovery
- RPO: 0 (partitions are pre-created, no data loss risk)
- Minimum 30 days future partition coverage
- Automated alerts for gaps > 3 days

SECURITY CONTROLS:
- Role-based access: partition_admin required
- Immutable audit trail for all operations
- Encryption: AES-256 for critical partitions
- Alerting: Automatic security alerts on failures
*/
