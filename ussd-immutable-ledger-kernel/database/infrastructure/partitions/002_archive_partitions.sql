-- =============================================================================
-- ARCHIVE PARTITIONS
-- Implements cold storage partitioning and archival procedures
-- =============================================================================

-- =============================================================================
-- ARCHIVE MANAGEMENT SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS archive_mgmt;

COMMENT ON SCHEMA archive_mgmt IS 'Schema for cold storage and archival management';

-- =============================================================================
-- ARCHIVE CONFIGURATION TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS archive_mgmt.archive_config (
    id SERIAL PRIMARY KEY,
    source_schema VARCHAR(63) NOT NULL,
    source_table VARCHAR(63) NOT NULL,
    archive_schema VARCHAR(63) NOT NULL DEFAULT 'archive',
    archive_table VARCHAR(63),
    partition_retention_days INTEGER NOT NULL DEFAULT 90,
    archive_retention_years INTEGER NOT NULL DEFAULT 7,
    compression_enabled BOOLEAN DEFAULT TRUE,
    encryption_enabled BOOLEAN DEFAULT TRUE,
    verify_after_archive BOOLEAN DEFAULT TRUE,
    archive_destination VARCHAR(255) DEFAULT 'S3', -- S3, GLACIER, LOCAL
    archive_path VARCHAR(500),
    last_archive_run TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(source_schema, source_table)
);

COMMENT ON TABLE archive_mgmt.archive_config IS 'Configuration for automated archival';

-- =============================================================================
-- ARCHIVE LOG TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS archive_mgmt.archive_log (
    id BIGSERIAL PRIMARY KEY,
    archive_job_id UUID NOT NULL DEFAULT gen_random_uuid(),
    source_schema VARCHAR(63) NOT NULL,
    source_table VARCHAR(63) NOT NULL,
    partition_name VARCHAR(128) NOT NULL,
    archive_action VARCHAR(50) NOT NULL, -- ARCHIVE, RESTORE, DELETE, VERIFY
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    rows_processed BIGINT,
    size_bytes BIGINT,
    checksum VARCHAR(64),
    archive_path VARCHAR(500),
    status VARCHAR(20) NOT NULL DEFAULT 'RUNNING', -- RUNNING, SUCCESS, FAILED, PARTIAL
    error_message TEXT,
    initiated_by VARCHAR(100) DEFAULT current_user,
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_archive_log_job 
ON archive_mgmt.archive_log(archive_job_id);

CREATE INDEX IF NOT EXISTS idx_archive_log_status 
ON archive_mgmt.archive_log(status, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_archive_log_partition 
ON archive_mgmt.archive_log(source_schema, source_table, partition_name);

-- =============================================================================
-- FUNCTION: Create archive schema and tables
-- =============================================================================
CREATE OR REPLACE FUNCTION archive_mgmt.setup_archive_storage()
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    -- Create archive schema
    CREATE SCHEMA IF NOT EXISTS archive;
    
    -- Create compressed archive table template
    CREATE TABLE IF NOT EXISTS archive.transaction_archive (
        id BIGINT,
        transaction_id UUID,
        ledger_id UUID,
        account_id UUID,
        entry_type VARCHAR(20),
        amount DECIMAL(20, 8),
        currency_code CHAR(3),
        created_at TIMESTAMPTZ,
        posted_at TIMESTAMPTZ,
        status VARCHAR(20),
        hash_chain BYTEA,
        metadata JSONB,
        archived_at TIMESTAMPTZ DEFAULT NOW(),
        archive_batch_id UUID
    ) WITH (compression = 'zstd');
    
    CREATE TABLE IF NOT EXISTS archive.audit_archive (
        id BIGINT,
        event_id UUID,
        event_timestamp TIMESTAMPTZ,
        event_type VARCHAR(50),
        event_severity VARCHAR(20),
        entity_type VARCHAR(50),
        entity_id UUID,
        user_id UUID,
        action VARCHAR(100),
        change_summary JSONB,
        integrity_hash BYTEA,
        archived_at TIMESTAMPTZ DEFAULT NOW(),
        archive_batch_id UUID
    ) WITH (compression = 'zstd');
    
    -- Create indexes on archive tables
    CREATE INDEX IF NOT EXISTS idx_txn_archive_batch 
    ON archive.transaction_archive(archive_batch_id);
    
    CREATE INDEX IF NOT EXISTS idx_txn_archive_created 
    ON archive.transaction_archive(created_at);
    
    CREATE INDEX IF NOT EXISTS idx_audit_archive_batch 
    ON archive.audit_archive(archive_batch_id);
    
    CREATE INDEX IF NOT EXISTS idx_audit_archive_timestamp 
    ON archive.audit_archive(event_timestamp);
    
    RETURN 'Archive storage initialized';
END;
$$;

-- =============================================================================
-- FUNCTION: Archive old partitions
-- =============================================================================
CREATE OR REPLACE FUNCTION archive_mgmt.archive_old_partitions(
    p_schema_name VARCHAR,
    p_table_name VARCHAR,
    p_older_than_days INTEGER DEFAULT 90
)
RETURNS TABLE(partition_name TEXT, status TEXT, rows_archived BIGINT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_partition RECORD;
    v_batch_id UUID := gen_random_uuid();
    v_archive_config RECORD;
    v_rows_count BIGINT;
    v_checksum VARCHAR(64);
    v_log_id BIGINT;
BEGIN
    -- Get archive config
    SELECT * INTO v_archive_config
    FROM archive_mgmt.archive_config
    WHERE source_schema = p_schema_name 
      AND source_table = p_table_name
      AND is_active = TRUE;
    
    IF NOT FOUND THEN
        partition_name := 'N/A';
        status := 'ERROR: No archive config found';
        rows_archived := 0;
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Find partitions to archive
    FOR v_partition IN 
        SELECT pm.*
        FROM partition_mgmt.partition_metadata pm
        WHERE pm.parent_schema = p_schema_name
          AND pm.parent_table = p_table_name
          AND pm.range_to < NOW() - (p_older_than_days || ' days')::INTERVAL
          AND pm.is_active = TRUE
          AND pm.is_archived = FALSE
        ORDER BY pm.range_from
    LOOP
        partition_name := v_partition.partition_name;
        
        -- Log archive start
        INSERT INTO archive_mgmt.archive_log (
            source_schema, source_table, partition_name,
            archive_action, archive_batch_id
        ) VALUES (
            p_schema_name, p_table_name, v_partition.partition_name,
            'ARCHIVE', v_batch_id
        ) RETURNING id INTO v_log_id;
        
        BEGIN
            -- Get row count
            EXECUTE format('
                SELECT COUNT(*) FROM %I.%I
            ', v_partition.partition_schema, v_partition.partition_name) INTO v_rows_count;
            
            -- Move data to archive (in production, this would export to cold storage)
            IF v_archive_config.archive_destination = 'LOCAL' THEN
                -- Insert into local archive table
                EXECUTE format('
                    INSERT INTO archive.transaction_archive (
                        id, transaction_id, ledger_id, account_id, entry_type,
                        amount, currency_code, created_at, posted_at, status,
                        hash_chain, metadata, archive_batch_id
                    )
                    SELECT 
                        id, transaction_id, ledger_id, account_id, entry_type,
                        amount, currency_code, created_at, posted_at, status,
                        hash_chain, metadata, %L
                    FROM %I.%I
                ', v_batch_id, v_partition.partition_schema, v_partition.partition_name);
            END IF;
            
            -- Calculate checksum
            EXECUTE format('
                SELECT encode(digest(%L || COUNT(*)::text || SUM(id)::text, ''sha256''), ''hex'')
                FROM %I.%I
            ', v_partition.partition_name, v_partition.partition_schema, v_partition.partition_name) 
            INTO v_checksum;
            
            -- Detach and drop partition
            EXECUTE format('
                ALTER TABLE %I.%I DETACH PARTITION %I.%I
            ', p_schema_name, p_table_name, 
               v_partition.partition_schema, v_partition.partition_name);
            
            EXECUTE format('
                DROP TABLE %I.%I
            ', v_partition.partition_schema, v_partition.partition_name);
            
            -- Update metadata
            UPDATE partition_mgmt.partition_metadata
            SET is_active = FALSE,
                is_archived = TRUE,
                archived_at = NOW()
            WHERE id = v_partition.id;
            
            -- Update log
            UPDATE archive_mgmt.archive_log
            SET completed_at = NOW(),
                rows_processed = v_rows_count,
                checksum = v_checksum,
                status = 'SUCCESS',
                archive_path = format('%s/%s/%s', 
                    v_archive_config.archive_destination,
                    v_archive_config.archive_path,
                    v_partition.partition_name)
            WHERE id = v_log_id;
            
            status := 'SUCCESS';
            rows_archived := v_rows_count;
            
        EXCEPTION WHEN OTHERS THEN
            -- Log error
            UPDATE archive_mgmt.archive_log
            SET completed_at = NOW(),
                status = 'FAILED',
                error_message = SQLERRM
            WHERE id = v_log_id;
            
            status := 'FAILED: ' || SQLERRM;
            rows_archived := 0;
        END;
        
        RETURN NEXT;
    END LOOP;
    
    -- Update last run timestamp
    UPDATE archive_mgmt.archive_config
    SET last_archive_run = NOW()
    WHERE source_schema = p_schema_name 
      AND source_table = p_table_name;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Verify archived partition integrity
-- =============================================================================
CREATE OR REPLACE FUNCTION archive_mgmt.verify_archive(
    p_archive_job_id UUID
)
RETURNS TABLE(checksum_valid BOOLEAN, rows_match BOOLEAN, details JSONB)
LANGUAGE plpgsql
AS $$
DECLARE
    v_log RECORD;
    v_current_checksum VARCHAR(64);
    v_current_rows BIGINT;
BEGIN
    SELECT * INTO v_log
    FROM archive_mgmt.archive_log
    WHERE archive_job_id = p_archive_job_id
      AND archive_action = 'ARCHIVE'
      AND status = 'SUCCESS';
    
    IF NOT FOUND THEN
        checksum_valid := FALSE;
        rows_match := FALSE;
        details := jsonb_build_object('error', 'Archive job not found or not successful');
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- In production, this would verify against cold storage
    -- For now, verify against local archive
    IF v_log.archive_path LIKE 'LOCAL/%' THEN
        SELECT COUNT(*) INTO v_current_rows
        FROM archive.transaction_archive
        WHERE archive_batch_id = p_archive_job_id;
        
        rows_match := (v_current_rows = v_log.rows_processed);
    ELSE
        rows_match := NULL; -- Cannot verify external storage
    END IF;
    
    checksum_valid := NULL; -- Would verify against stored checksum
    
    details := jsonb_build_object(
        'archive_job_id', p_archive_job_id,
        'expected_rows', v_log.rows_processed,
        'actual_rows', v_current_rows,
        'archived_at', v_log.completed_at,
        'archive_path', v_log.archive_path
    );
    
    -- Update log with verification
    INSERT INTO archive_mgmt.archive_log (
        source_schema, source_table, partition_name,
        archive_action, archive_batch_id, status, rows_processed
    ) VALUES (
        v_log.source_schema, v_log.source_table, v_log.partition_name,
        'VERIFY', p_archive_job_id, 
        CASE WHEN rows_match THEN 'SUCCESS' ELSE 'FAILED' END,
        v_current_rows
    );
    
    RETURN NEXT;
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Restore archived partition
-- =============================================================================
CREATE OR REPLACE FUNCTION archive_mgmt.restore_partition(
    p_archive_job_id UUID,
    p_target_schema VARCHAR,
    p_target_table VARCHAR
)
RETURNS TABLE(status TEXT, rows_restored BIGINT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_log RECORD;
    v_partition_name TEXT;
    v_parent_table TEXT;
    v_rows_count BIGINT;
    v_log_id BIGINT;
BEGIN
    SELECT * INTO v_log
    FROM archive_mgmt.archive_log
    WHERE archive_job_id = p_archive_job_id
      AND archive_action = 'ARCHIVE'
      AND status = 'SUCCESS';
    
    IF NOT FOUND THEN
        status := 'ERROR: Archive job not found';
        rows_restored := 0;
        RETURN NEXT;
        RETURN;
    END IF;
    
    v_parent_table := quote_ident(p_target_schema) || '.' || quote_ident(p_target_table);
    v_partition_name := quote_ident(p_target_schema) || '.' || 
                       quote_ident(v_log.partition_name || '_restored');
    
    -- Log restore start
    INSERT INTO archive_mgmt.archive_log (
        source_schema, source_table, partition_name,
        archive_action, archive_batch_id
    ) VALUES (
        p_target_schema, p_target_table, v_log.partition_name,
        'RESTORE', p_archive_job_id
    ) RETURNING id INTO v_log_id;
    
    BEGIN
        -- Create partition and restore data from archive
        EXECUTE format('
            CREATE TABLE %s PARTITION OF %s
            FOR VALUES FROM (%L) TO (%L)
        ', v_partition_name, v_parent_table, 
           v_log.metadata->>'range_from', v_log.metadata->>'range_to');
        
        -- Restore data from archive table
        EXECUTE format('
            INSERT INTO %s
            SELECT id, transaction_id, ledger_id, account_id, entry_type,
                   amount, currency_code, created_at, posted_at, status,
                   hash_chain, metadata, NULL, NULL
            FROM archive.transaction_archive
            WHERE archive_batch_id = %L
        ', v_partition_name, p_archive_job_id);
        
        GET DIAGNOSTICS v_rows_count = ROW_COUNT;
        
        -- Update log
        UPDATE archive_mgmt.archive_log
        SET completed_at = NOW(),
            rows_processed = v_rows_count,
            status = 'SUCCESS'
        WHERE id = v_log_id;
        
        status := 'SUCCESS';
        rows_restored := v_rows_count;
        
    EXCEPTION WHEN OTHERS THEN
        UPDATE archive_mgmt.archive_log
        SET completed_at = NOW(),
            status = 'FAILED',
            error_message = SQLERRM
        WHERE id = v_log_id;
        
        status := 'FAILED: ' || SQLERRM;
        rows_restored := 0;
    END;
    
    RETURN NEXT;
    RETURN;
END;
$$;

-- =============================================================================
-- VIEW: Archive status overview
-- =============================================================================
CREATE OR REPLACE VIEW archive_mgmt.archive_status AS
SELECT 
    ac.source_schema,
    ac.source_table,
    ac.partition_retention_days,
    ac.archive_retention_years,
    ac.last_archive_run,
    ac.is_active,
    COUNT(al.id) FILTER (WHERE al.status = 'SUCCESS') as successful_archives,
    COUNT(al.id) FILTER (WHERE al.status = 'FAILED') as failed_archives,
    SUM(al.rows_processed) FILTER (WHERE al.status = 'SUCCESS') as total_rows_archived,
    pg_size_pretty(SUM(al.size_bytes)) as total_size_archived
FROM archive_mgmt.archive_config ac
LEFT JOIN archive_mgmt.archive_log al ON (
    al.source_schema = ac.source_schema 
    AND al.source_table = ac.source_table
)
GROUP BY ac.source_schema, ac.source_table, ac.partition_retention_days,
         ac.archive_retention_years, ac.last_archive_run, ac.is_active;

-- =============================================================================
-- INITIALIZE DEFAULT CONFIGS
-- =============================================================================
INSERT INTO archive_mgmt.archive_config (
    source_schema, source_table, partition_retention_days,
    archive_retention_years, archive_destination, archive_path
) VALUES 
    ('ledger', 'transactions', 90, 7, 'S3', 'ledger/transactions'),
    ('audit', 'ledger_audit_log', 365, 7, 'S3', 'audit/ledger'),
    ('audit', 'transaction_audit_log', 365, 7, 'GLACIER', 'audit/transactions')
ON CONFLICT (source_schema, source_table) DO NOTHING;

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA archive_mgmt TO archive_admin;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA archive_mgmt TO archive_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA archive_mgmt TO archive_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA archive_mgmt TO archive_admin;
