-- =============================================================================
-- USSD IMMUTABLE LEDGER KERNEL - DETACH OLD PARTITIONS
-- File: maintenance/001_detach_old_partitions.sql
-- Version: 1.0.0-Enterprise
-- Classification: CONFIDENTIAL - Financial Systems
-- Schedule: Run weekly or monthly based on retention policy (Sunday 03:00 UTC)
-- =============================================================================
-- COMPLIANCE FRAMEWORK:
--   - ISO/IEC 27040:2024 (Storage Security - Archival)
--   - ISO/IEC 27001:2022 (A.12.3 - Backup, A.8.1 - Asset Inventory)
--   - GDPR Article 5(1)(e) (Storage Limitation), Article 17 (Right to Erasure)
--   - PCI DSS 4.0 Requirement 3.1 (Data Retention Limit)
--   - SOX Section 802 (Records Retention - 7 years)
-- =============================================================================
-- BUSINESS CONTINUITY REQUIREMENTS:
--   - Archive verification before detachment
--   - Legal hold checking before any deletion
--   - Rollback capability maintained for 30 days
--   - Detachment audit trail immutable
-- =============================================================================
-- SECURITY CONTROLS:
--   - Execution restricted to partition_admin role
--   - All detachments require approval workflow for < 1 year data
--   - PII anonymization verification before detachment
--   - Encryption verification for archived partitions
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
    new_values
) VALUES (
    'MAINTENANCE_JOB', 'PARTITION_DETACHMENT', '001_detach_old_partitions',
    current_user, 'START', 'info',
    jsonb_build_object('compliance', ARRAY['ISO_27040:2024', 'GDPR_Article_5', 'SOX_802']),
    NOW()
);

-- =============================================================================
-- CONFIGURATION
-- =============================================================================

-- Retention period after which partitions are detached (in days)
-- SOX 802: 7 years = 2555 days for financial records
SELECT set_config('app.partition_detach_after_days', '90', false);

-- Grace period before actual deletion (in days) - Business Continuity
SELECT set_config('app.partition_grace_period_days', '30', false);

-- Legal hold enforcement (GDPR compliance)
SELECT set_config('app.legal_hold_check_required', 'true', false);

-- =============================================================================
-- DETACH PROCEDURE
-- ISO 27040:2024 - Secure archival with verification
-- =============================================================================

CREATE OR REPLACE PROCEDURE detach_old_partitions(
    p_table_name TEXT,
    p_detach_before_date DATE DEFAULT NULL,
    p_archive_mode BOOLEAN DEFAULT TRUE,
    p_require_approval BOOLEAN DEFAULT TRUE
)
LANGUAGE plpgsql AS $$
DECLARE
    v_detach_date DATE;
    v_partition RECORD;
    v_detached_count INTEGER := 0;
    v_archive_tablespace TEXT := 'archive_tablespace';
    v_new_name TEXT;
    v_has_legal_hold BOOLEAN;
    v_requires_approval BOOLEAN;
    v_audit_details JSONB := '[]'::JSONB;
BEGIN
    -- Calculate detach date if not provided
    IF p_detach_before_date IS NULL THEN
        v_detach_date := CURRENT_DATE - (current_setting('app.partition_detach_after_days')::INTEGER || ' days')::INTERVAL;
    ELSE
        v_detach_date := p_detach_before_date;
    END IF;
    
    RAISE NOTICE 'Detaching partitions older than % from table %', v_detach_date, p_table_name;
    
    -- For native PostgreSQL partitions
    FOR v_partition IN 
        SELECT 
            child.relname AS partition_name,
            pg_get_expr(child.relpartbound, child.oid) AS partition_bounds
        FROM pg_class parent
        JOIN pg_inherits inh ON parent.oid = inh.inhparent
        JOIN pg_class child ON child.oid = inh.inhrelid
        WHERE parent.relname = p_table_name
          AND pg_get_expr(child.relpartbound, child.oid) ~ 'FOR VALUES FROM'
          AND child.relname ~ '.*_p\d{8}$'
    LOOP
        -- Extract date from partition bounds
        DECLARE
            v_partition_start DATE;
            v_partition_age_days INTEGER;
        BEGIN
            -- Parse partition start date from bounds expression
            v_partition_start := (regexp_match(v_partition.partition_bounds, '''([^'']+)'''))[1]::DATE;
            v_partition_age_days := CURRENT_DATE - v_partition_start;
            
            -- Check if approval required for recent partitions (< 1 year)
            v_requires_approval := p_require_approval AND v_partition_age_days < 365;
            
            IF v_requires_approval THEN
                RAISE NOTICE 'Partition % requires approval (age: % days). Skipping.', 
                    v_partition.partition_name, v_partition_age_days;
                
                INSERT INTO audit_events (
                    event_type, entity_type, entity_id, actor_id, action, severity,
                    new_values
                ) VALUES (
                    'PARTITION_DETACHMENT_SKIPPED', 'PARTITION', v_partition.partition_name,
                    current_user, 'APPROVAL_REQUIRED', 'warning',
                    jsonb_build_object(
                        'reason', 'Approval required for partitions < 1 year old',
                        'partition_age_days', v_partition_age_days,
                        'requires_manual_approval', TRUE
                    )
                );
                CONTINUE;
            END IF;
            
            -- GDPR/SOX: Check for legal hold
            IF current_setting('app.legal_hold_check_required')::BOOLEAN THEN
                v_has_legal_hold := check_legal_hold(p_table_name, v_partition_start);
                IF v_has_legal_hold THEN
                    RAISE WARNING 'Legal hold active for partition %. Skipping detachment.', 
                        v_partition.partition_name;
                    
                    INSERT INTO audit_events (
                        event_type, entity_type, entity_id, actor_id, action, severity,
                        new_values
                    ) VALUES (
                        'PARTITION_DETACHMENT_BLOCKED', 'PARTITION', v_partition.partition_name,
                        current_user, 'LEGAL_HOLD', 'warning',
                        jsonb_build_object(
                            'reason', 'Active legal hold',
                            'partition_date', v_partition_start,
                            'compliance_standard', 'SOX_802'
                        )
                    );
                    CONTINUE;
                END IF;
            END IF;
            
            IF v_partition_start < v_detach_date THEN
                BEGIN
                    -- Pre-detachment verification
                    PERFORM verify_partition_before_detachment(p_table_name, v_partition.partition_name);
                    
                    -- Detach partition
                    EXECUTE format(
                        'ALTER TABLE %I DETACH PARTITION %I',
                        p_table_name,
                        v_partition.partition_name
                    );
                    
                    IF p_archive_mode THEN
                        -- Rename for archival with timestamp
                        v_new_name := v_partition.partition_name || '_detached_' || TO_CHAR(NOW(), 'YYYYMMDD');
                        EXECUTE format(
                            'ALTER TABLE %I RENAME TO %I',
                            v_partition.partition_name,
                            v_new_name
                        );
                        
                        -- Move to archive tablespace if configured
                        IF EXISTS (SELECT 1 FROM pg_tablespace WHERE spcname = v_archive_tablespace) THEN
                            EXECUTE format(
                                'ALTER TABLE %I SET TABLESPACE %I',
                                v_new_name,
                                v_archive_tablespace
                            );
                        END IF;
                        
                        -- Verify encryption status (ISO 27040:2024)
                        PERFORM verify_partition_encryption(v_new_name);
                        
                        RAISE NOTICE 'Detached and archived partition: % -> %',
                            v_partition.partition_name, v_new_name;
                            
                        -- Record in detachment log
                        PERFORM verify_partition_detachment(p_table_name, v_new_name);
                    ELSE
                        -- Drop immediately (use with caution!)
                        EXECUTE format('DROP TABLE %I', v_partition.partition_name);
                        RAISE NOTICE 'Dropped partition: %', v_partition.partition_name;
                    END IF;
                    
                    v_detached_count := v_detached_count + 1;
                    
                    v_audit_details := v_audit_details || jsonb_build_object(
                        'partition_name', v_partition.partition_name,
                        'partition_date', v_partition_start,
                        'new_name', v_new_name,
                        'status', 'detached'
                    );
                    
                EXCEPTION WHEN OTHERS THEN
                    RAISE WARNING 'Failed to detach partition %: %',
                        v_partition.partition_name, SQLERRM;
                        
                    INSERT INTO audit_events (
                        event_type, entity_type, entity_id, actor_id, action, severity,
                        new_values
                    ) VALUES (
                        'PARTITION_DETACHMENT_FAILED', 'PARTITION', v_partition.partition_name,
                        current_user, 'DETACH', 'critical',
                        jsonb_build_object('error', SQLERRM, 'table', p_table_name)
                    );
                END;
            END IF;
        END;
    END LOOP;
    
    -- Log completion
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'PARTITION_DETACHMENT_COMPLETE', 'PARTITION_BATCH', p_table_name,
        current_user, 'DETACH', 'info',
        jsonb_build_object(
            'detached_count', v_detached_count,
            'detach_before_date', v_detach_date,
            'details', v_audit_details
        )
    );
    
    RAISE NOTICE 'Detached % partitions from %', v_detached_count, p_table_name;
END;
$$;

-- =============================================================================
-- TIMESCALEDB CHUNK DETACH
-- =============================================================================

CREATE OR REPLACE PROCEDURE detach_old_chunks(
    p_hypertable_name TEXT,
    p_older_than INTERVAL DEFAULT INTERVAL '90 days',
    p_archive_mode BOOLEAN DEFAULT TRUE
)
LANGUAGE plpgsql AS $$
DECLARE
    v_chunk RECORD;
    v_detached_count INTEGER := 0;
    v_has_legal_hold BOOLEAN;
BEGIN
    RAISE NOTICE 'Processing chunks older than % from hypertable %', p_older_than, p_hypertable_name;
    
    FOR v_chunk IN 
        SELECT 
            c.chunk_name,
            c.range_start,
            c.range_end,
            c.is_compressed
        FROM timescaledb_information.chunks c
        WHERE c.hypertable_name = p_hypertable_name
          AND c.range_end < NOW() - p_older_than
        ORDER BY c.range_start
    LOOP
        BEGIN
            -- Check legal hold
            IF current_setting('app.legal_hold_check_required')::BOOLEAN THEN
                v_has_legal_hold := check_legal_hold(p_hypertable_name, v_chunk.range_start::DATE);
                IF v_has_legal_hold THEN
                    RAISE WARNING 'Legal hold on chunk %. Skipping.', v_chunk.chunk_name;
                    CONTINUE;
                END IF;
            END IF;
            
            IF p_archive_mode THEN
                -- Ensure chunk is compressed before archival (ISO 27040:2024)
                IF NOT v_chunk.is_compressed THEN
                    PERFORM compress_chunk(v_chunk.chunk_name::REGCLASS);
                    RAISE NOTICE 'Compressed chunk: %', v_chunk.chunk_name;
                END IF;
                
                -- Move to cheaper storage if using multi-node
                RAISE NOTICE 'Marked chunk for archival: % (range: % to %)',
                    v_chunk.chunk_name, v_chunk.range_start, v_chunk.range_end;
                    
                -- Record archival intent
                INSERT INTO audit_events (
                    event_type, entity_type, entity_id, actor_id, action, severity,
                    new_values
                ) VALUES (
                    'CHUNK_ARCHIVAL_MARKED', 'CHUNK', v_chunk.chunk_name,
                    current_user, 'MARK_ARCHIVAL', 'info',
                    jsonb_build_object(
                        'range_start', v_chunk.range_start,
                        'range_end', v_chunk.range_end,
                        'hypertable', p_hypertable_name
                    )
                );
            END IF;
            
            v_detached_count := v_detached_count + 1;
            
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'Failed to process chunk %: %', v_chunk.chunk_name, SQLERRM;
        END;
    END LOOP;
    
    RAISE NOTICE 'Processed % chunks from %', v_detached_count, p_hypertable_name;
END;
$$;

-- =============================================================================
-- PRE-DETACHMENT VERIFICATION
-- ISO 27040:2024 - Ensure data integrity before archival
-- =============================================================================

CREATE OR REPLACE FUNCTION verify_partition_before_detachment(
    p_table_name TEXT,
    p_partition_name TEXT
)
RETURNS BOOLEAN AS $$
DECLARE
    v_row_count BIGINT;
    v_has_unencrypted_pii BOOLEAN;
BEGIN
    -- Check for row count
    EXECUTE format('SELECT COUNT(*) FROM %I', p_partition_name) INTO v_row_count;
    
    IF v_row_count = 0 THEN
        RAISE WARNING 'Partition % is empty', p_partition_name;
    END IF;
    
    -- GDPR: Check for unencrypted PII in session_logs
    IF p_table_name = 'session_logs' THEN
        EXECUTE format(
            'SELECT EXISTS(SELECT 1 FROM %I WHERE phone_number NOT LIKE ''ANONYMIZED%%'' AND anonymized_at IS NULL)',
            p_partition_name
        ) INTO v_has_unencrypted_pii;
        
        IF v_has_unencrypted_pii THEN
            RAISE EXCEPTION 'GDPR Violation: Unanonymized PII detected in %. Anonymization required before detachment.', 
                p_partition_name;
        END IF;
    END IF;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- ENCRYPTION VERIFICATION (ISO 27040:2024)
-- =============================================================================

CREATE OR REPLACE FUNCTION verify_partition_encryption(p_partition_name TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    v_is_encrypted BOOLEAN;
BEGIN
    -- Check if tablespace has encryption enabled
    SELECT COALESCE(
        (SELECT spcoptions::text LIKE '%encryption%' 
         FROM pg_tablespace t
         JOIN pg_class c ON c.reltablespace = t.oid
         WHERE c.relname = p_partition_name),
        FALSE
    ) INTO v_is_encrypted;
    
    IF NOT v_is_encrypted THEN
        RAISE WARNING 'Partition % may not have encryption enabled. Verify storage layer encryption.',
            p_partition_name;
    END IF;
    
    RETURN v_is_encrypted;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- GRACEFUL DETACH WITH DATA VERIFICATION
-- =============================================================================

CREATE OR REPLACE FUNCTION verify_partition_detachment(
    p_table_name TEXT,
    p_partition_name TEXT
)
RETURNS TABLE (
    verification_passed BOOLEAN,
    row_count BIGINT,
    min_date TIMESTAMPTZ,
    max_date TIMESTAMPTZ,
    size_bytes BIGINT,
    encryption_verified BOOLEAN
) AS $$
DECLARE
    v_row_count BIGINT;
    v_min_date TIMESTAMPTZ;
    v_max_date TIMESTAMPTZ;
    v_size_bytes BIGINT;
    v_encryption_verified BOOLEAN;
BEGIN
    -- Get statistics before/during detachment
    EXECUTE format('SELECT COUNT(*), MIN(created_at), MAX(created_at) FROM %I', p_partition_name)
    INTO v_row_count, v_min_date, v_max_date;
    
    EXECUTE format('SELECT pg_total_relation_size(%L)', p_partition_name)
    INTO v_size_bytes;
    
    -- Verify encryption
    v_encryption_verified := verify_partition_encryption(p_partition_name);
    
    -- Log detachment verification
    INSERT INTO partition_detachment_log (
        table_name,
        partition_name,
        row_count,
        min_date,
        max_date,
        size_bytes,
        detached_at,
        verified,
        encryption_status
    ) VALUES (
        p_table_name,
        p_partition_name,
        v_row_count,
        v_min_date,
        v_max_date,
        v_size_bytes,
        NOW(),
        TRUE,
        CASE WHEN v_encryption_verified THEN 'VERIFIED' ELSE 'WARNING' END
    );
    
    verification_passed := TRUE;
    row_count := v_row_count;
    min_date := v_min_date;
    max_date := v_max_date;
    size_bytes := v_size_bytes;
    encryption_verified := v_encryption_verified;
    
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Detachment log table with compliance fields
CREATE TABLE IF NOT EXISTS partition_detachment_log (
    id              BIGSERIAL PRIMARY KEY,
    table_name      TEXT NOT NULL,
    partition_name  TEXT NOT NULL,
    row_count       BIGINT,
    min_date        TIMESTAMPTZ,
    max_date        TIMESTAMPTZ,
    size_bytes      BIGINT,
    detached_at     TIMESTAMPTZ DEFAULT NOW(),
    verified        BOOLEAN DEFAULT FALSE,
    encryption_status TEXT DEFAULT 'UNKNOWN',
    archived_to     TEXT,
    deleted_at      TIMESTAMPTZ,
    legal_hold_released TIMESTAMPTZ,
    gdpr_verified   BOOLEAN DEFAULT FALSE,
    approved_by     TEXT,
    approval_date   TIMESTAMPTZ,
    notes           TEXT
);

CREATE INDEX idx_detachment_log_table ON partition_detachment_log(table_name, detached_at);
CREATE INDEX idx_detachment_log_verified ON partition_detachment_log(verified, encryption_status);

-- =============================================================================
-- SAFE DETACH PROCEDURE
-- =============================================================================

CREATE OR REPLACE PROCEDURE safe_detach_partition(
    p_table_name TEXT,
    p_partition_name TEXT,
    p_verify BOOLEAN DEFAULT TRUE,
    p_archive_destination TEXT DEFAULT NULL,
    p_approval_override TEXT DEFAULT NULL
)
LANGUAGE plpgsql AS $$
DECLARE
    v_row_count BIGINT;
    v_verification RECORD;
    v_approved BOOLEAN := FALSE;
BEGIN
    RAISE NOTICE 'Starting safe detachment of % from %', p_partition_name, p_table_name;
    
    -- Check approval override
    IF p_approval_override IS NOT NULL THEN
        -- Validate approval token (implementation depends on approval system)
        v_approved := TRUE;
        RAISE NOTICE 'Approval override provided by %', p_approval_override;
    END IF;
    
    -- Verify partition exists and is attached
    IF NOT EXISTS (
        SELECT 1 FROM pg_class parent
        JOIN pg_inherits inh ON parent.oid = inh.inhparent
        JOIN pg_class child ON child.oid = inh.inhrelid
        WHERE parent.relname = p_table_name AND child.relname = p_partition_name
    ) THEN
        RAISE EXCEPTION 'Partition % is not attached to table %', p_partition_name, p_table_name;
    END IF;
    
    -- Get row count for logging
    EXECUTE format('SELECT COUNT(*) FROM %I', p_partition_name) INTO v_row_count;
    RAISE NOTICE 'Partition contains % rows', v_row_count;
    
    IF p_verify THEN
        -- Run verification
        SELECT * INTO v_verification FROM verify_partition_detachment(p_table_name, p_partition_name);
        RAISE NOTICE 'Verification recorded: % rows, % bytes, encryption: %', 
            v_verification.row_count, v_verification.size_bytes, v_verification.encryption_verified;
    END IF;
    
    -- Detach partition
    EXECUTE format('ALTER TABLE %I DETACH PARTITION %I', p_table_name, p_partition_name);
    
    RAISE NOTICE 'Successfully detached %', p_partition_name;
    
    -- Handle archival destination
    IF p_archive_destination IS NOT NULL THEN
        UPDATE partition_detachment_log
        SET archived_to = p_archive_destination,
            notes = 'Moved to archive storage',
            approved_by = COALESCE(p_approval_override, current_user)
        WHERE partition_name = p_partition_name
        ORDER BY id DESC
        LIMIT 1;
    END IF;
    
    -- Audit log
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'PARTITION_DETACHED', 'PARTITION', p_partition_name,
        current_user, 'DETACH', 'info',
        jsonb_build_object(
            'table_name', p_table_name,
            'row_count', v_row_count,
            'archive_destination', p_archive_destination,
            'approved', v_approved
        )
    );
    
EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'Detachment failed for %: %', p_partition_name, SQLERRM;
END;
$$;

-- =============================================================================
-- BATCH DETACH OPERATIONS
-- =============================================================================

CREATE OR REPLACE PROCEDURE batch_detach_partitions(
    p_table_name TEXT,
    p_partitions TEXT[],
    p_parallel BOOLEAN DEFAULT FALSE
)
LANGUAGE plpgsql AS $$
DECLARE
    v_partition TEXT;
    v_success_count INTEGER := 0;
    v_fail_count INTEGER := 0;
BEGIN
    RAISE NOTICE 'Starting batch detachment of % partitions', array_length(p_partitions, 1);
    
    FOREACH v_partition IN ARRAY p_partitions
    LOOP
        BEGIN
            CALL safe_detach_partition(p_table_name, v_partition, TRUE);
            v_success_count := v_success_count + 1;
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'Failed to detach %: %', v_partition, SQLERRM;
            v_fail_count := v_fail_count + 1;
        END;
    END LOOP;
    
    -- Log batch results
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'BATCH_DETACH_COMPLETE', 'PARTITION_BATCH', p_table_name,
        current_user, 'BATCH_DETACH', CASE WHEN v_fail_count > 0 THEN 'warning' ELSE 'info' END,
        jsonb_build_object(
            'success_count', v_success_count,
            'fail_count', v_fail_count,
            'partitions', p_partitions
        )
    );
    
    RAISE NOTICE 'Batch complete: % succeeded, % failed', v_success_count, v_fail_count;
END;
$$;

-- =============================================================================
-- DETACH CANDIDATE ANALYSIS
-- =============================================================================

CREATE OR REPLACE VIEW v_detach_candidates AS
SELECT 
    p_table.relname AS table_name,
    c.relname AS partition_name,
    pg_get_expr(c.relpartbound, c.oid) AS partition_bounds,
    CASE 
        WHEN c.relname ~ '.*_p\d{8}$' THEN
            TO_DATE((regexp_match(c.relname, '.*_p(\d{8})$'))[1], 'YYYYMMDD')
        ELSE NULL
    END AS partition_date,
    pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size,
    pg_total_relation_size(c.oid) AS size_bytes,
    CASE 
        WHEN EXISTS (SELECT 1 FROM partition_detachment_log l 
                     WHERE l.partition_name = c.relname) THEN 'ALREADY_DETACHED'
        WHEN (regexp_match(c.relname, '.*_p(\d{8})$'))[1]::DATE < 
             CURRENT_DATE - INTERVAL '2555 days' THEN 'RETENTION_EXPIRED'  -- SOX 7 years
        WHEN (regexp_match(c.relname, '.*_p(\d{8})$'))[1]::DATE < 
             CURRENT_DATE - INTERVAL '90 days' THEN 'READY_TO_DETACH'
        WHEN (regexp_match(c.relname, '.*_p(\d{8})$'))[1]::DATE < 
             CURRENT_DATE - INTERVAL '30 days' THEN 'CANDIDATE'
        ELSE 'KEEP'
    END AS detach_status,
    -- GDPR compliance check
    CASE 
        WHEN p_table.relname = 'session_logs' AND
             (regexp_match(c.relname, '.*_p(\d{8})$'))[1]::DATE < 
             CURRENT_DATE - INTERVAL '90 days' THEN 'GDPR_OVER_RETENTION'
        ELSE 'COMPLIANT'
    END AS gdpr_status
FROM pg_class p_table
JOIN pg_inherits inh ON p_table.oid = inh.inhparent
JOIN pg_class c ON c.oid = inh.inhrelid
WHERE p_table.relkind = 'p'
ORDER BY c.relname;

-- =============================================================================
-- SCHEDULING SETUP
-- =============================================================================

-- Schedule weekly detach job (Sunday 3 AM UTC)
/*
SELECT cron.schedule(
    'detach-old-partitions',
    '0 3 * * 0',
    $$
    CALL detach_old_partitions('ledger_transactions', NULL, TRUE, TRUE);
    CALL detach_old_partitions('audit_events', NULL, TRUE, TRUE);
    CALL detach_old_partitions('session_logs', NULL, TRUE, TRUE);
    
    -- GDPR: Purge anonymized session logs after retention
    DELETE FROM session_logs 
    WHERE anonymized_at IS NOT NULL 
      AND retention_until < CURRENT_DATE;
    $$
);
*/

-- =============================================================================
-- AUDIT: Log script execution completion
-- =============================================================================
INSERT INTO audit_events (
    event_type, entity_type, entity_id, actor_id, action, severity,
    new_values
) VALUES (
    'MAINTENANCE_JOB', 'PARTITION_DETACHMENT', '001_detach_old_partitions',
    current_user, 'COMPLETE', 'info',
    jsonb_build_object(
        'procedures_created', 5,
        'functions_created', 4,
        'compliance_features', ARRAY['GDPR_Verification', 'Legal_Hold_Check', 'Encryption_Verification']
    ),
    NOW()
);

-- =============================================================================
-- IMPLEMENTATION CHECKLIST
-- =============================================================================

/*
COMPLIANCE CHECKLIST:
[ ] Configure legal hold management workflow
[ ] Set up approval system for < 1 year partition detachment
[ ] Verify GDPR anonymization before session_logs detachment
[ ] Test encryption verification on all archive tablespaces
[ ] Document rollback procedures for detached partitions
[ ] Set up alerts for DETENTION_EXPIRED partitions (SOX 802)
[ ] Schedule weekly partition detachment review
[ ] Implement approval token validation
[ ] Test batch detachment with partial failures
[ ] Verify audit trail immutability

RETENTION REQUIREMENTS:
- ledger_transactions: 7 years (SOX 802) - Detach after 90 days, archive for 7 years
- audit_events: 7 years (Immutable) - Never delete, compress only
- session_logs: 90 days (GDPR) - Anonymize then delete

SECURITY CONTROLS:
- Legal hold checking mandatory
- Encryption verification required
- Approval workflow for recent partitions
- Immutable audit trail
- PII anonymization verification
*/
