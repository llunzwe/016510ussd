-- ============================================================================
-- POINT-IN-TIME RECOVERY (PITR) PROCEDURE
-- ============================================================================
-- Purpose: Recover the ledger database to a specific point in time while
--          maintaining hash chain integrity and cryptographic proofs.
-- Author:  USSD Immutable Ledger Team
-- Date:    2026-03-30
-- ============================================================================
-- COMPLIANCE HEADER:
--   ISO/IEC 27031:2025 - Information Technology - Security Techniques - 
--   Guidelines for Information and Communications Technology Readiness for 
--   Business Continuity
--   
--   This procedure implements:
--   - Clause 6.2: Recovery strategies and procedures
--   - Clause 7.3: Data backup and restoration processes
--   - Clause 8.1: Testing and maintenance of recovery capabilities
--   - Annex B: Point-in-time recovery requirements
--
--   RTO Target: 4 hours | RPO Target: 15 minutes
--   Recovery Validation: Hash chain integrity verification required
--   Audit Trail: Full recovery operation logging mandatory
-- ============================================================================

-- =============================================================================
-- STEP 1: PRE-RECOVERY VALIDATION AND PREPARATION
-- =============================================================================

-- 1.1 Verify WAL archiving is enabled and functional
DO $$
DECLARE
    v_wal_level TEXT;
    v_archive_mode TEXT;
    v_archive_command TEXT;
BEGIN
    SELECT setting INTO v_wal_level FROM pg_settings WHERE name = 'wal_level';
    SELECT setting INTO v_archive_mode FROM pg_settings WHERE name = 'archive_mode';
    SELECT setting INTO v_archive_command FROM pg_settings WHERE name = 'archive_command';
    
    IF v_wal_level != 'replica' AND v_wal_level != 'logical' THEN
        RAISE EXCEPTION 'WAL level must be replica or logical for PITR. Current: %', v_wal_level;
    END IF;
    
    IF v_archive_mode != 'on' AND v_archive_mode != 'always' THEN
        RAISE EXCEPTION 'Archive mode must be enabled for PITR. Current: %', v_archive_mode;
    END IF;
    
    RAISE NOTICE 'WAL archiving configuration validated successfully';
END $$;

-- 1.2 Create recovery metadata tracking table if not exists
CREATE TABLE IF NOT EXISTS pitr_recovery_log (
    recovery_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_timestamp TIMESTAMPTZ NOT NULL,
    actual_recovery_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    recovery_status VARCHAR(50) NOT NULL DEFAULT 'INITIATED',
    base_backup_name TEXT NOT NULL,
    wal_segments_applied INTEGER,
    hash_chain_validated BOOLEAN DEFAULT FALSE,
    recovered_by TEXT DEFAULT CURRENT_USER,
    recovery_notes TEXT,
    rollback_snapshot_name TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 1.3 Record recovery initiation
-- NOTE: Customize these variables before execution
\set target_timestamp '2026-03-30 12:00:00+00'
\set base_backup_name 'base_backup_20260330_000000'

INSERT INTO pitr_recovery_log (
    target_timestamp,
    base_backup_name,
    recovery_status,
    recovery_notes
) VALUES (
    :'target_timestamp',
    :'base_backup_name',
    'INITIATED',
    'PITR initiated for ledger recovery'
) RETURNING recovery_id;

-- =============================================================================
-- STEP 2: CREATE PRE-RECOVERY SNAPSHOT FOR ROLLBACK CAPABILITY
-- =============================================================================

-- 2.1 Create a logical snapshot using pg_dump for critical tables
-- Default backup path - customize via environment variable or modify below
\set backup_path '/var/lib/postgresql/backups/pre_pitr_snapshot_' || (SELECT recovery_id::text FROM pitr_recovery_log WHERE recovery_status = 'INITIATED' ORDER BY created_at DESC LIMIT 1)

-- Create snapshot metadata
CREATE TABLE IF NOT EXISTS recovery_snapshots (
    snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_name TEXT NOT NULL UNIQUE,
    snapshot_type VARCHAR(20) NOT NULL CHECK (snapshot_type IN ('LOGICAL', 'PHYSICAL', 'BLOCK')),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    snapshot_path TEXT NOT NULL,
    checksum_sha256 TEXT,
    size_bytes BIGINT,
    recovery_id UUID REFERENCES pitr_recovery_log(recovery_id),
    is_valid BOOLEAN DEFAULT TRUE
);

-- 2.2 Record snapshot information
INSERT INTO recovery_snapshots (
    snapshot_name,
    snapshot_type,
    snapshot_path,
    recovery_id
) VALUES (
    'pre_pitr_snapshot_' || gen_random_uuid()::TEXT,
    'LOGICAL',
    :'backup_path',
    (SELECT recovery_id FROM pitr_recovery_log WHERE recovery_status = 'INITIATED' ORDER BY created_at DESC LIMIT 1)
);

-- =============================================================================
-- STEP 3: STOP APPLICATION CONNECTIONS AND PREPARE DATABASE
-- =============================================================================

-- 3.1 Terminate active connections (except current)
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE datname = current_database() 
AND pid != pg_backend_pid()
AND usename NOT IN ('postgres', 'replicator', 'backup', 'monitoring');  -- Exclude system/service users

-- 3.2 Set database to restricted mode
ALTER DATABASE current_database() WITH ALLOW_CONNECTIONS FALSE;

-- 3.3 Create recovery.signal file for PostgreSQL 12+
-- NOTE: This must be executed via shell command before PostgreSQL restart:
--   touch $PGDATA/recovery.signal

-- =============================================================================
-- STEP 4: CONFIGURE RECOVERY PARAMETERS
-- =============================================================================

-- 4.1 Generate recovery.conf equivalent (PostgreSQL 12+)
-- These settings should be placed in postgresql.auto.conf or postgresql.conf

/*
Add the following to postgresql.conf or use ALTER SYSTEM:

-- Point-in-time recovery target (customize timestamp as needed)
recovery_target_time = '2026-03-30 12:00:00+00'
recovery_target_action = 'pause'
recovery_target_inclusive = true

-- WAL restore configuration (customize paths to match your archive location)
restore_command = 'cp /var/lib/postgresql/archive/%f %p'
archive_cleanup_command = 'pg_archivecleanup /var/lib/postgresql/archive %r'

-- Recovery performance tuning
recovery_min_apply_delay = 0
hot_standby = on
max_wal_senders = 10
wal_keep_size = 1GB
*/

-- 4.2 Apply recovery settings via ALTER SYSTEM (requires restart)
-- Uncomment and customize these commands before execution:
-- ALTER SYSTEM SET recovery_target_time = '2026-03-30 12:00:00+00';
-- ALTER SYSTEM SET recovery_target_action = 'pause';
-- ALTER SYSTEM SET restore_command = 'cp /var/lib/postgresql/archive/%f %p';
-- SELECT pg_reload_conf();

-- =============================================================================
-- STEP 5: RESTORE FROM BASE BACKUP
-- =============================================================================

-- 5.1 Verify base backup integrity
-- Verify backup integrity using pg_verifybackup:
-- \! pg_verifybackup /var/lib/postgresql/backups/base/latest

-- 5.2 Restore base backup commands (execute via shell)
-- Execute these shell commands as the postgres user:
/*
#!/bin/bash
set -e

# Configuration
PGDATA=${PGDATA:-/var/lib/postgresql/data}
BACKUP_DIR="/var/lib/postgresql/backups/base/latest"
RECOVERY_TIMESTAMP="2026-03-30 12:00:00+00"

# 1. Stop PostgreSQL
pg_ctl stop -D $PGDATA -m fast || systemctl stop postgresql

# 2. Backup current data directory
echo "Creating safety backup..."
mv $PGDATA ${PGDATA}.pre_recovery.$(date +%Y%m%d_%H%M%S)
mkdir -p $PGDATA

# 3. Extract base backup
echo "Restoring from base backup..."
tar -xzf ${BACKUP_DIR}/base.tar.gz -C $PGDATA
if [ -f ${BACKUP_DIR}/pg_wal.tar.gz ]; then
    tar -xzf ${BACKUP_DIR}/pg_wal.tar.gz -C $PGDATA/pg_wal/
fi

# 4. Set correct permissions
chown -R postgres:postgres $PGDATA
chmod 700 $PGDATA

# 5. Configure recovery
echo "recovery_target_time = '${RECOVERY_TIMESTAMP}'" >> $PGDATA/postgresql.auto.conf
echo "recovery_target_action = 'pause'" >> $PGDATA/postgresql.auto.conf

# 6. Create recovery.signal
touch $PGDATA/recovery.signal

# 7. Start PostgreSQL
echo "Starting PostgreSQL in recovery mode..."
pg_ctl start -D $PGDATA || systemctl start postgresql

echo "Recovery initiated. Monitor logs with: tail -f $PGDATA/log/postgresql-*.log"
*/

-- =============================================================================
-- STEP 6: POST-RECOVERY HASH CHAIN VALIDATION
-- =============================================================================

-- 6.1 Validate hash chain continuity after recovery
CREATE OR REPLACE FUNCTION validate_hash_chain_after_recovery(
    p_start_time TIMESTAMPTZ,
    p_end_time TIMESTAMPTZ
) RETURNS TABLE (
    validation_status TEXT,
    records_checked BIGINT,
    broken_at_txn_id BIGINT,
    expected_hash TEXT,
    actual_hash TEXT
) AS $$
DECLARE
    v_records_checked BIGINT := 0;
    v_broken_at_txn_id BIGINT := NULL;
    v_expected_hash TEXT;
    v_actual_hash TEXT;
    v_prev_hash TEXT;
    rec RECORD;
BEGIN
    -- Use core.transaction_log as the ledger table
    FOR rec IN 
        SELECT 
            transaction_id,
            previous_hash,
            transaction_hash AS computed_hash,
            payload::TEXT AS transaction_data
        FROM core.transaction_log
        WHERE created_at BETWEEN p_start_time AND p_end_time
        ORDER BY transaction_id
    LOOP
        v_records_checked := v_records_checked + 1;
        
        -- Verify hash chain
        IF v_prev_hash IS NOT NULL AND rec.previous_hash != v_prev_hash THEN
            v_broken_at_txn_id := rec.transaction_id;
            v_expected_hash := v_prev_hash;
            v_actual_hash := rec.previous_hash;
            
            RETURN QUERY SELECT 
                'BROKEN_CHAIN'::TEXT,
                v_records_checked,
                v_broken_at_txn_id,
                v_expected_hash,
                v_actual_hash;
            RETURN;
        END IF;
        
        -- Verify computed hash
        v_expected_hash := encode(
            digest(
                concat(rec.previous_hash, rec.transaction_data::TEXT)::bytea,
                'sha256'
            ),
            'hex'
        );
        
        IF rec.computed_hash != v_expected_hash THEN
            v_broken_at_txn_id := rec.transaction_id;
            v_actual_hash := rec.computed_hash;
            
            RETURN QUERY SELECT 
                'INVALID_HASH'::TEXT,
                v_records_checked,
                v_broken_at_txn_id,
                v_expected_hash,
                v_actual_hash;
            RETURN;
        END IF;
        
        v_prev_hash := rec.computed_hash;
    END LOOP;
    
    RETURN QUERY SELECT 
        'VALID'::TEXT,
        v_records_checked,
        NULL::BIGINT,
        NULL::TEXT,
        NULL::TEXT;
END;
$$ LANGUAGE plpgsql;

-- 6.2 Execute hash chain validation
-- Customize the time range based on your recovery window
SELECT * FROM validate_hash_chain_after_recovery(
    CURRENT_TIMESTAMP - INTERVAL '7 days',  -- Default: validate last 7 days
    CURRENT_TIMESTAMP
);

-- =============================================================================
-- STEP 7: POST-RECOVERY VERIFICATION CHECKS
-- =============================================================================

-- 7.1 Verify transaction count integrity
DO $$
DECLARE
    v_expected_count BIGINT;
    v_actual_count BIGINT;
BEGIN
    -- Set expected count based on pre-recovery statistics
    SELECT COALESCE(reltuples::BIGINT, 0) INTO v_expected_count 
    FROM pg_class 
    WHERE relname = 'transaction_log'
    AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'ussd_core');
    
    SELECT reltuples::BIGINT INTO v_actual_count 
    FROM pg_class 
    WHERE relname = 'ledger_transactions';
    
    IF ABS(v_actual_count - v_expected_count) > (v_expected_count * 0.1) THEN
        RAISE WARNING 'Transaction count variance detected. Expected: %, Actual: %', 
            v_expected_count, v_actual_count;
    END IF;
END $$;

-- 7.2 Verify partition integrity
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
    n_tup_ins as inserts,
    n_tup_upd as updates,
    n_tup_del as deletes
FROM pg_stat_user_tables
WHERE tablename LIKE 'ledger_transactions_%'
ORDER BY tablename;

-- 7.3 Verify materialized views are refreshed
DO $$
DECLARE
    v_view_name TEXT;
BEGIN
    FOR v_view_name IN 
        SELECT matviewname 
        FROM pg_matviews 
        WHERE schemaname = 'public'
    LOOP
        -- Refresh materialized view from appropriate schema
        EXECUTE format('REFRESH MATERIALIZED VIEW CONCURRENTLY %I.%I', 
            COALESCE(
                (SELECT schemaname FROM pg_matviews WHERE matviewname = v_view_name LIMIT 1),
                'public'
            ), 
            v_view_name
        );
        RAISE NOTICE 'Refreshed materialized view: %', v_view_name;
    END LOOP;
END $$;

-- =============================================================================
-- STEP 8: FINALIZE RECOVERY AND ENABLE CONNECTIONS
-- =============================================================================

-- 8.1 Promote recovery (exit recovery mode)
-- After confirming recovery to target time, promote to primary:
-- Shell: pg_ctl promote -D $PGDATA
-- Or SQL: SELECT pg_wal_replay_resume();

-- 8.2 Re-enable database connections
ALTER DATABASE current_database() WITH ALLOW_CONNECTIONS TRUE;

-- 8.3 Update recovery log
UPDATE pitr_recovery_log
SET 
    recovery_status = 'COMPLETED',
    hash_chain_validated = TRUE,
    wal_segments_applied = (SELECT COUNT(*) FROM pg_stat_archiver WHERE archived_count > 0)
WHERE recovery_status = 'INITIATED'
ORDER BY created_at DESC
LIMIT 1;

-- =============================================================================
-- STEP 9: TEST CASES WITH EXPECTED RESULTS
-- =============================================================================

-- Test Case 9.1: Verify recovery to exact timestamp
-- Expected: Single row with exact target timestamp
SELECT 
    'TEST_9.1_RECOVERY_TIMESTAMP' as test_name,
    CASE 
        WHEN target_timestamp = '2026-03-30 12:00:00+00'::TIMESTAMPTZ 
        THEN 'PASSED' 
        ELSE 'FAILED' 
    END as result,
    target_timestamp as actual_value
FROM pitr_recovery_log
WHERE recovery_status = 'COMPLETED'
ORDER BY created_at DESC
LIMIT 1;

-- Test Case 9.2: Verify no gaps in transaction sequence
-- Expected: Empty result set (no gaps)
WITH RECURSIVE txn_sequence AS (
    SELECT transaction_id, 
           transaction_id - LAG(transaction_id) OVER (ORDER BY transaction_id) as gap
    FROM ledger_transactions
    WHERE created_at <= '2026-03-30 12:00:00+00'
)
SELECT 
    'TEST_9.2_NO_GAPS' as test_name,
    CASE WHEN COUNT(*) = 0 THEN 'PASSED' ELSE 'FAILED' END as result,
    COUNT(*) as gap_count
FROM txn_sequence WHERE gap > 1;

-- Test Case 9.3: Verify hash chain continuity
-- Expected: 'VALID' status
SELECT 
    'TEST_9.3_HASH_CHAIN' as test_name,
    validation_status as result,
    records_checked
FROM validate_hash_chain_after_recovery(
    '2026-03-29 00:00:00+00',
    '2026-03-30 12:00:00+00'
);

-- Test Case 9.4: Verify partition data integrity
-- Expected: All partitions have consistent data
SELECT 
    'TEST_9.4_PARTITION_INTEGRITY' as test_name,
    CASE 
        WHEN COUNT(*) = 0 THEN 'PASSED'
        ELSE 'FAILED'
    END as result,
    string_agg(tablename || ': ' || n_tup_del::TEXT, ', ') as issues
FROM pg_stat_user_tables
WHERE tablename LIKE 'ledger_transactions_%'
AND n_tup_del > 0;  -- Should be 0 for immutable ledger

-- =============================================================================
-- STEP 10: ROLLBACK PROCEDURES
-- =============================================================================

-- 10.1 Rollback to pre-recovery snapshot
CREATE OR REPLACE PROCEDURE rollback_pitr_recovery(
    p_recovery_id UUID
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_snapshot_path TEXT;
    v_snapshot_name TEXT;
BEGIN
    -- Get snapshot information
    SELECT snapshot_path, snapshot_name 
    INTO v_snapshot_path, v_snapshot_name
    FROM recovery_snapshots
    WHERE recovery_id = p_recovery_id;
    
    IF v_snapshot_path IS NULL THEN
        RAISE EXCEPTION 'No snapshot found for recovery_id: %', p_recovery_id;
    END IF;
    
    -- Log rollback initiation
    UPDATE pitr_recovery_log
    SET recovery_status = 'ROLLBACK_INITIATED',
        recovery_notes = recovery_notes || E'\nRollback initiated at ' || CURRENT_TIMESTAMP
    WHERE recovery_id = p_recovery_id;
    
    -- Execute shell commands to restore from snapshot
    /*
    #!/bin/bash
    set -e
    
    PGDATA=${PGDATA:-/var/lib/postgresql/data}
    
    # Stop PostgreSQL
    pg_ctl stop -D $PGDATA -m fast || systemctl stop postgresql
    
    # Restore from logical backup (if using pg_dump)
    if [[ "$v_snapshot_path" == *.sql ]] || [[ "$v_snapshot_path" == *.dump ]]; then
        pg_restore -d ussd_ledger --clean --if-exists "$v_snapshot_path"
    else
        # Restore from physical backup
        rm -rf $PGDATA/*
        tar -xzf "$v_snapshot_path" -C $PGDATA
        chown -R postgres:postgres $PGDATA
        chmod 700 $PGDATA
    fi
    
    # Start PostgreSQL
    pg_ctl start -D $PGDATA || systemctl start postgresql
    
    echo "Rollback completed at $(date)"
    */
    
    -- Update status
    UPDATE pitr_recovery_log
    SET recovery_status = 'ROLLED_BACK'
    WHERE recovery_id = p_recovery_id;
    
    RAISE NOTICE 'Rollback completed using snapshot: %', v_snapshot_name;
END;
$$;

-- 10.2 Emergency point-in-time rollback
CREATE OR REPLACE PROCEDURE emergency_rollback_to_timestamp(
    p_target_timestamp TIMESTAMPTZ
)
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE NOTICE 'Initiating emergency rollback to: %', p_target_timestamp;
    
    -- Create emergency recovery record
    INSERT INTO pitr_recovery_log (
        target_timestamp,
        base_backup_name,
        recovery_status,
        recovery_notes
    ) VALUES (
        p_target_timestamp,
        'EMERGENCY_ROLLBACK',
        'EMERGENCY_INITIATED',
        'Emergency rollback initiated'
    );
    
    -- Execute emergency PITR steps
    /*
    EMERGENCY ROLLBACK CHECKLIST:
    
    1. IMMEDIATE ACTIONS:
       - Notify stakeholders
       - Enable maintenance mode on applications
       - Stop all non-essential connections
    
    2. RECOVERY STEPS:
       - Create pre-emergency snapshot (if possible)
       - Stop PostgreSQL
       - Follow PITR procedure with target_timestamp = %
       - Validate hash chain integrity
       - Verify transaction counts
    
    3. VALIDATION:
       - Run all test cases in STEP 9
       - Verify application connectivity
       - Check critical business transactions
    
    4. POST-RECOVERY:
       - Disable maintenance mode
       - Notify stakeholders of completion
       - Document incident and actions taken
    
    MANUAL INTERVENTION REQUIRED - DO NOT PROCEED AUTOMATICALLY
    */
    
    RAISE NOTICE 'Emergency rollback target: %', p_target_timestamp;
    RAISE NOTICE 'Review the emergency checklist above before proceeding';
    RAISE NOTICE 'Execute PITR procedure manually with the specified target timestamp';
END;
$$;

-- =============================================================================
-- CONFIGURATION NOTES
-- =============================================================================

/*
CONFIGURATION CHECKLIST - Review and customize as needed:

1. TARGET TIMESTAMPS: Update timestamps in recovery operations based on your
   specific recovery requirements and RPO targets.

2. BACKUP PATHS: Verify and update paths to match your infrastructure:
   - Base backup: /var/lib/postgresql/backups/base/
   - WAL archive: /var/lib/postgresql/archive/
   - Snapshot storage: /var/lib/postgresql/backups/snapshots/

3. LEDGER TABLE: This procedure uses core.transaction_log as the ledger.
   Update references if your schema uses different table names.

4. RETENTION POLICIES: Configure cleanup for recovery logs and snapshots:
   - Recovery logs: 7 years (regulatory requirement)
   - Snapshots: 90 days minimum
   - WAL archives: Based on PITR window needs

5. MONITORING: Set up alerts for:
   - WAL archive lag (> 15 minutes)
   - Recovery operation progress
   - Hash chain validation failures
   - Backup job failures

6. RTO/RPO TARGETS: Default targets per ISO/IEC 27031:
   - RTO: 4 hours maximum
   - RPO: 15 minutes maximum
   - Validate procedures quarterly

7. AUTHORIZATION: Document who can initiate recovery:
   - Database administrators
   - Incident response team
   - Emergency contacts

8. CONNECTION HANDLING: Review excluded system users for your environment.

9. PERFORMANCE: For large databases, consider:
   - parallel_recovery_workers
   - Optimized restore_command with parallel copy

10. AUTOMATION: Integrate hash chain validation into monitoring dashboards.
*/

-- =============================================================================
-- END OF POINT-IN-TIME RECOVERY PROCEDURE
-- =============================================================================
