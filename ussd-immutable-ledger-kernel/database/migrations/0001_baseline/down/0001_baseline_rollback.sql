-- ============================================================================
-- BASELINE MIGRATION ROLLBACK
-- Migration: 0001_baseline
-- Description: Complete rollback of initial schema deployment
-- WARNING: This will DESTROY ALL DATA in the ledger system
-- Use only for complete system teardown or disaster recovery
-- 
-- COMPLIANCE NOTES:
-- - ISO 27031: ICT readiness for business continuity
-- - ISO 27001: A.8.1 - User endpoint devices (data removal)
-- - SOX: Change management and audit trail for destructive changes
-- - GDPR: Right to erasure implementation for complete data removal
-- ============================================================================

-- Start transaction
BEGIN;

-- Set session variables for audit logging
SET LOCAL app.current_user = 'rollback_script';
SET LOCAL app.current_migration = '0001_baseline_rollback';
SET LOCAL app.execution_timestamp = CURRENT_TIMESTAMP;
SET LOCAL app.approver = 'CDBA';  -- Change DB Admin approval reference

-- ============================================================================
-- AUDIT TRAIL: Log rollback initiation
-- ============================================================================
DO $$
BEGIN
    -- Create migration audit log if not exists
    CREATE TABLE IF NOT EXISTS migration_audit_log (
        audit_id BIGSERIAL PRIMARY KEY,
        migration_id VARCHAR(100) NOT NULL,
        operation VARCHAR(50) NOT NULL,  -- UP, DOWN, VERIFY
        executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        executed_by VARCHAR(100) DEFAULT CURRENT_USER,
        approver_reference VARCHAR(100),
        rollback_reason TEXT,
        change_ticket VARCHAR(50),
        status VARCHAR(20) DEFAULT 'IN_PROGRESS',
        verification_result BOOLEAN,
        rows_affected BIGINT,
        duration_ms INTEGER,
        checksum VARCHAR(64)
    );
    
    -- Log rollback start
    INSERT INTO migration_audit_log (
        migration_id, operation, approver_reference, status
    ) VALUES (
        '0001_baseline', 'DOWN', 'CDBA-' || TO_CHAR(CURRENT_DATE, 'YYYYMMDD'), 'IN_PROGRESS'
    );
END $$;

-- ============================================================================
-- STEP 1: CREATE BACKUP (Compliance Requirement)
-- ISO 27031: Change management requires backup before destructive operations
-- ============================================================================
DO $$
DECLARE
    backup_timestamp TEXT := TO_CHAR(CURRENT_TIMESTAMP, 'YYYYMMDD_HH24MISS');
BEGIN
    RAISE NOTICE 'Creating pre-rollback backup with timestamp: %', backup_timestamp;
    -- Note: Actual pg_dump command executed externally
    -- pg_dump -Fc ussd_ledger > /backups/migrations/0001_baseline_prerollback_$backup_timestamp.dump
END $$;

-- ============================================================================
-- STEP 2: DROP VIEWS (in reverse dependency order)
-- ============================================================================

DROP VIEW IF EXISTS v_ledger_entries_with_hash CASCADE;
DROP VIEW IF EXISTS v_account_balances_current CASCADE;
DROP VIEW IF EXISTS v_settlement_summary CASCADE;
DROP VIEW IF EXISTS v_session_transaction_summary CASCADE;
DROP VIEW IF EXISTS v_integrity_status CASCADE;
DROP VIEW IF EXISTS v_reconciliation_status CASCADE;

-- ============================================================================
-- STEP 3: DROP FUNCTIONS (in reverse dependency order)
-- ============================================================================

DROP FUNCTION IF EXISTS verify_entry_hash(bigint, bytea) CASCADE;
DROP FUNCTION IF EXISTS verify_entry_integrity(record, bytea) CASCADE;
DROP FUNCTION IF EXISTS calculate_entry_hash(uuid, decimal, varchar, timestamp, bytea) CASCADE;
DROP FUNCTION IF EXISTS get_last_verified_entry_id() CASCADE;
DROP FUNCTION IF EXISTS verify_full_hash_chain() CASCADE;
DROP FUNCTION IF EXISTS verify_incremental_hash_chain() CASCADE;
DROP FUNCTION IF EXISTS process_settlement_retries() CASCADE;
DROP FUNCTION IF EXISTS notify_provider_settlement(varchar, varchar) CASCADE;
DROP FUNCTION IF EXISTS alert_on_integrity_failure() CASCADE;
DROP FUNCTION IF EXISTS update_timestamp() CASCADE;
DROP FUNCTION IF EXISTS generate_chain_hash() CASCADE;
DROP FUNCTION IF EXISTS audit_entry_access() CASCADE;

-- ============================================================================
-- STEP 4: DROP TRIGGERS
-- ============================================================================

DROP TRIGGER IF EXISTS integrity_failure_alert ON verification_runs;
DROP TRIGGER IF EXISTS update_balance_timestamp ON account_balances;
DROP TRIGGER IF EXISTS audit_ledger_access ON ledger_entries;
DROP TRIGGER IF EXISTS generate_entry_hash ON ledger_entries;
DROP TRIGGER IF EXISTS maintain_hash_chain ON ledger_entries;

-- ============================================================================
-- STEP 5: DROP TABLES (in reverse dependency order - child tables first)
-- Data Protection: All table drops logged for GDPR Article 17 compliance
-- ============================================================================

-- Archive/incident tables
DROP TABLE IF EXISTS incident_snapshots CASCADE;
DROP TABLE IF EXISTS incident_system_state CASCADE;
DROP TABLE IF EXISTS incident_flags CASCADE;
DROP TABLE IF EXISTS incident_queue CASCADE;

-- Settlement tables
DROP TABLE IF EXISTS settlement_corrections CASCADE;
DROP TABLE IF EXISTS settlement_retry_queue CASCADE;
DROP TABLE IF EXISTS settlement_entries CASCADE;
DROP TABLE IF EXISTS settlement_batches CASCADE;
DROP TABLE IF EXISTS mno_settlement CASCADE;

-- Support/ticketing tables
DROP TABLE IF EXISTS support_tickets CASCADE;

-- Audit tables
DROP TABLE IF EXISTS settlement_batch_history CASCADE;
DROP TABLE IF EXISTS transaction_audit CASCADE;
DROP TABLE IF EXISTS verification_runs CASCADE;
DROP TABLE IF EXISTS integrity_violations CASCADE;

-- USSD session tables
DROP TABLE IF EXISTS session_transactions CASCADE;
DROP TABLE IF EXISTS session_states CASCADE;
DROP TABLE IF EXISTS ussd_message_outbound CASCADE;
DROP TABLE IF EXISTS ussd_message_inbound CASCADE;
DROP TABLE IF EXISTS ussd_sessions CASCADE;

-- Ledger core tables
DROP TABLE IF EXISTS balance_snapshots CASCADE;
DROP TABLE IF EXISTS ledger_hash_chain CASCADE;
DROP TABLE IF EXISTS ledger_entries CASCADE;

-- Configuration tables
DROP TABLE IF EXISTS command_routing CASCADE;
DROP TABLE IF EXISTS gateway_config CASCADE;
DROP TABLE IF EXISTS mno_config CASCADE;

-- Account tables
DROP TABLE IF EXISTS account_balances CASCADE;
DROP TABLE IF EXISTS accounts CASCADE;

-- Service provider tables
DROP TABLE IF EXISTS service_providers CASCADE;

-- ============================================================================
-- STEP 6: DROP CUSTOM TYPES/ENUMS
-- ============================================================================

DROP TYPE IF EXISTS entry_type_enum CASCADE;
DROP TYPE IF EXISTS account_type_enum CASCADE;
DROP TYPE IF EXISTS account_status_enum CASCADE;
DROP TYPE IF EXISTS session_status_enum CASCADE;
DROP TYPE IF EXISTS message_type_enum CASCADE;
DROP TYPE IF EXISTS settlement_status_enum CASCADE;
DROP TYPE IF EXISTS batch_type_enum CASCADE;
DROP TYPE IF EXISTS provider_status_enum CASCADE;
DROP TYPE IF EXISTS verification_type_enum CASCADE;
DROP TYPE IF EXISTS violation_type_enum CASCADE;

-- ============================================================================
-- STEP 7: DROP INDEXES (cascade with tables will handle most, explicit for safety)
-- ============================================================================

-- Explicit index drops if tables failed to drop cleanly
DROP INDEX IF EXISTS idx_ledger_entries_account;
DROP INDEX IF EXISTS idx_ledger_entries_session;
DROP INDEX IF EXISTS idx_ledger_entries_msisdn;
DROP INDEX IF EXISTS idx_ledger_entries_created;
DROP INDEX IF EXISTS idx_hash_chain_entry;
DROP INDEX IF EXISTS idx_audit_entry;
DROP INDEX IF EXISTS idx_audit_time;
DROP INDEX IF EXISTS idx_balance_account;
DROP INDEX IF EXISTS idx_accounts_msisdn;
DROP INDEX IF EXISTS idx_accounts_provider;
DROP INDEX IF EXISTS idx_sessions_msisdn;
DROP INDEX IF EXISTS idx_sessions_account;
DROP INDEX IF EXISTS idx_sessions_status;
DROP INDEX IF EXISTS idx_settlement_provider;
DROP INDEX IF EXISTS idx_settlement_status;
DROP INDEX IF EXISTS idx_settlement_entry_batch;

-- ============================================================================
-- STEP 8: DROP SCHEMAS
-- ============================================================================

DROP SCHEMA IF EXISTS archive CASCADE;
DROP SCHEMA IF EXISTS incident_snapshots CASCADE;

-- ============================================================================
-- STEP 9: DROP MIGRATION TRACKING (optional - comment out if using external tool)
-- ============================================================================

-- Uncomment if using schema_migrations table
-- DELETE FROM schema_migrations WHERE version = '0001';

-- ============================================================================
-- STEP 10: CLEAN UP EXTENSIONS (optional - comment out if shared)
-- ============================================================================

-- NOTE: Only drop extensions if they are not used by other databases
-- Comment these out in shared environments
-- DROP EXTENSION IF EXISTS "uuid-ossp";
-- DROP EXTENSION IF EXISTS "pgcrypto";
-- DROP EXTENSION IF EXISTS "pg_stat_statements";

-- ============================================================================
-- STEP 11: VERIFY CLEANUP
-- ISO 27031: Change management requires verification of rollback
-- ============================================================================

DO $$
DECLARE
    v_table_count INT;
    v_view_count INT;
    v_function_count INT;
    v_audit_id BIGINT;
BEGIN
    -- Get the audit ID for this rollback
    SELECT MAX(audit_id) INTO v_audit_id
    FROM migration_audit_log
    WHERE migration_id = '0001_baseline' AND operation = 'DOWN';

    -- Count remaining objects
    SELECT COUNT(*) INTO v_table_count
    FROM information_schema.tables 
    WHERE table_schema = 'public' 
      AND table_type = 'BASE TABLE'
      AND table_name IN (
        'ledger_entries', 'ledger_hash_chain', 'balance_snapshots',
        'accounts', 'account_balances', 'ussd_sessions', 'session_states',
        'session_transactions', 'settlement_batches', 'settlement_entries',
        'service_providers', 'mno_config', 'ussd_message_inbound', 
        'ussd_message_outbound'
      );
    
    SELECT COUNT(*) INTO v_view_count
    FROM information_schema.views
    WHERE table_schema = 'public'
      AND table_name LIKE 'v_%';
    
    SELECT COUNT(*) INTO v_function_count
    FROM information_schema.routines
    WHERE routine_schema = 'public'
      AND routine_type = 'FUNCTION'
      AND routine_name IN (
        'verify_entry_hash', 'verify_full_hash_chain', 
        'verify_incremental_hash_chain', 'get_last_verified_entry_id'
      );
    
    IF v_table_count > 0 OR v_view_count > 0 OR v_function_count > 0 THEN
        RAISE WARNING 'Rollback incomplete: % tables, % views, % functions remain',
            v_table_count, v_view_count, v_function_count;
        
        -- Update audit log with failure
        UPDATE migration_audit_log
        SET status = 'FAILED',
            verification_result = false,
            duration_ms = EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - executed_at))*1000
        WHERE audit_id = v_audit_id;
    ELSE
        RAISE NOTICE 'Rollback verified: All ledger objects removed successfully';
        
        -- Update audit log with success
        UPDATE migration_audit_log
        SET status = 'COMPLETED',
            verification_result = true,
            duration_ms = EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - executed_at))*1000
        WHERE audit_id = v_audit_id;
    END IF;
END $$;

-- ============================================================================
-- STEP 12: VERSION CONTROL STANDARDS
-- ============================================================================
--
-- Version Control Requirements per ISO 27031:
-- 1. All migrations must be stored in version control (Git)
-- 2. Migrations must follow naming convention: NNNN_description.sql
-- 3. Rollback scripts must be tested in non-production before deployment
-- 4. Migration execution must be logged in audit trail
-- 5. Emergency rollbacks require CAB (Change Advisory Board) approval
--
-- Git Workflow:
--   feature/migration-0001-baseline -> develop -> staging -> main
--
-- Required Approvals:
--   - Standard rollback: Database Architect
--   - Emergency rollback: CDBA + Engineering Director
--   - Production rollback: CAB approval required
--
-- Pre-Rollback Checklist:
--   [ ] Backup created and verified
--   [ ] Change ticket approved
--   [ ] Stakeholders notified
--   [ ] Rollback tested in staging
--   [ ] Rollback window scheduled
--   [ ] Rollback team assembled
--
-- Post-Rollback Checklist:
--   [ ] Verification completed
--   [ ] Audit log updated
--   [ ] Stakeholders notified
--   [ ] Systems monitored for 24 hours
--   [ ] Post-rollback review scheduled
--
-- ============================================================================

-- ============================================================================
-- COMMIT OR ROLLBACK
-- ============================================================================

-- Uncomment to actually execute:
-- COMMIT;

-- Default to rollback for safety (dry run mode)
ROLLBACK;

-- ============================================================================
-- TODOs
-- ============================================================================

-- [ ] Add data export before rollback option
-- [ ] Implement object-level rollback (selective table drop)
-- [ ] Add rollback verification report generation
-- [ ] Create pre-rollback checklist procedure
-- [ ] Implement rollback simulation mode
-- [ ] Add rollback timing estimation
-- [ ] Create cross-database dependency check
-- [ ] Add replication slot cleanup
-- [ ] Implement connection termination before rollback
-- [ ] Create rollback audit logging table
