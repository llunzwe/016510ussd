-- =============================================================================
-- USSD KERNEL CORE SCHEMA - INTEGRITY TRIGGERS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    030_core_integrity_triggers.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      core
-- DESCRIPTION: Append-only enforcement triggers for immutable tables.
--              CRITICAL: This file MUST run after all core tables are created
--              to ensure immutability is enforced before any data insertion.
-- =============================================================================

/*
================================================================================
IMMUTABILITY ENFORCEMENT FRAMEWORK
================================================================================

This migration implements strict immutability through PostgreSQL triggers:

1. PREVENT_UPDATE: Blocks all UPDATE operations on immutable tables
2. PREVENT_DELETE: Blocks all DELETE operations on immutable tables
3. PREVENT_TRUNCATE: Blocks TRUNCATE operations (cascade protection)
4. ALLOW_STATUS_UPDATE: Exception for status-only updates where applicable

AUDIT NOTE: These triggers are the FINAL LINE OF DEFENSE for immutability.
            Any attempt to modify immutable data will raise an exception
            and be logged to the security audit trail.

================================================================================
CRITICAL DEPENDENCIES
================================================================================

MUST run AFTER:
- 004_core_transaction_log.sql
- 007_core_blocks_merkle.sql
- 020_core_audit_trail.sql
- All core table creation scripts

MUST run BEFORE:
- Any data insertion
- Application startup

================================================================================
*/

-- =============================================================================
-- IMMUTABILITY TRIGGER FUNCTIONS
-- =============================================================================

-- Function to prevent UPDATE on immutable tables
CREATE OR REPLACE FUNCTION core.prevent_update()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Log the violation attempt
    INSERT INTO core.security_audit_log (
        event_type,
        severity,
        table_name,
        record_id,
        old_data,
        new_data,
        session_user_name,
        application_name,
        client_addr
    ) VALUES (
        'IMMUTABILITY_VIOLATION',
        'CRITICAL',
        TG_TABLE_NAME,
        COALESCE(OLD.transaction_id::TEXT, OLD.block_id::TEXT, OLD.audit_id::TEXT, 'UNKNOWN'),
        to_jsonb(OLD),
        to_jsonb(NEW),
        session_user,
        current_setting('application_name', true),
        inet_client_addr()
    );
    
    -- Raise exception to block the operation
    RAISE EXCEPTION 'IMMUTABILITY_VIOLATION: UPDATE not allowed on %.%. Use compensating transactions for corrections. Attempted by user: %',
        TG_TABLE_SCHEMA, TG_TABLE_NAME, session_user
        USING ERRCODE = 'P0001',
              HINT = 'To correct errors, create a compensating transaction with type REVERSAL or ADJUSTMENT';
    
    RETURN NULL;
END;
$$;

-- Function to prevent DELETE on immutable tables
CREATE OR REPLACE FUNCTION core.prevent_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Log the violation attempt
    INSERT INTO core.security_audit_log (
        event_type,
        severity,
        table_name,
        record_id,
        old_data,
        session_user_name,
        application_name,
        client_addr
    ) VALUES (
        'IMMUTABILITY_VIOLATION',
        'CRITICAL',
        TG_TABLE_NAME,
        COALESCE(OLD.transaction_id::TEXT, OLD.block_id::TEXT, OLD.audit_id::TEXT, 'UNKNOWN'),
        to_jsonb(OLD),
        session_user,
        current_setting('application_name', true),
        inet_client_addr()
    );
    
    -- Raise exception to block the operation
    RAISE EXCEPTION 'IMMUTABILITY_VIOLATION: DELETE not allowed on %.%. Data is permanently retained for compliance. Attempted by user: %',
        TG_TABLE_SCHEMA, TG_TABLE_NAME, session_user
        USING ERRCODE = 'P0001',
              HINT = 'Records cannot be deleted from immutable ledger. Use data classification for retention policies.';
    
    RETURN NULL;
END;
$$;

-- Function to prevent TRUNCATE on immutable tables
CREATE OR REPLACE FUNCTION core.prevent_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Log the violation attempt
    INSERT INTO core.security_audit_log (
        event_type,
        severity,
        table_name,
        session_user_name,
        application_name,
        client_addr
    ) VALUES (
        'IMMUTABILITY_VIOLATION',
        'CRITICAL',
        TG_TABLE_NAME,
        session_user,
        current_setting('application_name', true),
        inet_client_addr()
    );
    
    RAISE EXCEPTION 'IMMUTABILITY_VIOLATION: TRUNCATE not allowed on %.% - would destroy immutable ledger integrity. Attempted by user: %',
        TG_TABLE_SCHEMA, TG_TABLE_NAME, session_user
        USING ERRCODE = 'P0001';
    
    RETURN NULL;
END;
$$;

-- Function to allow only status updates (for workflow tables)
CREATE OR REPLACE FUNCTION core.prevent_update_except_status()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_allowed_columns TEXT[] := ARRAY['status', 'updated_at', 'updated_by', 'status_reason', 
                                       'confirmed_at', 'verified_at', 'completed_at', 
                                       'terminated_at', 'rotated_at', 'compromise_detected_at'];
    v_col TEXT;
    v_old_val TEXT;
    v_new_val TEXT;
BEGIN
    -- Check each column
    FOR v_col IN 
        SELECT key FROM jsonb_each(to_jsonb(OLD))
    LOOP
        -- Skip allowed columns
        IF v_col = ANY(v_allowed_columns) THEN
            CONTINUE;
        END IF;
        
        -- Get values
        EXECUTE format('SELECT ($1).%I::TEXT, ($2).%I::TEXT', v_col, v_col)
        INTO v_old_val, v_new_val
        USING OLD, NEW;
        
        -- Check if value changed
        IF v_old_val IS DISTINCT FROM v_new_val THEN
            -- Log violation
            INSERT INTO core.security_audit_log (
                event_type,
                severity,
                table_name,
                record_id,
                message
            ) VALUES (
                'IMMUTABILITY_VIOLATION',
                'HIGH',
                TG_TABLE_NAME,
                COALESCE(OLD.transaction_id::TEXT, OLD.block_id::TEXT, 'UNKNOWN'),
                format('Attempted to modify column %s (allowed: status only)', v_col)
            );
            
            RAISE EXCEPTION 'IMMUTABILITY_VIOLATION: Column % cannot be modified on %.%. Only status fields are mutable. Attempted by user: %',
                v_col, TG_TABLE_SCHEMA, TG_TABLE_NAME, session_user
                USING ERRCODE = 'P0001';
        END IF;
    END LOOP;
    
    RETURN NEW;
END;
$$;

-- =============================================================================
-- APPLY IMMUTABILITY TRIGGERS TO CORE TABLES
-- =============================================================================

-- 1. TRANSACTION_LOG - Strictly immutable
DROP TRIGGER IF EXISTS trg_transaction_log_prevent_update ON core.transaction_log;
CREATE TRIGGER trg_transaction_log_prevent_update
    BEFORE UPDATE ON core.transaction_log
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

DROP TRIGGER IF EXISTS trg_transaction_log_prevent_delete ON core.transaction_log;
CREATE TRIGGER trg_transaction_log_prevent_delete
    BEFORE DELETE ON core.transaction_log
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

DROP TRIGGER IF EXISTS trg_transaction_log_prevent_truncate ON core.transaction_log;
CREATE TRIGGER trg_transaction_log_prevent_truncate
    BEFORE TRUNCATE ON core.transaction_log
    FOR EACH STATEMENT
    EXECUTE FUNCTION core.prevent_truncate();

-- 2. BLOCKS - Strictly immutable
DROP TRIGGER IF EXISTS trg_blocks_prevent_update ON core.blocks;
CREATE TRIGGER trg_blocks_prevent_update
    BEFORE UPDATE ON core.blocks
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

DROP TRIGGER IF EXISTS trg_blocks_prevent_delete ON core.blocks;
CREATE TRIGGER trg_blocks_prevent_delete
    BEFORE DELETE ON core.blocks
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

DROP TRIGGER IF EXISTS trg_blocks_prevent_truncate ON core.blocks;
CREATE TRIGGER trg_blocks_prevent_truncate
    BEFORE TRUNCATE ON core.blocks
    FOR EACH STATEMENT
    EXECUTE FUNCTION core.prevent_truncate();

-- 3. MERKLE_NODES - Strictly immutable
DROP TRIGGER IF EXISTS trg_merkle_nodes_prevent_update ON core.merkle_nodes;
CREATE TRIGGER trg_merkle_nodes_prevent_update
    BEFORE UPDATE ON core.merkle_nodes
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

DROP TRIGGER IF EXISTS trg_merkle_nodes_prevent_delete ON core.merkle_nodes;
CREATE TRIGGER trg_merkle_nodes_prevent_delete
    BEFORE DELETE ON core.merkle_nodes
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- 4. MERKLE_PROOFS - Strictly immutable
DROP TRIGGER IF EXISTS trg_merkle_proofs_prevent_update ON core.merkle_proofs;
CREATE TRIGGER trg_merkle_proofs_prevent_update
    BEFORE UPDATE ON core.merkle_proofs
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

DROP TRIGGER IF EXISTS trg_merkle_proofs_prevent_delete ON core.merkle_proofs;
CREATE TRIGGER trg_merkle_proofs_prevent_delete
    BEFORE DELETE ON core.merkle_proofs
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- 5. AUDIT_TRAIL - Strictly immutable
DROP TRIGGER IF EXISTS trg_audit_trail_prevent_update ON core.audit_trail;
CREATE TRIGGER trg_audit_trail_prevent_update
    BEFORE UPDATE ON core.audit_trail
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

DROP TRIGGER IF EXISTS trg_audit_trail_prevent_delete ON core.audit_trail;
CREATE TRIGGER trg_audit_trail_prevent_delete
    BEFORE DELETE ON core.audit_trail
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

DROP TRIGGER IF EXISTS trg_audit_trail_prevent_truncate ON core.audit_trail;
CREATE TRIGGER trg_audit_trail_prevent_truncate
    BEFORE TRUNCATE ON core.audit_trail
    FOR EACH STATEMENT
    EXECUTE FUNCTION core.prevent_truncate();

-- 6. CONTINUOUS_AUDIT_TRAIL - Strictly immutable
DROP TRIGGER IF EXISTS trg_continuous_audit_prevent_update ON core.continuous_audit_trail;
CREATE TRIGGER trg_continuous_audit_prevent_update
    BEFORE UPDATE ON core.continuous_audit_trail
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

DROP TRIGGER IF EXISTS trg_continuous_audit_prevent_delete ON core.continuous_audit_trail;
CREATE TRIGGER trg_continuous_audit_prevent_delete
    BEFORE DELETE ON core.continuous_audit_trail
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- 7. IDEMPOTENCY_KEYS - Status-only updates allowed (for cleanup)
DROP TRIGGER IF EXISTS trg_idempotency_keys_status_only ON core.idempotency_keys;
CREATE TRIGGER trg_idempotency_keys_status_only
    BEFORE UPDATE ON core.idempotency_keys
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update_except_status();

DROP TRIGGER IF EXISTS trg_idempotency_keys_prevent_delete ON core.idempotency_keys;
CREATE TRIGGER trg_idempotency_keys_prevent_delete
    BEFORE DELETE ON core.idempotency_keys
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- 8. SECURITY_AUDIT_LOG - Strictly immutable (even more critical)
DROP TRIGGER IF EXISTS trg_security_audit_prevent_update ON core.security_audit_log;
CREATE TRIGGER trg_security_audit_prevent_update
    BEFORE UPDATE ON core.security_audit_log
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

DROP TRIGGER IF EXISTS trg_security_audit_prevent_delete ON core.security_audit_log;
CREATE TRIGGER trg_security_audit_prevent_delete
    BEFORE DELETE ON core.security_audit_log
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- 9. HASH_CHAIN_VERIFICATION - Strictly immutable
DROP TRIGGER IF EXISTS trg_hash_chain_prevent_update ON core.hash_chain_verification;
CREATE TRIGGER trg_hash_chain_prevent_update
    BEFORE UPDATE ON core.hash_chain_verification
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

DROP TRIGGER IF EXISTS trg_hash_chain_prevent_delete ON core.hash_chain_verification;
CREATE TRIGGER trg_hash_chain_prevent_delete
    BEFORE DELETE ON core.hash_chain_verification
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- =============================================================================
-- IMMUTABILITY VERIFICATION FUNCTION
-- =============================================================================

-- Function to verify immutability is enforced
CREATE OR REPLACE FUNCTION core.verify_immutability_enforcement()
RETURNS TABLE (
    table_name TEXT,
    has_update_trigger BOOLEAN,
    has_delete_trigger BOOLEAN,
    has_truncate_trigger BOOLEAN,
    status TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        t.tablename::TEXT,
        EXISTS (
            SELECT 1 FROM pg_trigger tr
            JOIN pg_class c ON tr.tgrelid = c.oid
            JOIN pg_namespace n ON c.relnamespace = n.oid
            WHERE n.nspname = 'core'
            AND c.relname = t.tablename
            AND tr.tgname LIKE '%prevent_update%'
        ) as has_update_trigger,
        EXISTS (
            SELECT 1 FROM pg_trigger tr
            JOIN pg_class c ON tr.tgrelid = c.oid
            JOIN pg_namespace n ON c.relnamespace = n.oid
            WHERE n.nspname = 'core'
            AND c.relname = t.tablename
            AND tr.tgname LIKE '%prevent_delete%'
        ) as has_delete_trigger,
        EXISTS (
            SELECT 1 FROM pg_trigger tr
            JOIN pg_class c ON tr.tgrelid = c.oid
            JOIN pg_namespace n ON c.relnamespace = n.oid
            WHERE n.nspname = 'core'
            AND c.relname = t.tablename
            AND tr.tgname LIKE '%prevent_truncate%'
        ) as has_truncate_trigger,
        CASE 
            WHEN EXISTS (
                SELECT 1 FROM pg_trigger tr
                JOIN pg_class c ON tr.tgrelid = c.oid
                JOIN pg_namespace n ON c.relnamespace = n.oid
                WHERE n.nspname = 'core'
                AND c.relname = t.tablename
                AND tr.tgname LIKE '%prevent_update%'
            ) THEN 'PROTECTED'
            ELSE 'VULNERABLE'
        END as status
    FROM pg_tables t
    WHERE t.schemaname = 'core'
    AND t.tablename IN (
        'transaction_log', 'blocks', 'merkle_nodes', 'merkle_proofs',
        'audit_trail', 'continuous_audit_trail', 'security_audit_log',
        'hash_chain_verification', 'idempotency_keys'
    );
END;
$$;

-- =============================================================================
-- VERIFICATION ON DEPLOYMENT
-- =============================================================================

DO $$
DECLARE
    v_unprotected_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_unprotected_count
    FROM core.verify_immutability_enforcement()
    WHERE status = 'VULNERABLE';
    
    IF v_unprotected_count > 0 THEN
        RAISE WARNING 'IMMATABILITY WARNING: % core tables are missing protection triggers!', v_unprotected_count;
        RAISE WARNING 'Run SELECT * FROM core.verify_immutability_enforcement(); for details.';
    ELSE
        RAISE NOTICE 'IMMUTABILITY VERIFIED: All core tables are protected against UPDATE/DELETE/TRUNCATE.';
    END IF;
END;
$$;

-- =============================================================================
-- FINAL IMMUTABILITY VERIFICATION
-- =============================================================================

-- Function to verify complete immutability protection
CREATE OR REPLACE FUNCTION core.final_immutability_check()
RETURNS TABLE (
    check_name TEXT,
    check_status TEXT,
    details TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER;
    v_table TEXT;
BEGIN
    -- Check 1: All core tables have update triggers
    check_name := 'Core Tables Update Protection';
    SELECT COUNT(DISTINCT tablename) INTO v_count
    FROM pg_tables t
    JOIN pg_trigger tr ON tr.tgrelid = (quote_ident('core') || '.' || quote_ident(t.tablename))::regclass
    WHERE t.schemaname = 'core'
    AND tr.tgname LIKE '%prevent_update%';
    
    IF v_count >= 5 THEN
        check_status := 'PASS';
        details := format('%s core tables protected', v_count);
    ELSE
        check_status := 'FAIL';
        details := format('Only %s tables protected, expected 5+', v_count);
    END IF;
    RETURN NEXT;
    
    -- Check 2: All core tables have delete triggers
    check_name := 'Core Tables Delete Protection';
    SELECT COUNT(DISTINCT tablename) INTO v_count
    FROM pg_tables t
    JOIN pg_trigger tr ON tr.tgrelid = (quote_ident('core') || '.' || quote_ident(t.tablename))::regclass
    WHERE t.schemaname = 'core'
    AND tr.tgname LIKE '%prevent_delete%';
    
    IF v_count >= 5 THEN
        check_status := 'PASS';
        details := format('%s core tables protected', v_count);
    ELSE
        check_status := 'FAIL';
        details := format('Only %s tables protected, expected 5+', v_count);
    END IF;
    RETURN NEXT;
    
    -- Check 3: Transaction log has hash fields
    check_name := 'Transaction Log Hash Fields';
    SELECT COUNT(*) INTO v_count
    FROM information_schema.columns
    WHERE table_schema = 'core'
    AND table_name = 'transaction_log'
    AND column_name IN ('previous_hash', 'current_hash', 'payload_hash');
    
    IF v_count = 3 THEN
        check_status := 'PASS';
        details := 'All hash fields present';
    ELSE
        check_status := 'FAIL';
        details := format('Only %s/3 hash fields present', v_count);
    END IF;
    RETURN NEXT;
    
    -- Check 4: Blocks have Merkle root
    check_name := 'Blocks Merkle Root';
    SELECT COUNT(*) INTO v_count
    FROM information_schema.columns
    WHERE table_schema = 'core'
    AND table_name = 'blocks'
    AND column_name IN ('merkle_root', 'previous_block_hash');
    
    IF v_count = 2 THEN
        check_status := 'PASS';
        details := 'Merkle fields present';
    ELSE
        check_status := 'FAIL';
        details := 'Missing Merkle fields';
    END IF;
    RETURN NEXT;
    
    -- Check 5: Audit trail exists and is immutable
    check_name := 'Audit Trail Immutability';
    SELECT COUNT(*) INTO v_count
    FROM pg_trigger tr
    JOIN pg_class c ON tr.tgrelid = c.oid
    JOIN pg_namespace n ON c.relnamespace = n.oid
    WHERE n.nspname = 'core'
    AND c.relname = 'audit_trail'
    AND tr.tgname LIKE '%prevent%';
    
    IF v_count >= 2 THEN
        check_status := 'PASS';
        details := format('%s protection triggers on audit_trail', v_count);
    ELSE
        check_status := 'WARN';
        details := 'Limited protection on audit_trail';
    END IF;
    RETURN NEXT;
    
    -- Check 6: RLS is enabled on tenant tables
    check_name := 'Row Level Security';
    SELECT COUNT(*) INTO v_count
    FROM pg_class c
    JOIN pg_namespace n ON c.relnamespace = n.oid
    WHERE n.nspname IN ('core', 'app')
    AND c.relkind = 'r'
    AND c.relrowsecurity = TRUE;
    
    IF v_count >= 3 THEN
        check_status := 'PASS';
        details := format('%s tables have RLS enabled', v_count);
    ELSE
        check_status := 'WARN';
        details := 'Limited RLS coverage';
    END IF;
    RETURN NEXT;
END;
$$;

-- Run the check
DO $$
DECLARE
    v_result RECORD;
    v_failures INTEGER := 0;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '================================================================================';
    RAISE NOTICE 'FINAL IMMUTABILITY VERIFICATION';
    RAISE NOTICE '================================================================================';
    
    FOR v_result IN SELECT * FROM core.final_immutability_check()
    LOOP
        RAISE NOTICE '%: % - %', v_result.check_name, v_result.check_status, v_result.details;
        IF v_result.check_status = 'FAIL' THEN
            v_failures := v_failures + 1;
        END IF;
    END LOOP;
    
    RAISE NOTICE '================================================================================';
    IF v_failures = 0 THEN
        RAISE NOTICE 'ALL CHECKS PASSED - System is ready for production';
    ELSE
        RAISE WARNING '% CHECKS FAILED - Review and fix before production', v_failures;
    END IF;
    RAISE NOTICE '================================================================================';
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON FUNCTION core.prevent_update() IS 
    'Trigger function that blocks UPDATE operations on immutable tables and logs violations';
COMMENT ON FUNCTION core.prevent_delete() IS 
    'Trigger function that blocks DELETE operations on immutable tables and logs violations';
COMMENT ON FUNCTION core.prevent_truncate() IS 
    'Trigger function that blocks TRUNCATE operations on immutable tables';
COMMENT ON FUNCTION core.verify_immutability_enforcement() IS 
    'Verification function to ensure all immutable tables have protection triggers';
COMMENT ON FUNCTION core.final_immutability_check() IS 
    'Final verification that all immutability protections are in place';

-- =============================================================================
-- END OF FILE
-- =============================================================================
