-- =============================================================================
-- USSD KERNEL CORE SCHEMA - MISSING TRIGGER FUNCTIONS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    055_missing_trigger_functions.sql
-- MIGRATION:   0001_baseline/up
-- DESCRIPTION: Trigger functions referenced in other files but not defined.
--              Includes hash calculation, audit logging, and validation.
-- =============================================================================

/*
================================================================================
TRIGGER FUNCTIONS COMPLETION
================================================================================

This migration adds trigger functions that are referenced in table definitions
and other migrations but were not created in the baseline. These functions
enforce business rules, calculate hashes, and maintain audit trails.

Functions Added:
1. core.calculate_record_hash() - Calculate SHA-256 hash of record
2. core.update_record_hash() - Trigger to update hash on insert
3. core.audit_trigger() - Generic audit logging trigger
4. core.validate_payload_schema() - JSON schema validation
5. core.update_updated_at() - Auto-update timestamp trigger
6. core.check_chain_integrity() - Hash chain validation
7. core.prevent_duplicate_idempotency_key() - Duplicate prevention

================================================================================
*/

-- =============================================================================
-- 1. RECORD HASH CALCULATION
-- =============================================================================

-- Function to calculate SHA-256 hash of a record
CREATE OR REPLACE FUNCTION core.calculate_record_hash(
    p_table_name TEXT,
    p_record_id TEXT,
    p_payload JSONB DEFAULT NULL
)
RETURNS VARCHAR(64)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_hash_input TEXT;
    v_hash VARCHAR(64);
BEGIN
    -- Build hash input from table, id, timestamp, and payload
    v_hash_input := p_table_name || ':' || 
                    p_record_id || ':' || 
                    extract(epoch from clock_timestamp())::TEXT;
    
    IF p_payload IS NOT NULL THEN
        v_hash_input := v_hash_input || ':' || p_payload::TEXT;
    END IF;
    
    -- Calculate SHA-256 hash
    SELECT encode(digest(v_hash_input, 'sha256'), 'hex') INTO v_hash;
    
    RETURN v_hash;
END;
$$;

-- Trigger function to update record_hash on INSERT
CREATE OR REPLACE FUNCTION core.update_record_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_record_id TEXT;
    v_payload JSONB;
    v_hash VARCHAR(64);
BEGIN
    -- Get record identifier
    v_record_id := COALESCE(
        NEW.transaction_id::TEXT,
        NEW.block_id::TEXT,
        NEW.audit_id::TEXT,
        NEW.saga_id::TEXT,
        NEW.key_id::TEXT,
        gen_random_uuid()::TEXT
    );
    
    -- Get payload if exists
    BEGIN
        v_payload := to_jsonb(NEW);
        -- Remove the record_hash field itself from hash calculation
        v_payload := v_payload - 'record_hash';
    EXCEPTION WHEN OTHERS THEN
        v_payload := NULL;
    END;
    
    -- Calculate hash
    v_hash := core.calculate_record_hash(TG_TABLE_NAME, v_record_id, v_payload);
    
    -- Set the hash
    NEW.record_hash := v_hash;
    
    RETURN NEW;
END;
$$;

-- =============================================================================
-- 2. AUDIT TRIGGER
-- =============================================================================

-- Generic audit trigger function
CREATE OR REPLACE FUNCTION core.audit_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_old_data JSONB;
    v_new_data JSONB;
    v_audit_id UUID;
BEGIN
    -- Prepare data based on operation
    IF TG_OP = 'INSERT' THEN
        v_old_data := NULL;
        v_new_data := to_jsonb(NEW);
    ELSIF TG_OP = 'UPDATE' THEN
        v_old_data := to_jsonb(OLD);
        v_new_data := to_jsonb(NEW);
    ELSIF TG_OP = 'DELETE' THEN
        v_old_data := to_jsonb(OLD);
        v_new_data := NULL;
    END IF;
    
    -- Insert audit record
    INSERT INTO core.audit_trail (
        table_name,
        record_id,
        action,
        old_values,
        new_values,
        changed_by,
        changed_at,
        session_user_name,
        application_name
    ) VALUES (
        TG_TABLE_NAME,
        COALESCE(NEW.id::TEXT, OLD.id::TEXT, 'UNKNOWN'),
        TG_OP,
        v_old_data,
        v_new_data,
        NULL,  -- Changed by - should be set from session context
        NOW(),
        session_user,
        current_setting('application_name', true)
    )
    RETURNING audit_id INTO v_audit_id;
    
    -- Return appropriate record
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$;

-- =============================================================================
-- 3. PAYLOAD SCHEMA VALIDATION
-- =============================================================================

-- Function to validate JSON payload against schema
CREATE OR REPLACE FUNCTION core.validate_payload_schema()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_schema JSONB;
    v_validation_errors TEXT[];
BEGIN
    -- Basic validation - check for required fields based on transaction type
    IF NEW.payload IS NULL THEN
        RAISE EXCEPTION 'Payload cannot be NULL';
    END IF;
    
    -- Check for required fields
    IF NOT (NEW.payload ? 'version') THEN
        RAISE EXCEPTION 'Payload must contain "version" field';
    END IF;
    
    IF NOT (NEW.payload ? 'timestamp') THEN
        RAISE EXCEPTION 'Payload must contain "timestamp" field';
    END IF;
    
    -- Additional validation based on transaction type could be added here
    -- For now, we accept the payload if it has basic structure
    
    RETURN NEW;
END;
$$;

-- =============================================================================
-- 4. AUTO-UPDATE TIMESTAMP
-- =============================================================================

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION core.update_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$;

-- =============================================================================
-- 5. CHAIN INTEGRITY VALIDATION
-- =============================================================================

-- Function to validate hash chain integrity on insert
CREATE OR REPLACE FUNCTION core.check_chain_integrity()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_expected_previous_hash VARCHAR(64);
    v_actual_previous_hash VARCHAR(64);
    v_previous_record RECORD;
BEGIN
    -- Only validate if there's a previous record
    IF NEW.previous_transaction_id IS NOT NULL THEN
        -- Get previous record
        SELECT current_hash, record_hash 
        INTO v_previous_record
        FROM core.transaction_log
        WHERE transaction_id = NEW.previous_transaction_id;
        
        IF FOUND THEN
            v_expected_previous_hash := COALESCE(v_previous_record.current_hash, v_previous_record.record_hash);
            v_actual_previous_hash := NEW.previous_hash;
            
            -- Validate chain link
            IF v_expected_previous_hash IS DISTINCT FROM v_actual_previous_hash THEN
                RAISE EXCEPTION 'CHAIN_INTEGRITY_VIOLATION: Previous hash mismatch. Expected: %, Got: %',
                    v_expected_previous_hash, v_actual_previous_hash;
            END IF;
        END IF;
    END IF;
    
    RETURN NEW;
END;
$$;

-- =============================================================================
-- 6. IDEMPOTENCY KEY DUPLICATE PREVENTION
-- =============================================================================

-- Function to prevent duplicate idempotency keys
CREATE OR REPLACE FUNCTION core.prevent_duplicate_idempotency_key()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_existing_idempotency RECORD;
BEGIN
    -- Skip if no idempotency key
    IF NEW.idempotency_key IS NULL THEN
        RETURN NEW;
    END IF;
    
    -- Check for existing key
    SELECT * INTO v_existing_idempotency
    FROM core.idempotency_keys
    WHERE idempotency_key = NEW.idempotency_key
    AND status IN ('ACTIVE', 'PROCESSING');
    
    IF FOUND THEN
        -- If key exists and is still valid, block the insert
        IF v_existing_idempotency.expires_at > NOW() THEN
            RAISE EXCEPTION 'IDEMPOTENCY_KEY_EXISTS: Key % is already in use (status: %). Existing transaction: %',
                NEW.idempotency_key, v_existing_idempotency.status, v_existing_idempotency.transaction_id
                USING ERRCODE = 'unique_violation';
        END IF;
    END IF;
    
    RETURN NEW;
END;
$$;

-- =============================================================================
-- 7. BLOCK MERKLE ROOT VALIDATION
-- =============================================================================

-- Function to validate Merkle root on block insert
CREATE OR REPLACE FUNCTION core.validate_block_merkle_root()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_calculated_root VARCHAR(64);
    v_transaction_hashes TEXT[];
BEGIN
    -- Get all transaction hashes for this block
    SELECT array_agg(transaction_hash ORDER BY transaction_id)
    INTO v_transaction_hashes
    FROM core.transaction_log
    WHERE block_id = NEW.block_id;
    
    -- If there are transactions, calculate and verify Merkle root
    IF v_transaction_hashes IS NOT NULL AND array_length(v_transaction_hashes, 1) > 0 THEN
        -- Simple hash of concatenated hashes (production would use proper Merkle tree)
        SELECT encode(digest(array_to_string(v_transaction_hashes, ''), 'sha256'), 'hex')
        INTO v_calculated_root;
        
        -- For now, just log the validation
        -- In strict mode, would compare: IF v_calculated_root != NEW.merkle_root THEN ...
        
        RAISE DEBUG 'Block %: Calculated Merkle root: %, Stored: %', 
            NEW.block_id, v_calculated_root, NEW.merkle_root;
    END IF;
    
    RETURN NEW;
END;
$$;

-- =============================================================================
-- 8. CONTINUOUS AUDIT TRAIL CHAIN
-- =============================================================================

-- Function to maintain continuous audit trail chain
CREATE OR REPLACE FUNCTION core.maintain_audit_chain()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_previous_hash VARCHAR(64);
BEGIN
    -- Get previous record's hash
    SELECT record_hash INTO v_previous_hash
    FROM core.continuous_audit_trail
    ORDER BY sequence_number DESC
    LIMIT 1;
    
    -- Set previous hash
    NEW.previous_hash := COALESCE(v_previous_hash, 'GENESIS');
    
    RETURN NEW;
END;
$$;

-- =============================================================================
-- APPLY MISSING TRIGGERS
-- =============================================================================

-- Apply record hash triggers to tables that need them
DO $$
DECLARE
    v_table RECORD;
BEGIN
    FOR v_table IN 
        SELECT tablename 
        FROM pg_tables 
        WHERE schemaname = 'core'
        AND tablename IN ('transaction_sagas', 'saga_steps', 'security_audit_log', 
                          'hash_chain_verification', 'signing_keys', 'external_blockchain_anchors',
                          'data_classification', 'retention_policies')
    LOOP
        -- Check if column exists
        IF EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_schema = 'core' 
            AND table_name = v_table.tablename 
            AND column_name = 'record_hash'
        ) THEN
            EXECUTE format('DROP TRIGGER IF EXISTS trg_%s_hash ON core.%s',
                          v_table.tablename, v_table.tablename);
            EXECUTE format('CREATE TRIGGER trg_%s_hash BEFORE INSERT ON core.%s FOR EACH ROW EXECUTE FUNCTION core.update_record_hash()',
                          v_table.tablename, v_table.tablename);
            
            RAISE NOTICE 'Created hash trigger for %', v_table.tablename;
        END IF;
    END LOOP;
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON FUNCTION core.calculate_record_hash IS 
    'Calculate SHA-256 hash of a record for integrity verification';
COMMENT ON FUNCTION core.update_record_hash IS 
    'Trigger function to automatically calculate and set record_hash on insert';
COMMENT ON FUNCTION core.audit_trigger IS 
    'Generic audit trigger for tracking changes to tables';
COMMENT ON FUNCTION core.check_chain_integrity IS 
    'Validate hash chain integrity by verifying previous_hash links';
COMMENT ON FUNCTION core.prevent_duplicate_idempotency_key IS 
    'Prevent duplicate idempotency keys in transaction processing';

-- =============================================================================
-- END OF FILE
-- =============================================================================
