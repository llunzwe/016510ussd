-- =============================================================================
-- USSD KERNEL CORE SCHEMA - TRIGGERS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    001_hash_chain_automation.sql
-- SCHEMA:      core
-- CATEGORY:    Triggers - Hash Chain Automation
-- DESCRIPTION: Automated hash computation triggers for maintaining
--              cryptographic hash chains on INSERT operations.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.10.1 Cryptographic controls - Automated hash computation
├── A.10.2 Cryptographic controls - Chain integrity automation
└── A.12.4 Logging and monitoring - Hash computation monitoring

ISO/IEC 27040:2024 (Storage Security)
├── Automated hashing: Every record hashed on insert
├── Chain maintenance: Previous hash retrieval automation
├── Integrity verification: Automated verification triggers
└── Tamper detection: Real-time chain validation

ISO/IEC 27031:2025 (Business Continuity ICT Readiness)
├── Hash computation during recovery: Post-disaster chain rebuild
├── Verification automation: Scheduled integrity checks
└── Backup validation: Hash-verified backups

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. TRIGGER TIMING
   - BEFORE INSERT: Compute hash before storage
   - AFTER INSERT: Verify hash after storage
   - Deferred constraints for complex validation

2. HASH COMPUTATION
   - Deterministic input construction
   - Canonical ordering of fields
   - Null handling strategy
   - Algorithm selection

3. ERROR HANDLING
   - Hash computation failures
   - Chain break detection
   - Recovery procedures

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

HASH CHAIN AUTOMATION:
1. Per-Account Chain
   - Retrieve previous hash for account
   - Compute new hash with linkage
   - Store both hashes
   - Verify chain integrity

2. Global Chain
   - Retrieve global previous hash
   - Compute global sequence
   - Maintain global integrity

3. Verification
   - Post-insert verification trigger
   - Periodic verification schedule
   - Alert on chain breaks

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

COMPUTATION OPTIMIZATION:
- Efficient hash functions
- Minimal I/O for previous hash
- Batch computation for bulk inserts
- Connection pooling

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- HASH_COMPUTED
- CHAIN_LINKED
- HASH_VERIFIED
- CHAIN_BREAK_DETECTED

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- Create compute_transaction_hash_trigger function
-- DESCRIPTION: Compute hash on transaction insert
-- PRIORITY: CRITICAL
-- =============================================================================
CREATE OR REPLACE FUNCTION core.compute_transaction_hash_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_prev_hash BYTEA;
    v_account_sequence BIGINT;
    v_global_prev_hash BYTEA;
    v_global_sequence BIGINT;
BEGIN
    -- Get previous hash for account chain
    SELECT previous_hash, account_sequence
    INTO v_prev_hash, v_account_sequence
    FROM core.get_previous_hash(NEW.initiator_account_id, NEW.application_id);
    
    -- Get previous hash for global chain
    SELECT previous_hash, chain_sequence
    INTO v_global_prev_hash, v_global_sequence
    FROM core.get_global_previous_hash();
    
    -- Compute transaction hash
    NEW.current_hash := core.compute_transaction_hash(
        NEW.transaction_type_id,
        NEW.application_id,
        NEW.payload,
        NEW.initiator_account_id,
        NEW.beneficiary_account_id,
        NEW.amount,
        NEW.currency,
        NEW.entry_date,
        v_prev_hash
    );
    
    -- Set chain metadata
    NEW.previous_hash := v_prev_hash;
    NEW.account_sequence := v_account_sequence + 1;
    NEW.chain_sequence := v_global_sequence + 1;
    NEW.previous_global_hash := v_global_prev_hash;
    
    -- Log hash computation
    INSERT INTO core.audit_trail (
        event_type,
        table_name,
        record_id,
        details
    ) VALUES (
        'HASH_COMPUTED',
        'transaction_log',
        NEW.transaction_id::text,
        jsonb_build_object(
            'account_sequence', NEW.account_sequence,
            'chain_sequence', NEW.chain_sequence,
            'hash_algorithm', 'SHA-256'
        )
    );
    
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION core.compute_transaction_hash_trigger() IS 'Trigger function to automatically compute hash chain on transaction insert';

-- Apply trigger to transaction_log table
DROP TRIGGER IF EXISTS trg_transaction_hash_compute ON core.transaction_log;
CREATE TRIGGER trg_transaction_hash_compute
    BEFORE INSERT ON core.transaction_log
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_transaction_hash_trigger();

-- =============================================================================
-- Create verify_hash_chain_trigger function
-- DESCRIPTION: Verify hash chain integrity after insert
-- PRIORITY: HIGH
-- =============================================================================
CREATE OR REPLACE FUNCTION core.verify_hash_chain_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_computed_hash BYTEA;
    v_chain_valid BOOLEAN := true;
BEGIN
    -- Recompute hash to verify
    v_computed_hash := core.compute_transaction_hash(
        NEW.transaction_type_id,
        NEW.application_id,
        NEW.payload,
        NEW.initiator_account_id,
        NEW.beneficiary_account_id,
        NEW.amount,
        NEW.currency,
        NEW.entry_date,
        NEW.previous_hash
    );
    
    -- Verify computed hash matches stored hash
    IF v_computed_hash != NEW.current_hash THEN
        v_chain_valid := false;
        
        -- Log verification failure
        INSERT INTO core.audit_trail (
            event_type,
            table_name,
            record_id,
            details,
            severity
        ) VALUES (
            'CHAIN_BREAK_DETECTED',
            'transaction_log',
            NEW.transaction_id::text,
            jsonb_build_object(
                'computed_hash', encode(v_computed_hash, 'hex'),
                'stored_hash', encode(NEW.current_hash, 'hex'),
                'account_sequence', NEW.account_sequence
            ),
            'CRITICAL'
        );
        
        RAISE EXCEPTION 'HASH_VERIFICATION_FAILED'
            USING HINT = 'Computed hash does not match stored hash. Possible data corruption.',
                  ERRCODE = 'P0002';
    END IF;
    
    -- Verify previous hash linkage (if not genesis)
    IF NEW.previous_hash != '\x00'::BYTEA THEN
        IF NOT EXISTS (
            SELECT 1 FROM core.transaction_log 
            WHERE current_hash = NEW.previous_hash
              AND initiator_account_id = NEW.initiator_account_id
        ) THEN
            v_chain_valid := false;
            
            INSERT INTO core.audit_trail (
                event_type,
                table_name,
                record_id,
                details,
                severity
            ) VALUES (
                'CHAIN_LINKAGE_ERROR',
                'transaction_log',
                NEW.transaction_id::text,
                jsonb_build_object(
                    'previous_hash', encode(NEW.previous_hash, 'hex'),
                    'account_id', NEW.initiator_account_id
                ),
                'CRITICAL'
            );
            
            RAISE EXCEPTION 'CHAIN_LINKAGE_ERROR'
                USING HINT = 'Previous hash not found in chain. Chain may be broken.',
                      ERRCODE = 'P0003';
        END IF;
    END IF;
    
    -- Log successful verification
    INSERT INTO core.audit_trail (
        event_type,
        table_name,
        record_id,
        details
    ) VALUES (
        'HASH_VERIFIED',
        'transaction_log',
        NEW.transaction_id::text,
        jsonb_build_object(
            'account_sequence', NEW.account_sequence,
            'chain_sequence', NEW.chain_sequence,
            'verified_at', CURRENT_TIMESTAMP
        )
    );
    
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION core.verify_hash_chain_trigger() IS 'Trigger function to verify hash chain integrity after transaction insert';

-- Apply verification trigger to transaction_log table
DROP TRIGGER IF EXISTS trg_transaction_hash_verify ON core.transaction_log;
CREATE TRIGGER trg_transaction_hash_verify
    AFTER INSERT ON core.transaction_log
    FOR EACH ROW
    EXECUTE FUNCTION core.verify_hash_chain_trigger();

/*
================================================================================
MIGRATION CHECKLIST:
□ Create compute_transaction_hash_trigger function
□ Create verify_hash_chain_trigger function
□ Apply triggers to transaction_log
□ Apply triggers to account_registry
□ Apply triggers to movement_legs
□ Test hash computation on insert
□ Test chain verification
□ Benchmark trigger performance
================================================================================
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
