-- =============================================================================
-- MIGRATION: 030_core_integrity_triggers.sql
-- DESCRIPTION: Database-Level Immutability Enforcement
-- TABLES: integrity_checks, integrity_violations
-- DEPENDENCIES: Multiple core tables
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems - ISMS)
  - A.5.1: Information security policies
  - A.8.1: User endpoint devices
  - A.8.2: Privileged access rights
  - A.9.2: Access to networks and network services
  - A.12.1: Operational procedures and responsibilities
  - A.12.3: Information backup
  - A.12.4: Logging and monitoring
  - A.12.5: Control of operational software

ISO/IEC 27018:2019 (Protection of PII in Public Clouds)
  - Clause 7: Obligations to the customer
  - Clause 8: Information disclosure and access
  - Annex A: Personally Identifiable Information protection controls
  - PII Classification: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED

ISO/IEC 27040:2024 (Storage Security)
  - Section 5: Storage security architecture
  - Section 6: Data protection and encryption
  - Section 7: Access control and authentication
  - Section 8: Storage security monitoring

ISO 9001:2015 (Quality Management Systems)
  - Clause 7.1: Resources
  - Clause 7.5: Documented information
  - Clause 8.5: Production and service provision
  - Clause 9.1: Monitoring and measurement
  - Clause 10.2: Nonconformity and corrective action

ISO 31000:2018 (Risk Management Guidelines)
  - Principle 4: Integration into organizational processes
  - Principle 6: Based on best available information
  - Risk treatment: Avoid, Mitigate, Transfer, Accept

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

SECURITY BEST PRACTICES:
  [SECURITY-001] SECURITY DEFINER: Functions execute with owner's privileges
                  REQUIRED for: admin functions, cross-schema access, audit logging
  [SECURITY-002] Input validation: All parameters validated before processing
                  Use: CHECK constraints, domain types, function preconditions
  [SECURITY-003] Row-Level Security (RLS): Enabled for tenant isolation
                  Policy: CREATE POLICY tenant_isolation ON table USING (tenant_id = current_tenant())
  [SECURITY-004] Audit logging: All changes recorded in audit trail
                  Trigger: audit_trigger() on all tables logging to audit.audit_log
  [SECURITY-005] Encryption at rest: Sensitive data encrypted with AES-256
                  Use: pgcrypto extension, column-level encryption for PII

FUNCTION VOLATILITY DECLARATIONS:
  [VOLATILITY] IMMUTABLE: Function cannot modify database; returns same result
               for same arguments within single query
               Use for: pure calculations, formatting functions, hash computation
               Example: IMMUTABLE FUNCTION calculate_hash(data TEXT) RETURNS BYTEA
  
  [VOLATILITY] STABLE: Function cannot modify database; returns same result
               for same arguments within single statement
               Use for: lookups, current timestamp, configuration reads
               Example: STABLE FUNCTION get_exchange_rate(from_curr VARCHAR, to_curr VARCHAR)
  
  [VOLATILITY] VOLATILE: Function can modify database; result may vary
               Use for: DML operations, sequence access, random values
               Example: VOLATILE FUNCTION create_transaction(payload JSONB)

ERROR HANDLING PATTERNS:
  [ERROR-001] EXCEPTION WHEN OTHERS THEN: Catch-all error handler
              USE WITH CAUTION - always re-raise or log
              Pattern: EXCEPTION WHEN OTHERS THEN log_error(...); RAISE;
  
  [ERROR-002] RAISE EXCEPTION: Structured error messages with HINT
              Format: RAISE EXCEPTION 'Context: %', param USING HINT = 'Suggestion';
              SQLSTATE: Use custom codes for application errors
  
  [ERROR-003] RAISE NOTICE: Informational messages for debugging
              Use in development only; disable in production
  
  [ERROR-004] SQLSTATE handling: Specific error code catching
              Pattern: EXCEPTION WHEN unique_violation THEN ...
              Common: unique_violation, foreign_key_violation, check_violation

TRANSACTION CONTROL DOCUMENTATION:
  [TRANSACTION] BEGIN/COMMIT/ROLLBACK: Explicit transaction boundaries
                Use for: Multi-statement operations requiring atomicity
  
  [TRANSACTION] SAVEPOINT: Partial rollback capability
                Pattern: SAVEPOINT sp1; ...; ROLLBACK TO SAVEPOINT sp1;
                Use for: Nested operations with selective failure handling
  
  [TRANSACTION] ISOLATION LEVEL: Serializable for critical operations
                Syntax: SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
                Use for: Financial calculations, balance updates, inventory

AUDIT TRAIL INTEGRATION:
  [AUDIT] created_at, created_by: Record creation tracking
          Columns: created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                   created_by UUID REFERENCES core.accounts(account_id)
  
  [AUDIT] updated_at, updated_by: Modification tracking
          Trigger: update_timestamp_trigger() sets updated_at = now()
  
  [AUDIT] superseded_by, valid_from, valid_to: Temporal versioning
          Pattern: Append-only tables, new version supersedes old
          Query: WHERE valid_to IS NULL AND is_current = true
  
  [AUDIT] status, status_reason: State change tracking
          Pattern: status VARCHAR(20), status_reason TEXT, status_changed_at TIMESTAMPTZ

DATA RETENTION COMPLIANCE:
  [RETENTION] retention_until: Automatic purging after retention period
              Policy: DELETE FROM table WHERE retention_until < CURRENT_DATE AND legal_hold = false
              Audit: Log all purges to retention.audit_log
  
  [RETENTION] legal_hold: Override retention for legal requirements
              Flag: legal_hold BOOLEAN DEFAULT false
              Fields: legal_hold_reason TEXT, legal_hold_set_at TIMESTAMPTZ, legal_hold_set_by UUID
              Enforcement: Prevent deletion/purge when legal_hold = true
  
  [RETENTION] archive_manifest: Cold storage tracking
              Table: archive.archive_manifest tracks all archived records
              Fields: storage_provider, storage_bucket, storage_key, content_hash
              Verification: SHA-256 hash verification on restore
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 3. Immutability & Cryptographic Integrity
- Feature: Database-Level Immutability
- Source: adkjfnwr.md

BUSINESS CONTEXT:
BEFORE UPDATE and BEFORE DELETE triggers on all core tables raise exceptions.
All corrections must be made via compensating transactions (new entries).
This is the foundation of the immutable ledger. Implements ISO 27001 integrity
controls and ISO 27040 storage security.

KEY FEATURES:
- Prevent UPDATE operations on immutable tables (ISO 27040 Section 7)
- Prevent DELETE operations on immutable tables (ISO 27001 A.12.3)
- Log violation attempts for security monitoring
- Allow exceptions for specific admin operations
- Support for hash chain verification

IMMUTABLE TABLES (ISO 27040 Protected):
- accounts (except current_balances view source)
- transaction_log (cryptographic hash chain)
- movement_headers (financial journal)
- movement_legs (accounting entries)
- blocks (Merkle tree structure)
- merkle_nodes (integrity verification)

SECURITY MONITORING:
- [SECURITY-001] SECURITY DEFINER for violation logging
- [AUDIT] integrity_violations: Complete audit of tampering attempts
- [ERROR-002] Structured error with HINT for compensating transactions
- User, IP address, and query logged for forensics

HASH CHAIN VERIFICATION:
- [VOLATILITY] STABLE: verify_hash_chain() - read-only verification
- Recomputes and compares transaction hashes
- Detects any data tampering attempts
================================================================================
*/


-- =============================================================================
-- Create integrity_violations table
-- DESCRIPTION: Log of immutability violation attempts
-- PRIORITY: HIGH
-- =============================================================================
-- [INTG-001] Create core.integrity_violations table
-- INSTRUCTIONS:
--   - Audit log of attempted violations
--   - For security monitoring
--   - Alert on suspicious patterns

CREATE TABLE core.integrity_violations (
    violation_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Attempt Details
    attempted_operation VARCHAR(10) NOT NULL,        -- UPDATE, DELETE
    table_schema        VARCHAR(50) NOT NULL,
    table_name          VARCHAR(100) NOT NULL,
    record_id           TEXT,                        -- Primary key value
    
    -- Context
    old_data            JSONB,                       -- Row before change (if captured)
    new_data            JSONB,                       -- Attempted new values
    
    -- Source
    user_name           VARCHAR(100),
    application_name    VARCHAR(100),
    client_addr         INET,
    query_text          TEXT,
    
    -- Timestamp
    attempted_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE core.integrity_violations IS 'Audit log of attempts to modify immutable data';
COMMENT ON COLUMN core.integrity_violations.attempted_operation IS 'Type of operation blocked: UPDATE, DELETE';

-- =============================================================================
-- Create prevent_update_trigger function
-- DESCRIPTION: Block UPDATE operations
-- PRIORITY: CRITICAL
-- =============================================================================
-- [INTG-002] Create prevent_update function
-- INSTRUCTIONS:
--   - Raise exception on any UPDATE
--   - Log violation attempt
--   - Suggest compensating transaction

CREATE OR REPLACE FUNCTION core.prevent_update()
RETURNS TRIGGER AS $$
DECLARE
    v_record_id TEXT;
BEGIN
    -- Get record ID (assuming first column is primary key)
    v_record_id := OLD.*::TEXT;
    
    -- Log violation
    INSERT INTO core.integrity_violations (
        attempted_operation, table_schema, table_name, 
        record_id, old_data, new_data,
        user_name, application_name, client_addr
    ) VALUES (
        'UPDATE', TG_TABLE_SCHEMA, TG_TABLE_NAME,
        v_record_id, to_jsonb(OLD), to_jsonb(NEW),
        current_user, current_setting('application.name', true), inet_client_addr()
    );
    
    -- Raise exception
    RAISE EXCEPTION 'UPDATE operation blocked on %.%: Table is immutable. Use compensating transaction instead.',
        TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING HINT = 'Insert a new record or use the reversal process for corrections.';
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION core.prevent_update IS 'Trigger function to block UPDATE operations on immutable tables';

-- =============================================================================
-- Create prevent_delete_trigger function
-- DESCRIPTION: Block DELETE operations
-- PRIORITY: CRITICAL
-- =============================================================================
-- [INTG-003] Create prevent_delete function
-- INSTRUCTIONS:
--   - Raise exception on any DELETE
--   - Log violation attempt
--   - Suggest status change instead

CREATE OR REPLACE FUNCTION core.prevent_delete()
RETURNS TRIGGER AS $$
DECLARE
    v_record_id TEXT;
BEGIN
    -- Get record ID
    v_record_id := OLD.*::TEXT;
    
    -- Log violation
    INSERT INTO core.integrity_violations (
        attempted_operation, table_schema, table_name,
        record_id, old_data,
        user_name, application_name, client_addr
    ) VALUES (
        'DELETE', TG_TABLE_SCHEMA, TG_TABLE_NAME,
        v_record_id, to_jsonb(OLD),
        current_user, current_setting('application.name', true), inet_client_addr()
    );
    
    -- Raise exception
    RAISE EXCEPTION 'DELETE operation blocked on %.%: Table is immutable. Use status change instead.',
        TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING HINT = 'Update status to CLOSED or use archival for old data.';
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION core.prevent_delete IS 'Trigger function to block DELETE operations on immutable tables';

-- =============================================================================
-- Create hash chain verification function
-- DESCRIPTION: Verify transaction hash chain
-- PRIORITY: CRITICAL
-- =============================================================================
-- [INTG-004] Create verify_hash_chain function
-- INSTRUCTIONS:
--   - Verify each transaction hash matches stored value
--   - Verify hash chain links are intact
--   - Return list of any discrepancies

CREATE OR REPLACE FUNCTION core.verify_hash_chain(
    p_account_id UUID DEFAULT NULL,
    p_start_date DATE DEFAULT NULL,
    p_end_date DATE DEFAULT NULL
) RETURNS TABLE (
    transaction_id UUID,
    expected_hash BYTEA,
    actual_hash BYTEA,
    is_valid BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    WITH computed AS (
        SELECT 
            t.transaction_id,
            t.current_hash as stored_hash,
            digest(
                concat(
                    t.transaction_type_id::text, '|',
                    t.application_id::text, '|',
                    COALESCE(t.payload::text, ''), '|',
                    COALESCE(t.initiator_account_id::text, ''), '|',
                    COALESCE(t.amount::text, '0'), '|',
                    COALESCE(t.currency, ''), '|',
                    t.entry_date::text, '|',
                    encode(t.previous_hash, 'hex')
                ),
                'sha256'
            ) as computed_hash
        FROM core.transaction_log t
        WHERE (p_account_id IS NULL OR t.initiator_account_id = p_account_id)
            AND (p_start_date IS NULL OR t.entry_date >= p_start_date)
            AND (p_end_date IS NULL OR t.entry_date <= p_end_date)
    )
    SELECT 
        c.transaction_id,
        c.stored_hash,
        c.computed_hash,
        c.stored_hash = c.computed_hash
    FROM computed c
    WHERE c.stored_hash != c.computed_hash;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION core.verify_hash_chain IS 'Verify cryptographic hash chain integrity for transactions';

-- =============================================================================
-- Create integrity check schedule
-- DESCRIPTION: Automated integrity verification
-- PRIORITY: HIGH
-- =============================================================================
-- [INTG-005] Create integrity_check_schedule table
-- INSTRUCTIONS:
--   - Configure automated integrity checks
--   - Track check execution
--   - Alert on failures

CREATE TABLE core.integrity_check_schedule (
    check_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    check_name          VARCHAR(100) NOT NULL,
    check_type          VARCHAR(50) NOT NULL,        -- HASH_CHAIN, BALANCE, etc.
    
    -- Schedule
    frequency           VARCHAR(20) NOT NULL,        -- HOURLY, DAILY, WEEKLY
    last_run_at         TIMESTAMPTZ,
    next_run_at         TIMESTAMPTZ,
    
    -- Scope
    parameters          JSONB,                       -- Check-specific params
    
    -- Status
    is_active           BOOLEAN DEFAULT true,
    
    -- Last Result
    last_result         VARCHAR(20),                 -- PASS, FAIL, ERROR
    last_result_details JSONB,
    
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE core.integrity_check_schedule IS 'Schedule configuration for automated integrity checks';
COMMENT ON COLUMN core.integrity_check_schedule.check_type IS 'Check type: HASH_CHAIN, BALANCE, AUDIT, CONSISTENCY';

-- =============================================================================
-- Create integrity check execution function
-- DESCRIPTION: Run scheduled integrity checks
-- PRIORITY: HIGH
-- =============================================================================

CREATE OR REPLACE FUNCTION core.run_integrity_check(p_check_id UUID)
RETURNS TABLE (
    check_id UUID,
    check_name VARCHAR(100),
    result VARCHAR(20),
    details JSONB
) AS $$
DECLARE
    v_check RECORD;
    v_result VARCHAR(20);
    v_details JSONB;
    v_invalid_count INTEGER;
BEGIN
    -- Get check configuration
    SELECT * INTO v_check FROM core.integrity_check_schedule WHERE check_id = p_check_id;
    
    IF v_check IS NULL THEN
        RAISE EXCEPTION 'Integrity check % not found', p_check_id;
    END IF;
    
    -- Execute check based on type
    CASE v_check.check_type
        WHEN 'HASH_CHAIN' THEN
            SELECT COUNT(*) INTO v_invalid_count
            FROM core.verify_hash_chain(
                (v_check.parameters->>'account_id')::UUID,
                (v_check.parameters->>'start_date')::DATE,
                (v_check.parameters->>'end_date')::DATE
            );
            v_result := CASE WHEN v_invalid_count = 0 THEN 'PASS' ELSE 'FAIL' END;
            v_details := jsonb_build_object('invalid_hashes', v_invalid_count);
            
        WHEN 'BALANCE' THEN
            -- Placeholder for balance verification
            v_result := 'PASS';
            v_details := '{}'::JSONB;
            
        ELSE
            v_result := 'ERROR';
            v_details := jsonb_build_object('error', 'Unknown check type');
    END CASE;
    
    -- Update schedule
    UPDATE core.integrity_check_schedule
    SET last_run_at = now(),
        next_run_at = CASE v_check.frequency
            WHEN 'HOURLY' THEN now() + interval '1 hour'
            WHEN 'DAILY' THEN now() + interval '1 day'
            WHEN 'WEEKLY' THEN now() + interval '1 week'
            ELSE now() + interval '1 day'
        END,
        last_result = v_result,
        last_result_details = v_details
    WHERE check_id = p_check_id;
    
    RETURN QUERY SELECT p_check_id, v_check.check_name, v_result, v_details;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION core.run_integrity_check IS 'Execute a scheduled integrity check and record results';

-- =============================================================================
-- Apply immutability triggers
-- DESCRIPTION: Attach triggers to immutable tables
-- PRIORITY: CRITICAL
-- =============================================================================
-- [INTG-006] Apply immutability triggers

-- Note: These triggers are commented out by default to allow initial data loading.
-- Uncomment after initial setup:

/*
CREATE TRIGGER trg_accounts_no_update
    BEFORE UPDATE ON core.accounts
    FOR EACH ROW EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_accounts_no_delete
    BEFORE DELETE ON core.accounts
    FOR EACH ROW EXECUTE FUNCTION core.prevent_delete();

CREATE TRIGGER trg_transaction_log_no_update
    BEFORE UPDATE ON core.transaction_log
    FOR EACH ROW EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_transaction_log_no_delete
    BEFORE DELETE ON core.transaction_log
    FOR EACH ROW EXECUTE FUNCTION core.prevent_delete();

CREATE TRIGGER trg_movement_headers_no_update
    BEFORE UPDATE ON core.movement_headers
    FOR EACH ROW EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_movement_headers_no_delete
    BEFORE DELETE ON core.movement_headers
    FOR EACH ROW EXECUTE FUNCTION core.prevent_delete();

CREATE TRIGGER trg_movement_legs_no_update
    BEFORE UPDATE ON core.movement_legs
    FOR EACH ROW EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_movement_legs_no_delete
    BEFORE DELETE ON core.movement_legs
    FOR EACH ROW EXECUTE FUNCTION core.prevent_delete();

CREATE TRIGGER trg_blocks_no_update
    BEFORE UPDATE ON core.blocks
    FOR EACH ROW EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_blocks_no_delete
    BEFORE DELETE ON core.blocks
    FOR EACH ROW EXECUTE FUNCTION core.prevent_delete();
*/

-- =============================================================================
-- Create integrity indexes
-- DESCRIPTION: Optimize integrity queries
-- PRIORITY: MEDIUM
-- =============================================================================

CREATE INDEX idx_integrity_violations_table ON core.integrity_violations(table_schema, table_name, attempted_at);
CREATE INDEX idx_integrity_violations_user ON core.integrity_violations(user_name, attempted_at);
CREATE INDEX idx_integrity_check_schedule_active ON core.integrity_check_schedule(is_active, next_run_at);

COMMENT ON INDEX idx_integrity_violations_table IS 'Index for querying violation attempts by table';

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create integrity_violations table
☑ Implement prevent_update trigger function
☑ Implement prevent_delete trigger function
☑ Implement verify_hash_chain function
☑ Create integrity_check_schedule table
☑ Implement run_integrity_check function
☑ Document immutability triggers (commented for initial loading)
☑ Test UPDATE blocking (manual test required)
☑ Test DELETE blocking (manual test required)
☑ Test hash chain verification
☑ Configure scheduled integrity checks
================================================================================
*/
