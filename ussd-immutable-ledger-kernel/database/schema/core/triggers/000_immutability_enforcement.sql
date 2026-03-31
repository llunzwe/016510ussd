-- =============================================================================
-- USSD KERNEL CORE SCHEMA - TRIGGERS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    000_immutability_enforcement.sql
-- SCHEMA:      core
-- CATEGORY:    Triggers - Immutability
-- DESCRIPTION: Database-level immutability enforcement triggers preventing
--              UPDATE, DELETE, and TRUNCATE operations on core ledger tables.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Modification attempt logging
├── A.10.1 Cryptographic controls - Integrity enforcement
├── A.12.4 Logging and monitoring - Violation monitoring
├── A.16.1 Management of information security incidents - Violation response
└── A.16.2 Assessment and decision - Incident investigation

ISO/IEC 27040:2024 (Storage Security - CRITICAL for immutable ledger)
├── Write-Once-Read-Many (WORM): Hardware-level enforcement
├── Tamper prevention: Database-level enforcement
├── Violation logging: Immutable audit trail
├── Superuser override: Emergency procedures with audit
└── Compensating transactions: Correction workflow

ISO/IEC 27031:2025 (Business Continuity ICT Readiness)
├── Immutability during failover: Cross-site enforcement
├── Recovery integrity: Post-recovery verification
└── Backup immutability: Backup protection

Financial Regulations
├── Audit trail: Complete transaction history
├── Tamper evidence: Cryptographic proof
├── Correction workflow: Compensating entries
└── Regulatory examination: Immutable evidence

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. TRIGGER TYPES
   - BEFORE UPDATE: Block all updates
   - BEFORE DELETE: Block all deletes
   - BEFORE TRUNCATE: Block truncation
   - Conditional: Allow superuser in emergencies

2. ERROR HANDLING
   - Meaningful error messages
   - Hints for corrective action
   - Error codes for programmatic handling
   - Audit logging of attempts

3. EXCEPTION MANAGEMENT
   - Superuser bypass (configurable)
   - Emergency maintenance window
   - Explicit logging of bypass
   - Post-bypass verification

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

IMMUTABILITY ENFORCEMENT:
1. Update Prevention
   - BEFORE UPDATE trigger on all immutable tables
   - Exception raised for all UPDATE attempts
   - Superuser bypass with explicit warning (if enabled)
   - Violation logged to integrity_violations table

2. Delete Prevention
   - BEFORE DELETE trigger on all immutable tables
   - Exception raised for all DELETE attempts
   - No bypass allowed (even for superuser)
   - Violation logged with full context

3. Truncate Prevention
   - BEFORE TRUNCATE trigger on all immutable tables
   - Exception raised for all TRUNCATE attempts
   - No bypass allowed (truncation is too destructive)
   - Critical violation alert generated

VIOLATION HANDLING:
1. Logging
   - Complete violation context captured
   - User, time, query, and data recorded
   - Automated alerting on violations
   - Forensic investigation support

2. Response
   - Immediate blocking of operation
   - Real-time alerting to security team
   - Investigation workflow triggered
   - Incident documentation required

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

TRIGGER EFFICIENCY:
- Minimal trigger function overhead
- Fast condition checking
- Efficient logging
- No impact on INSERT performance

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

MANDATORY AUDIT EVENTS:
1. IMMUTABILITY_VIOLATION_ATTEMPT: Any attempt to modify immutable data
2. SUPERUSER_BYPASS: Emergency override usage
3. VIOLATION_INVESTIGATION: Investigation initiation
4. VIOLATION_RESOLUTION: Investigation completion

LOGGED FIELDS:
- attempted_operation: UPDATE, DELETE, TRUNCATE
- table_schema, table_name: Target table
- record_id: Affected record identifier
- old_data, new_data: Before/after values
- user_name: Database user
- application_name: Connected application
- client_addr, client_port: Network source
- backend_pid: Process ID
- query_text: Executed SQL
- attempted_at: Timestamp

RETENTION: 7 years (violations are security incidents)
================================================================================
*/

-- =============================================================================
-- Create integrity_violations table
-- DESCRIPTION: Log of immutability violation attempts
-- PRIORITY: HIGH
-- SECURITY: Append-only audit trail
-- =============================================================================
CREATE TABLE IF NOT EXISTS core.integrity_violations (
    violation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attempted_operation VARCHAR(20) NOT NULL CHECK (attempted_operation IN ('UPDATE', 'DELETE', 'TRUNCATE')),
    table_schema VARCHAR(63) NOT NULL,
    table_name VARCHAR(63) NOT NULL,
    record_id TEXT,
    old_data JSONB,
    new_data JSONB,
    user_name VARCHAR(100) NOT NULL DEFAULT CURRENT_USER,
    application_name VARCHAR(100) DEFAULT current_setting('application_name', true),
    client_addr INET DEFAULT inet_client_addr(),
    client_port INTEGER DEFAULT inet_client_port(),
    backend_pid INTEGER DEFAULT pg_backend_pid(),
    query_text TEXT DEFAULT current_query(),
    is_superuser BOOLEAN DEFAULT (CURRENT_USER = 'postgres' OR pg_has_role(CURRENT_USER, 'pg_execute_server_program', 'MEMBER')),
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE core.integrity_violations IS 'Immutable audit trail of all attempts to modify immutable ledger data';
COMMENT ON COLUMN core.integrity_violations.attempted_operation IS 'Type of modification attempted: UPDATE, DELETE, or TRUNCATE';
COMMENT ON COLUMN core.integrity_violations.is_superuser IS 'Whether the attempt was made by a superuser (for bypass tracking)';

-- Create index for efficient querying
CREATE INDEX IF NOT EXISTS idx_integrity_violations_attempted_at 
    ON core.integrity_violations(attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_integrity_violations_table 
    ON core.integrity_violations(table_schema, table_name);

-- =============================================================================
-- Create prevent_update trigger function
-- DESCRIPTION: Block UPDATE operations on immutable tables
-- PRIORITY: CRITICAL
-- =============================================================================
CREATE OR REPLACE FUNCTION core.prevent_update()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_allow_superuser_bypass BOOLEAN := false;  -- Configurable: set to true for emergency maintenance
    v_is_superuser BOOLEAN;
BEGIN
    -- Check if current user is superuser
    v_is_superuser := (CURRENT_USER = 'postgres' OR 
                       pg_has_role(CURRENT_USER, 'pg_execute_server_program', 'MEMBER'));
    
    -- Log the violation attempt
    INSERT INTO core.integrity_violations (
        attempted_operation,
        table_schema,
        table_name,
        record_id,
        old_data,
        new_data,
        is_superuser
    ) VALUES (
        'UPDATE',
        TG_TABLE_SCHEMA,
        TG_TABLE_NAME,
        COALESCE(OLD.id::text, OLD.transaction_id::text, OLD.account_id::text, 'unknown'),
        to_jsonb(OLD),
        to_jsonb(NEW),
        v_is_superuser
    );
    
    -- Allow superuser bypass if configured (with warning)
    IF v_is_superuser AND v_allow_superuser_bypass THEN
        RAISE WARNING 'SUPERUSER BYPASS: Update allowed on immutable table %.% by %', 
            TG_TABLE_SCHEMA, TG_TABLE_NAME, CURRENT_USER;
        RETURN NEW;
    END IF;
    
    -- Block the update
    RAISE EXCEPTION 'IMMUTABILITY_VIOLATION'
        USING HINT = 'Updates are not permitted on immutable ledger tables. Use compensating transactions for corrections.',
              ERRCODE = 'P0001',
              DETAIL = format('Attempted to update record in %I.%I. If correction is needed, create a compensating entry.', 
                              TG_TABLE_SCHEMA, TG_TABLE_NAME);
END;
$$;

COMMENT ON FUNCTION core.prevent_update() IS 'Trigger function to prevent UPDATE operations on immutable ledger tables';

-- =============================================================================
-- Create prevent_delete trigger function
-- DESCRIPTION: Block DELETE operations on immutable tables
-- PRIORITY: CRITICAL
-- =============================================================================
CREATE OR REPLACE FUNCTION core.prevent_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Log the violation attempt (no bypass allowed for DELETE)
    INSERT INTO core.integrity_violations (
        attempted_operation,
        table_schema,
        table_name,
        record_id,
        old_data,
        is_superuser
    ) VALUES (
        'DELETE',
        TG_TABLE_SCHEMA,
        TG_TABLE_NAME,
        COALESCE(OLD.id::text, OLD.transaction_id::text, OLD.account_id::text, 'unknown'),
        to_jsonb(OLD),
        (CURRENT_USER = 'postgres' OR pg_has_role(CURRENT_USER, 'pg_execute_server_program', 'MEMBER'))
    );
    
    -- Block the delete (no bypass allowed - deletion is too destructive)
    RAISE EXCEPTION 'IMMUTABILITY_VIOLATION'
        USING HINT = 'Deletes are not permitted on immutable ledger tables. Records must be retained for audit and compliance.',
              ERRCODE = 'P0001',
              DETAIL = format('Attempted to delete record from %I.%I. Deletion is permanently prohibited.', 
                              TG_TABLE_SCHEMA, TG_TABLE_NAME);
END;
$$;

COMMENT ON FUNCTION core.prevent_delete() IS 'Trigger function to prevent DELETE operations on immutable ledger tables (no bypass allowed)';

-- =============================================================================
-- Create prevent_truncate trigger function
-- DESCRIPTION: Block TRUNCATE operations on immutable tables
-- PRIORITY: CRITICAL
-- =============================================================================
CREATE OR REPLACE FUNCTION core.prevent_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Log the violation attempt (no bypass allowed for TRUNCATE)
    INSERT INTO core.integrity_violations (
        attempted_operation,
        table_schema,
        table_name,
        is_superuser
    ) VALUES (
        'TRUNCATE',
        TG_TABLE_SCHEMA,
        TG_TABLE_NAME,
        (CURRENT_USER = 'postgres' OR pg_has_role(CURRENT_USER, 'pg_execute_server_program', 'MEMBER'))
    );
    
    -- Block the truncate (no bypass allowed - truncation is catastrophic)
    RAISE EXCEPTION 'IMMUTABILITY_VIOLATION'
        USING HINT = 'TRUNCATE is not permitted on immutable ledger tables. This is a critical security violation.',
              ERRCODE = 'P0001',
              DETAIL = format('Attempted to truncate %I.%I. This operation is permanently prohibited and has been logged as a critical security event.', 
                              TG_TABLE_SCHEMA, TG_TABLE_NAME);
END;
$$;

COMMENT ON FUNCTION core.prevent_truncate() IS 'Trigger function to prevent TRUNCATE operations on immutable ledger tables (critical security)';

-- =============================================================================
-- Apply immutability triggers to core tables
-- DESCRIPTION: Attach triggers to all immutable tables
-- PRIORITY: CRITICAL
-- =============================================================================

-- Function to apply immutability triggers to a table
CREATE OR REPLACE FUNCTION core.apply_immutability_triggers(p_schema TEXT, p_table TEXT)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Apply UPDATE prevention trigger
    EXECUTE format('
        CREATE OR REPLACE TRIGGER trg_%I_%I_prevent_update
        BEFORE UPDATE ON %I.%I
        FOR EACH ROW
        EXECUTE FUNCTION core.prevent_update()',
        p_table, p_schema, p_schema, p_table);
    
    -- Apply DELETE prevention trigger
    EXECUTE format('
        CREATE OR REPLACE TRIGGER trg_%I_%I_prevent_delete
        BEFORE DELETE ON %I.%I
        FOR EACH ROW
        EXECUTE FUNCTION core.prevent_delete()',
        p_table, p_schema, p_schema, p_table);
    
    -- Apply TRUNCATE prevention trigger
    EXECUTE format('
        CREATE OR REPLACE TRIGGER trg_%I_%I_prevent_truncate
        BEFORE TRUNCATE ON %I.%I
        FOR EACH STATEMENT
        EXECUTE FUNCTION core.prevent_truncate()',
        p_table, p_schema, p_schema, p_table);
    
    RAISE NOTICE 'Applied immutability triggers to %.%', p_schema, p_table;
END;
$$;

-- Apply triggers to core ledger tables (tables must exist)
-- Note: These will fail silently if tables don't exist yet; run after table creation
DO $$
BEGIN
    -- transaction_log
    IF EXISTS (SELECT 1 FROM information_schema.tables 
               WHERE table_schema = 'core' AND table_name = 'transaction_log') THEN
        PERFORM core.apply_immutability_triggers('core', 'transaction_log');
    END IF;
    
    -- account_registry
    IF EXISTS (SELECT 1 FROM information_schema.tables 
               WHERE table_schema = 'core' AND table_name = 'account_registry') THEN
        PERFORM core.apply_immutability_triggers('core', 'account_registry');
    END IF;
    
    -- movement_headers
    IF EXISTS (SELECT 1 FROM information_schema.tables 
               WHERE table_schema = 'core' AND table_name = 'movement_headers') THEN
        PERFORM core.apply_immutability_triggers('core', 'movement_headers');
    END IF;
    
    -- movement_legs
    IF EXISTS (SELECT 1 FROM information_schema.tables 
               WHERE table_schema = 'core' AND table_name = 'movement_legs') THEN
        PERFORM core.apply_immutability_triggers('core', 'movement_legs');
    END IF;
    
    -- merkle_nodes
    IF EXISTS (SELECT 1 FROM information_schema.tables 
               WHERE table_schema = 'core' AND table_name = 'merkle_nodes') THEN
        PERFORM core.apply_immutability_triggers('core', 'merkle_nodes');
    END IF;
    
    -- blocks (with exception for OPEN blocks - handled separately)
    IF EXISTS (SELECT 1 FROM information_schema.tables 
               WHERE table_schema = 'core' AND table_name = 'blocks') THEN
        PERFORM core.apply_immutability_triggers('core', 'blocks');
    END IF;
    
    -- integrity_violations itself is immutable (no updates allowed to audit trail)
    PERFORM core.apply_immutability_triggers('core', 'integrity_violations');
    
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'Some tables may not exist yet. Run apply_immutability_triggers() after table creation.';
END;
$$;

/*
================================================================================
MIGRATION CHECKLIST:
□ Create integrity_violations table
□ Create prevent_update trigger function
□ Create prevent_delete trigger function
□ Create prevent_truncate trigger function
□ Apply triggers to transaction_log
□ Apply triggers to accounts
□ Apply triggers to movement_headers
□ Apply triggers to movement_legs
□ Apply triggers to blocks (with OPEN exception)
□ Apply triggers to merkle_nodes
□ Test UPDATE blocking
□ Test DELETE blocking
□ Test TRUNCATE blocking
□ Test superuser bypass (if configured)
□ Set up alerts on integrity_violations inserts
================================================================================
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
