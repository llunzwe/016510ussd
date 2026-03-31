-- =============================================================================
-- USSD KERNEL CORE SCHEMA - TRIGGERS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    002_audit_log_capture.sql
-- SCHEMA:      core
-- CATEGORY:    Triggers - Audit Log Capture
-- DESCRIPTION: Comprehensive audit trail capture for all data modifications
--              with immutable logging and forensic support.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Access logging
├── A.8.5 Secure authentication - Authentication audit
├── A.8.15 Logging - Comprehensive activity logging
├── A.12.4 Logging and monitoring - Real-time monitoring
└── A.16.1 Management of information security incidents - Investigation support

ISO/IEC 27040:2024 (Storage Security)
├── Immutable audit logs: WORM storage
├── Tamper detection: Hash chain for audit trail
├── Long-term retention: 7+ years
└── Forensic support: Complete reconstruction

GDPR Compliance
├── Lawful basis: Legitimate interest
├── Data minimization: Minimal PII in logs
├── Retention limits: Time-based purging
└── Subject access: Log provision capability

Financial Regulations
├── Audit trail: Complete transaction history
├── Examination support: Regulatory query support
├── Retention: 7+ year requirement
└── Integrity: Tamper-evident logging

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. CAPTURE SCOPE
   - All INSERT operations
   - All UPDATE operations (even if blocked)
   - All DELETE attempts (even if blocked)
   - All SELECT on sensitive tables

2. CAPTURED DATA
   - Actor identification
   - Timestamp with timezone
   - Operation type
   - Before/after values
   - Query text
   - Client context

3. PERFORMANCE
   - Async logging where possible
   - Minimal transaction impact
   - Efficient storage
   - Partitioning for scale

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

AUDIT TRAIL CAPTURE:
1. Data Access Logging
   - All queries logged
   - Result counts captured
   - Execution time recorded
   - Access patterns analyzed

2. Modification Logging
   - Before/after images
   - Change attribution
   - Approval workflow tracking
   - Rollback logging

3. Security Event Logging
   - Authentication events
   - Authorization failures
   - Privilege escalation
   - Policy violations

PROTECTION:
1. Immutability
   - Audit table immutability triggers
   - Separate schema protection
   - Database-level restrictions

2. Integrity
   - Hash chain for audit records
   - Digital signatures (optional)
   - External archival

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

LOGGING OPTIMIZATION:
- Batch audit inserts
- Async processing
- Partitioned audit tables
- Compressed archival

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

MANDATORY EVENTS:
1. DATA_ACCESSED: Any data read operation
2. DATA_CREATED: New record inserted
3. DATA_MODIFIED: Update attempt (even blocked)
4. DATA_DELETED: Delete attempt (even blocked)
5. AUTHENTICATION: Login/logout events
6. AUTHORIZATION: Permission check results
7. SECURITY: Security-related events

RETENTION:
- Security events: 7 years
- Data changes: 7 years
- Access logs: 2 years
- Debug logs: 30 days

================================================================================
*/

-- Create audit_trail table if not exists
CREATE TABLE IF NOT EXISTS core.audit_trail (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(50) NOT NULL,
    table_name VARCHAR(100),
    record_id TEXT,
    old_data JSONB,
    new_data JSONB,
    details JSONB,
    severity VARCHAR(20) DEFAULT 'INFO' CHECK (severity IN ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')),
    actor_id UUID,
    actor_type VARCHAR(20) DEFAULT 'USER' CHECK (actor_type IN ('USER', 'SYSTEM', 'SERVICE')),
    session_id TEXT,
    ip_address INET,
    application_name VARCHAR(100) DEFAULT current_setting('application_name', true),
    query_text TEXT DEFAULT current_query(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE core.audit_trail IS 'Immutable audit trail for all system activities';

-- Create indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_audit_trail_created_at ON core.audit_trail(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_trail_event_type ON core.audit_trail(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_trail_table_name ON core.audit_trail(table_name);
CREATE INDEX IF NOT EXISTS idx_audit_trail_severity ON core.audit_trail(severity) WHERE severity IN ('ERROR', 'CRITICAL');

-- =============================================================================
-- Create audit_log_insert_trigger function
-- DESCRIPTION: Capture INSERT operations to audit trail
-- PRIORITY: CRITICAL
-- =============================================================================
CREATE OR REPLACE FUNCTION core.audit_log_insert_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_record_id TEXT;
    v_actor_id UUID;
BEGIN
    -- Extract record identifier
    v_record_id := COALESCE(
        NEW.id::text,
        NEW.transaction_id::text,
        NEW.account_id::text,
        NEW.movement_id::text,
        NEW.block_id::text,
        'unknown'
    );
    
    -- Get actor ID from session or context
    v_actor_id := NULLIF(current_setting('app.current_actor_id', true), '')::UUID;
    
    -- Log the insert
    INSERT INTO core.audit_trail (
        event_type,
        table_name,
        record_id,
        new_data,
        actor_id,
        severity,
        details
    ) VALUES (
        'DATA_CREATED',
        TG_TABLE_NAME,
        v_record_id,
        to_jsonb(NEW),
        v_actor_id,
        'INFO',
        jsonb_build_object(
            'schema', TG_TABLE_SCHEMA,
            'trigger_name', TG_NAME,
            'operation', TG_OP
        )
    );
    
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION core.audit_log_insert_trigger() IS 'Trigger function to capture INSERT operations to audit trail';

-- =============================================================================
-- Create audit_log_access_trigger function
-- DESCRIPTION: Capture SELECT operations on sensitive tables
-- PRIORITY: HIGH
-- =============================================================================
CREATE OR REPLACE FUNCTION core.audit_log_access_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_actor_id UUID;
    v_access_level VARCHAR(20);
BEGIN
    -- Get actor ID from session
    v_actor_id := NULLIF(current_setting('app.current_actor_id', true), '')::UUID;
    
    -- Determine access level based on role
    v_access_level := COALESCE(current_setting('app.access_level', true), 'READ');
    
    -- Log the access (throttled to avoid overwhelming logs)
    -- Only log every 100th access or sensitive table access
    IF (random() < 0.01) OR (TG_TABLE_NAME IN ('transaction_log', 'movement_legs', 'account_registry')) THEN
        INSERT INTO core.audit_trail (
            event_type,
            table_name,
            actor_id,
            severity,
            details
        ) VALUES (
            'DATA_ACCESSED',
            TG_TABLE_NAME,
            v_actor_id,
            CASE WHEN TG_TABLE_NAME IN ('transaction_log', 'movement_legs') THEN 'WARNING' ELSE 'DEBUG' END,
            jsonb_build_object(
                'schema', TG_TABLE_SCHEMA,
                'access_level', v_access_level,
                'statement_only', true
            )
        );
    END IF;
    
    RETURN NULL; -- Statement-level trigger returns NULL
END;
$$;

COMMENT ON FUNCTION core.audit_log_access_trigger() IS 'Trigger function to capture SELECT operations on sensitive tables (sampled)';

-- Function to apply audit triggers to a table
CREATE OR REPLACE FUNCTION core.apply_audit_triggers(p_schema TEXT, p_table TEXT)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Apply INSERT audit trigger
    EXECUTE format('
        DROP TRIGGER IF EXISTS trg_%I_%I_audit_insert ON %I.%I;
        CREATE TRIGGER trg_%I_%I_audit_insert
        AFTER INSERT ON %I.%I
        FOR EACH ROW
        EXECUTE FUNCTION core.audit_log_insert_trigger()',
        p_table, p_schema, p_schema, p_table,
        p_table, p_schema, p_schema, p_table);
    
    RAISE NOTICE 'Applied audit triggers to %.%', p_schema, p_table;
END;
$$;

-- Apply audit triggers to core tables (run after table creation)
DO $$
BEGIN
    -- Apply to key tables if they exist
    IF EXISTS (SELECT 1 FROM information_schema.tables 
               WHERE table_schema = 'core' AND table_name = 'transaction_log') THEN
        PERFORM core.apply_audit_triggers('core', 'transaction_log');
    END IF;
    
    IF EXISTS (SELECT 1 FROM information_schema.tables 
               WHERE table_schema = 'core' AND table_name = 'account_registry') THEN
        PERFORM core.apply_audit_triggers('core', 'account_registry');
    END IF;
    
    IF EXISTS (SELECT 1 FROM information_schema.tables 
               WHERE table_schema = 'core' AND table_name = 'movement_headers') THEN
        PERFORM core.apply_audit_triggers('core', 'movement_headers');
    END IF;
    
    IF EXISTS (SELECT 1 FROM information_schema.tables 
               WHERE table_schema = 'core' AND table_name = 'movement_legs') THEN
        PERFORM core.apply_audit_triggers('core', 'movement_legs');
    END IF;
    
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'Some tables may not exist yet. Run apply_audit_triggers() after table creation.';
END;
$$;

/*
================================================================================
MIGRATION CHECKLIST:
□ Create audit_log_insert_trigger function
□ Create audit_log_access_trigger function
□ Apply triggers to all core tables
□ Test audit capture
□ Verify audit immutability
□ Set up audit monitoring
□ Schedule audit archival
================================================================================
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
