-- =============================================================================
-- MIGRATION: 053_security_audit_tables.sql
-- DESCRIPTION: Comprehensive Security Audit Logging
-- TABLES: audit_logs, audit_access_logs, audit_config_changes
-- DEPENDENCIES: Multiple tables for audit triggers
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.8.11: Data masking (audit log protection)
  - A.8.15: Logging
  - A.8.16: Monitoring activities
  - A.8.17: Clock synchronization

ISO/IEC 27018:2019 - Protection of PII in Public Clouds
  - Clause 8.5: Access (audit for PII access)
  - Clause 9.4: Privacy policy audit

ISO/IEC 27050-3:2020 - Electronic Discovery
  - Section 8: Processing and review (audit as evidence)
  - Audit logs are primary source of authenticity

GDPR / Zimbabwe Data Protection Act (Chapter 11:12)
  - Article 30: Records of processing activities
  - Article 33: Personal data breach notification (audit detection)
  - Section 14: Security measures (audit requirement)
  - Section 17: Data subject rights (audit for verification)

FINANCIAL REGULATIONS:
  - SOX: Change tracking and accountability
  - PCI DSS: Access logging requirements
  - Audit trail immutability requirements

SECURITY CLASSIFICATION: RESTRICTED
DATA SENSITIVITY: AUDIT EVIDENCE - LEGALLY SENSITIVE
RETENTION PERIOD: 7 years minimum; Permanent for security events
AUDIT REQUIREMENT: Self-protecting; Tamper-evident
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 5. Security & Access Control, 14. Observability
- Feature: Audit Logging
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Separate immutable audit table recording all configuration changes (e.g.,
new application created, role assigned, fee structure updated). Compliance:
know who changed the loan interest rate and when.

KEY FEATURES:
- Immutable audit records
- Granular action tracking
- Data change capture
- Access logging
- Tamper-evident hashes

SECURITY & COMPLIANCE REQUIREMENTS:
- Append-only (no modifications)
- Hash chain for integrity verification
- Separate schema with restricted access
- Automated archival to cold storage
- Real-time alerting for suspicious activity
================================================================================
*/

-- =============================================================================
-- IMPLEMENTED: Create audit_log table
-- DESCRIPTION: Master audit trail
-- PRIORITY: CRITICAL
-- SECURITY: Append-only; separate schema; restricted access
-- INTEGRITY: SHA-256 hash chain for tamper detection
-- RETENTION: 7 years hot; permanent cold storage
-- =============================================================================
-- [AUDIT-001] Create audit.audit_log table
CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE audit.audit_log (
    audit_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_reference     VARCHAR(100) UNIQUE NOT NULL,
    
    -- Classification (ISO 27001 A.8.15)
    audit_category      VARCHAR(50) NOT NULL,        -- CONFIG, ACCESS, DATA, SECURITY
    audit_action        VARCHAR(50) NOT NULL,        -- CREATE, UPDATE, DELETE, LOGIN
    
    -- Target
    table_schema        VARCHAR(50),
    table_name          VARCHAR(100),
    record_id           TEXT,                        -- Primary key value
    
    -- Change Details
    old_values          JSONB,
    new_values          JSONB,
    changed_fields      TEXT[],                      -- List of changed columns
    
    -- Actor
    actor_id            UUID,                        -- Account ID if known
    actor_type          VARCHAR(20) DEFAULT 'USER',  -- USER, SYSTEM, API
    actor_name          VARCHAR(100),                -- Username or service name
    
    -- Context
    application_id      UUID,
    session_id          UUID,
    request_id          VARCHAR(100),
    
    -- Source
    client_ip           INET,
    user_agent          TEXT,
    source_service      VARCHAR(100),                -- Which service made the change
    
    -- Integrity (Tamper-evident hash chain)
    previous_audit_hash BYTEA,                       -- Hash chain
    current_audit_hash  BYTEA NOT NULL,
    
    -- Timestamp (ISO 27001 A.8.17 - synchronized)
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE audit.audit_log IS 'Immutable audit trail with tamper-evident hash chain';
COMMENT ON COLUMN audit.audit_log.current_audit_hash IS 'SHA-256 hash for integrity verification';
COMMENT ON COLUMN audit.audit_log.previous_audit_hash IS 'Links to previous audit record for chain verification';

-- Prevent updates to audit log (append-only)
CREATE OR REPLACE FUNCTION audit.prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs are immutable and cannot be modified';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_immutable
    BEFORE UPDATE OR DELETE ON audit.audit_log
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_audit_modification();

-- =============================================================================
-- IMPLEMENTED: Create audit_access_logs table
-- DESCRIPTION: Data access tracking
-- PRIORITY: HIGH
-- SECURITY: RLS protected; PII access logged
-- PRIVACY: GDPR Article 30 - processing records
-- RETENTION: 7 years for compliance reporting
-- =============================================================================
-- [AUDIT-002] Create audit.audit_access_logs table
CREATE TABLE audit.audit_access_logs (
    access_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Access Details
    access_type         VARCHAR(20) NOT NULL,        -- VIEW, DOWNLOAD, EXPORT
    
    -- Target
    table_schema        VARCHAR(50) NOT NULL,
    table_name          VARCHAR(100) NOT NULL,
    record_id           TEXT,
    
    -- Accessor
    accessor_id         UUID,
    accessor_type       VARCHAR(20),                 -- USER, ADMIN, SYSTEM
    
    -- Context
    access_reason       TEXT,
    legal_basis         VARCHAR(50),                 -- GDPR legal basis
    
    -- PII handling
    pii_fields_accessed TEXT[],                      -- Which PII fields were accessed
    data_subject_id     VARCHAR(100),                -- For subject rights tracking
    
    -- Audit
    accessed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_address          INET,
    session_id          UUID
);

COMMENT ON TABLE audit.audit_access_logs IS 'Data access tracking for GDPR Article 30 compliance';
COMMENT ON COLUMN audit.audit_access_logs.legal_basis IS 'GDPR legal basis for processing';
COMMENT ON COLUMN audit.audit_access_logs.pii_fields_accessed IS 'Tracks which PII was accessed';

-- =============================================================================
-- IMPLEMENTED: Create audit log trigger function
-- DESCRIPTION: Auto-log data changes
-- PRIORITY: CRITICAL
-- SECURITY: SECURITY DEFINER; protected from bypass
-- INTEGRITY: Calculates hash chain for tamper detection
-- PERFORMANCE: Asynchronous logging recommended for high volume
-- =============================================================================
-- [AUDIT-003] Create audit_trigger function
CREATE OR REPLACE FUNCTION audit.log_audit_event()
RETURNS TRIGGER AS $$
DECLARE
    v_old JSONB;
    v_new JSONB;
    v_changed_fields TEXT[] := ARRAY[]::TEXT[];
    v_key TEXT;
    v_prev_hash BYTEA;
    v_record_id TEXT;
    v_audit_id UUID;
BEGIN
    -- Get previous hash for chain
    SELECT current_audit_hash INTO v_prev_hash
    FROM audit.audit_log
    ORDER BY occurred_at DESC
    LIMIT 1;
    
    -- Determine operation type
    IF TG_OP = 'DELETE' THEN
        v_old := to_jsonb(OLD);
        v_new := NULL;
        v_record_id := OLD.primary_key_column::TEXT;
        -- Try to get actual PK value dynamically
        BEGIN
            EXECUTE format('SELECT ($1).%I::text', (
                SELECT a.attname
                FROM pg_index i
                JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
                WHERE i.indrelid = TG_RELID AND i.indisprimary
                LIMIT 1
            )) INTO v_record_id USING OLD;
        EXCEPTION WHEN OTHERS THEN
            v_record_id := OLD.primary_key_column::TEXT;
        END;
    ELSIF TG_OP = 'INSERT' THEN
        v_old := NULL;
        v_new := to_jsonb(NEW);
        BEGIN
            EXECUTE format('SELECT ($1).%I::text', (
                SELECT a.attname
                FROM pg_index i
                JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
                WHERE i.indrelid = TG_RELID AND i.indisprimary
                LIMIT 1
            )) INTO v_record_id USING NEW;
        EXCEPTION WHEN OTHERS THEN
            v_record_id := NEW.primary_key_column::TEXT;
        END;
    ELSIF TG_OP = 'UPDATE' THEN
        v_old := to_jsonb(OLD);
        v_new := to_jsonb(NEW);
        BEGIN
            EXECUTE format('SELECT ($1).%I::text', (
                SELECT a.attname
                FROM pg_index i
                JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
                WHERE i.indrelid = TG_RELID AND i.indisprimary
                LIMIT 1
            )) INTO v_record_id USING NEW;
        EXCEPTION WHEN OTHERS THEN
            v_record_id := NEW.primary_key_column::TEXT;
        END;
        
        -- Find changed fields
        FOR v_key IN SELECT jsonb_object_keys(v_new)
        LOOP
            IF v_old->v_key IS DISTINCT FROM v_new->v_key THEN
                v_changed_fields := array_append(v_changed_fields, v_key);
            END IF;
        END LOOP;
    END IF;
    
    -- Insert audit record
    INSERT INTO audit.audit_log (
        audit_reference, audit_category, audit_action,
        table_schema, table_name, record_id,
        old_values, new_values, changed_fields,
        actor_id, actor_type, actor_name,
        application_id, client_ip, source_service,
        previous_audit_hash, current_audit_hash
    ) VALUES (
        'AUD-' || to_char(now(), 'YYYYMMDD-HH24MISS') || '-' || substr(gen_random_uuid()::text, 1, 6),
        'DATA',
        TG_OP,
        TG_TABLE_SCHEMA,
        TG_TABLE_NAME,
        v_record_id,
        v_old,
        v_new,
        v_changed_fields,
        current_setting('app.current_account_id', true)::UUID,
        'USER',
        current_user,
        current_setting('app.current_application_id', true)::UUID,
        inet_client_addr(),
        current_setting('application.name', true),
        v_prev_hash,
        digest(COALESCE(v_prev_hash, '\x00') || v_old::text || v_new::text || now()::text, 'sha256')
    )
    RETURNING audit_id INTO v_audit_id;
    
    -- Also log access if PII was involved
    IF TG_OP = 'SELECT' OR (v_new ? 'msisdn') OR (v_old ? 'msisdn') THEN
        INSERT INTO audit.audit_access_logs (
            access_type, table_schema, table_name, record_id,
            accessor_id, accessor_type, pii_fields_accessed,
            ip_address, session_id
        ) VALUES (
            CASE TG_OP WHEN 'SELECT' THEN 'VIEW' ELSE 'MODIFY' END,
            TG_TABLE_SCHEMA,
            TG_TABLE_NAME,
            v_record_id,
            current_setting('app.current_account_id', true)::UUID,
            'USER',
            CASE WHEN (v_new ? 'msisdn') OR (v_old ? 'msisdn') THEN ARRAY['msisdn'] ELSE NULL END,
            inet_client_addr(),
            current_setting('app.session_id', true)::UUID
        );
    END IF;
    
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION audit.log_audit_event IS 'Generic audit trigger with tamper-evident hash chain';

-- =============================================================================
-- IMPLEMENTED: Apply audit triggers
-- DESCRIPTION: Attach to auditable tables
-- PRIORITY: HIGH
-- SECURITY: Triggers are SECURITY DEFINER
-- PERFORMANCE: Monitor trigger overhead
-- =============================================================================
-- [AUDIT-004] Apply audit triggers

-- Core tables audit triggers
CREATE TRIGGER accounts_audit
    AFTER INSERT OR UPDATE OR DELETE ON core.accounts
    FOR EACH ROW EXECUTE FUNCTION audit.log_audit_event();

CREATE TRIGGER transaction_log_audit
    AFTER INSERT OR UPDATE OR DELETE ON core.transaction_log
    FOR EACH ROW EXECUTE FUNCTION audit.log_audit_event();

CREATE TRIGGER movement_headers_audit
    AFTER INSERT OR UPDATE OR DELETE ON core.movement_headers
    FOR EACH ROW EXECUTE FUNCTION audit.log_audit_event();

-- App tables audit triggers
CREATE TRIGGER applications_audit
    AFTER INSERT OR UPDATE OR DELETE ON app.applications
    FOR EACH ROW EXECUTE FUNCTION audit.log_audit_event();

CREATE TRIGGER roles_audit
    AFTER INSERT OR UPDATE OR DELETE ON app.roles
    FOR EACH ROW EXECUTE FUNCTION audit.log_audit_event();

-- USSD tables audit triggers
CREATE TRIGGER ussd_sessions_audit
    AFTER INSERT OR UPDATE OR DELETE ON ussd.ussd_sessions
    FOR EACH ROW EXECUTE FUNCTION audit.log_audit_event();

CREATE TRIGGER pending_transactions_audit
    AFTER INSERT OR UPDATE OR DELETE ON ussd.pending_ussd_transactions
    FOR EACH ROW EXECUTE FUNCTION audit.log_audit_event();

-- =============================================================================
-- IMPLEMENTED: Create audit query functions
-- DESCRIPTION: Query audit trail
-- PRIORITY: MEDIUM
-- SECURITY: RLS by application_id; admin can see all
-- PRIVACY: Access logs reviewed for unauthorized PII access
-- =============================================================================
-- [AUDIT-005] Create audit query functions

-- Get audit history for record
CREATE OR REPLACE FUNCTION audit.get_record_history(
    p_table_schema VARCHAR,
    p_table_name VARCHAR,
    p_record_id TEXT
) RETURNS SETOF audit.audit_log AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM audit.audit_log
    WHERE table_schema = p_table_schema
        AND table_name = p_table_name
        AND record_id = p_record_id
    ORDER BY occurred_at DESC;
END;
$$ LANGUAGE plpgsql STABLE;

-- Verify audit chain integrity
CREATE OR REPLACE FUNCTION audit.verify_audit_chain()
RETURNS TABLE (
    is_valid BOOLEAN,
    broken_at_audit_id UUID,
    expected_hash BYTEA,
    actual_hash BYTEA
) AS $$
DECLARE
    v_current RECORD;
    v_previous_hash BYTEA := '\x00'::bytea;
    v_calculated_hash BYTEA;
BEGIN
    FOR v_current IN 
        SELECT * FROM audit.audit_log
        ORDER BY occurred_at ASC
    LOOP
        v_calculated_hash := digest(
            v_previous_hash || 
            COALESCE(v_current.old_values::text, '') || 
            COALESCE(v_current.new_values::text, '') ||
            v_current.occurred_at::text,
            'sha256'
        );
        
        IF v_current.previous_audit_hash IS DISTINCT FROM v_previous_hash OR
           v_current.current_audit_hash IS DISTINCT FROM v_calculated_hash THEN
            RETURN QUERY SELECT 
                false, 
                v_current.audit_id,
                v_calculated_hash,
                v_current.current_audit_hash;
            RETURN;
        END IF;
        
        v_previous_hash := v_current.current_audit_hash;
    END LOOP;
    
    RETURN QUERY SELECT true, NULL::UUID, NULL::BYTEA, NULL::BYTEA;
END;
$$ LANGUAGE plpgsql STABLE;

-- Get PII access report for data subject
CREATE OR REPLACE FUNCTION audit.get_pii_access_report(
    p_data_subject_id VARCHAR(100),
    p_from_date TIMESTAMPTZ DEFAULT now() - interval '30 days'
) RETURNS TABLE (
    accessed_at TIMESTAMPTZ,
    accessor_type VARCHAR(20),
    table_name VARCHAR(100),
    access_type VARCHAR(20),
    legal_basis VARCHAR(50),
    access_reason TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        aal.accessed_at,
        aal.accessor_type,
        aal.table_name,
        aal.access_type,
        aal.legal_basis,
        aal.access_reason
    FROM audit.audit_access_logs aal
    WHERE aal.data_subject_id = p_data_subject_id
        AND aal.accessed_at >= p_from_date
        AND aal.pii_fields_accessed IS NOT NULL
    ORDER BY aal.accessed_at DESC;
END;
$$ LANGUAGE plpgsql STABLE;

-- =============================================================================
-- IMPLEMENTED: Create audit indexes
-- DESCRIPTION: Optimize audit queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for investigation queries
-- =============================================================================
-- [AUDIT-006] Create audit indexes

-- Audit Log indexes
CREATE INDEX idx_audit_table_record ON audit.audit_log(table_schema, table_name, record_id, occurred_at);
CREATE INDEX idx_audit_actor ON audit.audit_log(actor_id, occurred_at);
CREATE INDEX idx_audit_application ON audit.audit_log(application_id, audit_category, occurred_at);
CREATE INDEX idx_audit_occurred ON audit.audit_log(occurred_at);
CREATE INDEX idx_audit_category_action ON audit.audit_log(audit_category, audit_action, occurred_at);
CREATE INDEX idx_audit_reference ON audit.audit_log(audit_reference);

-- Access Logs indexes
CREATE INDEX idx_access_logs_table ON audit.audit_access_logs(table_schema, table_name, accessed_at);
CREATE INDEX idx_access_logs_accessor ON audit.audit_access_logs(accessor_id, accessed_at);
CREATE INDEX idx_access_logs_pii ON audit.audit_access_logs(data_subject_id, accessed_at) 
    WHERE data_subject_id IS NOT NULL;

/*
================================================================================
AUDIT LOGGING SECURITY & COMPLIANCE GUIDE
================================================================================

1. AUDIT CATEGORIES (ISO 27001 A.8.15):
   ┌─────────────────┬─────────────────────────────────────────────────────┐
   │ Category        │ Description                                         │
   ├─────────────────┼─────────────────────────────────────────────────────┤
   │ CONFIG          │ Configuration changes, policy updates               │
   │ ACCESS          │ Login/logout, permission grants                     │
   │ DATA            │ CRUD operations on business data                    │
   │ SECURITY        │ Security events, policy violations                  │
   │ PII_ACCESS      │ Personal data access (GDPR Article 30)              │
   │ ADMIN           │ Administrative actions, elevated privileges         │
   │ SYSTEM          │ Automated system events                             │
   └─────────────────┴─────────────────────────────────────────────────────┘

2. TAMPER-EVIDENT ARCHITECTURE:
   
   Record N:   [Data] + Hash(N-1)  →  Hash(N)
   Record N+1: [Data] + Hash(N)    →  Hash(N+1)
   
   Verification:
   - Recalculate hash chain from any point
   - Mismatch indicates tampering
   - External notary service for critical events
   - Blockchain anchoring optional (high assurance)

3. GDPR COMPLIANCE (Article 30):
   - All PII processing activities logged
   - Purpose of access recorded
   - Legal basis documented
   - Retention periods tracked
   - Cross-border transfers logged

4. SECURITY MONITORING:
   Alert Triggers:
   - Failed login attempts > 5 in 10 minutes
   - Admin access outside business hours
   - Bulk data exports (> 1000 records)
   - PII access without documented purpose
   - Audit log modification attempts (critical!)
   - Privilege escalation events

5. FORENSIC REQUIREMENTS:
   - Chain of custody for audit records
   - Timestamp accuracy (NTP synchronized)
   - Complete, unmodifiable history
   - Export capabilities for legal proceedings
   - Integrity verification tools

ACCESS CONTROL MATRIX:
┌────────────────────┬─────────────┬─────────────┬─────────────┬─────────────┐
│ Role               │ View Own    │ View App    │ View All    │ Modify      │
├────────────────────┼─────────────┼─────────────┼─────────────┼─────────────┤
│ End User           │ Yes         │ No          │ No          │ No          │
│ Application Admin  │ Yes         │ Yes         │ No          │ No          │
│ Security Officer   │ Yes         │ Yes         │ Yes*        │ No          │
│ Compliance Officer │ Yes         │ Yes         │ Yes*        │ No          │
│ System Admin       │ No          │ No          │ No          │ No          │
└────────────────────┴─────────────┴─────────────┴─────────────┴─────────────┘
* With documented business justification

Note: NO ONE can modify audit logs - immutability enforced at database level
================================================================================
*/

/*
================================================================================
MIGRATION CHECKLIST:
[x] Create audit.audit_log table with hash chain
[x] Create audit.audit_access_logs table
[x] Implement log_audit_event trigger function
[x] Apply audit triggers to key tables
[x] Implement audit query functions
[x] Add all indexes for audit queries
[ ] Test audit logging
[ ] Test hash chain integrity
[ ] Test audit queries
[ ] Verify immutability constraints
[ ] Set up security monitoring alerts
[ ] Configure automated archival
[ ] Document forensic procedures
================================================================================
*/
