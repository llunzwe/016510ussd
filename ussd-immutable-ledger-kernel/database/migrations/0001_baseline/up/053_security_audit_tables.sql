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
-- TODO: Create audit_log table
-- DESCRIPTION: Master audit trail
-- PRIORITY: CRITICAL
-- SECURITY: Append-only; separate schema; restricted access
-- INTEGRITY: SHA-256 hash chain for tamper detection
-- RETENTION: 7 years hot; permanent cold storage
-- =============================================================================
-- TODO: [AUDIT-001] Create audit.audit_log table
-- INSTRUCTIONS:
--   - Immutable audit records
--   - All schema changes logged
--   - Tamper-evident
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE audit.audit_log (
--       audit_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       audit_reference     VARCHAR(100) UNIQUE NOT NULL,
--       
--       -- Classification (ISO 27001 A.8.15)
--       audit_category      VARCHAR(50) NOT NULL,        -- CONFIG, ACCESS, DATA, SECURITY
--       audit_action        VARCHAR(50) NOT NULL,        -- CREATE, UPDATE, DELETE, LOGIN
--       
--       -- Target
--       table_schema        VARCHAR(50),
--       table_name          VARCHAR(100),
--       record_id           TEXT,                        -- Primary key value
--       
--       -- Change Details
--       old_values          JSONB,
--       new_values          JSONB,
--       changed_fields      TEXT[],                      -- List of changed columns
--       
--       -- Actor
--       actor_id            UUID,                        -- Account ID if known
--       actor_type          VARCHAR(20) DEFAULT 'USER',  -- USER, SYSTEM, API
--       actor_name          VARCHAR(100),                -- Username or service name
--       
--       -- Context
--       application_id      UUID,
--       session_id          UUID,
--       request_id          VARCHAR(100),
--       
--       -- Source
--       client_ip           INET,
--       user_agent          TEXT,
--       source_service      VARCHAR(100),                -- Which service made the change
--       
--       -- Integrity (Tamper-evident hash chain)
--       previous_audit_hash BYTEA,                       -- Hash chain
--       current_audit_hash  BYTEA NOT NULL,
--       
--       -- Timestamp (ISO 27001 A.8.17 - synchronized)
--       occurred_at         TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create audit_access_logs table
-- DESCRIPTION: Data access tracking
-- PRIORITY: HIGH
-- SECURITY: RLS protected; PII access logged
-- PRIVACY: GDPR Article 30 - processing records
-- RETENTION: 7 years for compliance reporting
-- =============================================================================
-- TODO: [AUDIT-002] Create audit.audit_access_logs table
-- INSTRUCTIONS:
--   - Record of data access
--   - For GDPR compliance
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE audit.audit_access_logs (
--       access_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Access Details
--       access_type         VARCHAR(20) NOT NULL,        -- VIEW, DOWNLOAD, EXPORT
--       
--       -- Target
--       table_schema        VARCHAR(50) NOT NULL,
--       table_name          VARCHAR(100) NOT NULL,
--       record_id           TEXT,
--       
--       -- Accessor
--       accessor_id         UUID,
--       accessor_type       VARCHAR(20),                 -- USER, ADMIN, SYSTEM
--       
--       -- Context
--       access_reason       TEXT,
--       legal_basis         VARCHAR(50),                 -- GDPR legal basis
--       
--       -- Audit
--       accessed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
--       ip_address          INET
--   );

-- =============================================================================
-- TODO: Create audit log trigger function
-- DESCRIPTION: Auto-log data changes
-- PRIORITY: CRITICAL
-- SECURITY: SECURITY DEFINER; protected from bypass
-- INTEGRITY: Calculates hash chain for tamper detection
-- PERFORMANCE: Asynchronous logging recommended for high volume
-- =============================================================================
-- TODO: [AUDIT-003] Create audit_trigger function
-- INSTRUCTIONS:
--   - Generic trigger for audit logging
--   - Capture old and new values
--   - Calculate hash chain
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION audit.log_audit_event()
--   RETURNS TRIGGER AS $$
--   DECLARE
--       v_old JSONB;
--       v_new JSONB;
--       v_changed_fields TEXT[] := ARRAY[]::TEXT[];
--       v_key TEXT;
--       v_prev_hash BYTEA;
--   BEGIN
--       -- Get previous hash for chain
--       SELECT current_audit_hash INTO v_prev_hash
--       FROM audit.audit_log
--       ORDER BY occurred_at DESC
--       LIMIT 1;
--       
--       IF TG_OP = 'DELETE' THEN
--           v_old := to_jsonb(OLD);
--           v_new := NULL;
--       ELSIF TG_OP = 'INSERT' THEN
--           v_old := NULL;
--           v_new := to_jsonb(NEW);
--       ELSIF TG_OP = 'UPDATE' THEN
--           v_old := to_jsonb(OLD);
--           v_new := to_jsonb(NEW);
--           
--           -- Find changed fields
--           FOR v_key IN SELECT jsonb_object_keys(v_new)
--           LOOP
--               IF v_old->v_key IS DISTINCT FROM v_new->v_key THEN
--                   v_changed_fields := array_append(v_changed_fields, v_key);
--               END IF;
--           END LOOP;
--       END IF;
--       
--       -- Insert audit record
--       INSERT INTO audit.audit_log (
--           audit_reference, audit_category, audit_action,
--           table_schema, table_name, record_id,
--           old_values, new_values, changed_fields,
--           actor_id, actor_type, actor_name,
--           application_id, client_ip, source_service,
--           previous_audit_hash, current_audit_hash
--       ) VALUES (
--           'AUD-' || to_char(now(), 'YYYYMMDD-HH24MISS') || '-' || substr(gen_random_uuid()::text, 1, 6),
--           'DATA',
--           TG_OP,
--           TG_TABLE_SCHEMA,
--           TG_TABLE_NAME,
--           OLD.primary_key_column::TEXT,
--           v_old,
--           v_new,
--           v_changed_fields,
--           current_setting('app.current_account_id', true)::UUID,
--           'USER',
--           current_user,
--           current_setting('app.current_application_id', true)::UUID,
--           inet_client_addr(),
--           current_setting('application.name', true),
--           v_prev_hash,
--           digest(COALESCE(v_prev_hash, '\x00') || v_old::text || v_new::text, 'sha256')
--       );
--       
--       RETURN COALESCE(NEW, OLD);
--   END;
--   $$ LANGUAGE plpgsql SECURITY DEFINER;

-- =============================================================================
-- TODO: Apply audit triggers
-- DESCRIPTION: Attach to auditable tables
-- PRIORITY: HIGH
-- SECURITY: Triggers are SECURITY DEFINER
-- PERFORMANCE: Monitor trigger overhead
-- =============================================================================
-- TODO: [AUDIT-004] Apply audit triggers
-- INSTRUCTIONS:
--   CREATE TRIGGER accounts_audit
--       AFTER INSERT OR UPDATE OR DELETE ON core.accounts
--       FOR EACH ROW EXECUTE FUNCTION audit.log_audit_event();
--   
--   -- Apply to other important tables

-- =============================================================================
-- TODO: Create audit query functions
-- DESCRIPTION: Query audit trail
-- PRIORITY: MEDIUM
-- SECURITY: RLS by application_id; admin can see all
-- PRIVACY: Access logs reviewed for unauthorized PII access
-- =============================================================================
-- TODO: [AUDIT-005] Create audit query functions
-- INSTRUCTIONS:
--   -- Get audit history for record
--   CREATE OR REPLACE FUNCTION audit.get_record_history(
--       p_table_schema VARCHAR,
--       p_table_name VARCHAR,
--       p_record_id TEXT
--   ) RETURNS SETOF audit.audit_log AS $$
--   BEGIN
--       RETURN QUERY
--       SELECT * FROM audit.audit_log
--       WHERE table_schema = p_table_schema
--           AND table_name = p_table_name
--           AND record_id = p_record_id
--       ORDER BY occurred_at DESC;
--   END;
--   $$ LANGUAGE plpgsql STABLE;

-- =============================================================================
-- TODO: Create audit indexes
-- DESCRIPTION: Optimize audit queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for investigation queries
-- =============================================================================
-- TODO: [AUDIT-006] Create audit indexes
-- INDEX LIST:
--   -- Audit Log:
--   - PRIMARY KEY (audit_id)
--   - UNIQUE (audit_reference)
--   - INDEX on (table_schema, table_name, record_id, occurred_at)
--   - INDEX on (actor_id, occurred_at)
--   - INDEX on (application_id, audit_category, occurred_at)
--   - INDEX on (occurred_at)
--   -- Access Logs:
--   - PRIMARY KEY (access_id)
--   - INDEX on (table_schema, table_name, accessed_at)
--   - INDEX on (accessor_id, accessed_at)

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
□ Create audit.audit_log table with hash chain
□ Create audit.audit_access_logs table
□ Implement log_audit_event trigger function
□ Apply audit triggers to key tables
□ Implement audit query functions
□ Add all indexes for audit queries
□ Test audit logging
□ Test hash chain integrity
□ Test audit queries
□ Verify immutability constraints
□ Set up security monitoring alerts
□ Configure automated archival
□ Document forensic procedures
================================================================================
*/
