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
-- TODO: Create integrity_violations table
-- DESCRIPTION: Log of immutability violation attempts
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [INTG-001] Create core.integrity_violations table
-- INSTRUCTIONS:
--   - Audit log of attempted violations
--   - For security monitoring
--   - Alert on suspicious patterns
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.integrity_violations (
--       violation_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Attempt Details
--       attempted_operation VARCHAR(10) NOT NULL,        -- UPDATE, DELETE
--       table_schema        VARCHAR(50) NOT NULL,
--       table_name          VARCHAR(100) NOT NULL,
--       record_id           TEXT,                        -- Primary key value
--       
--       -- Context
--       old_data            JSONB,                       -- Row before change (if captured)
--       new_data            JSONB,                       -- Attempted new values
--       
--       -- Source
--       user_name           VARCHAR(100),
--       application_name    VARCHAR(100),
--       client_addr         INET,
--       query_text          TEXT,
--       
--       -- Timestamp
--       attempted_at        TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create prevent_update_trigger function
-- DESCRIPTION: Block UPDATE operations
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [INTG-002] Create prevent_update function
-- INSTRUCTIONS:
--   - Raise exception on any UPDATE
--   - Log violation attempt
--   - Suggest compensating transaction
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.prevent_update()
--   RETURNS TRIGGER AS $$
--   BEGIN
--       -- Log violation
--       INSERT INTO core.integrity_violations (
--           attempted_operation, table_schema, table_name, 
--           record_id, old_data, new_data,
--           user_name, application_name, client_addr
--       ) VALUES (
--           'UPDATE', TG_TABLE_SCHEMA, TG_TABLE_NAME,
--           OLD.primary_key_column::text, to_jsonb(OLD), to_jsonb(NEW),
--           current_user, current_setting('application.name', true), inet_client_addr()
--       );
--       
--       -- Raise exception
--       RAISE EXCEPTION 'UPDATE operation blocked on %.%: Table is immutable. Use compensating transaction instead.',
--           TG_TABLE_SCHEMA, TG_TABLE_NAME
--           USING HINT = 'Insert a new record or use the reversal process for corrections.';
--       
--       RETURN NULL;
--   END;
--   $$ LANGUAGE plpgsql SECURITY DEFINER;

-- =============================================================================
-- TODO: Create prevent_delete_trigger function
-- DESCRIPTION: Block DELETE operations
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [INTG-003] Create prevent_delete function
-- INSTRUCTIONS:
--   - Raise exception on any DELETE
--   - Log violation attempt
--   - Suggest status change instead
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.prevent_delete()
--   RETURNS TRIGGER AS $$
--   BEGIN
--       -- Log violation
--       INSERT INTO core.integrity_violations (
--           attempted_operation, table_schema, table_name,
--           record_id, old_data,
--           user_name, application_name, client_addr
--       ) VALUES (
--           'DELETE', TG_TABLE_SCHEMA, TG_TABLE_NAME,
--           OLD.primary_key_column::text, to_jsonb(OLD),
--           current_user, current_setting('application.name', true), inet_client_addr()
--       );
--       
--       -- Raise exception
--       RAISE EXCEPTION 'DELETE operation blocked on %.%: Table is immutable. Use status change instead.',
--           TG_TABLE_SCHEMA, TG_TABLE_NAME
--           USING HINT = 'Update status to CLOSED or use archival for old data.';
--       
--       RETURN NULL;
--   END;
--   $$ LANGUAGE plpgsql SECURITY DEFINER;

-- =============================================================================
-- TODO: Create hash chain verification function
-- DESCRIPTION: Verify transaction hash chain
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [INTG-004] Create verify_hash_chain function
-- INSTRUCTIONS:
--   - Verify each transaction hash matches stored value
--   - Verify hash chain links are intact
--   - Return list of any discrepancies
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.verify_hash_chain(
--       p_account_id UUID DEFAULT NULL,
--       p_start_date DATE DEFAULT NULL,
--       p_end_date DATE DEFAULT NULL
--   ) RETURNS TABLE (
--       transaction_id UUID,
--       expected_hash BYTEA,
--       actual_hash BYTEA,
--       is_valid BOOLEAN
--   ) AS $$
--   BEGIN
--       RETURN QUERY
--       WITH computed AS (
--           SELECT 
--               t.transaction_id,
--               t.current_hash as stored_hash,
--               core.compute_transaction_hash(
--                   t.transaction_type_id, t.application_id, t.payload,
--                   t.initiator_account_id, t.amount, t.currency,
--                   t.entry_date, t.previous_hash
--               ) as computed_hash
--           FROM core.transaction_log t
--           WHERE (p_account_id IS NULL OR t.initiator_account_id = p_account_id)
--               AND (p_start_date IS NULL OR t.entry_date >= p_start_date)
--               AND (p_end_date IS NULL OR t.entry_date <= p_end_date)
--       )
--       SELECT 
--           c.transaction_id,
--           c.stored_hash,
--           c.computed_hash,
--           c.stored_hash = c.computed_hash
--       FROM computed c
--       WHERE c.stored_hash != c.computed_hash;
--   END;
--   $$ LANGUAGE plpgsql STABLE;

-- =============================================================================
-- TODO: Create integrity check schedule
-- DESCRIPTION: Automated integrity verification
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [INTG-005] Create integrity_check_schedule table
-- INSTRUCTIONS:
--   - Configure automated integrity checks
--   - Track check execution
--   - Alert on failures
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.integrity_check_schedule (
--       check_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       check_name          VARCHAR(100) NOT NULL,
--       check_type          VARCHAR(50) NOT NULL,        -- HASH_CHAIN, BALANCE, etc.
--       
--       -- Schedule
--       frequency           VARCHAR(20) NOT NULL,        -- HOURLY, DAILY, WEEKLY
--       last_run_at         TIMESTAMPTZ,
--       next_run_at         TIMESTAMPTZ,
--       
--       -- Scope
--       parameters          JSONB,                       -- Check-specific params
--       
--       -- Status
--       is_active           BOOLEAN DEFAULT true,
--       
--       -- Last Result
--       last_result         VARCHAR(20),                 -- PASS, FAIL, ERROR
--       last_result_details JSONB,
--       
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Apply immutability triggers
-- DESCRIPTION: Attach triggers to immutable tables
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [INTG-006] Apply immutability triggers
-- INSTRUCTIONS:
--   CREATE TRIGGER accounts_no_update
--       BEFORE UPDATE ON core.accounts
--       FOR EACH ROW EXECUTE FUNCTION core.prevent_update();
--   
--   CREATE TRIGGER accounts_no_delete
--       BEFORE DELETE ON core.accounts
--       FOR EACH ROW EXECUTE FUNCTION core.prevent_delete();
--   
--   -- Repeat for: transaction_log, movement_headers, movement_legs, blocks, etc.

/*
================================================================================
MIGRATION CHECKLIST:
□ Create integrity_violations table
□ Implement prevent_update trigger function
□ Implement prevent_delete trigger function
□ Implement verify_hash_chain function
□ Create integrity_check_schedule table
□ Apply immutability triggers to all core tables
□ Test UPDATE blocking
□ Test DELETE blocking
□ Test hash chain verification
□ Configure scheduled integrity checks
================================================================================
*/
