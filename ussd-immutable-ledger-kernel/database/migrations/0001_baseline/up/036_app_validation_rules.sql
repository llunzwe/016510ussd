-- =============================================================================
-- MIGRATION: 036_app_validation_rules.sql
-- DESCRIPTION: Application-Specific Validation Rules Engine
-- TABLES: validation_rules, rule_executions
-- DEPENDENCIES: 033_app_roles_permissions.sql
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
- Section: 4. Transaction Type Scoping / 4. Transaction Processing
- Feature: Validation Rules Engine
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Pluggable validation logic per transaction type. Rules can be SQL functions
or external microservice calls. Prevents overdrawing accounts or exceeding
limits per ISO 27001 integrity controls.

KEY FEATURES:
- Ordered execution with priority
- Fail-fast or continue-on-error modes
- Conditional rules based on context
- Rule versioning for audit
- Execution logging for debugging

RULE TYPES:
- BALANCE_CHECK: Verify sufficient balance
- LIMIT_CHECK: Check entitlement limits (ISO 31000)
- SCHEMA_VALIDATION: Validate JSON payload
- DUPLICATE_CHECK: Check for duplicates (idempotency)
- COMPLIANCE_CHECK: Sanctions/AML screening
- CUSTOM: Application-specific logic

ERROR BEHAVIOR:
- FAIL: Stop processing, reject transaction
- WARN: Continue with warning logged
- SKIP: Skip this rule, continue with next

EXECUTION CONTROL:
- [TRANSACTION] Ordered execution per execution_order
- [ERROR-001] EXCEPTION WHEN OTHERS per rule
- [AUDIT] rule_executions: Complete execution log
================================================================================
*/


-- =============================================================================
-- TODO: Create validation_rules table
-- DESCRIPTION: Rule definitions
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [VAL-001] Create app.validation_rules table
-- INSTRUCTIONS:
--   - Per-application validation rules
--   - Ordered execution
--   - Versioned
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE app.validation_rules (
--       rule_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Identification
--       rule_code           VARCHAR(50) NOT NULL,
--       rule_name           VARCHAR(100) NOT NULL,
--       description         TEXT,
--       
--       -- Scope
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       transaction_type_id UUID REFERENCES core.transaction_types(transaction_type_id),
--       
--       -- Execution Order
--       execution_order     INTEGER NOT NULL DEFAULT 100,
--       
--       -- Rule Type
--       rule_type           VARCHAR(50) NOT NULL,        -- BALANCE_CHECK, SCHEMA_VALIDATION, etc.
--       
--       -- Implementation
--       implementation      VARCHAR(50) NOT NULL,        -- SQL_FUNCTION, WEBHOOK, STORED_PROC
--       implementation_ref  VARCHAR(255) NOT NULL,       -- Function name or URL
--       
--       -- Parameters
--       parameters          JSONB DEFAULT '{}',          -- Rule-specific params
--       
--       -- Error Handling
--       error_behavior      VARCHAR(20) DEFAULT 'FAIL',  -- FAIL, WARN, SKIP
--       error_message       VARCHAR(255),                -- Custom error message
--       
--       -- Conditions
--       condition_expression TEXT,                       -- When to apply rule
--       
--       -- Versioning
--       version             INTEGER DEFAULT 1,
--       valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       valid_to            TIMESTAMPTZ,
--       
--       -- Status
--       is_active           BOOLEAN DEFAULT true,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id)
--   );
--
-- CONSTRAINTS:
--   - UNIQUE (application_id, transaction_type_id, rule_code, valid_to) 
--     WHERE valid_to IS NULL

-- =============================================================================
-- TODO: Create rule_executions table
-- DESCRIPTION: Track rule execution results
-- PRIORITY: MEDIUM
-- =============================================================================
-- TODO: [VAL-002] Create app.rule_executions table
-- INSTRUCTIONS:
--   - Log each rule execution
--   - Performance metrics
--   - Debug information
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE app.rule_executions (
--       execution_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Context
--       rule_id             UUID NOT NULL REFERENCES app.validation_rules(rule_id),
--       transaction_id      UUID REFERENCES core.transaction_log(transaction_id),
--       
--       -- Execution
--       status              VARCHAR(20) NOT NULL,        -- PASS, FAIL, ERROR, SKIPPED
--       result_data         JSONB,                       -- Rule output
--       error_message       TEXT,
--       
--       -- Performance
--       started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       completed_at        TIMESTAMPTZ,
--       duration_ms         INTEGER,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create execute_validation_rules function
-- DESCRIPTION: Run all applicable rules
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [VAL-003] Create execute_validation_rules function
-- INSTRUCTIONS:
--   - Find applicable rules for transaction
--   - Execute in order
--   - Handle failures per error_behavior
--   - Return overall pass/fail
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION app.execute_validation_rules(
--       p_transaction_id UUID,
--       p_transaction_type_id UUID,
--       p_application_id UUID
--   ) RETURNS TABLE (
--       rule_id UUID,
--       rule_name VARCHAR(100),
--       status VARCHAR(20),
--       message TEXT
--   ) AS $$
--   DECLARE
--       v_rule RECORD;
--       v_result JSONB;
--       v_all_passed BOOLEAN := true;
--   BEGIN
--       -- Find applicable rules
--       FOR v_rule IN 
--           SELECT * FROM app.validation_rules
--           WHERE application_id = p_application_id
--               AND (transaction_type_id = p_transaction_type_id OR transaction_type_id IS NULL)
--               AND is_active = true
--               AND valid_from <= now()
--               AND (valid_to IS NULL OR valid_to > now())
--           ORDER BY execution_order
--       LOOP
--           -- Execute rule based on implementation type
--           BEGIN
--               CASE v_rule.implementation
--                   WHEN 'SQL_FUNCTION' THEN
--                       EXECUTE format('SELECT %s($1, $2)', v_rule.implementation_ref)
--                       INTO v_result
--                       USING p_transaction_id, v_rule.parameters;
--                   WHEN 'WEBHOOK' THEN
--                       v_result := app.call_validation_webhook(
--                           v_rule.implementation_ref, p_transaction_id, v_rule.parameters);
--                   -- etc.
--               END CASE;
--               
--               -- Record execution
--               INSERT INTO app.rule_executions (rule_id, transaction_id, status, result_data)
--               VALUES (v_rule.rule_id, p_transaction_id, 'PASS', v_result);
--               
--               RETURN QUERY SELECT v_rule.rule_id, v_rule.rule_name, 'PASS'::VARCHAR, NULL::TEXT;
--               
--           EXCEPTION WHEN OTHERS THEN
--               -- Record failure
--               INSERT INTO app.rule_executions (rule_id, transaction_id, status, error_message)
--               VALUES (v_rule.rule_id, p_transaction_id, 'FAIL', SQLERRM);
--               
--               IF v_rule.error_behavior = 'FAIL' THEN
--                   v_all_passed := false;
--                   RETURN QUERY SELECT v_rule.rule_id, v_rule.rule_name, 'FAIL'::VARCHAR, SQLERRM::TEXT;
--                   
--                   IF v_rule.error_behavior = 'FAIL' THEN
--                       RETURN;  -- Stop on first failure
--                   END IF;
--               ELSE
--                   RETURN QUERY SELECT v_rule.rule_id, v_rule.rule_name, 'WARN'::VARCHAR, SQLERRM::TEXT;
--               END IF;
--           END;
--       END LOOP;
--       
--       RETURN;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create standard validation functions
-- DESCRIPTION: Built-in validation rules
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [VAL-004] Create standard validation functions
-- INSTRUCTIONS:
--   - validate_balance: Check sufficient balance
--   - validate_schema: Validate JSON against schema
--   - validate_limits: Check entitlement limits
--   - validate_duplicate: Check idempotency

-- =============================================================================
-- TODO: Create validation indexes
-- DESCRIPTION: Optimize validation queries
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [VAL-005] Create validation indexes
-- INDEX LIST:
--   -- Rules:
--   - PRIMARY KEY (rule_id)
--   - UNIQUE (application_id, transaction_type_id, rule_code) WHERE valid_to IS NULL
--   - INDEX on (application_id, is_active, execution_order)
--   -- Executions:
--   - PRIMARY KEY (execution_id)
--   - INDEX on (rule_id, transaction_id)
--   - INDEX on (transaction_id, status)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create validation_rules table
□ Create rule_executions table
□ Implement execute_validation_rules function
□ Implement standard validation functions
□ Add all indexes for validation queries
□ Test rule execution ordering
□ Test error behavior (fail vs warn)
□ Test conditional rules
□ Verify rule versioning
================================================================================
*/
