-- =============================================================================
-- MIGRATION: 037_app_hooks_registry.sql
-- DESCRIPTION: Business Logic Hooks System with Event-Driven Architecture
-- TABLES: hooks, hook_executions, hook_subscriptions
-- DEPENDENCIES: 031_app_registry.sql
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
- Section: 6. Application-Specific Business Logic Hooks
- Feature: Pluggable Rule Engines / Hooks
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Pre-commit and post-commit hooks (URLs or stored procedures) allow custom
modules to integrate without modifying core code. Event-driven hooks for
blockchain anchoring, real-time notifications. Implements ISO 27001 change
management and ISO 27018 data sharing controls.

KEY FEATURES:
- Ordered execution with priority levels
- Retry with exponential backoff for reliability
- Dead letter queue for failed hooks
- Hook metrics and performance monitoring
- Authentication and encryption for webhooks

HOOK TYPES:
- PRE_COMMIT: Before transaction commit (validation)
- POST_COMMIT: After successful commit (notifications)
- ON_ERROR: When transaction fails (alerting)
- ON_STATUS_CHANGE: When status changes (workflow)
- SCHEDULED: Time-based execution

RELIABILITY PATTERNS:
- [ERROR-001] max_retries with exponential backoff
- [ERROR-004] Dead letter queue after max retries
- [AUDIT] Complete execution logging
- Timeout handling to prevent blocking

SECURITY:
- [SECURITY-001] SECURITY DEFINER for hook execution
- [SECURITY-002] Authentication: API_KEY, OAUTH support
- [SECURITY-005] Encrypted credentials in auth_config
================================================================================
*/


-- =============================================================================
-- TODO: Create hooks table
-- DESCRIPTION: Hook definitions
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [HOOK-001] Create app.hooks table
-- INSTRUCTIONS:
--   - Hook configuration per application
--   - Event type and trigger conditions
--   - Versioned
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE app.hooks (
--       hook_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       hook_code           VARCHAR(50) NOT NULL,
--       
--       -- Identity
--       hook_name           VARCHAR(100) NOT NULL,
--       description         TEXT,
--       
--       -- Scope
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Trigger
--       event_type          VARCHAR(50) NOT NULL,        -- PRE_COMMIT, POST_COMMIT, etc.
--       entity_type         VARCHAR(50),                 -- TRANSACTION, MOVEMENT, etc.
--       
--       -- Conditions
--       trigger_condition   JSONB,                       -- When to fire
--       -- Example: {"transaction_type": "TRANSFER", "amount_min": 1000}
--       
--       -- Implementation
--       hook_type           VARCHAR(50) NOT NULL,        -- WEBHOOK, STORED_PROC, QUEUE
--       endpoint_url        VARCHAR(500),                -- For WEBHOOK
--       function_name       VARCHAR(100),                -- For STORED_PROC
--       queue_name          VARCHAR(100),                -- For QUEUE
--       
--       -- Authentication
--       auth_type           VARCHAR(50),                 -- NONE, API_KEY, OAUTH
--       auth_config         JSONB,                       -- Credentials (encrypted)
--       
--       -- Execution Order
--       priority            INTEGER DEFAULT 100,
--       
--       -- Retry Configuration
--       max_retries         INTEGER DEFAULT 3,
--       retry_delay_seconds INTEGER DEFAULT 60,
--       retry_backoff       VARCHAR(20) DEFAULT 'FIXED', -- FIXED, EXPONENTIAL
--       
--       -- Timeout
--       timeout_seconds     INTEGER DEFAULT 30,
--       
--       -- Status
--       is_active           BOOLEAN DEFAULT true,
--       
--       -- Versioning
--       version             INTEGER DEFAULT 1,
--       valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       valid_to            TIMESTAMPTZ,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id)
--   );
--
-- CONSTRAINTS:
--   - UNIQUE (application_id, hook_code) WHERE valid_to IS NULL

-- =============================================================================
-- TODO: Create hook_executions table
-- DESCRIPTION: Hook invocation log
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [HOOK-002] Create app.hook_executions table
-- INSTRUCTIONS:
--   - Records each hook invocation
--   - Tracks success/failure
--   - Supports retry
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE app.hook_executions (
--       execution_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Context
--       hook_id             UUID NOT NULL REFERENCES app.hooks(hook_id),
--       entity_type         VARCHAR(50) NOT NULL,
--       entity_id           UUID NOT NULL,
--       
--       -- Execution
--       status              VARCHAR(20) DEFAULT 'PENDING',
--                           -- PENDING, RUNNING, SUCCESS, FAILED, CANCELLED
--       
--       -- Request/Response
--       request_payload     JSONB,
--       response_status     INTEGER,                     -- HTTP status or result code
--       response_body       TEXT,
--       error_message       TEXT,
--       
--       -- Retry
--       attempt_number      INTEGER DEFAULT 1,
--       max_attempts        INTEGER,
--       next_retry_at       TIMESTAMPTZ,
--       
--       -- Timing
--       scheduled_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
--       started_at          TIMESTAMPTZ,
--       completed_at        TIMESTAMPTZ,
--       duration_ms         INTEGER,
--       
--       -- Dead Letter
--       dead_lettered_at    TIMESTAMPTZ,
--       dead_letter_reason  TEXT,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create execute_hooks function
-- DESCRIPTION: Fire applicable hooks
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [HOOK-003] Create execute_hooks function
-- INSTRUCTIONS:
--   - Find hooks matching event
--   - Check trigger conditions
--   - Create execution records
--   - Handle synchronous vs async
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION app.execute_hooks(
--       p_event_type VARCHAR(50),
--       p_entity_type VARCHAR(50),
--       p_entity_id UUID,
--       p_payload JSONB,
--       p_synchronous BOOLEAN DEFAULT false
--   ) RETURNS VOID AS $$
--   DECLARE
--       v_hook RECORD;
--       v_execution_id UUID;
--   BEGIN
--       -- Find matching hooks
--       FOR v_hook IN 
--           SELECT * FROM app.hooks
--           WHERE event_type = p_event_type
--               AND (entity_type = p_entity_type OR entity_type IS NULL)
--               AND is_active = true
--               AND valid_from <= now()
--               AND (valid_to IS NULL OR valid_to > now())
--           ORDER BY priority
--       LOOP
--           -- Check trigger conditions
--           IF NOT app.check_hook_conditions(v_hook.trigger_condition, p_payload) THEN
--               CONTINUE;
--           END IF;
--           
--           -- Create execution record
--           INSERT INTO app.hook_executions (
--               hook_id, entity_type, entity_id, request_payload,
--               max_attempts, status
--           ) VALUES (
--               v_hook.hook_id, p_entity_type, p_entity_id, p_payload,
--               v_hook.max_retries + 1, 
--               CASE WHEN p_synchronous THEN 'RUNNING' ELSE 'PENDING' END
--           )
--           RETURNING execution_id INTO v_execution_id;
--           
--           -- Execute if synchronous
--           IF p_synchronous THEN
--               PERFORM app.execute_single_hook(v_execution_id);
--           END IF;
--       END LOOP;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create webhook caller function
-- DESCRIPTION: Execute webhook hooks
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [HOOK-004] Create call_webhook function
-- INSTRUCTIONS:
--   - Build HTTP request
--   - Add authentication headers
--   - Handle timeout
--   - Parse response
--   - Update execution record

-- =============================================================================
-- TODO: Create retry processor function
-- DESCRIPTION: Process failed hook retries
-- PRIORITY: MEDIUM
-- =============================================================================
-- TODO: [HOOK-005] Create process_hook_retries function
-- INSTRUCTIONS:
--   - Find failed hooks due for retry
--   - Execute retry
--   - Move to dead letter after max retries

-- =============================================================================
-- TODO: Create hook metrics view
-- DESCRIPTION: Hook performance statistics
-- PRIORITY: LOW
-- =============================================================================
-- TODO: [HOOK-006] Create hook_metrics view
-- INSTRUCTIONS:
--   - Success/failure rates
--   - Average latency
--   - Per-hook statistics

-- =============================================================================
-- TODO: Create hook indexes
-- DESCRIPTION: Optimize hook queries
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [HOOK-007] Create hook indexes
-- INDEX LIST:
--   -- Hooks:
--   - PRIMARY KEY (hook_id)
--   - UNIQUE (application_id, hook_code) WHERE valid_to IS NULL
--   - INDEX on (application_id, event_type, is_active)
--   -- Executions:
--   - PRIMARY KEY (execution_id)
--   - INDEX on (hook_id, status, scheduled_at)
--   - INDEX on (status, next_retry_at) WHERE status = 'FAILED'
--   - INDEX on (entity_type, entity_id)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create hooks table
□ Create hook_executions table
□ Implement execute_hooks function
□ Implement call_webhook function
□ Implement retry processor
□ Create hook_metrics view
□ Add all indexes for hook queries
□ Test hook triggering
□ Test retry logic
□ Test dead letter handling
□ Verify hook ordering
================================================================================
*/
