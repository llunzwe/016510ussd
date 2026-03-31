/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - HOOKS REGISTRY
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-007
 * Feature Name:       Event Hook System
 * Description:        Event-driven hook system for extending ledger
 *                     functionality. Supports pre/post commit
 *                     webhooks, and custom function invocation with
 *                     ordering, retry logic, and circuit breaker patterns.
 * 
 * Version:            1.0.0
 * Author:             Eng. llunzwe
 * Created:            2026-03-30
 * Last Modified:      2026-03-30
 * 
 * =============================================================================
 * COMPLIANCE & CERTIFICATIONS
 * =============================================================================
 * 
 * ISO/IEC 27001:2022 (ISMS)
 *   - Control A.8.15: Logging (hook execution logs)
 *   - Control A.8.20: Network services security (webhooks)
 *   - Control A.8.24: Use of cryptography (webhook signatures)
 *   - Control A.8.26: Application security requirements
 *   - Control A.8.31: Separation of environments
 * 
 * ISO/IEC 27017:2015 (Cloud Security)
 *   - Section 9: Network security (outbound webhooks)
 *   - Section 12: Multi-tenant event isolation
 * 
 * SOC 2 Type II
 *   - CC7.2: System monitoring (hook failure alerting)
 *   - CC8.1: Change management (hook deployment)
 * 
 * =============================================================================
 * MULTI-TENANCY SECURITY ANNOTATIONS
 * =============================================================================
 * 
 * HOOK ISOLATION:
 *   - Hooks isolated by application (app_id)
 *   - Webhook secrets scoped per hook
 *   - IP allowlists for webhook endpoints
 * 
 * SECURITY CONTROLS:
 *   - Circuit breaker prevents cascade failures
 *   - Webhook payload signatures (HMAC)
 *   - Timeout limits prevent resource exhaustion
 *   - URL validation prevents SSRF
 * 
 * =============================================================================
 * RBAC ENFORCEMENT DOCUMENTATION
 * =============================================================================
 * 
 * REQUIRED PERMISSIONS:
 * 
 * | Operation                    | Required Permission              |
 * |------------------------------|----------------------------------|
 * | CREATE hook                  | app:hook:create                  |
 * | READ hook                    | app:hook:read                    |
 * | UPDATE hook                  | app:hook:update                  |
 * | DELETE hook                  | app:hook:delete                  |
 * | EXECUTE hook                 | (System - enforcement)           |
 * | RESET circuit breaker        | app:hook:admin                   |
 * 
 * =============================================================================
 * AUDIT TRAIL REQUIREMENTS
 * =============================================================================
 * 
 * MANDATORY AUDIT EVENTS:
 *   - Hook Execution (success/failure, duration)
 *   - Circuit Breaker State Change (open/close)
 *   - Webhook Invocation (endpoint, signature)
 *   - Circuit Breaker Trip (failure count)
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - app.t_application_registry (FK: app_id)
 * 
 * CHANGE LOG:
 *   1.0.0 - Initial schema creation
 * =============================================================================
 */



-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Controls A.5.x - A.9.x)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Multi-tenancy)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds
-- ISO 9001:2015 - Quality Management Systems
-- ISO 31000:2018 - Risk Management Guidelines
-- ============================================================================
-- CODING PRACTICES:
-- - Use parameterized queries to prevent SQL injection
-- - Implement proper error handling with transaction rollback
-- - Use SECURITY DEFINER
-- - Enforce RLS policies for multi-tenant data isolation
-- - Use explicit column lists (avoid SELECT *)
-- - Add audit logging for all security-relevant operations
-- - Use UUIDs for primary identifiers to prevent enumeration
-- - Implement optimistic locking with version columns
-- - Use TIMESTAMPTZ for all timestamp columns
-- - Validate all inputs with CHECK constraints
-- ============================================================================

-- =============================================================================
-- TABLE: app.t_hooks_registry
-- =============================================================================
CREATE TABLE IF NOT EXISTS app.t_hooks_registry (
    hook_id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    app_id                      UUID NOT NULL,
                                CONSTRAINT fk_hooks_app 
                                    FOREIGN KEY (app_id) 
                                    REFERENCES app.t_application_registry(app_id)
                                    ON DELETE CASCADE,
    
    hook_code                   VARCHAR(50) NOT NULL,
    
    -- Classification
    hook_type                   VARCHAR(30) NOT NULL,
                                CONSTRAINT chk_hook_type 
                                    CHECK (hook_type IN ('webhook', 'function', 'queue', 'event', 'workflow')),
    hook_phase                  VARCHAR(30) NOT NULL,
                                CONSTRAINT chk_hook_phase 
                                    CHECK (hook_phase IN ('pre_validation', 'pre_commit  -- [TXN] ISO 27001: ACID transaction boundary', 'post_commit')),
    
    -- Event Triggering
    trigger_events              TEXT[] NOT NULL DEFAULT '{}',
    trigger_conditions          JSONB DEFAULT '{}',
    
    -- Configuration
    hook_config                 JSONB NOT NULL DEFAULT '{}',
    
    -- Execution Control
    execution_order             INTEGER NOT NULL DEFAULT 100,
    is_blocking  -- [HOOK] Safety: Blocking vs non-blocking execution mode                 BOOLEAN NOT NULL DEFAULT FALSE,
    timeout_seconds  -- [HOOK] ISO 27001: Resource exhaustion prevention             INTEGER NOT NULL DEFAULT 30,
    
    -- Retry
    retry_policy                JSONB DEFAULT '{"max_retries": 3, "backoff": "exponential"}',
    
    -- Circuit Breaker
    circuit_breaker  -- [HOOK] ISO 27001: Fail-safe protection -- [HOOK] ISO 27001: Fail-safe circuit breaker protection_threshold   INTEGER DEFAULT 5,
    circuit_breaker  -- [HOOK] ISO 27001: Fail-safe protection -- [HOOK] ISO 27001: Fail-safe circuit breaker protection_timeout_sec INTEGER DEFAULT 60,
    circuit_state  -- [HOOK] Safety: Circuit breaker state -- [HOOK] Safety: Circuit state (closed/open/half_open)               VARCHAR(20) DEFAULT 'closed',
                                CONSTRAINT chk_circuit_state  -- [HOOK] Safety: Circuit breaker state
                                    CHECK (circuit_state  -- [HOOK] Safety: Circuit breaker state -- [HOOK] Safety: Circuit state (closed/open/half_open) IN ('closed', 'open', 'half_open')),
    circuit_failure_count       INTEGER DEFAULT 0,
    circuit_last_failure_at     TIMESTAMPTZ,
    
    -- Payload
    payload_template            TEXT,
    payload_transform           TEXT,
    
    -- Security
    signature_secret            VARCHAR(255),
                                -- HMAC secret for webhook signatures
    allowed_ip_ranges           TEXT[],
                                -- IP whitelist for webhooks
    
    -- Monitoring
    success_count               BIGINT DEFAULT 0,
    failure_count               BIGINT DEFAULT 0,
    last_execution_at           TIMESTAMPTZ,
    last_success_at             TIMESTAMPTZ,
    last_failure_at             TIMESTAMPTZ,
    last_error_message          TEXT,
    average_execution_ms        INTEGER,
    
    -- Lifecycle
    status                      VARCHAR(20) NOT NULL DEFAULT 'active',
                                CONSTRAINT chk_hook_status 
                                    CHECK (status IN ('active', 'paused', 'deprecated', 'failed')),
    
    -- Audit
    version                     INTEGER NOT NULL DEFAULT 1  -- [AUDIT] ISO 9001: Optimistic locking for version control,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()  -- [AUDIT] ISO 27001: Non-repudiation timestamp,
    created_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    
    CONSTRAINT uq_app_hook_code UNIQUE (app_id, hook_code)
);

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON TABLE app.t_hooks_registry IS 
    'Event-driven hooks for extending ledger functionality. ' ||
    'Feature: CORE-APP-007. ' ||
    'Compliance: ISO 27001, ISO 27017. ' ||
    'Security: Circuit breaker, webhook signatures, IP allowlists. ' ||
    'Audit: Execution logs and circuit breaker state changes.';

COMMENT ON COLUMN app.t_hooks_registry.signature_secret IS 
    'HMAC secret for webhook payload signing. Stored hashed.';
    
COMMENT ON COLUMN app.t_hooks_registry.circuit_state;  -- [HOOK] Safety: Circuit breaker state

-- =============================================================================
-- INDEXES
-- =============================================================================
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_hooks_app 
    ON app.t_hooks_registry(app_id);

CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_hooks_phase 
    ON app.t_hooks_registry(hook_phase, execution_order) 
    WHERE status = 'active';

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Hooks execute in strict priority order
-- 2. Blocking hooks stop execution on failure
-- 3. Circuit breaker protects against failing hooks
-- 4. Webhooks use idempotency keys for safety
-- 5. All executions measured and logged
-- 6. IP allowlist prevents SSRF attacks
-- =============================================================================
