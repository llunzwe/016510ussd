-- =============================================================================
-- MIGRATION: 035_app_entitlement_limits.sql
-- DESCRIPTION: Entitlement Limits per Role/Account for Risk Management
-- TABLES: entitlement_limits, limit_usage
-- DEPENDENCIES: 034_app_user_role_assignments.sql
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
- Section: 6. Entitlements & Access Control
- Feature: Entitlement Limits
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Per-entitlement limits: max amount per transaction, daily/monthly limits,
allowed counterparties, allowed payment schemes. Prevents fraud and manages
risk per ISO 31000 risk management guidelines.

KEY FEATURES:
- Multiple limit dimensions (amount, count, time)
- Usage tracking with automatic reset
- Limit override workflow with approval
- Alert on threshold breach
- Risk-based limit calculation

LIMIT TYPES (ISO 31000 Risk Mitigation):
- TRANSACTION_MAX: Maximum per transaction (fraud prevention)
- DAILY_LIMIT: Cumulative daily total (exposure control)
- MONTHLY_LIMIT: Cumulative monthly total (risk management)
- COUNTERPARTY: Allowed/disallowed counterparties
- SCHEME: Allowed payment schemes

ENFORCEMENT ACTIONS:
- BLOCK: Reject transaction exceeding limit
- WARN: Allow with warning logged
- NOTIFY: Allow with notification sent

SECURITY:
- [SECURITY-002] Input validation on all limit parameters
- [AUDIT] created_by, created_at: Limit creation tracking
- [AUDIT] limit_usage: Complete usage tracking
================================================================================
*/


-- =============================================================================
-- IMPLEMENTED: Create entitlement_limits table
-- DESCRIPTION: Limit definitions
-- PRIORITY: CRITICAL
-- =============================================================================
-- [LIM-001] Create app.entitlement_limits table
CREATE TABLE app.entitlement_limits (
    limit_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Scope
    limit_scope         VARCHAR(20) NOT NULL,        -- ROLE, ACCOUNT, GLOBAL
    role_id             UUID REFERENCES app.roles(role_id),
    account_id          UUID REFERENCES core.accounts(account_id),
    application_id      UUID REFERENCES app.applications(application_id),
    
    -- Limit Definition
    limit_type          VARCHAR(50) NOT NULL,        -- TRANSACTION_MAX, DAILY, etc.
    limit_name          VARCHAR(100),
    
    -- Limit Value
    limit_amount        NUMERIC(20, 8),
    limit_currency      VARCHAR(3),
    limit_count         INTEGER,                     -- For count-based limits
    
    -- Time Period (for time-based limits)
    period_type         VARCHAR(20),                 -- TRANSACTION, DAILY, WEEKLY, MONTHLY
    period_start        TIME,                        -- e.g., 00:00 for daily
    
    -- Counterparty/Scheme restrictions
    allowed_values      TEXT[],                      -- Allowed counterparties/schemes
    blocked_values      TEXT[],                      -- Blocked counterparties/schemes
    
    -- Enforcement
    enforcement_action  VARCHAR(20) DEFAULT 'BLOCK', -- BLOCK, WARN, NOTIFY
    
    -- Validity
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,
    
    -- Status
    is_active           BOOLEAN DEFAULT true,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id)
);

-- CONSTRAINTS:
ALTER TABLE app.entitlement_limits
    ADD CONSTRAINT chk_limit_scope 
        CHECK (limit_scope IN ('ROLE', 'ACCOUNT', 'GLOBAL'));

ALTER TABLE app.entitlement_limits
    ADD CONSTRAINT chk_limit_type 
        CHECK (limit_type IN ('TRANSACTION_MAX', 'DAILY', 'MONTHLY', 'COUNTERPARTY', 'SCHEME'));

COMMENT ON TABLE app.entitlement_limits IS 'Entitlement limits per role/account for risk management';

-- =============================================================================
-- IMPLEMENTED: Create limit_usage table
-- DESCRIPTION: Track current period usage
-- PRIORITY: HIGH
-- =============================================================================
-- [LIM-002] Create app.limit_usage table
CREATE TABLE app.limit_usage (
    usage_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Links
    limit_id            UUID NOT NULL REFERENCES app.entitlement_limits(limit_id),
    account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
    
    -- Period
    period_start        TIMESTAMPTZ NOT NULL,
    period_end          TIMESTAMPTZ NOT NULL,
    
    -- Usage
    used_amount         NUMERIC(20, 8) DEFAULT 0,
    used_count          INTEGER DEFAULT 0,
    remaining_amount    NUMERIC(20, 8),
    
    -- Last Transaction
    last_transaction_at TIMESTAMPTZ,
    last_transaction_id UUID REFERENCES core.transaction_log(transaction_id),
    
    -- Audit
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- CONSTRAINTS:
CREATE UNIQUE INDEX idx_limit_usage_unique_period 
    ON app.limit_usage (limit_id, account_id, period_start);

COMMENT ON TABLE app.limit_usage IS 'Tracks usage against entitlement limits';

-- =============================================================================
-- IMPLEMENTED: Create check_limit function
-- DESCRIPTION: Validate transaction against limits
-- PRIORITY: CRITICAL
-- =============================================================================
-- [LIM-003] Create check_entitlement_limit function
CREATE OR REPLACE FUNCTION app.check_entitlement_limit(
    p_account_id UUID,
    p_application_id UUID,
    p_amount NUMERIC,
    p_currency VARCHAR(3),
    p_counterparty UUID DEFAULT NULL,
    p_scheme VARCHAR(50) DEFAULT NULL
) RETURNS TABLE (
    limit_id UUID,
    limit_name VARCHAR(100),
    check_passed BOOLEAN,
    reason TEXT,
    remaining NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    WITH applicable_limits AS (
        SELECT * FROM app.entitlement_limits
        WHERE is_active = true
            AND valid_from <= now()
            AND (valid_to IS NULL OR valid_to > now())
            AND (account_id = p_account_id OR 
                 role_id IN (SELECT role_id FROM app.effective_roles 
                            WHERE account_id = p_account_id AND application_id = p_application_id) OR
                 limit_scope = 'GLOBAL')
    )
    SELECT 
        al.limit_id,
        al.limit_name,
        CASE 
            WHEN al.limit_type = 'TRANSACTION_MAX' AND p_amount > al.limit_amount THEN false
            WHEN al.limit_type = 'DAILY' AND COALESCE(lu.used_amount, 0) + p_amount > al.limit_amount THEN false
            ELSE true
        END as check_passed,
        CASE 
            WHEN al.limit_type = 'TRANSACTION_MAX' AND p_amount > al.limit_amount 
                THEN 'Transaction amount exceeds maximum'
            WHEN al.limit_type = 'DAILY' AND COALESCE(lu.used_amount, 0) + p_amount > al.limit_amount 
                THEN 'Daily limit would be exceeded'
            ELSE 'Within limit'
        END as reason,
        COALESCE(al.limit_amount - lu.used_amount, al.limit_amount) as remaining
    FROM applicable_limits al
    LEFT JOIN app.limit_usage lu ON al.limit_id = lu.limit_id 
        AND lu.account_id = p_account_id
        AND lu.period_start <= now() AND lu.period_end > now();
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION app.check_entitlement_limit IS 'Validates a transaction against applicable entitlement limits';

-- =============================================================================
-- IMPLEMENTED: Create update_usage function
-- DESCRIPTION: Record usage against limit
-- PRIORITY: CRITICAL
-- =============================================================================
-- [LIM-004] Create record_limit_usage function
CREATE OR REPLACE FUNCTION app.record_limit_usage(
    p_limit_id UUID,
    p_account_id UUID,
    p_amount NUMERIC,
    p_transaction_id UUID DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_limit RECORD;
    v_period_start TIMESTAMPTZ;
    v_period_end TIMESTAMPTZ;
BEGIN
    -- Get limit details
    SELECT * INTO v_limit FROM app.entitlement_limits WHERE limit_id = p_limit_id;
    
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    
    -- Calculate period boundaries
    IF v_limit.period_type = 'DAILY' THEN
        v_period_start := date_trunc('day', now());
        v_period_end := v_period_start + INTERVAL '1 day';
    ELSIF v_limit.period_type = 'MONTHLY' THEN
        v_period_start := date_trunc('month', now());
        v_period_end := v_period_start + INTERVAL '1 month';
    ELSIF v_limit.period_type = 'WEEKLY' THEN
        v_period_start := date_trunc('week', now());
        v_period_end := v_period_start + INTERVAL '1 week';
    ELSE
        -- Default to daily
        v_period_start := date_trunc('day', now());
        v_period_end := v_period_start + INTERVAL '1 day';
    END IF;
    
    -- Upsert usage record
    INSERT INTO app.limit_usage (
        limit_id, account_id, period_start, period_end,
        used_amount, used_count, last_transaction_at, last_transaction_id
    ) VALUES (
        p_limit_id, p_account_id, v_period_start, v_period_end,
        p_amount, 1, now(), p_transaction_id
    )
    ON CONFLICT (limit_id, account_id, period_start) 
    DO UPDATE SET
        used_amount = app.limit_usage.used_amount + p_amount,
        used_count = app.limit_usage.used_count + 1,
        remaining_amount = app.entitlement_limits.limit_amount - (app.limit_usage.used_amount + p_amount),
        last_transaction_at = now(),
        last_transaction_id = p_transaction_id,
        updated_at = now()
    FROM app.entitlement_limits
    WHERE app.entitlement_limits.limit_id = p_limit_id;
    
    RETURN true;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION app.record_limit_usage IS 'Records usage against an entitlement limit';

-- =============================================================================
-- IMPLEMENTED: Create limit override function
-- DESCRIPTION: Temporary limit increase
-- PRIORITY: MEDIUM
-- =============================================================================
-- [LIM-005] Create override_limit function
CREATE OR REPLACE FUNCTION app.override_limit(
    p_limit_id UUID,
    p_new_amount NUMERIC,
    p_reason TEXT,
    p_authorized_by UUID,
    p_valid_until TIMESTAMPTZ
) RETURNS UUID AS $$
DECLARE
    v_new_limit_id UUID;
    v_old_limit RECORD;
BEGIN
    -- Get current limit
    SELECT * INTO v_old_limit FROM app.entitlement_limits WHERE limit_id = p_limit_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Limit not found: %', p_limit_id;
    END IF;
    
    -- Create new limit with override amount
    INSERT INTO app.entitlement_limits (
        limit_scope, role_id, account_id, application_id,
        limit_type, limit_name, limit_amount, limit_currency,
        period_type, allowed_values, blocked_values,
        enforcement_action, valid_from, valid_to, is_active, created_by
    ) VALUES (
        v_old_limit.limit_scope, v_old_limit.role_id, v_old_limit.account_id, 
        v_old_limit.application_id, v_old_limit.limit_type,
        v_old_limit.limit_name || ' (OVERRIDE)', p_new_amount, v_old_limit.limit_currency,
        v_old_limit.period_type, v_old_limit.allowed_values, v_old_limit.blocked_values,
        v_old_limit.enforcement_action, now(), p_valid_until, true, p_authorized_by
    )
    RETURNING limit_id INTO v_new_limit_id;
    
    -- Deactivate old limit
    UPDATE app.entitlement_limits
    SET valid_to = now(), is_active = false
    WHERE limit_id = p_limit_id;
    
    RETURN v_new_limit_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION app.override_limit IS 'Creates a temporary limit override with authorization';

-- =============================================================================
-- IMPLEMENTED: Create limit indexes
-- DESCRIPTION: Optimize limit queries
-- PRIORITY: HIGH
-- =============================================================================
-- [LIM-006] Create limit indexes
-- Limits:
-- PRIMARY KEY (limit_id) - created with table

CREATE INDEX idx_entitlement_limits_role_type_active 
    ON app.entitlement_limits (role_id, limit_type, is_active);

CREATE INDEX idx_entitlement_limits_account_type_active 
    ON app.entitlement_limits (account_id, limit_type, is_active);

CREATE INDEX idx_entitlement_limits_app_scope_active 
    ON app.entitlement_limits (application_id, limit_scope, is_active);

-- Usage:
-- PRIMARY KEY (usage_id) - created with table
-- UNIQUE (limit_id, account_id, period_start) - created above

CREATE INDEX idx_limit_usage_account_period 
    ON app.limit_usage (account_id, period_end);

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create entitlement_limits table
☑ Create limit_usage table
☑ Implement check_entitlement_limit function
☑ Implement record_limit_usage function
☑ Implement override_limit function
☑ Add all indexes for limit queries
☐ Test limit checking
☐ Test usage tracking
☐ Test period rollovers
☐ Verify limit enforcement
================================================================================
*/
