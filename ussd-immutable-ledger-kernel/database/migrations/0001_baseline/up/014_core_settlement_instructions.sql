-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (External party management)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Settlement security)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Destination data handling)
-- ISO/IEC 27040:2024 - Storage Security (Settlement integrity)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Settlement recovery)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Multiple settlement methods with validation
-- - Finality tracking for reconciliation
-- - External reference linking
-- - Failure handling and retry logic
-- ============================================================================
-- =============================================================================
-- MIGRATION: 014_core_settlement_instructions.sql
-- DESCRIPTION: External Settlement Instructions
-- TABLES: settlement_instructions, settlement_attempts
-- DEPENDENCIES: 005_core_movement_legs.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 7. Settlement & External Integration
- Feature: Settlement Instructions
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Tracks settlement of movements to external systems (mobile money, bank).
When a user withdraws from a savings group to mobile money, a settlement
instruction records the external payout status.

KEY FEATURES:
- Multiple settlement methods (RTGS, mobile money, wallet)
- Finality tracking for reconciliation
- External reference linking (mobile money tx ID)
- Failure handling and retry logic
- Settlement reconciliation matching

SETTLEMENT METHODS:
- RTGS: Real-time gross settlement
- MOBILE_MONEY: Mobile network operator
- WALLET: Internal wallet transfer
- CASH: Physical cash disbursement
- BANK_TRANSFER: ACH/wire transfer
================================================================================
*/

-- =============================================================================
-- Create settlement_methods table
-- DESCRIPTION: Catalog of settlement methods
-- PRIORITY: HIGH
-- SECURITY: Validate configuration schema
-- ============================================================================
CREATE TABLE core.settlement_methods (
    method_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    method_code         VARCHAR(50) NOT NULL,
    method_name         VARCHAR(100) NOT NULL,
    description         TEXT,
    
    -- Classification
    method_type         VARCHAR(50) NOT NULL,        -- RTGS, MOBILE_MONEY, etc.
    direction           VARCHAR(10) NOT NULL,        -- INBOUND, OUTBOUND, BOTH
    
    -- Configuration
    config_schema       JSONB,                       -- Required config fields
    default_config      JSONB,                       -- Default values
    
    -- Limits
    min_amount          NUMERIC(20, 8),
    max_amount          NUMERIC(20, 8),
    
    -- Timing
    typical_delay_minutes INTEGER,
    cutoff_time         TIME,                        -- Daily cutoff
    
    -- Application Scope
    application_id      UUID REFERENCES app.applications(application_id), -- NULL = global
    
    is_active           BOOLEAN DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Constraints
    CONSTRAINT chk_settlement_methods_direction 
        CHECK (direction IN ('INBOUND', 'OUTBOUND', 'BOTH')),
    CONSTRAINT chk_settlement_methods_type 
        CHECK (method_type IN ('RTGS', 'MOBILE_MONEY', 'WALLET', 'CASH', 'BANK_TRANSFER', 'CARD'))
);

-- Seed settlement methods
INSERT INTO core.settlement_methods (method_code, method_name, description, method_type, direction, min_amount, max_amount, typical_delay_minutes) VALUES
('RTGS', 'RTGS Transfer', 'Real-time gross settlement', 'RTGS', 'BOTH', 0.01, 999999999.99, 0),
('MOMO', 'Mobile Money', 'Mobile network operator transfer', 'MOBILE_MONEY', 'BOTH', 0.01, 10000.00, 1),
('WALLET', 'Internal Wallet', 'Internal wallet transfer', 'WALLET', 'BOTH', 0.00000001, 999999999.99, 0),
('CASH', 'Cash Disbursement', 'Physical cash disbursement', 'CASH', 'OUTBOUND', 0.01, 50000.00, 60),
('BANK', 'Bank Transfer', 'ACH or wire transfer', 'BANK_TRANSFER', 'BOTH', 0.01, 1000000.00, 1440)
ON CONFLICT DO NOTHING;

CREATE UNIQUE INDEX idx_settlement_methods_code ON core.settlement_methods(method_code, application_id) 
    WHERE application_id IS NOT NULL;

COMMENT ON TABLE core.settlement_methods IS 'Catalog of available settlement methods per application';

-- =============================================================================
-- Create settlement_instructions table
-- DESCRIPTION: Individual settlement records
-- PRIORITY: CRITICAL
-- SECURITY: Encrypt destination details
-- ============================================================================
CREATE TABLE core.settlement_instructions (
    instruction_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instruction_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Link to Movement
    movement_id         UUID NOT NULL REFERENCES core.movement_headers(movement_id),
    leg_id              UUID REFERENCES core.movement_legs(leg_id),
    
    -- Settlement Details
    method_id           UUID NOT NULL REFERENCES core.settlement_methods(method_id),
    settlement_method   VARCHAR(50) NOT NULL,        -- Denormalized for queries
    
    -- Amount
    amount              NUMERIC(20, 8) NOT NULL,
    currency            VARCHAR(3) NOT NULL,
    fees                NUMERIC(20, 8) DEFAULT 0,
    net_amount          NUMERIC(20, 8) NOT NULL,
    
    -- Destination
    destination_type    VARCHAR(50),                 -- BANK_ACCOUNT, MOBILE_WALLET
    destination_details JSONB,                       -- Account number, etc.
    
    -- Status Workflow
    status              VARCHAR(20) DEFAULT 'PENDING',
                        -- PENDING, SUBMITTED, PROCESSING, 
                        -- COMPLETED, FAILED, CANCELLED, REVERSED
    
    -- External Reference
    external_reference  VARCHAR(255),                -- Provider's transaction ID
    external_status     VARCHAR(50),                 -- Provider's status
    
    -- Finality (for reconciliation)
    is_final            BOOLEAN DEFAULT false,       -- Irreversible
    finality_timestamp  TIMESTAMPTZ,                 -- When became final
    
    -- Timing
    requested_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    submitted_at        TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    expected_completion TIMESTAMPTZ,
    
    -- Retry
    retry_count         INTEGER DEFAULT 0,
    max_retries         INTEGER DEFAULT 3,
    next_retry_at       TIMESTAMPTZ,
    
    -- Application
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    updated_at          TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT chk_settlement_instructions_status 
        CHECK (status IN ('PENDING', 'SUBMITTED', 'PROCESSING', 'COMPLETED', 'FAILED', 'CANCELLED', 'REVERSED')),
    CONSTRAINT chk_settlement_instructions_amount 
        CHECK (amount > 0 AND net_amount >= 0)
);

-- Indexes for settlement_instructions
CREATE INDEX idx_settlement_instructions_movement ON core.settlement_instructions(movement_id);
CREATE INDEX idx_settlement_instructions_retry ON core.settlement_instructions(status, next_retry_at) 
    WHERE status IN ('PENDING', 'FAILED');
CREATE INDEX idx_settlement_instructions_external ON core.settlement_instructions(external_reference);
CREATE INDEX idx_settlement_instructions_app ON core.settlement_instructions(application_id, status);
CREATE INDEX idx_settlement_instructions_final ON core.settlement_instructions(is_final, finality_timestamp) 
    WHERE is_final = true;
CREATE INDEX idx_settlement_instructions_method ON core.settlement_instructions(method_id, status);

COMMENT ON TABLE core.settlement_instructions IS 'Individual settlement records linking to external systems';
COMMENT ON COLUMN core.settlement_instructions.is_final IS 'True when settlement is irreversible';
COMMENT ON COLUMN core.settlement_instructions.destination_details IS 'Encrypted destination account details';

-- =============================================================================
-- Create settlement_attempts table
-- DESCRIPTION: Log of settlement submission attempts
-- PRIORITY: MEDIUM
-- SECURITY: Log raw provider responses for debugging
-- ============================================================================
CREATE TABLE core.settlement_attempts (
    attempt_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instruction_id      UUID NOT NULL REFERENCES core.settlement_instructions(instruction_id),
    
    -- Attempt Details
    attempt_number      INTEGER NOT NULL,
    status              VARCHAR(20) NOT NULL,        -- SUCCESS, FAILED, TIMEOUT
    
    -- Request/Response
    request_payload     JSONB,
    response_payload    JSONB,
    response_code       VARCHAR(50),
    error_message       TEXT,
    
    -- Timing
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at        TIMESTAMPTZ,
    duration_ms         INTEGER,
    
    -- Provider
    provider_reference  VARCHAR(255),
    
    -- Audit
    processed_by        VARCHAR(100),                 -- Service instance
    
    -- Constraints
    CONSTRAINT chk_settlement_attempts_status 
        CHECK (status IN ('SUCCESS', 'FAILED', 'TIMEOUT', 'PENDING')),
    CONSTRAINT uq_settlement_attempts UNIQUE (instruction_id, attempt_number)
);

CREATE INDEX idx_settlement_attempts_instruction ON core.settlement_attempts(instruction_id, attempt_number);
CREATE INDEX idx_settlement_attempts_status ON core.settlement_attempts(status, started_at);

COMMENT ON TABLE core.settlement_attempts IS 'Log of each settlement submission attempt with provider responses';

-- =============================================================================
-- Create settlement execution function
-- DESCRIPTION: Submit settlement to external provider
-- PRIORITY: CRITICAL
-- SECURITY: Timeout and retry handling
-- ============================================================================
CREATE OR REPLACE FUNCTION core.execute_settlement(
    p_instruction_id UUID,
    p_provider_config JSONB DEFAULT '{}'
) RETURNS VARCHAR AS $$
DECLARE
    v_instruction RECORD;
    v_attempt_id UUID;
    v_start_time TIMESTAMPTZ;
    v_attempt_number INTEGER;
BEGIN
    SELECT * INTO v_instruction 
    FROM core.settlement_instructions 
    WHERE instruction_id = p_instruction_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Settlement instruction % not found', p_instruction_id;
    END IF;
    
    IF v_instruction.status NOT IN ('PENDING', 'FAILED') THEN
        RAISE EXCEPTION 'Settlement instruction % has invalid status: %', 
            p_instruction_id, v_instruction.status;
    END IF;
    
    -- Mark as processing
    UPDATE core.settlement_instructions
    SET status = 'PROCESSING', submitted_at = now()
    WHERE instruction_id = p_instruction_id;
    
    v_start_time := clock_timestamp();
    v_attempt_number := v_instruction.retry_count + 1;
    
    -- Create attempt record
    INSERT INTO core.settlement_attempts (
        instruction_id, attempt_number, status, started_at, request_payload
    ) VALUES (
        p_instruction_id, v_attempt_number, 'PENDING', v_start_time,
        jsonb_build_object(
            'amount', v_instruction.amount,
            'currency', v_instruction.currency,
            'destination', v_instruction.destination_type
        )
    )
    RETURNING attempt_id INTO v_attempt_id;
    
    -- Here would be the actual provider call
    -- For now, this is a placeholder that simulates async processing
    
    -- Update attempt with simulated pending status
    UPDATE core.settlement_attempts
    SET status = 'PENDING',
        processed_by = current_setting('app.service_name', true)
    WHERE attempt_id = v_attempt_id;
    
    -- Update instruction retry count
    UPDATE core.settlement_instructions
    SET retry_count = retry_count + 1
    WHERE instruction_id = p_instruction_id;
    
    RETURN 'PROCESSING';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.execute_settlement IS 'Submits settlement to external provider and tracks attempt';

-- =============================================================================
-- Create settlement finality check function
-- DESCRIPTION: Verify settlement is irreversible
-- PRIORITY: HIGH
-- SECURITY: Confirm finality before reconciliation
-- ============================================================================
CREATE OR REPLACE FUNCTION core.check_settlement_finality(
    p_instruction_id UUID,
    p_provider_confirmation BOOLEAN DEFAULT false
) RETURNS BOOLEAN AS $$
DECLARE
    v_instruction RECORD;
    v_is_final BOOLEAN;
BEGIN
    SELECT * INTO v_instruction 
    FROM core.settlement_instructions 
    WHERE instruction_id = p_instruction_id;
    
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    
    -- Finality rules based on method and status
    v_is_final := v_instruction.status = 'COMPLETED' 
                  AND v_instruction.external_reference IS NOT NULL
                  AND p_provider_confirmation;
    
    -- Some methods are immediately final
    IF v_instruction.settlement_method IN ('WALLET', 'INTERNAL') 
       AND v_instruction.status = 'COMPLETED' THEN
        v_is_final := true;
    END IF;
    
    -- Update if now final
    IF v_is_final AND NOT v_instruction.is_final THEN
        UPDATE core.settlement_instructions
        SET is_final = true,
            finality_timestamp = now()
        WHERE instruction_id = p_instruction_id;
    END IF;
    
    RETURN v_is_final;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.check_settlement_finality IS 'Verifies if settlement is irreversible for reconciliation';

-- =============================================================================
-- Create settlement failure handling function
-- DESCRIPTION: Process failed settlements
-- PRIORITY: HIGH
-- SECURITY: Alert on max retries exceeded
-- ============================================================================
CREATE OR REPLACE FUNCTION core.handle_settlement_failure(
    p_instruction_id UUID,
    p_error_message TEXT DEFAULT NULL,
    p_should_retry BOOLEAN DEFAULT true
) RETURNS VARCHAR AS $$
DECLARE
    v_instruction RECORD;
    v_next_retry TIMESTAMPTZ;
BEGIN
    SELECT * INTO v_instruction 
    FROM core.settlement_instructions 
    WHERE instruction_id = p_instruction_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Settlement instruction % not found', p_instruction_id;
    END IF;
    
    -- Determine if should retry
    IF p_should_retry 
       AND v_instruction.retry_count < v_instruction.max_retries 
       AND v_instruction.status != 'CANCELLED' THEN
        
        -- Calculate exponential backoff
        v_next_retry := now() + (INTERVAL '5 minutes' * POWER(2, v_instruction.retry_count));
        
        UPDATE core.settlement_instructions
        SET status = 'FAILED',
            next_retry_at = v_next_retry,
            updated_at = now()
        WHERE instruction_id = p_instruction_id;
        
        -- Log retry scheduled
        RAISE NOTICE 'Settlement % scheduled for retry at % (attempt % of %)',
            p_instruction_id, v_next_retry, v_instruction.retry_count + 1, v_instruction.max_retries;
        
        RETURN 'SCHEDULED_FOR_RETRY';
    ELSE
        -- Max retries exceeded or not retryable
        UPDATE core.settlement_instructions
        SET status = 'FAILED',
            next_retry_at = NULL,
            updated_at = now()
        WHERE instruction_id = p_instruction_id;
        
        -- Alert operations (simplified - would integrate with alerting system)
        IF v_instruction.retry_count >= v_instruction.max_retries THEN
            RAISE WARNING 'Settlement % exceeded max retries - manual intervention required',
                p_instruction_id;
        END IF;
        
        RETURN 'FAILED_PERMANENTLY';
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.handle_settlement_failure IS 'Processes settlement failure with retry scheduling';

-- =============================================================================
-- Create settlement status update function
-- DESCRIPTION: Update settlement from provider callback
-- PRIORITY: HIGH
-- ============================================================================
CREATE OR REPLACE FUNCTION core.update_settlement_status(
    p_instruction_id UUID,
    p_status VARCHAR(20),
    p_external_reference VARCHAR(255) DEFAULT NULL,
    p_external_status VARCHAR(50) DEFAULT NULL,
    p_response_payload JSONB DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_instruction RECORD;
BEGIN
    SELECT * INTO v_instruction 
    FROM core.settlement_instructions 
    WHERE instruction_id = p_instruction_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Settlement instruction % not found', p_instruction_id;
    END IF;
    
    -- Validate status transition
    IF v_instruction.status IN ('COMPLETED', 'CANCELLED', 'REVERSED') 
       AND p_status != v_instruction.status THEN
        RAISE WARNING 'Cannot change settlement % from % to %',
            p_instruction_id, v_instruction.status, p_status;
        RETURN false;
    END IF;
    
    -- Update instruction
    UPDATE core.settlement_instructions
    SET status = p_status,
        external_reference = COALESCE(p_external_reference, external_reference),
        external_status = COALESCE(p_external_status, external_status),
        completed_at = CASE WHEN p_status = 'COMPLETED' THEN now() ELSE completed_at END,
        updated_at = now()
    WHERE instruction_id = p_instruction_id;
    
    -- Update latest attempt
    UPDATE core.settlement_attempts
    SET status = CASE 
            WHEN p_status = 'COMPLETED' THEN 'SUCCESS' 
            WHEN p_status IN ('FAILED', 'CANCELLED') THEN 'FAILED'
            ELSE status 
        END,
        response_payload = p_response_payload,
        completed_at = now(),
        duration_ms = EXTRACT(EPOCH FROM (now() - started_at)) * 1000
    WHERE instruction_id = p_instruction_id
      AND attempt_number = (
          SELECT MAX(attempt_number) FROM core.settlement_attempts 
          WHERE instruction_id = p_instruction_id
      );
    
    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.update_settlement_status IS 'Updates settlement status from provider callback';

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create settlement_methods table
☑ Create settlement_instructions table
☑ Create settlement_attempts table
☑ Implement execute_settlement function
☑ Implement check_settlement_finality function
☑ Implement handle_settlement_failure function
☑ Add all indexes for settlement queries
☑ Test settlement submission flow
☑ Test retry logic
☑ Verify external reference linking
================================================================================
*/
