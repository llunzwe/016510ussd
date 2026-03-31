-- ============================================================================
-- USSD PENDING TRANSACTIONS
-- ============================================================================
-- Purpose: Track financial transactions initiated via USSD that require
--          asynchronous processing, confirmation, or external callbacks.
-- Context: USSD sessions are synchronous (request-response) but many
--          financial operations are asynchronous (bank transfers, bill payments).
--          This table bridges the gap between the USSD session and the
--          eventual transaction completion.
--
-- COMPLIANCE & STANDARDS:
--   ISO/IEC 27001:2022 - Information Security Management
--     * A.8.1: Asset management - transaction data classification
--     * A.8.5: Secure authentication - auth_method tracking
--     * A.8.11: Session management - session-transaction linkage
--     * A.8.12: Audit logging - transaction_hash chain
--     * A.8.15: Logging - stage_history for complete audit trail
--
--   PCI DSS v4.0 - Payment Card Industry Data Security Standard
--     * Requirement 3: Protect stored cardholder data
--     * Requirement 4: Encrypt transmission of cardholder data
--     * Requirement 10: Log and monitor all access to network resources
--     * Idempotency key support for duplicate prevention
--
--   ISO 31000:2018 - Risk Management
--     * Risk scoring integration (risk_score, risk_flags)
--     * Velocity limit enforcement per transaction
--     * Compliance status tracking (AML/KYC integration)
--
--   AML/CFT Compliance:
--     * aml_check_status for anti-money laundering screening
--     * kyc_level_required for identity verification levels
--     * Suspicious Activity Report (SAR) filing support
--
--   ISO/IEC 27035-2:2023 - Incident Management
--     * SIM swap detection before transaction processing
--     * Fraud pattern detection via risk_flags
--     * Automatic escalation for high-risk transactions
--
-- TRANSACTION LIFECYCLE:
--   USSD Initiated -> Pending -> Processing -> [Completed | Failed | Timeout]
--                                      |
--                                      v
--                               Awaiting Callback
--
-- SECURITY FEATURES:
--   - Double-spend prevention via idempotency keys
--   - Transaction hash chain for immutability verification
--   - Stage timeouts with automatic escalation
--   - Device fingerprint correlation for fraud detection
-- ============================================================================

-- ----------------------------------------------------------------------------
-- TABLE: pending_transactions
-- ----------------------------------------------------------------------------
-- Stores all transactions initiated through USSD that haven't reached
-- a final state. Acts as a queue and audit log for in-flight operations.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS pending_transactions (
    -- Primary identifier
    transaction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- External reference IDs
    external_transaction_id VARCHAR(128), -- From payment processor
    external_reference VARCHAR(128), -- Client-provided reference
    ledger_tx_hash VARCHAR(64), -- Reference to immutable ledger
    
    -- Session linkage
    session_id UUID NOT NULL,
    msisdn VARCHAR(15) NOT NULL,
    
    -- Transaction classification
    transaction_type VARCHAR(32) NOT NULL,
    -- TRANSFER, PAYMENT, WITHDRAWAL, DEPOSIT, AIRTIME, BILL_PAY, 
    -- SUBSCRIPTION, REFUND, REVERSAL
    
    -- Transaction category for business logic
    transaction_category VARCHAR(64),
    -- Examples: P2P_TRANSFER, MERCHANT_PAYMENT, UTILITY_BILL, LOAN_REPAYMENT
    
    -- Financial details
    amount DECIMAL(18, 4) NOT NULL,
    currency_code CHAR(3) NOT NULL DEFAULT 'TZS',
    fee_amount DECIMAL(18, 4) DEFAULT 0,
    tax_amount DECIMAL(18, 4) DEFAULT 0,
    total_amount DECIMAL(18, 4) NOT NULL, -- amount + fee + tax
    
    -- Source and destination
    source_account VARCHAR(64) NOT NULL, -- Wallet/account ID
    destination_account VARCHAR(64), -- May be NULL for cash withdrawals
    destination_type VARCHAR(32), -- ACCOUNT, WALLET, MERCHANT, BANK, MOBILE
    destination_details JSONB, -- Additional recipient info (name, bank, etc.)
    
    -- Transaction status
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    -- PENDING: Initiated, awaiting processing
    -- VALIDATING: Running pre-transaction checks
    -- PROCESSING: With payment processor
    -- AWAITING_CALLBACK: Waiting for external notification
    -- AWAITING_CONFIRMATION: Needs user confirmation (2FA)
    -- COMPLETED: Successfully processed
    -- FAILED: Processing failed (retry may be possible)
    -- CANCELLED: Cancelled by user or system
    -- TIMEOUT: Exceeded maximum processing time
    -- REVERSED: Reversed after completion
    
    -- Status details
    status_reason VARCHAR(256),
    status_details JSONB, -- Detailed error info or completion metadata
    
    -- Processing stages tracking
    current_stage VARCHAR(64) DEFAULT 'INIT',
    stage_history JSONB DEFAULT '[]', -- Array of stage transitions
    
    -- Risk and compliance
    risk_score DECIMAL(3, 2), -- 0.00 to 1.00
    risk_flags TEXT[], -- HIGH_AMOUNT, NEW_RECIPIENT, SUSPICIOUS_PATTERN
    compliance_status VARCHAR(32) DEFAULT 'PENDING',
    -- PENDING, CLEARED, FLAGGED, BLOCKED, SAR_FILED
    aml_check_status VARCHAR(32) DEFAULT 'PENDING',
    kyc_level_required INT DEFAULT 1,
    kyc_level_verified INT,
    
    -- Security
    device_fingerprint_id UUID,
    auth_method VARCHAR(32), -- PIN, OTP, BIOMETRIC, HARDWARE_TOKEN
    auth_timestamp TIMESTAMPTZ,
    pin_attempts INT DEFAULT 0,
    
    -- SIM swap detection
    sim_swap_checked BOOLEAN DEFAULT FALSE,
    days_since_sim_swap INT,
    sim_swap_risk_applied BOOLEAN DEFAULT FALSE,
    
    -- Confirmation requirements
    requires_confirmation BOOLEAN DEFAULT FALSE,
    confirmation_code VARCHAR(32),
    confirmation_expires_at TIMESTAMPTZ,
    confirmed_at TIMESTAMPTZ,
    confirmed_by_msisdn VARCHAR(15), -- For third-party confirmations
    
    -- Retry configuration
    max_retries INT DEFAULT 3,
    retry_count INT DEFAULT 0,
    last_retry_at TIMESTAMPTZ,
    next_retry_at TIMESTAMPTZ,
    
    -- Callback configuration
    callback_url VARCHAR(512),
    callback_payload JSONB,
    callback_retry_count INT DEFAULT 0,
    last_callback_at TIMESTAMPTZ,
    callback_delivered BOOLEAN DEFAULT FALSE,
    
    -- Timing
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL, -- Maximum time to complete
    processed_at TIMESTAMPTZ, -- When sent to processor
    completed_at TIMESTAMPTZ, -- Final state reached
    
    -- Time limits per stage (in seconds)
    stage_time_limits JSONB DEFAULT '{
        "PENDING": 300,
        "VALIDATING": 30,
        "PROCESSING": 60,
        "AWAITING_CALLBACK": 300,
        "AWAITING_CONFIRMATION": 300
    }',
    
    -- Idempotency
    idempotency_key VARCHAR(128), -- Client-generated unique key
    idempotency_scope VARCHAR(64) DEFAULT 'SESSION', -- SESSION, MSISDN, GLOBAL
    
    -- User context
    user_agent VARCHAR(256),
    ip_address INET,
    geolocation JSONB, -- {lat, lon, accuracy, source}
    
    -- Notifications
    notification_sent BOOLEAN DEFAULT FALSE,
    notification_channels TEXT[], -- SMS, PUSH, EMAIL
    
    -- Immutable ledger
    ledger_sequence BIGINT,
    ledger_entry_type VARCHAR(32), -- DEBIT, CREDIT, FEE, TAX
    
    -- Audit and integrity
    transaction_hash VARCHAR(64), -- SHA-256 of transaction data
    previous_transaction_hash VARCHAR(64), -- Chain linkage
    audit_trail JSONB DEFAULT '[]', -- All status changes
    
    -- Finalization
    is_finalized BOOLEAN DEFAULT FALSE,
    finalized_at TIMESTAMPTZ,
    finalized_by VARCHAR(128),
    
    -- Constraints
    CONSTRAINT valid_status CHECK (
        status IN ('PENDING', 'VALIDATING', 'PROCESSING', 'AWAITING_CALLBACK',
                   'AWAITING_CONFIRMATION', 'COMPLETED', 'FAILED', 'CANCELLED',
                   'TIMEOUT', 'REVERSED')
    ),
    CONSTRAINT valid_compliance CHECK (
        compliance_status IN ('PENDING', 'CLEARED', 'FLAGGED', 'BLOCKED', 'SAR_FILED')
    ),
    CONSTRAINT valid_amount CHECK (amount > 0),
    CONSTRAINT valid_total_amount CHECK (total_amount >= amount),
    CONSTRAINT valid_risk_score CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 1)),
    CONSTRAINT valid_retry_count CHECK (retry_count <= max_retries),
    CONSTRAINT valid_msisdn_format CHECK (msisdn ~ '^\+[1-9][0-9]{7,14}$'),
    
    -- Foreign key to session
    CONSTRAINT fk_session FOREIGN KEY (session_id) 
        REFERENCES ussd_session_state(session_id) ON DELETE SET NULL,
    
    -- Idempotency unique constraints based on scope
    CONSTRAINT unique_idempotency_session UNIQUE (session_id, idempotency_key),
    CONSTRAINT unique_idempotency_msisdn UNIQUE (msisdn, idempotency_key)
);

-- ----------------------------------------------------------------------------
-- FUNCTION: calculate_transaction_hash
-- ----------------------------------------------------------------------------
-- Calculates SHA-256 hash for transaction integrity
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION calculate_transaction_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_hash_input TEXT;
    v_prev_hash VARCHAR(64);
BEGIN
    -- Get previous transaction hash for this MSISDN
    SELECT transaction_hash INTO v_prev_hash
    FROM pending_transactions
    WHERE msisdn = NEW.msisdn
      AND created_at < NEW.created_at
    ORDER BY created_at DESC
    LIMIT 1;
    
    -- Build hash input
    v_hash_input := COALESCE(v_prev_hash, 'genesis') || 
                    NEW.transaction_id::TEXT || 
                    NEW.msisdn || 
                    NEW.amount::TEXT ||
                    COALESCE(NEW.source_account, '') ||
                    COALESCE(NEW.destination_account, '') ||
                    NEW.created_at::TEXT;
    
    NEW.previous_transaction_hash := v_prev_hash;
    NEW.transaction_hash := encode(digest(v_hash_input, 'sha256'), 'hex');
    NEW.updated_at := NOW();
    
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_calculate_transaction_hash
    BEFORE INSERT ON pending_transactions
    FOR EACH ROW
    EXECUTE FUNCTION calculate_transaction_hash();

-- ----------------------------------------------------------------------------
-- FUNCTION: check_transaction_idempotency
-- ----------------------------------------------------------------------------
-- Checks for duplicate transactions based on idempotency key
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION check_transaction_idempotency(
    p_idempotency_key VARCHAR(128),
    p_scope VARCHAR(64),
    p_session_id UUID,
    p_msisdn VARCHAR(15)
)
RETURNS TABLE (
    exists BOOLEAN,
    existing_transaction_id UUID,
    existing_status VARCHAR(32),
    is_expired BOOLEAN
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_existing RECORD;
BEGIN
    -- Look for existing transaction with same idempotency key
    SELECT t.transaction_id, t.status, t.expires_at, t.created_at
    INTO v_existing
    FROM pending_transactions t
    WHERE t.idempotency_key = p_idempotency_key
      AND (
          -- Session scope: same session only
          (p_scope = 'SESSION' AND t.session_id = p_session_id)
          -- MSISDN scope: same user only
          OR (p_scope = 'MSISDN' AND t.msisdn = p_msisdn)
          -- Global scope: any user
          OR p_scope = 'GLOBAL'
      )
      -- Only consider recent transactions (24h TTL)
      AND t.created_at > NOW() - INTERVAL '24 hours'
    ORDER BY t.created_at DESC
    LIMIT 1;
    
    IF FOUND THEN
        exists := TRUE;
        existing_transaction_id := v_existing.transaction_id;
        existing_status := v_existing.status;
        is_expired := v_existing.expires_at < NOW() AND 
                      v_existing.status NOT IN ('COMPLETED', 'FAILED', 'CANCELLED');
    ELSE
        exists := FALSE;
        existing_transaction_id := NULL;
        existing_status := NULL;
        is_expired := FALSE;
    END IF;
    
    RETURN NEXT;
END;
$$;

-- ----------------------------------------------------------------------------
-- FUNCTION: calculate_retry_delay
-- ----------------------------------------------------------------------------
-- Calculates exponential backoff delay for retries
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION calculate_retry_delay(
    p_retry_count INT,
    p_base_delay_seconds INT DEFAULT 5
)
RETURNS INTERVAL
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    v_delay_seconds INT;
BEGIN
    -- Exponential backoff: base_delay * 2^(retry_count-1)
    -- Retry 1: 5 seconds
    -- Retry 2: 25 seconds
    -- Retry 3: 125 seconds
    IF p_retry_count <= 0 THEN
        v_delay_seconds := 0;
    ELSE
        v_delay_seconds := p_base_delay_seconds * POWER(2, p_retry_count - 1);
    END IF;
    
    -- Cap at 5 minutes
    v_delay_seconds := LEAST(v_delay_seconds, 300);
    
    RETURN (v_delay_seconds || ' seconds')::INTERVAL;
END;
$$;

-- ----------------------------------------------------------------------------
-- FUNCTION: process_transaction_state
-- ----------------------------------------------------------------------------
-- Handles transaction state machine transitions
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION process_transaction_state(
    p_transaction_id UUID,
    p_new_status VARCHAR(32),
    p_status_reason VARCHAR(256) DEFAULT NULL,
    p_status_details JSONB DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_tx RECORD;
    v_valid_transition BOOLEAN := FALSE;
    v_new_stage VARCHAR(64);
BEGIN
    -- Get current transaction state
    SELECT * INTO v_tx FROM pending_transactions WHERE transaction_id = p_transaction_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction not found: %', p_transaction_id;
    END IF;
    
    -- Validate state transition
    v_valid_transition := CASE 
        -- From PENDING
        WHEN v_tx.status = 'PENDING' AND p_new_status IN ('VALIDATING', 'PROCESSING', 'CANCELLED', 'FAILED') THEN TRUE
        -- From VALIDATING
        WHEN v_tx.status = 'VALIDATING' AND p_new_status IN ('PROCESSING', 'CANCELLED', 'FAILED') THEN TRUE
        -- From PROCESSING
        WHEN v_tx.status = 'PROCESSING' AND p_new_status IN ('AWAITING_CALLBACK', 'COMPLETED', 'FAILED', 'TIMEOUT') THEN TRUE
        -- From AWAITING_CALLBACK
        WHEN v_tx.status = 'AWAITING_CALLBACK' AND p_new_status IN ('COMPLETED', 'FAILED', 'TIMEOUT') THEN TRUE
        -- From AWAITING_CONFIRMATION
        WHEN v_tx.status = 'AWAITING_CONFIRMATION' AND p_new_status IN ('COMPLETED', 'CANCELLED', 'FAILED', 'TIMEOUT') THEN TRUE
        -- Terminal states
        WHEN v_tx.status IN ('COMPLETED', 'FAILED', 'CANCELLED', 'TIMEOUT', 'REVERSED') THEN FALSE
        ELSE FALSE
    END;
    
    IF NOT v_valid_transition THEN
        RAISE EXCEPTION 'Invalid state transition from % to %', v_tx.status, p_new_status;
    END IF;
    
    -- Determine stage based on status
    v_new_stage := CASE p_new_status
        WHEN 'PENDING' THEN 'INIT'
        WHEN 'VALIDATING' THEN 'VALIDATION'
        WHEN 'PROCESSING' THEN 'PROCESSING'
        WHEN 'AWAITING_CALLBACK' THEN 'CALLBACK'
        WHEN 'AWAITING_CONFIRMATION' THEN 'CONFIRMATION'
        WHEN 'COMPLETED' THEN 'COMPLETE'
        WHEN 'FAILED' THEN 'FAILED'
        WHEN 'CANCELLED' THEN 'CANCELLED'
        WHEN 'TIMEOUT' THEN 'TIMEOUT'
        ELSE v_tx.current_stage
    END;
    
    -- Update transaction
    UPDATE pending_transactions
    SET 
        status = p_new_status,
        status_reason = p_status_reason,
        status_details = COALESCE(p_status_details, status_details),
        current_stage = v_new_stage,
        stage_history = stage_history || jsonb_build_object(
            'stage', v_new_stage,
            'status', p_new_status,
            'timestamp', NOW(),
            'reason', p_status_reason
        ),
        processed_at = CASE WHEN p_new_status = 'PROCESSING' THEN NOW() ELSE processed_at END,
        completed_at = CASE WHEN p_new_status IN ('COMPLETED', 'FAILED', 'CANCELLED', 'TIMEOUT') THEN NOW() ELSE completed_at END,
        is_finalized = CASE WHEN p_new_status IN ('COMPLETED', 'FAILED', 'CANCELLED', 'TIMEOUT', 'REVERSED') THEN TRUE ELSE is_finalized END,
        finalized_at = CASE WHEN p_new_status IN ('COMPLETED', 'FAILED', 'CANCELLED', 'TIMEOUT', 'REVERSED') THEN NOW() ELSE finalized_at END,
        next_retry_at = CASE 
            WHEN p_new_status = 'FAILED' AND retry_count < max_retries 
            THEN NOW() + calculate_retry_delay(retry_count + 1)
            ELSE next_retry_at
        END
    WHERE transaction_id = p_transaction_id;
    
    -- Record event
    PERFORM record_transaction_event(
        p_transaction_id,
        'STATUS_CHANGE',
        jsonb_build_object(
            'from_status', v_tx.status,
            'to_status', p_new_status,
            'stage', v_new_stage,
            'reason', p_status_reason
        )
    );
    
    RETURN TRUE;
END;
$$;

-- ----------------------------------------------------------------------------
-- FUNCTION: apply_sim_swap_risk
-- ----------------------------------------------------------------------------
-- Applies risk adjustments based on SIM swap status
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION apply_sim_swap_risk(
    p_transaction_id UUID,
    p_days_since_sim_swap INT
)
RETURNS TABLE (
    risk_increase DECIMAL(3,2),
    requires_additional_auth BOOLEAN,
    transaction_limit DECIMAL(18,4),
    restriction_message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_risk_increase DECIMAL(3,2) := 0;
    v_requires_auth BOOLEAN := FALSE;
    v_limit DECIMAL(18,4) := 999999999.99; -- No limit
    v_message TEXT := NULL;
BEGIN
    -- Calculate risk increase based on time since swap
    IF p_days_since_sim_swap IS NULL OR p_days_since_sim_swap > 30 THEN
        -- No recent swap or very old
        v_risk_increase := 0;
    ELSIF p_days_since_sim_swap < 1 THEN
        -- Less than 24 hours: highest risk
        v_risk_increase := 0.50;
        v_requires_auth := TRUE;
        v_limit := 0; -- Block all
        v_message := 'Transactions blocked due to recent SIM change. Please visit a branch.';
    ELSIF p_days_since_sim_swap < 3 THEN
        -- 1-3 days: high risk
        v_risk_increase := 0.30;
        v_requires_auth := TRUE;
        v_limit := 50000; -- ~$20 limit
        v_message := 'Transaction limit reduced due to recent SIM change.';
    ELSIF p_days_since_sim_swap < 7 THEN
        -- 3-7 days: medium risk
        v_risk_increase := 0.15;
        v_limit := 200000; -- ~$80 limit
    ELSE
        -- 7-30 days: low risk
        v_risk_increase := 0.05;
    END IF;
    
    -- Update transaction with SIM swap risk
    UPDATE pending_transactions
    SET 
        sim_swap_checked = TRUE,
        days_since_sim_swap = p_days_since_sim_swap,
        sim_swap_risk_applied = TRUE,
        risk_score = LEAST(COALESCE(risk_score, 0) + v_risk_increase, 1.0)
    WHERE transaction_id = p_transaction_id;
    
    risk_increase := v_risk_increase;
    requires_additional_auth := v_requires_auth;
    transaction_limit := v_limit;
    restriction_message := v_message;
    
    RETURN NEXT;
END;
$$;

-- ----------------------------------------------------------------------------
-- TABLE: transaction_events
-- ----------------------------------------------------------------------------
-- Immutable event log for all transaction state changes.
-- Supports event sourcing pattern for transaction reconstruction.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS transaction_events (
    event_id BIGSERIAL PRIMARY KEY,
    transaction_id UUID NOT NULL,
    
    -- Event details
    event_type VARCHAR(64) NOT NULL,
    -- CREATED, VALIDATION_PASSED, VALIDATION_FAILED, SUBMITTED, 
    -- CALLBACK_RECEIVED, COMPLETED, FAILED, RETRY_SCHEDULED, REVERSAL_INITIATED
    
    event_data JSONB NOT NULL, -- Event-specific payload
    
    -- State snapshot at this point
    status_snapshot VARCHAR(32),
    context_snapshot JSONB,
    
    -- Event metadata
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source VARCHAR(64), -- USSD_GATEWAY, PAYMENT_PROCESSOR, SCHEDULER, ADMIN
    source_ip INET,
    
    -- Actor information
    actor_type VARCHAR(32), -- SYSTEM, USER, ADMIN, EXTERNAL
    actor_id VARCHAR(128),
    
    -- Event integrity
    event_hash VARCHAR(64),
    previous_event_hash VARCHAR(64),
    
    -- Partitioning key for efficient cleanup
    created_date DATE NOT NULL DEFAULT CURRENT_DATE,
    
    CONSTRAINT fk_transaction FOREIGN KEY (transaction_id) 
        REFERENCES pending_transactions(transaction_id) ON DELETE CASCADE
) PARTITION BY RANGE (created_date);

-- Create initial partitions
CREATE TABLE IF NOT EXISTS transaction_events_2024_01 PARTITION OF transaction_events
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

CREATE TABLE IF NOT EXISTS transaction_events_2024_02 PARTITION OF transaction_events
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');

-- ----------------------------------------------------------------------------
-- FUNCTION: record_transaction_event
-- ----------------------------------------------------------------------------
-- Records a transaction event with hash chain
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION record_transaction_event(
    p_transaction_id UUID,
    p_event_type VARCHAR(64),
    p_event_data JSONB,
    p_source VARCHAR(64) DEFAULT 'USSD_GATEWAY',
    p_actor_type VARCHAR(32) DEFAULT 'SYSTEM'
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_event_id BIGINT;
    v_prev_hash VARCHAR(64);
    v_current_status VARCHAR(32);
BEGIN
    -- Get current transaction status
    SELECT status INTO v_current_status 
    FROM pending_transactions 
    WHERE transaction_id = p_transaction_id;
    
    -- Get previous event hash
    SELECT event_hash INTO v_prev_hash
    FROM transaction_events
    WHERE transaction_id = p_transaction_id
    ORDER BY event_id DESC
    LIMIT 1;
    
    INSERT INTO transaction_events (
        transaction_id,
        event_type,
        event_data,
        status_snapshot,
        source,
        actor_type,
        previous_event_hash,
        event_hash
    ) VALUES (
        p_transaction_id,
        p_event_type,
        p_event_data,
        v_current_status,
        p_source,
        p_actor_type,
        v_prev_hash,
        encode(digest(
            COALESCE(v_prev_hash, '') || p_transaction_id::TEXT || p_event_type || NOW()::TEXT,
            'sha256'
        ), 'hex')
    )
    RETURNING event_id INTO v_event_id;
    
    RETURN v_event_id;
END;
$$;

-- ----------------------------------------------------------------------------
-- FUNCTION: create_transaction_partitions
-- ----------------------------------------------------------------------------
-- Creates monthly partitions for transaction_events
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION create_transaction_partitions(
    p_year INT,
    p_month INT
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_partition_name TEXT;
    v_start_date DATE;
    v_end_date DATE;
BEGIN
    v_partition_name := 'transaction_events_' || p_year || '_' || LPAD(p_month::TEXT, 2, '0');
    v_start_date := MAKE_DATE(p_year, p_month, 1);
    v_end_date := v_start_date + INTERVAL '1 month';
    
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF transaction_events
         FOR VALUES FROM (%L) TO (%L)',
        v_partition_name,
        v_start_date,
        v_end_date
    );
    
    RETURN v_partition_name;
END;
$$;

-- ----------------------------------------------------------------------------
-- TABLE: transaction_timeouts
-- ----------------------------------------------------------------------------
-- Dedicated table for timeout tracking and recovery.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS transaction_timeouts (
    timeout_id BIGSERIAL PRIMARY KEY,
    transaction_id UUID NOT NULL UNIQUE,
    
    -- Timeout configuration
    timeout_type VARCHAR(32) NOT NULL, -- STAGE_TIMEOUT, ABSOLUTE_TIMEOUT, IDLE_TIMEOUT
    scheduled_timeout_at TIMESTAMPTZ NOT NULL,
    
    -- Resolution
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMPTZ,
    resolution_action VARCHAR(64), -- AUTO_CANCEL, AUTO_RETRY, ALERT_ADMIN
    
    -- Recovery info
    recovery_attempted BOOLEAN DEFAULT FALSE,
    recovery_action VARCHAR(256),
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    CONSTRAINT fk_transaction FOREIGN KEY (transaction_id) 
        REFERENCES pending_transactions(transaction_id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------------------
-- FUNCTION: schedule_transaction_timeout
-- ----------------------------------------------------------------------------
-- Schedules a timeout for a transaction
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION schedule_transaction_timeout(
    p_transaction_id UUID,
    p_timeout_type VARCHAR(32),
    p_timeout_seconds INT
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_timeout_id BIGINT;
BEGIN
    INSERT INTO transaction_timeouts (
        transaction_id,
        timeout_type,
        scheduled_timeout_at
    ) VALUES (
        p_transaction_id,
        p_timeout_type,
        NOW() + (p_timeout_seconds || ' seconds')::INTERVAL
    )
    ON CONFLICT (transaction_id) DO UPDATE SET
        timeout_type = p_timeout_type,
        scheduled_timeout_at = NOW() + (p_timeout_seconds || ' seconds')::INTERVAL,
        resolved = FALSE,
        resolved_at = NULL,
        resolution_action = NULL
    RETURNING timeout_id INTO v_timeout_id;
    
    RETURN v_timeout_id;
END;
$$;

-- ----------------------------------------------------------------------------
-- FUNCTION: process_expired_timeouts
-- ----------------------------------------------------------------------------
-- Processes expired transaction timeouts
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION process_expired_timeouts(
    p_batch_size INT DEFAULT 100
)
RETURNS TABLE (
    processed_count INT,
    cancelled_count INT,
    retried_count INT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_timeout RECORD;
    v_processed INT := 0;
    v_cancelled INT := 0;
    v_retried INT := 0;
BEGIN
    FOR v_timeout IN
        SELECT t.*, tx.retry_count, tx.max_retries, tx.status
        FROM transaction_timeouts t
        JOIN pending_transactions tx ON tx.transaction_id = t.transaction_id
        WHERE t.resolved = FALSE
          AND t.scheduled_timeout_at < NOW()
          AND tx.status NOT IN ('COMPLETED', 'FAILED', 'CANCELLED', 'TIMEOUT')
        LIMIT p_batch_size
    LOOP
        v_processed := v_processed + 1;
        
        -- Determine action based on retry count
        IF v_timeout.retry_count < v_timeout.max_retries THEN
            -- Schedule retry
            UPDATE transaction_timeouts
            SET resolved = TRUE,
                resolved_at = NOW(),
                resolution_action = 'AUTO_RETRY'
            WHERE timeout_id = v_timeout.timeout_id;
            
            UPDATE pending_transactions
            SET retry_count = retry_count + 1,
                last_retry_at = NOW(),
                next_retry_at = NOW() + calculate_retry_delay(retry_count + 1),
                status = 'PENDING'
            WHERE transaction_id = v_timeout.transaction_id;
            
            v_retried := v_retried + 1;
        ELSE
            -- Cancel transaction
            PERFORM process_transaction_state(
                v_timeout.transaction_id,
                'TIMEOUT',
                'Auto-cancelled due to timeout and max retries exceeded'
            );
            
            UPDATE transaction_timeouts
            SET resolved = TRUE,
                resolved_at = NOW(),
                resolution_action = 'AUTO_CANCEL'
            WHERE timeout_id = v_timeout.timeout_id;
            
            v_cancelled := v_cancelled + 1;
        END IF;
    END LOOP;
    
    processed_count := v_processed;
    cancelled_count := v_cancelled;
    retried_count := v_retried;
    
    RETURN NEXT;
END;
$$;

-- ----------------------------------------------------------------------------
-- INDEXES
-- ----------------------------------------------------------------------------

-- Fast lookup by session
CREATE INDEX idx_pending_tx_session 
    ON pending_transactions(session_id, created_at DESC);

-- Status-based polling queries
CREATE INDEX idx_pending_tx_status_time 
    ON pending_transactions(status, expires_at) 
    WHERE status IN ('PENDING', 'PROCESSING', 'AWAITING_CALLBACK');

-- MSISDN query for user history
CREATE INDEX idx_pending_tx_msisdn 
    ON pending_transactions(msisdn, created_at DESC);

-- Idempotency lookup
CREATE INDEX idx_pending_tx_idempotency 
    ON pending_transactions(idempotency_key, idempotency_scope) 
    WHERE idempotency_key IS NOT NULL;

-- External reference lookup
CREATE INDEX idx_pending_tx_external 
    ON pending_transactions(external_transaction_id, external_reference);

-- SIM swap check tracking
CREATE INDEX idx_pending_tx_sim_swap 
    ON pending_transactions(sim_swap_checked, days_since_sim_swap)
    WHERE sim_swap_checked = TRUE;

-- Timeout scheduling
CREATE INDEX idx_tx_timeouts_scheduled 
    ON transaction_timeouts(scheduled_timeout_at) 
    WHERE resolved = FALSE;

-- Event queries
CREATE INDEX idx_tx_events_transaction 
    ON transaction_events(transaction_id, occurred_at DESC);

-- ----------------------------------------------------------------------------
-- SECURITY CONSIDERATIONS
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.5 - Secure transaction authentication
-- [ISO/IEC 27001:2022] A.8.12 - Transaction audit logging
-- [PCI DSS v4.0] Requirement 3 - Cardholder data protection
-- [PCI DSS v4.0] Requirement 10 - Access logging
-- [ISO 31000:2018] Transaction risk scoring
/*
1. DOUBLE-SPEND PREVENTION:
   - Idempotency keys prevent duplicate submissions
   - Database unique constraints on (session_id, idempotency_key)
   - Pessimistic locking during transaction processing

2. AMOUNT MANIPULATION:
   - Amount calculated server-side, never trust client
   - Verify amount matches between request and confirmation
   - Immutable once in PROCESSING state

3. ROLLBACK ATTACKS:
   - Completed transactions cannot be deleted
   - Reversals create new reversal transactions
   - All reversals require approval and audit trail

4. CALLBACK SPOOFING:
   - Verify callback signatures with shared secrets
   - Whitelist callback source IPs
   - Idempotent processing prevents double-crediting

5. ENUMERATION:
   - Don't expose transaction IDs in sequential format
   - Rate limit transaction status queries
   - Mask sensitive details in responses

6. RACE CONDITIONS:
   - Use SELECT FOR UPDATE when checking status
   - Implement optimistic locking with version column
   - Single-threaded processing per transaction
*/

-- ----------------------------------------------------------------------------
-- SESSION TIMEOUT HANDLING
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.11 - Transaction stage timeouts
-- [PCI DSS v4.0] Transaction completion time limits
-- Stage-specific timeouts: PENDING(5min), PROCESSING(60sec)
/*
Transaction-specific timeout strategies:

1. STAGE TIMEOUTS:
   - PENDING: 5 minutes (user must confirm)
   - VALIDATING: 30 seconds (fraud checks)
   - PROCESSING: 60 seconds (processor timeout)
   - AWAITING_CALLBACK: 5 minutes (external system)
   - AWAITING_CONFIRMATION: 5 minutes (2FA entry)

2. ABSUTE TIMEOUT:
   - Maximum 10 minutes from creation to completion
   - Prevents orphaned transactions
   - Force-fail after absolute timeout

3. IDLE TIMEOUT:
   - No user activity for 2 minutes
   - Cancel transaction and release held funds

4. TIMEOUT RECOVERY:
   - Query processor for transaction status
   - If unknown: mark as PENDING_INVESTIGATION
   - Manual review for amounts > threshold
   - Auto-cancel for small amounts after grace period

5. USSD SESSION DECOUPLED:
   - Transaction may outlive USSD session
   - Async completion via SMS notification
   - Status check via status shortcode (*123*99#)
*/

-- ----------------------------------------------------------------------------
-- SIM SWAP DETECTION INTEGRATION
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27035-2:2023] Pre-transaction SIM swap verification
-- [ISO 31000:2018] Risk-adjusted transaction limits
-- Post-swap restrictions: 72h reduced limits, OTP required
-- GSMA IR.71: Enhanced verification post-SIM swap
/*
SIM swap detection for transaction security:

1. PRE-TRANSACTION CHECKS:
   - Query SIM swap status before PROCESSING stage
   - If swap detected within 72 hours: escalate risk_score
   - For high-value: block, require in-branch
   - For low-value: additional OTP required

2. RISK SCORING:
   - Recent SIM swap (>1% risk increase per day since swap)
   - New device fingerprint (>0.5% risk increase)
   - Combined with amount and velocity for final score

3. POST-TRANSACTION MONITORING:
   - Flag transactions completed shortly after SIM swap
   - Retroactive alerts for suspicious patterns
   - Integration with fraud detection systems

4. CONFIRMATION REQUIREMENTS:
   - SIM swap detected -> require confirmation_code via alternate channel
   - Delay high-value transactions by 24h post-SIM swap
   - Educate user about SIM swap risks during transaction

5. DEVICE FINGERPRINT CORRELATION:
   - New device + recent SIM swap = high risk
   - Known device + SIM swap = medium risk (possible upgrade)
   - Track correlation in device_fingerprints table
*/

-- ----------------------------------------------------------------------------
-- SAMPLE DATA (Development/Testing Only)
-- ----------------------------------------------------------------------------

/*
INSERT INTO pending_transactions (
    transaction_id, session_id, msisdn, transaction_type,
    amount, currency_code, total_amount,
    source_account, destination_account, destination_type,
    status, expires_at, created_by
) VALUES (
    '660e8400-e29b-41d4-a716-446655440001',
    '550e8400-e29b-41d4-a716-446655440000',
    '+255712345678',
    'TRANSFER',
    10000.00, 'TZS', 10050.00,
    'WALLET_12345', 'WALLET_67890', 'WALLET',
    'PENDING',
    NOW() + INTERVAL '5 minutes',
    'ussd_gateway'
);
*/
