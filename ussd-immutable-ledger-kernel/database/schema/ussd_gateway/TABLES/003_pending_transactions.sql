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
        REFERENCES ussd_session_state(session_id) ON DELETE SET NULL
);

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

-- Create monthly partitions for transaction_events
-- (Execute these as needed, or use pg_partman)
-- CREATE TABLE transaction_events_2024_01 PARTITION OF transaction_events
--     FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

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
-- TODO: IMPLEMENTATION INSTRUCTIONS
-- ----------------------------------------------------------------------------

/*
TODO [TX-001]: Implement transaction state machine
  - States: PENDING -> VALIDATING -> PROCESSING -> AWAITING_CALLBACK -> COMPLETED
  - Handle failure paths at each stage
  - Implement idempotency checks at entry points
  
  State transitions:
  ```
  PENDING -> VALIDATING -> PROCESSING -> AWAITING_CALLBACK -> COMPLETED
     |           |            |               |                 |
     v           v            v               v                 v
  CANCELLED   FAILED       FAILED         TIMEOUT           REVERSED
  ```

TODO [TX-002]: Implement idempotency handling
  - Check idempotency_key on transaction creation
  - Return existing transaction if key matches and not expired
  - Scope: SESSION (same session only), MSISDN (same user), GLOBAL (any user)
  - TTL for idempotency keys: 24 hours

TODO [TX-003]: Implement retry logic with exponential backoff
  - First retry: immediate
  - Second retry: 5 seconds
  - Third retry: 25 seconds
  - Max: 3 retries (configurable per transaction type)
  - Dead letter queue after max retries

TODO [TX-004]: Implement timeout recovery
  - Query transaction status with external processor
  - Reconcile unknown states
  - Auto-cancel if cannot determine status after investigation
  - Human workflow for large amounts

TODO [TX-005]: Implement callback handling
  - Idempotent callback processing
  - Verify callback signatures (HMAC)
  - Handle duplicate callbacks
  - Async callback processing (don't block HTTP response)

TODO [TX-006]: Implement transaction reconciliation
  - Periodic reconciliation with external systems
  - Detect and handle orphaned transactions
  - Auto-reverse if completion cannot be confirmed
  - Daily settlement reports

TODO [TX-007]: Implement risk scoring integration
  - Call risk engine before PROCESSING stage
  - Risk factors: amount, velocity, device trust, recipient history
  - Block high-risk transactions pending review
  - Dynamic friction based on risk score

TODO [TX-008]: Implement notification system
  - SMS on completion/failure
  - Push notifications if app installed
  - Failed notification retry queue
  - User preference respect (quiet hours)

TODO [TX-009]: Implement ledger integration
  - Write to immutable ledger on status changes
  - Maintain hash chain for audit
  - Async ledger writes to avoid blocking
  - Ledger failure handling (retry queue)

TODO [TX-010]: Implement transaction metrics
  - Real-time success rate monitoring
  - Latency percentiles per transaction type
  - Alert on anomaly detection
  - Capacity planning data
*/

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

-- Timeout scheduling
CREATE INDEX idx_tx_timeouts_scheduled 
    ON transaction_timeouts(scheduled_timeout_at) 
    WHERE resolved = FALSE;

-- Event queries
CREATE INDEX idx_tx_events_transaction 
    ON transaction_events(transaction_id, occurred_at DESC);

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
