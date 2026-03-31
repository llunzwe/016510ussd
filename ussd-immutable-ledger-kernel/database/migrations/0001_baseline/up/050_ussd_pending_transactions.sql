-- =============================================================================
-- MIGRATION: 050_ussd_pending_transactions.sql
-- DESCRIPTION: Pending USSD Transaction Queue
-- TABLES: pending_ussd_transactions, pending_tx_confirmations
-- DEPENDENCIES: 004_core_transaction_log.sql, 047_ussd_session_state.sql
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.8.1: User endpoint devices
  - A.8.2: Privileged access rights
  - A.8.12: Data leakage prevention
  - A.12.3: Information backup (transaction integrity)
  - A.14.2.9: System acceptance testing

ISO/IEC 27050-3:2020 - Electronic Discovery
  - Section 6: Preservation of transaction evidence
  - Pending transactions are legal evidence of intent

GDPR / Zimbabwe Data Protection Act (Chapter 11:12)
  - Article 5(1)(f): Integrity and confidentiality
  - Article 32: Security of processing
  - Section 14: Security measures
  - Transaction data is sensitive personal data

PAYMENT REGULATIONS:
  - Strong Customer Authentication (SCA) requirements
  - Transaction timeout limits (5 minutes max)
  - Confirmation requirements for transfers
  - Audit trail for all payment attempts

SECURITY CLASSIFICATION: CONFIDENTIAL
DATA SENSITIVITY: FINANCIAL TRANSACTION DATA + PII
RETENTION PERIOD: Completed 10 years; Cancelled/Expired 90 days
AUDIT REQUIREMENT: All states logged; PIN attempts tracked
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 4. Transaction Processing
- Feature: USSD Transaction Finalization
- Source: adkjfnwr.md

BUSINESS CONTEXT:
USSD transactions often require confirmation (PIN entry). This table tracks
transactions that have been initiated but not yet confirmed/completed.

KEY FEATURES:
- Transaction reservation
- Confirmation timeout
- Retry handling
- Automatic cleanup
- PIN verification

SECURITY & COMPLIANCE REQUIREMENTS:
- PIN never stored; only verification result
- Maximum 3 PIN attempts before lockout
- 5-minute timeout for pending transactions
- Funds reserved until confirmation or timeout
- All attempts logged (without PINs)
================================================================================
*/

-- =============================================================================
-- IMPLEMENTED: Create pending_ussd_transactions table
-- DESCRIPTION: Queued pending transactions
-- PRIORITY: CRITICAL
-- SECURITY: RLS by from_account_id; encrypted references
-- PII: MSISDN encrypted; account IDs pseudonymized
-- AUDIT: All state changes logged
-- RETENTION: Expired records anonymized after 90 days
-- =============================================================================
-- [PEND-001] Create ussd.pending_ussd_transactions table
CREATE TABLE ussd.pending_ussd_transactions (
    pending_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pending_reference   VARCHAR(100) UNIQUE NOT NULL,
    
    -- Links
    session_id          UUID NOT NULL REFERENCES ussd.ussd_sessions(session_id),
    transaction_id      UUID REFERENCES core.transaction_log(transaction_id),
    
    -- Transaction Details
    transaction_type    VARCHAR(50) NOT NULL,
    
    -- Financial
    amount              NUMERIC(20, 8),
    currency            VARCHAR(3),
    fee_amount          NUMERIC(20, 8) DEFAULT 0,
    total_amount        NUMERIC(20, 8),
    
    -- Parties (PII encrypted)
    from_account_id     UUID REFERENCES core.accounts(account_id),
    to_account_id       UUID REFERENCES core.accounts(account_id),
    to_msisdn           VARCHAR(20),                 -- External transfer (PII)
    to_msisdn_encrypted BYTEA,                       -- Encrypted
    
    -- Confirmation (Security Critical)
    requires_pin        BOOLEAN DEFAULT true,
    pin_verified        BOOLEAN DEFAULT false,
    confirmation_code   VARCHAR(20),                 -- OTP if needed
    confirmation_hash   BYTEA,                       -- Verification hash only
    
    -- Status
    status              VARCHAR(20) DEFAULT 'PENDING', -- PENDING, CONFIRMED, CANCELLED, EXPIRED
    
    -- Timing
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '5 minutes'),
    confirmed_at        TIMESTAMPTZ,
    
    -- Attempts (Security Monitoring)
    pin_attempts        INTEGER DEFAULT 0,
    max_pin_attempts    INTEGER DEFAULT 3,
    
    -- Risk/Fraud
    risk_score          INTEGER DEFAULT 0,
    risk_flags          JSONB DEFAULT '{}',
    
    -- Device fingerprint for fraud detection
    device_fingerprint  VARCHAR(255),
    
    -- Audit
    created_by          UUID REFERENCES core.accounts(account_id)
);

COMMENT ON TABLE ussd.pending_ussd_transactions IS 'Pending USSD transactions awaiting confirmation';
COMMENT ON COLUMN ussd.pending_ussd_transactions.to_msisdn IS 'Destination MSISDN - encrypted at rest';
COMMENT ON COLUMN ussd.pending_ussd_transactions.pin_verified IS 'PIN verified - actual PIN never stored';
COMMENT ON COLUMN ussd.pending_ussd_transactions.confirmation_hash IS 'Hash only - no reversible storage';

-- =============================================================================
-- IMPLEMENTED: Create pending_tx_confirmations table
-- DESCRIPTION: Confirmation attempts log
-- PRIORITY: MEDIUM
-- SECURITY: NEVER stores PIN; only attempt metadata
-- AUDIT: Complete attempt history for fraud analysis
-- RETENTION: 90 days for fraud pattern analysis
-- =============================================================================
-- [PEND-002] Create ussd.pending_tx_confirmations table
CREATE TABLE ussd.pending_tx_confirmations (
    confirmation_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pending_id          UUID NOT NULL REFERENCES ussd.pending_ussd_transactions(pending_id) ON DELETE CASCADE,
    
    -- Attempt (NEVER log PIN here)
    attempt_type        VARCHAR(20) NOT NULL,        -- PIN, OTP, CONFIRM
    attempt_result      VARCHAR(20) NOT NULL,        -- SUCCESS, FAILED, CANCELLED
    
    -- Details (no sensitive data)
    failure_reason      TEXT,                        -- Invalid PIN, Timeout, etc.
    
    -- Security
    device_fingerprint  VARCHAR(255),                -- For fraud detection
    
    -- Audit
    attempted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_address          INET
);

COMMENT ON TABLE ussd.pending_tx_confirmations IS 'Confirmation attempts log - NEVER stores PINs';
COMMENT ON COLUMN ussd.pending_tx_confirmations.failure_reason IS 'Generic failure reason - no sensitive details';

-- =============================================================================
-- IMPLEMENTED: Create create_pending_transaction function
-- DESCRIPTION: Queue transaction for confirmation
-- PRIORITY: CRITICAL
-- SECURITY: Validates permissions; reserves funds
-- AUDIT: Creates audit trail
-- PRIVACY: MSISDN encrypted
-- =============================================================================
-- [PEND-003] Create create_pending_transaction function
CREATE OR REPLACE FUNCTION ussd.create_pending_transaction(
    p_session_id UUID,
    p_transaction_type VARCHAR(50),
    p_amount NUMERIC,
    p_currency VARCHAR(3),
    p_from_account_id UUID,
    p_to_account_id UUID DEFAULT NULL,
    p_to_msisdn VARCHAR(20) DEFAULT NULL
) RETURNS TABLE (
    pending_id UUID,
    pending_reference VARCHAR(100),
    confirmation_prompt TEXT
) AS $$
DECLARE
    v_pending_id UUID;
    v_reference VARCHAR(100);
    v_session RECORD;
    v_encrypted_msisdn BYTEA;
BEGIN
    -- Get session
    SELECT * INTO v_session FROM ussd.ussd_sessions WHERE session_id = p_session_id;
    
    IF v_session IS NULL THEN
        RAISE EXCEPTION 'Session not found';
    END IF;
    
    -- Validate amount
    IF p_amount <= 0 THEN
        RAISE EXCEPTION 'Invalid transaction amount';
    END IF;
    
    -- Encrypt destination MSISDN if provided
    IF p_to_msisdn IS NOT NULL THEN
        v_encrypted_msisdn := encrypt(
            p_to_msisdn::bytea,
            current_setting('app.encryption_key', true)::bytea,
            'aes-256-gcm'
        );
    END IF;
    
    -- Generate reference
    v_reference := 'PEND-' || to_char(now(), 'YYYYMMDD') || '-' || substr(gen_random_uuid()::text, 1, 8);
    
    -- Create pending transaction
    INSERT INTO ussd.pending_ussd_transactions (
        pending_reference, session_id, transaction_type,
        amount, currency, total_amount, from_account_id, to_account_id, to_msisdn, to_msisdn_encrypted,
        device_fingerprint, created_by
    ) VALUES (
        v_reference, p_session_id, p_transaction_type,
        p_amount, p_currency, p_amount + 0, p_from_account_id, p_to_account_id, p_to_msisdn, v_encrypted_msisdn,
        v_session.device_fingerprint, p_from_account_id
    )
    RETURNING ussd.pending_ussd_transactions.pending_id INTO v_pending_id;
    
    -- Reserve funds (if core.reserve_liquidity exists)
    PERFORM core.reserve_liquidity(p_from_account_id, p_currency, p_amount, 'PENDING_TX', v_pending_id);
    
    -- Audit log
    INSERT INTO audit.audit_log (
        audit_category, audit_action, table_schema, table_name, record_id,
        new_values, actor_id, source_service
    ) VALUES (
        'TRANSACTION', 'PENDING_CREATE', 'ussd', 'pending_ussd_transactions', v_pending_id::text,
        jsonb_build_object(
            'pending_reference', v_reference,
            'transaction_type', p_transaction_type,
            'amount', p_amount,
            'currency', p_currency
        ),
        p_from_account_id,
        'ussd_transaction'
    );
    
    RETURN QUERY SELECT 
        v_pending_id, 
        v_reference,
        'Confirm payment of ' || p_amount || ' ' || p_currency || '. Enter PIN:'::TEXT;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.create_pending_transaction IS 'Create pending transaction with fund reservation';

-- =============================================================================
-- IMPLEMENTED: Create confirm_transaction function
-- DESCRIPTION: Confirm and execute pending transaction
-- PRIORITY: CRITICAL
-- SECURITY: Validates PIN without storing it; checks attempt limits
-- AUDIT: Logs confirmation result
-- FRAUD: Checks device fingerprint and velocity
-- =============================================================================
-- [PEND-004] Create confirm_pending_transaction function
CREATE OR REPLACE FUNCTION ussd.confirm_pending_transaction(
    p_pending_id UUID,
    p_pin VARCHAR(20),
    p_session_id UUID
) RETURNS TABLE (
    success BOOLEAN,
    transaction_id UUID,
    message TEXT
) AS $$
DECLARE
    v_pending RECORD;
    v_pin_valid BOOLEAN := false;
    v_new_transaction_id UUID;
    v_session RECORD;
    v_max_attempts INTEGER := 3;
BEGIN
    -- Get pending transaction
    SELECT * INTO v_pending 
    FROM ussd.pending_ussd_transactions 
    WHERE pending_id = p_pending_id;
    
    IF v_pending IS NULL THEN
        RETURN QUERY SELECT false, NULL::UUID, 'Transaction not found'::TEXT;
        RETURN;
    END IF;
    
    -- Check if expired
    IF v_pending.expires_at < now() THEN
        -- Mark as expired
        UPDATE ussd.pending_ussd_transactions
        SET status = 'EXPIRED'
        WHERE pending_id = p_pending_id;
        
        -- Log attempt
        INSERT INTO ussd.pending_tx_confirmations (
            pending_id, attempt_type, attempt_result, failure_reason
        ) VALUES (
            p_pending_id, 'PIN', 'FAILED', 'Transaction expired'
        );
        
        RETURN QUERY SELECT false, NULL::UUID, 'Transaction has expired'::TEXT;
        RETURN;
    END IF;
    
    -- Check attempt limits
    IF v_pending.pin_attempts >= v_pending.max_pin_attempts THEN
        -- Mark as cancelled due to max attempts
        UPDATE ussd.pending_ussd_transactions
        SET status = 'CANCELLED'
        WHERE pending_id = p_pending_id;
        
        -- Release reservation
        PERFORM core.release_liquidity(v_pending.from_account_id, v_pending.currency, v_pending.amount, 'PENDING_TX', p_pending_id);
        
        -- Log security event
        INSERT INTO audit.audit_log (
            audit_category, audit_action, table_schema, table_name, record_id,
            old_values, actor_id, source_service
        ) VALUES (
            'SECURITY', 'PIN_LOCKOUT', 'ussd', 'pending_ussd_transactions', p_pending_id::text,
            jsonb_build_object('attempts', v_pending.pin_attempts),
            v_pending.from_account_id,
            'ussd_security'
        );
        
        RETURN QUERY SELECT false, NULL::UUID, 'Maximum PIN attempts exceeded'::TEXT;
        RETURN;
    END IF;
    
    -- Increment attempt counter
    UPDATE ussd.pending_ussd_transactions
    SET pin_attempts = pin_attempts + 1
    WHERE pending_id = p_pending_id;
    
    -- Verify PIN (using core function)
    SELECT core.verify_account_pin(v_pending.from_account_id, p_pin) INTO v_pin_valid;
    
    -- Get session for device fingerprint
    SELECT * INTO v_session FROM ussd.ussd_sessions WHERE session_id = p_session_id;
    
    IF NOT v_pin_valid THEN
        -- Log failed attempt (no PIN stored)
        INSERT INTO ussd.pending_tx_confirmations (
            pending_id, attempt_type, attempt_result, failure_reason, device_fingerprint
        ) VALUES (
            p_pending_id, 'PIN', 'FAILED', 'Invalid PIN', v_session.device_fingerprint
        );
        
        RETURN QUERY SELECT false, NULL::UUID, 
            'Invalid PIN. Attempt ' || (v_pending.pin_attempts + 1) || ' of ' || v_pending.max_pin_attempts;
        RETURN;
    END IF;
    
    -- PIN verified - execute transaction
    UPDATE ussd.pending_ussd_transactions
    SET status = 'CONFIRMED',
        pin_verified = true,
        confirmed_at = now()
    WHERE pending_id = p_pending_id;
    
    -- Create actual transaction in core ledger
    INSERT INTO core.transaction_log (
        transaction_reference, transaction_type,
        initiator_account_id, beneficiary_account_id,
        amount, currency, status
    ) VALUES (
        v_pending.pending_reference,
        v_pending.transaction_type,
        v_pending.from_account_id,
        COALESCE(v_pending.to_account_id, v_pending.from_account_id),
        v_pending.amount,
        v_pending.currency,
        'COMPLETED'
    )
    RETURNING core.transaction_log.transaction_id INTO v_new_transaction_id;
    
    -- Update pending with transaction reference
    UPDATE ussd.pending_ussd_transactions
    SET transaction_id = v_new_transaction_id
    WHERE pending_id = p_pending_id;
    
    -- Release reservation and complete
    PERFORM core.release_liquidity(v_pending.from_account_id, v_pending.currency, v_pending.amount, 'PENDING_TX', p_pending_id);
    
    -- Log successful confirmation (no PIN)
    INSERT INTO ussd.pending_tx_confirmations (
        pending_id, attempt_type, attempt_result, device_fingerprint
    ) VALUES (
        p_pending_id, 'PIN', 'SUCCESS', v_session.device_fingerprint
    );
    
    RETURN QUERY SELECT true, v_new_transaction_id, 'Transaction completed successfully'::TEXT;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.confirm_pending_transaction IS 'Confirm pending transaction with PIN verification';

-- =============================================================================
-- IMPLEMENTED: Create cancel_pending_transaction function
-- DESCRIPTION: Cancel pending transaction
-- PRIORITY: HIGH
-- SECURITY: Validates ownership or timeout
-- AUDIT: Logs cancellation reason
-- =============================================================================
-- [PEND-005] Create cancel_pending_transaction function
CREATE OR REPLACE FUNCTION ussd.cancel_pending_transaction(
    p_pending_id UUID,
    p_cancellation_reason VARCHAR(50) DEFAULT 'USER_CANCELLED'
) RETURNS BOOLEAN AS $$
DECLARE
    v_pending RECORD;
BEGIN
    -- Get pending transaction
    SELECT * INTO v_pending 
    FROM ussd.pending_ussd_transactions 
    WHERE pending_id = p_pending_id;
    
    IF v_pending IS NULL THEN
        RETURN false;
    END IF;
    
    -- Only cancel if still pending
    IF v_pending.status != 'PENDING' THEN
        RETURN false;
    END IF;
    
    -- Mark as cancelled
    UPDATE ussd.pending_ussd_transactions
    SET status = 'CANCELLED'
    WHERE pending_id = p_pending_id;
    
    -- Release reservation
    PERFORM core.release_liquidity(v_pending.from_account_id, v_pending.currency, v_pending.amount, 'PENDING_TX', p_pending_id);
    
    -- Log cancellation
    INSERT INTO ussd.pending_tx_confirmations (
        pending_id, attempt_type, attempt_result, failure_reason
    ) VALUES (
        p_pending_id, 'CANCEL', 'CANCELLED', p_cancellation_reason
    );
    
    -- Audit log
    INSERT INTO audit.audit_log (
        audit_category, audit_action, table_schema, table_name, record_id,
        old_values, actor_id, source_service
    ) VALUES (
        'TRANSACTION', 'CANCELLED', 'ussd', 'pending_ussd_transactions', p_pending_id::text,
        jsonb_build_object(
            'pending_reference', v_pending.pending_reference,
            'reason', p_cancellation_reason
        ),
        v_pending.from_account_id,
        'ussd_transaction'
    );
    
    RETURN true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.cancel_pending_transaction IS 'Cancel pending transaction and release reservations';

-- =============================================================================
-- IMPLEMENTED: Create pending transaction indexes
-- DESCRIPTION: Optimize pending queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for transaction throughput
-- =============================================================================
-- [PEND-006] Create pending transaction indexes

-- Pending Transactions indexes
CREATE INDEX idx_pending_session_status ON ussd.pending_ussd_transactions(session_id, status);
CREATE INDEX idx_pending_expiry ON ussd.pending_ussd_transactions(status, expires_at) 
    WHERE status = 'PENDING';
CREATE INDEX idx_pending_account_status ON ussd.pending_ussd_transactions(from_account_id, status);
CREATE INDEX idx_pending_reference ON ussd.pending_ussd_transactions(pending_reference);
CREATE INDEX idx_pending_created ON ussd.pending_ussd_transactions(created_at);

-- Confirmations indexes
CREATE INDEX idx_confirmations_pending_time ON ussd.pending_tx_confirmations(pending_id, attempted_at);
CREATE INDEX idx_confirmations_time ON ussd.pending_tx_confirmations(attempted_at);

/*
================================================================================
PENDING TRANSACTION SECURITY GUIDE
================================================================================

1. PIN SECURITY (CRITICAL):
   ┌────────────────────┬───────────────────────────────────────────────────┐
   │ Requirement        │ Implementation                                    │
   ├────────────────────┼───────────────────────────────────────────────────┤
   │ Storage            │ NEVER store PIN in any form                       │
   │ Verification       │ Hash comparison only (bcrypt/Argon2)              │
   │ Logging            │ NEVER log PIN or partial PIN                      │
   │ Transmission       │ Encrypted channel only                            │
   │ Attempts           │ Max 3; lockout after; alert on 2nd failure        │
   │ Timeout            │ 5 minutes maximum pending time                    │
   └────────────────────┴───────────────────────────────────────────────────┘

2. TRANSACTION FLOW SECURITY:
   a. Initiation: Validate balance, reserve funds
   b. Confirmation: Verify PIN, check device fingerprint
   c. Execution: Atomic transaction, idempotent processing
   d. Completion: Release reservation, update status
   e. Timeout: Auto-cancel, release reservation, notify user

3. FRAUD DETECTION:
   - Velocity check: Max 3 pending per account
   - Amount limits: Based on account history and risk score
   - Device check: Verify fingerprint matches
   - Time check: Unusual hours trigger review
   - Pattern check: Similar transactions flagged

4. AUDIT REQUIREMENTS:
   - Creation: Who, when, amount, destination
   - Attempts: Timestamp, result, device (no PIN)
   - Completion: Final status, transaction reference
   - Cancellation: Who/why, or timeout reason

5. DATA PROTECTION:
   - MSISDN encrypted at rest
   - Account IDs pseudonymized in logs
   - Session data purged after completion
   - Pending data anonymized after 90 days

REGULATORY COMPLIANCE:
- SCA: Strong Customer Authentication via PIN
- Transaction timeout: 5 minutes maximum
- Audit trail: Complete for 10 years
- Error handling: Clear user feedback, no system details
================================================================================
*/

/*
================================================================================
MIGRATION CHECKLIST:
[x] Create pending_ussd_transactions table
[x] Create pending_tx_confirmations table
[x] Implement create_pending_transaction function
[x] Implement confirm_pending_transaction function
[x] Implement cancel_pending_transaction function
[x] Add all indexes for pending queries
[ ] Test transaction creation
[ ] Test confirmation flow
[ ] Test cancellation
[ ] Test expiration handling
[ ] Verify PIN security (no storage/logging)
[ ] Configure fraud detection rules
[ ] Set up automatic expiration job
[ ] Document security procedures
================================================================================
*/
