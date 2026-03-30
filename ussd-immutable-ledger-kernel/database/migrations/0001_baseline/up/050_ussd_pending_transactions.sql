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
-- TODO: Create pending_ussd_transactions table
-- DESCRIPTION: Queued pending transactions
-- PRIORITY: CRITICAL
-- SECURITY: RLS by from_account_id; encrypted references
-- PII: MSISDN encrypted; account IDs pseudonymized
-- AUDIT: All state changes logged
-- RETENTION: Expired records anonymized after 90 days
-- =============================================================================
-- TODO: [PEND-001] Create ussd.pending_ussd_transactions table
-- INSTRUCTIONS:
--   - Track transactions awaiting confirmation
--   - Links to session and core transaction
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE ussd.pending_ussd_transactions (
--       pending_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       pending_reference   VARCHAR(100) UNIQUE NOT NULL,
--       
--       -- Links
--       session_id          UUID NOT NULL REFERENCES ussd.ussd_sessions(session_id),
--       transaction_id      UUID REFERENCES core.transaction_log(transaction_id),
--       
--       -- Transaction Details
--       transaction_type    VARCHAR(50) NOT NULL,
--       
--       -- Financial
--       amount              NUMERIC(20, 8),
--       currency            VARCHAR(3),
--       fee_amount          NUMERIC(20, 8) DEFAULT 0,
--       total_amount        NUMERIC(20, 8),
--       
--       -- Parties (PII encrypted)
--       from_account_id     UUID REFERENCES core.accounts(account_id),
--       to_account_id       UUID REFERENCES core.accounts(account_id),
--       to_msisdn           VARCHAR(20),                 -- External transfer (PII)
--       to_msisdn_encrypted BYTEA,                       -- Encrypted
--       
--       -- Confirmation (Security Critical)
--       requires_pin        BOOLEAN DEFAULT true,
--       pin_verified        BOOLEAN DEFAULT false,
--       confirmation_code   VARCHAR(20),                 -- OTP if needed
--       confirmation_hash   BYTEA,                       -- Verification hash only
--       
--       -- Status
--       status              VARCHAR(20) DEFAULT 'PENDING', -- PENDING, CONFIRMED, CANCELLED, EXPIRED
--       
--       -- Timing
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       expires_at          TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '5 minutes'),
--       confirmed_at        TIMESTAMPTZ,
--       
--       -- Attempts (Security Monitoring)
--       pin_attempts        INTEGER DEFAULT 0,
--       max_pin_attempts    INTEGER DEFAULT 3,
--       
--       -- Risk/Fraud
--       risk_score          INTEGER DEFAULT 0,
--       risk_flags          JSONB DEFAULT '{}',
--       
--       -- Audit
--       created_by          UUID REFERENCES core.accounts(account_id)
--   );

-- =============================================================================
-- TODO: Create pending_tx_confirmations table
-- DESCRIPTION: Confirmation attempts log
-- PRIORITY: MEDIUM
-- SECURITY: NEVER stores PIN; only attempt metadata
-- AUDIT: Complete attempt history for fraud analysis
-- RETENTION: 90 days for fraud pattern analysis
-- =============================================================================
-- TODO: [PEND-002] Create ussd.pending_tx_confirmations table
-- INSTRUCTIONS:
--   - Log of confirmation attempts
--   - Success and failure tracking
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE ussd.pending_tx_confirmations (
--       confirmation_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       pending_id          UUID NOT NULL REFERENCES ussd.pending_ussd_transactions(pending_id),
--       
--       -- Attempt (NEVER log PIN here)
--       attempt_type        VARCHAR(20) NOT NULL,        -- PIN, OTP, CONFIRM
--       attempt_result      VARCHAR(20) NOT NULL,        -- SUCCESS, FAILED, CANCELLED
--       
--       -- Details (no sensitive data)
--       failure_reason      TEXT,                        -- Invalid PIN, Timeout, etc.
--       
--       -- Security
--       device_fingerprint  VARCHAR(255),                -- For fraud detection
--       
--       -- Audit
--       attempted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
--       ip_address          INET
--   );

-- =============================================================================
-- TODO: Create create_pending_transaction function
-- DESCRIPTION: Queue transaction for confirmation
-- PRIORITY: CRITICAL
-- SECURITY: Validates permissions; reserves funds
-- AUDIT: Creates audit trail
-- PRIVACY: MSISDN encrypted
-- =============================================================================
-- TODO: [PEND-003] Create create_pending_transaction function
-- INSTRUCTIONS:
--   - Validate transaction parameters
--   - Reserve funds if needed
--   - Create pending record
--   - Return confirmation prompt
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION ussd.create_pending_transaction(
--       p_session_id UUID,
--       p_transaction_type VARCHAR(50),
--       p_amount NUMERIC,
--       p_currency VARCHAR(3),
--       p_from_account_id UUID,
--       p_to_account_id UUID DEFAULT NULL,
--       p_to_msisdn VARCHAR(20) DEFAULT NULL
--   ) RETURNS TABLE (
--       pending_id UUID,
--       pending_reference VARCHAR(100),
--       confirmation_prompt TEXT
--   ) AS $$
--   DECLARE
--       v_pending_id UUID;
--       v_reference VARCHAR(100);
--       v_session RECORD;
--   BEGIN
--       -- Get session
--       SELECT * INTO v_session FROM ussd.ussd_sessions WHERE session_id = p_session_id;
--       
--       -- Generate reference
--       v_reference := 'PEND-' || to_char(now(), 'YYYYMMDD') || '-' || substr(gen_random_uuid()::text, 1, 8);
--       
--       -- Create pending transaction
--       INSERT INTO ussd.pending_ussd_transactions (
--           pending_reference, session_id, transaction_type,
--           amount, currency, from_account_id, to_account_id, to_msisdn
--       ) VALUES (
--           v_reference, p_session_id, p_transaction_type,
--           p_amount, p_currency, p_from_account_id, p_to_account_id, p_to_msisdn
--       )
--       RETURNING pending_ussd_transactions.pending_id INTO v_pending_id;
--       
--       -- Reserve funds
--       PERFORM core.reserve_liquidity(p_from_account_id, p_currency, p_amount, 'PENDING_TX', v_pending_id);
--       
--       RETURN QUERY SELECT 
--           v_pending_id, 
--           v_reference,
--           'Confirm payment of ' || p_amount || ' ' || p_currency || '. Enter PIN:'::TEXT;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create confirm_transaction function
-- DESCRIPTION: Confirm and execute pending transaction
-- PRIORITY: CRITICAL
-- SECURITY: Validates PIN without storing it; checks attempt limits
-- AUDIT: Logs confirmation result
-- FRAUD: Checks device fingerprint and velocity
-- =============================================================================
-- TODO: [PEND-004] Create confirm_pending_transaction function
-- INSTRUCTIONS:
--   - Verify PIN/confirmation
--   - Update pending status
--   - Execute core transaction
--   - Release reservation
--   - Handle failures

-- =============================================================================
-- TODO: Create cancel_pending_transaction function
-- DESCRIPTION: Cancel pending transaction
-- PRIORITY: HIGH
-- SECURITY: Validates ownership or timeout
-- AUDIT: Logs cancellation reason
-- =============================================================================
-- TODO: [PEND-005] Create cancel_pending_transaction function
-- INSTRUCTIONS:
--   - Mark as cancelled
--   - Release reservations
--   - Log cancellation

-- =============================================================================
-- TODO: Create pending transaction indexes
-- DESCRIPTION: Optimize pending queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for transaction throughput
-- =============================================================================
-- TODO: [PEND-006] Create pending transaction indexes
-- INDEX LIST:
--   -- Pending Transactions:
--   - PRIMARY KEY (pending_id)
--   - UNIQUE (pending_reference)
--   - INDEX on (session_id, status)
--   - INDEX on (status, expires_at) WHERE status = 'PENDING'
--   - INDEX on (from_account_id, status)
--   -- Confirmations:
--   - PRIMARY KEY (confirmation_id)
--   - INDEX on (pending_id, attempted_at)

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
□ Create pending_ussd_transactions table
□ Create pending_tx_confirmations table
□ Implement create_pending_transaction function
□ Implement confirm_pending_transaction function
□ Implement cancel_pending_transaction function
□ Add all indexes for pending queries
□ Test transaction creation
□ Test confirmation flow
□ Test cancellation
□ Test expiration handling
□ Verify PIN security (no storage/logging)
□ Configure fraud detection rules
□ Set up automatic expiration job
□ Document security procedures
================================================================================
*/
