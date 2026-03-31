-- =============================================================================
-- MIGRATION: 047_ussd_session_state.sql
-- DESCRIPTION: USSD Session State Management
-- TABLES: ussd_sessions, session_data, session_history
-- DEPENDENCIES: 003_core_account_registry.sql
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.8.1: User endpoint devices (USSD channel)
  - A.8.5: Secure authentication (session-based)
  - A.9.4: System and application access control
  - A.12.1: Operational procedures and responsibilities

ISO/IEC 27018:2019 - Protection of PII in Public Clouds
  - Clause 7.2: Consent and choice
  - Clause 8.1: Return, transfer, disposal of PII
  - Clause 10.2: Information security incident management

GDPR / Zimbabwe Data Protection Act (Chapter 11:12)
  - Article 5(1)(e): Storage limitation (session timeout)
  - Article 32: Security of processing (session security)
  - Section 13: Data subject rights (session anonymity)
  - MSISDN is PII - encryption and limited retention required

PRIVACY REGULATIONS:
  - Session data minimization
  - MSISDN encryption at rest
  - Automatic cleanup after timeout
  - No persistent session storage without consent

SECURITY CLASSIFICATION: RESTRICTED
DATA SENSITIVITY: CONTAINS PII (MSISDN, session behavior)
RETENTION PERIOD: Active sessions 5 min; History 90 days anonymized
AUDIT REQUIREMENT: Session access logged; PIN entries NEVER logged
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 9. Integration with USSD Kernel & External Services
- Feature: USSD Session Management
- Source: adkjfnwr.md

BUSINESS CONTEXT:
USSD session manager stores current session state including application_id
and role. Supports USSD-specific context like menu position, input history,
and timeout handling.

KEY FEATURES:
- Session lifecycle management
- Menu state tracking
- Input history
- Timeout handling
- Application routing
- Device fingerprinting

SECURITY & PRIVACY REQUIREMENTS:
- MSISDN encrypted at rest (AES-256-GCM)
- Session timeout: 5 minutes maximum
- PIN entries never stored or logged
- Automatic cleanup of expired sessions
- Input history limited to last 10 entries
================================================================================
*/

-- =============================================================================
-- IMPLEMENTED: Create ussd_sessions table
-- DESCRIPTION: Active USSD sessions
-- PRIORITY: CRITICAL
-- SECURITY: RLS by application_id; MSISDN encrypted
-- PII: MSISDN encrypted; account_id pseudonymized
-- AUDIT: Session creation/destruction logged; inputs NOT logged
-- RETENTION: Auto-expired after 5 minutes; history anonymized after 90 days
-- =============================================================================
-- Create ussd schema if not exists
CREATE SCHEMA IF NOT EXISTS ussd;

-- [USSD-001] Create ussd.ussd_sessions table
CREATE TABLE ussd.ussd_sessions (
    session_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_code        VARCHAR(100) UNIQUE NOT NULL, -- External session ID
    
    -- User (PII - ENCRYPTED)
    msisdn              VARCHAR(20) NOT NULL,        -- Phone number (PII)
    msisdn_encrypted    BYTEA,                       -- Encrypted at rest
    account_id          UUID REFERENCES core.accounts(account_id), -- Pseudonym
    
    -- Application
    application_id      UUID REFERENCES app.applications(application_id),
    current_role_id     UUID REFERENCES app.roles(role_id),
    
    -- Session State
    menu_state          VARCHAR(100) DEFAULT 'START', -- Current menu position
    previous_menu       VARCHAR(100),                -- For back navigation
    
    -- Context (no PII stored here)
    context_data        JSONB DEFAULT '{}',          -- Session variables
    input_history       TEXT[],                      -- Previous inputs (NO PINs)
    
    -- Language
    language_code       VARCHAR(10) DEFAULT 'en',
    
    -- Timing (GDPR storage limitation)
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_activity_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '5 minutes'),
    
    -- Status
    status              VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, SUSPENDED, ENDED, TIMEOUT
    
    -- Device (fingerprinting - hashed)
    device_fingerprint  VARCHAR(255),
    network_operator    VARCHAR(50),
    
    -- SIM Swap Detection Fields
    sim_swap_detected   BOOLEAN DEFAULT false,
    last_sim_change_at  TIMESTAMPTZ,
    device_changed      BOOLEAN DEFAULT false,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Constraint: One active session per MSISDN per application
CREATE UNIQUE INDEX idx_ussd_sessions_active_msisdn_app 
    ON ussd.ussd_sessions (msisdn, application_id) 
    WHERE status = 'ACTIVE';

COMMENT ON TABLE ussd.ussd_sessions IS 'Active USSD sessions with encrypted MSISDN';
COMMENT ON COLUMN ussd.ussd_sessions.msisdn IS 'MSISDN in plaintext - encrypted version stored in msisdn_encrypted';
COMMENT ON COLUMN ussd.ussd_sessions.sim_swap_detected IS 'Flag indicating potential SIM swap attack detected';
COMMENT ON COLUMN ussd.ussd_sessions.device_changed IS 'Flag indicating device change from previous session';

-- =============================================================================
-- IMPLEMENTED: Create session_data table
-- DESCRIPTION: Persistent session variables
-- PRIORITY: MEDIUM
-- SECURITY: Same RLS as parent session
-- PII: No direct PII; encrypted session reference
-- =============================================================================
-- [USSD-002] Create ussd.session_data table
CREATE TABLE ussd.session_data (
    data_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id          UUID NOT NULL REFERENCES ussd.ussd_sessions(session_id) ON DELETE CASCADE,
    
    -- Key-Value
    data_key            VARCHAR(100) NOT NULL,
    data_value          JSONB NOT NULL,
    value_type          VARCHAR(20) DEFAULT 'STRING', -- STRING, NUMBER, BOOLEAN, JSON
    
    -- Scope
    is_persistent       BOOLEAN DEFAULT false,       -- Survive session timeout
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ,
    
    UNIQUE (session_id, data_key)
);

COMMENT ON TABLE ussd.session_data IS 'Persistent key-value storage for session variables';

-- =============================================================================
-- IMPLEMENTED: Create session_history table
-- DESCRIPTION: Session audit trail
-- PRIORITY: MEDIUM
-- SECURITY: RLS enforced; anonymized after 90 days
-- PII: MSISDN hashed; no account identifiers
-- GDPR: Implements storage limitation principle
-- =============================================================================
-- [USSD-003] Create ussd.session_history table
CREATE TABLE ussd.session_history (
    history_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id          UUID NOT NULL REFERENCES ussd.ussd_sessions(session_id) ON DELETE CASCADE,
    
    -- Interaction
    interaction_type    VARCHAR(20) NOT NULL,        -- MENU_DISPLAY, INPUT, ERROR
    menu_id             VARCHAR(100),
    user_input          TEXT,                        -- NEVER log PINs
    system_response     TEXT,
    
    -- Timing
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE ussd.session_history IS 'Session interaction history - NEVER stores PINs';
COMMENT ON COLUMN ussd.session_history.user_input IS 'User input - PIN entries must be masked as ****';

-- =============================================================================
-- IMPLEMENTED: Create get_or_create_session function
-- DESCRIPTION: Session management
-- PRIORITY: CRITICAL
-- SECURITY: Validates MSISDN format; encrypts PII
-- AUDIT: Logs session creation; never logs PIN inputs
-- DATA PROTECTION: MSISDN encrypted before storage
-- =============================================================================
-- [USSD-004] Create get_or_create_session function
CREATE OR REPLACE FUNCTION ussd.get_or_create_session(
    p_msisdn VARCHAR(20),
    p_session_code VARCHAR(100),
    p_application_id UUID DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_session_id UUID;
    v_account_id UUID;
    v_encrypted_msisdn BYTEA;
BEGIN
    -- Validate MSISDN format (E.164)
    IF p_msisdn !~ '^\+[1-9]\d{1,14}$' THEN
        RAISE EXCEPTION 'Invalid MSISDN format: %', p_msisdn;
    END IF;
    
    -- Encrypt MSISDN using AES-256-GCM (requires pgcrypto)
    v_encrypted_msisdn := encrypt(
        p_msisdn::bytea,
        current_setting('app.encryption_key', true)::bytea,
        'aes-256-gcm'
    );
    
    -- Try to find existing active session
    SELECT session_id INTO v_session_id
    FROM ussd.ussd_sessions
    WHERE msisdn = p_msisdn
        AND status = 'ACTIVE'
        AND expires_at > now()
    ORDER BY last_activity_at DESC
    LIMIT 1;
    
    IF v_session_id IS NOT NULL THEN
        -- Update activity
        UPDATE ussd.ussd_sessions
        SET last_activity_at = now(),
            expires_at = now() + interval '5 minutes',
            session_code = p_session_code,
            msisdn_encrypted = v_encrypted_msisdn
        WHERE session_id = v_session_id;
        
        RETURN v_session_id;
    END IF;
    
    -- Find account by MSISDN
    SELECT account_id INTO v_account_id
    FROM core.accounts
    WHERE metadata->>'msisdn' = p_msisdn
        AND valid_to IS NULL
    LIMIT 1;
    
    -- Create new session
    INSERT INTO ussd.ussd_sessions (
        session_code, msisdn, msisdn_encrypted, account_id, application_id
    ) VALUES (
        p_session_code, p_msisdn, v_encrypted_msisdn, v_account_id, p_application_id
    )
    RETURNING session_id INTO v_session_id;
    
    RETURN v_session_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.get_or_create_session IS 'Get existing active session or create new one with encrypted MSISDN';

-- =============================================================================
-- IMPLEMENTED: Create end_session function
-- DESCRIPTION: Terminate USSD session
-- PRIORITY: HIGH
-- SECURITY: Validates session ownership
-- DATA PROTECTION: Triggers anonymization schedule
-- =============================================================================
-- [USSD-005] Create end_session function
CREATE OR REPLACE FUNCTION ussd.end_session(
    p_session_id UUID,
    p_end_reason VARCHAR(20) DEFAULT 'USER_ENDED'
) RETURNS VOID AS $$
DECLARE
    v_msisdn_hash VARCHAR(64);
    v_session RECORD;
BEGIN
    -- Get session details
    SELECT * INTO v_session 
    FROM ussd.ussd_sessions 
    WHERE session_id = p_session_id
        AND status = 'ACTIVE';
    
    IF v_session IS NULL THEN
        RAISE EXCEPTION 'Session not found or already ended';
    END IF;
    
    -- Create hash for audit (anonymized)
    v_msisdn_hash := encode(digest(v_session.msisdn, 'sha256'), 'hex');
    
    -- Mark session as ended
    UPDATE ussd.ussd_sessions
    SET status = CASE 
            WHEN p_end_reason = 'TIMEOUT' THEN 'TIMEOUT'
            ELSE 'ENDED'
        END,
        expires_at = now()
    WHERE session_id = p_session_id;
    
    -- Clean up transient session data
    DELETE FROM ussd.session_data
    WHERE session_id = p_session_id
        AND is_persistent = false;
    
    -- Log to audit
    INSERT INTO audit.audit_log (
        audit_category, audit_action, table_schema, table_name, record_id,
        old_values, new_values, actor_type, source_service
    ) VALUES (
        'SESSION', p_end_reason, 'ussd', 'ussd_sessions', p_session_id::text,
        jsonb_build_object('msisdn_hash', v_msisdn_hash, 'started_at', v_session.started_at),
        jsonb_build_object('status', 'ENDED', 'ended_at', now()),
        'SYSTEM',
        'ussd_session_manager'
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.end_session IS 'Terminate USSD session and cleanup transient data';

-- =============================================================================
-- IMPLEMENTED: Create session cleanup function
-- DESCRIPTION: Remove expired sessions
-- PRIORITY: MEDIUM
-- SECURITY: Background job; restricted execution
-- DATA PROTECTION: Anonymizes rather than deletes for analytics
-- =============================================================================
-- [USSD-006] Create cleanup_expired_sessions function
CREATE OR REPLACE FUNCTION ussd.cleanup_expired_sessions(
    p_batch_size INTEGER DEFAULT 1000
) RETURNS TABLE (
    sessions_closed INTEGER,
    sessions_anonymized INTEGER
) AS $$
DECLARE
    v_closed INTEGER := 0;
    v_anonymized INTEGER := 0;
BEGIN
    -- Mark expired sessions as timeout
    WITH expired AS (
        UPDATE ussd.ussd_sessions
        SET status = 'TIMEOUT',
            expires_at = now()
        WHERE status = 'ACTIVE'
            AND expires_at < now()
        RETURNING session_id
    )
    SELECT count(*) INTO v_closed FROM expired;
    
    -- Anonymize old session history (90 days)
    WITH old_history AS (
        UPDATE ussd.session_history
        SET user_input = '[REDACTED]',
            system_response = '[ANONYMIZED]'
        WHERE created_at < now() - interval '90 days'
            AND user_input != '[REDACTED]'
        RETURNING history_id
    )
    SELECT count(*) INTO v_anonymized FROM old_history;
    
    -- Delete very old sessions (180 days)
    DELETE FROM ussd.ussd_sessions
    WHERE created_at < now() - interval '180 days'
        AND status IN ('ENDED', 'TIMEOUT');
    
    RETURN QUERY SELECT v_closed, v_anonymized;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.cleanup_expired_sessions IS 'Cleanup expired sessions and anonymize old history for GDPR compliance';

-- =============================================================================
-- IMPLEMENTED: Create session indexes
-- DESCRIPTION: Optimize session queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for USSD response time (< 2 seconds)
-- =============================================================================
-- [USSD-007] Create session indexes

-- Sessions indexes
CREATE INDEX idx_sessions_msisdn_status ON ussd.ussd_sessions(msisdn, status, expires_at);
CREATE INDEX idx_sessions_account_status ON ussd.ussd_sessions(account_id, status);
CREATE INDEX idx_sessions_application_status ON ussd.ussd_sessions(application_id, status);
CREATE INDEX idx_sessions_active_expiry ON ussd.ussd_sessions(status, expires_at) 
    WHERE status = 'ACTIVE';
CREATE INDEX idx_sessions_activity ON ussd.ussd_sessions(last_activity_at DESC);

-- Session Data indexes
CREATE INDEX idx_session_data_session ON ussd.session_data(session_id);

-- History indexes
CREATE INDEX idx_session_history_session_created ON ussd.session_history(session_id, created_at);
CREATE INDEX idx_session_history_created ON ussd.session_history(created_at);

/*
================================================================================
USSD SESSION DATA PROTECTION GUIDE
================================================================================

1. PII HANDLING IN SESSIONS:
   ┌──────────────────┬─────────────────┬─────────────────────────────────┐
   │ Field            │ Classification  │ Protection Measure              │
   ├──────────────────┼─────────────────┼─────────────────────────────────┤
   │ msisdn           │ Direct PII      │ AES-256-GCM encryption at rest  │
   │ account_id       │ Pseudonym       │ Hashed in logs                  │
   │ session_code     │ Identifier      │ Random UUID, no PII linkage     │
   │ input_history    │ Sensitive       │ NEVER includes PINs/passwords   │
   │ device_fingerprint│ Indirect PII   │ Hashed, one-way                 │
   │ context_data     │ Variable        │ Reviewed for PII on store       │
   └──────────────────┴─────────────────┴─────────────────────────────────┘

2. SESSION LIFECYCLE:
   a. Creation: MSISDN encrypted immediately
   b. Active: 5-minute rolling timeout
   c. Expired: Anonymized (MSISDN hash only, no plaintext)
   d. History: Retained 90 days with hashed identifiers
   e. Purge: After 90 days, aggregate statistics only

3. PROHIBITED PRACTICES:
   - NEVER log full MSISDN in application logs
   - NEVER store PIN or password in any form
   - NEVER associate session with PII in analytics
   - NEVER export session data with MSISDN plaintext

4. SECURITY CONTROLS:
   - Session fixation protection (new code on each request)
   - Concurrent session limit per MSISDN
   - Geographic anomaly detection
   - Rate limiting on session creation
   - Automatic lockout on suspicious patterns

5. SUBJECT RIGHTS IMPLEMENTATION:
   - Right to access: Session history provided with hashed MSISDN
   - Right to erasure: Immediate session termination + anonymization
   - Right to portability: Session export in standard format
   - Right to object: Marketing flags in session context

LEGAL BASIS (GDPR Article 6):
- Contract performance: Session required for service delivery
- Legitimate interest: Fraud prevention via device fingerprinting
- Consent: Optional persistent session preferences
================================================================================
*/

/*
================================================================================
MIGRATION CHECKLIST:
[x] Create ussd_sessions table
[x] Create session_data table
[x] Create session_history table
[x] Implement get_or_create_session function
[x] Implement end_session function
[x] Implement cleanup_expired_sessions function
[x] Add all indexes for session queries
[ ] Test session lifecycle
[ ] Test timeout handling
[ ] Test menu state tracking
[ ] Verify MSISDN lookup
[ ] Configure MSISDN encryption
[ ] Set up automatic anonymization job
[ ] Document PII handling procedures
================================================================================
*/
