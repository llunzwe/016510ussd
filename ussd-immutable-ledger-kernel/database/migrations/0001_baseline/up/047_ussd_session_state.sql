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
-- TODO: Create ussd_sessions table
-- DESCRIPTION: Active USSD sessions
-- PRIORITY: CRITICAL
-- SECURITY: RLS by application_id; MSISDN encrypted
-- PII: MSISDN encrypted; account_id pseudonymized
-- AUDIT: Session creation/destruction logged; inputs NOT logged
-- RETENTION: Auto-expired after 5 minutes; history anonymized after 90 days
-- =============================================================================
-- TODO: [USSD-001] Create ussd.ussd_sessions table
-- INSTRUCTIONS:
--   - Active session tracking
--   - Links to account and application
--   - Menu state storage
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE ussd.ussd_sessions (
--       session_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       session_code        VARCHAR(100) UNIQUE NOT NULL, -- External session ID
--       
--       -- User (PII - ENCRYPTED)
--       msisdn              VARCHAR(20) NOT NULL,        -- Phone number (PII)
--       msisdn_encrypted    BYTEA,                       -- Encrypted at rest
--       account_id          UUID REFERENCES core.accounts(account_id), -- Pseudonym
--       
--       -- Application
--       application_id      UUID REFERENCES app.applications(application_id),
--       current_role_id     UUID REFERENCES app.roles(role_id),
--       
--       -- Session State
--       menu_state          VARCHAR(100) DEFAULT 'START', -- Current menu position
--       previous_menu       VARCHAR(100),                -- For back navigation
--       
--       -- Context (no PII stored here)
--       context_data        JSONB DEFAULT '{}',          -- Session variables
--       input_history       TEXT[],                      -- Previous inputs (NO PINs)
--       
--       -- Language
--       language_code       VARCHAR(10) DEFAULT 'en',
--       
--       -- Timing (GDPR storage limitation)
--       started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       last_activity_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
--       expires_at          TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '5 minutes'),
--       
--       -- Status
--       status              VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, SUSPENDED, ENDED, TIMEOUT
--       
--       -- Device (fingerprinting - hashed)
--       device_fingerprint  VARCHAR(255),
--       network_operator    VARCHAR(50),
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );
--
-- CONSTRAINTS:
--   - Active session per MSISDN per application

-- =============================================================================
-- TODO: Create session_data table
-- DESCRIPTION: Persistent session variables
-- PRIORITY: MEDIUM
-- SECURITY: Same RLS as parent session
-- PII: No direct PII; encrypted session reference
-- =============================================================================
-- TODO: [USSD-002] Create ussd.session_data table
-- INSTRUCTIONS:
--   - Key-value storage for session
--   - Survives menu transitions
--   - Typed values
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE ussd.session_data (
--       data_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       session_id          UUID NOT NULL REFERENCES ussd.ussd_sessions(session_id),
--       
--       -- Key-Value
--       data_key            VARCHAR(100) NOT NULL,
--       data_value          JSONB NOT NULL,
--       value_type          VARCHAR(20) DEFAULT 'STRING', -- STRING, NUMBER, BOOLEAN, JSON
--       
--       -- Scope
--       is_persistent       BOOLEAN DEFAULT false,       -- Survive session timeout
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       updated_at          TIMESTAMPTZ,
--       
--       UNIQUE (session_id, data_key)
--   );

-- =============================================================================
-- TODO: Create session_history table
-- DESCRIPTION: Session audit trail
-- PRIORITY: MEDIUM
-- SECURITY: RLS enforced; anonymized after 90 days
-- PII: MSISDN hashed; no account identifiers
-- GDPR: Implements storage limitation principle
-- =============================================================================
-- TODO: [USSD-003] Create ussd.session_history table
-- INSTRUCTIONS:
--   - Record of session interactions
--   - Menu navigation history
--   - Input/output logging
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE ussd.session_history (
--       history_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       session_id          UUID NOT NULL REFERENCES ussd.ussd_sessions(session_id),
--       
--       -- Interaction
--       interaction_type    VARCHAR(20) NOT NULL,        -- MENU_DISPLAY, INPUT, ERROR
--       menu_id             VARCHAR(100),
--       user_input          TEXT,                        -- NEVER log PINs
--       system_response     TEXT,
--       
--       -- Timing
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create get_or_create_session function
-- DESCRIPTION: Session management
-- PRIORITY: CRITICAL
-- SECURITY: Validates MSISDN format; encrypts PII
-- AUDIT: Logs session creation; never logs PIN inputs
-- DATA PROTECTION: MSISDN encrypted before storage
-- =============================================================================
-- TODO: [USSD-004] Create get_or_create_session function
-- INSTRUCTIONS:
--   - Find existing active session
--   - Create new if not found or expired
--   - Update activity timestamp
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION ussd.get_or_create_session(
--       p_msisdn VARCHAR(20),
--       p_session_code VARCHAR(100),
--       p_application_id UUID DEFAULT NULL
--   ) RETURNS UUID AS $$
--   DECLARE
--       v_session_id UUID;
--       v_account_id UUID;
--   BEGIN
--       -- Try to find existing active session
--       SELECT session_id INTO v_session_id
--       FROM ussd.ussd_sessions
--       WHERE msisdn = p_msisdn
--           AND status = 'ACTIVE'
--           AND expires_at > now()
--       ORDER BY last_activity_at DESC
--       LIMIT 1;
--       
--       IF v_session_id IS NOT NULL THEN
--           -- Update activity
--           UPDATE ussd.ussd_sessions
--           SET last_activity_at = now(),
--               expires_at = now() + interval '5 minutes',
--               session_code = p_session_code
--           WHERE session_id = v_session_id;
--           
--           RETURN v_session_id;
--       END IF;
--       
--       -- Find account by MSISDN
--       SELECT account_id INTO v_account_id
--       FROM core.accounts
--       WHERE metadata->>'msisdn' = p_msisdn
--           AND valid_to IS NULL
--       LIMIT 1;
--       
--       -- Create new session
--       INSERT INTO ussd.ussd_sessions (
--           session_code, msisdn, account_id, application_id
--       ) VALUES (
--           p_session_code, p_msisdn, v_account_id, p_application_id
--       )
--       RETURNING session_id INTO v_session_id;
--       
--       RETURN v_session_id;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create end_session function
-- DESCRIPTION: Terminate USSD session
-- PRIORITY: HIGH
-- SECURITY: Validates session ownership
-- DATA PROTECTION: Triggers anonymization schedule
-- =============================================================================
-- TODO: [USSD-005] Create end_session function
-- INSTRUCTIONS:
--   - Mark session as ended
--   - Record final state
--   - Cleanup transient data

-- =============================================================================
-- TODO: Create session cleanup function
-- DESCRIPTION: Remove expired sessions
-- PRIORITY: MEDIUM
-- SECURITY: Background job; restricted execution
-- DATA PROTECTION: Anonymizes rather than deletes for analytics
-- =============================================================================
-- TODO: [USSD-006] Create cleanup_expired_sessions function
-- INSTRUCTIONS:
--   - Find expired sessions
--   - Archive if needed
--   - Delete or mark timeout

-- =============================================================================
-- TODO: Create session indexes
-- DESCRIPTION: Optimize session queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for USSD response time (< 2 seconds)
-- =============================================================================
-- TODO: [USSD-007] Create session indexes
-- INDEX LIST:
--   -- Sessions:
--   - PRIMARY KEY (session_id)
--   - UNIQUE (session_code)
--   - INDEX on (msisdn, status, expires_at)
--   - INDEX on (account_id, status)
--   - INDEX on (application_id, status)
--   - INDEX on (status, expires_at) WHERE status = 'ACTIVE'
--   -- Session Data:
--   - PRIMARY KEY (data_id)
--   - UNIQUE (session_id, data_key)
--   -- History:
--   - PRIMARY KEY (history_id)
--   - INDEX on (session_id, created_at)

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
□ Create ussd_sessions table
□ Create session_data table
□ Create session_history table
□ Implement get_or_create_session function
□ Implement end_session function
□ Implement cleanup_expired_sessions function
□ Add all indexes for session queries
□ Test session lifecycle
□ Test timeout handling
□ Test menu state tracking
□ Verify MSISDN lookup
□ Configure MSISDN encryption
□ Set up automatic anonymization job
□ Document PII handling procedures
================================================================================
*/
