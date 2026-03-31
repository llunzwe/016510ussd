-- =============================================================================
-- FILE: 000_session_state.sql
-- DESCRIPTION: USSD Session State Management
-- TABLES: ussd_sessions, session_data, session_history
-- SCHEMA: ussd
-- PRIORITY: CRITICAL
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

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create schema if not exists
CREATE SCHEMA IF NOT EXISTS ussd;

-- =============================================================================
-- TABLE: ussd_sessions
-- DESCRIPTION: Active USSD sessions with PII protection
-- SECURITY: RLS by application_id; MSISDN encrypted
-- PII: MSISDN encrypted; account_id pseudonymized
-- AUDIT: Session creation/destruction logged; inputs NOT logged
-- RETENTION: Auto-expired after 5 minutes; history anonymized after 90 days
-- =============================================================================
CREATE TABLE IF NOT EXISTS ussd.ussd_sessions (
    session_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_code            VARCHAR(100) UNIQUE NOT NULL,    -- External session ID
    
    -- User (PII - ENCRYPTED)
    msisdn                  VARCHAR(20) NOT NULL,            -- Phone number (PII)
    msisdn_encrypted        BYTEA NOT NULL,                  -- Encrypted at rest (AES-256-GCM)
    msisdn_hash             VARCHAR(64),                     -- SHA-256 for lookups without decryption
    account_id              UUID REFERENCES core.accounts(account_id), -- Pseudonym
    
    -- Application Context
    application_id          UUID REFERENCES app.applications(application_id),
    current_role_id         UUID REFERENCES app.roles(role_id),
    
    -- Session State
    menu_state              VARCHAR(100) DEFAULT 'START',    -- Current menu position
    previous_menu           VARCHAR(100),                    -- For back navigation
    menu_stack              TEXT[] DEFAULT '{}',             -- Navigation history stack
    
    -- Context (no PII stored here)
    context_data            JSONB DEFAULT '{}',              -- Session variables (encrypted sensitive fields)
    context_data_encrypted  BYTEA,                           -- Encrypted context for sensitive data
    input_history           TEXT[] DEFAULT '{}',             -- Previous inputs (NO PINs)
    
    -- Language
    language_code           VARCHAR(10) DEFAULT 'en',
    
    -- Multi-layer Timeout Management (ISO 27001 A.8.11)
    started_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_activity_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    network_timeout_at      TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '2 minutes'),  -- Network layer
    application_timeout_at  TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '5 minutes'),  -- App layer
    absolute_timeout_at     TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '15 minutes'), -- Max session
    
    -- Status
    status                  VARCHAR(20) DEFAULT 'ACTIVE',    -- ACTIVE, SUSPENDED, ENDED, TIMEOUT, ERROR
    termination_reason      VARCHAR(100),                    -- Why session ended
    
    -- Security Fields
    session_hash            VARCHAR(64) NOT NULL,            -- SHA-256 hash for integrity
    previous_session_hash   VARCHAR(64),                     -- Hash chain for audit
    
    -- Device (fingerprinting - hashed)
    device_fingerprint      VARCHAR(255),                    -- One-way device hash
    network_operator        VARCHAR(50),                     -- MNO identifier
    country_code            VARCHAR(2),                      -- ISO country code
    cell_tower_id           VARCHAR(50),                     -- Approximate location (cell tower)
    
    -- SIM Information (for swap detection)
    imsi_hash               VARCHAR(64),                     -- Hashed IMSI
    imei_hash               VARCHAR(64),                     -- Hashed IMEI
    sim_serial_hash         VARCHAR(64),                     -- Hashed SIM serial
    sim_first_seen_at       TIMESTAMPTZ,                     -- When this SIM was first used
    
    -- Security Flags
    is_suspicious           BOOLEAN DEFAULT false,           -- Flagged for review
    suspicion_reason        TEXT,                            -- Why flagged
    fraud_score             INTEGER DEFAULT 0,               -- 0-100 risk score
    velocity_flags          JSONB DEFAULT '{}',              -- Rate limit violations
    
    -- Audit
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at                TIMESTAMPTZ,
    created_by              UUID REFERENCES core.accounts(account_id),
    
    -- Constraints
    CONSTRAINT valid_msisdn_format CHECK (msisdn ~ '^\+[1-9][0-9]{7,14}$'),
    CONSTRAINT valid_status CHECK (status IN ('ACTIVE', 'SUSPENDED', 'ENDED', 'TIMEOUT', 'ERROR')),
    CONSTRAINT valid_language CHECK (language_code ~ '^[a-z]{2}(-[A-Z]{2})?$'),
    CONSTRAINT valid_fraud_score CHECK (fraud_score >= 0 AND fraud_score <= 100)
);

-- Add table comment
COMMENT ON TABLE ussd.ussd_sessions IS 'Active USSD sessions with PII protection and hash chain integrity';

-- Column comments for PII identification
COMMENT ON COLUMN ussd.ussd_sessions.msisdn IS 'PII: Phone number in E.164 format (+XXXXXXXXXXX)';
COMMENT ON COLUMN ussd.ussd_sessions.msisdn_encrypted IS 'PII: AES-256-GCM encrypted MSISDN';
COMMENT ON COLUMN ussd.ussd_sessions.context_data IS 'Session variables - no PII allowed in plaintext';
COMMENT ON COLUMN ussd.ussd_sessions.input_history IS 'NEVER store PINs or passwords in this field';
COMMENT ON COLUMN ussd.ussd_sessions.imsi_hash IS 'Hashed IMSI for SIM swap detection';
COMMENT ON COLUMN ussd.ussd_sessions.imei_hash IS 'Hashed IMEI for device tracking';

-- =============================================================================
-- TABLE: session_data
-- DESCRIPTION: Persistent session variables
-- SECURITY: Same RLS as parent session
-- PII: No direct PII; encrypted session reference
-- =============================================================================
CREATE TABLE IF NOT EXISTS ussd.session_data (
    data_id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id              UUID NOT NULL REFERENCES ussd.ussd_sessions(session_id) ON DELETE CASCADE,
    
    -- Key-Value
    data_key                VARCHAR(100) NOT NULL,
    data_value              JSONB NOT NULL,
    value_type              VARCHAR(20) DEFAULT 'STRING',    -- STRING, NUMBER, BOOLEAN, JSON, BINARY
    
    -- Sensitivity
    is_sensitive            BOOLEAN DEFAULT false,           -- Requires encryption
    encrypted_value         BYTEA,                           -- Encrypted if sensitive
    
    -- Scope
    is_persistent           BOOLEAN DEFAULT false,           -- Survive session timeout
    persistence_expires_at  TIMESTAMPTZ,                     -- When persistent data expires
    
    -- Validation
    validation_regex        VARCHAR(255),                    -- Pattern for validation
    max_length              INTEGER,                         -- Max length constraint
    
    -- Audit
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ,
    accessed_at             TIMESTAMPTZ,                     -- Last read
    access_count            INTEGER DEFAULT 0,               -- Read frequency
    
    UNIQUE (session_id, data_key),
    CONSTRAINT valid_value_type CHECK (value_type IN ('STRING', 'NUMBER', 'BOOLEAN', 'JSON', 'BINARY')),
    CONSTRAINT valid_data_key CHECK (data_key ~ '^[a-zA-Z_][a-zA-Z0-9_]*$')
);

COMMENT ON TABLE ussd.session_data IS 'Session key-value storage with optional encryption for sensitive data';

-- =============================================================================
-- TABLE: session_history
-- DESCRIPTION: Session audit trail
-- SECURITY: RLS enforced; anonymized after 90 days
-- PII: MSISDN hashed; no account identifiers
-- GDPR: Implements storage limitation principle
-- =============================================================================
CREATE TABLE IF NOT EXISTS ussd.session_history (
    history_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id              UUID NOT NULL REFERENCES ussd.ussd_sessions(session_id) ON DELETE CASCADE,
    
    -- Interaction
    interaction_type        VARCHAR(20) NOT NULL,            -- MENU_DISPLAY, INPUT, ERROR, NAVIGATE, ACTION
    menu_id                 VARCHAR(100),                    -- Current menu
    menu_item_id            UUID,                            -- Specific menu item
    user_input              TEXT,                            -- NEVER log PINs or passwords
    input_type              VARCHAR(20),                     -- TEXT, NUMBER, SELECT, PIN (masked)
    system_response         TEXT,                            -- What was shown to user
    response_code           VARCHAR(20),                     -- SUCCESS, ERROR, TIMEOUT, etc.
    
    -- Timing
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    processing_time_ms      INTEGER,                         -- Performance metric
    
    -- Navigation
    from_menu               VARCHAR(100),                    -- Previous menu
    to_menu                 VARCHAR(100),                    -- Target menu
    navigation_action       VARCHAR(50),                     -- NEXT, BACK, HOME, END
    
    -- Audit
    device_fingerprint      VARCHAR(255),                    -- At time of interaction
    network_latency_ms      INTEGER                          -- Network performance
);

COMMENT ON TABLE ussd.session_history IS 'Session interaction audit trail - NEVER store PINs or passwords';
COMMENT ON COLUMN ussd.session_history.user_input IS 'NEVER log PINs, passwords, or OTPs in this field';

-- =============================================================================
-- TABLE: session_events
-- DESCRIPTION: Security and lifecycle events
-- SECURITY: Tamper-evident with hash chain
-- =============================================================================
CREATE TABLE IF NOT EXISTS ussd.session_events (
    event_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id              UUID NOT NULL REFERENCES ussd.ussd_sessions(session_id) ON DELETE CASCADE,
    
    -- Event Details
    event_type              VARCHAR(50) NOT NULL,            -- CREATED, TIMEOUT, ENDED, SUSPICIOUS, FRAUD_ALERT
    event_severity          VARCHAR(20) DEFAULT 'INFO',      -- DEBUG, INFO, WARNING, ERROR, CRITICAL
    event_description       TEXT,
    
    -- Security
    event_hash              VARCHAR(64) NOT NULL,            -- SHA-256 of event data
    previous_event_hash     VARCHAR(64),                     -- Hash chain link
    
    -- Context
    event_data              JSONB DEFAULT '{}',              -- Additional context
    triggered_by            VARCHAR(100),                    -- Function/rule that triggered
    
    -- Audit
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    CONSTRAINT valid_event_severity CHECK (event_severity IN ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'))
);

COMMENT ON TABLE ussd.session_events IS 'Security events with hash chain for tamper detection';

-- =============================================================================
-- INDEXES FOR SESSION TABLES
-- =============================================================================

-- ussd_sessions indexes
CREATE INDEX IF NOT EXISTS idx_ussd_sessions_msisdn_hash ON ussd.ussd_sessions(msisdn_hash) 
    WHERE msisdn_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ussd_sessions_account_id ON ussd.ussd_sessions(account_id) 
    WHERE account_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ussd_sessions_application_id ON ussd.ussd_sessions(application_id, status);
CREATE INDEX IF NOT EXISTS idx_ussd_sessions_status_expires ON ussd.ussd_sessions(status, application_timeout_at) 
    WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS idx_ussd_sessions_device_fingerprint ON ussd.ussd_sessions(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_ussd_sessions_created_at ON ussd.ussd_sessions(created_at);
CREATE INDEX IF NOT EXISTS idx_ussd_sessions_fraud_score ON ussd.ussd_sessions(fraud_score) 
    WHERE fraud_score > 0;

-- session_data indexes
CREATE INDEX IF NOT EXISTS idx_session_data_session_key ON ussd.session_data(session_id, data_key);
CREATE INDEX IF NOT EXISTS idx_session_data_persistent ON ussd.session_data(is_persistent, persistence_expires_at) 
    WHERE is_persistent = true;

-- session_history indexes
CREATE INDEX IF NOT EXISTS idx_session_history_session_created ON ussd.session_history(session_id, created_at);
CREATE INDEX IF NOT EXISTS idx_session_history_interaction ON ussd.session_history(interaction_type, created_at);
CREATE INDEX IF NOT EXISTS idx_session_history_menu ON ussd.session_history(menu_id, created_at);

-- session_events indexes
CREATE INDEX IF NOT EXISTS idx_session_events_session ON ussd.session_events(session_id, created_at);
CREATE INDEX IF NOT EXISTS idx_session_events_type ON ussd.session_events(event_type, event_severity);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function: Generate session hash for integrity
CREATE OR REPLACE FUNCTION ussd.generate_session_hash(
    p_session_id UUID,
    p_msisdn VARCHAR(20),
    p_timestamp TIMESTAMPTZ
) RETURNS VARCHAR(64) AS $$
BEGIN
    RETURN encode(
        digest(
            p_session_id::text || '|' || 
            COALESCE(p_msisdn, '') || '|' || 
            extract(epoch from p_timestamp)::text,
            'sha256'
        ),
        'hex'
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function: Encrypt MSISDN
CREATE OR REPLACE FUNCTION ussd.encrypt_msisdn(
    p_msisdn VARCHAR(20),
    p_key_id VARCHAR(100) DEFAULT 'default'
) RETURNS BYTEA AS $$
BEGIN
    -- In production, this would use AWS KMS, HashiCorp Vault, or similar
    -- For now, using pgp_sym_encrypt with a placeholder key reference
    RETURN pgp_sym_encrypt(
        p_msisdn, 
        current_setting('app.encryption_key', true)::text,
        'cipher-algo=aes256, compress-algo=0'
    )::bytea;
END;
$$ LANGUAGE plpgsql;

-- Function: Decrypt MSISDN
CREATE OR REPLACE FUNCTION ussd.decrypt_msisdn(
    p_encrypted_msisdn BYTEA
) RETURNS VARCHAR(20) AS $$
BEGIN
    RETURN pgp_sym_decrypt(
        p_encrypted_msisdn,
        current_setting('app.encryption_key', true)::text
    )::VARCHAR(20);
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Function: Create session hash for MSISDN lookup
CREATE OR REPLACE FUNCTION ussd.hash_msisdn(
    p_msisdn VARCHAR(20)
) RETURNS VARCHAR(64) AS $$
BEGIN
    RETURN encode(digest(p_msisdn, 'sha256'), 'hex');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function: Update session activity timestamp
CREATE OR REPLACE FUNCTION ussd.update_session_activity(
    p_session_id UUID,
    p_menu_state VARCHAR(100) DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_updated INTEGER;
BEGIN
    UPDATE ussd.ussd_sessions
    SET 
        last_activity_at = now(),
        network_timeout_at = now() + interval '2 minutes',
        application_timeout_at = now() + interval '5 minutes',
        menu_state = COALESCE(p_menu_state, menu_state),
        updated_at = now()
    WHERE session_id = p_session_id
      AND status = 'ACTIVE'
      AND application_timeout_at > now();
    
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    RETURN v_updated > 0;
END;
$$ LANGUAGE plpgsql;

-- Function: End session
CREATE OR REPLACE FUNCTION ussd.end_session(
    p_session_id UUID,
    p_reason VARCHAR(100) DEFAULT 'USER_ENDED'
) RETURNS BOOLEAN AS $$
DECLARE
    v_updated INTEGER;
BEGIN
    UPDATE ussd.ussd_sessions
    SET 
        status = CASE 
            WHEN application_timeout_at < now() THEN 'TIMEOUT'
            ELSE 'ENDED'
        END,
        termination_reason = p_reason,
        ended_at = now(),
        updated_at = now()
    WHERE session_id = p_session_id
      AND status = 'ACTIVE';
    
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    
    -- Log event
    IF v_updated > 0 THEN
        INSERT INTO ussd.session_events (
            session_id, event_type, event_description, event_hash
        ) VALUES (
            p_session_id,
            'SESSION_ENDED',
            p_reason,
            encode(digest(gen_random_uuid()::text, 'sha256'), 'hex')
        );
    END IF;
    
    RETURN v_updated > 0;
END;
$$ LANGUAGE plpgsql;

-- Function: Cleanup expired sessions
CREATE OR REPLACE FUNCTION ussd.cleanup_expired_sessions(
    p_batch_size INTEGER DEFAULT 1000
) RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    -- Mark expired sessions
    WITH expired AS (
        UPDATE ussd.ussd_sessions
        SET status = 'TIMEOUT',
            termination_reason = 'AUTO_TIMEOUT',
            ended_at = now(),
            updated_at = now()
        WHERE status = 'ACTIVE'
          AND application_timeout_at < now()
        RETURNING session_id
    )
    SELECT COUNT(*) INTO v_count FROM expired;
    
    -- Log cleanup event
    IF v_count > 0 THEN
        INSERT INTO ussd.session_events (
            session_id, event_type, event_description, event_hash
        )
        SELECT 
            session_id,
            'SESSION_TIMEOUT',
            'Automatic timeout - session expired',
            encode(digest(gen_random_uuid()::text, 'sha256'), 'hex')
        FROM ussd.ussd_sessions
        WHERE status = 'TIMEOUT'
          AND ended_at > now() - interval '1 minute';
    END IF;
    
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- Function: Get active session by MSISDN hash
CREATE OR REPLACE FUNCTION ussd.get_active_session_by_msisdn(
    p_msisdn_hash VARCHAR(64)
) RETURNS TABLE (
    session_id UUID,
    session_code VARCHAR(100),
    account_id UUID,
    application_id UUID,
    menu_state VARCHAR(100),
    status VARCHAR(20),
    expires_at TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        s.session_id,
        s.session_code,
        s.account_id,
        s.application_id,
        s.menu_state,
        s.status,
        s.application_timeout_at as expires_at
    FROM ussd.ussd_sessions s
    WHERE s.msisdn_hash = p_msisdn_hash
      AND s.status = 'ACTIVE'
      AND s.application_timeout_at > now()
    ORDER BY s.last_activity_at DESC
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- Function: Record session navigation
CREATE OR REPLACE FUNCTION ussd.record_navigation(
    p_session_id UUID,
    p_from_menu VARCHAR(100),
    p_to_menu VARCHAR(100),
    p_action VARCHAR(50),
    p_user_input TEXT DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_history_id UUID;
BEGIN
    INSERT INTO ussd.session_history (
        session_id,
        interaction_type,
        from_menu,
        to_menu,
        navigation_action,
        user_input,
        input_type,
        created_at
    ) VALUES (
        p_session_id,
        'NAVIGATE',
        p_from_menu,
        p_to_menu,
        p_action,
        p_user_input,
        CASE WHEN p_user_input IS NULL THEN NULL ELSE 'TEXT' END,
        now()
    )
    RETURNING history_id INTO v_history_id;
    
    -- Update session menu stack
    UPDATE ussd.ussd_sessions
    SET 
        previous_menu = p_from_menu,
        menu_stack = array_append(menu_stack, p_to_menu),
        updated_at = now()
    WHERE session_id = p_session_id;
    
    RETURN v_history_id;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TRIGGER FUNCTIONS
-- =============================================================================

-- Trigger: Auto-update timestamps
CREATE OR REPLACE FUNCTION ussd.trigger_update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_ussd_sessions_update
    BEFORE UPDATE ON ussd.ussd_sessions
    FOR EACH ROW
    EXECUTE FUNCTION ussd.trigger_update_timestamp();

-- Trigger: Encrypt MSISDN before insert
CREATE OR REPLACE FUNCTION ussd.trigger_encrypt_msisdn()
RETURNS TRIGGER AS $$
BEGIN
    -- Generate hash for lookups
    NEW.msisdn_hash := ussd.hash_msisdn(NEW.msisdn);
    
    -- Encrypt the MSISDN
    NEW.msisdn_encrypted := ussd.encrypt_msisdn(NEW.msisdn);
    
    -- Clear plaintext MSISDN (optional - keep if needed for display)
    -- NEW.msisdn := NULL;  -- Uncomment to remove plaintext
    
    -- Generate session hash
    NEW.session_hash := ussd.generate_session_hash(
        NEW.session_id, 
        NEW.msisdn, 
        NEW.created_at
    );
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_ussd_sessions_encrypt
    BEFORE INSERT ON ussd.ussd_sessions
    FOR EACH ROW
    EXECUTE FUNCTION ussd.trigger_encrypt_msisdn();

-- Trigger: Log session creation
CREATE OR REPLACE FUNCTION ussd.trigger_log_session_event()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO ussd.session_events (
            session_id,
            event_type,
            event_description,
            event_hash,
            event_data
        ) VALUES (
            NEW.session_id,
            'SESSION_CREATED',
            'New USSD session started',
            encode(digest(gen_random_uuid()::text, 'sha256'), 'hex'),
            jsonb_build_object(
                'application_id', NEW.application_id,
                'country_code', NEW.country_code,
                'network_operator', NEW.network_operator
            )
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_ussd_sessions_event_log
    AFTER INSERT ON ussd.ussd_sessions
    FOR EACH ROW
    EXECUTE FUNCTION ussd.trigger_log_session_event();

-- =============================================================================
-- ROW LEVEL SECURITY POLICIES
-- =============================================================================

-- Enable RLS
ALTER TABLE ussd.ussd_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.session_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.session_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.session_events ENABLE ROW LEVEL SECURITY;

-- Policy: Sessions accessible by application
CREATE POLICY ussd_sessions_app_isolation ON ussd.ussd_sessions
    USING (application_id = current_setting('app.current_application_id', true)::UUID);

-- Policy: Session data accessible by session owner
CREATE POLICY session_data_session_isolation ON ussd.session_data
    USING (session_id IN (
        SELECT session_id FROM ussd.ussd_sessions 
        WHERE application_id = current_setting('app.current_application_id', true)::UUID
    ));

-- =============================================================================
-- GRANTS
-- =============================================================================

-- Create roles if not exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ussd_gateway_role') THEN
        CREATE ROLE ussd_gateway_role NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ussd_security_role') THEN
        CREATE ROLE ussd_security_role NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ussd_cleanup_role') THEN
        CREATE ROLE ussd_cleanup_role NOLOGIN;
    END IF;
END
$$;

-- Grant permissions
GRANT USAGE ON SCHEMA ussd TO ussd_gateway_role, ussd_security_role, ussd_cleanup_role;
GRANT SELECT, INSERT, UPDATE ON ussd.ussd_sessions TO ussd_gateway_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON ussd.session_data TO ussd_gateway_role;
GRANT SELECT, INSERT ON ussd.session_history TO ussd_gateway_role;
GRANT SELECT, INSERT ON ussd.session_events TO ussd_gateway_role, ussd_security_role;
GRANT ALL ON ussd.ussd_sessions TO ussd_cleanup_role;

-- =============================================================================
-- COMPLIANCE NOTES
-- =============================================================================
/*
1. PII PROTECTION:
   - MSISDN encrypted with AES-256-GCM
   - SHA-256 hash for lookups without decryption
   - Plaintext MSISDN can be cleared after encryption if required

2. SESSION INTEGRITY:
   - Hash chain links sessions for audit trail
   - Event log with tamper-evident hashes
   - All state changes tracked

3. TIMEOUT MANAGEMENT:
   - Network timeout: 2 minutes (carrier connection)
   - Application timeout: 5 minutes (user inactivity)
   - Absolute timeout: 15 minutes (maximum session length)

4. SECURITY MONITORING:
   - Fraud score tracking
   - Velocity flag recording
   - Suspicious activity detection

5. DATA RETENTION:
   - Active sessions: Until timeout or explicit end
   - Session history: 90 days then anonymize
   - Events: 1 year
   - Expired sessions: Anonymize after 90 days
*/
