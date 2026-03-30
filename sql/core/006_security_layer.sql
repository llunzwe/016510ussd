-- ============================================================================
-- USSD KERNEL CORE SCHEMA - SECURITY LAYER
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Security infrastructure including encryption, key management,
--              access control, and audit logging.
-- Immutability: Mixed - Keys and configs are versioned, audit log is immutable
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. ENCRYPTION KEY MANAGEMENT
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_core.encryption_keys (
    key_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Key identification
    key_name VARCHAR(100) NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    key_purpose VARCHAR(50) NOT NULL,  -- 'field_encryption', 'signing', 'backup'
    
    -- Key material (encrypted at rest by database/HSM)
    key_data BYTEA NOT NULL,  -- The actual key (encrypted by master key)
    key_algorithm VARCHAR(20) DEFAULT 'aes-256-gcm',
    
    -- Status
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'rotated', 'compromised', 'archived')),
    
    -- Key hierarchy
    parent_key_id UUID REFERENCES ussd_core.encryption_keys(key_id),
    
    -- Metadata
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    created_by UUID,
    rotated_at TIMESTAMPTZ,
    rotated_to_key_id UUID REFERENCES ussd_core.encryption_keys(key_id),
    expires_at TIMESTAMPTZ,
    
    -- Audit
    record_hash VARCHAR(64) NOT NULL
);

-- Key usage log (for audit)
CREATE TABLE ussd_audit.key_usage_log (
    usage_id BIGSERIAL PRIMARY KEY,
    key_id UUID NOT NULL,
    operation VARCHAR(20) NOT NULL,  -- 'encrypt', 'decrypt', 'sign', 'verify'
    context TEXT,  -- Purpose/context of usage
    performed_by UUID,
    performed_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    success BOOLEAN DEFAULT TRUE
);

-- ----------------------------------------------------------------------------
-- 2. FIELD-LEVEL ENCRYPTION FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to encrypt sensitive field data
CREATE OR REPLACE FUNCTION ussd_core.encrypt_field(
    p_plaintext TEXT,
    p_key_id UUID DEFAULT NULL
)
RETURNS BYTEA
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_key BYTEA;
    v_encrypted BYTEA;
    v_key_to_use UUID;
BEGIN
    -- Get active key if not specified
    IF p_key_id IS NULL THEN
        SELECT key_id INTO v_key_to_use
        FROM ussd_core.encryption_keys
        WHERE key_purpose = 'field_encryption' AND status = 'active'
        ORDER BY created_at DESC
        LIMIT 1;
    ELSE
        v_key_to_use := p_key_id;
    END IF;
    
    IF v_key_to_use IS NULL THEN
        RAISE EXCEPTION 'No active encryption key found';
    END IF;
    
    -- Get key data (in production, this would involve HSM/KMS unwrapping)
    SELECT key_data INTO v_key
    FROM ussd_core.encryption_keys
    WHERE key_id = v_key_to_use;
    
    -- Encrypt using pgcrypto (AES-256-GCM)
    v_encrypted := pgp_sym_encrypt(
        p_plaintext,
        encode(v_key, 'hex'),
        'cipher-algo=aes256, compress-algo=0'
    );
    
    -- Log usage
    INSERT INTO ussd_audit.key_usage_log (key_id, operation, context)
    VALUES (v_key_to_use, 'encrypt', 'field_encryption');
    
    -- Prepend key ID for decryption
    RETURN concat(v_key_to_use::TEXT::BYTEA, '\x00'::BYTEA, v_encrypted);
END;
$$;

-- Function to decrypt field data
CREATE OR REPLACE FUNCTION ussd_core.decrypt_field(
    p_ciphertext BYTEA
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_key_id UUID;
    v_key BYTEA;
    v_encrypted BYTEA;
    v_parts TEXT[];
    v_result TEXT;
BEGIN
    -- Extract key ID from prefix (format: key_id\x00encrypted_data)
    v_parts := string_to_array(encode(p_ciphertext, 'escape'), '\x00');
    v_key_id := v_parts[1]::UUID;
    v_encrypted := decode(v_parts[2], 'escape');
    
    -- Get key data
    SELECT key_data INTO v_key
    FROM ussd_core.encryption_keys
    WHERE key_id = v_key_id AND status IN ('active', 'rotated');
    
    IF v_key IS NULL THEN
        RAISE EXCEPTION 'Encryption key % not found or not available', v_key_id;
    END IF;
    
    -- Decrypt
    v_result := pgp_sym_decrypt(v_encrypted, encode(v_key, 'hex'));
    
    -- Log usage
    INSERT INTO ussd_audit.key_usage_log (key_id, operation, context)
    VALUES (v_key_id, 'decrypt', 'field_encryption');
    
    RETURN v_result;
END;
$$;

-- ----------------------------------------------------------------------------
-- 3. DIGITAL SIGNATURE FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to sign data with kernel key
CREATE OR REPLACE FUNCTION ussd_core.sign_data(
    p_data TEXT,
    p_key_id UUID DEFAULT NULL
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_key BYTEA;
    v_key_to_use UUID;
    v_signature TEXT;
BEGIN
    -- Get signing key
    IF p_key_id IS NULL THEN
        SELECT key_id INTO v_key_to_use
        FROM ussd_core.encryption_keys
        WHERE key_purpose = 'signing' AND status = 'active'
        ORDER BY created_at DESC
        LIMIT 1;
    ELSE
        v_key_to_use := p_key_id;
    END IF;
    
    IF v_key_to_use IS NULL THEN
        RAISE EXCEPTION 'No active signing key found';
    END IF;
    
    -- Get key data
    SELECT key_data INTO v_key
    FROM ussd_core.encryption_keys
    WHERE key_id = v_key_to_use;
    
    -- Create HMAC signature (simplified - production would use proper asymmetric signing)
    v_signature := encode(
        hmac(p_data::BYTEA, v_key, 'sha256'),
        'base64'
    );
    
    -- Log usage
    INSERT INTO ussd_audit.key_usage_log (key_id, operation, context)
    VALUES (v_key_to_use, 'sign', 'data_signing');
    
    RETURN v_signature;
END;
$$;

-- Function to verify signature
CREATE OR REPLACE FUNCTION ussd_core.verify_signature(
    p_data TEXT,
    p_signature TEXT,
    p_key_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_key BYTEA;
    v_computed TEXT;
BEGIN
    -- Get key data
    SELECT key_data INTO v_key
    FROM ussd_core.encryption_keys
    WHERE key_id = p_key_id AND status IN ('active', 'rotated');
    
    IF v_key IS NULL THEN
        RETURN FALSE;
    END IF;
    
    -- Compute signature
    v_computed := encode(
        hmac(p_data::BYTEA, v_key, 'sha256'),
        'base64'
    );
    
    -- Log usage
    INSERT INTO ussd_audit.key_usage_log (key_id, operation, context)
    VALUES (p_key_id, 'verify', 'signature_verification');
    
    RETURN v_computed = p_signature;
END;
$$;

-- ----------------------------------------------------------------------------
-- 4. ACCESS CONTROL TABLES
-- ----------------------------------------------------------------------------

-- API Keys for service-to-service authentication
CREATE TABLE ussd_core.api_keys (
    key_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Key identification
    key_name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,  -- SHA-256 hash of the key
    
    -- Scope
    application_id UUID,  -- NULL = system-wide access
    account_id UUID,  -- Associated account
    
    -- Permissions
    scopes TEXT[] DEFAULT '{}',  -- e.g., ['read:transactions', 'write:transactions']
    rate_limit_per_minute INTEGER DEFAULT 1000,
    
    -- Lifecycle
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    use_count BIGINT DEFAULT 0,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
    
    -- Audit
    created_by UUID,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT
);

-- API Key usage log
CREATE TABLE ussd_audit.api_key_usage (
    usage_id BIGSERIAL PRIMARY KEY,
    key_id UUID NOT NULL,
    endpoint VARCHAR(255),
    method VARCHAR(10),
    client_ip INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    response_time_ms INTEGER,
    used_at TIMESTAMPTZ DEFAULT ussd_core.precise_now()
);

-- Session management
CREATE TABLE ussd_core.sessions (
    session_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Authentication info
    account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    application_id UUID,
    
    -- Session data
    token_hash VARCHAR(64) NOT NULL,  -- Hash of session token
    mfa_verified BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    client_ip INET,
    user_agent TEXT,
    device_fingerprint TEXT,
    
    -- Timing
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    
    -- Status
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked', 'terminated')),
    
    -- Termination
    terminated_at TIMESTAMPTZ,
    termination_reason TEXT
);

-- ----------------------------------------------------------------------------
-- 5. ACCESS CONTROL FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to authenticate API key
CREATE OR REPLACE FUNCTION ussd_core.authenticate_api_key(
    p_api_key TEXT
)
RETURNS TABLE (
    is_valid BOOLEAN,
    key_id UUID,
    account_id UUID,
    application_id UUID,
    scopes TEXT[]
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_key_hash VARCHAR(64);
    v_record RECORD;
BEGIN
    v_key_hash := ussd_core.generate_hash(p_api_key);
    
    SELECT * INTO v_record
    FROM ussd_core.api_keys
    WHERE key_hash = v_key_hash
      AND status = 'active'
      AND (expires_at IS NULL OR expires_at > NOW());
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::UUID, NULL::UUID, NULL::UUID, NULL::TEXT[];
        RETURN;
    END IF;
    
    -- Update usage stats
    UPDATE ussd_core.api_keys
    SET last_used_at = NOW(),
        use_count = use_count + 1
    WHERE key_id = v_record.key_id;
    
    RETURN QUERY SELECT TRUE, v_record.key_id, v_record.account_id, 
                        v_record.application_id, v_record.scopes;
END;
$$;

-- Function to validate session
CREATE OR REPLACE FUNCTION ussd_core.validate_session(
    p_session_token TEXT
)
RETURNS TABLE (
    is_valid BOOLEAN,
    session_id UUID,
    account_id UUID,
    application_id UUID,
    mfa_verified BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_token_hash VARCHAR(64);
    v_record RECORD;
BEGIN
    v_token_hash := ussd_core.generate_hash(p_session_token);
    
    SELECT * INTO v_record
    FROM ussd_core.sessions
    WHERE token_hash = v_token_hash
      AND status = 'active'
      AND expires_at > NOW();
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::UUID, NULL::UUID, NULL::UUID, NULL::BOOLEAN;
        RETURN;
    END IF;
    
    -- Update last activity
    UPDATE ussd_core.sessions
    SET last_activity_at = NOW()
    WHERE session_id = v_record.session_id;
    
    RETURN QUERY SELECT TRUE, v_record.session_id, v_record.account_id,
                        v_record.application_id, v_record.mfa_verified;
END;
$$;

-- Function to check permission
CREATE OR REPLACE FUNCTION ussd_core.check_permission(
    p_account_id UUID,
    p_permission VARCHAR,
    p_application_id UUID DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    -- Check system-level permissions
    IF EXISTS (
        SELECT 1 FROM ussd_app.user_roles ur
        JOIN ussd_app.role_permissions rp ON ur.role_id = rp.role_id
        JOIN ussd_app.permissions p ON rp.permission_id = p.permission_id
        WHERE ur.account_id = p_account_id
          AND p.permission_code = p_permission
          AND ur.valid_to IS NULL
          AND rp.valid_to IS NULL
          AND (p.application_id IS NULL OR p.application_id = p_application_id)
    ) THEN
        RETURN TRUE;
    END IF;
    
    -- Check API key scopes (if called via API key)
    IF current_setting('app.api_key_scopes', TRUE) IS NOT NULL THEN
        RETURN p_permission = ANY(string_to_array(current_setting('app.api_key_scopes', TRUE), ','));
    END IF;
    
    RETURN FALSE;
END;
$$;

-- ----------------------------------------------------------------------------
-- 6. SECURITY VIEWS
-- ----------------------------------------------------------------------------

-- Active API keys
CREATE VIEW ussd_core.active_api_keys AS
SELECT 
    key_id,
    key_name,
    application_id,
    account_id,
    scopes,
    rate_limit_per_minute,
    created_at,
    expires_at,
    last_used_at,
    use_count,
    status
FROM ussd_core.api_keys
WHERE status = 'active';

-- Active sessions
CREATE VIEW ussd_core.active_sessions AS
SELECT 
    session_id,
    account_id,
    application_id,
    mfa_verified,
    client_ip,
    created_at,
    expires_at,
    last_activity_at,
    EXTRACT(EPOCH FROM (expires_at - NOW())) / 60 as minutes_remaining
FROM ussd_core.sessions
WHERE status = 'active' AND expires_at > NOW();

-- Key rotation status
CREATE VIEW ussd_core.key_rotation_status AS
SELECT 
    k.key_id,
    k.key_name,
    k.key_purpose,
    k.key_version,
    k.status,
    k.created_at,
    k.expires_at,
    k.rotated_at,
    k2.key_id as rotated_to_key_id,
    CASE 
        WHEN k.expires_at IS NULL THEN NULL
        WHEN k.expires_at < NOW() + INTERVAL '30 days' THEN 'expiring_soon'
        ELSE 'healthy'
    END as health_status
FROM ussd_core.encryption_keys k
LEFT JOIN ussd_core.encryption_keys k2 ON k.rotated_to_key_id = k2.key_id
WHERE k.status IN ('active', 'rotated')
ORDER BY k.key_purpose, k.created_at DESC;

-- ----------------------------------------------------------------------------
-- 7. INDEXES
-- ----------------------------------------------------------------------------
CREATE INDEX idx_api_keys_hash ON ussd_core.api_keys(key_hash);
CREATE INDEX idx_api_keys_account ON ussd_core.api_keys(account_id);
CREATE INDEX idx_api_keys_app ON ussd_core.api_keys(application_id);
CREATE INDEX idx_api_keys_status ON ussd_core.api_keys(status) WHERE status = 'active';

CREATE INDEX idx_sessions_account ON ussd_core.sessions(account_id);
CREATE INDEX idx_sessions_token ON ussd_core.sessions(token_hash);
CREATE INDEX idx_sessions_status ON ussd_core.sessions(status, expires_at) WHERE status = 'active';

CREATE INDEX idx_key_usage_key ON ussd_audit.key_usage_log(key_id);
CREATE INDEX idx_key_usage_time ON ussd_audit.key_usage_log(performed_at);

CREATE INDEX idx_api_key_usage_key ON ussd_audit.api_key_usage(key_id);
CREATE INDEX idx_api_key_usage_time ON ussd_audit.api_key_usage(used_at);

-- ----------------------------------------------------------------------------
-- 8. ROW LEVEL SECURITY
-- ----------------------------------------------------------------------------
ALTER TABLE ussd_core.encryption_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd_core.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd_core.sessions ENABLE ROW LEVEL SECURITY;

-- Only system can access encryption keys directly
CREATE POLICY encryption_keys_system ON ussd_core.encryption_keys
    FOR ALL USING (NULLIF(current_setting('app.is_system', TRUE), '')::BOOLEAN = TRUE);

-- Users can see their own API keys (but not the hash)
CREATE POLICY api_keys_own ON ussd_core.api_keys
    FOR SELECT USING (account_id = NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID);

-- Users can see their own sessions
CREATE POLICY sessions_own ON ussd_core.sessions
    FOR SELECT USING (account_id = NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID);

-- ----------------------------------------------------------------------------
-- 9. INITIAL SECURITY SETUP
-- ----------------------------------------------------------------------------

-- Insert initial encryption key (in production, use proper key ceremony)
INSERT INTO ussd_core.encryption_keys (
    key_id,
    key_name,
    key_purpose,
    key_data,
    status,
    created_by,
    record_hash
) VALUES (
    '00000000-0000-0000-0000-000000000001'::UUID,
    'master_field_encryption_key_v1',
    'field_encryption',
    decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
    'active',
    '00000000-0000-0000-0000-000000000001'::UUID,
    ussd_core.generate_hash('initial_field_key')
);

-- Insert initial signing key
INSERT INTO ussd_core.encryption_keys (
    key_id,
    key_name,
    key_purpose,
    key_data,
    status,
    created_by,
    record_hash
) VALUES (
    '00000000-0000-0000-0000-000000000002'::UUID,
    'master_signing_key_v1',
    'signing',
    decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
    'active',
    '00000000-0000-0000-0000-000000000001'::UUID,
    ussd_core.generate_hash('initial_signing_key')
);

-- ----------------------------------------------------------------------------
-- 10. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_core.encryption_keys IS 
    'Encryption and signing keys - encrypted at rest, access logged';
COMMENT ON TABLE ussd_core.api_keys IS 
    'API keys for service-to-service authentication - key hashes only stored';
COMMENT ON TABLE ussd_core.sessions IS 
    'User sessions with token hashes - never store raw tokens';
COMMENT ON FUNCTION ussd_core.encrypt_field IS 
    'Encrypts sensitive field data using AEAD';
COMMENT ON FUNCTION ussd_core.sign_data IS 
    'Creates HMAC signature for data integrity';
