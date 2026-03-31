-- ============================================================================
-- Encryption Setup
-- ============================================================================

-- Enable pgcrypto for encryption functions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Table: Encryption keys registry
CREATE TABLE IF NOT EXISTS security.encryption_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_name VARCHAR(100) NOT NULL UNIQUE,
    key_version INTEGER DEFAULT 1,
    key_algorithm VARCHAR(32) DEFAULT 'AES-256-GCM',
    created_at TIMESTAMPTZ DEFAULT now(),
    created_by VARCHAR(100) DEFAULT current_user,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE
);

COMMENT ON TABLE security.encryption_keys IS 'Registry of encryption keys for data protection';

-- Function: Encrypt sensitive data
CREATE OR REPLACE FUNCTION security.encrypt_value(
    p_plaintext TEXT,
    p_key_name VARCHAR(100) DEFAULT 'default'
)
RETURNS BYTEA
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ussd_security, public
AS $$
DECLARE
    v_key TEXT;
BEGIN
    -- In production, retrieve key from external KMS
    -- This is a simplified implementation
    v_key := current_setting('app.encryption_key', TRUE);
    
    IF v_key IS NULL THEN
        RAISE EXCEPTION 'Encryption key not configured';
    END IF;

    RETURN pgp_sym_encrypt(p_plaintext, v_key);
END;
$$;

COMMENT ON FUNCTION security.encrypt_value IS 'Encrypts sensitive data using symmetric encryption';

-- Function: Decrypt sensitive data
CREATE OR REPLACE FUNCTION security.decrypt_value(
    p_ciphertext BYTEA,
    p_key_name VARCHAR(100) DEFAULT 'default'
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ussd_security, public
AS $$
DECLARE
    v_key TEXT;
BEGIN
    v_key := current_setting('app.encryption_key', TRUE);
    
    IF v_key IS NULL THEN
        RAISE EXCEPTION 'Encryption key not configured';
    END IF;

    RETURN pgp_sym_decrypt(p_ciphertext, v_key);
END;
$$;

COMMENT ON FUNCTION security.decrypt_value IS 'Decrypts encrypted data';
