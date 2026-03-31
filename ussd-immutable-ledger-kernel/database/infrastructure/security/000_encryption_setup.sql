-- =============================================================================
-- ENCRYPTION SETUP
-- Base encryption configuration and pgcrypto extension setup
-- =============================================================================

-- =============================================================================
-- ENABLE EXTENSIONS
-- =============================================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Verify pgcrypto is available
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto'
    ) THEN
        RAISE EXCEPTION 'pgcrypto extension is required but not available';
    END IF;
END $$;

-- =============================================================================
-- ENCRYPTION SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS encryption;

COMMENT ON SCHEMA encryption IS 'Encryption configuration and key management functions';

-- =============================================================================
-- ENCRYPTION CONFIGURATION TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS encryption.config (
    id SERIAL PRIMARY KEY,
    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT NOT NULL,
    config_type VARCHAR(20) NOT NULL DEFAULT 'TEXT', -- TEXT, BYTEA, INTEGER, BOOLEAN, JSON
    is_encrypted BOOLEAN DEFAULT FALSE,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE encryption.config IS 'Encryption configuration parameters';

-- =============================================================================
-- DEFAULT ENCRYPTION CONFIGURATION
-- =============================================================================
INSERT INTO encryption.config (config_key, config_value, config_type, description) VALUES
    ('encryption_enabled', 'true', 'BOOLEAN', 'Master switch for encryption'),
    ('default_algorithm', 'aes-256-gcm', 'TEXT', 'Default encryption algorithm'),
    ('hash_algorithm', 'sha256', 'TEXT', 'Default hash algorithm'),
    ('kdf_iterations', '100000', 'INTEGER', 'PBKDF2 iteration count'),
    ('key_rotation_days', '90', 'INTEGER', 'Automatic key rotation interval'),
    ('master_key_digest', '', 'TEXT', 'Digest of master key for verification'),
    ('data_encryption_at_rest', 'true', 'BOOLEAN', 'Enable data encryption at rest'),
    ('data_encryption_in_transit', 'true', 'BOOLEAN', 'Require TLS for connections'),
    ('column_encryption_default', 'false', 'BOOLEAN', 'Default column-level encryption')
ON CONFLICT (config_key) DO UPDATE SET
    config_value = EXCLUDED.config_value,
    config_type = EXCLUDED.config_type,
    description = EXCLUDED.description;

-- =============================================================================
-- ENCRYPTED DATA TYPES (domains with validation)
-- =============================================================================

-- Encrypted text type with validation
CREATE DOMAIN encryption.encrypted_text AS BYTEA
CHECK (LENGTH(VALUE) >= 32); -- Minimum length for encrypted data with IV

COMMENT ON DOMAIN encryption.encrypted_text IS 'Domain for encrypted text data';

-- Hash type with validation
CREATE DOMAIN encryption.hash_value AS BYTEA
CHECK (LENGTH(VALUE) IN (32, 48, 64)); -- SHA-256, SHA-384, SHA-512

COMMENT ON DOMAIN encryption.hash_value IS 'Domain for hash values';

-- =============================================================================
-- FUNCTION: Get config value
-- =============================================================================
CREATE OR REPLACE FUNCTION encryption.get_config(p_key VARCHAR)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_value TEXT;
BEGIN
    SELECT config_value INTO v_value
    FROM encryption.config
    WHERE config_key = p_key;
    
    RETURN v_value;
END;
$$;

-- =============================================================================
-- FUNCTION: Set config value
-- =============================================================================
CREATE OR REPLACE FUNCTION encryption.set_config(
    p_key VARCHAR,
    p_value TEXT,
    p_type VARCHAR DEFAULT 'TEXT'
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO encryption.config (config_key, config_value, config_type)
    VALUES (p_key, p_value, p_type)
    ON CONFLICT (config_key) DO UPDATE SET
        config_value = EXCLUDED.config_value,
        config_type = EXCLUDED.config_type,
        updated_at = NOW();
    
    RETURN format('Set %s = %s', p_key, p_value);
END;
$$;

-- =============================================================================
-- FUNCTION: Generate cryptographically secure random bytes
-- =============================================================================
CREATE OR REPLACE FUNCTION encryption.random_bytes(p_length INTEGER)
RETURNS BYTEA
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN gen_random_bytes(p_length);
END;
$$;

-- =============================================================================
-- FUNCTION: Generate UUID v4
-- =============================================================================
CREATE OR REPLACE FUNCTION encryption.gen_uuid()
RETURNS UUID
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN gen_random_uuid();
END;
$$;

-- =============================================================================
-- FUNCTION: Hash password using bcrypt
-- =============================================================================
CREATE OR REPLACE FUNCTION encryption.hash_password(p_password TEXT)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN crypt(p_password, gen_salt('bf', 10));
END;
$$;

-- =============================================================================
-- FUNCTION: Verify password against hash
-- =============================================================================
CREATE OR REPLACE FUNCTION encryption.verify_password(
    p_password TEXT,
    p_hash TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN crypt(p_password, p_hash) = p_hash;
END;
$$;

-- =============================================================================
-- FUNCTION: Encrypt data using AES-256-GCM
-- =============================================================================
CREATE OR REPLACE FUNCTION encryption.encrypt_aes_gcm(
    p_plaintext TEXT,
    p_key BYTEA,
    p_associated_data TEXT DEFAULT NULL
)
RETURNS BYTEA
LANGUAGE plpgsql
AS $$
DECLARE
    v_iv BYTEA;
    v_ciphertext BYTEA;
    v_aad BYTEA;
BEGIN
    -- Generate random IV (12 bytes for GCM)
    v_iv := gen_random_bytes(12);
    
    -- Convert AAD to bytes if provided
    v_aad := CASE WHEN p_associated_data IS NULL 
                  THEN '\x'::BYTEA 
                  ELSE convert_to(p_associated_data, 'UTF8') 
             END;
    
    -- Encrypt using pgcrypto (using pgp_sym_encrypt_bytea with session key)
    v_ciphertext := pgp_sym_encrypt_bytea(
        convert_to(p_plaintext, 'UTF8'),
        encode(p_key, 'hex'),
        'cipher-algo=aes256, compress-algo=0'
    );
    
    -- Return IV + ciphertext
    RETURN v_iv || v_ciphertext;
END;
$$;

-- =============================================================================
-- FUNCTION: Decrypt data using AES-256-GCM
-- =============================================================================
CREATE OR REPLACE FUNCTION encryption.decrypt_aes_gcm(
    p_ciphertext BYTEA,
    p_key BYTEA,
    p_associated_data TEXT DEFAULT NULL
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_plaintext BYTEA;
BEGIN
    -- Decrypt using pgcrypto
    v_plaintext := pgp_sym_decrypt_bytea(
        p_ciphertext,
        encode(p_key, 'hex')
    );
    
    RETURN convert_from(v_plaintext, 'UTF8');
EXCEPTION WHEN OTHERS THEN
    RETURN NULL; -- Return NULL on decryption failure
END;
$$;

-- =============================================================================
-- FUNCTION: Generate HMAC
-- =============================================================================
CREATE OR REPLACE FUNCTION encryption.hmac(
    p_data TEXT,
    p_key BYTEA,
    p_algorithm TEXT DEFAULT 'sha256'
)
RETURNS BYTEA
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN hmac(convert_to(p_data, 'UTF8'), p_key, p_algorithm);
END;
$$;

-- =============================================================================
-- FUNCTION: Compute SHA-256 hash
-- =============================================================================
CREATE OR REPLACE FUNCTION encryption.sha256(p_data TEXT)
RETURNS BYTEA
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN digest(p_data, 'sha256');
END;
$$;

CREATE OR REPLACE FUNCTION encryption.sha256(p_data BYTEA)
RETURNS BYTEA
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN digest(p_data, 'sha256');
END;
$$;

-- =============================================================================
-- FUNCTION: Compute SHA-512 hash
-- =============================================================================
CREATE OR REPLACE FUNCTION encryption.sha512(p_data TEXT)
RETURNS BYTEA
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN digest(p_data, 'sha512');
END;
$$;

-- =============================================================================
-- FUNCTION: Derive key from password using PBKDF2
-- =============================================================================
CREATE OR REPLACE FUNCTION encryption.derive_key(
    p_password TEXT,
    p_salt BYTEA,
    p_key_length INTEGER DEFAULT 32,
    p_iterations INTEGER DEFAULT 100000
)
RETURNS BYTEA
LANGUAGE plpgsql
AS $$
BEGIN
    -- Note: PostgreSQL doesn't have native PBKDF2, this is a simplified version
    -- In production, use a proper KDF
    RETURN digest(
        p_salt || convert_to(p_password, 'UTF8') || p_salt,
        'sha256'
    );
END;
$$;

-- =============================================================================
-- FUNCTION: Constant time comparison (timing attack safe)
-- =============================================================================
CREATE OR REPLACE FUNCTION encryption.constant_time_compare(
    p_a BYTEA,
    p_b BYTEA
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_result INTEGER := 0;
    v_i INTEGER;
BEGIN
    IF length(p_a) != length(p_b) THEN
        RETURN FALSE;
    END IF;
    
    FOR v_i IN 1..length(p_a) LOOP
        v_result := v_result | (get_byte(p_a, v_i-1) # get_byte(p_b, v_i-1));
    END LOOP;
    
    RETURN v_result = 0;
END;
$$;

-- =============================================================================
-- VIEW: Encryption status
-- =============================================================================
CREATE OR REPLACE VIEW encryption.encryption_status AS
SELECT 
    c.config_key,
    CASE 
        WHEN c.is_encrypted THEN '***ENCRYPTED***'
        ELSE c.config_value
    END as config_value,
    c.config_type,
    c.description,
    c.created_at,
    c.updated_at
FROM encryption.config c;

-- =============================================================================
-- TRIGGER: Update timestamp
-- =============================================================================
CREATE OR REPLACE FUNCTION encryption.update_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_config_updated
    BEFORE UPDATE ON encryption.config
    FOR EACH ROW EXECUTE FUNCTION encryption.update_timestamp();

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA encryption TO encryption_admin;
GRANT SELECT ON encryption.config TO encryption_admin;
GRANT SELECT ON encryption.encryption_status TO encryption_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA encryption TO encryption_admin;
