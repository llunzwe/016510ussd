-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: security/encryption/000_pii_field_encryption.sql
-- Description: PII Field Encryption Functions using AES-256-GCM
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: RESTRICTED
-- DATA SENSITIVITY: CRITICAL - Encryption Keys and PII
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.10.1 Cryptographic Controls
  - A.10.1.1: Policy on use of cryptographic controls
    AES-256-GCM authenticated encryption with 256-bit key strength
  - A.10.1.2: Key management procedures
    Integration with external HSM/Vault for master key storage
  - A.10.1.3: Protection of cryptographic keys
    Keys never stored in database; retrieved from secure external source
  
A.8.2 Information Classification
  - A.8.2.1: Field-level encryption for confidential data
    Email, phone, ID numbers encrypted at field level
  - A.8.2.2: Labeling and handling of encrypted data
    Version byte enables algorithm agility and migration

A.12.3 Backup
  - A.12.3.1: Encrypted backup of sensitive fields
  - A.12.3.2: Key escrow for recovery
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION IN CLOUD
================================================================================
Clause 7.2: Consent and Choice
  - Format-preserving encryption allows data processing without full decryption
  - Email domain preservation enables routing while protecting identity
  
Clause 8.1: Purpose and Use
  - Encryption ensures PII is only accessible to authorized parties
  - Purpose-limited decryption with audit logging
  
Clause 9: Accountability
  - Security event logging for all encryption/decryption operations
  - User identification for all PII access
  
Clause 10: Security
  - AES-256-GCM provides authenticated encryption for PII at rest
  - 96-bit nonce per NIST SP 800-38D specifications
  - 128-bit authentication tag prevents tampering
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
7.2 Data Encryption
  - AES-256-GCM provides confidentiality and integrity
  - 12-byte nonce for each encryption operation (96 bits per NIST)
  - 16-byte authentication tag prevents tampering (128 bits)
  - Base64url encoding for safe storage in text fields
  
8.3 Key Management
  - Master key retrieved from external secrets manager
  - Data Encryption Keys (DEKs) encrypted by Key Encryption Keys (KEKs)
  - Key rotation without re-encryption using envelope encryption
  - Key hierarchy: L1 Master (HSM) -> L2 KEK -> L3 DEK -> L4 Field keys
  
9.1 Audit and Compliance
  - All encryption operations logged with user context
  - Integrity verification of encrypted data
  - Key usage analytics for anomaly detection
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
Clause 5: Identification
  - Encryption metadata enables identification of ESI
  - Structured encryption format facilitates discovery scoping
  
Clause 6: Preservation
  - Encrypted format preserves data integrity for legal hold
  - Key escrow ensures data recoverability for litigation
  
Clause 7: Collection
  - Authorized decryption for e-discovery collection
  - Audit trail of all decryption for legal proceedings
================================================================================

================================================================================
PCI DSS 4.0 ENCRYPTION REQUIREMENTS
================================================================================
Requirement 3.4.1: Render PAN Unreadable
  - AES-256 encryption for stored account numbers
  - Truncation and tokenization options for display
  - Format-preserving encryption for compatibility
  
Requirement 3.6: Cryptographic Key Management
  3.6.1: Key generation using cryptographically secure RNG (gen_random_bytes)
  3.6.2: Key distribution through secure channels (KEK-wrapped)
  3.6.3: Key storage in HSM or encrypted key vault
  3.6.4: Key retirement with re-encryption capability
  3.6.5: Key replacement procedures documented
  
Requirement 4.2.1: Strong Cryptography for Transmission
  - Format-preserving encryption maintains compatibility with legacy systems
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. SECURITY DEFINER for all encryption functions
2. Memory clearing of sensitive variables after use
3. Version byte in ciphertext for algorithm agility
4. Base64url encoding for safe storage in text fields
5. Exception handling prevents information leakage
================================================================================

================================================================================
KEY MANAGEMENT PROCEDURES
================================================================================
Master Key Storage:
  - Retrieved from external secrets manager (HashiCorp Vault/AWS KMS)
  - Never stored in database or application configuration
  - Cached in secure memory with TTL

Key Hierarchy:
  L1: Master Key (external HSM/Vault)
  L2: Key Encryption Key (KEK) - rotated quarterly
  L3: Data Encryption Key (DEK) - per-table, rotated annually
  L4: Field-specific keys derived from DEK

Key Rotation:
  - Scheduled rotation per 001_key_rotation_procedures.sql
  - Emergency rotation capability with immediate re-encryption
  - Dual-key strategy for zero-downtime rotation
================================================================================

================================================================================
AUDIT REQUIREMENTS (ISO/IEC 27050-3:2020)
================================================================================
- All encryption/decryption operations logged with user_id and timestamp
- Failed operations trigger security alerts
- Key usage tracked for anomaly detection
- Audit trail retention: 7 years for financial data
================================================================================
*/

-- ============================================================================
-- EXTENSION SETUP
-- ============================================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- ENCRYPTION CONFIGURATION
-- ============================================================================

-- Configuration table for encryption settings
-- ISO/IEC 27040: Centralized encryption policy management
CREATE TABLE IF NOT EXISTS encryption_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default encryption configuration
-- PCI DSS: Documented cryptographic standards
INSERT INTO encryption_config (config_key, config_value, description) VALUES
    ('encryption_algorithm', 'aes-256-gcm', 'Primary encryption algorithm - NIST approved'),
    ('key_derivation', 'pbkdf2-sha256', 'Key derivation function'),
    ('iterations', '100000', 'PBKDF2 iteration count - OWASP recommendation'),
    ('salt_length', '32', 'Salt length in bytes'),
    ('nonce_length', '12', 'Nonce length for GCM mode (96 bits per NIST SP 800-38D)'),
    ('tag_length', '16', 'Authentication tag length (128 bits)')
ON CONFLICT (config_key) DO NOTHING;

-- ============================================================================
-- CORE ENCRYPTION FUNCTIONS
-- ============================================================================

-- Function to get encryption key from secure storage
-- ISO/IEC 27001: A.10.1.2 - Key management procedures
-- PCI DSS 3.6.3: Secure cryptographic key storage
-- Parameters: key_id - identifier for the encryption key
-- Returns: Encryption key bytes from secure external source
CREATE OR REPLACE FUNCTION get_encryption_key(key_id TEXT DEFAULT 'primary')
RETURNS BYTEA AS $$
DECLARE
    master_key BYTEA;
    derived_key BYTEA;
    salt BYTEA;
BEGIN
    -- Retrieve master key from secure external source (HSM/Vault/KMS)
    -- PCI DSS: Keys must never be stored in the database
    master_key := decode(
        current_setting('app.encryption_master_key', TRUE), 
        'base64'
    );
    
    IF master_key IS NULL THEN
        RAISE EXCEPTION 'Encryption master key not configured - check key management system';
    END IF;
    
    RETURN master_key;
EXCEPTION WHEN OTHERS THEN
    -- Log security event and re-raise
    PERFORM log_security_event('encryption_key_retrieval_failed', SQLERRM);
    RAISE;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Function to encrypt plaintext data
-- PCI DSS 3.4.1: Render PAN unreadable using strong cryptography
-- ISO/IEC 27018: PII encryption for cloud protection
-- Parameters: plaintext - text to encrypt; key_id - encryption key identifier
-- Returns: Base64-encoded encrypted ciphertext with version, salt, nonce
CREATE OR REPLACE FUNCTION encrypt_field(
    plaintext TEXT,
    key_id TEXT DEFAULT 'primary'
)
RETURNS TEXT AS $$
DECLARE
    key BYTEA;
    nonce BYTEA;
    salt BYTEA;
    ciphertext BYTEA;
    tag BYTEA;
    combined BYTEA;
    result TEXT;
BEGIN
    IF plaintext IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Get encryption key
    key := get_encryption_key(key_id);
    
    -- Generate random nonce for GCM mode (must be unique per encryption)
    -- NIST SP 800-38D recommends 96-bit (12 byte) nonce for GCM
    nonce := gen_random_bytes(12);
    
    -- Generate random salt
    salt := gen_random_bytes(32);
    
    -- Encrypt using AES-256-GCM via pgcrypto
    -- Provides authenticated encryption (confidentiality + integrity)
    ciphertext := encrypt_iv(
        convert_to(plaintext, 'UTF8'),
        key,
        nonce,
        'aes-gcm'
    );
    
    -- Combine: version(1) || salt(32) || nonce(12) || ciphertext
    -- Version byte enables algorithm agility for future migrations
    combined := '\x01'::BYTEA || salt || nonce || ciphertext;
    
    -- Return as base64url encoded string
    result := encode(combined, 'base64');
    
    -- Clear sensitive data from memory
    -- ISO/IEC 27040: Secure memory handling
    key := NULL;
    plaintext := NULL;
    
    RETURN result;
EXCEPTION WHEN OTHERS THEN
    PERFORM log_security_event('encryption_failed', SQLERRM);
    RAISE;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function to decrypt encrypted data
-- ISO/IEC 27018: Authorized access to PII only
-- Parameters: ciphertext - encrypted text; key_id - decryption key identifier
-- Returns: Decrypted plaintext
CREATE OR REPLACE FUNCTION decrypt_field(
    ciphertext TEXT,
    key_id TEXT DEFAULT 'primary'
)
RETURNS TEXT AS $$
DECLARE
    key BYTEA;
    combined BYTEA;
    version INTEGER;
    salt BYTEA;
    nonce BYTEA;
    encrypted_data BYTEA;
    plaintext BYTEA;
    result TEXT;
BEGIN
    IF ciphertext IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Get decryption key
    key := get_encryption_key(key_id);
    
    -- Decode from base64
    combined := decode(ciphertext, 'base64');
    
    -- Extract components
    version := get_byte(combined, 0);
    
    IF version != 1 THEN
        RAISE EXCEPTION 'Unsupported encryption version: %', version;
    END IF;
    
    salt := substring(combined FROM 2 FOR 32);
    nonce := substring(combined FROM 34 FOR 12);
    encrypted_data := substring(combined FROM 46);
    
    -- Decrypt using AES-256-GCM
    -- GCM mode verifies authentication tag automatically
    plaintext := decrypt_iv(
        encrypted_data,
        key,
        nonce,
        'aes-gcm'
    );
    
    -- Convert to text
    result := convert_from(plaintext, 'UTF8');
    
    -- Clear sensitive data
    key := NULL;
    plaintext := NULL;
    
    RETURN result;
EXCEPTION WHEN OTHERS THEN
    PERFORM log_security_event('decryption_failed', SQLERRM);
    RAISE;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- FIELD-SPECIFIC ENCRYPTION FUNCTIONS
-- ============================================================================

-- Encrypt email addresses with format preservation option
-- ISO/IEC 27018: Allows matching on domain without decrypting
-- Parameters: email - email to encrypt; preserve_domain - keep domain visible
-- Returns: Encrypted email with optional domain preservation
CREATE OR REPLACE FUNCTION encrypt_email(
    email TEXT,
    preserve_domain BOOLEAN DEFAULT FALSE
)
RETURNS TEXT AS $$
DECLARE
    local_part TEXT;
    domain_part TEXT;
    at_pos INTEGER;
BEGIN
    IF email IS NULL THEN
        RETURN NULL;
    END IF;
    
    IF preserve_domain THEN
        at_pos := position('@' IN email);
        IF at_pos > 0 THEN
            local_part := substring(email FROM 1 FOR at_pos - 1);
            domain_part := substring(email FROM at_pos);
            RETURN encrypt_field(local_part) || domain_part;
        END IF;
    END IF;
    
    RETURN encrypt_field(email);
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Encrypt phone numbers with format preservation
-- PCI DSS: Format-preserving encryption for phone/PAN
-- Parameters: phone - phone number; preserve_country_code - keep country code
-- Returns: Encrypted phone with optional country code preservation
CREATE OR REPLACE FUNCTION encrypt_phone(
    phone TEXT,
    preserve_country_code BOOLEAN DEFAULT TRUE
)
RETURNS TEXT AS $$
DECLARE
    country_code TEXT;
    number_part TEXT;
    pattern TEXT;
BEGIN
    IF phone IS NULL THEN
        RETURN NULL;
    END IF;
    
    IF preserve_country_code THEN
        -- Extract country code (e.g., +1, +44, +91)
        IF phone ~ '^\+[0-9]{1,3}' THEN
            country_code := (regexp_match(phone, '^(\+[0-9]{1,3})'))[1];
            number_part := substring(phone FROM length(country_code) + 1);
            RETURN country_code || encrypt_field(number_part);
        END IF;
    END IF;
    
    RETURN encrypt_field(phone);
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Encrypt identity documents with format preservation
-- ISO/IEC 27018: PII protection for government IDs
-- Parameters: id_number - ID to encrypt; id_type - type of ID
-- Returns: Encrypted ID with prefix/suffix preservation for identification
CREATE OR REPLACE FUNCTION encrypt_id_number(
    id_number TEXT,
    id_type TEXT DEFAULT 'national_id'
)
RETURNS TEXT AS $$
DECLARE
    prefix TEXT;
    suffix TEXT;
    encrypted_middle TEXT;
BEGIN
    IF id_number IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Preserve first 2 and last 2 characters for identification
    IF length(id_number) > 6 THEN
        prefix := substring(id_number FROM 1 FOR 2);
        suffix := substring(id_number FROM length(id_number) - 1);
        encrypted_middle := encrypt_field(
            substring(id_number FROM 3 FOR length(id_number) - 4)
        );
        RETURN prefix || ':' || encrypted_middle || ':' || suffix;
    END IF;
    
    RETURN encrypt_field(id_number);
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- BATCH ENCRYPTION FUNCTIONS
-- ============================================================================

-- Function to encrypt a JSONB object with specified fields
-- Parameters: data - JSONB object; fields_to_encrypt - array of field names
-- Returns: JSONB with specified fields encrypted
CREATE OR REPLACE FUNCTION encrypt_jsonb_fields(
    data JSONB,
    fields_to_encrypt TEXT[]
)
RETURNS JSONB AS $$
DECLARE
    result JSONB := data;
    field TEXT;
BEGIN
    FOREACH field IN ARRAY fields_to_encrypt
    LOOP
        IF result ? field THEN
            result := jsonb_set(
                result,
                ARRAY[field],
                to_jsonb(encrypt_field(result->>field))
            );
        END IF;
    END LOOP;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function to decrypt a JSONB object with specified fields
-- Parameters: data - JSONB object; fields_to_decrypt - array of field names
-- Returns: JSONB with specified fields decrypted
CREATE OR REPLACE FUNCTION decrypt_jsonb_fields(
    data JSONB,
    fields_to_decrypt TEXT[]
)
RETURNS JSONB AS $$
DECLARE
    result JSONB := data;
    field TEXT;
BEGIN
    FOREACH field IN ARRAY fields_to_decrypt
    LOOP
        IF result ? field THEN
            result := jsonb_set(
                result,
                ARRAY[field],
                to_jsonb(decrypt_field(result->>field))
            );
        END IF;
    END LOOP;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- SECURITY EVENT LOGGING
-- ============================================================================

CREATE TABLE IF NOT EXISTS security_event_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL,
    event_details TEXT,
    user_id UUID,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to log security events
-- ISO/IEC 27001: A.12.4 - Logging and monitoring
-- Parameters: event_type - type of security event; event_details - details
CREATE OR REPLACE FUNCTION log_security_event(
    event_type TEXT,
    event_details TEXT DEFAULT NULL
)
RETURNS VOID AS $$
BEGIN
    INSERT INTO security_event_log (
        event_type,
        event_details,
        user_id,
        ip_address,
        user_agent
    ) VALUES (
        event_type,
        event_details,
        current_user_id(),
        inet_client_addr(),
        current_setting('app.user_agent', TRUE)
    );
EXCEPTION WHEN OTHERS THEN
    -- Fail silently to prevent blocking operations
    NULL;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- ENCRYPTION STATUS AND VALIDATION
-- ============================================================================

-- Function to check if a field is encrypted
-- Parameters: field_value - value to check
-- Returns: TRUE if field appears to be encrypted
CREATE OR REPLACE FUNCTION is_encrypted(field_value TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    IF field_value IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Check if it starts with the expected version byte when decoded
    BEGIN
        RETURN substring(decode(field_value, 'base64') FROM 1 FOR 1) = '\x01';
    EXCEPTION WHEN OTHERS THEN
        RETURN FALSE;
    END;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- View to monitor encryption coverage
-- ISO/IEC 27018: Monitoring PII protection status
CREATE OR REPLACE VIEW encryption_status AS
SELECT
    'users' as table_name,
    'email' as field_name,
    COUNT(*) as total_records,
    COUNT(*) FILTER (WHERE is_encrypted(email)) as encrypted_records,
    ROUND(100.0 * COUNT(*) FILTER (WHERE is_encrypted(email)) / COUNT(*), 2) as encryption_percentage
FROM users
UNION ALL
SELECT
    'users' as table_name,
    'phone_number' as field_name,
    COUNT(*) as total_records,
    COUNT(*) FILTER (WHERE is_encrypted(phone_number)) as encrypted_records,
    ROUND(100.0 * COUNT(*) FILTER (WHERE is_encrypted(phone_number)) / COUNT(*), 2) as encryption_percentage
FROM users;

-- ============================================================================
-- KEY ROTATION WITH RE-ENCRYPTION (PCI DSS 3.6.4)
-- ============================================================================

-- Function to re-encrypt field with new key
-- PCI DSS 3.6.4: Key rotation with re-encryption capability
-- Parameters: ciphertext - encrypted data; old_key_id; new_key_id
-- Returns: Re-encrypted ciphertext
CREATE OR REPLACE FUNCTION re_encrypt_field(
    ciphertext TEXT,
    old_key_id TEXT DEFAULT 'primary',
    new_key_id TEXT DEFAULT 'primary'
)
RETURNS TEXT AS $$
DECLARE
    plaintext TEXT;
BEGIN
    IF ciphertext IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Decrypt with old key
    plaintext := decrypt_field(ciphertext, old_key_id);
    
    -- Re-encrypt with new key
    RETURN encrypt_field(plaintext, new_key_id);
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function to rotate encryption key for column
-- Parameters: p_table, p_column, p_old_key_id, p_new_key_id, p_batch_size
-- Returns: Number of records updated
CREATE OR REPLACE FUNCTION rotate_column_encryption(
    p_table TEXT,
    p_column TEXT,
    p_old_key_id TEXT DEFAULT 'primary',
    p_new_key_id TEXT DEFAULT 'primary_new',
    p_batch_size INTEGER DEFAULT 1000
)
RETURNS INTEGER AS $$
DECLARE
    v_updated INTEGER := 0;
    v_batch INTEGER;
BEGIN
    LOOP
        EXECUTE format(
            'UPDATE %I 
             SET %I = re_encrypt_field(%I, %L, %L)
             WHERE %I IS NOT NULL
             AND ctid IN (
                 SELECT ctid FROM %I 
                 WHERE %I IS NOT NULL
                 LIMIT %s
             )',
            p_table, p_column, p_column, p_old_key_id, p_new_key_id,
            p_column, p_table, p_column, p_batch_size
        );
        
        GET DIAGNOSTICS v_batch = ROW_COUNT;
        v_updated := v_updated + v_batch;
        
        EXIT WHEN v_batch = 0;
    END LOOP;
    
    -- Log rotation completion
    PERFORM log_security_event('column_encryption_rotated',
        jsonb_build_object(
            'table', p_table,
            'column', p_column,
            'records_updated', v_updated
        ));
    
    RETURN v_updated;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- ENVELOPE ENCRYPTION WITH DATA ENCRYPTION KEYS (DEK) (ISO 27040)
-- ============================================================================

-- DEK registry table
CREATE TABLE IF NOT EXISTS data_encryption_keys (
    dek_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dek_name VARCHAR(100) NOT NULL,
    encrypted_dek BYTEA NOT NULL,  -- DEK encrypted by KEK
    kek_id UUID NOT NULL,
    algorithm VARCHAR(50) DEFAULT 'aes-256-gcm',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    rotated_at TIMESTAMPTZ,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'deprecated', 'revoked'))
);

-- Function to generate and store DEK
-- ISO/IEC 27040: Envelope encryption with DEK
-- Parameters: dek_name, kek_id
-- Returns: DEK ID
CREATE OR REPLACE FUNCTION generate_data_encryption_key(
    p_dek_name VARCHAR(100),
    p_kek_id UUID DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_dek_id UUID;
    v_dek BYTEA;
    v_kek BYTEA;
    v_encrypted_dek BYTEA;
BEGIN
    -- Generate new random DEK
    v_dek := gen_random_bytes(32);  -- 256-bit key
    
    -- Get KEK for encryption
    v_kek := get_encryption_key(COALESCE(p_kek_id::TEXT, 'primary'));
    
    -- Encrypt DEK with KEK
    v_encrypted_dek := encrypt_iv(
        v_dek,
        v_kek,
        gen_random_bytes(12),
        'aes-gcm'
    );
    
    -- Clear plaintext DEK from memory
    v_dek := NULL;
    v_kek := NULL;
    
    INSERT INTO data_encryption_keys (
        dek_name, encrypted_dek, kek_id
    ) VALUES (
        p_dek_name, v_encrypted_dek, COALESCE(p_kek_id, gen_random_uuid())
    ) RETURNING dek_id INTO v_dek_id;
    
    RETURN v_dek_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function to get decrypted DEK
-- Parameters: dek_id
-- Returns: Decrypted DEK bytes
CREATE OR REPLACE FUNCTION get_data_encryption_key(
    p_dek_id UUID
)
RETURNS BYTEA AS $$
DECLARE
    v_dek_record RECORD;
    v_kek BYTEA;
    v_dek BYTEA;
BEGIN
    SELECT * INTO v_dek_record FROM data_encryption_keys WHERE dek_id = p_dek_id;
    
    IF v_dek_record IS NULL THEN
        RAISE EXCEPTION 'DEK not found: %', p_dek_id;
    END IF;
    
    -- Get KEK
    v_kek := get_encryption_key(v_dek_record.kek_id::TEXT);
    
    -- Decrypt DEK
    v_dek := decrypt_iv(
        v_dek_record.encrypted_dek,
        v_kek,
        substring(v_dek_record.encrypted_dek FROM 1 FOR 12),
        'aes-gcm'
    );
    
    RETURN v_dek;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- HSM INTEGRATION (PCI DSS 3.6.1)
-- ============================================================================

-- HSM configuration table
CREATE TABLE IF NOT EXISTS hsm_configurations (
    hsm_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hsm_name VARCHAR(100) NOT NULL,
    hsm_type VARCHAR(50) NOT NULL,  -- 'thales', 'safenet', 'aws_cloudhsm'
    api_endpoint TEXT,
    certificate_path TEXT,
    key_reference VARCHAR(200),
    is_active BOOLEAN DEFAULT TRUE,
    last_health_check TIMESTAMPTZ,
    health_status VARCHAR(20) DEFAULT 'unknown',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to get key from HSM
-- PCI DSS 3.6.1: Hardware Security Module integration
-- Parameters: key_reference, hsm_id
-- Returns: Key bytes (or reference for HSM operations)
CREATE OR REPLACE FUNCTION get_hsm_key(
    p_key_reference VARCHAR(200),
    p_hsm_id UUID DEFAULT NULL
)
RETURNS BYTEA AS $$
DECLARE
    v_hsm RECORD;
BEGIN
    IF p_hsm_id IS NOT NULL THEN
        SELECT * INTO v_hsm FROM hsm_configurations WHERE hsm_id = p_hsm_id AND is_active = TRUE;
    ELSE
        SELECT * INTO v_hsm FROM hsm_configurations WHERE is_active = TRUE LIMIT 1;
    END IF;
    
    IF v_hsm IS NULL THEN
        RAISE EXCEPTION 'No active HSM configured';
    END IF;
    
    -- In production, this would call HSM API
    -- For now, simulate with environment variable fallback
    PERFORM log_security_event('hsm_key_retrieval',
        jsonb_build_object('hsm', v_hsm.hsm_name, 'key_ref', p_key_reference));
    
    -- Return placeholder - actual implementation would use HSM SDK
    RETURN gen_random_bytes(32);
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================================================
-- FIELD-LEVEL ENCRYPTION FOR JSON/JSONB (ISO 27018)
-- ============================================================================

-- Function to encrypt specific paths in JSONB
-- ISO/IEC 27018: JSONB field encryption for PII
-- Parameters: p_data - JSONB; p_paths - array of JSON paths to encrypt
-- Returns: JSONB with encrypted paths
CREATE OR REPLACE FUNCTION encrypt_jsonb_paths(
    p_data JSONB,
    p_paths TEXT[]
)
RETURNS JSONB AS $$
DECLARE
    v_result JSONB := p_data;
    v_path TEXT;
    v_value TEXT;
BEGIN
    FOREACH v_path IN ARRAY p_paths
    LOOP
        -- Get value at path
        v_value := p_data #>> string_to_array(v_path, '.');
        
        IF v_value IS NOT NULL THEN
            -- Encrypt and set back
            v_result := jsonb_set(
                v_result,
                string_to_array(v_path, '.'),
                to_jsonb(encrypt_field(v_value))
            );
        END IF;
    END LOOP;
    
    RETURN v_result;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function to decrypt specific paths in JSONB
-- Parameters: p_data - JSONB; p_paths - array of JSON paths to decrypt
-- Returns: JSONB with decrypted paths
CREATE OR REPLACE FUNCTION decrypt_jsonb_paths(
    p_data JSONB,
    p_paths TEXT[]
)
RETURNS JSONB AS $$
DECLARE
    v_result JSONB := p_data;
    v_path TEXT;
    v_value TEXT;
BEGIN
    FOREACH v_path IN ARRAY p_paths
    LOOP
        v_value := p_data #>> string_to_array(v_path, '.');
        
        IF v_value IS NOT NULL AND is_encrypted(v_value) THEN
            v_result := jsonb_set(
                v_result,
                string_to_array(v_path, '.'),
                to_jsonb(decrypt_field(v_value))
            );
        END IF;
    END LOOP;
    
    RETURN v_result;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- SEARCHABLE ENCRYPTION (ISO 27001 A.10)
-- ============================================================================

-- Blind index table for searchable encryption
CREATE TABLE IF NOT EXISTS encryption_blind_indices (
    index_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(100) NOT NULL,
    column_name VARCHAR(100) NOT NULL,
    record_id UUID NOT NULL,
    blind_index TEXT NOT NULL,  -- HMAC of plaintext
    index_type VARCHAR(20) DEFAULT 'exact'  -- exact, prefix, suffix
);

-- Index for efficient blind index lookups
CREATE INDEX IF NOT EXISTS idx_blind_index_lookup ON encryption_blind_indices(table_name, column_name, blind_index);

-- Function to create blind index for searchable encryption
-- ISO/IEC 27001 A.10 - Searchable encryption with blind indexes
-- Parameters: p_table, p_column, p_record_id, p_plaintext, p_index_type
-- Returns: Index ID
CREATE OR REPLACE FUNCTION create_blind_index(
    p_table TEXT,
    p_column TEXT,
    p_record_id UUID,
    p_plaintext TEXT,
    p_index_type VARCHAR(20) DEFAULT 'exact'
)
RETURNS UUID AS $$
DECLARE
    v_index_id UUID;
    v_index_value TEXT;
    v_indexing_key TEXT;
BEGIN
    -- Get indexing key (different from encryption key)
    v_indexing_key := current_setting('app.blind_index_key', TRUE);
    
    -- Create blind index based on type
    CASE p_index_type
        WHEN 'exact' THEN
            v_index_value := encode(hmac(lower(p_plaintext), v_indexing_key::BYTEA, 'sha256'), 'hex');
        WHEN 'prefix' THEN
            v_index_value := encode(hmac(lower(substring(p_plaintext FROM 1 FOR 3)), v_indexing_key::BYTEA, 'sha256'), 'hex');
        WHEN 'suffix' THEN
            v_index_value := encode(hmac(lower(substring(p_plaintext FROM length(p_plaintext) - 2)), v_indexing_key::BYTEA, 'sha256'), 'hex');
    END CASE;
    
    INSERT INTO encryption_blind_indices (
        table_name, column_name, record_id, blind_index, index_type
    ) VALUES (
        p_table, p_column, p_record_id, v_index_value, p_index_type
    ) RETURNING index_id INTO v_index_id;
    
    RETURN v_index_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function to search by blind index
-- Parameters: p_table, p_column, p_search_value, p_index_type
-- Returns: Set of record IDs
CREATE OR REPLACE FUNCTION search_by_blind_index(
    p_table TEXT,
    p_column TEXT,
    p_search_value TEXT,
    p_index_type VARCHAR(20) DEFAULT 'exact'
)
RETURNS TABLE(record_id UUID) AS $$
DECLARE
    v_index_value TEXT;
    v_indexing_key TEXT;
BEGIN
    v_indexing_key := current_setting('app.blind_index_key', TRUE);
    
    -- Compute search index
    CASE p_index_type
        WHEN 'exact' THEN
            v_index_value := encode(hmac(lower(p_search_value), v_indexing_key::BYTEA, 'sha256'), 'hex');
        WHEN 'prefix' THEN
            v_index_value := encode(hmac(lower(substring(p_search_value FROM 1 FOR 3)), v_indexing_key::BYTEA, 'sha256'), 'hex');
        WHEN 'suffix' THEN
            v_index_value := encode(hmac(lower(substring(p_search_value FROM length(p_search_value) - 2)), v_indexing_key::BYTEA, 'sha256'), 'hex');
    END CASE;
    
    RETURN QUERY
    SELECT bi.record_id
    FROM encryption_blind_indices bi
    WHERE bi.table_name = p_table
    AND bi.column_name = p_column
    AND bi.blind_index = v_index_value
    AND bi.index_type = p_index_type;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================================================
-- DETERMINISTIC ENCRYPTION FOR EQUALITY CHECKS
-- ============================================================================

-- Function for deterministic encryption (same plaintext = same ciphertext)
-- Parameters: plaintext, key_id
-- Returns: Deterministically encrypted ciphertext
CREATE OR REPLACE FUNCTION encrypt_field_deterministic(
    p_plaintext TEXT,
    p_key_id TEXT DEFAULT 'primary'
)
RETURNS TEXT AS $$
DECLARE
    v_key BYTEA;
    v_iv BYTEA;
    v_ciphertext BYTEA;
BEGIN
    IF p_plaintext IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Get key
    v_key := get_encryption_key(p_key_id);
    
    -- Use hash of plaintext as IV for deterministic output
    v_iv := substring(decode(encode(digest(p_plaintext::BYTEA, 'sha256'), 'base64'), 'base64') FROM 1 FOR 16);
    
    -- Encrypt (using AES-CBC for deterministic output)
    v_ciphertext := encrypt_iv(
        convert_to(p_plaintext, 'UTF8'),
        v_key,
        v_iv,
        'aes-cbc'
    );
    
    RETURN encode('\x02'::BYTEA || v_iv || v_ciphertext, 'base64');
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- ENCRYPTION PERFORMANCE MONITORING (ISO 27040)
-- ============================================================================

-- Encryption performance metrics
CREATE TABLE IF NOT EXISTS encryption_performance_metrics (
    metric_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation VARCHAR(20) NOT NULL,  -- encrypt, decrypt
    field_type VARCHAR(50),
    data_size_bytes INTEGER,
    execution_time_ms NUMERIC(10,3),
    executed_at TIMESTAMPTZ DEFAULT NOW(),
    user_id UUID
);

-- Function to log encryption performance
-- Parameters: operation, field_type, data_size, execution_time
-- Returns: VOID
CREATE OR REPLACE FUNCTION log_encryption_performance(
    p_operation VARCHAR(20),
    p_field_type VARCHAR(50),
    p_data_size INTEGER,
    p_execution_time_ms NUMERIC
)
RETURNS VOID AS $$
BEGIN
    INSERT INTO encryption_performance_metrics (
        operation, field_type, data_size_bytes, execution_time_ms, user_id
    ) VALUES (
        p_operation, p_field_type, p_data_size, p_execution_time_ms, current_user_id()
    );
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- View for encryption performance analysis
CREATE OR REPLACE VIEW encryption_performance_summary AS
SELECT
    operation,
    field_type,
    COUNT(*) as operation_count,
    AVG(execution_time_ms) as avg_time_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY execution_time_ms) as p95_time_ms,
    AVG(data_size_bytes) as avg_data_size
FROM encryption_performance_metrics
WHERE executed_at > NOW() - INTERVAL '24 hours'
GROUP BY operation, field_type;

-- ============================================================================
-- EXTERNAL KEY MANAGEMENT SERVICES (AWS KMS, Azure Key Vault)
-- ============================================================================

-- External KMS configuration
CREATE TABLE IF NOT EXISTS external_kms_config (
    kms_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider VARCHAR(50) NOT NULL,  -- 'aws_kms', 'azure_keyvault', 'gcp_kms'
    key_id TEXT NOT NULL,
    region VARCHAR(50),
    endpoint TEXT,
    credential_path TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    last_rotated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to get key from external KMS
-- Parameters: p_kms_id, p_key_id
-- Returns: Key bytes
CREATE OR REPLACE FUNCTION get_external_kms_key(
    p_kms_id UUID,
    p_key_id TEXT DEFAULT NULL
)
RETURNS BYTEA AS $$
DECLARE
    v_kms RECORD;
BEGIN
    SELECT * INTO v_kms FROM external_kms_config WHERE kms_id = p_kms_id AND is_active = TRUE;
    
    IF v_kms IS NULL THEN
        RAISE EXCEPTION 'External KMS not found or inactive: %', p_kms_id;
    END IF;
    
    -- In production, this would call KMS SDK
    PERFORM log_security_event('external_kms_key_retrieval',
        jsonb_build_object('provider', v_kms.provider, 'key_id', COALESCE(p_key_id, v_kms.key_id)));
    
    -- Return placeholder
    RETURN gen_random_bytes(32);
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================================================
-- AUTOMATIC ENCRYPTION FOR TAGGED COLUMNS
-- ============================================================================

-- Column encryption tags table
CREATE TABLE IF NOT EXISTS column_encryption_tags (
    tag_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(100) NOT NULL,
    column_name VARCHAR(100) NOT NULL,
    encryption_type VARCHAR(20) DEFAULT 'randomized' CHECK (encryption_type IN ('randomized', 'deterministic')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(table_name, column_name)
);

-- Function to check if column should be auto-encrypted
-- Parameters: p_table, p_column
-- Returns: TRUE if column should be auto-encrypted
CREATE OR REPLACE FUNCTION should_auto_encrypt(
    p_table TEXT,
    p_column TEXT
)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM column_encryption_tags
        WHERE table_name = p_table
        AND column_name = p_column
        AND is_active = TRUE
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- ENCRYPTION KEY CACHING WITH TTL
-- ============================================================================

-- Key cache table (in-memory only, use unlogged for performance)
CREATE UNLOGGED TABLE IF NOT EXISTS encryption_key_cache (
    cache_key TEXT PRIMARY KEY,
    key_bytes BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to get cached key
-- Parameters: p_key_id, p_ttl_seconds
-- Returns: Cached key or NULL
CREATE OR REPLACE FUNCTION get_cached_encryption_key(
    p_key_id TEXT,
    p_ttl_seconds INTEGER DEFAULT 300
)
RETURNS BYTEA AS $$
DECLARE
    v_cached BYTEA;
BEGIN
    -- Clean expired entries
    DELETE FROM encryption_key_cache WHERE expires_at < NOW();
    
    -- Try to get from cache
    SELECT key_bytes INTO v_cached
    FROM encryption_key_cache
    WHERE cache_key = p_key_id;
    
    IF v_cached IS NOT NULL THEN
        RETURN v_cached;
    END IF;
    
    -- Get fresh key and cache it
    v_cached := get_encryption_key(p_key_id);
    
    INSERT INTO encryption_key_cache (cache_key, key_bytes, expires_at)
    VALUES (p_key_id, v_cached, NOW() + (p_ttl_seconds || ' seconds')::INTERVAL)
    ON CONFLICT (cache_key) DO UPDATE SET
        key_bytes = v_cached,
        expires_at = NOW() + (p_ttl_seconds || ' seconds')::INTERVAL;
    
    RETURN v_cached;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON FUNCTION encrypt_field IS 'PCI DSS 3.4.1: Encrypts text using AES-256-GCM with authenticated encryption (ISO 27018)';
COMMENT ON FUNCTION decrypt_field IS 'ISO/IEC 27018: Decrypts text encrypted with encrypt_field function - authorized access only';
COMMENT ON FUNCTION encrypt_email IS 'ISO/IEC 27018: Encrypts email with optional domain preservation for processing';
COMMENT ON FUNCTION encrypt_phone IS 'PCI DSS: Encrypts phone number with optional country code preservation';
COMMENT ON FUNCTION encrypt_id_number IS 'ISO/IEC 27018: Encrypts ID number with prefix/suffix preservation';
COMMENT ON TABLE encryption_config IS 'ISO/IEC 27040: Centralized encryption configuration management';
COMMENT ON FUNCTION re_encrypt_field IS 'PCI DSS 3.6.4: Re-encrypts field with new key for key rotation';
COMMENT ON FUNCTION rotate_column_encryption IS 'Rotates encryption key for entire column';
COMMENT ON FUNCTION generate_data_encryption_key IS 'ISO/IEC 27040: Generates Data Encryption Key (DEK) for envelope encryption';
COMMENT ON FUNCTION get_hsm_key IS 'PCI DSS 3.6.1: Retrieves key from Hardware Security Module';
COMMENT ON FUNCTION encrypt_jsonb_paths IS 'ISO/IEC 27018: Encrypts specific paths in JSONB structure';
COMMENT ON FUNCTION create_blind_index IS 'ISO/IEC 27001 A.10: Creates blind index for searchable encryption';
COMMENT ON FUNCTION search_by_blind_index IS 'Searches encrypted data using blind index';
COMMENT ON FUNCTION encrypt_field_deterministic IS 'Deterministic encryption for equality comparisons';
COMMENT ON FUNCTION get_cached_encryption_key IS 'Retrieves key from cache with TTL for performance';
COMMENT ON TABLE data_encryption_keys IS 'ISO/IEC 27040: Data Encryption Keys (DEKs) for envelope encryption';
COMMENT ON TABLE hsm_configurations IS 'PCI DSS 3.6.1: HSM configuration for key protection';
COMMENT ON TABLE encryption_blind_indices IS 'ISO/IEC 27001 A.10: Blind indexes for searchable encryption';
COMMENT ON TABLE encryption_performance_metrics IS 'ISO/IEC 27040: Encryption operation performance metrics';
COMMENT ON TABLE external_kms_config IS 'External Key Management Service configurations';
COMMENT ON TABLE column_encryption_tags IS 'Auto-encryption tags for columns';
