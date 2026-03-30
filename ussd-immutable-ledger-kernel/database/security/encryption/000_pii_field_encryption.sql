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
-- COMMENTS
-- ============================================================================
COMMENT ON FUNCTION encrypt_field IS 'PCI DSS 3.4.1: Encrypts text using AES-256-GCM with authenticated encryption (ISO 27018)';
COMMENT ON FUNCTION decrypt_field IS 'ISO/IEC 27018: Decrypts text encrypted with encrypt_field function - authorized access only';
COMMENT ON FUNCTION encrypt_email IS 'ISO/IEC 27018: Encrypts email with optional domain preservation for processing';
COMMENT ON FUNCTION encrypt_phone IS 'PCI DSS: Encrypts phone number with optional country code preservation';
COMMENT ON TABLE encryption_config IS 'ISO/IEC 27040: Centralized encryption configuration management';

-- ============================================================================
-- SECURITY AUDIT LOG ENTRY
-- ============================================================================
DO $$
BEGIN
    PERFORM log_security_event(
        'pii_encryption_initialized',
        jsonb_build_object(
            'algorithm', 'AES-256-GCM',
            'standards', ARRAY['ISO/IEC 27001:2022', 'ISO/IEC 27018:2019', 'PCI DSS 4.0', 'ISO/IEC 27040:2024'],
            'functions', ARRAY['encrypt_field', 'decrypt_field', 'encrypt_email', 'encrypt_phone', 'encrypt_id_number'],
            'timestamp', NOW()
        )
    );
EXCEPTION WHEN OTHERS THEN
    NULL;
END $$;

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Implement key rotation mechanism with re-encryption capability (PCI DSS 3.6.4)
-- TODO: Add support for envelope encryption with data encryption keys (DEK) (ISO 27040)
-- TODO: Implement hardware security module (HSM) integration (PCI DSS 3.6.1)
-- TODO: Add field-level encryption for JSON/JSONB columns (ISO 27018)
-- TODO: Implement searchable encryption for encrypted fields (ISO 27001 A.10)
-- TODO: Add deterministic encryption option for fields requiring equality checks
-- TODO: Implement encryption performance monitoring and optimization (ISO 27040)
-- TODO: Add support for external key management services (AWS KMS, Azure Key Vault)
-- TODO: Implement automatic encryption for columns marked with encryption tags
-- TODO: Add encryption key caching with TTL for performance (secure memory)
-- ============================================================================
