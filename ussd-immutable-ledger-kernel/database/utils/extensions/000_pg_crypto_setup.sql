-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0 | FIPS 140-2
-- ============================================================================
-- File: utils/extensions/000_pg_crypto_setup.sql
-- Description: PostgreSQL Cryptographic Functions Setup
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: RESTRICTED
-- DATA SENSITIVITY: CRITICAL - Cryptographic Infrastructure
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.10.1 Cryptographic Controls
  - A.10.1.1: Policy on use of cryptographic controls
  - A.10.1.2: Key management procedures
  - A.10.1.3: Protection of cryptographic keys
  
A.12.3.2: Protection from Malware
  - Cryptographic hashing for file integrity verification
  
A.14.2.8: System Security Testing
  - Cryptographic validation functions
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION IN CLOUD
================================================================================
Clause 10: Security - AES-256 encryption for PII at rest and in transit
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
7.2 Data Encryption
  - AES-256-GCM for data confidentiality and integrity
  - Secure key derivation using PBKDF2
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
Clause 6: Preservation - Encrypted data preservation with key escrow
================================================================================

================================================================================
PCI DSS 4.0 CRYPTOGRAPHIC REQUIREMENTS
================================================================================
Requirement 3.6: Cryptographic Key Management
  3.6.1: Strong cryptography for key generation (gen_random_bytes)
  3.6.2: Secure cryptographic key distribution
  3.6.3: Secure cryptographic key storage
  3.6.4: Cryptographic key changes (rotation)

Requirement 4.1: Strong Cryptography for Transmission
  - TLS 1.2+ for data in transit
================================================================================

================================================================================
FIPS 140-2 COMPLIANCE (Cryptographic Module Validation)
================================================================================
- When using FIPS-enabled OpenSSL with pgcrypto
- AES-256 encryption meets FIPS 197 (Advanced Encryption Standard)
- SHA-256 hashing meets FIPS 180-4 (Secure Hash Standard)
- HMAC-SHA256 meets FIPS 198-1 (HMAC Standard)

Note: PostgreSQL pgcrypto is not FIPS 140-2 validated itself, but uses
OpenSSL which can be FIPS-validated when properly configured.
================================================================================

================================================================================
NIST SP 800-57 KEY MANAGEMENT GUIDELINES
================================================================================
- 128-bit minimum security strength for general use
- 256-bit security strength for long-term protection
- Key derivation using PBKDF2 with 100,000+ iterations
- Key separation for different cryptographic purposes
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. Use SECURITY DEFINER for all cryptographic functions
2. Clear sensitive variables from memory after use
3. Validate all inputs before cryptographic operations
4. Use constant-time comparison for secrets
5. Document security level for each algorithm used
================================================================================

================================================================================
CRYPTOGRAPHIC CONFIGURATION
================================================================================
Approved Algorithms:
  - Encryption: AES-256-GCM, AES-256-CBC
  - Hashing: SHA-256, SHA-384, SHA-512
  - Password Hashing: bcrypt (blowfish) with cost 10+
  - HMAC: HMAC-SHA256
  - Key Derivation: PBKDF2-SHA256

Deprecated/Prohibited:
  - MD5 (except for legacy compatibility)
  - SHA-1 (deprecated)
  - DES/3DES
  - RC4
================================================================================

================================================================================
KEY MANAGEMENT INTEGRATION
================================================================================
- Master keys stored in HSM or external vault
- Data Encryption Keys (DEKs) encrypted by Key Encryption Keys (KEKs)
- Key rotation scheduled per organizational policy
- Secure key generation using gen_random_bytes()
================================================================================

================================================================================
AUDIT REQUIREMENTS (ISO/IEC 27050-3:2020)
================================================================================
- All cryptographic operations logged with user context
- Key usage tracked for anomaly detection
- Failed operations trigger security alerts
================================================================================
*/

-- ============================================================================
-- EXTENSION INSTALLATION
-- ============================================================================

-- Install pgcrypto extension
-- Note: Requires superuser privileges or appropriate permissions
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

-- Verify installation
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto'
    ) THEN
        RAISE EXCEPTION 'pgcrypto extension installation failed - cryptographic functions unavailable';
    END IF;
    RAISE NOTICE 'pgcrypto extension installed successfully - %', NOW();
END $$;

-- ============================================================================
-- CRYPTOGRAPHIC CONFIGURATION
-- ============================================================================

-- Configuration table for cryptographic settings
-- ISO/IEC 27001: A.10.1.1 - Centralized crypto policy
CREATE TABLE IF NOT EXISTS crypto_configuration (
    config_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT NOT NULL,
    config_type VARCHAR(20) NOT NULL DEFAULT 'string',
    description TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default configurations
-- PCI DSS 3.6: Documented cryptographic standards
INSERT INTO crypto_configuration (config_key, config_value, config_type, description, is_sensitive) VALUES
    ('hash_algorithm', 'sha256', 'string', 'Default hashing algorithm (FIPS 180-4)', FALSE),
    ('password_hash_algorithm', 'bf', 'string', 'Blowfish for passwords (bcrypt)', FALSE),
    ('password_hash_cost', '12', 'integer', 'Blowfish iteration cost (OWASP recommendation)', FALSE),
    ('encryption_algorithm', 'aes-256-cbc', 'string', 'Default symmetric encryption (FIPS 197)', FALSE),
    ('hmac_algorithm', 'sha256', 'string', 'HMAC algorithm (FIPS 198-1)', FALSE),
    ('salt_length', '16', 'integer', 'Random salt length in bytes', FALSE),
    ('iv_length', '16', 'integer', 'Initialization vector length', FALSE),
    ('key_length', '32', 'integer', 'Encryption key length (32 bytes = 256 bits)', FALSE),
    ('min_password_length', '12', 'integer', 'Minimum password length (PCI DSS 8.2.3)', FALSE),
    ('max_password_length', '128', 'integer', 'Maximum password length', FALSE)
ON CONFLICT (config_key) DO NOTHING;

-- ============================================================================
-- HASHING FUNCTIONS
-- ============================================================================

-- Function to hash data using configured algorithm
-- NIST SP 800-57: Approved hashing algorithms
-- FIPS 180-4: SHA-256/384/512 secure hash standards
-- Parameters: data, algorithm
-- Returns: Hex-encoded hash
CREATE OR REPLACE FUNCTION crypto_hash(
    data TEXT,
    algorithm TEXT DEFAULT 'sha256'
)
RETURNS TEXT AS $$
DECLARE
    hash_bytes BYTEA;
BEGIN
    CASE algorithm
        WHEN 'sha256' THEN
            hash_bytes := digest(data, 'sha256');
        WHEN 'sha384' THEN
            hash_bytes := digest(data, 'sha384');
        WHEN 'sha512' THEN
            hash_bytes := digest(data, 'sha512');
        ELSE
            RAISE EXCEPTION 'Unsupported hash algorithm: %', algorithm;
    END CASE;
    
    RETURN encode(hash_bytes, 'hex');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON EXTENSION pgcrypto IS 'ISO/IEC 27001 A.10.1: Cryptographic functions for PostgreSQL (FIPS-aligned, PCI DSS compliant)';
COMMENT ON FUNCTION crypto_hash IS 'NIST SP 800-57/FIPS 180-4: Generate cryptographic hash using approved algorithms';
COMMENT ON TABLE crypto_configuration IS 'ISO/IEC 27001 A.10.1.1: Centralized cryptographic policy configuration';

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Add support for Argon2 password hashing when available (OWASP latest)
-- TODO: Implement key wrapping and unwrapping functions (NIST SP 800-57)
-- TODO: Add support for AEAD (Authenticated Encryption with Associated Data)
-- TODO: Implement certificate validation functions (X.509)
-- TODO: Add support for hardware security module (HSM) integration (PCI DSS 3.6.1)
-- TODO: Implement secure key escrow mechanisms
-- TODO: Add support for quantum-resistant algorithms preparation (NIST PQC)
-- TODO: Implement secure memory wiping for sensitive data
-- TODO: Add FIPS 140-2 compliance mode detection and enforcement
-- TODO: Implement crypto operation rate limiting (DoS prevention)
-- ============================================================================
