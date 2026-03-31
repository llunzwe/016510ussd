-- =============================================================================
-- MIGRATION: 006_security_signing_keys.sql
-- DESCRIPTION: Create security.signing_keys table for block signatures
-- DEPENDENCIES: 001_create_schemas.sql, 003_core_account_registry.sql
-- PRIORITY: Must run BEFORE 007_core_blocks_merkle.sql
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.8.2: Privileged access rights (key management)
  - A.10.1: Cryptographic controls

ISO/IEC 27040:2024 - Storage Security
  - Section 6: Data protection and encryption
  - Section 7: Access control and authentication
================================================================================
*/

-- Create the security schema if it doesn't exist
CREATE SCHEMA IF NOT EXISTS security;

-- =============================================================================
-- Create signing_keys table
-- DESCRIPTION: Stores cryptographic signing keys for block signatures
-- PRIORITY: CRITICAL
-- SECURITY: Private keys encrypted at rest
-- =============================================================================
CREATE TABLE IF NOT EXISTS security.signing_keys (
    key_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_name            VARCHAR(100) NOT NULL,
    key_type            VARCHAR(20) NOT NULL DEFAULT 'ED25519',
                        -- ED25519, RSA-2048, ECDSA-P256, etc.
    
    -- Keys (public always stored, private encrypted if not using HSM)
    public_key          BYTEA NOT NULL,
    private_key_encrypted BYTEA,  -- NULL if using HSM
    
    -- Key metadata
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    expires_at          TIMESTAMPTZ,
    
    -- Status lifecycle
    status              VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
                        -- ACTIVE, EXPIRED, REVOKED, COMPROMISED
    revoked_at          TIMESTAMPTZ,
    revoked_reason      TEXT,
    revoked_by          UUID REFERENCES core.accounts(account_id),
    
    -- Audit
    last_used_at        TIMESTAMPTZ,
    use_count           INTEGER DEFAULT 0,
    
    -- Constraints
    CONSTRAINT chk_signing_keys_status 
        CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'COMPROMISED')),
    CONSTRAINT chk_signing_keys_type 
        CHECK (key_type IN ('ED25519', 'RSA-2048', 'RSA-4096', 'ECDSA-P256', 'ECDSA-P384'))
);

-- Create indexes for signing_keys
CREATE UNIQUE INDEX IF NOT EXISTS idx_signing_keys_name_active 
    ON security.signing_keys(key_name) 
    WHERE status = 'ACTIVE';

CREATE INDEX IF NOT EXISTS idx_signing_keys_status 
    ON security.signing_keys(status) 
    WHERE status = 'ACTIVE';

CREATE INDEX IF NOT EXISTS idx_signing_keys_expires 
    ON security.signing_keys(expires_at) 
    WHERE expires_at IS NOT NULL AND status = 'ACTIVE';

-- Comments
COMMENT ON TABLE security.signing_keys IS 'Cryptographic signing keys for block signatures and transaction verification';
COMMENT ON COLUMN security.signing_keys.private_key_encrypted IS 'AES-256 encrypted private key; NULL if using HSM/external key management';
COMMENT ON COLUMN security.signing_keys.status IS 'Key status: ACTIVE, EXPIRED, REVOKED, COMPROMISED';

-- =============================================================================
-- Create function to rotate signing keys
-- DESCRIPTION: Safely rotate expired or compromised keys
-- PRIORITY: HIGH
-- =============================================================================
CREATE OR REPLACE FUNCTION security.rotate_signing_key(
    p_old_key_id UUID,
    p_new_public_key BYTEA,
    p_new_private_key_encrypted BYTEA DEFAULT NULL,
    p_new_key_type VARCHAR(20) DEFAULT 'ED25519',
    p_rotated_by UUID DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_new_key_id UUID;
BEGIN
    -- Verify old key exists and is active
    IF NOT EXISTS (
        SELECT 1 FROM security.signing_keys 
        WHERE key_id = p_old_key_id AND status = 'ACTIVE'
    ) THEN
        RAISE EXCEPTION 'Active key % not found', p_old_key_id;
    END IF;
    
    -- Revoke old key
    UPDATE security.signing_keys
    SET status = 'REVOKED',
        revoked_at = now(),
        revoked_reason = 'Rotated - key rotation policy',
        revoked_by = p_rotated_by
    WHERE key_id = p_old_key_id;
    
    -- Create new key
    INSERT INTO security.signing_keys (
        key_name, key_type, public_key, private_key_encrypted,
        created_by, expires_at, status
    )
    SELECT 
        key_name || '-rotated-' || to_char(now(), 'YYYYMMDD'),
        p_new_key_type,
        p_new_public_key,
        p_new_private_key_encrypted,
        p_rotated_by,
        now() + interval '1 year',
        'ACTIVE'
    FROM security.signing_keys
    WHERE key_id = p_old_key_id
    RETURNING key_id INTO v_new_key_id;
    
    RETURN v_new_key_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION security.rotate_signing_key IS 'Rotates a signing key by revoking the old one and creating a new one';

-- =============================================================================
-- Create function to record key usage
-- DESCRIPTION: Audit trail of key usage
-- PRIORITY: MEDIUM
-- =============================================================================
CREATE OR REPLACE FUNCTION security.record_key_usage(
    p_key_id UUID
) RETURNS VOID AS $$
BEGIN
    UPDATE security.signing_keys
    SET last_used_at = now(),
        use_count = use_count + 1
    WHERE key_id = p_key_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION security.record_key_usage IS 'Records usage of a signing key for audit purposes';

/*
================================================================================
MIGRATION CHECKLIST:
[x] Create security schema
[x] Create signing_keys table with all columns
[x] Add indexes for key lookups
[x] Create key rotation function
[x] Create key usage tracking function
[x] Add all comments
[ ] Insert initial kernel signing key (manual step)
================================================================================
*/
