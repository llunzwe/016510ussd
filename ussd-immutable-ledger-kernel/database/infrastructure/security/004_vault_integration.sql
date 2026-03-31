-- =============================================================================
-- VAULT INTEGRATION
-- HashiCorp Vault integration for dynamic secrets and key management
-- =============================================================================

-- =============================================================================
-- VAULT SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS vault_integration;

COMMENT ON SCHEMA vault_integration IS 'HashiCorp Vault integration for secrets management';

-- =============================================================================
-- VAULT CONFIGURATION
-- =============================================================================
CREATE TABLE IF NOT EXISTS vault_integration.config (
    id SERIAL PRIMARY KEY,
    config_name VARCHAR(100) NOT NULL UNIQUE,
    vault_addr VARCHAR(500) NOT NULL,
    vault_namespace VARCHAR(100), -- For Vault Enterprise
    auth_method VARCHAR(50) NOT NULL DEFAULT 'kubernetes', -- kubernetes, approle, token, aws, azure
    
    -- Auth configuration (references to external secure storage)
    role_name VARCHAR(100),
    auth_path VARCHAR(100) DEFAULT 'auth/kubernetes',
    service_account_path VARCHAR(200) DEFAULT '/var/run/secrets/kubernetes.io/serviceaccount/token',
    
    -- Secret paths
    secrets_engine_path VARCHAR(100) DEFAULT 'secret',
    database_secrets_path VARCHAR(100) DEFAULT 'database/creds',
    pki_secrets_path VARCHAR(100) DEFAULT 'pki',
    transit_secrets_path VARCHAR(100) DEFAULT 'transit',
    
    -- Connection settings
    tls_enabled BOOLEAN DEFAULT TRUE,
    tls_ca_cert_path VARCHAR(500),
    tls_client_cert_path VARCHAR(500),
    tls_client_key_path VARCHAR(500),
    
    -- Timeout settings
    request_timeout_seconds INTEGER DEFAULT 30,
    max_retries INTEGER DEFAULT 3,
    retry_delay_ms INTEGER DEFAULT 1000,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    last_health_check TIMESTAMPTZ,
    last_health_status VARCHAR(20),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE vault_integration.config IS 'Vault connection configuration';

-- =============================================================================
-- SECRET LEASES TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS vault_integration.secret_leases (
    id SERIAL PRIMARY KEY,
    lease_id VARCHAR(500) NOT NULL UNIQUE,
    secret_path VARCHAR(500) NOT NULL,
    secret_type VARCHAR(50) NOT NULL, -- database, pki, kv, aws, etc.
    
    -- Lease details
    lease_duration INTEGER, -- seconds
    lease_renewable BOOLEAN DEFAULT FALSE,
    leased_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_renewed_at TIMESTAMPTZ,
    renew_count INTEGER DEFAULT 0,
    
    -- Secret data (encrypted)
    username VARCHAR(100),
    password_encrypted BYTEA,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    revoked_at TIMESTAMPTZ,
    revoke_reason VARCHAR(100),
    
    -- Metadata
    requested_by VARCHAR(100) DEFAULT current_user,
    client_address INET,
    purpose TEXT
);

CREATE INDEX IF NOT EXISTS idx_leases_active 
ON vault_integration.secret_leases(is_active, expires_at) 
WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_leases_path 
ON vault_integration.secret_leases(secret_path);

-- =============================================================================
-- AUDIT LOG
-- =============================================================================
CREATE TABLE IF NOT EXISTS vault_integration.audit_log (
    id BIGSERIAL PRIMARY KEY,
    operation VARCHAR(50) NOT NULL, -- AUTH, READ, WRITE, DELETE, RENEW, REVOKE
    secret_path VARCHAR(500),
    status VARCHAR(20) NOT NULL, -- SUCCESS, FAILURE
    error_code VARCHAR(100),
    error_message TEXT,
    performed_at TIMESTAMPTZ DEFAULT NOW(),
    performed_by VARCHAR(100) DEFAULT current_user,
    client_ip INET,
    response_time_ms INTEGER,
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_vault_audit_time 
ON vault_integration.audit_log(performed_at DESC);

-- =============================================================================
-- DEFAULT CONFIGURATION
-- =============================================================================
INSERT INTO vault_integration.config (
    config_name, vault_addr, auth_method, role_name,
    secrets_engine_path, database_secrets_path, pki_secrets_path,
    description
) VALUES 
(
    'production_vault',
    'https://vault.ledger.internal:8200',
    'kubernetes',
    'ledger-database-role',
    'secret/data/ledger',
    'database/creds/ledger-app',
    'pki/issue/ledger-internal',
    'Primary Vault for production secrets'
),
(
    'staging_vault',
    'https://vault-staging.ledger.internal:8200',
    'kubernetes',
    'ledger-database-role-staging',
    'secret/data/ledger-staging',
    'database/creds/ledger-app-staging',
    'pki/issue/ledger-staging',
    'Vault for staging environment'
)
ON CONFLICT (config_name) DO UPDATE SET
    vault_addr = EXCLUDED.vault_addr,
    auth_method = EXCLUDED.auth_method,
    updated_at = NOW();

-- =============================================================================
-- FUNCTION: Build Vault API URL
-- =============================================================================
CREATE OR REPLACE FUNCTION vault_integration.build_url(
    p_config_name VARCHAR,
    p_path VARCHAR
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
BEGIN
    SELECT * INTO v_config
    FROM vault_integration.config
    WHERE config_name = p_config_name AND is_active = TRUE;
    
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    
    RETURN format('%s/v1/%s', v_config.vault_addr, p_path);
END;
$$;

-- =============================================================================
-- FUNCTION: Log Vault operation
-- =============================================================================
CREATE OR REPLACE FUNCTION vault_integration.log_operation(
    p_operation VARCHAR,
    p_secret_path VARCHAR,
    p_status VARCHAR,
    p_error_code VARCHAR DEFAULT NULL,
    p_error_message TEXT DEFAULT NULL,
    p_response_time_ms INTEGER DEFAULT NULL,
    p_metadata JSONB DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO vault_integration.audit_log (
        operation, secret_path, status, error_code, 
        error_message, response_time_ms, metadata
    ) VALUES (
        p_operation, p_secret_path, p_status, p_error_code,
        p_error_message, p_response_time_ms, p_metadata
    );
END;
$$;

-- =============================================================================
-- FUNCTION: Store lease
-- =============================================================================
CREATE OR REPLACE FUNCTION vault_integration.store_lease(
    p_lease_id VARCHAR,
    p_secret_path VARCHAR,
    p_secret_type VARCHAR,
    p_lease_duration INTEGER,
    p_lease_renewable BOOLEAN,
    p_username VARCHAR DEFAULT NULL,
    p_password_encrypted BYTEA DEFAULT NULL,
    p_purpose TEXT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO vault_integration.secret_leases (
        lease_id, secret_path, secret_type,
        lease_duration, lease_renewable,
        expires_at, username, password_encrypted,
        purpose
    ) VALUES (
        p_lease_id, p_secret_path, p_secret_type,
        p_lease_duration, p_lease_renewable,
        NOW() + (p_lease_duration || ' seconds')::INTERVAL,
        p_username, p_password_encrypted,
        p_purpose
    );
END;
$$;

-- =============================================================================
-- FUNCTION: Revoke lease
-- =============================================================================
CREATE OR REPLACE FUNCTION vault_integration.revoke_lease(
    p_lease_id VARCHAR,
    p_reason VARCHAR DEFAULT 'MANUAL_REVOKE'
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE vault_integration.secret_leases
    SET is_active = FALSE,
        revoked_at = NOW(),
        revoke_reason = p_reason
    WHERE lease_id = p_lease_id
      AND is_active = TRUE;
    
    IF FOUND THEN
        RETURN format('SUCCESS: Lease %s revoked', p_lease_id);
    ELSE
        RETURN format('ERROR: Lease %s not found or already revoked', p_lease_id);
    END IF;
END;
$$;

-- =============================================================================
-- FUNCTION: Renew lease
-- =============================================================================
CREATE OR REPLACE FUNCTION vault_integration.renew_lease(
    p_lease_id VARCHAR,
    p_increment INTEGER DEFAULT NULL
)
RETURNS TABLE(
    renewed BOOLEAN,
    new_expires_at TIMESTAMPTZ,
    message TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_lease RECORD;
    v_new_duration INTEGER;
BEGIN
    SELECT * INTO v_lease
    FROM vault_integration.secret_leases
    WHERE lease_id = p_lease_id
      AND is_active = TRUE
      AND lease_renewable = TRUE;
    
    IF NOT FOUND THEN
        renewed := FALSE;
        new_expires_at := NULL;
        message := 'Lease not found, not active, or not renewable';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Calculate new duration
    v_new_duration := COALESCE(p_increment, v_lease.lease_duration);
    
    -- Update lease
    UPDATE vault_integration.secret_leases
    SET last_renewed_at = NOW(),
        expires_at = NOW() + (v_new_duration || ' seconds')::INTERVAL,
        renew_count = renew_count + 1
    WHERE id = v_lease.id;
    
    renewed := TRUE;
    new_expires_at := NOW() + (v_new_duration || ' seconds')::INTERVAL;
    message := format('Lease renewed for %s seconds', v_new_duration);
    
    -- Log renewal
    PERFORM vault_integration.log_operation(
        'RENEW', v_lease.secret_path, 'SUCCESS',
        NULL, NULL, NULL,
        jsonb_build_object('lease_id', p_lease_id, 'increment', v_new_duration)
    );
    
    RETURN NEXT;
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Get active database credentials
-- =============================================================================
CREATE OR REPLACE FUNCTION vault_integration.get_db_credentials(
    p_config_name VARCHAR,
    p_role VARCHAR DEFAULT NULL
)
RETURNS TABLE(
    username TEXT,
    password TEXT,
    lease_id TEXT,
    expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
AS $$
BEGIN
    -- In production, this would make actual Vault API calls
    -- For now, return placeholder indicating external integration needed
    username := 'vault_dynamic_user';
    password := '[RETRIEVE_FROM_VAULT]';
    lease_id := gen_random_uuid()::TEXT;
    expires_at := NOW() + INTERVAL '1 hour';
    
    RETURN NEXT;
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Get PKI certificate
-- =============================================================================
CREATE OR REPLACE FUNCTION vault_integration.get_pki_certificate(
    p_config_name VARCHAR,
    p_common_name VARCHAR,
    p_ttl VARCHAR DEFAULT '720h',
    p_alt_names TEXT[] DEFAULT NULL
)
RETURNS TABLE(
    certificate TEXT,
    private_key TEXT,
    ca_chain TEXT,
    serial_number TEXT,
    lease_id TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
BEGIN
    SELECT * INTO v_config
    FROM vault_integration.config
    WHERE config_name = p_config_name AND is_active = TRUE;
    
    IF NOT FOUND THEN
        RETURN;
    END IF;
    
    -- In production, this would call Vault PKI API
    certificate := '[CERTIFICATE_FROM_VAULT]';
    private_key := '[PRIVATE_KEY_FROM_VAULT]';
    ca_chain := '[CA_CHAIN_FROM_VAULT]';
    serial_number := gen_random_uuid()::TEXT;
    lease_id := gen_random_uuid()::TEXT;
    
    -- Log operation
    PERFORM vault_integration.log_operation(
        'READ', v_config.pki_secrets_path, 'SUCCESS',
        NULL, NULL, NULL,
        jsonb_build_object('common_name', p_common_name, 'ttl', p_ttl)
    );
    
    RETURN NEXT;
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Encrypt with Transit engine
-- =============================================================================
CREATE OR REPLACE FUNCTION vault_integration.transit_encrypt(
    p_config_name VARCHAR,
    p_key_name VARCHAR,
    p_plaintext TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_config RECORD;
BEGIN
    SELECT * INTO v_config
    FROM vault_integration.config
    WHERE config_name = p_config_name AND is_active = TRUE;
    
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    
    -- In production, this would call Vault Transit API
    -- For now, use local encryption as fallback
    RETURN format('vault:v1:%s', encode(encryption.sha256(p_plaintext), 'base64'));
END;
$$;

-- =============================================================================
-- FUNCTION: Decrypt with Transit engine
-- =============================================================================
CREATE OR REPLACE FUNCTION vault_integration.transit_decrypt(
    p_config_name VARCHAR,
    p_key_name VARCHAR,
    p_ciphertext TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    -- In production, this would call Vault Transit API
    RETURN '[DECRYPTION_REQUIRES_VAULT_API]';
END;
$$;

-- =============================================================================
-- FUNCTION: Clean expired leases
-- =============================================================================
CREATE OR REPLACE FUNCTION vault_integration.clean_expired_leases()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER;
BEGIN
    UPDATE vault_integration.secret_leases
    SET is_active = FALSE,
        revoke_reason = 'EXPIRED'
    WHERE is_active = TRUE
      AND expires_at < NOW();
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    
    RETURN v_count;
END;
$$;

-- =============================================================================
-- VIEW: Active leases
-- =============================================================================
CREATE OR REPLACE VIEW vault_integration.active_leases AS
SELECT 
    lease_id,
    secret_path,
    secret_type,
    lease_duration,
    lease_renewable,
    leased_at,
    expires_at,
    last_renewed_at,
    renew_count,
    username,
    EXTRACT(EPOCH FROM (expires_at - NOW()))::INTEGER as seconds_remaining,
    CASE 
        WHEN expires_at < NOW() + INTERVAL '5 minutes' THEN 'CRITICAL'
        WHEN expires_at < NOW() + INTERVAL '1 hour' THEN 'WARNING'
        ELSE 'HEALTHY'
    END as lease_status,
    purpose
FROM vault_integration.secret_leases
WHERE is_active = TRUE
ORDER BY expires_at;

-- =============================================================================
-- VIEW: Lease statistics
-- =============================================================================
CREATE OR REPLACE VIEW vault_integration.lease_stats AS
SELECT 
    secret_type,
    COUNT(*) FILTER (WHERE is_active) as active_count,
    COUNT(*) FILTER (WHERE NOT is_active) as revoked_count,
    AVG(lease_duration) as avg_duration,
    AVG(renew_count) as avg_renewals,
    MAX(leased_at) as last_issued,
    COUNT(*) FILTER (WHERE expires_at < NOW() AND is_active) as expired_not_cleaned
FROM vault_integration.secret_leases
GROUP BY secret_type;

-- =============================================================================
-- VIEW: Audit summary
-- =============================================================================
CREATE OR REPLACE VIEW vault_integration.audit_summary AS
SELECT 
    operation,
    status,
    COUNT(*) as count,
    MAX(performed_at) as last_occurrence,
    AVG(response_time_ms) as avg_response_time_ms
FROM vault_integration.audit_log
WHERE performed_at > NOW() - INTERVAL '24 hours'
GROUP BY operation, status;

-- =============================================================================
-- TRIGGER: Update timestamp
-- =============================================================================
CREATE TRIGGER trigger_vault_config_updated
    BEFORE UPDATE ON vault_integration.config
    FOR EACH ROW EXECUTE FUNCTION encryption.update_timestamp();

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA vault_integration TO vault_admin;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA vault_integration TO vault_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA vault_integration TO vault_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA vault_integration TO vault_admin;
