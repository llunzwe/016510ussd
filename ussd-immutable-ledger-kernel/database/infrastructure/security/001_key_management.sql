-- =============================================================================
-- KEY MANAGEMENT
-- Comprehensive key lifecycle management for encryption
-- =============================================================================

-- =============================================================================
-- KEY SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS key_mgmt;

COMMENT ON SCHEMA key_mgmt IS 'Key management and lifecycle operations';

-- =============================================================================
-- KEY HIERARCHY TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS key_mgmt.keys (
    id SERIAL PRIMARY KEY,
    key_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    key_name VARCHAR(200) NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    
    -- Key classification
    key_type VARCHAR(50) NOT NULL, -- MASTER, DATA, COLUMN, BACKUP, SESSION
    algorithm VARCHAR(50) NOT NULL DEFAULT 'AES-256-GCM',
    key_length INTEGER NOT NULL DEFAULT 256,
    
    -- Key material (encrypted with master key in production)
    key_fingerprint VARCHAR(64) NOT NULL,
    key_reference VARCHAR(500) NOT NULL, -- Reference to external key storage
    
    -- Key state
    key_state VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, ROTATING, EXPIRED, REVOKED, DESTROYED
    
    -- Lifecycle dates
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    destroyed_at TIMESTAMPTZ,
    
    -- Rotation settings
    auto_rotation_enabled BOOLEAN DEFAULT TRUE,
    rotation_interval_days INTEGER DEFAULT 90,
    next_rotation_at TIMESTAMPTZ,
    
    -- Usage tracking
    encrypt_count BIGINT DEFAULT 0,
    decrypt_count BIGINT DEFAULT 0,
    last_used_at TIMESTAMPTZ,
    
    -- Audit
    created_by VARCHAR(100) DEFAULT current_user,
    purpose TEXT,
    
    UNIQUE(key_name, key_version)
);

CREATE INDEX IF NOT EXISTS idx_keys_state 
ON key_mgmt.keys(key_state) WHERE key_state IN ('ACTIVE', 'ROTATING');

CREATE INDEX IF NOT EXISTS idx_keys_type 
ON key_mgmt.keys(key_type, key_name);

CREATE INDEX IF NOT EXISTS idx_keys_rotation 
ON key_mgmt.keys(next_rotation_at) 
WHERE auto_rotation_enabled = TRUE AND key_state = 'ACTIVE';

COMMENT ON TABLE key_mgmt.keys IS 'Key hierarchy and lifecycle management';

-- =============================================================================
-- KEY USAGE LOG
-- =============================================================================
CREATE TABLE IF NOT EXISTS key_mgmt.key_usage_log (
    id BIGSERIAL PRIMARY KEY,
    key_id UUID NOT NULL REFERENCES key_mgmt.keys(key_id),
    operation VARCHAR(20) NOT NULL, -- ENCRYPT, DECRYPT, SIGN, VERIFY, WRAP, UNWRAP
    performed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    performed_by VARCHAR(100) DEFAULT current_user,
    client_ip INET,
    application_name VARCHAR(100),
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_key_usage_key 
ON key_mgmt.key_usage_log(key_id, performed_at DESC);

CREATE INDEX IF NOT EXISTS idx_key_usage_time 
ON key_mgmt.key_usage_log(performed_at DESC);

-- =============================================================================
-- KEY DEPENDENCY MAP
-- =============================================================================
CREATE TABLE IF NOT EXISTS key_mgmt.key_dependencies (
    id SERIAL PRIMARY KEY,
    parent_key_id UUID NOT NULL REFERENCES key_mgmt.keys(key_id),
    child_key_id UUID NOT NULL REFERENCES key_mgmt.keys(key_id),
    dependency_type VARCHAR(50) NOT NULL, -- WRAPS, DERIVES, SIGNS
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(parent_key_id, child_key_id, dependency_type)
);

-- =============================================================================
-- DEFAULT KEYS
-- =============================================================================
INSERT INTO key_mgmt.keys (
    key_name, key_type, algorithm, key_fingerprint, key_reference,
    activated_at, expires_at, rotation_interval_days, next_rotation_at, purpose
) VALUES 
(
    'MASTER_KEY_001', 'MASTER', 'AES-256-GCM',
    encode(digest('master_key_placeholder', 'sha256'), 'hex'),
    'vault://secret/ledger/master-key-001',
    NOW(), NOW() + INTERVAL '1 year', 365, NOW() + INTERVAL '1 year',
    'Master encryption key for data protection'
),
(
    'DATA_KEY_001', 'DATA', 'AES-256-GCM',
    encode(digest('data_key_placeholder', 'sha256'), 'hex'),
    'vault://secret/ledger/data-key-001',
    NOW(), NOW() + INTERVAL '90 days', 90, NOW() + INTERVAL '90 days',
    'Data encryption key for sensitive fields'
),
(
    'COLUMN_KEY_001', 'COLUMN', 'AES-256-GCM',
    encode(digest('column_key_placeholder', 'sha256'), 'hex'),
    'vault://secret/ledger/column-key-001',
    NOW(), NOW() + INTERVAL '90 days', 90, NOW() + INTERVAL '90 days',
    'Column-level encryption key'
),
(
    'BACKUP_KEY_001', 'BACKUP', 'AES-256-GCM',
    encode(digest('backup_key_placeholder', 'sha256'), 'hex'),
    'vault://secret/ledger/backup-key-001',
    NOW(), NOW() + INTERVAL '180 days', 180, NOW() + INTERVAL '180 days',
    'Backup encryption key'
)
ON CONFLICT (key_name, key_version) DO UPDATE SET
    key_fingerprint = EXCLUDED.key_fingerprint,
    expires_at = EXCLUDED.expires_at;

-- =============================================================================
-- FUNCTION: Generate new key
-- =============================================================================
CREATE OR REPLACE FUNCTION key_mgmt.generate_key(
    p_key_name VARCHAR,
    p_key_type VARCHAR,
    p_algorithm VARCHAR DEFAULT 'AES-256-GCM',
    p_key_length INTEGER DEFAULT 256,
    p_rotation_interval_days INTEGER DEFAULT 90,
    p_purpose TEXT DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_key_id UUID := gen_random_uuid();
    v_version INTEGER;
    v_fingerprint VARCHAR(64);
    v_key_material BYTEA;
BEGIN
    -- Get next version
    SELECT COALESCE(MAX(key_version), 0) + 1 INTO v_version
    FROM key_mgmt.keys
    WHERE key_name = p_key_name;
    
    -- Generate key material
    v_key_material := gen_random_bytes(p_key_length / 8);
    v_fingerprint := encode(digest(v_key_material, 'sha256'), 'hex');
    
    -- Insert key record
    INSERT INTO key_mgmt.keys (
        key_id, key_name, key_version, key_type, algorithm, key_length,
        key_fingerprint, key_reference,
        activated_at, expires_at, rotation_interval_days, next_rotation_at,
        purpose
    ) VALUES (
        v_key_id, p_key_name, v_version, p_key_type, p_algorithm, p_key_length,
        v_fingerprint, format('vault://secret/ledger/%s-v%s', p_key_name, v_version),
        NOW(), NOW() + (p_rotation_interval_days || ' days')::INTERVAL,
        p_rotation_interval_days, NOW() + (p_rotation_interval_days || ' days')::INTERVAL,
        p_purpose
    );
    
    -- Clear key material from memory
    v_key_material := '\x00'::BYTEA;
    
    RETURN v_key_id;
EXCEPTION WHEN OTHERS THEN
    -- Ensure key material is cleared on error
    v_key_material := '\x00'::BYTEA;
    RAISE;
END;
$$;

-- =============================================================================
-- FUNCTION: Get active key by name
-- =============================================================================
CREATE OR REPLACE FUNCTION key_mgmt.get_active_key(p_key_name VARCHAR)
RETURNS TABLE(
    key_id UUID,
    key_version INTEGER,
    key_fingerprint VARCHAR,
    key_reference VARCHAR,
    expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        k.key_id,
        k.key_version,
        k.key_fingerprint,
        k.key_reference,
        k.expires_at
    FROM key_mgmt.keys k
    WHERE k.key_name = p_key_name
      AND k.key_state = 'ACTIVE'
    ORDER BY k.key_version DESC
    LIMIT 1;
END;
$$;

-- =============================================================================
-- FUNCTION: Rotate key
-- =============================================================================
CREATE OR REPLACE FUNCTION key_mgmt.rotate_key(
    p_key_name VARCHAR,
    p_grace_period_days INTEGER DEFAULT 7
)
RETURNS TABLE(old_key_id UUID, new_key_id UUID, status TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_old_key RECORD;
    v_new_key_id UUID;
BEGIN
    -- Get current active key
    SELECT * INTO v_old_key
    FROM key_mgmt.keys
    WHERE key_name = p_key_name
      AND key_state = 'ACTIVE'
    ORDER BY key_version DESC
    LIMIT 1;
    
    IF NOT FOUND THEN
        old_key_id := NULL;
        new_key_id := NULL;
        status := 'ERROR: No active key found';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Mark old key for rotation
    UPDATE key_mgmt.keys
    SET key_state = 'ROTATING',
        rotated_at = NOW(),
        expires_at = NOW() + (p_grace_period_days || ' days')::INTERVAL
    WHERE key_id = v_old_key.key_id;
    
    -- Generate new key
    v_new_key_id := key_mgmt.generate_key(
        p_key_name,
        v_old_key.key_type,
        v_old_key.algorithm,
        v_old_key.key_length,
        v_old_key.rotation_interval_days,
        v_old_key.purpose
    );
    
    old_key_id := v_old_key.key_id;
    new_key_id := v_new_key_id;
    status := format('SUCCESS: Key rotated, grace period: %s days', p_grace_period_days);
    
    RETURN NEXT;
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Revoke key
-- =============================================================================
CREATE OR REPLACE FUNCTION key_mgmt.revoke_key(
    p_key_id UUID,
    p_reason TEXT DEFAULT NULL
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE key_mgmt.keys
    SET key_state = 'REVOKED',
        revoked_at = NOW(),
        expires_at = NOW(),
        purpose = COALESCE(purpose || '; Revoked: ' || p_reason, 'Revoked: ' || p_reason)
    WHERE key_id = p_key_id
      AND key_state IN ('ACTIVE', 'ROTATING');
    
    IF FOUND THEN
        RETURN format('SUCCESS: Key %s revoked', p_key_id);
    ELSE
        RETURN format('ERROR: Key %s not found or not active', p_key_id);
    END IF;
END;
$$;

-- =============================================================================
-- FUNCTION: Destroy key (crypto-shredding)
-- =============================================================================
CREATE OR REPLACE FUNCTION key_mgmt.destroy_key(
    p_key_id UUID,
    p_confirm_force BOOLEAN DEFAULT FALSE
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_key_name VARCHAR;
    v_dependencies INTEGER;
BEGIN
    -- Check for dependencies
    SELECT COUNT(*) INTO v_dependencies
    FROM key_mgmt.key_dependencies
    WHERE parent_key_id = p_key_id;
    
    IF v_dependencies > 0 AND NOT p_confirm_force THEN
        RETURN format('ERROR: Key has %s dependent keys, use force to destroy', v_dependencies);
    END IF;
    
    -- Get key name for logging
    SELECT key_name INTO v_key_name
    FROM key_mgmt.keys
    WHERE key_id = p_key_id;
    
    -- Mark as destroyed
    UPDATE key_mgmt.keys
    SET key_state = 'DESTROYED',
        destroyed_at = NOW(),
        expires_at = NOW(),
        key_reference = '[DESTROYED]'
    WHERE key_id = p_key_id;
    
    IF FOUND THEN
        RETURN format('SUCCESS: Key %s (%s) destroyed', p_key_id, v_key_name);
    ELSE
        RETURN format('ERROR: Key %s not found', p_key_id);
    END IF;
END;
$$;

-- =============================================================================
-- FUNCTION: Log key usage
-- =============================================================================
CREATE OR REPLACE FUNCTION key_mgmt.log_usage(
    p_key_id UUID,
    p_operation VARCHAR,
    p_success BOOLEAN DEFAULT TRUE,
    p_error_message TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    -- Log usage
    INSERT INTO key_mgmt.key_usage_log (
        key_id, operation, success, error_message, metadata
    ) VALUES (
        p_key_id, p_operation, p_success, p_error_message, p_metadata
    );
    
    -- Update key statistics
    UPDATE key_mgmt.keys
    SET 
        encrypt_count = CASE WHEN p_operation = 'ENCRYPT' THEN encrypt_count + 1 ELSE encrypt_count END,
        decrypt_count = CASE WHEN p_operation = 'DECRYPT' THEN decrypt_count + 1 ELSE decrypt_count END,
        last_used_at = NOW()
    WHERE key_id = p_key_id;
END;
$$;

-- =============================================================================
-- FUNCTION: Check for keys needing rotation
-- =============================================================================
CREATE OR REPLACE FUNCTION key_mgmt.check_rotation_needed()
RETURNS TABLE(
    key_name VARCHAR,
    key_id UUID,
    current_version INTEGER,
    expires_at TIMESTAMPTZ,
    days_until_expiry INTEGER
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        k.key_name::VARCHAR(200),
        k.key_id,
        k.key_version,
        k.expires_at,
        EXTRACT(DAY FROM (k.expires_at - NOW()))::INTEGER as days_until_expiry
    FROM key_mgmt.keys k
    WHERE k.key_state = 'ACTIVE'
      AND k.auto_rotation_enabled = TRUE
      AND (k.next_rotation_at <= NOW() OR k.expires_at <= NOW() + INTERVAL '7 days')
    ORDER BY k.expires_at;
END;
$$;

-- =============================================================================
-- FUNCTION: Auto-rotate expired keys
-- =============================================================================
CREATE OR REPLACE FUNCTION key_mgmt.auto_rotate_expired_keys()
RETURNS TABLE(key_name VARCHAR, old_key_id UUID, new_key_id UUID, status TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_key RECORD;
    v_result RECORD;
BEGIN
    FOR v_key IN 
        SELECT k.key_name
        FROM key_mgmt.keys k
        WHERE k.key_state = 'ACTIVE'
          AND k.auto_rotation_enabled = TRUE
          AND k.next_rotation_at <= NOW()
    LOOP
        SELECT * INTO v_result
        FROM key_mgmt.rotate_key(v_key.key_name);
        
        key_name := v_key.key_name::VARCHAR(200);
        old_key_id := v_result.old_key_id;
        new_key_id := v_result.new_key_id;
        status := v_result.status;
        
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- VIEW: Key inventory
-- =============================================================================
CREATE OR REPLACE VIEW key_mgmt.key_inventory AS
SELECT 
    k.key_id,
    k.key_name,
    k.key_version,
    k.key_type,
    k.algorithm,
    k.key_length,
    substring(k.key_fingerprint, 1, 16) || '...' as fingerprint_short,
    k.key_state,
    k.created_at,
    k.activated_at,
    k.expires_at,
    k.rotated_at,
    CASE 
        WHEN k.key_state != 'ACTIVE' THEN 'N/A'
        WHEN k.expires_at < NOW() THEN 'EXPIRED'
        WHEN k.expires_at < NOW() + INTERVAL '7 days' THEN 'CRITICAL'
        WHEN k.expires_at < NOW() + INTERVAL '30 days' THEN 'WARNING'
        ELSE 'HEALTHY'
    END as expiry_status,
    k.rotation_interval_days,
    k.next_rotation_at,
    k.encrypt_count,
    k.decrypt_count,
    k.last_used_at,
    k.purpose
FROM key_mgmt.keys k
ORDER BY k.key_name, k.key_version DESC;

-- =============================================================================
-- VIEW: Key usage statistics
-- =============================================================================
CREATE OR REPLACE VIEW key_mgmt.key_usage_stats AS
SELECT 
    k.key_id,
    k.key_name,
    k.key_version,
    k.key_state,
    COUNT(kul.id) as total_operations,
    COUNT(kul.id) FILTER (WHERE kul.operation = 'ENCRYPT') as encrypt_ops,
    COUNT(kul.id) FILTER (WHERE kul.operation = 'DECRYPT') as decrypt_ops,
    COUNT(kul.id) FILTER (WHERE kul.success = FALSE) as failed_ops,
    MAX(kul.performed_at) as last_operation_at,
    COUNT(kul.id) FILTER (WHERE kul.performed_at > NOW() - INTERVAL '24 hours') as ops_24h
FROM key_mgmt.keys k
LEFT JOIN key_mgmt.key_usage_log kul ON kul.key_id = k.key_id
GROUP BY k.key_id, k.key_name, k.key_version, k.key_state;

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA key_mgmt TO key_admin;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA key_mgmt TO key_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA key_mgmt TO key_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA key_mgmt TO key_admin;
