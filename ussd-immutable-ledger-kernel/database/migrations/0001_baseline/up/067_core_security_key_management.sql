-- =============================================================================
-- USSD KERNEL CORE SCHEMA - SECURITY KEY MANAGEMENT
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    067_core_security_key_management.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      core
-- DESCRIPTION: Centralized encryption key management with HSM/Vault integration,
--              key rotation, and secure key lifecycle management.
-- =============================================================================

/*
================================================================================
SECURITY FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.10.1 Cryptographic controls
├── A.10.2 Key management
└── A.12.3 Information backup

PCI DSS 4.0
├── Requirement 3: Protect stored cardholder data
└── Requirement 8: Key management procedures

Financial Regulations
├── Key rotation: Quarterly or on compromise
├── Key escrow: Recovery procedures
└── Audit: Complete key lifecycle logging

================================================================================
KEY HIERARCHY
================================================================================

L1: Master Key (HSM or Vault) - Never leaves secure storage
L2: Key Encryption Key (KEK) - Encrypts data keys
L3: Data Encryption Key (DEK) - Encrypts actual data
L4: Field-level keys - Derived from DEK per field type

================================================================================
KEY LIFECYCLE
================================================================================

1. Generation - Secure random generation
2. Distribution - Encrypted transport to authorized systems
3. Storage - HSM/Vault with access controls
4. Rotation - Scheduled or triggered replacement
5. Compromise - Emergency revocation and re-encryption
6. Destruction - Secure deletion with audit

================================================================================
*/

-- =============================================================================
-- KEY REGISTRY
-- =============================================================================

CREATE TABLE core.encryption_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Key hierarchy
    key_level INTEGER NOT NULL CHECK (key_level BETWEEN 1 AND 4),
    parent_key_id UUID REFERENCES core.encryption_keys(key_id),
    
    -- Key type
    key_type VARCHAR(20) NOT NULL 
        CHECK (key_type IN ('MASTER', 'KEK', 'DEK', 'FIELD', 'SIGNING', 'HMAC')),
    key_algorithm VARCHAR(20) NOT NULL DEFAULT 'AES-256-GCM'
        CHECK (key_algorithm IN ('AES-128-GCM', 'AES-256-GCM', 'ChaCha20-Poly1305', 'RSA-4096', 'Ed25519')),
    key_purpose TEXT NOT NULL,  -- What this key encrypts
    
    -- Key material (encrypted with parent key)
    -- The actual key is encrypted - only decrypted in memory when needed
    encrypted_key_material BYTEA NOT NULL,
    key_checksum VARCHAR(64) NOT NULL,  -- SHA-256 of decrypted key for verification
    
    -- Key version for rotation tracking
    key_version INTEGER NOT NULL DEFAULT 1,
    replaces_key_id UUID REFERENCES core.encryption_keys(key_id),
    
    -- Status
    key_status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (key_status IN ('ACTIVE', 'ROTATING', 'COMPROMISED', 'DEPRECATED', 'DESTROYED')),
    
    -- Validity period
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    activated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    destroyed_at TIMESTAMPTZ,
    
    -- Rotation policy
    rotation_period INTERVAL DEFAULT INTERVAL '90 days',
    auto_rotate BOOLEAN DEFAULT TRUE,
    
    -- Compromise handling
    compromise_detected_at TIMESTAMPTZ,
    compromise_reason TEXT,
    
    -- Access controls
    created_by UUID,
    activated_by UUID,
    rotated_by UUID,
    destroyed_by UUID,
    
    -- Audit
    access_count INTEGER DEFAULT 0,
    last_accessed_at TIMESTAMPTZ,
    last_accessed_by UUID,
    last_access_reason TEXT,
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- KEY ACCESS LOG
-- =============================================================================

CREATE TABLE core.key_access_log (
    access_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id UUID NOT NULL REFERENCES core.encryption_keys(key_id),
    
    -- Access details
    access_type VARCHAR(20) NOT NULL
        CHECK (access_type IN ('CREATE', 'READ', 'USE', 'ROTATE', 'DESTROY', 'EXPORT')),
    access_reason TEXT NOT NULL,
    
    -- Context
    accessed_by UUID,
    session_id TEXT,
    client_ip INET,
    application_id UUID,
    
    -- Result
    access_granted BOOLEAN NOT NULL,
    denial_reason TEXT,
    
    -- Timestamps
    accessed_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    
    -- Compliance
    approved_by UUID,  -- For sensitive operations
    approval_reference VARCHAR(100)
);

-- =============================================================================
-- KEY ROTATION QUEUE
-- =============================================================================

CREATE TABLE core.key_rotation_queue (
    queue_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id UUID NOT NULL REFERENCES core.encryption_keys(key_id),
    
    -- Rotation details
    rotation_type VARCHAR(20) NOT NULL
        CHECK (rotation_type IN ('SCHEDULED', 'EMERGENCY', 'COMPLIANCE', 'MANUAL')),
    priority INTEGER DEFAULT 100,
    
    -- Status
    status VARCHAR(20) DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED')),
    
    -- Progress tracking
    total_records INTEGER,
    processed_records INTEGER DEFAULT 0,
    failed_records INTEGER DEFAULT 0,
    
    -- Error handling
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    
    -- Timestamps
    scheduled_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    
    -- Audit
    requested_by UUID,
    approved_by UUID
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Key registry indexes
CREATE INDEX idx_encryption_keys_status ON core.encryption_keys(key_status, key_type) 
    WHERE key_status IN ('ACTIVE', 'ROTATING');
CREATE INDEX idx_encryption_keys_level ON core.encryption_keys(key_level, key_status);
CREATE INDEX idx_encryption_keys_expiry ON core.encryption_keys(expires_at) 
    WHERE key_status = 'ACTIVE' AND expires_at IS NOT NULL;
CREATE INDEX idx_encryption_keys_rotation ON core.encryption_keys(rotated_at, rotation_period) 
    WHERE auto_rotate = TRUE AND key_status = 'ACTIVE';

-- Access log indexes
CREATE INDEX idx_key_access_log_key ON core.key_access_log(key_id, accessed_at DESC);
CREATE INDEX idx_key_access_log_time ON core.key_access_log(accessed_at DESC);
CREATE INDEX idx_key_access_log_denied ON core.key_access_log(access_granted, accessed_at) 
    WHERE access_granted = FALSE;

-- Rotation queue indexes
CREATE INDEX idx_key_rotation_queue_status ON core.key_rotation_queue(status, priority, scheduled_at) 
    WHERE status = 'PENDING';

-- =============================================================================
-- IMMUTABILITY TRIGGERS (for key registry)
-- =============================================================================

-- Key registry is append-only for audit, but status can change
-- Use versioning instead of updates for critical fields

-- Key access log is fully immutable
CREATE TRIGGER trg_key_access_log_prevent_update
    BEFORE UPDATE ON core.key_access_log
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_key_access_log_prevent_delete
    BEFORE DELETE ON core.key_access_log
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

ALTER TABLE core.encryption_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.key_access_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.key_rotation_queue ENABLE ROW LEVEL SECURITY;

-- Only kernel role can access keys directly
CREATE POLICY encryption_keys_kernel ON core.encryption_keys
    FOR ALL TO ussd_kernel_role USING (true);

CREATE POLICY key_access_log_kernel ON core.key_access_log
    FOR ALL TO ussd_kernel_role USING (true);

CREATE POLICY key_rotation_queue_kernel ON core.key_rotation_queue
    FOR ALL TO ussd_kernel_role USING (true);

-- =============================================================================
-- KEY MANAGEMENT FUNCTIONS
-- =============================================================================

-- Function to generate new key
CREATE OR REPLACE FUNCTION core.generate_encryption_key(
    p_key_type VARCHAR,
    p_key_level INTEGER,
    p_key_purpose TEXT,
    p_parent_key_id UUID DEFAULT NULL,
    p_created_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_key_id UUID;
    v_reference VARCHAR(100);
    v_key_material BYTEA;
    v_encrypted_material BYTEA;
    v_checksum VARCHAR(64);
    v_parent_key BYTEA;
BEGIN
    -- Generate key reference
    v_reference := 'KEY-' || p_key_type || '-' || TO_CHAR(core.precise_now(), 'YYYYMMDD-HH24MISS') || '-' ||
                   SUBSTRING(MD5(RANDOM()::TEXT), 1, 6);
    
    -- Generate key material using pgcrypto
    v_key_material := gen_random_bytes(32);  -- 256-bit key
    
    -- Calculate checksum
    v_checksum := encode(digest(v_key_material, 'sha256'), 'hex');
    
    -- Encrypt with parent key if provided
    IF p_parent_key_id IS NOT NULL THEN
        SELECT encrypted_key_material INTO v_parent_key
        FROM core.encryption_keys WHERE key_id = p_parent_key_id;
        
        -- In real implementation, decrypt parent key first, then encrypt new key
        -- This is a simplified version
        v_encrypted_material := pgp_sym_encrypt(v_key_material, 'parent-key-placeholder');
    ELSE
        -- For master keys, use HSM or Vault integration
        -- This is a placeholder - real implementation would call external HSM
        v_encrypted_material := pgp_sym_encrypt(v_key_material, 'hsm-protected-master');
    END IF;
    
    -- Insert key record
    INSERT INTO core.encryption_keys (
        key_reference,
        key_level,
        key_type,
        key_purpose,
        parent_key_id,
        encrypted_key_material,
        key_checksum,
        created_by
    ) VALUES (
        v_reference,
        p_key_level,
        p_key_type,
        p_key_purpose,
        p_parent_key_id,
        v_encrypted_material,
        v_checksum,
        p_created_by
    )
    RETURNING key_id INTO v_key_id;
    
    -- Log key creation
    INSERT INTO core.key_access_log (
        key_id, access_type, access_reason, accessed_by, access_granted
    ) VALUES (
        v_key_id, 'CREATE', 'Key generation', p_created_by, TRUE
    );
    
    RETURN v_key_id;
END;
$$;

-- Function to retrieve key (with audit)
CREATE OR REPLACE FUNCTION core.retrieve_key(
    p_key_id UUID,
    p_reason TEXT,
    p_accessed_by UUID DEFAULT NULL,
    p_session_id TEXT DEFAULT NULL,
    p_client_ip INET DEFAULT NULL
)
RETURNS BYTEA
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_key_record RECORD;
    v_decrypted_key BYTEA;
    v_access_granted BOOLEAN := FALSE;
    v_denial_reason TEXT := NULL;
BEGIN
    -- Get key record
    SELECT * INTO v_key_record
    FROM core.encryption_keys
    WHERE key_id = p_key_id;
    
    -- Check if key exists and is active
    IF NOT FOUND THEN
        v_denial_reason := 'Key not found';
    ELSIF v_key_record.key_status != 'ACTIVE' THEN
        v_denial_reason := 'Key not active: ' || v_key_record.key_status;
    ELSIF v_key_record.expires_at IS NOT NULL AND v_key_record.expires_at < core.precise_now() THEN
        v_denial_reason := 'Key expired';
    ELSE
        v_access_granted := TRUE;
    END IF;
    
    -- Log access attempt
    INSERT INTO core.key_access_log (
        key_id, access_type, access_reason, accessed_by, session_id, client_ip,
        access_granted, denial_reason
    ) VALUES (
        p_key_id, 'USE', p_reason, p_accessed_by, p_session_id, p_client_ip,
        v_access_granted, v_denial_reason
    );
    
    -- Update access stats
    IF v_access_granted THEN
        UPDATE core.encryption_keys SET
            access_count = access_count + 1,
            last_accessed_at = core.precise_now(),
            last_accessed_by = p_accessed_by,
            last_access_reason = p_reason
        WHERE key_id = p_key_id;
        
        -- In real implementation, decrypt and return key
        -- This is a placeholder
        RETURN v_key_record.encrypted_key_material;
    ELSE
        RAISE EXCEPTION 'Key access denied: %', v_denial_reason;
    END IF;
END;
$$;

-- Function to schedule key rotation
CREATE OR REPLACE FUNCTION core.schedule_key_rotation(
    p_key_id UUID,
    p_rotation_type VARCHAR DEFAULT 'SCHEDULED',
    p_scheduled_at TIMESTAMPTZ DEFAULT NULL,
    p_requested_by UUID DEFAULT NULL,
    p_priority INTEGER DEFAULT 100
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_queue_id UUID;
BEGIN
    INSERT INTO core.key_rotation_queue (
        key_id,
        rotation_type,
        priority,
        scheduled_at,
        requested_by
    ) VALUES (
        p_key_id,
        p_rotation_type,
        p_priority,
        COALESCE(p_scheduled_at, core.precise_now()),
        p_requested_by
    )
    RETURNING queue_id INTO v_queue_id;
    
    -- Update key status
    UPDATE core.encryption_keys 
    SET key_status = 'ROTATING',
        rotated_by = p_requested_by
    WHERE key_id = p_key_id;
    
    RETURN v_queue_id;
END;
$$;

-- Function to execute key rotation
CREATE OR REPLACE FUNCTION core.execute_key_rotation(
    p_queue_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_queue RECORD;
    v_old_key RECORD;
    v_new_key_id UUID;
    v_affected_count INTEGER := 0;
BEGIN
    SELECT * INTO v_queue FROM core.key_rotation_queue WHERE queue_id = p_queue_id;
    SELECT * INTO v_old_key FROM core.encryption_keys WHERE key_id = v_queue.key_id;
    
    -- Mark rotation as started
    UPDATE core.key_rotation_queue SET
        status = 'IN_PROGRESS',
        started_at = core.precise_now()
    WHERE queue_id = p_queue_id;
    
    -- Generate new key version
    v_new_key_id := core.generate_encryption_key(
        v_old_key.key_type,
        v_old_key.key_level,
        v_old_key.key_purpose,
        v_old_key.parent_key_id,
        v_queue.requested_by
    );
    
    -- Update new key with rotation info
    UPDATE core.encryption_keys SET
        replaces_key_id = v_old_key.key_id,
        key_version = v_old_key.key_version + 1
    WHERE key_id = v_new_key_id;
    
    -- Re-encrypt data (simplified - in production this would iterate through all encrypted data)
    -- This is application-specific and would typically be done in batches
    
    -- Mark old key as deprecated
    UPDATE core.encryption_keys SET
        key_status = 'DEPRECATED',
        rotated_at = core.precise_now(),
        rotated_by = v_queue.requested_by
    WHERE key_id = v_old_key.key_id;
    
    -- Complete rotation
    UPDATE core.key_rotation_queue SET
        status = 'COMPLETED',
        completed_at = core.precise_now(),
        processed_records = v_affected_count
    WHERE queue_id = p_queue_id;
    
    RETURN TRUE;
EXCEPTION
    WHEN OTHERS THEN
        UPDATE core.key_rotation_queue SET
            status = 'FAILED',
            error_message = SQLERRM,
            retry_count = retry_count + 1
        WHERE queue_id = p_queue_id;
        RETURN FALSE;
END;
$$;

-- Function to handle compromised key
CREATE OR REPLACE FUNCTION core.compromise_key(
    p_key_id UUID,
    p_reason TEXT,
    p_detected_by UUID DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    -- Mark key as compromised
    UPDATE core.encryption_keys SET
        key_status = 'COMPROMISED',
        compromise_detected_at = core.precise_now(),
        compromise_reason = p_reason
    WHERE key_id = p_key_id;
    
    -- Log the compromise
    INSERT INTO core.key_access_log (
        key_id, access_type, access_reason, accessed_by, access_granted
    ) VALUES (
        p_key_id, 'DESTROY', 'Key compromise: ' || p_reason, p_detected_by, TRUE
    );
    
    -- Trigger emergency rotation
    PERFORM core.schedule_key_rotation(
        p_key_id,
        'EMERGENCY',
        core.precise_now(),
        p_detected_by,
        1  -- Highest priority
    );
    
    RETURN TRUE;
END;
$$;

-- =============================================================================
-- KEY ROTATION MAINTENANCE PROCEDURE
-- =============================================================================

CREATE OR REPLACE PROCEDURE core.run_key_rotation_maintenance()
LANGUAGE plpgsql
AS $$
DECLARE
    v_key RECORD;
    v_queue_id UUID;
BEGIN
    -- Find keys due for rotation
    FOR v_key IN 
        SELECT key_id
        FROM core.encryption_keys
        WHERE key_status = 'ACTIVE'
          AND auto_rotate = TRUE
          AND (
              rotated_at IS NULL 
              OR rotated_at + rotation_period < core.precise_now()
          )
    LOOP
        -- Check if already in queue
        IF NOT EXISTS (
            SELECT 1 FROM core.key_rotation_queue 
            WHERE key_id = v_key.key_id 
            AND status IN ('PENDING', 'IN_PROGRESS')
        ) THEN
            v_queue_id := core.schedule_key_rotation(
                v_key.key_id,
                'SCHEDULED',
                core.precise_now() + INTERVAL '1 hour',
                NULL
            );
            
            RAISE NOTICE 'Scheduled rotation for key %, queue_id=%', v_key.key_id, v_queue_id;
        END IF;
    END LOOP;
END;
$$;

-- =============================================================================
-- INITIAL KEY GENERATION
-- =============================================================================

DO $$
DECLARE
    v_master_key UUID;
    v_kek_id UUID;
BEGIN
    -- Generate master key (L1) if not exists
    IF NOT EXISTS (SELECT 1 FROM core.encryption_keys WHERE key_level = 1 AND key_status = 'ACTIVE') THEN
        v_master_key := core.generate_encryption_key(
            'MASTER',
            1,
            'Master encryption key for kernel',
            NULL,
            NULL
        );
        
        RAISE NOTICE 'Generated master key: %', v_master_key;
        
        -- Generate KEK (L2)
        v_kek_id := core.generate_encryption_key(
            'KEK',
            2,
            'Key encryption key for data keys',
            v_master_key,
            NULL
        );
        
        RAISE NOTICE 'Generated KEK: %', v_kek_id;
    END IF;
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE core.encryption_keys IS 
    'Registry of all encryption keys with hierarchical key management';
COMMENT ON TABLE core.key_access_log IS 
    'Immutable audit log of all key access operations';
COMMENT ON FUNCTION core.generate_encryption_key IS 
    'Generate new encryption key with secure random material';
COMMENT ON FUNCTION core.compromise_key IS 
    'Emergency procedure for compromised key handling';

-- =============================================================================
-- END OF FILE
-- =============================================================================
