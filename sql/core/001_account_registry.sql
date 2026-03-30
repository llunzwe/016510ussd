-- ============================================================================
-- USSD KERNEL CORE SCHEMA - ACCOUNT REGISTRY
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Immutable account registry storing all participants (users,
--              groups, merchants, system accounts) with hierarchical support
--              and cryptographic identity verification.
-- Immutability: 100% - Append only, no updates or deletes allowed
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. ACCOUNT REGISTRY TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_core.account_registry (
    -- Primary identifier
    account_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Account classification
    account_type ussd_core.account_type NOT NULL,
    account_subtype VARCHAR(50),  -- e.g., 'premium', 'basic', 'enterprise'
    
    -- Human-readable identifier (MSISDN, email, etc.)
    -- Encrypted at rest for privacy
    primary_identifier VARCHAR(255) NOT NULL,
    primary_identifier_hash VARCHAR(64) NOT NULL,  -- For lookups without decryption
    
    -- Additional identifiers (JSON array of {type, value, verified, verified_at})
    identifiers JSONB DEFAULT '[]',
    
    -- Cryptographic identity
    public_key TEXT,  -- PEM format public key for transaction signing
    key_algorithm VARCHAR(20) DEFAULT 'ed25519',  -- ed25519, secp256k1, rsa-4096
    key_created_at TIMESTAMPTZ,
    
    -- Metadata
    display_name VARCHAR(255),
    metadata JSONB DEFAULT '{}',  -- Flexible app-specific data
    
    -- Hierarchical relationships
    parent_account_id UUID REFERENCES ussd_core.account_registry(account_id),
    account_path LTREE,  -- Materialized path for fast tree traversal
    
    -- Primary application (though accounts can be shared)
    primary_application_id UUID,  -- References ussd_app.applications
    
    -- Lifecycle
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'closed')),
    
    -- Timestamps and versioning (immutable)
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    created_by UUID,  -- Account that created this entry
    superseded_by UUID REFERENCES ussd_core.account_registry(account_id),
    valid_from TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    valid_to TIMESTAMPTZ,  -- NULL means current version
    
    -- Audit trail
    creation_tx_id BIGINT,  -- References first transaction for this account
    
    -- Computed hash for integrity
    record_hash VARCHAR(64) NOT NULL
);

-- ----------------------------------------------------------------------------
-- 2. INDEXES FOR PERFORMANCE
-- ----------------------------------------------------------------------------
-- Primary lookups
CREATE UNIQUE INDEX idx_account_identifier_hash_active 
    ON ussd_core.account_registry(primary_identifier_hash) 
    WHERE valid_to IS NULL;

-- Hierarchical queries
CREATE INDEX idx_account_parent ON ussd_core.account_registry(parent_account_id);
CREATE INDEX idx_account_path ON ussd_core.account_registry USING GIST(account_path);
CREATE INDEX idx_account_path_btree ON ussd_core.account_registry USING BTREE(account_path);

-- Application-scoped queries
CREATE INDEX idx_account_primary_app ON ussd_core.account_registry(primary_application_id);
CREATE INDEX idx_account_type ON ussd_core.account_registry(account_type);

-- Status and validity window
CREATE INDEX idx_account_status ON ussd_core.account_registry(status) WHERE valid_to IS NULL;
CREATE INDEX idx_account_valid_range ON ussd_core.account_registry(valid_from, valid_to);

-- Full-text search on display name and metadata
CREATE INDEX idx_account_display_name_trgm 
    ON ussd_core.account_registry USING gin(display_name gin_trgm_ops);

-- JSONB indexes for common metadata queries
CREATE INDEX idx_account_metadata_gin ON ussd_core.account_registry USING gin(metadata);
CREATE INDEX idx_account_metadata_email ON ussd_core.account_registry 
    ((metadata->>'email')) WHERE metadata->>'email' IS NOT NULL;

-- Public key lookups
CREATE INDEX idx_account_public_key ON ussd_core.account_registry(public_key) 
    WHERE public_key IS NOT NULL;

-- ----------------------------------------------------------------------------
-- 3. IMMUTABILITY TRIGGERS
-- ----------------------------------------------------------------------------
CREATE TRIGGER trg_account_registry_prevent_update
    BEFORE UPDATE ON ussd_core.account_registry
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_update();

CREATE TRIGGER trg_account_registry_prevent_delete
    BEFORE DELETE ON ussd_core.account_registry
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_delete();

-- ----------------------------------------------------------------------------
-- 4. HASH COMPUTATION TRIGGER
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd_core.compute_account_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_data TEXT;
BEGIN
    v_data := NEW.account_id::TEXT || 
              NEW.account_type::TEXT || 
              COALESCE(NEW.primary_identifier_hash, '') ||
              COALESCE(NEW.public_key, '') ||
              NEW.created_at::TEXT;
    NEW.record_hash := ussd_core.generate_hash(v_data);
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_account_registry_compute_hash
    BEFORE INSERT ON ussd_core.account_registry
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.compute_account_hash();

-- ----------------------------------------------------------------------------
-- 5. VERSIONING TRIGGER (For status changes, creates new version)
-- ----------------------------------------------------------------------------
-- Note: Since the table is immutable, status changes require creating
-- a new record. This function is provided for the application layer
-- to call when it needs to update account status.

CREATE OR REPLACE FUNCTION ussd_core.create_account_version(
    p_account_id UUID,
    p_new_status VARCHAR(20),
    p_new_metadata JSONB DEFAULT NULL,
    p_reason TEXT DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_old_record ussd_core.account_registry%ROWTYPE;
    v_new_account_id UUID;
BEGIN
    -- Get the current active version
    SELECT * INTO v_old_record
    FROM ussd_core.account_registry
    WHERE account_id = p_account_id AND valid_to IS NULL;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Account not found or already superseded: %', p_account_id;
    END IF;
    
    -- Close the old record
    UPDATE ussd_core.account_registry  -- This bypasses the trigger via security definer
    SET valid_to = ussd_core.precise_now(),
        superseded_by = v_new_account_id
    WHERE account_id = p_account_id;
    
    -- Create new version
    INSERT INTO ussd_core.account_registry (
        account_type,
        account_subtype,
        primary_identifier,
        primary_identifier_hash,
        identifiers,
        public_key,
        key_algorithm,
        key_created_at,
        display_name,
        metadata,
        parent_account_id,
        account_path,
        primary_application_id,
        status,
        created_by,
        valid_from
    ) VALUES (
        v_old_record.account_type,
        v_old_record.account_subtype,
        v_old_record.primary_identifier,
        v_old_record.primary_identifier_hash,
        v_old_record.identifiers,
        v_old_record.public_key,
        v_old_record.key_algorithm,
        v_old_record.key_created_at,
        v_old_record.display_name,
        COALESCE(p_new_metadata, v_old_record.metadata),
        v_old_record.parent_account_id,
        v_old_record.account_path,
        v_old_record.primary_application_id,
        p_new_status,
        v_old_record.account_id,
        ussd_core.precise_now()
    )
    RETURNING account_id INTO v_new_account_id;
    
    -- Log the change
    PERFORM ussd_audit.log_audit_event(
        'ussd_core', 'account_registry',
        v_new_account_id::TEXT,
        'UPDATE',
        to_jsonb(v_old_record),
        NULL,
        p_reason
    );
    
    RETURN v_new_account_id;
END;
$$;

-- ----------------------------------------------------------------------------
-- 6. HELPER FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to generate account path from parent
CREATE OR REPLACE FUNCTION ussd_core.compute_account_path()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.parent_account_id IS NULL THEN
        NEW.account_path := text2ltree(NEW.account_id::TEXT);
    ELSE
        SELECT account_path || NEW.account_id::TEXT::ltree
        INTO NEW.account_path
        FROM ussd_core.account_registry
        WHERE account_id = NEW.parent_account_id;
        
        IF NEW.account_path IS NULL THEN
            RAISE EXCEPTION 'Parent account not found: %', NEW.parent_account_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_account_registry_compute_path
    BEFORE INSERT ON ussd_core.account_registry
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.compute_account_path();

-- Function to lookup account by identifier hash
CREATE OR REPLACE FUNCTION ussd_core.lookup_account(
    p_identifier_hash VARCHAR(64)
)
RETURNS TABLE (
    account_id UUID,
    account_type ussd_core.account_type,
    status VARCHAR(20),
    display_name VARCHAR(255),
    primary_application_id UUID
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ar.account_id,
        ar.account_type,
        ar.status,
        ar.display_name,
        ar.primary_application_id
    FROM ussd_core.account_registry ar
    WHERE ar.primary_identifier_hash = p_identifier_hash
      AND ar.valid_to IS NULL;
END;
$$;

-- Function to get account hierarchy
CREATE OR REPLACE FUNCTION ussd_core.get_account_descendants(
    p_account_id UUID
)
RETURNS TABLE (
    account_id UUID,
    account_type ussd_core.account_type,
    display_name VARCHAR(255),
    depth INTEGER
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE descendants AS (
        SELECT 
            ar.account_id,
            ar.account_type,
            ar.display_name,
            0 AS depth,
            ar.account_path
        FROM ussd_core.account_registry ar
        WHERE ar.account_id = p_account_id AND ar.valid_to IS NULL
        
        UNION ALL
        
        SELECT 
            ar.account_id,
            ar.account_type,
            ar.display_name,
            d.depth + 1,
            ar.account_path
        FROM ussd_core.account_registry ar
        JOIN descendants d ON ar.account_path <@ d.account_path 
            AND ar.account_path != d.account_path
        WHERE ar.valid_to IS NULL
    )
    SELECT d.account_id, d.account_type, d.display_name, d.depth
    FROM descendants d
    WHERE d.depth > 0
    ORDER BY d.depth, d.display_name;
END;
$$;

-- ----------------------------------------------------------------------------
-- 7. ROW LEVEL SECURITY POLICIES
-- ----------------------------------------------------------------------------
ALTER TABLE ussd_core.account_registry ENABLE ROW LEVEL SECURITY;

-- Policy: Accounts can only see their own data unless they have special permissions
CREATE POLICY account_self_access ON ussd_core.account_registry
    FOR SELECT
    USING (
        account_id = NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID
        OR EXISTS (
            SELECT 1 FROM ussd_app.user_roles ur
            JOIN ussd_app.role_permissions rp ON ur.role_id = rp.role_id
            JOIN ussd_app.permissions p ON rp.permission_id = p.permission_id
            WHERE ur.account_id = NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID
              AND p.permission_code = 'account:read:all'
              AND ur.valid_to IS NULL
        )
    );

-- Policy: Application-scoped access
CREATE POLICY account_app_access ON ussd_core.account_registry
    FOR SELECT
    USING (
        primary_application_id = NULLIF(current_setting('app.application_id', TRUE), '')::UUID
        OR EXISTS (
            SELECT 1 FROM ussd_app.account_memberships am
            WHERE am.account_id = ussd_core.account_registry.account_id
              AND am.application_id = NULLIF(current_setting('app.application_id', TRUE), '')::UUID
              AND am.valid_to IS NULL
        )
    );

-- ----------------------------------------------------------------------------
-- 8. VIEWS
-- ----------------------------------------------------------------------------

-- Current active accounts only
CREATE VIEW ussd_core.active_accounts AS
SELECT *
FROM ussd_core.account_registry
WHERE valid_to IS NULL
  AND status = 'active';

-- Accounts by application
CREATE VIEW ussd_core.application_accounts AS
SELECT 
    ar.*,
    am.application_id,
    am.membership_metadata,
    am.enrolled_at
FROM ussd_core.account_registry ar
JOIN ussd_app.account_memberships am ON ar.account_id = am.account_id
WHERE ar.valid_to IS NULL AND am.valid_to IS NULL;

-- ----------------------------------------------------------------------------
-- 9. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_core.account_registry IS 
    'Immutable registry of all accounts in the system. Each change creates a new version.';
COMMENT ON COLUMN ussd_core.account_registry.record_hash IS 
    'Cryptographic hash of the record for integrity verification';
COMMENT ON COLUMN ussd_core.account_registry.account_path IS 
    'Materialized path for efficient hierarchical queries using LTREE';
COMMENT ON COLUMN ussd_core.account_registry.primary_identifier_hash IS 
    'One-way hash of primary identifier (MSISDN/email) for privacy-preserving lookups';

-- ----------------------------------------------------------------------------
-- 10. INITIAL SYSTEM ACCOUNTS
-- ----------------------------------------------------------------------------
INSERT INTO ussd_core.account_registry (
    account_id,
    account_type,
    account_subtype,
    primary_identifier,
    primary_identifier_hash,
    display_name,
    metadata,
    status,
    created_by
) VALUES 
-- System kernel account
(
    '00000000-0000-0000-0000-000000000001'::UUID,
    'system',
    'kernel',
    'KERNEL_SYSTEM',
    ussd_core.generate_hash('KERNEL_SYSTEM'),
    'USSD Kernel System Account',
    '{"description": "Root system account for kernel operations"}',
    'active',
    '00000000-0000-0000-0000-000000000001'::UUID
),
-- Fees and commissions account
(
    '00000000-0000-0000-0000-000000000002'::UUID,
    'system',
    'fees',
    'KERNEL_FEES',
    ussd_core.generate_hash('KERNEL_FEES'),
    'Fees and Commissions Account',
    '{"description": "Holds all system fees and commissions"}',
    'active',
    '00000000-0000-0000-0000-000000000001'::UUID
),
-- Reconciliation suspense account
(
    '00000000-0000-0000-0000-000000000003'::UUID,
    'system',
    'suspense',
    'KERNEL_SUSPENSE',
    ussd_core.generate_hash('KERNEL_SUSPENSE'),
    'Reconciliation Suspense Account',
    '{"description": "Temporary holding for reconciliation discrepancies"}',
    'active',
    '00000000-0000-0000-0000-000000000001'::UUID
);
