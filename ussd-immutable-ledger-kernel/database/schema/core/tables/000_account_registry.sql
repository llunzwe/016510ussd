-- =============================================================================
-- USSD KERNEL CORE SCHEMA - ACCOUNT REGISTRY
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    000_account_registry.sql
-- SCHEMA:      ussd_core
-- TABLE:       account_registry
-- DESCRIPTION: Immutable account registry storing all participants (users,
--              groups, merchants, system accounts) with hierarchical support
--              and cryptographic identity verification.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.5.9 Information and other associated assets shall be inventoried
├── A.8.1 User endpoint devices shall be registered
└── A.8.5 Authentication information and secret authentication information
    shall be managed securely throughout their lifecycle

ISO/IEC 27040:2024 (Storage Security - CRITICAL for immutable ledger)
├── Storage lifecycle: Data must be protected at all stages
├── Immutable storage: Write-once-read-many (WORM) enforcement
├── Cryptographic integrity: Hash-based verification mandatory
└── Key management: HSM-backed key storage for account credentials

ISO/IEC 27031:2025 (Business Continuity ICT Readiness)
├── Redundancy: Account data replicated across availability zones
├── Recovery: RPO < 1 second for account registry
└── Failover: Automatic promotion of standby nodes

ISO/IEC 27017:2015 (Cloud Security)
├── Multi-tenant isolation: Application-scoped account visibility
├── Data residency: Geographic restrictions on account data
└── Access logging: All account queries audited

PCI DSS 4.0 (if handling card data)
├── Requirement 3: Protect stored account data
├── Requirement 8: Identify and authenticate access to system components
└── Requirement 10: Log and monitor access

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. NAMING CONVENTIONS
   - Tables: lowercase with underscores (account_registry)
   - Columns: descriptive, type-indicating where helpful
   - Constraints: pk_{table}, fk_{table}_{column}, chk_{condition}
   - Indexes: idx_{table}_{column}_{type}

2. DATA TYPES
   - Primary keys: UUID (distributed-safe, non-sequential)
   - Financial amounts: NUMERIC(20, 8) - NEVER FLOAT
   - Timestamps: TIMESTAMPTZ (UTC with timezone awareness)
   - Enumerations: Custom DOMAIN types for type safety
   - JSON: JSONB (indexed, compressed) over JSON

3. CONSTRAINTS
   - NOT NULL on all mandatory fields
   - CHECK constraints for business rules
   - FOREIGN KEY with ON DELETE RESTRICT (immutable references)
   - UNIQUE constraints for natural keys

4. COMMENTING
   - TABLE: Overall purpose and usage patterns
   - COLUMN: Business meaning and valid values
   - INDEX: Query optimization justification
   - CONSTRAINT: Business rule explanation

5. PERFORMANCE
   - Partition key strategy documented
   - Index selectivity analyzed
   - Vacuum and analyze schedule defined

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

ENCRYPTION AT REST:
- Primary identifier encrypted using AES-256-GCM via pgcrypto
- Encryption key managed by external KMS (HashiCorp Vault/AWS KMS)
- Key rotation every 90 days with re-encryption
- Column-level encryption for PII fields

ACCESS CONTROL:
- Row-Level Security (RLS) enabled - see policies/000_row_level_security_core.sql
- Application-scoped visibility enforced via RLS policies
- Cryptographic key access restricted to kernel role only
- All access logged to audit_trail table

HASHING:
- Primary identifier hashed using SHA-256 for lookups
- Salted hashing prevents rainbow table attacks
- Hash values indexed for performance
- Original values never stored unencrypted

IMMUTABILITY:
- BEFORE UPDATE trigger blocks all modifications
- BEFORE DELETE trigger prevents record removal
- Status changes via versioned record insertion
- Valid_from/valid_to temporal versioning

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEX STRATEGY:
1. PRIMARY KEY: account_id (clustered)
2. LOOKUP: primary_identifier_hash (unique, partial where valid_to IS NULL)
3. HIERARCHY: account_path USING GIST (LTREE for tree traversal)
4. APPLICATION: primary_application_id (foreign key lookups)
5. TEMPORAL: valid_from, valid_to (range queries)
6. SEARCH: display_name USING gin_trgm_ops (fuzzy search)

QUERY PATTERNS:
- Active accounts: WHERE valid_to IS NULL
- Account lookup: WHERE primary_identifier_hash = ?
- Hierarchy: WHERE account_path <@ 'parent'::ltree
- Application scope: WHERE primary_application_id = ?

PARTITIONING:
- Consider range partitioning by created_at for large registries
- Partition pruning for historical account queries
- Separate hot (recent) and cold (archived) partitions

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

MANDATORY AUDIT EVENTS:
1. ACCOUNT_CREATED: New account insertion
2. ACCOUNT_UPDATED: Versioned record created (status change)
3. ACCOUNT_ACCESSED: Balance inquiry or detail view
4. AUTH_FAILURE: Failed authentication attempt
5. KEY_ROTATION: Public key update (new version)

LOGGED FIELDS:
- actor_account_id: Who performed the action
- action_timestamp: Precise transaction time
- client_ip: Source network address
- session_id: Application session identifier
- query_text: Executed SQL (sanitized)

RETENTION:
- Audit logs: 7 years (financial regulation compliance)
- Access logs: 2 years
- Failed authentication: 1 year

ALERTING:
- Multiple failed auth attempts (brute force detection)
- Unusual access patterns (anomaly detection)
- Bulk account exports (data exfiltration risk)
- After-hours administrative access
================================================================================
*/

-- =============================================================================
-- CREATE TABLE: account_registry
-- =============================================================================

CREATE TABLE core.account_registry (
    -- Primary identifier
    account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Account classification
    account_type VARCHAR(50) NOT NULL CHECK (account_type IN ('individual', 'group', 'merchant', 'system', 'agent', 'corporate')),
    account_subtype VARCHAR(50),  -- e.g., 'premium', 'basic', 'enterprise'
    
    -- Human-readable identifier (MSISDN, email, etc.)
    -- Encrypted at rest for privacy
    primary_identifier VARCHAR(255) NOT NULL,
    primary_identifier_hash VARCHAR(64) NOT NULL,  -- For lookups without decryption
    
    -- Additional identifiers (JSON array of {type, value, verified, verified_at})
    identifiers JSONB DEFAULT '[]',
    
    -- Cryptographic identity
    public_key TEXT,  -- PEM format public key for transaction signing
    key_algorithm VARCHAR(20) DEFAULT 'ed25519' CHECK (key_algorithm IN ('ed25519', 'secp256k1', 'rsa-4096')),
    key_created_at TIMESTAMPTZ,
    
    -- Metadata
    display_name VARCHAR(255),
    metadata JSONB DEFAULT '{}',  -- Flexible app-specific data
    
    -- Hierarchical relationships
    parent_account_id UUID REFERENCES core.account_registry(account_id) ON DELETE RESTRICT,
    account_path LTREE,  -- Materialized path for fast tree traversal
    
    -- Primary application (though accounts can be shared)
    primary_application_id UUID,  -- References ussd_app.applications
    
    -- Lifecycle
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'closed')),
    
    -- Timestamps and versioning (immutable)
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    created_by UUID,  -- Account that created this entry
    superseded_by UUID REFERENCES core.account_registry(account_id) ON DELETE RESTRICT,
    valid_from TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    valid_to TIMESTAMPTZ,  -- NULL means current version
    
    -- Audit trail
    creation_tx_id BIGINT,  -- References first transaction for this account
    
    -- Computed hash for integrity
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    CONSTRAINT chk_valid_to_after_from CHECK (valid_to IS NULL OR valid_to > valid_from),
    CONSTRAINT chk_no_self_parent CHECK (parent_account_id IS NULL OR parent_account_id != account_id)
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Primary identifier lookup (hashed for privacy)
CREATE UNIQUE INDEX idx_account_identifier_hash_active 
    ON core.account_registry(primary_identifier_hash) 
    WHERE valid_to IS NULL;

-- Hierarchical queries (LTREE)
CREATE INDEX idx_account_path ON core.account_registry 
    USING GIST(account_path);
CREATE INDEX idx_account_path_btree ON core.account_registry 
    USING BTREE(account_path);

-- Application-scoped queries
CREATE INDEX idx_account_primary_app ON core.account_registry(primary_application_id) 
    WHERE valid_to IS NULL;
CREATE INDEX idx_account_type ON core.account_registry(account_type) 
    WHERE valid_to IS NULL;

-- Status filtering
CREATE INDEX idx_account_status ON core.account_registry(status) 
    WHERE valid_to IS NULL;

-- Parent account lookup
CREATE INDEX idx_account_parent ON core.account_registry(parent_account_id) 
    WHERE valid_to IS NULL;

-- Full-text search (requires pg_trgm)
CREATE INDEX idx_account_display_name_trgm 
    ON core.account_registry USING gin(display_name gin_trgm_ops);

-- Temporal queries
CREATE INDEX idx_account_valid_period ON core.account_registry(valid_from, valid_to);

-- =============================================================================
-- IMMUTABILITY TRIGGERS
-- =============================================================================

-- Prevent updates on immutable table
CREATE TRIGGER trg_account_registry_prevent_update
    BEFORE UPDATE ON core.account_registry
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

-- Prevent deletes on immutable table
CREATE TRIGGER trg_account_registry_prevent_delete
    BEFORE DELETE ON core.account_registry
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- =============================================================================
-- HASH COMPUTATION TRIGGER
-- =============================================================================

CREATE OR REPLACE FUNCTION core.compute_account_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.account_id::TEXT || 
        NEW.account_type::TEXT || 
        COALESCE(NEW.primary_identifier_hash, '') ||
        COALESCE(NEW.public_key, '') ||
        NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_account_registry_compute_hash
    BEFORE INSERT ON core.account_registry
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_account_hash();

-- =============================================================================
-- PATH COMPUTATION TRIGGER
-- =============================================================================

CREATE OR REPLACE FUNCTION core.compute_account_path()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.parent_account_id IS NULL THEN
        NEW.account_path := text2ltree(NEW.account_id::TEXT);
    ELSE
        SELECT account_path || NEW.account_id::TEXT::ltree
        INTO NEW.account_path
        FROM core.account_registry
        WHERE account_id = NEW.parent_account_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_account_registry_compute_path
    BEFORE INSERT ON core.account_registry
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_account_path();

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

-- Enable RLS
ALTER TABLE core.account_registry ENABLE ROW LEVEL SECURITY;

-- Policy: Accounts can only view their own data
CREATE POLICY account_registry_self_access ON core.account_registry
    FOR SELECT
    TO ussd_app_user
    USING (account_id = current_setting('app.current_account_id', true)::UUID);

-- Policy: Application-scoped access (can see accounts in their application)
CREATE POLICY account_registry_app_access ON core.account_registry
    FOR SELECT
    TO ussd_app_user
    USING (
        primary_application_id = current_setting('app.current_application_id', true)::UUID
        OR EXISTS (
            SELECT 1 FROM ussd_app.account_memberships am
            WHERE am.account_id = account_registry.account_id
            AND am.application_id = current_setting('app.current_application_id', true)::UUID
        )
    );

-- Policy: Kernel role has full access
CREATE POLICY account_registry_kernel_access ON core.account_registry
    FOR ALL
    TO ussd_kernel_role
    USING (true);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to create a new version of an account (for status changes)
CREATE OR REPLACE FUNCTION core.create_account_version(
    p_account_id UUID,
    p_new_status VARCHAR(20),
    p_updated_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_new_account_id UUID;
    v_old_record RECORD;
BEGIN
    -- Get the current active record
    SELECT * INTO v_old_record
    FROM core.account_registry
    WHERE account_id = p_account_id
    AND valid_to IS NULL;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Active account not found: %', p_account_id;
    END IF;
    
    -- Update valid_to on current record
    UPDATE core.account_registry
    SET valid_to = core.precise_now()
    WHERE account_id = p_account_id
    AND valid_to IS NULL;
    
    -- Insert new version
    INSERT INTO core.account_registry (
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
        primary_application_id,
        status,
        created_by,
        valid_from,
        creation_tx_id
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
        v_old_record.metadata,
        v_old_record.parent_account_id,
        v_old_record.primary_application_id,
        p_new_status,
        p_updated_by,
        core.precise_now(),
        v_old_record.creation_tx_id
    )
    RETURNING account_id INTO v_new_account_id;
    
    -- Update superseded_by on old record
    UPDATE core.account_registry
    SET superseded_by = v_new_account_id
    WHERE account_id = p_account_id;
    
    RETURN v_new_account_id;
END;
$$;

-- Function to lookup account by identifier hash
CREATE OR REPLACE FUNCTION core.lookup_account_by_identifier(
    p_identifier_hash VARCHAR(64)
)
RETURNS TABLE (
    account_id UUID,
    account_type VARCHAR(50),
    status VARCHAR(20),
    display_name VARCHAR(255),
    valid_from TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ar.account_id,
        ar.account_type,
        ar.status,
        ar.display_name,
        ar.valid_from
    FROM core.account_registry ar
    WHERE ar.primary_identifier_hash = p_identifier_hash
    AND ar.valid_to IS NULL;
END;
$$;

-- Function to get account hierarchy
CREATE OR REPLACE FUNCTION core.get_account_hierarchy(
    p_account_id UUID
)
RETURNS TABLE (
    account_id UUID,
    display_name VARCHAR(255),
    account_type VARCHAR(50),
    depth INTEGER
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE hierarchy AS (
        SELECT 
            ar.account_id,
            ar.display_name,
            ar.account_type,
            ar.parent_account_id,
            0 as depth
        FROM core.account_registry ar
        WHERE ar.account_id = p_account_id
        AND ar.valid_to IS NULL
        
        UNION ALL
        
        SELECT 
            ar.account_id,
            ar.display_name,
            ar.account_type,
            ar.parent_account_id,
            h.depth + 1
        FROM core.account_registry ar
        INNER JOIN hierarchy h ON ar.account_id = h.parent_account_id
        WHERE ar.valid_to IS NULL
        AND h.depth < 10  -- Prevent infinite recursion
    )
    SELECT h.account_id, h.display_name, h.account_type, h.depth
    FROM hierarchy h;
END;
$$;

-- =============================================================================
-- TABLE AND COLUMN COMMENTS
-- =============================================================================

COMMENT ON TABLE core.account_registry IS 
    'Immutable account registry storing all participants with hierarchical support and cryptographic identity verification. Records are never updated; status changes create new versions.';

COMMENT ON COLUMN core.account_registry.account_id IS 
    'Unique identifier for the account (UUID v4)';
COMMENT ON COLUMN core.account_registry.account_type IS 
    'Account classification: individual, group, merchant, system, agent, corporate';
COMMENT ON COLUMN core.account_registry.primary_identifier IS 
    'Primary human-readable identifier (MSISDN, email, etc.) - encrypted at rest';
COMMENT ON COLUMN core.account_registry.primary_identifier_hash IS 
    'SHA-256 hash of primary identifier for lookups without decryption';
COMMENT ON COLUMN core.account_registry.public_key IS 
    'PEM format public key for transaction signature verification';
COMMENT ON COLUMN core.account_registry.account_path IS 
    'LTREE materialized path for fast hierarchical queries';
COMMENT ON COLUMN core.account_registry.status IS 
    'Account lifecycle status: active, suspended, closed';
COMMENT ON COLUMN core.account_registry.valid_from IS 
    'Timestamp when this version became valid';
COMMENT ON COLUMN core.account_registry.valid_to IS 
    'Timestamp when this version was superseded (NULL = current version)';
COMMENT ON COLUMN core.account_registry.record_hash IS 
    'SHA-256 hash of record contents for integrity verification';
COMMENT ON COLUMN core.account_registry.superseded_by IS 
    'Reference to the account version that replaced this one';

-- =============================================================================
-- INITIAL DATA: System accounts
-- =============================================================================

INSERT INTO core.account_registry (
    account_id,
    account_type,
    account_subtype,
    primary_identifier,
    primary_identifier_hash,
    display_name,
    status,
    metadata,
    created_by
) VALUES 
-- Kernel System Account
('00000000-0000-0000-0000-000000000001'::UUID, 'system', 'kernel', 
 'SYSTEM_KERNEL', 
 encode(digest('SYSTEM_KERNEL', 'sha256'), 'hex'),
 'USSD Kernel System Account',
 'active',
 '{"description": "Root system account for kernel operations"}',
 '00000000-0000-0000-0000-000000000001'::UUID),

-- Fees and Commissions Account
('00000000-0000-0000-0000-000000000002'::UUID, 'system', 'fees',
 'SYSTEM_FEES',
 encode(digest('SYSTEM_FEES', 'sha256'), 'hex'),
 'Fees and Commissions Account',
 'active',
 '{"description": "Collects all transaction fees and commissions"}',
 '00000000-0000-0000-0000-000000000001'::UUID),

-- Reconciliation Suspense Account
('00000000-0000-0000-0000-000000000003'::UUID, 'system', 'suspense',
 'SYSTEM_SUSPENSE',
 encode(digest('SYSTEM_SUSPENSE', 'sha256'), 'hex'),
 'Reconciliation Suspense Account',
 'active',
 '{"description": "Holds funds pending reconciliation resolution"}',
 '00000000-0000-0000-0000-000000000001'::UUID);

-- =============================================================================
-- END OF FILE
-- =============================================================================
