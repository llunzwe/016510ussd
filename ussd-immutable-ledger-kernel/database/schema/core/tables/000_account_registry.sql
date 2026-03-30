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

-- -----------------------------------------------------------------------------
-- TODO[PRIMARY_KEY]: Define primary key for account_registry
-- -----------------------------------------------------------------------------
-- DECISION NEEDED: Choose between UUID (default) or BIGINT with sequence
-- RECOMMENDATION: UUID PRIMARY KEY DEFAULT uuid_generate_v4()
-- RATIONALE: Global uniqueness for distributed systems, no coordination needed
-- IMPLEMENTATION: 
--   account_id UUID PRIMARY KEY DEFAULT uuid_generate_v4()
--
-- ALTERNATIVE (if strict ordering needed):
--   account_id BIGSERIAL PRIMARY KEY
--   account_uuid UUID UNIQUE DEFAULT uuid_generate_v4()  -- For external refs

-- -----------------------------------------------------------------------------
-- TODO[FOREIGN_KEYS]: Define self-referential hierarchy FK
-- -----------------------------------------------------------------------------
-- parent_account_id UUID REFERENCES ussd_core.account_registry(account_id)
-- CONSTRAINT: Circular reference prevention via trigger or application logic
-- NOTE: LTREE extension must be enabled in 000_setup.sql for account_path

-- -----------------------------------------------------------------------------
-- TODO[INDEXES]: Define performance-critical indexes
-- -----------------------------------------------------------------------------
-- 1. Primary identifier lookup (hashed for privacy):
--    CREATE UNIQUE INDEX idx_account_identifier_hash_active 
--        ON ussd_core.account_registry(primary_identifier_hash) 
--        WHERE valid_to IS NULL;
--
-- 2. Hierarchical queries (LTREE):
--    CREATE INDEX idx_account_path ON ussd_core.account_registry 
--        USING GIST(account_path);
--    CREATE INDEX idx_account_path_btree ON ussd_core.account_registry 
--        USING BTREE(account_path);
--
-- 3. Application-scoped queries:
--    CREATE INDEX idx_account_primary_app ON ussd_core.account_registry(primary_application_id);
--    CREATE INDEX idx_account_type ON ussd_core.account_registry(account_type);
--
-- 4. Status filtering:
--    CREATE INDEX idx_account_status ON ussd_core.account_registry(status) 
--        WHERE valid_to IS NULL;
--
-- 5. Full-text search (requires pg_trgm):
--    CREATE INDEX idx_account_display_name_trgm 
--        ON ussd_core.account_registry USING gin(display_name gin_trgm_ops);

-- -----------------------------------------------------------------------------
-- TODO[CONSTRAINTS]: Define business rule constraints
-- -----------------------------------------------------------------------------
-- 1. Status values: CHECK (status IN ('active', 'suspended', 'closed'))
-- 2. Account type: Uses custom TYPE ussd_core.account_type
-- 3. Validity period: valid_to > valid_when OR valid_to IS NULL
-- 4. Key algorithm: CHECK (key_algorithm IN ('ed25519', 'secp256k1', 'rsa-4096'))

-- -----------------------------------------------------------------------------
-- TODO[IMMUTABILITY_TRIGGERS]: Prevent updates and deletes
-- -----------------------------------------------------------------------------
-- CREATE TRIGGER trg_account_registry_prevent_update
--     BEFORE UPDATE ON ussd_core.account_registry
--     FOR EACH ROW
--     EXECUTE FUNCTION ussd_core.prevent_update();
--
-- CREATE TRIGGER trg_account_registry_prevent_delete
--     BEFORE DELETE ON ussd_core.account_registry
--     FOR EACH ROW
--     EXECUTE FUNCTION ussd_core.prevent_delete();

-- -----------------------------------------------------------------------------
-- TODO[HASH_COMPUTATION]: Automatic record hash generation
-- -----------------------------------------------------------------------------
-- CREATE OR REPLACE FUNCTION ussd_core.compute_account_hash()
-- RETURNS TRIGGER
-- LANGUAGE plpgsql
-- AS $$
-- BEGIN
--     NEW.record_hash := ussd_core.generate_hash(
--         NEW.account_id::TEXT || 
--         NEW.account_type::TEXT || 
--         COALESCE(NEW.primary_identifier_hash, '') ||
--         COALESCE(NEW.public_key, '') ||
--         NEW.created_at::TEXT
--     );
--     RETURN NEW;
-- END;
-- $$;
--
-- CREATE TRIGGER trg_account_registry_compute_hash
--     BEFORE INSERT ON ussd_core.account_registry
--     FOR EACH ROW
--     EXECUTE FUNCTION ussd_core.compute_account_hash();

-- -----------------------------------------------------------------------------
-- TODO[PATH_COMPUTATION]: Automatic LTREE path computation
-- -----------------------------------------------------------------------------
-- CREATE OR REPLACE FUNCTION ussd_core.compute_account_path()
-- RETURNS TRIGGER
-- LANGUAGE plpgsql
-- AS $$
-- BEGIN
--     IF NEW.parent_account_id IS NULL THEN
--         NEW.account_path := text2ltree(NEW.account_id::TEXT);
--     ELSE
--         SELECT account_path || NEW.account_id::TEXT::ltree
--         INTO NEW.account_path
--         FROM ussd_core.account_registry
--         WHERE account_id = NEW.parent_account_id;
--     END IF;
--     RETURN NEW;
-- END;
-- $$;

-- -----------------------------------------------------------------------------
-- TODO[VERSIONING]: Handle status changes via versioned records
-- -----------------------------------------------------------------------------
-- Since the table is immutable, status changes require creating new versions.
-- Implement ussd_core.create_account_version() function for this purpose.
-- Pattern:
--   1. Set valid_to = NOW() on current record
--   2. Insert new record with new status, valid_from = NOW()
--   3. Set superseded_by link

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.account_registry (
    -- Primary identifier
    account_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Account classification
    account_type ussd_core.account_type NOT NULL,  -- ENUM: individual, group, merchant, system, agent, corporate
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
*/

-- -----------------------------------------------------------------------------
-- IMPLEMENTATION NOTES
-- -----------------------------------------------------------------------------
-- 1. LTREE EXTENSION: Ensure 'CREATE EXTENSION IF NOT EXISTS ltree;' in setup
-- 2. ENCRYPTION: Consider pgcrypto for primary_identifier encryption at rest
-- 3. RLS: Enable Row Level Security for multi-tenant data isolation
-- 4. PARTITIONING: Consider range partitioning by created_at for very large registries
-- 5. SYSTEM ACCOUNTS: Reserve UUID range 00000000-0000-0000-0000-000000000001+ for kernel

-- -----------------------------------------------------------------------------
-- INITIAL DATA
-- -----------------------------------------------------------------------------
-- TODO: Insert kernel system accounts after table creation
-- - Kernel System Account (00000000-0000-0000-0000-000000000001)
-- - Fees and Commissions Account (00000000-0000-0000-0000-000000000002)
-- - Reconciliation Suspense Account (00000000-0000-0000-0000-000000000003)

-- =============================================================================
-- END OF FILE
-- =============================================================================
