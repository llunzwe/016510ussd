-- ============================================================================
-- USSD KERNEL CORE SCHEMA - SETUP AND FOUNDATION
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Foundation setup for the immutable ledger kernel including
--              schemas, extensions, custom types, and base configurations.
-- Immutability: N/A (Setup)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. CREATE SCHEMAS
-- ----------------------------------------------------------------------------
DROP SCHEMA IF EXISTS ussd_core CASCADE;
DROP SCHEMA IF EXISTS ussd_app CASCADE;
DROP SCHEMA IF EXISTS ussd_audit CASCADE;

CREATE SCHEMA ussd_core;
CREATE SCHEMA ussd_app;
CREATE SCHEMA ussd_audit;

COMMENT ON SCHEMA ussd_core IS 'Immutable core ledger - append-only transaction log, accounts, and cryptographic proofs';
COMMENT ON SCHEMA ussd_app IS 'Application schema - multi-tenancy, RBAC, configuration with audit trail';
COMMENT ON SCHEMA ussd_audit IS 'Audit trail - immutable record of all administrative actions';

-- ----------------------------------------------------------------------------
-- 2. ENABLE REQUIRED EXTENSIONS
-- ----------------------------------------------------------------------------
-- Cryptographic functions for hashing and signing
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- JSON schema validation (if available, otherwise application-level)
-- CREATE EXTENSION IF NOT EXISTS pg_jsonschema;  -- Optional: requires separate installation

-- Full-text search
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ----------------------------------------------------------------------------
-- 3. CUSTOM TYPES AND ENUMERATIONS
-- ----------------------------------------------------------------------------

-- Account types for the registry
CREATE TYPE ussd_core.account_type AS ENUM (
    'individual',       -- Single user account
    'group',           -- Group or collective account
    'merchant',        -- Business/merchant account
    'system',          -- Internal system account
    'agent',           -- USSD agent account
    'corporate'        -- Corporate/enterprise account
);

-- Transaction status lifecycle
CREATE TYPE ussd_core.transaction_status AS ENUM (
    'pending',         -- Awaiting processing
    'committed',       -- Successfully committed to ledger
    'failed',          -- Failed validation/processing
    'rejected'         -- Rejected by business rules
);

-- Block status for batching
CREATE TYPE ussd_core.block_status AS ENUM (
    'open',            -- Accepting transactions
    'sealing',         -- In process of being sealed
    'sealed',          -- Immutable, hash computed
    'anchored'         -- External blockchain anchor confirmed
);

-- Application status
CREATE TYPE ussd_app.application_status AS ENUM (
    'draft',           -- Under development
    'active',          -- Fully operational
    'suspended',       -- Temporarily disabled
    'deprecated',      -- Scheduled for retirement
    'archived'         -- Retired, read-only access
);

-- Hook types for extensibility
CREATE TYPE ussd_app.hook_type AS ENUM (
    'pre_validate',    -- Before validation
    'pre_commit',      -- Before transaction commit
    'post_commit',     -- After transaction committed
    'block_created',   -- When block is sealed
    'integrity_alert'  -- On integrity verification failure
);

-- Hook execution modes
CREATE TYPE ussd_app.hook_mode AS ENUM (
    'sync',            -- Synchronous execution
    'async',           -- Asynchronous execution
    'retryable'        -- Async with retry logic
);

-- Permission action types
CREATE TYPE ussd_app.permission_action AS ENUM (
    'create', 'read', 'update', 'delete', 'execute', 'admin'
);

-- Audit action types
CREATE TYPE ussd_audit.audit_action AS ENUM (
    'INSERT', 'UPDATE', 'DELETE', 'LOGIN', 'LOGOUT', 'CONFIG_CHANGE',
    'PERMISSION_GRANT', 'PERMISSION_REVOKE', 'ARCHIVE'
);

-- ----------------------------------------------------------------------------
-- 4. UTILITY FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to generate cryptographically secure hash
CREATE OR REPLACE FUNCTION ussd_core.generate_hash(
    p_data TEXT,
    p_algorithm TEXT DEFAULT 'sha256'
) RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
    RETURN encode(digest(p_data, p_algorithm), 'hex');
END;
$$;

-- Function to generate transaction hash
CREATE OR REPLACE FUNCTION ussd_core.compute_transaction_hash(
    p_previous_hash TEXT,
    p_transaction_type TEXT,
    p_payload JSONB,
    p_timestamp TIMESTAMPTZ,
    p_initiator UUID,
    p_idempotency_key TEXT
) RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    v_combined TEXT;
BEGIN
    v_combined := COALESCE(p_previous_hash, '') || 
                  p_transaction_type || 
                  COALESCE(p_payload::TEXT, '{}') || 
                  p_timestamp::TEXT || 
                  COALESCE(p_initiator::TEXT, '') || 
                  COALESCE(p_idempotency_key, '');
    RETURN ussd_core.generate_hash(v_combined);
END;
$$;

-- Function to get current timestamp with microsecond precision
CREATE OR REPLACE FUNCTION ussd_core.precise_now()
RETURNS TIMESTAMPTZ
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN clock_timestamp();
END;
$$;

-- Function to prevent any updates (immutability enforcement helper)
CREATE OR REPLACE FUNCTION ussd_core.prevent_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABILITY_VIOLATION: Table %.% is immutable. Updates are prohibited. Use compensating transactions instead.',
        TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'P0001';
    RETURN NULL;
END;
$$;

-- Function to prevent any deletes (immutability enforcement helper)
CREATE OR REPLACE FUNCTION ussd_core.prevent_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABILITY_VIOLATION: Table %.% is immutable. Deletes are prohibited.',
        TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'P0001';
    RETURN NULL;
END;
$$;

-- Function to set partition boundaries
CREATE OR REPLACE FUNCTION ussd_core.get_partition_suffix(p_date DATE)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
    RETURN to_char(p_date, 'YYYY_MM');
END;
$$;

-- ----------------------------------------------------------------------------
-- 5. CONFIGURATION TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_core.kernel_config (
    config_key VARCHAR(100) PRIMARY KEY,
    config_value TEXT NOT NULL,
    config_type VARCHAR(20) DEFAULT 'string' CHECK (config_type IN ('string', 'integer', 'boolean', 'json', 'encrypted')),
    description TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    updated_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    updated_by VARCHAR(100)
);

-- Insert default configuration
INSERT INTO ussd_core.kernel_config (config_key, config_value, config_type, description) VALUES
    ('kernel.version', '1.0.0', 'string', 'Kernel version identifier'),
    ('kernel.block_size', '1000', 'integer', 'Maximum transactions per block'),
    ('kernel.block_interval_seconds', '300', 'integer', 'Maximum seconds before auto-sealing a block'),
    ('kernel.hash_algorithm', 'sha256', 'string', 'Cryptographic hash algorithm'),
    ('kernel.enable_merkle_trees', 'true', 'boolean', 'Enable Merkle tree computation for blocks'),
    ('kernel.enable_blockchain_anchor', 'false', 'boolean', 'Enable external blockchain anchoring'),
    ('kernel.retention_years_default', '7', 'integer', 'Default data retention period in years'),
    ('kernel.enable_rls', 'true', 'boolean', 'Enable Row Level Security policies');

-- ----------------------------------------------------------------------------
-- 6. AUDIT LOGGING INFRASTRUCTURE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_audit.global_audit_log (
    audit_id BIGSERIAL PRIMARY KEY,
    table_schema VARCHAR(63) NOT NULL,
    table_name VARCHAR(63) NOT NULL,
    record_id TEXT NOT NULL,
    action ussd_audit.audit_action NOT NULL,
    old_values JSONB,
    new_values JSONB,
    changed_by UUID,
    changed_by_username VARCHAR(100),
    session_id TEXT,
    application_id UUID,
    client_ip INET,
    reason TEXT,
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now()
) PARTITION BY RANGE (created_at);

-- Create initial partitions for audit log
CREATE TABLE ussd_audit.global_audit_log_2024_01 
    PARTITION OF ussd_audit.global_audit_log
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

CREATE TABLE ussd_audit.global_audit_log_2024_02 
    PARTITION OF ussd_audit.global_audit_log
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');

-- Function to create audit log entries
CREATE OR REPLACE FUNCTION ussd_audit.log_audit_event(
    p_table_schema VARCHAR,
    p_table_name VARCHAR,
    p_record_id TEXT,
    p_action ussd_audit.audit_action,
    p_old_values JSONB,
    p_new_values JSONB,
    p_reason TEXT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    INSERT INTO ussd_audit.global_audit_log (
        table_schema, table_name, record_id, action,
        old_values, new_values, changed_by, changed_by_username,
        session_id, application_id, client_ip, reason
    ) VALUES (
        p_table_schema, p_table_name, p_record_id, p_action,
        p_old_values, p_new_values,
        NULLIF(current_setting('app.current_user_id', TRUE), '')::UUID,
        current_setting('app.current_username', TRUE),
        current_setting('app.session_id', TRUE),
        NULLIF(current_setting('app.application_id', TRUE), '')::UUID,
        NULLIF(current_setting('app.client_ip', TRUE), '')::INET,
        p_reason
    );
END;
$$;

-- ----------------------------------------------------------------------------
-- 7. COMMENTS AND DOCUMENTATION
-- ----------------------------------------------------------------------------
COMMENT ON FUNCTION ussd_core.generate_hash IS 'Generates cryptographic hash of input data using specified algorithm';
COMMENT ON FUNCTION ussd_core.compute_transaction_hash IS 'Computes transaction hash including chain linkage for tamper evidence';
COMMENT ON FUNCTION ussd_core.prevent_update IS 'Trigger function to enforce immutability by preventing updates';
COMMENT ON FUNCTION ussd_core.prevent_delete IS 'Trigger function to enforce immutability by preventing deletes';
COMMENT ON TABLE ussd_core.kernel_config IS 'Kernel configuration parameters - mutable with audit trail';
COMMENT ON TABLE ussd_audit.global_audit_log IS 'Immutable audit trail of all administrative actions across schemas';

-- ----------------------------------------------------------------------------
-- 8. VERIFICATION
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    RAISE NOTICE 'USSD Kernel Core Schema Setup Complete';
    RAISE NOTICE '  - Schemas created: ussd_core, ussd_app, ussd_audit';
    RAISE NOTICE '  - Extensions enabled: pgcrypto, uuid-ossp, pg_trgm';
    RAISE NOTICE '  - Custom types defined for accounts, transactions, blocks, hooks';
    RAISE NOTICE '  - Utility functions created for hashing and immutability enforcement';
END;
$$;
