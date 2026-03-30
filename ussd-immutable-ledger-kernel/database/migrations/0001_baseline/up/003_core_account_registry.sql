-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Identity management)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Account isolation)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (KYC data protection)
-- ISO/IEC 27040:2024 - Storage Security (Immutable account records)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Account recovery)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - UUID primary keys for distributed systems
-- - Immutable versioning with hash chaining
-- - Bitemporal validity periods (system_time vs valid_time)
-- - Exclusion constraints for temporal integrity
-- - RLS policies for multi-tenant isolation
-- ============================================================================
-- =============================================================================
-- MIGRATION: 003_core_account_registry.sql
-- DESCRIPTION: Account Registry - Stores all participants (users, groups, merchants)
-- TABLES: accounts, account_types, account_status_history
-- DEPENDENCIES: 001_create_schemas.sql, 002_core_extensions.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 1. Identity & Multi-Tenancy / 2. Core Immutable Ledger
- Feature: Account Registry (Participants)
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Stores every participant in the USSD ecosystem:
- Individual users (savings group members, loan recipients)
- Groups (savings groups, investment clubs)
- Merchants (transport operators, health providers, e-commerce sellers)
- System accounts (fee collection, interest accrual, suspense accounts)

KEY FEATURES:
- Hierarchical relationships via LTREE (groups containing members)
- KYC/AML fields for micro-finance compliance
- Optional public key for cryptographic signing
- Bitemporal validity (system_time vs valid_time)
- Risk scoring and sanctions screening support
================================================================================
*/

-- =============================================================================
-- TODO: Create account_types lookup table
-- DESCRIPTION: Define valid account classifications
-- PRIORITY: HIGH
-- SECURITY: Immutable lookup - changes create new versions
-- ============================================================================
-- TODO: [ACCT-001] Create core.account_types table
-- INSTRUCTIONS:
--   - Immutable lookup of account type definitions
--   - Defines behavior: can_have_balance, can_have_members, kyc_required
--   - Supports extension for new business models
--   - ERROR HANDLING: Use EXCEPTION block for constraint violations
--   - TRANSACTION ISOLATION: SERIALIZABLE for version updates
-- COMPLIANCE: ISO/IEC 27001 (Classification)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.account_types (
--       account_type_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       type_code           VARCHAR(50) UNIQUE NOT NULL,  -- 'INDIVIDUAL', 'GROUP', 'MERCHANT', 'SYSTEM'
--       type_name           VARCHAR(100) NOT NULL,
--       description         TEXT,
--       account_class       VARCHAR(20) NOT NULL,         -- 'ASSET', 'LIABILITY', 'EQUITY', 'INCOME', 'EXPENSE'
--       can_have_balance    BOOLEAN DEFAULT true,
--       can_have_members    BOOLEAN DEFAULT false,        -- true for groups
--       kyc_required        BOOLEAN DEFAULT true,
--       kyc_level_required  INTEGER DEFAULT 1,            -- 1=basic, 2=enhanced, 3=full
--       allowed_currencies  VARCHAR(3)[],                 -- NULL = all currencies
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id),
--       superseded_by       UUID REFERENCES core.account_types(account_type_id),
--       valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       valid_to            TIMESTAMPTZ                  -- NULL = current version
--   );
--
-- INDEXES TO CREATE:
--   - UNIQUE (type_code, valid_to) WHERE valid_to IS NULL  -- Only one current version
--   - INDEX on account_class
--
-- SEED DATA (in 055_seed_data.sql):
--   - INDIVIDUAL: Single user account
--   - GROUP: Savings group, investment club
--   - MERCHANT: Business/merchant account
--   - SYSTEM: Internal system accounts (fees, interest, suspense)
--   - VIRTUAL: Virtual wallet linked to master account

-- =============================================================================
-- TODO: Create accounts table
-- DESCRIPTION: Primary registry of all participants
-- PRIORITY: CRITICAL
-- SECURITY: Contains PII - enable RLS, encrypt sensitive fields
-- ============================================================================
-- TODO: [ACCT-002] Create core.accounts table
-- INSTRUCTIONS:
--   - Immutable append-only table
--   - No updates allowed - changes create new version rows
--   - Hash chain for integrity verification
--   - RLS POLICY: Tenant isolation by application_id
--   - SECURITY DEFINER: Use for controlled access functions
-- COMPLIANCE: ISO/IEC 27018 (PII Protection), ISO/IEC 27040 (Immutability)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.accounts (
--       -- Identity
--       account_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       account_number      VARCHAR(50) UNIQUE NOT NULL,  -- Human-readable
--       
--       -- Classification
--       account_type_id     UUID NOT NULL REFERENCES core.account_types(account_type_id),
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Hierarchy (LTREE for group membership)
--       parent_account_id   UUID REFERENCES core.accounts(account_id),
--       account_path        LTREE,                        -- Path in hierarchy
--       
--       -- Status (versioned)
--       status              VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- PENDING, ACTIVE, FROZEN, CLOSED
--       status_reason       TEXT,
--       
--       -- KYC/AML Fields
--       kyc_level           INTEGER DEFAULT 0,            -- 0=none, 1=basic, 2=enhanced, 3=full
--       kyc_verified_at     TIMESTAMPTZ,
--       risk_score          INTEGER CHECK (risk_score BETWEEN 0 AND 100),
--       sanctions_status    VARCHAR(20) DEFAULT 'CLEAR',  -- CLEAR, PENDING, MATCH, BLOCKED
--       sanctions_checked_at TIMESTAMPTZ,
--       
--       -- Cryptographic Identity
--       public_key          BYTEA,                        -- For transaction signing
--       key_algorithm       VARCHAR(20),                  -- 'ED25519', 'RSA-2048'
--       
--       -- Metadata
--       display_name        VARCHAR(200),
--       metadata            JSONB DEFAULT '{}',           -- Flexible attributes
--       
--       -- Currency & Limits
--       base_currency       VARCHAR(3) DEFAULT 'USD',
--       
--       -- Immutability Fields
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id),
--       superseded_by       UUID REFERENCES core.accounts(account_id),
--       
--       -- Temporal Validity (bitemporal)
--       valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       valid_to            TIMESTAMPTZ,                  -- NULL = current version
--       
--       -- Integrity
--       version             INTEGER NOT NULL DEFAULT 1,
--       previous_hash       BYTEA,                        -- Hash of previous version
--       current_hash        BYTEA NOT NULL                -- Hash of this record
--   );
--
-- INDEXES TO CREATE:
--   - INDEX on account_number
--   - INDEX on application_id
--   - INDEX on (account_type_id, status) WHERE valid_to IS NULL
--   - GIN INDEX on metadata
--   - GiST INDEX on account_path (for hierarchical queries)
--   - UNIQUE (account_number, valid_to) WHERE valid_to IS NULL

-- =============================================================================
-- TODO: Create immutability triggers for accounts
-- DESCRIPTION: Prevent UPDATE/DELETE on core tables
-- PRIORITY: CRITICAL
-- SECURITY: Enforce append-only data model
-- ============================================================================
-- TODO: [ACCT-003] Create before_update_trigger
-- INSTRUCTIONS:
--   - Raise exception on any UPDATE attempt
--   - Force use of versioned inserts for changes
--   - ERROR HANDLING: Clear exception message for API consumers
--   - AUDIT LOGGING: Log attempted violations
-- COMPLIANCE: ISO/IEC 27040 (Immutability Enforcement)
--
-- TRIGGER FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.prevent_update()
--   RETURNS TRIGGER AS $$
--   BEGIN
--       RAISE EXCEPTION 'Updates not allowed on %.%'. Use versioned insert instead.,
--           TG_TABLE_SCHEMA, TG_TABLE_NAME;
--   END;
--   $$ LANGUAGE plpgsql;
--
--   CREATE TRIGGER accounts_no_update
--       BEFORE UPDATE ON core.accounts
--       FOR EACH ROW EXECUTE FUNCTION core.prevent_update();

-- TODO: [ACCT-004] Create before_delete_trigger
-- INSTRUCTIONS:
--   - Raise exception on any DELETE attempt
--   - All "deletions" are status changes to CLOSED
--   - RLS POLICY: Soft delete via status field only

-- =============================================================================
-- TODO: Create hash computation function
-- DESCRIPTION: Calculate record hash for integrity
-- PRIORITY: CRITICAL
-- SECURITY: Deterministic hash for verification
-- ============================================================================
-- TODO: [ACCT-005] Create compute_account_hash function
-- INSTRUCTIONS:
--   - Hash all significant fields except current_hash itself
--   - Use SHA-256 via pgcrypto
--   - Include previous_hash for chain integrity
--   - SEARCH PATH: Explicitly set to prevent search_path injection
-- COMPLIANCE: ISO/IEC 27040 (Cryptographic Hashing)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.compute_account_hash(
--       p_account_number VARCHAR(50),
--       p_account_type_id UUID,
--       p_application_id UUID,
--       p_status VARCHAR(20),
--       p_metadata JSONB,
--       p_valid_from TIMESTAMPTZ,
--       p_version INTEGER,
--       p_previous_hash BYTEA
--   ) RETURNS BYTEA AS $$
--   BEGIN
--       RETURN digest(
--           p_account_number::text || 
--           p_account_type_id::text || 
--           p_application_id::text || 
--           p_status || 
--           p_metadata::text || 
--           p_valid_from::text || 
--           p_version::text || 
--           COALESCE(p_previous_hash, '\x00'),
--           'sha256'
--       );
--   END;
--   $$ LANGUAGE plpgsql IMMUTABLE;

-- =============================================================================
-- TODO: Create account_status_history table
-- DESCRIPTION: Audit trail of all status changes
-- PRIORITY: MEDIUM
-- SECURITY: Immutable audit log of account lifecycle
-- ============================================================================
-- TODO: [ACCT-006] Create core.account_status_history table
-- INSTRUCTIONS:
--   - Separate table for status change audit trail
--   - Links to accounts via account_id
--   - AUDIT LOGGING: Auto-populated via trigger
-- COMPLIANCE: ISO/IEC 27001 (Audit Trail)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.account_status_history (
--       history_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
--       previous_status     VARCHAR(20),
--       new_status          VARCHAR(20) NOT NULL,
--       reason              TEXT,
--       changed_by          UUID REFERENCES core.accounts(account_id),
--       changed_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       reference_type      VARCHAR(50),                  -- 'MANUAL', 'SYSTEM', 'COMPLIANCE'
--       reference_id        UUID                          -- Link to triggering entity
--   );

-- =============================================================================
-- TODO: Create account lookup views
-- DESCRIPTION: Convenience views for current state
-- PRIORITY: MEDIUM
-- SECURITY: Views provide controlled access to current data
-- ============================================================================
-- TODO: [ACCT-007] Create current_accounts view
-- INSTRUCTIONS:
--   - View showing only current (non-superseded) accounts
--   - Most queries should use this view
--   - RLS POLICY: Apply to view, not underlying table
-- COMPLIANCE: ISO/IEC 27001 (Access Control)
--
-- VIEW DEFINITION:
--   CREATE VIEW core.current_accounts AS
--   SELECT * FROM core.accounts
--   WHERE valid_to IS NULL AND superseded_by IS NULL;

-- TODO: [ACCT-008] Create active_accounts view
-- INSTRUCTIONS:
--   - View showing only ACTIVE status accounts
--   - For transaction validation lookups
--   - SECURITY DEFINER: Use for internal validation functions

/*
================================================================================
MIGRATION CHECKLIST:
□ Create account_types lookup table with seed values
□ Create accounts table with all fields
□ Add immutability triggers (no UPDATE/DELETE)
□ Create hash computation function
□ Create status history table
□ Create current_accounts view
□ Add all indexes for query performance
□ Verify foreign key constraints
□ Test hash chain integrity
================================================================================
*/
