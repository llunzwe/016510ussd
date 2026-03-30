-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Transaction integrity)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Cloud audit logging)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Payload encryption)
-- ISO/IEC 27040:2024 - Storage Security (Hash chaining, tamper evidence)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Transaction recovery)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Cryptographic hash chaining for tamper evidence
-- - Partitioning by tenant for performance and isolation
-- - Idempotency key support for exactly-once processing
-- - Digital signature support for non-repudiation
-- ============================================================================
-- =============================================================================
-- MIGRATION: 004_core_transaction_log.sql
-- DESCRIPTION: Immutable Transaction Log - Central append-only ledger
-- TABLES: transaction_log, transaction_types, idempotency_keys
-- DEPENDENCIES: 003_core_account_registry.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 1. Immutable Data Structures / 3. Immutability & Integrity Enforcement
- Feature: Append-Only Transaction Log, Idempotency Management
- Source: adkjfnwr.md

BUSINESS CONTEXT:
The central immutable table where every state change is recorded as a row.
This is the "single source of truth" for the entire USSD ledger system.

KEY FEATURES:
- Cryptographic hash chaining (each tx references previous hash)
- Global idempotency key support (prevent duplicate processing)
- JSON payload for flexible transaction data
- Digital signature support for non-repudiation
- Block/batch reference for Merkle tree inclusion
- Partitioned by application_id then by time for scalability

TRANSACTION TYPES:
- TRANSFER: Standard peer-to-peer transfer
- CONTRIBUTION: Savings group member contribution
- LOAN_DISBURSEMENT: Loan funds release
- LOAN_REPAYMENT: Loan payment
- RIDE_PAYMENT: Transport service payment
- PRODUCT_PURCHASE: E-commerce purchase
- FEE: Service fee charge
- INTEREST: Interest accrual/payment
- REVERSAL: Correction/compensating transaction
================================================================================
*/

-- =============================================================================
-- TODO: Create transaction_types registry
-- DESCRIPTION: Catalog of allowed transaction types
-- PRIORITY: CRITICAL
-- SECURITY: JSON schema validation for payload integrity
-- ============================================================================
-- TODO: [TX-001] Create core.transaction_types table
-- INSTRUCTIONS:
--   - Immutable registry of transaction type definitions
--   - Each type specifies JSON schema for payload validation
--   - Versioned to support schema evolution
--   - ERROR HANDLING: Validate JSON schema on insert
-- COMPLIANCE: ISO/IEC 27040 (Data Validation)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.transaction_types (
--       transaction_type_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       type_code           VARCHAR(50) NOT NULL,        -- 'TRANSFER', 'CONTRIBUTION', etc.
--       type_name           VARCHAR(100) NOT NULL,
--       description         TEXT,
--       
--       -- Scope
--       scope               VARCHAR(20) DEFAULT 'GLOBAL', -- GLOBAL, APPLICATION_SPECIFIC
--       application_id      UUID REFERENCES app.applications(application_id), -- NULL if global
--       
--       -- Validation Schema
--       payload_schema      JSONB NOT NULL,              -- JSON Schema for validation
--       required_approvals  INTEGER DEFAULT 0,           -- Number of approvals required
--       
--       -- Processing Rules
--       auto_execute        BOOLEAN DEFAULT true,        -- Auto-execute or manual
--       allowed_statuses    VARCHAR(20)[] DEFAULT '{PENDING,POSTED}',
--       
--       -- Hooks
--       pre_commit_hook     VARCHAR(500),                -- URL or function name
--       post_commit_hook    VARCHAR(500),
--       
--       -- Immutability
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id),
--       superseded_by       UUID REFERENCES core.transaction_types(transaction_type_id),
--       
--       -- Versioning
--       version             INTEGER NOT NULL DEFAULT 1,
--       valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       valid_to            TIMESTAMPTZ
--   );
--
-- CONSTRAINTS:
--   - UNIQUE (type_code, application_id, valid_to) WHERE valid_to IS NULL
--   - CHECK: (scope = 'GLOBAL' AND application_id IS NULL) OR 
--            (scope = 'APPLICATION_SPECIFIC' AND application_id IS NOT NULL)

-- =============================================================================
-- TODO: Create idempotency_keys table
-- DESCRIPTION: Global idempotency key storage
-- PRIORITY: CRITICAL
-- SECURITY: TTL-based cleanup prevents key accumulation
-- ============================================================================
-- TODO: [TX-002] Create core.idempotency_keys table
-- INSTRUCTIONS:
--   - Prevents duplicate transaction processing
--   - Keys scoped per application to avoid collisions
--   - TTL-based automatic cleanup for old keys
--   - TRANSACTION ISOLATION: SERIALIZABLE for key allocation
-- COMPLIANCE: ISO/IEC 27031 (Exactly-once Processing)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.idempotency_keys (
--       idempotency_key_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       idempotency_key     VARCHAR(255) NOT NULL,       -- Client-provided key
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Resolution
--       status              VARCHAR(20) NOT NULL,        -- PENDING, COMPLETED, FAILED
--       transaction_id      UUID REFERENCES core.transaction_log(transaction_id),
--       rejection_id        UUID REFERENCES core.rejection_log(rejection_id),
--       
--       -- Request fingerprint
--       request_hash        BYTEA NOT NULL,              -- Hash of request payload
--       response_payload    JSONB,                       -- Cached response
--       
--       -- TTL
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       expires_at          TIMESTAMPTZ NOT NULL,        -- Auto-cleanup after TTL
--       
--       -- Lock for concurrent requests
--       locked_at           TIMESTAMPTZ,
--       locked_by           UUID                         -- Session/connection ID
--   );
--
-- INDEXES:
--   - UNIQUE (idempotency_key, application_id)
--   - INDEX on expires_at (for cleanup job)
--   - INDEX on transaction_id

-- =============================================================================
-- TODO: Create transaction_log table
-- DESCRIPTION: The central immutable transaction ledger
-- PRIORITY: CRITICAL
-- SECURITY: Partitioned by tenant, encrypted payloads
-- ============================================================================
-- TODO: [TX-003] Create core.transaction_log table
-- INSTRUCTIONS:
--   - Partitioned by application_id (list) then by created_at (range)
--   - Hash chaining for integrity
--   - No updates/deletes allowed (immutable)
--   - RLS POLICY: Tenant isolation enforced at partition level
--   - AUDIT LOGGING: All access logged to audit schema
-- COMPLIANCE: ISO/IEC 27040 (Immutable Ledger)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.transaction_log (
--       -- Identity
--       transaction_id      UUID NOT NULL DEFAULT gen_random_uuid(),
--       transaction_reference VARCHAR(100) NOT NULL,     -- Human-readable reference
--       
--       -- Type & Application
--       transaction_type_id UUID NOT NULL REFERENCES core.transaction_types(transaction_type_id),
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Cryptographic Integrity (Hash Chain)
--       chain_sequence      BIGINT NOT NULL,             -- Global sequence
--       account_sequence    BIGINT NOT NULL,             -- Per-account sequence
--       previous_hash       BYTEA NOT NULL,              -- Hash of previous tx (global chain)
--       account_prev_hash   BYTEA NOT NULL,              -- Hash of previous tx for primary account
--       current_hash        BYTEA NOT NULL,              -- Hash of this transaction
--       
--       -- Content
--       payload             JSONB NOT NULL,              -- Transaction data
--       payload_hash        BYTEA NOT NULL,              -- Hash of payload
--       
--       -- Participants
--       initiator_account_id UUID NOT NULL REFERENCES core.accounts(account_id),
--       beneficiary_account_id UUID REFERENCES core.accounts(account_id),
--       
--       -- Financial
--       amount              NUMERIC(20, 8),
--       currency            VARCHAR(3),
--       
--       -- Status
--       status              VARCHAR(20) NOT NULL DEFAULT 'PENDING',
--                           -- PENDING, VALIDATING, EXECUTING, POSTED, FAILED, REVERSED
--       
--       -- Block/Merkle Reference
--       block_id            UUID REFERENCES core.blocks(block_id),
--       merkle_leaf_index   INTEGER,                     -- Position in Merkle tree
--       
--       -- Digital Signature
--       signature           BYTEA,                       -- ED25519 signature
--       signature_algorithm VARCHAR(20) DEFAULT 'ED25519',
--       
--       -- Idempotency
--       idempotency_key_id  UUID REFERENCES core.idempotency_keys(idempotency_key_id),
--       
--       -- Correlation (for sagas/workflows)
--       correlation_id      UUID,                        -- Groups related transactions
--       saga_id             UUID REFERENCES core.transaction_sagas(saga_id),
--       
--       -- Timing
--       entry_date          DATE NOT NULL DEFAULT CURRENT_DATE,
--       value_date          DATE NOT NULL DEFAULT CURRENT_DATE,
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       posted_at           TIMESTAMPTZ,
--       
--       -- Metadata
--       source_ip           INET,                        -- For audit
--       user_agent          TEXT,
--       device_fingerprint  VARCHAR(255)
--   ) PARTITION BY LIST (application_id);
--
-- PARTITIONING STRATEGY:
--   - Create partitions per application_id
--   - Sub-partition by month: transaction_log_y2024m01, etc.
--   - Default partition for new applications

-- =============================================================================
-- TODO: Create global sequence for chain
-- DESCRIPTION: Monotonic sequence for hash chain
-- PRIORITY: CRITICAL
-- SECURITY: Prevent sequence gaps for audit
-- ============================================================================
-- TODO: [TX-004] Create global transaction sequence
-- INSTRUCTIONS:
--   - Bigint sequence for global ordering
--   - Used in chain_sequence column
--   - ERROR HANDLING: Cache 1 to prevent gaps on crash
-- COMPLIANCE: ISO/IEC 27040 (Chain Integrity)
-- IMPLEMENTATION:
--   CREATE SEQUENCE core.transaction_global_seq START 1 CACHE 1;

-- =============================================================================
-- TODO: Create per-account sequence tracking
-- DESCRIPTION: Track sequence per account for account-level hash chain
-- PRIORITY: HIGH
-- SECURITY: Advisory locks prevent concurrent sequence allocation
-- ============================================================================
-- TODO: [TX-005] Create account sequence tracking
-- INSTRUCTIONS:
--   - Use advisory locks or separate sequence table
--   - Each account needs independent sequence counter
--   - TRANSACTION ISOLATION: Use advisory locks for atomic increment
--
-- TABLE STRUCTURE:
--   CREATE TABLE core.account_sequences (
--       account_id          UUID PRIMARY KEY REFERENCES core.accounts(account_id),
--       last_sequence       BIGINT NOT NULL DEFAULT 0,
--       last_hash           BYTEA NOT NULL DEFAULT '\x00',
--       updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create hash computation function
-- DESCRIPTION: Compute transaction hash for chain
-- PRIORITY: CRITICAL
-- SECURITY: Deterministic, collision-resistant hashing
-- ============================================================================
-- TODO: [TX-006] Create compute_transaction_hash function
-- INSTRUCTIONS:
--   - Include all significant fields
--   - Include previous_hash for chain integrity
--   - Deterministic output for verification
--   - SEARCH PATH: Explicitly set for security
-- COMPLIANCE: ISO/IEC 27040 (Cryptographic Hashing)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.compute_transaction_hash(
--       p_transaction_type_id UUID,
--       p_application_id UUID,
--       p_payload JSONB,
--       p_initiator_account_id UUID,
--       p_amount NUMERIC,
--       p_currency VARCHAR(3),
--       p_entry_date DATE,
--       p_previous_hash BYTEA
--   ) RETURNS BYTEA AS $$
--   BEGIN
--       RETURN digest(
--           p_transaction_type_id::text ||
--           p_application_id::text ||
--           p_payload::text ||
--           p_initiator_account_id::text ||
--           COALESCE(p_amount::text, '0') ||
--           COALESCE(p_currency, 'XXX') ||
--           p_entry_date::text ||
--           p_previous_hash,
--           'sha256'
--       );
--   END;
--   $$ LANGUAGE plpgsql IMMUTABLE;

-- =============================================================================
-- TODO: Create immutability triggers
-- DESCRIPTION: Prevent UPDATE/DELETE on transaction_log
-- PRIORITY: CRITICAL
-- SECURITY: Enforce append-only via trigger
-- ============================================================================
-- TODO: [TX-007] Add immutability triggers
-- INSTRUCTIONS:
--   - BEFORE UPDATE: Raise exception
--   - BEFORE DELETE: Raise exception
--   - Only status change via separate status_update table
--   - AUDIT LOGGING: Log all violation attempts
-- COMPLIANCE: ISO/IEC 27040 (Immutability Enforcement)

-- =============================================================================
-- TODO: Create transaction lookup indexes
-- DESCRIPTION: Optimize common query patterns
-- PRIORITY: HIGH
-- SECURITY: Limit index information leakage
-- ============================================================================
-- TODO: [TX-008] Create indexes
-- INDEX LIST:
--   - PRIMARY KEY (transaction_id, application_id)  -- Include partition key
--   - UNIQUE (transaction_reference, application_id)
--   - INDEX on (initiator_account_id, created_at DESC)
--   - INDEX on (beneficiary_account_id, created_at DESC)
--   - INDEX on (correlation_id)
--   - INDEX on (saga_id)
--   - INDEX on (status, created_at) WHERE status = 'PENDING'
--   - GIN INDEX on payload (for JSON queries)
--   - INDEX on (block_id, merkle_leaf_index)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create transaction_types registry with validation schemas
□ Create idempotency_keys table with TTL support
□ Create transaction_log table with partitioning
□ Create global sequence for chain ordering
□ Create account sequence tracking table
□ Implement hash computation function
□ Add immutability triggers
□ Create all indexes for query patterns
□ Verify hash chain integrity on insert
□ Test partition routing
================================================================================
*/
