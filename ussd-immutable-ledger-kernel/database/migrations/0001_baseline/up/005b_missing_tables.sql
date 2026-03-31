-- =============================================================================
-- USSD KERNEL CORE SCHEMA - MISSING TABLES
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    005b_missing_tables.sql
-- MIGRATION:   0001_baseline/up
-- DESCRIPTION: Tables referenced in code but not defined in baseline.
--              These tables support features like transaction sagas,
--              security audit logging, and hash chain verification.
-- =============================================================================

/*
================================================================================
MISSING TABLES COMPLETION
================================================================================

This migration adds tables that are referenced in other migration files
but were not created in the baseline. Completing the schema ensures
referential integrity and feature completeness.

Tables Added:
1. core.transaction_sagas - Long-running transaction orchestration
2. core.saga_steps - Individual steps within sagas
3. core.security_audit_log - Security event logging
4. core.hash_chain_verification - Hash chain integrity checks
5. core.signing_keys - Digital signature key management
6. core.external_blockchain_anchors - External blockchain anchoring
7. core.data_classification - Data retention and classification
8. core.retention_policies - Automated retention management

================================================================================
*/

-- =============================================================================
-- 1. TRANSACTION SAGAS (Long-running transaction orchestration)
-- =============================================================================

CREATE TABLE IF NOT EXISTS core.transaction_sagas (
    saga_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Saga identification
    saga_type VARCHAR(50) NOT NULL,
    saga_name VARCHAR(200) NOT NULL,
    
    -- Status tracking
    status VARCHAR(20) DEFAULT 'PENDING' 
        CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'COMPENSATING', 'COMPENSATED')),
    
    -- Context
    initiator_account_id UUID REFERENCES core.account_registry(account_id),
    application_id UUID,
    
    -- Payload
    saga_payload JSONB NOT NULL,
    saga_result JSONB,
    
    -- Step tracking
    current_step INTEGER DEFAULT 0,
    total_steps INTEGER NOT NULL,
    
    -- Timing
    created_at TIMESTAMPTZ DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,
    
    -- Error handling
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    
    -- Compensation
    compensation_payload JSONB,
    compensation_applied BOOLEAN DEFAULT FALSE,
    
    -- Idempotency
    idempotency_key VARCHAR(100) UNIQUE,
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- Saga steps
CREATE TABLE IF NOT EXISTS core.saga_steps (
    step_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    saga_id UUID REFERENCES core.transaction_sagas(saga_id) ON DELETE CASCADE,
    
    -- Step details
    step_number INTEGER NOT NULL,
    step_name VARCHAR(100) NOT NULL,
    step_type VARCHAR(50) NOT NULL 
        CHECK (step_type IN ('ACTION', 'COMPENSATION', 'VERIFY')),
    
    -- Status
    status VARCHAR(20) DEFAULT 'PENDING' 
        CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'SKIPPED')),
    
    -- Execution
    action_payload JSONB,
    result_payload JSONB,
    error_details JSONB,
    
    -- Transaction link
    transaction_id BIGINT REFERENCES core.transaction_log(transaction_id),
    
    -- Timing
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- 2. SECURITY AUDIT LOG (Security event logging)
-- =============================================================================

CREATE TABLE IF NOT EXISTS core.security_audit_log (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Event details
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL 
        CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    
    -- Context
    table_name VARCHAR(100),
    record_id TEXT,
    operation VARCHAR(20),
    
    -- Data
    old_data JSONB,
    new_data JSONB,
    message TEXT,
    
    -- User context
    session_user_name TEXT,
    current_user_name TEXT,
    application_name TEXT,
    client_addr INET,
    client_port INTEGER,
    
    -- Session
    backend_pid INTEGER,
    transaction_id BIGINT,
    
    -- Timing
    event_timestamp TIMESTAMPTZ DEFAULT NOW(),
    
    -- Chain hash for integrity
    previous_hash VARCHAR(64),
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- 3. HASH CHAIN VERIFICATION (Automated integrity checks)
-- =============================================================================

CREATE TABLE IF NOT EXISTS core.hash_chain_verification (
    verification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Scope
    table_name VARCHAR(100) NOT NULL,
    verification_type VARCHAR(50) NOT NULL 
        CHECK (verification_type IN ('FULL_SCAN', 'INCREMENTAL', 'SPOT_CHECK', 'MERKLE_PROOF')),
    
    -- Status
    status VARCHAR(20) DEFAULT 'RUNNING' 
        CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED')),
    
    -- Range checked
    start_sequence BIGINT,
    end_sequence BIGINT,
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    
    -- Results
    records_checked INTEGER,
    records_valid INTEGER,
    records_invalid INTEGER,
    broken_chains INTEGER,
    
    -- Details
    invalid_records JSONB,  -- Array of {record_id, expected_hash, actual_hash}
    error_message TEXT,
    
    -- Performance
    execution_time_ms INTEGER,
    
    -- Audit
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    started_by UUID,
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- 4. SIGNING KEYS (Digital signature management)
-- =============================================================================

CREATE TABLE IF NOT EXISTS core.signing_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Key identification
    key_name VARCHAR(100) NOT NULL,
    key_purpose VARCHAR(50) NOT NULL 
        CHECK (key_purpose IN ('TRANSACTION', 'BLOCK', 'AUDIT', 'APPLICATION')),
    
    -- Algorithm
    algorithm VARCHAR(20) NOT NULL DEFAULT 'ED25519' 
        CHECK (algorithm IN ('ED25519', 'ECDSA', 'RSA-PSS', 'HMAC-SHA256')),
    
    -- Public key (safe to store)
    public_key BYTEA NOT NULL,
    public_key_fingerprint VARCHAR(64) NOT NULL,
    
    -- Key reference (private key stored in HSM/Vault only)
    key_reference VARCHAR(200) NOT NULL,  -- Reference to external HSM/Vault
    
    -- Status
    key_status VARCHAR(20) DEFAULT 'ACTIVE' 
        CHECK (key_status IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'COMPROMISED')),
    
    -- Validity
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    
    -- Usage
    use_count INTEGER DEFAULT 0,
    last_used_at TIMESTAMPTZ,
    
    -- Audit
    created_by UUID,
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- 5. EXTERNAL BLOCKCHAIN ANCHORS
-- =============================================================================

CREATE TABLE IF NOT EXISTS core.external_blockchain_anchors (
    anchor_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Link to internal block
    block_id UUID REFERENCES core.blocks(block_id),
    
    -- Target blockchain
    blockchain_type VARCHAR(50) NOT NULL 
        CHECK (blockchain_type IN ('ETHEREUM', 'STELLAR', 'BITCOIN', 'HYPERLEDGER', 'POLYGON', 'OTHER')),
    network VARCHAR(50) NOT NULL,  -- 'mainnet', 'testnet', etc.
    
    -- Anchor transaction
    anchor_tx_hash VARCHAR(100) NOT NULL,
    anchor_block_number BIGINT,
    anchor_block_hash VARCHAR(100),
    anchor_timestamp TIMESTAMPTZ,
    
    -- Merkle root anchored
    merkle_root VARCHAR(64) NOT NULL,
    
    -- Verification
    confirmations INTEGER DEFAULT 0,
    is_finalized BOOLEAN DEFAULT FALSE,
    finalized_at TIMESTAMPTZ,
    
    -- Status
    anchor_status VARCHAR(20) DEFAULT 'PENDING' 
        CHECK (anchor_status IN ('PENDING', 'CONFIRMED', 'FAILED', 'FINALIZED')),
    
    -- Error handling
    retry_count INTEGER DEFAULT 0,
    error_message TEXT,
    
    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),
    confirmed_at TIMESTAMPTZ,
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- 6. DATA CLASSIFICATION
-- =============================================================================

CREATE TABLE IF NOT EXISTS core.data_classification (
    classification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Data identification
    table_name VARCHAR(100) NOT NULL,
    column_name VARCHAR(100),
    record_id TEXT,  -- NULL for table-level classification
    
    -- Classification
    classification_level VARCHAR(20) NOT NULL 
        CHECK (classification_level IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'SECRET')),
    data_category VARCHAR(50) NOT NULL 
        CHECK (data_category IN ('PII', 'FINANCIAL', 'HEALTH', 'GOVERNMENT', 'TRADE_SECRET', 'OTHER')),
    
    -- Retention
    retention_years INTEGER NOT NULL,
    legal_hold BOOLEAN DEFAULT FALSE,
    legal_hold_reason TEXT,
    legal_hold_until DATE,
    
    -- Compliance
    gdpr_applies BOOLEAN DEFAULT FALSE,
    pci_scope BOOLEAN DEFAULT FALSE,
    sox_relevant BOOLEAN DEFAULT FALSE,
    
    -- Audit
    classified_by UUID,
    classified_at TIMESTAMPTZ DEFAULT NOW(),
    review_date DATE,
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- 7. RETENTION POLICIES
-- =============================================================================

CREATE TABLE IF NOT EXISTS core.retention_policies (
    policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Policy details
    policy_name VARCHAR(100) NOT NULL,
    policy_type VARCHAR(50) NOT NULL 
        CHECK (policy_type IN ('STANDARD', 'REGULATORY', 'LEGAL_HOLD', 'ARCHIVAL')),
    
    -- Scope
    applies_to_table VARCHAR(100) NOT NULL,
    applies_to_classification VARCHAR(20),
    
    -- Retention rules
    retention_period INTERVAL NOT NULL,
    retention_basis VARCHAR(50) NOT NULL 
        CHECK (retention_basis IN ('CREATION_DATE', 'LAST_MODIFIED', 'EVENT_DATE', 'LEGAL_REQUIREMENT')),
    
    -- Actions
    action_after_retention VARCHAR(50) DEFAULT 'ARCHIVE' 
        CHECK (action_after_retention IN ('ARCHIVE', 'DELETE', 'ANONYMIZE', 'REVIEW')),
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    effective_date DATE NOT NULL,
    expiry_date DATE,
    
    -- Audit
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Saga indexes
CREATE INDEX IF NOT EXISTS idx_transaction_sagas_status ON core.transaction_sagas(status, created_at);
CREATE INDEX IF NOT EXISTS idx_transaction_sagas_initiator ON core.transaction_sagas(initiator_account_id);
CREATE INDEX IF NOT EXISTS idx_saga_steps_saga ON core.saga_steps(saga_id, step_number);

-- Security audit indexes
CREATE INDEX IF NOT EXISTS idx_security_audit_time ON core.security_audit_log(event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_audit_type ON core.security_audit_log(event_type, severity);

-- Hash verification indexes
CREATE INDEX IF NOT EXISTS idx_hash_verification_status ON core.hash_chain_verification(status, started_at);

-- Blockchain anchor indexes
CREATE INDEX IF NOT EXISTS idx_blockchain_anchors_block ON core.external_blockchain_anchors(block_id);
CREATE INDEX IF NOT EXISTS idx_blockchain_anchors_status ON core.external_blockchain_anchors(anchor_status);

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE core.transaction_sagas IS 
    'Long-running transaction orchestration with saga pattern support';
COMMENT ON TABLE core.security_audit_log IS 
    'Security event logging including immutability violation attempts';
COMMENT ON TABLE core.hash_chain_verification IS 
    'Automated hash chain integrity verification runs';
COMMENT ON TABLE core.external_blockchain_anchors IS 
    'External blockchain anchoring for extra immutability guarantees';

-- =============================================================================
-- END OF FILE
-- =============================================================================
