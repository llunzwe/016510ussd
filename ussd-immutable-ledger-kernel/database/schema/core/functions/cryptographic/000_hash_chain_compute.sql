-- =============================================================================
-- USSD KERNEL CORE SCHEMA - CRYPTOGRAPHIC FUNCTIONS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    000_hash_chain_compute.sql
-- SCHEMA:      core
-- CATEGORY:    Cryptographic Functions
-- DESCRIPTION: Cryptographic hash chain computation for transaction integrity
--              with per-account and global ledger hash chain support.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.10.1 Cryptographic controls - Hash algorithm selection
├── A.10.2 Cryptographic controls - Key management (for keyed hashes)
└── A.12.4 Logging and monitoring - Hash verification monitoring

ISO/IEC 27040:2024 (Storage Security - CRITICAL for immutable ledger)
├── Hash algorithm: SHA-256 (FIPS 180-4 compliant)
├── Hash chaining: Cryptographic linkage between records
├── Tamper evidence: Any modification breaks chain
├── Verification: Independent chain verification support
└── Storage integrity: Hash-protected storage

ISO/IEC 27031:2025 (Business Continuity ICT Readiness)
├── Chain reconstruction: Post-disaster chain rebuild
├── Verification procedures: Regular integrity checks
└── Backup integrity: Hash-verified backups

FIPS 140-3 Compliance (if applicable)
├── Approved algorithms: SHA-256
├── Implementation validation: Cryptographic module validation
└── Key management: HSM-backed when applicable

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. FUNCTION ATTRIBUTES
   - IMMUTABLE: For deterministic hash functions (no side effects)
   - STABLE: For functions reading from tables
   - SECURITY DEFINER: When elevated privileges needed
   - STRICT: Returns NULL if any input is NULL

2. ERROR HANDLING
   - Exception handling for crypto operations
   - Validation of input parameters
   - Meaningful error messages
   - Audit logging of failures

3. PERFORMANCE
   - COST annotation for query planner
   - Parallel safety declaration
   - Memory usage optimization

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

KEY MANAGEMENT PROCEDURES:
1. Hash Algorithm Specifications
   - Primary: SHA-256 (FIPS 180-4)
   - Backup: SHA-384 (for future-proofing)
   - Deprecated: MD5, SHA-1 (prohibited)
   - Selection criteria: Security strength, performance, compliance

2. Key Management (for HMAC if used)
   - Key generation: Cryptographically secure RNG
   - Key storage: HSM or encrypted keystore
   - Key rotation: Annual rotation schedule
   - Key destruction: Secure deletion procedures

3. Hash Input Construction
   - Deterministic ordering of fields
   - Canonical JSON for complex data
   - Null handling: Explicit encoding
   - Delimiter strategy: Unambiguous separation

INTEGRITY VERIFICATION PROTOCOLS:
1. Per-Account Chain Verification
   - Sequential hash validation
   - Missing sequence detection
   - Hash mismatch reporting
   - Automated verification schedule

2. Global Chain Verification
   - Cross-account sequence validation
   - Global consistency checks
   - Periodic full ledger audit

3. External Verification Support
   - Documented hash input format
   - Standalone verification tools
   - API for external auditors

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

HASH COMPUTATION:
- Inline computation during INSERT
- Batch verification for history
- Caching of recent hashes
- Parallel verification for old data

INDEXING:
- Index on current_hash for verification lookups
- Index on previous_hash for chain traversal
- Covering indexes for verification queries

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- HASH_COMPUTED: New hash calculated
- VERIFICATION_SUCCESS: Chain verified
- VERIFICATION_FAILURE: Chain break detected
- ALGORITHM_DEPRECATED: Algorithm change logged

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- TODO: Create compute_transaction_hash function
-- DESCRIPTION: Compute cryptographic hash for transaction integrity
-- PRIORITY: CRITICAL
-- SECURITY: IMMUTABLE - no side effects, deterministic output
-- =============================================================================
-- TODO: [HASH-001] Implement core.compute_transaction_hash()
-- INSTRUCTIONS:
--   - Use digest() from pgcrypto extension with 'sha256' algorithm
--   - Concatenate all significant fields in deterministic order
--   - Include previous_hash to maintain chain integrity
--   - Include application_id for multi-tenancy isolation
--   - Return BYTEA (32 bytes for SHA-256)
--
-- FUNCTION STRUCTURE:
--   CREATE OR REPLACE FUNCTION core.compute_transaction_hash(
--       p_transaction_type_id UUID,      -- Transaction classification
--       p_application_id UUID,           -- Tenant isolation
--       p_payload JSONB,                 -- Transaction data
--       p_initiator_account_id UUID,     -- Actor identification
--       p_beneficiary_account_id UUID,   -- Counterparty (nullable)
--       p_amount NUMERIC,                -- Financial amount
--       p_currency VARCHAR(3),           -- Currency code
--       p_entry_date DATE,               -- Accounting date
--       p_previous_hash BYTEA            -- Chain link
--   ) RETURNS BYTEA
--   LANGUAGE plpgsql
--   IMMUTABLE                    -- CRITICAL: Must be deterministic
--   STRICT                       -- Returns NULL if any input is NULL
--   SECURITY INVOKER             -- Execute with caller's permissions
--   COST 100                     -- Relatively expensive operation
--   AS $$
--   DECLARE
--       v_hash_input TEXT;
--   BEGIN
--       -- Build deterministic input string
--       v_hash_input := COALESCE(p_transaction_type_id::text, '') ||
--                       COALESCE(p_application_id::text, '') ||
--                       COALESCE(p_payload::text, '{}') ||
--                       COALESCE(p_initiator_account_id::text, '') ||
--                       COALESCE(p_beneficiary_account_id::text, '') ||
--                       COALESCE(p_amount::text, '0') ||
--                       COALESCE(p_currency, 'XXX') ||
--                       COALESCE(p_entry_date::text, '1970-01-01') ||
--                       COALESCE(encode(p_previous_hash, 'hex'), '00');
--       
--       -- Return SHA-256 hash as BYTEA
--       RETURN digest(v_hash_input, 'sha256');
--   END;
--   $$;
--
-- PERFORMANCE NOTES:
--   - Index on current_hash for verification lookups
--   - Index on previous_hash for chain traversal
--   - Consider caching for repeated computations

-- =============================================================================
-- TODO: Create compute_account_hash function
-- DESCRIPTION: Compute hash for account registry entries
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [HASH-002] Implement core.compute_account_hash()
-- INSTRUCTIONS:
--   - Hash account_number, account_type_id, application_id, status
--   - Include metadata JSONB for comprehensive coverage
--   - Include temporal fields (valid_from) for bitemporal integrity
--   - Include version and previous_hash for versioning chain
--
-- FUNCTION STRUCTURE:
--   CREATE OR REPLACE FUNCTION core.compute_account_hash(
--       p_account_number VARCHAR(50),
--       p_account_type_id UUID,
--       p_application_id UUID,
--       p_status VARCHAR(20),
--       p_metadata JSONB,
--       p_valid_from TIMESTAMPTZ,
--       p_version INTEGER,
--       p_previous_hash BYTEA
--   ) RETURNS BYTEA
--   LANGUAGE plpgsql
--   IMMUTABLE
--   AS $$
--   BEGIN
--       RETURN digest(
--           COALESCE(p_account_number, '') ||
--           COALESCE(p_account_type_id::text, '') ||
--           COALESCE(p_application_id::text, '') ||
--           COALESCE(p_status, '') ||
--           COALESCE(p_metadata::text, '{}') ||
--           COALESCE(p_valid_from::text, '') ||
--           COALESCE(p_version::text, '1') ||
--           COALESCE(encode(p_previous_hash, 'hex'), '00'),
--           'sha256'
--       );
--   END;
--   $$;

-- =============================================================================
-- TODO: Create compute_leg_hash function
-- DESCRIPTION: Compute hash for movement legs (double-entry)
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [HASH-003] Implement core.compute_leg_hash()
-- INSTRUCTIONS:
--   - Hash movement_id, account_id, direction, amount, currency
--   - Include COA code for accounting integrity
--   - Used for individual leg verification
--
-- FUNCTION STRUCTURE:
--   CREATE OR REPLACE FUNCTION core.compute_leg_hash(
--       p_movement_id UUID,
--       p_account_id UUID,
--       p_direction VARCHAR(6),      -- 'DEBIT' or 'CREDIT'
--       p_amount NUMERIC(20, 8),
--       p_currency VARCHAR(3),
--       p_coa_code VARCHAR(50)
--   ) RETURNS BYTEA
--   LANGUAGE plpgsql
--   IMMUTABLE
--   AS $$
--   BEGIN
--       RETURN digest(
--           COALESCE(p_movement_id::text, '') ||
--           COALESCE(p_account_id::text, '') ||
--           COALESCE(p_direction, '') ||
--           COALESCE(p_amount::text, '0') ||
--           COALESCE(p_currency, '') ||
--           COALESCE(p_coa_code, ''),
--           'sha256'
--       );
--   END;
--   $$;

-- =============================================================================
-- TODO: Create compute_movement_control_hash function
-- DESCRIPTION: Aggregate hash of all legs in a movement
-- PRIORITY: MEDIUM
-- =============================================================================
-- TODO: [HASH-004] Implement core.compute_movement_control_hash()
-- INSTRUCTIONS:
--   - Concatenate all leg hashes in sequence order
--   - Compute SHA-256 of concatenation
--   - Store in movement_headers.control_hash
--
-- FUNCTION STRUCTURE:
--   CREATE OR REPLACE FUNCTION core.compute_movement_control_hash(
--       p_movement_id UUID
--   ) RETURNS BYTEA
--   LANGUAGE plpgsql
--   STABLE                       -- Reads from table
--   SECURITY DEFINER             -- Access to leg hashes
--   AS $$
--   DECLARE
--       v_concatenated_hashes TEXT := '';
--       v_leg_hash BYTEA;
--   BEGIN
--       FOR v_leg_hash IN
--           SELECT leg_hash 
--           FROM core.movement_legs 
--           WHERE movement_id = p_movement_id 
--           ORDER BY leg_sequence
--       LOOP
--           v_concatenated_hashes := v_concatenated_hashes || encode(v_leg_hash, 'hex');
--       END LOOP;
--       
--       RETURN digest(v_concatenated_hashes, 'sha256');
--   END;
--   $$;

-- =============================================================================
-- TODO: Create get_previous_hash function
-- DESCRIPTION: Retrieve the previous hash in an account's chain
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [HASH-005] Implement core.get_previous_hash()
-- INSTRUCTIONS:
--   - Query transaction_log for last transaction by account
--   - Return current_hash of most recent transaction
--   - Handle genesis case (no previous transactions)
--   - Use FOR UPDATE to prevent race conditions
--
-- FUNCTION STRUCTURE:
--   CREATE OR REPLACE FUNCTION core.get_previous_hash(
--       p_account_id UUID,
--       p_application_id UUID DEFAULT NULL
--   ) RETURNS TABLE (
--       previous_hash BYTEA,
--       account_sequence BIGINT
--   )
--   LANGUAGE plpgsql
--   STABLE
--   AS $$
--   DECLARE
--       v_prev_hash BYTEA;
--       v_sequence BIGINT;
--   BEGIN
--       SELECT 
--           current_hash,
--           account_sequence
--       INTO 
--           v_prev_hash,
--           v_sequence
--       FROM core.transaction_log
--       WHERE initiator_account_id = p_account_id
--         AND (p_application_id IS NULL OR application_id = p_application_id)
--       ORDER BY account_sequence DESC
--       LIMIT 1
--       FOR UPDATE SKIP LOCKED;  -- Prevent deadlocks
--       
--       IF v_prev_hash IS NULL THEN
--           -- Genesis transaction - return zero hash
--           RETURN QUERY SELECT '\x00'::BYTEA, 0::BIGINT;
--       ELSE
--           RETURN QUERY SELECT v_prev_hash, v_sequence;
--       END IF;
--   END;
--   $$;

-- =============================================================================
-- TODO: Create get_global_previous_hash function
-- DESCRIPTION: Retrieve the previous hash in the global chain
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [HASH-006] Implement core.get_global_previous_hash()
-- INSTRUCTIONS:
--   - Query for the globally last transaction
--   - Return current_hash and chain_sequence
--   - Used for global ledger integrity
--
-- FUNCTION STRUCTURE:
--   CREATE OR REPLACE FUNCTION core.get_global_previous_hash()
--   RETURNS TABLE (
--       previous_hash BYTEA,
--       chain_sequence BIGINT
--   )
--   LANGUAGE plpgsql
--   STABLE
--   AS $$
--   DECLARE
--       v_prev_hash BYTEA;
--       v_sequence BIGINT;
--   BEGIN
--       SELECT 
--           current_hash,
--           chain_sequence
--       INTO 
--           v_prev_hash,
--           v_sequence
--       FROM core.transaction_log
--       ORDER BY chain_sequence DESC
--       LIMIT 1;
--       
--       IF v_prev_hash IS NULL THEN
--           RETURN QUERY SELECT '\x00'::BYTEA, 0::BIGINT;
--       ELSE
--           RETURN QUERY SELECT v_prev_hash, v_sequence;
--       IF;
--   END;
--   $$;

/*
================================================================================
MIGRATION CHECKLIST:
□ Install pgcrypto extension (if not already installed)
□ Create compute_transaction_hash function
□ Create compute_account_hash function
□ Create compute_leg_hash function
□ Create compute_movement_control_hash function
□ Create get_previous_hash function
□ Create get_global_previous_hash function
□ Test hash computation with sample data
□ Verify deterministic output (same input = same hash)
□ Benchmark hash computation performance
□ Document hash input format for external verification
================================================================================
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
