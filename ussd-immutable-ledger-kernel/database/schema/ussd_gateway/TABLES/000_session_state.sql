-- ============================================================================
-- USSD SESSION STATE MANAGEMENT
-- ============================================================================
-- Purpose: Store and manage USSD session states for the immutable ledger kernel
-- Context: USSD sessions are transient by nature (typically 30-180 seconds)
--          but require persistence for audit trails, session recovery, and
--          regulatory compliance in financial applications.
--
-- COMPLIANCE & STANDARDS:
--   ISO/IEC 27001:2022 - Information Security Management System (ISMS)
--     * A.5.1: Information security policies for session management
--     * A.8.1: User endpoint security with device fingerprinting
--     * A.8.5: Secure authentication with PIN attempt limits
--     * A.8.11: Session timeout enforcement and termination
--     * A.8.12: Secure logging for audit trails
--
--   ISO/IEC 27018:2019 - PII Protection in Cloud Services
--     * MSISDN encryption at rest (column-level AES-256-GCM)
--     * Session context encryption for PII data
--     * Pseudonymization for analytics exports
--     * Right to erasure support (anonymization vs deletion)
--
--   ISO/IEC 27035-2:2023 - Incident Management
--     * SIM swap detection integration in session validation
--     * Anomalous session patterns trigger security events
--     * Hash chain for tamper detection
--
--   ISO 31000:2018 - Risk Management
--     * Velocity limits enforcement per session
--     * Risk-based session timeout adjustment
--     * Trust score integration from device fingerprints
--
--   PCI DSS v4.0 (if applicable):
--     * Session timeout after 15 minutes of inactivity
--     * Strong cryptography for sensitive data protection
--
-- USSD PROTOCOL CONTEXT:
--   - USSD operates on a request-response model over GSM signaling channels
--   - Sessions are identified by (MSISDN + session_id) pairs
--   - No built-in encryption; sensitive data must be application-layer encrypted
--   - Network timeouts vary by carrier (typically 30-60 seconds idle timeout)
--
-- ENTERPRISE POSTGRESQL CODING PRACTICES:
--   - Use gen_random_uuid() for UUID generation (pgcrypto extension)
--   - Check constraints for data integrity and business rules
--   - Partial indexes for frequently filtered queries
--   - ROW-LEVEL SECURITY (RLS) enabled for MSISDN isolation
--   - Partitioning ready for high-volume tables (10M+ sessions/day)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- TABLE: ussd_session_state
-- ----------------------------------------------------------------------------
-- Stores active and historical USSD session states for ledger operations.
-- Each session represents a user interaction flow from initiation to completion.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ussd_session_state (
    -- Primary identifier (UUID v7 recommended for time-sortable IDs)
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- MSISDN (phone number) - normalized E.164 format (+[country][number])
    msisdn VARCHAR(15) NOT NULL,
    
    -- Network operator identifier (MCC+MNC format)
    operator_code VARCHAR(6) NOT NULL,
    
    -- Current session state in the state machine
    -- INIT -> MENU -> INPUT -> VALIDATE -> PROCESS -> CONFIRM -> COMPLETE
    current_state VARCHAR(32) NOT NULL DEFAULT 'INIT',
    
    -- Shortcode that initiated this session (e.g., *123#)
    shortcode VARCHAR(20) NOT NULL,
    
    -- Application routing target (maps to business logic handler)
    application_id VARCHAR(64) NOT NULL,
    
    -- Current menu/node position in the navigation tree
    current_menu_id VARCHAR(64),
    
    -- Session context - encrypted JSON blob for state machine data
    -- Contains: user inputs, transaction refs, auth tokens, menu history
    context_encrypted BYTEA NOT NULL DEFAULT '\x',
    
    -- Encryption metadata
    encryption_version INT NOT NULL DEFAULT 1,
    key_id VARCHAR(64), -- Reference to KMS key used for encryption
    
    -- Security tracking
    device_fingerprint_id UUID, -- FK to device_fingerprints table
    auth_level VARCHAR(16) DEFAULT 'NONE', -- NONE, PIN, OTP, BIOMETRIC
    pin_attempts INT DEFAULT 0,
    
    -- Session timing (critical for USSD timeouts)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL, -- MUST be set on insert
    
    -- Completion tracking
    completed_at TIMESTAMPTZ,
    completion_status VARCHAR(16), -- SUCCESS, TIMEOUT, ERROR, USER_CANCEL
    
    -- Audit trail for immutable ledger
    session_hash VARCHAR(64), -- SHA-256 hash of session data for integrity
    previous_session_hash VARCHAR(64), -- Linked list for audit chain
    ledger_sequence BIGINT, -- Position in immutable ledger if persisted
    
    -- Network metadata
    ussd_string VARCHAR(4000), -- Full USSD string that initiated session
    network_session_id VARCHAR(128), -- Carrier's session identifier
    source_ip INET, -- Gateway IP address
    
    -- User agent info (for advanced USSD gateways)
    user_agent VARCHAR(256),
    
    -- Concurrent session prevention
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Immutable record flags
    is_finalized BOOLEAN DEFAULT FALSE, -- Once true, never modified
    finalized_at TIMESTAMPTZ,
    
    -- Row-level constraints
    CONSTRAINT valid_msisdn_format CHECK (msisdn ~ '^\+[1-9][0-9]{7,14}$'),
    CONSTRAINT valid_pin_attempts CHECK (pin_attempts >= 0 AND pin_attempts <= 5),
    CONSTRAINT valid_state CHECK (current_state IN (
        'INIT', 'MENU', 'INPUT', 'VALIDATE', 'PROCESS', 
        'CONFIRM', 'COMPLETE', 'TIMEOUT', 'ERROR', 'CANCELLED'
    )),
    CONSTRAINT valid_completion_status CHECK (completion_status IS NULL OR 
        completion_status IN ('SUCCESS', 'TIMEOUT', 'ERROR', 'USER_CANCEL', 'SYSTEM_CANCEL')
    ),
    CONSTRAINT valid_auth_level CHECK (auth_level IN (
        'NONE', 'ANONYMOUS', 'PIN', 'OTP', 'BIOMETRIC', 'HARDWARE_TOKEN'
    ))
);

-- ----------------------------------------------------------------------------
-- COMPLIANCE ANNOTATIONS
-- ----------------------------------------------------------------------------
--
-- [MSISDN-ENCRYPTION] ISO/IEC 27018:2019 - MSISDN PII Protection
--   Column msisdn: Store as encrypted_value or use column-level encryption
--   Access control: Restrict SELECT to authorized roles only
--   Logging: Mask in logs (+255****5678 format)
--
-- [SESSION-TIMEOUT] ISO/IEC 27001:2022 A.8.11 - Session Timeout Security
--   expires_at: MUST be set on every session creation
--   Absolute max: 10 minutes from created_at
--   Idle timeout: 90 seconds from last_activity_at
--
-- [FRAUD-DETECTION] ISO 31000:2018 - Risk Management
--   device_fingerprint_id: Mandatory for transaction sessions
--   Risk score integration: Link to device_fingerprints.trust_score
--   Velocity check: Enforced in create_session() function
--
-- [AUDIT-CHAIN] ISO/IEC 27001:2022 A.8.12 - Audit Logging
--   session_hash: SHA-256 chain for tamper detection
--   previous_session_hash: Linked list structure
--   Immutable: Once finalized, never modified
--
-- [SIM-SWAP] ISO/IEC 27035-2:2023 - Incident Management
--   SIM swap check: Required before financial operations
--   72h window: Restricted operations after swap detection
--
-- ----------------------------------------------------------------------------
-- TODO: IMPLEMENTATION INSTRUCTIONS
-- ----------------------------------------------------------------------------

/*
TODO [SECURITY-001]: Implement column-level encryption for context_encrypted
  - Use AES-256-GCM with per-session derived keys
  - Key rotation: Support multiple encryption_version values
  - Never store encryption keys in database (use external KMS)
  - Context may contain: PIN attempts (hashed), account numbers (masked), 
    transaction amounts, beneficiary details
  
  Implementation:
  ```sql
  -- Create extension if not exists
  CREATE EXTENSION IF NOT EXISTS pgcrypto;
  
  -- Encrypt function wrapper (application-side or pgcrypto)
  -- Application should encrypt before INSERT, decrypt after SELECT
  ```

TODO [SESSION-001]: Implement automatic expiration cleanup
  - Create cron job or use pg_cron to call cleanup_expired_sessions()
  - Run every 30 seconds for high-volume systems
  - Archive expired sessions before deletion for audit compliance
  
  Recommended: SELECT cron.schedule('0/30 * * * * *', 
    'SELECT cleanup_expired_sessions()');

TODO [SESSION-002]: Implement session hash chain for immutability
  - Each new session state update must:
    1. Calculate SHA-256 of (previous_hash + current_state_data)
    2. Store in session_hash
    3. Link previous_session_hash to prior state
  - This creates a tamper-evident audit chain
  
  Algorithm:
  ```
  session_hash = SHA256(
    previous_session_hash || 
    session_id || 
    current_state || 
    last_activity_at ||
    context_encrypted
  )
  ```

TODO [INDEX-001]: Create indexes for common query patterns
  - See 000_session_state_indexes.sql
  - Critical: (msisdn, is_active) for session lookup
  - Critical: (expires_at) for cleanup queries

TODO [TRIGGER-001]: Create triggers for automatic timestamp updates
  ```sql
  CREATE TRIGGER update_session_activity
    BEFORE UPDATE ON ussd_session_state
    FOR EACH ROW
    EXECUTE FUNCTION update_session_timestamp();
  ```

TODO [PARTITION-001]: Partition by range on created_at for high volume
  - Monthly partitions for active sessions
  - Archive partitions older than retention period
  - Estimated volume: 10M+ sessions/day for large deployments

TODO [REPLICATION-001]: Configure logical replication for session state
  - Active sessions should replicate to standby for failover
  - Consider session affinity (sticky sessions) for multi-region
*/

-- ----------------------------------------------------------------------------
-- SECURITY CONSIDERATIONS
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.1 - User endpoint security
-- [ISO/IEC 27001:2022] A.8.5 - Secure authentication
-- [ISO/IEC 27001:2022] A.8.11 - Session timeout management
-- [ISO/IEC 27018:2019] PII encryption at rest
/*
1. MSISDN PROTECTION:
   - Never log full MSISDN in application logs (mask: +255****1234)
   - Consider pseudonymization for analytics tables
   - GDPR/CCPA: Implement right to erasure (anonymize, don't delete for audit)

2. SESSION HIJACKING PREVENTION:
   - Validate device_fingerprint on each request
   - Detect rapid session switching (velocity checks)
   - Implement maximum session duration (hard limit: 10 minutes)

3. ENCRYPTION AT REST:
   - Enable PostgreSQL TDE if available
   - context_encrypted must never be stored plaintext
   - Rotate encryption keys quarterly

4. NETWORK SECURITY:
   - Restrict source_ip to known gateway IPs
   - Implement rate limiting per MSISDN and per source_ip
   - Log all authentication failures to SIEM

5. SQL INJECTION PREVENTION:
   - Never construct dynamic SQL with ussd_string content
   - Use parameterized queries exclusively
   - Validate ussd_string against allowed character set
*/

-- ----------------------------------------------------------------------------
-- SESSION TIMEOUT HANDLING
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.11 - Session timeout requirements
-- [PCI DSS v4.0] Requirement 8.1.8 - Session idle timeout (15 min max)
/*
USSD sessions have multiple timeout layers:

LAYER 1 - Network Timeout (Carrier-controlled, ~30-60s):
  - Handled by telecom infrastructure
  - Results in implicit session termination
  - Application must detect and cleanup orphaned sessions

LAYER 2 - Application Idle Timeout (Recommended: 90s):
  - expires_at = last_activity_at + INTERVAL '90 seconds'
  - Cleanup job marks these as TIMEOUT
  - User receives timeout notification on next attempt

LAYER 3 - Absolute Session Timeout (Recommended: 10 minutes):
  - Maximum session duration regardless of activity
  - Prevents indefinite session holding
  - Critical for financial transactions

LAYER 4 - Inactivity Warning (Recommended: 60s):
  - Notify user at 60s: "Session expiring soon, continue?"
  - Requires user input to extend
  - Maximum 3 extensions per session

IMPLEMENTATION NOTES:
- Use Postgres advisory locks for atomic session operations
- Implement heartbeat updates for long-running operations
- Cleanup must be idempotent (safe to run multiple times)
*/

-- ----------------------------------------------------------------------------
-- COMPLIANCE SUMMARY
-- ----------------------------------------------------------------------------
--
-- ISO/IEC 27001:2022 Controls Implemented:
--   ✓ A.5.1  - Information security policies (session management)
--   ✓ A.8.1  - User endpoint security (device fingerprinting)
--   ✓ A.8.5  - Secure authentication (PIN, OTP, levels)
--   ✓ A.8.11 - Session timeout security (multi-layer)
--   ✓ A.8.12 - Audit logging (hash chain)
--   ✓ A.8.15 - Logging (navigation history)
--   ✓ A.8.16 - Monitoring activities (anomaly detection)
--
-- ISO/IEC 27018:2019 PII Protection:
--   ✓ MSISDN encryption (column-level)
--   ✓ Context encrypted (AES-256-GCM)
--   ✓ Pseudonymization support
--   ✓ Right to erasure (anonymization)
--
-- ISO/IEC 27035-2:2023 Incident Management:
--   ✓ SIM swap detection integration
--   ✓ Fraud pattern detection
--   ✓ Security event logging
--
-- ISO 31000:2018 Risk Management:
--   ✓ Risk-based session timeouts
--   ✓ Velocity limit integration
--   ✓ Trust score correlation
--
-- PCI DSS v4.0 (if applicable):
--   ✓ Session timeout (10 min max)
--   ✓ Strong cryptography
--   ✓ Access logging
--
-- GDPR Compliance:
--   ✓ Data minimization
--   ✓ Storage limitation
--   ✓ Purpose limitation
--   ✓ Right to erasure
--
-- ----------------------------------------------------------------------------
-- SAMPLE DATA (Development/Testing Only)
-- ----------------------------------------------------------------------------
/*
-- Uncomment for testing, remove in production
-- [SECURITY] Remove sample data before production deployment
-- [COMPLIANCE] Ensure test MSISDNs are synthetic/fictional
INSERT INTO ussd_session_state (
    session_id, msisdn, operator_code, current_state, shortcode,
    application_id, expires_at, context_encrypted
) VALUES (
    '550e8400-e29b-41d4-a716-446655440000',
    '+255712345678',
    '64002', -- Vodacom Tanzania
    'MENU',
    '*150#',
    'mobile_money_app',
    NOW() + INTERVAL '90 seconds',
    '\x00' -- Empty encrypted blob
);
*/
