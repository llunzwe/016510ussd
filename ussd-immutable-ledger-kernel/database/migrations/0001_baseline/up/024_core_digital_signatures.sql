-- =============================================================================
-- MIGRATION: 024_core_digital_signatures.sql
-- DESCRIPTION: Digital Signatures with eIDAS Compliance
-- TABLES: digital_signatures, signature_requests
-- DEPENDENCIES: 022_core_document_registry.sql
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems - ISMS)
  - A.5.1: Information security policies
  - A.8.1: User endpoint devices
  - A.8.2: Privileged access rights
  - A.9.2: Access to networks and network services
  - A.12.1: Operational procedures and responsibilities
  - A.12.3: Information backup
  - A.12.4: Logging and monitoring
  - A.12.5: Control of operational software

ISO/IEC 27018:2019 (Protection of PII in Public Clouds)
  - Clause 7: Obligations to the customer
  - Clause 8: Information disclosure and access
  - Annex A: Personally Identifiable Information protection controls
  - PII Classification: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED

ISO/IEC 27040:2024 (Storage Security)
  - Section 5: Storage security architecture
  - Section 6: Data protection and encryption
  - Section 7: Access control and authentication
  - Section 8: Storage security monitoring

ISO 9001:2015 (Quality Management Systems)
  - Clause 7.1: Resources
  - Clause 7.5: Documented information
  - Clause 8.5: Production and service provision
  - Clause 9.1: Monitoring and measurement
  - Clause 10.2: Nonconformity and corrective action

ISO 31000:2018 (Risk Management Guidelines)
  - Principle 4: Integration into organizational processes
  - Principle 6: Based on best available information
  - Risk treatment: Avoid, Mitigate, Transfer, Accept

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

SECURITY BEST PRACTICES:
  [SECURITY-001] SECURITY DEFINER: Functions execute with owner's privileges
                  REQUIRED for: admin functions, cross-schema access, audit logging
  [SECURITY-002] Input validation: All parameters validated before processing
                  Use: CHECK constraints, domain types, function preconditions
  [SECURITY-003] Row-Level Security (RLS): Enabled for tenant isolation
                  Policy: CREATE POLICY tenant_isolation ON table USING (tenant_id = current_tenant())
  [SECURITY-004] Audit logging: All changes recorded in audit trail
                  Trigger: audit_trigger() on all tables logging to audit.audit_log
  [SECURITY-005] Encryption at rest: Sensitive data encrypted with AES-256
                  Use: pgcrypto extension, column-level encryption for PII

FUNCTION VOLATILITY DECLARATIONS:
  [VOLATILITY] IMMUTABLE: Function cannot modify database; returns same result
               for same arguments within single query
               Use for: pure calculations, formatting functions, hash computation
               Example: IMMUTABLE FUNCTION calculate_hash(data TEXT) RETURNS BYTEA
  
  [VOLATILITY] STABLE: Function cannot modify database; returns same result
               for same arguments within single statement
               Use for: lookups, current timestamp, configuration reads
               Example: STABLE FUNCTION get_exchange_rate(from_curr VARCHAR, to_curr VARCHAR)
  
  [VOLATILITY] VOLATILE: Function can modify database; result may vary
               Use for: DML operations, sequence access, random values
               Example: VOLATILE FUNCTION create_transaction(payload JSONB)

ERROR HANDLING PATTERNS:
  [ERROR-001] EXCEPTION WHEN OTHERS THEN: Catch-all error handler
              USE WITH CAUTION - always re-raise or log
              Pattern: EXCEPTION WHEN OTHERS THEN log_error(...); RAISE;
  
  [ERROR-002] RAISE EXCEPTION: Structured error messages with HINT
              Format: RAISE EXCEPTION 'Context: %', param USING HINT = 'Suggestion';
              SQLSTATE: Use custom codes for application errors
  
  [ERROR-003] RAISE NOTICE: Informational messages for debugging
              Use in development only; disable in production
  
  [ERROR-004] SQLSTATE handling: Specific error code catching
              Pattern: EXCEPTION WHEN unique_violation THEN ...
              Common: unique_violation, foreign_key_violation, check_violation

TRANSACTION CONTROL DOCUMENTATION:
  [TRANSACTION] BEGIN/COMMIT/ROLLBACK: Explicit transaction boundaries
                Use for: Multi-statement operations requiring atomicity
  
  [TRANSACTION] SAVEPOINT: Partial rollback capability
                Pattern: SAVEPOINT sp1; ...; ROLLBACK TO SAVEPOINT sp1;
                Use for: Nested operations with selective failure handling
  
  [TRANSACTION] ISOLATION LEVEL: Serializable for critical operations
                Syntax: SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
                Use for: Financial calculations, balance updates, inventory

AUDIT TRAIL INTEGRATION:
  [AUDIT] created_at, created_by: Record creation tracking
          Columns: created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                   created_by UUID REFERENCES core.accounts(account_id)
  
  [AUDIT] updated_at, updated_by: Modification tracking
          Trigger: update_timestamp_trigger() sets updated_at = now()
  
  [AUDIT] superseded_by, valid_from, valid_to: Temporal versioning
          Pattern: Append-only tables, new version supersedes old
          Query: WHERE valid_to IS NULL AND is_current = true
  
  [AUDIT] status, status_reason: State change tracking
          Pattern: status VARCHAR(20), status_reason TEXT, status_changed_at TIMESTAMPTZ

DATA RETENTION COMPLIANCE:
  [RETENTION] retention_until: Automatic purging after retention period
              Policy: DELETE FROM table WHERE retention_until < CURRENT_DATE AND legal_hold = false
              Audit: Log all purges to retention.audit_log
  
  [RETENTION] legal_hold: Override retention for legal requirements
              Flag: legal_hold BOOLEAN DEFAULT false
              Fields: legal_hold_reason TEXT, legal_hold_set_at TIMESTAMPTZ, legal_hold_set_by UUID
              Enforcement: Prevent deletion/purge when legal_hold = true
  
  [RETENTION] archive_manifest: Cold storage tracking
              Table: archive.archive_manifest tracks all archived records
              Fields: storage_provider, storage_bucket, storage_key, content_hash
              Verification: SHA-256 hash verification on restore
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 10. Document & Evidence Management
- Feature: Digital Signatures (eIDAS Compliant)
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Records signature of document by a participant using PIN, biometric, or
cryptographic key. Supports eIDAS levels (SES, AdES, QES). Implements
ISO 27001 authentication controls and ISO 27040 signature integrity.

KEY FEATURES:
- eIDAS compliant signature levels (SES, AdES, QES)
- Signature integrity verification with hash chain
- Timestamp authority integration (RFC 3161)
- Multi-party signature workflows
- Signature revocation with audit trail

SIGNATURE TYPES:
- PIN: Simple PIN confirmation (SES level)
- BIOMETRIC: Fingerprint/face scan (requires biometric encryption per ISO 27040)
- CRYPTO: Private key signature (AdES/QES level)
- OTP: SMS/Email one-time password

SECURITY CONTROLS:
- [SECURITY-001] SECURITY DEFINER for signature verification functions
- [SECURITY-002] Biometric data encrypted at rest (ISO 27040 Section 6)
- [AUDIT] Complete signature audit trail with geolocation
- [RETENTION] Signature records retained per legal requirements

eIDAS COMPLIANCE:
- SES: Simple Electronic Signature
- AdES: Advanced Electronic Signature
- QES: Qualified Electronic Signature (highest legal standing)
================================================================================
*/


-- =============================================================================
-- TODO: Create digital_signatures table
-- DESCRIPTION: Signature records
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [SIG-001] Create core.digital_signatures table
-- INSTRUCTIONS:
--   - Immutable signature records
--   - Links to documents and signers
--   - Cryptographic proof of signing
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.digital_signatures (
--       signature_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       signature_reference VARCHAR(100) UNIQUE NOT NULL,
--       
--       -- Document
--       document_id         UUID NOT NULL REFERENCES core.document_registry(document_id),
--       version_id          UUID REFERENCES core.document_versions(version_id),
--       
--       -- Signer
--       signer_account_id   UUID NOT NULL REFERENCES core.accounts(account_id),
--       signer_name         VARCHAR(200) NOT NULL,       -- At time of signing
--       
--       -- Signature Type
--       signature_type      VARCHAR(20) NOT NULL,        -- PIN, BIOMETRIC, CRYPTO, OTP
--       eidas_level         VARCHAR(10),                 -- SES, AdES, QES
--       
--       -- Signature Data
--       signature_data      BYTEA,                       -- Cryptographic signature
--       signed_hash         BYTEA NOT NULL,              -- Hash of document at signing
--       signing_algorithm   VARCHAR(50) DEFAULT 'SHA256withRSA',
--       
--       -- Authentication
--       auth_method         VARCHAR(50),                 -- PIN, FINGERPRINT, etc.
--       auth_verified       BOOLEAN DEFAULT false,
--       auth_timestamp      TIMESTAMPTZ,
--       
--       -- Timestamp Authority
--       timestamp_token     BYTEA,                       -- RFC 3161 timestamp
--       timestamp_authority VARCHAR(255),
--       timestamped_at      TIMESTAMPTZ,
--       
--       -- Location (for audit)
--       ip_address          INET,
--       geolocation         JSONB,
--       device_info         JSONB,
--       
--       -- Validity
--       is_valid            BOOLEAN DEFAULT true,
--       revoked_at          TIMESTAMPTZ,
--       revoked_by          UUID REFERENCES core.accounts(account_id),
--       revocation_reason   TEXT,
--       
--       -- Audit
--       signed_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create signature_requests table
-- DESCRIPTION: Signature workflow management
-- PRIORITY: MEDIUM
-- =============================================================================
-- TODO: [SIG-002] Create core.signature_requests table
-- INSTRUCTIONS:
--   - Track pending signature requests
--   - Multi-party signing workflows
--   - Reminder and expiration
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.signature_requests (
--       request_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Document
--       document_id         UUID NOT NULL REFERENCES core.document_registry(document_id),
--       
--       -- Signer
--       signer_account_id   UUID NOT NULL REFERENCES core.accounts(account_id),
--       
--       -- Status
--       status              VARCHAR(20) DEFAULT 'PENDING',
--                           -- PENDING, SENT, VIEWED, SIGNED, DECLINED, EXPIRED
--       
--       -- Sequence (for ordered signing)
--       sequence_order      INTEGER DEFAULT 1,
--       depends_on_request  UUID REFERENCES core.signature_requests(request_id),
--       
--       -- Request
--       request_message     TEXT,
--       requested_by        UUID NOT NULL REFERENCES core.accounts(account_id),
--       requested_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
--       
--       -- Expiration
--       expires_at          TIMESTAMPTZ,
--       reminder_sent_at    TIMESTAMPTZ[],
--       
--       -- Completion
--       signature_id        UUID REFERENCES core.digital_signatures(signature_id),
--       completed_at        TIMESTAMPTZ,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create signature verification function
-- DESCRIPTION: Verify signature validity
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [SIG-003] Create verify_signature function
-- INSTRUCTIONS:
--   - Recompute document hash
--   - Verify against signed_hash
--   - Check certificate validity (for crypto signatures)
--   - Return verification result
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.verify_signature(p_signature_id UUID)
--   RETURNS TABLE (
--       is_valid BOOLEAN,
--       verification_time TIMESTAMPTZ,
--       verification_message TEXT
--   ) AS $$
--   DECLARE
--       v_sig RECORD;
--       v_current_hash BYTEA;
--   BEGIN
--       -- Get signature
--       SELECT * INTO v_sig FROM core.digital_signatures WHERE signature_id = p_signature_id;
--       
--       -- Check if revoked
--       IF v_sig.revoked_at IS NOT NULL THEN
--           RETURN QUERY SELECT false, now(), 'Signature has been revoked'::TEXT;
--           RETURN;
--       END IF;
--       
--       -- Verify hash (would actually retrieve and hash document)
--       -- v_current_hash := core.compute_document_hash(v_sig.document_id);
--       
--       IF v_sig.signed_hash = v_current_hash THEN
--           RETURN QUERY SELECT true, now(), 'Signature verified'::TEXT;
--       ELSE
--           RETURN QUERY SELECT false, now(), 'Document has been modified'::TEXT;
--       END IF;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create signature request function
-- DESCRIPTION: Request signature from user
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [SIG-004] Create request_signature function
-- INSTRUCTIONS:
--   - Create signature request
--   - Send notification to signer
--   - Set expiration
--   - Handle reminders

-- =============================================================================
-- TODO: Create signature recording function
-- DESCRIPTION: Record completed signature
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [SIG-005] Create record_signature function
-- INSTRUCTIONS:
--   - Verify authentication
--   - Compute document hash
--   - Create signature record
--   - Update request status
--   - Check if all signatures complete

-- =============================================================================
-- TODO: Create signature indexes
-- DESCRIPTION: Optimize signature queries
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [SIG-006] Create signature indexes
-- INDEX LIST:
--   -- Signatures:
--   - PRIMARY KEY (signature_id)
--   - UNIQUE (signature_reference)
--   - INDEX on (document_id, is_valid)
--   - INDEX on (signer_account_id, signed_at)
--   - INDEX on (signed_hash)
--   -- Requests:
--   - PRIMARY KEY (request_id)
--   - INDEX on (document_id, status)
--   - INDEX on (signer_account_id, status)
--   - INDEX on (status, expires_at) WHERE status = 'PENDING'

/*
================================================================================
MIGRATION CHECKLIST:
□ Create digital_signatures table
□ Create signature_requests table
□ Implement verify_signature function
□ Implement request_signature function
□ Implement record_signature function
□ Add all indexes for signature queries
□ Test signature verification
□ Test signature workflow
□ Test revocation
□ Verify hash computation
================================================================================
*/
