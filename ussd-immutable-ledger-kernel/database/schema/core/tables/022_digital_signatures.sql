-- =============================================================================
-- USSD KERNEL CORE SCHEMA - DIGITAL SIGNATURES
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    022_digital_signatures.sql
-- SCHEMA:      ussd_core
-- TABLE:       digital_signatures
-- DESCRIPTION: Registry of all digital signatures with verification metadata,
--              certificate information, and revocation status.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.10.1 Cryptographic controls - Signature key management
├── A.10.2 Cryptographic controls - Signature verification
└── A.10.3 Cryptographic controls - Key lifecycle management

ISO/IEC 27040:2024 (Storage Security)
├── Signature preservation: Immutable signature storage
├── Certificate chain: Complete chain validation
└── Revocation checking: Real-time CRL/OCSP checking

eIDAS Compliance (EU)
├── Qualified electronic signatures
├── Timestamp authority integration
├── Legal admissibility requirements
└── Cross-border recognition

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. SIGNATURE TYPES
   - TRANSACTION: Transaction authorization
   - DOCUMENT: Document signing
   - APPROVAL: Process approval
   - AUDIT: Audit trail signing

2. ALGORITHMS
   - RSA-PSS with SHA-256
   - ECDSA with P-256 curve
   - Ed25519 (modern preferred)

3. VERIFICATION
   - Signature validation
   - Certificate chain validation
   - Revocation status check
   - Timestamp verification

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

KEY MANAGEMENT:
- HSM storage for private keys
- Key rotation schedule
- Key escrow procedures
- Key compromise response

CERTIFICATE MANAGEMENT:
- Certificate lifecycle tracking
- Expiration monitoring
- Renewal automation
- Revocation handling

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: signature_id
- SIGNER: signer_account_id + created_at
- DOCUMENT: document_hash
- CERTIFICATE: certificate_id

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- SIGNATURE_CREATED
- SIGNATURE_VERIFIED
- SIGNATURE_REVOKED
- CERTIFICATE_EXPIRED

RETENTION: Permanent (signatures are legal evidence)
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.digital_signatures (
    -- Primary identifier
    signature_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Signature classification
    signature_type VARCHAR(50) NOT NULL
        CHECK (signature_type IN ('TRANSACTION', 'DOCUMENT', 'APPROVAL', 'AUDIT')),
    
    -- Signer
    signer_account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    signer_certificate_id UUID,
    
    -- Signed content
    content_hash VARCHAR(64) NOT NULL,  -- SHA-256 of signed content
    content_reference VARCHAR(255),     -- Reference to signed document/transaction
    
    -- Signature value
    signature_algorithm VARCHAR(20) NOT NULL,  -- 'RSA-PSS-SHA256', 'ECDSA-P256', 'Ed25519'
    signature_value BYTEA NOT NULL,
    
    -- Timestamp (RFC 3161)
    timestamp_token BYTEA,
    timestamp_authority VARCHAR(100),
    timestamped_at TIMESTAMPTZ,
    
    -- Verification
    verified_at TIMESTAMPTZ,
    verified_by UUID,
    verification_result BOOLEAN,
    verification_details JSONB,
    
    -- Revocation
    revoked_at TIMESTAMPTZ,
    revocation_reason VARCHAR(100),
    
    -- Certificate info (at time of signing)
    certificate_serial VARCHAR(100),
    certificate_issuer VARCHAR(500),
    certificate_subject VARCHAR(500),
    certificate_not_before TIMESTAMPTZ,
    certificate_not_after TIMESTAMPTZ,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    record_hash VARCHAR(64) NOT NULL
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
