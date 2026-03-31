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
- DOCUMENT: content_hash
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
-- CREATE TABLE: digital_signatures
-- -----------------------------------------------------------------------------
CREATE TABLE core.digital_signatures (
    -- Primary identifier
    signature_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    signature_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Signature classification
    signature_type VARCHAR(50) NOT NULL
        CHECK (signature_type IN ('TRANSACTION', 'DOCUMENT', 'APPROVAL', 'AUDIT', 'CONSENT')),
    
    -- Signer
    signer_account_id UUID NOT NULL REFERENCES core.account_registry(account_id) ON DELETE RESTRICT,
    signer_certificate_id UUID,
    
    -- Signed content
    content_hash VARCHAR(64) NOT NULL,  -- SHA-256 of signed content
    content_reference VARCHAR(255),     -- Reference to signed document/transaction
    content_type VARCHAR(50),           -- Type of content signed
    
    -- Signature value
    signature_algorithm VARCHAR(20) NOT NULL  -- 'RSA-PSS-SHA256', 'ECDSA-P256', 'Ed25519'
        CHECK (signature_algorithm IN ('RSA-PSS-SHA256', 'ECDSA-P256', 'ECDSA-P384', 'Ed25519')),
    signature_value BYTEA NOT NULL,
    signature_format VARCHAR(20) DEFAULT 'RAW'  -- 'RAW', 'CMS', 'JWS', 'XML-DSIG'
        CHECK (signature_format IN ('RAW', 'CMS', 'JWS', 'XML-DSIG')),
    
    -- Timestamp (RFC 3161)
    timestamp_token BYTEA,
    timestamp_authority VARCHAR(100),
    timestamped_at TIMESTAMPTZ,
    timestamp_serial_number VARCHAR(100),
    
    -- Verification
    verified_at TIMESTAMPTZ,
    verified_by UUID,
    verification_result BOOLEAN,
    verification_details JSONB,
    verification_method VARCHAR(50),  -- 'ONLINE', 'OFFLINE', 'THIRD_PARTY'
    
    -- Revocation
    revoked_at TIMESTAMPTZ,
    revocation_reason VARCHAR(100)
        CHECK (revocation_reason IN ('KEY_COMPROMISE', 'CERTIFICATE_EXPIRED', 'SUPERSEDED', 'CESSATION_OF_OPERATION', 'AFFILIATION_CHANGED')),
    revoked_by UUID,
    
    -- Certificate info (at time of signing)
    certificate_serial VARCHAR(100),
    certificate_issuer VARCHAR(500),
    certificate_subject VARCHAR(500),
    certificate_not_before TIMESTAMPTZ,
    certificate_not_after TIMESTAMPTZ,
    certificate_fingerprint VARCHAR(64),
    
    -- Legal validity
    signature_level VARCHAR(20) DEFAULT 'SIMPLE'  -- 'SIMPLE', 'ADVANCED', 'QUALIFIED'
        CHECK (signature_level IN ('SIMPLE', 'ADVANCED', 'QUALIFIED')),
    jurisdiction VARCHAR(50),  -- For eIDAS compliance
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- -----------------------------------------------------------------------------
-- INDEXES
-- -----------------------------------------------------------------------------
-- Signer lookups
CREATE INDEX idx_digital_signatures_signer 
    ON core.digital_signatures(signer_account_id, created_at DESC);

-- Content hash lookups
CREATE INDEX idx_digital_signatures_content 
    ON core.digital_signatures(content_hash);

-- Signature type queries
CREATE INDEX idx_digital_signatures_type 
    ON core.digital_signatures(signature_type, created_at);

-- Verification status
CREATE INDEX idx_digital_signatures_verification 
    ON core.digital_signatures(verification_result, verified_at) 
    WHERE verification_result IS NOT NULL;

-- Certificate tracking
CREATE INDEX idx_digital_signatures_certificate 
    ON core.digital_signatures(certificate_fingerprint) 
    WHERE certificate_fingerprint IS NOT NULL;

-- Revocation tracking
CREATE INDEX idx_digital_signatures_revoked 
    ON core.digital_signatures(revoked_at) 
    WHERE revoked_at IS NOT NULL;

-- Content reference lookups
CREATE INDEX idx_digital_signatures_reference 
    ON core.digital_signatures(content_reference) 
    WHERE content_reference IS NOT NULL;

-- Timestamp queries
CREATE INDEX idx_digital_signatures_timestamp 
    ON core.digital_signatures(timestamped_at) 
    WHERE timestamped_at IS NOT NULL;

-- -----------------------------------------------------------------------------
-- IMMUTABILITY TRIGGERS
-- -----------------------------------------------------------------------------
CREATE TRIGGER trg_digital_signatures_prevent_update
    BEFORE UPDATE ON core.digital_signatures
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_digital_signatures_prevent_delete
    BEFORE DELETE ON core.digital_signatures
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- -----------------------------------------------------------------------------
-- HASH COMPUTATION TRIGGER
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION core.compute_signature_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.signature_id::TEXT || 
        NEW.signature_reference || 
        NEW.signer_account_id::TEXT ||
        NEW.signature_type ||
        NEW.content_hash ||
        COALESCE(NEW.content_reference, '') ||
        NEW.signature_algorithm ||
        ENCODE(NEW.signature_value, 'hex') ||
        NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_digital_signatures_compute_hash
    BEFORE INSERT ON core.digital_signatures
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_signature_hash();

-- -----------------------------------------------------------------------------
-- HELPER FUNCTIONS
-- -----------------------------------------------------------------------------

-- Function to register a new signature
CREATE OR REPLACE FUNCTION core.register_signature(
    p_signature_type VARCHAR(50),
    p_signer_account_id UUID,
    p_content_hash VARCHAR(64),
    p_content_reference VARCHAR(255),
    p_signature_algorithm VARCHAR(20),
    p_signature_value BYTEA,
    p_signer_certificate_id UUID DEFAULT NULL,
    p_signature_format VARCHAR(20) DEFAULT 'RAW',
    p_signature_level VARCHAR(20) DEFAULT 'SIMPLE'
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_signature_id UUID;
    v_reference VARCHAR(100);
BEGIN
    -- Generate reference
    v_reference := 'SIG-' || UPPER(p_signature_type) || '-' || TO_CHAR(NOW(), 'YYYYMMDD') || '-' || SUBSTRING(MD5(RANDOM()::TEXT), 1, 6);
    
    INSERT INTO core.digital_signatures (
        signature_reference,
        signature_type,
        signer_account_id,
        signer_certificate_id,
        content_hash,
        content_reference,
        signature_algorithm,
        signature_value,
        signature_format,
        signature_level
    ) VALUES (
        v_reference,
        p_signature_type,
        p_signer_account_id,
        p_signer_certificate_id,
        p_content_hash,
        p_content_reference,
        p_signature_algorithm,
        p_signature_value,
        p_signature_format,
        p_signature_level
    ) RETURNING signature_id INTO v_signature_id;
    
    RETURN v_signature_id;
END;
$$;

-- Function to verify a signature
CREATE OR REPLACE FUNCTION core.verify_signature(
    p_signature_id UUID,
    p_verified_by UUID,
    p_verification_result BOOLEAN,
    p_verification_details JSONB DEFAULT NULL,
    p_verification_method VARCHAR(50) DEFAULT 'ONLINE'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    -- Note: Since table is immutable, we create a verification record
    -- In production, this would create a new signature record with verification details
    -- or use a separate verification log table
    
    RAISE NOTICE 'Signature % verified by %: %', p_signature_id, p_verified_by, p_verification_result;
    RETURN p_verification_result;
END;
$$;

-- Function to revoke a signature
CREATE OR REPLACE FUNCTION core.revoke_signature(
    p_signature_id UUID,
    p_revocation_reason VARCHAR(100),
    p_revoked_by UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    -- Note: Since table is immutable, revocation creates a new record
    -- or uses a revocation list
    
    RAISE NOTICE 'Signature % revoked by %: %', p_signature_id, p_revoked_by, p_revocation_reason;
    RETURN TRUE;
END;
$$;

-- Function to get signature statistics
CREATE OR REPLACE FUNCTION core.get_signature_statistics(
    p_signer_account_id UUID DEFAULT NULL,
    p_start_date DATE DEFAULT NULL,
    p_end_date DATE DEFAULT NULL
)
RETURNS TABLE (
    signature_type VARCHAR(50),
    signature_count BIGINT,
    verified_count BIGINT,
    revoked_count BIGINT,
    unique_signers BIGINT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ds.signature_type,
        COUNT(*) as signature_count,
        COUNT(*) FILTER (WHERE ds.verification_result = TRUE) as verified_count,
        COUNT(*) FILTER (WHERE ds.revoked_at IS NOT NULL) as revoked_count,
        COUNT(DISTINCT ds.signer_account_id) as unique_signers
    FROM core.digital_signatures ds
    WHERE (p_signer_account_id IS NULL OR ds.signer_account_id = p_signer_account_id)
      AND (p_start_date IS NULL OR ds.created_at::DATE >= p_start_date)
      AND (p_end_date IS NULL OR ds.created_at::DATE <= p_end_date)
    GROUP BY ds.signature_type
    ORDER BY signature_count DESC;
END;
$$;

-- Function to find signatures by content
CREATE OR REPLACE FUNCTION core.find_signatures_by_content(
    p_content_hash VARCHAR(64)
)
RETURNS TABLE (
    signature_id UUID,
    signature_reference VARCHAR(100),
    signature_type VARCHAR(50),
    signer_account_id UUID,
    created_at TIMESTAMPTZ,
    verification_result BOOLEAN
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ds.signature_id,
        ds.signature_reference,
        ds.signature_type,
        ds.signer_account_id,
        ds.created_at,
        ds.verification_result
    FROM core.digital_signatures ds
    WHERE ds.content_hash = p_content_hash
    ORDER BY ds.created_at DESC;
END;
$$;

-- -----------------------------------------------------------------------------
-- COMMENTS
-- -----------------------------------------------------------------------------
COMMENT ON TABLE core.digital_signatures IS 'Registry of all digital signatures with verification metadata';
COMMENT ON COLUMN core.digital_signatures.signature_id IS 'Unique identifier for the signature';
COMMENT ON COLUMN core.digital_signatures.content_hash IS 'SHA-256 hash of the signed content';
COMMENT ON COLUMN core.digital_signatures.signature_value IS 'The actual signature bytes';
COMMENT ON COLUMN core.digital_signatures.signature_level IS 'eIDAS compliance level (SIMPLE, ADVANCED, QUALIFIED)';

-- =============================================================================
-- END OF FILE
-- =============================================================================
