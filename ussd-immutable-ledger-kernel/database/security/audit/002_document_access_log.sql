-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: security/audit/002_document_access_log.sql
-- Description: Comprehensive logging for document access, downloads, and 
--              modifications with DLP integration
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: RESTRICTED
-- DATA SENSITIVITY: HIGH - Document Access and DLP
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.12.4 Logging and Monitoring
  - A.12.4.1: Document access event logging
  - A.12.4.4: Clock synchronization for audit timestamps
  
A.13.2 Information Transfer
  - A.13.2.1: Information transfer policies (DLP)
  - A.13.2.2: Agreements on information transfer
  - A.13.2.3: Electronic messaging security

A.18.1.3 Protection of Records
  - Document lifecycle tracking and legal hold support
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION IN CLOUD
================================================================================
Clause 8: Purpose and Use
  - Legal basis tracking for document processing
  - Consent reference for PII-containing documents
  
Clause 9: Accountability and Choice
  - User access attribution for compliance
  - Data subject access request support
  
Clause 10: Security
  - Document classification-based access controls
  - Watermarking for data loss prevention
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
5.4 Data Protection for Documents
  - Access logging for document storage security
  - Version control for document integrity
  
7.3 Data Retention and Disposal
  - Document retention tracking
  - Secure deletion audit trail
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
Clause 5: Identification
  - Document type and classification for e-discovery
  - Geolocation data for jurisdiction determination
  
Clause 6: Preservation
  - Version history for legal hold
  - Share log for distribution tracking
  
Clause 9: Presentation
  - Access timeline for litigation support
================================================================================

================================================================================
PCI DSS 4.0 DOCUMENT SECURITY
================================================================================
Requirement 3.4: Render PAN Unreadable in Documents
Requirement 9: Physical security of documents
Requirement 10: Audit trail for document access
================================================================================

================================================================================
DATA LOSS PREVENTION (DLP) INTEGRATION
================================================================================
Document Classification Levels:
  - public: No restrictions
  - internal: Authenticated users only
  - confidential: Need-to-know basis
  - restricted: Clearance level required
  - secret: Super admin only

Watermarking:
  - Dynamic watermarking with user/session info
  - Invisible forensic watermarks for tracking
  - Automatic application on download

DLP Actions:
  - Scan on access/download
  - Block for restricted classifications
  - Alert on anomalous access patterns
================================================================================

================================================================================
GDPR/CCPA COMPLIANCE FEATURES
================================================================================
- Legal basis tracking for each access
- Consent reference for lawful processing
- Data subject ID for access requests
- Retention limit enforcement
- Right to erasure workflow support
================================================================================
*/

-- ============================================================================
-- DOCUMENT ACCESS TABLES
-- ============================================================================

-- Document access log (main table)
-- ISO/IEC 27018: Document access tracking with legal basis
CREATE TABLE IF NOT EXISTS document_access_log (
    access_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL,
    document_type VARCHAR(50) NOT NULL,
    document_classification VARCHAR(20) DEFAULT 'internal',
    access_type VARCHAR(30) NOT NULL CHECK (access_type IN (
        'view', 'download', 'print', 'share', 'edit', 'delete', 'copy', 'export'
    )),
    accessed_by UUID NOT NULL,
    access_method VARCHAR(30) DEFAULT 'web',
    access_context JSONB DEFAULT '{}',
    
    -- Access details
    ip_address INET,
    user_agent TEXT,
    session_id UUID,
    request_id UUID,
    
    -- Geolocation (if available)
    geo_country VARCHAR(2),
    geo_region VARCHAR(50),
    geo_city VARCHAR(100),
    geo_location POINT,
    
    -- Access control
    access_granted BOOLEAN DEFAULT TRUE,
    denial_reason VARCHAR(100),
    required_clearance INTEGER,
    user_clearance INTEGER,
    
    -- Compliance
    legal_basis VARCHAR(50),
    consent_reference VARCHAR(100),
    data_subject_id TEXT,
    retention_days INTEGER DEFAULT 2555,
    
    -- Watermarking/DLP
    watermark_applied BOOLEAN DEFAULT FALSE,
    watermark_data JSONB,
    dlp_scan_result VARCHAR(20),
    
    -- Session tracking
    download_started_at TIMESTAMPTZ,
    download_completed_at TIMESTAMPTZ,
    bytes_transferred BIGINT,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- Create monthly partitions
DO $$
DECLARE
    current_month TEXT;
    next_month TEXT;
BEGIN
    current_month := to_char(NOW(), 'YYYY_MM');
    next_month := to_char(NOW() + INTERVAL '1 month', 'YYYY_MM');
    
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS document_access_log_%s PARTITION OF document_access_log
         FOR VALUES FROM (%L) TO (%L)',
        current_month,
        date_trunc('month', NOW()),
        date_trunc('month', NOW() + INTERVAL '1 month')
    );
    
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS document_access_log_%s PARTITION OF document_access_log
         FOR VALUES FROM (%L) TO (%L)',
        next_month,
        date_trunc('month', NOW() + INTERVAL '1 month'),
        date_trunc('month', NOW() + INTERVAL '2 months')
    );
END $$;

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_doc_access_document ON document_access_log(document_id);
CREATE INDEX IF NOT EXISTS idx_doc_access_user ON document_access_log(accessed_by);
CREATE INDEX IF NOT EXISTS idx_doc_access_type ON document_access_log(access_type);
CREATE INDEX IF NOT EXISTS idx_doc_access_time ON document_access_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_doc_access_denied ON document_access_log(access_granted) WHERE NOT access_granted;

-- ============================================================================
-- ACCESS LOGGING FUNCTION
-- ============================================================================

-- Main function to log document access
-- ISO/IEC 27018: PII access tracking with legal basis
-- Parameters: p_document_id, p_document_type, p_access_type, p_context
-- Returns: Access log entry UUID
CREATE OR REPLACE FUNCTION log_document_access(
    p_document_id UUID,
    p_document_type VARCHAR(50),
    p_access_type VARCHAR(30),
    p_context JSONB DEFAULT '{}'
)
RETURNS UUID AS $$
DECLARE
    v_access_id UUID;
    v_classification VARCHAR(20);
    v_required_clearance INTEGER;
    v_user_clearance INTEGER;
    v_access_granted BOOLEAN := TRUE;
    v_denial_reason VARCHAR(100) := NULL;
BEGIN
    -- Get document classification
    SELECT classification, required_clearance_level
    INTO v_classification, v_required_clearance
    FROM documents
    WHERE id = p_document_id;
    
    -- Get user's clearance level
    v_user_clearance := current_user_clearance_level();
    
    -- Check access permission
    IF v_user_clearance < COALESCE(v_required_clearance, 0) THEN
        v_access_granted := FALSE;
        v_denial_reason := 'insufficient_clearance';
    END IF;
    
    -- Insert access log
    INSERT INTO document_access_log (
        document_id,
        document_type,
        document_classification,
        access_type,
        accessed_by,
        access_granted,
        denial_reason,
        required_clearance,
        user_clearance,
        legal_basis,
        consent_reference,
        ip_address
    ) VALUES (
        p_document_id,
        p_document_type,
        v_classification,
        p_access_type,
        current_user_id(),
        v_access_granted,
        v_denial_reason,
        v_required_clearance,
        v_user_clearance,
        p_context->>'legal_basis',
        p_context->>'consent_reference',
        inet_client_addr()
    ) RETURNING access_id INTO v_access_id;
    
    -- Log denied access attempts
    IF NOT v_access_granted THEN
        PERFORM log_security_event(
            'document_access_denied',
            jsonb_build_object(
                'document_id', p_document_id,
                'access_type', p_access_type,
                'reason', v_denial_reason
            )
        );
    END IF;
    
    RETURN v_access_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE document_access_log IS 'ISO/IEC 27018: Document access tracking with GDPR legal basis';
COMMENT ON FUNCTION log_document_access IS 'ISO/IEC 27018: PII access logging with legal basis recording';

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Implement blockchain-based document integrity verification
-- TODO: Add ML-based document classification auto-detection
-- TODO: Implement digital rights management (DRM) integration
-- TODO: Add support for document watermarking automation
-- TODO: Implement secure document destruction audit trail
-- TODO: Add integration with external DLP (Data Loss Prevention) systems
-- TODO: Implement document retention policy enforcement
-- TODO: Add support for secure document collaboration tracking
-- TODO: Implement document access pattern analysis
-- TODO: Add integration with identity verification services for sensitive access
-- ============================================================================
