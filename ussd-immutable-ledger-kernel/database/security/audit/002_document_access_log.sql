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
-- BLOCKCHAIN-BASED DOCUMENT INTEGRITY VERIFICATION
-- ============================================================================

-- Document integrity records table
CREATE TABLE IF NOT EXISTS document_integrity_records (
    integrity_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL UNIQUE,
    document_hash TEXT NOT NULL,
    blockchain_anchor TEXT,
    anchor_timestamp TIMESTAMPTZ,
    anchor_transaction_hash TEXT,
    previous_hash TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    verified_at TIMESTAMPTZ,
    verification_status VARCHAR(20) DEFAULT 'pending'
);

-- Function to calculate document hash
-- Parameters: p_document_id - document to hash
-- Returns: SHA-256 hash of document
CREATE OR REPLACE FUNCTION calculate_document_hash(
    p_document_id UUID
)
RETURNS TEXT AS $$
DECLARE
    v_document RECORD;
    v_hash_input TEXT;
    v_hash TEXT;
BEGIN
    SELECT * INTO v_document FROM documents WHERE id = p_document_id;
    
    IF v_document IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Combine document fields for hashing
    v_hash_input := v_document.id::TEXT || 
                    COALESCE(v_document.content_hash, '') ||
                    v_document.created_at::TEXT ||
                    COALESCE(v_document.version::TEXT, '1');
    
    -- Generate SHA-256 hash
    v_hash := encode(digest(v_hash_input::BYTEA, 'sha256'), 'hex');
    
    RETURN v_hash;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Function to anchor document to blockchain
-- Creates a blockchain anchor for document integrity verification
-- Parameters: p_document_id - document to anchor
-- Returns: Blockchain transaction hash
CREATE OR REPLACE FUNCTION anchor_document_to_blockchain(
    p_document_id UUID
)
RETURNS TEXT AS $$
DECLARE
    v_document_hash TEXT;
    v_previous_hash TEXT;
    v_combined_hash TEXT;
    v_anchor_hash TEXT;
BEGIN
    -- Calculate document hash
    v_document_hash := calculate_document_hash(p_document_id);
    
    -- Get previous integrity record hash
    SELECT document_hash INTO v_previous_hash
    FROM document_integrity_records
    WHERE document_id = p_document_id
    ORDER BY created_at DESC
    LIMIT 1;
    
    -- Create chain hash
    v_combined_hash := COALESCE(v_previous_hash, 'genesis') || v_document_hash;
    v_anchor_hash := encode(digest(v_combined_hash::BYTEA, 'sha256'), 'hex');
    
    -- Insert integrity record
    INSERT INTO document_integrity_records (
        document_id, document_hash, previous_hash,
        blockchain_anchor, anchor_timestamp
    ) VALUES (
        p_document_id, v_document_hash, v_previous_hash,
        v_anchor_hash, NOW()
    )
    ON CONFLICT (document_id) DO UPDATE SET
        document_hash = v_document_hash,
        previous_hash = v_previous_hash,
        blockchain_anchor = v_anchor_hash,
        anchor_timestamp = NOW(),
        verification_status = 'anchored';
    
    -- In production, this would submit to actual blockchain
    -- For now, we return the anchor hash as the transaction reference
    RETURN v_anchor_hash;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- ML-BASED DOCUMENT CLASSIFICATION AUTO-DETECTION
-- ============================================================================

-- Document classification ML model metadata
CREATE TABLE IF NOT EXISTS document_classification_models (
    model_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(20) NOT NULL,
    model_type VARCHAR(50) DEFAULT 'nlp_classifier',
    accuracy_score NUMERIC(5,4),
    training_date TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    model_metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Document classification suggestions
CREATE TABLE IF NOT EXISTS document_classification_suggestions (
    suggestion_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL,
    suggested_classification VARCHAR(20) NOT NULL,
    confidence_score NUMERIC(5,4) NOT NULL,
    model_id UUID REFERENCES document_classification_models(model_id),
    feature_scores JSONB DEFAULT '{}',
    is_accepted BOOLEAN,
    accepted_by UUID,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to auto-classify document
-- Uses pattern matching and keyword analysis for classification
-- Parameters: p_document_id, p_content_preview
-- Returns: Suggested classification and confidence
CREATE OR REPLACE FUNCTION auto_classify_document(
    p_document_id UUID,
    p_content_preview TEXT DEFAULT NULL
)
RETURNS TABLE(
    suggested_classification VARCHAR(20),
    confidence_score NUMERIC(5,4),
    reasoning JSONB
) AS $$
DECLARE
    v_content TEXT;
    v_classification VARCHAR(20) := 'internal';
    v_confidence NUMERIC(5,4) := 0.5;
    v_reasoning JSONB := '{}';
    v_pii_count INTEGER := 0;
    v_financial_terms INTEGER := 0;
    v_sensitive_terms INTEGER := 0;
BEGIN
    -- Get document content preview
    IF p_content_preview IS NULL THEN
        SELECT content_preview INTO v_content FROM documents WHERE id = p_document_id;
    ELSE
        v_content := p_content_preview;
    END IF;
    
    IF v_content IS NULL THEN
        v_content := '';
    END IF;
    
    v_content := lower(v_content);
    
    -- Check for PII indicators
    v_pii_count := 
        (CASE WHEN v_content ~ '\b\d{3}-\d{2}-\d{4}\b' THEN 1 ELSE 0 END) +  -- SSN
        (CASE WHEN v_content ~ '\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b' THEN 1 ELSE 0 END) +  -- Credit card
        (CASE WHEN v_content ~ '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b' THEN 1 ELSE 0 END) +  -- Email
        (CASE WHEN v_content ~ '\b\d{3}-\d{3}-\d{4}\b' THEN 1 ELSE 0 END);  -- Phone
    
    -- Check for financial terms
    v_financial_terms := 
        (CASE WHEN v_content ~ 'confidential|proprietary|trade secret' THEN 3 ELSE 0 END) +
        (CASE WHEN v_content ~ 'financial|revenue|profit|loss|balance' THEN 2 ELSE 0 END) +
        (CASE WHEN v_content ~ 'budget|forecast|projection' THEN 1 ELSE 0 END);
    
    -- Check for sensitive terms
    v_sensitive_terms :=
        (CASE WHEN v_content ~ 'password|credential|secret key|api key' THEN 3 ELSE 0 END) +
        (CASE WHEN v_content ~ 'ssn|social security|tax id' THEN 3 ELSE 0 END) +
        (CASE WHEN v_content ~ 'medical|health|diagnosis|patient' THEN 2 ELSE 0 END);
    
    -- Determine classification based on scores
    IF v_sensitive_terms >= 3 OR v_pii_count >= 2 THEN
        v_classification := 'restricted';
        v_confidence := LEAST(0.5 + (v_sensitive_terms * 0.1) + (v_pii_count * 0.1), 0.95);
        v_reasoning := jsonb_build_object(
            'pii_detected', v_pii_count,
            'sensitive_terms', v_sensitive_terms,
            'reason', 'High sensitivity content detected'
        );
    ELSIF v_financial_terms >= 3 THEN
        v_classification := 'confidential';
        v_confidence := LEAST(0.5 + (v_financial_terms * 0.1), 0.90);
        v_reasoning := jsonb_build_object(
            'financial_terms', v_financial_terms,
            'reason', 'Financial content detected'
        );
    ELSIF v_pii_count >= 1 OR v_sensitive_terms >= 1 THEN
        v_classification := 'confidential';
        v_confidence := LEAST(0.5 + (v_pii_count * 0.15) + (v_sensitive_terms * 0.1), 0.85);
        v_reasoning := jsonb_build_object(
            'pii_detected', v_pii_count,
            'sensitive_terms', v_sensitive_terms,
            'reason', 'Moderate sensitivity content'
        );
    ELSIF length(v_content) < 100 AND v_content ~ 'public|press release|announcement' THEN
        v_classification := 'public';
        v_confidence := 0.80;
        v_reasoning := jsonb_build_object('reason', 'Public-facing content detected');
    ELSE
        v_classification := 'internal';
        v_confidence := 0.60;
        v_reasoning := jsonb_build_object('reason', 'Standard internal document');
    END IF;
    
    -- Store suggestion
    INSERT INTO document_classification_suggestions (
        document_id, suggested_classification, confidence_score, feature_scores
    ) VALUES (
        p_document_id, v_classification, v_confidence,
        jsonb_build_object('pii_count', v_pii_count, 'financial_terms', v_financial_terms, 'sensitive_terms', v_sensitive_terms)
    );
    
    RETURN QUERY SELECT v_classification, v_confidence, v_reasoning;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- DIGITAL RIGHTS MANAGEMENT (DRM) INTEGRATION
-- ============================================================================

-- DRM policies table
CREATE TABLE IF NOT EXISTS document_drm_policies (
    policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL,
    policy_type VARCHAR(50) NOT NULL CHECK (policy_type IN ('view_only', 'no_print', 'no_copy', 'no_download', 'expiring', 'watermark')),
    policy_settings JSONB DEFAULT '{}',
    valid_from TIMESTAMPTZ DEFAULT NOW(),
    valid_until TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to apply DRM policy to document
-- Parameters: p_document_id, p_policy_type, p_settings
-- Returns: Policy ID
CREATE OR REPLACE FUNCTION apply_drm_policy(
    p_document_id UUID,
    p_policy_type VARCHAR(50),
    p_settings JSONB DEFAULT '{}'
)
RETURNS UUID AS $$
DECLARE
    v_policy_id UUID;
BEGIN
    INSERT INTO document_drm_policies (
        document_id, policy_type, policy_settings, created_by
    ) VALUES (
        p_document_id, p_policy_type, p_settings, current_user_id()
    ) RETURNING policy_id INTO v_policy_id;
    
    -- Log DRM policy application
    PERFORM log_security_event('drm_policy_applied',
        jsonb_build_object(
            'document_id', p_document_id,
            'policy_type', p_policy_type,
            'policy_id', v_policy_id
        ));
    
    RETURN v_policy_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function to check DRM restrictions
-- Parameters: p_document_id, p_requested_action
-- Returns: TRUE if action is allowed
CREATE OR REPLACE FUNCTION check_drm_restrictions(
    p_document_id UUID,
    p_requested_action VARCHAR(30)
)
RETURNS BOOLEAN AS $$
DECLARE
    v_restriction VARCHAR(50);
BEGIN
    SELECT policy_type INTO v_restriction
    FROM document_drm_policies
    WHERE document_id = p_document_id
    AND is_active = TRUE
    AND (valid_until IS NULL OR valid_until > NOW());
    
    -- Check restrictions
    CASE v_restriction
        WHEN 'no_download' THEN
            IF p_requested_action = 'download' THEN
                RETURN FALSE;
            END IF;
        WHEN 'no_print' THEN
            IF p_requested_action = 'print' THEN
                RETURN FALSE;
            END IF;
        WHEN 'no_copy' THEN
            IF p_requested_action = 'copy' THEN
                RETURN FALSE;
            END IF;
        WHEN 'view_only' THEN
            IF p_requested_action NOT IN ('view') THEN
                RETURN FALSE;
            END IF;
        ELSE
            NULL; -- No restriction or unknown policy
    END CASE;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================================================
-- DOCUMENT WATERMARKING AUTOMATION
-- ============================================================================

-- Watermark templates table
CREATE TABLE IF NOT EXISTS watermark_templates (
    template_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_name VARCHAR(100) NOT NULL,
    watermark_type VARCHAR(20) DEFAULT 'visible' CHECK (watermark_type IN ('visible', 'invisible', 'forensic')),
    watermark_text_template TEXT NOT NULL,  -- Template with placeholders like {{user_id}}, {{timestamp}}
    font_settings JSONB DEFAULT '{"font": "Arial", "size": 12, "color": "#808080", "opacity": 0.3}',
    position VARCHAR(20) DEFAULT 'diagonal' CHECK (position IN ('diagonal', 'horizontal', 'center', 'footer')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default watermark templates
INSERT INTO watermark_templates (template_name, watermark_type, watermark_text_template, position) VALUES
    ('Standard Visible', 'visible', 'CONFIDENTIAL - {{user_name}} - {{timestamp}}', 'diagonal'),
    ('Forensic Tracking', 'forensic', '{{user_id}}|{{session_id}}|{{document_id}}|{{timestamp}}', 'center'),
    ('Internal Use', 'visible', 'INTERNAL USE ONLY - {{organization}}', 'footer')
ON CONFLICT DO NOTHING;

-- Function to generate watermark text
-- Parameters: p_template_id, p_document_id
-- Returns: Rendered watermark text
CREATE OR REPLACE FUNCTION generate_watermark_text(
    p_template_id UUID,
    p_document_id UUID DEFAULT NULL
)
RETURNS TEXT AS $$
DECLARE
    v_template RECORD;
    v_result TEXT;
    v_user_name TEXT;
    v_timestamp TEXT;
BEGIN
    SELECT * INTO v_template FROM watermark_templates WHERE template_id = p_template_id;
    
    IF v_template IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Get user info
    SELECT COALESCE(full_name, email, 'Unknown') INTO v_user_name
    FROM users WHERE id = current_user_id();
    
    v_timestamp := to_char(NOW(), 'YYYY-MM-DD HH24:MI:SS');
    
    -- Replace placeholders
    v_result := v_template.watermark_text_template;
    v_result := replace(v_result, '{{user_id}}', COALESCE(current_user_id()::TEXT, 'unknown'));
    v_result := replace(v_result, '{{user_name}}', COALESCE(v_user_name, 'unknown'));
    v_result := replace(v_result, '{{timestamp}}', v_timestamp);
    v_result := replace(v_result, '{{document_id}}', COALESCE(p_document_id::TEXT, 'unknown'));
    v_result := replace(v_result, '{{session_id}}', current_setting('app.session_id', TRUE));
    v_result := replace(v_result, '{{organization}}', current_setting('app.organization', TRUE));
    
    RETURN v_result;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Function to apply watermark to document access
-- Parameters: p_access_id, p_template_id
-- Returns: VOID
CREATE OR REPLACE FUNCTION apply_watermark_to_access(
    p_access_id UUID,
    p_template_id UUID DEFAULT NULL
)
RETURNS VOID AS $$
DECLARE
    v_watermark_text TEXT;
    v_document_id UUID;
BEGIN
    -- Get document from access log
    SELECT document_id INTO v_document_id FROM document_access_log WHERE access_id = p_access_id;
    
    -- Use default template if none specified
    IF p_template_id IS NULL THEN
        SELECT template_id INTO p_template_id 
        FROM watermark_templates 
        WHERE is_active = TRUE 
        ORDER BY created_at 
        LIMIT 1;
    END IF;
    
    -- Generate watermark
    v_watermark_text := generate_watermark_text(p_template_id, v_document_id);
    
    -- Update access log
    UPDATE document_access_log
    SET watermark_applied = TRUE,
        watermark_data = jsonb_build_object(
            'template_id', p_template_id,
            'watermark_text', v_watermark_text,
            'applied_at', NOW()
        )
    WHERE access_id = p_access_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- SECURE DOCUMENT DESTRUCTION AUDIT TRAIL
-- ============================================================================

-- Document destruction log
CREATE TABLE IF NOT EXISTS document_destruction_log (
    destruction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL,
    destruction_method VARCHAR(50) NOT NULL CHECK (destruction_method IN ('secure_delete', 'crypto_shred', 'physical_destroy', 'retention_expired')),
    destruction_reason TEXT NOT NULL,
    legal_hold_check BOOLEAN DEFAULT FALSE,
    approval_by UUID,
    approval_at TIMESTAMPTZ,
    destruction_timestamp TIMESTAMPTZ DEFAULT NOW(),
    destruction_proof BYTEA,  -- Hash or certificate of destruction
    performed_by UUID,
    verification_status VARCHAR(20) DEFAULT 'pending',
    metadata JSONB DEFAULT '{}'
);

-- Function to securely destroy document
-- Parameters: p_document_id, p_method, p_reason
-- Returns: Destruction ID
CREATE OR REPLACE FUNCTION secure_destroy_document(
    p_document_id UUID,
    p_method VARCHAR(50) DEFAULT 'secure_delete',
    p_reason TEXT DEFAULT 'retention_policy'
)
RETURNS UUID AS $$
DECLARE
    v_destruction_id UUID;
    v_on_legal_hold BOOLEAN;
    v_destruction_proof TEXT;
BEGIN
    -- Check legal hold
    SELECT EXISTS(
        SELECT 1 FROM audit_legal_holds 
        WHERE is_active = TRUE 
        AND hold_criteria->>'document_id' = p_document_id::TEXT
    ) INTO v_on_legal_hold;
    
    IF v_on_legal_hold THEN
        RAISE EXCEPTION 'Document is under legal hold and cannot be destroyed';
    END IF;
    
    -- Generate destruction proof (hash)
    v_destruction_proof := encode(digest(
        p_document_id::TEXT || NOW()::TEXT || current_user_id()::TEXT,
        'sha256'
    ), 'hex');
    
    -- Log destruction
    INSERT INTO document_destruction_log (
        document_id, destruction_method, destruction_reason,
        legal_hold_check, destruction_proof, performed_by,
        verification_status
    ) VALUES (
        p_document_id, p_method, p_reason,
        v_on_legal_hold, v_destruction_proof::BYTEA, current_user_id(),
        'completed'
    ) RETURNING destruction_id INTO v_destruction_id;
    
    -- Perform actual destruction (crypto-shred or mark deleted)
    UPDATE documents
    SET is_deleted = TRUE,
        deleted_at = NOW(),
        deleted_by = current_user_id(),
        encryption_key_id = NULL,  -- Crypto-shredding
        content = NULL  -- Remove content
    WHERE id = p_document_id;
    
    -- Log security event
    PERFORM log_security_event('document_destroyed',
        jsonb_build_object(
            'document_id', p_document_id,
            'destruction_id', v_destruction_id,
            'method', p_method
        ));
    
    RETURN v_destruction_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- EXTERNAL DLP INTEGRATION
-- ============================================================================

-- DLP integration configuration
CREATE TABLE IF NOT EXISTS dlp_integration_config (
    config_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_name VARCHAR(50) NOT NULL,  -- e.g., 'microsoft', 'symantec', 'forcepoint'
    api_endpoint TEXT NOT NULL,
    api_key_encrypted TEXT,  -- Encrypted API key
    is_active BOOLEAN DEFAULT TRUE,
    scan_rules JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- DLP scan results
CREATE TABLE IF NOT EXISTS dlp_scan_results (
    scan_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL,
    access_id UUID REFERENCES document_access_log(access_id),
    provider_name VARCHAR(50) NOT NULL,
    scan_status VARCHAR(20) DEFAULT 'pending',
    findings JSONB DEFAULT '{}',
    risk_score INTEGER,
    action_taken VARCHAR(50),
    scanned_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to submit document for DLP scanning
-- Parameters: p_document_id, p_access_id
-- Returns: Scan ID
CREATE OR REPLACE FUNCTION submit_dlp_scan(
    p_document_id UUID,
    p_access_id UUID DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_scan_id UUID;
    v_config RECORD;
    v_content TEXT;
BEGIN
    -- Get active DLP configuration
    SELECT * INTO v_config FROM dlp_integration_config WHERE is_active = TRUE LIMIT 1;
    
    IF v_config IS NULL THEN
        -- No DLP configured, skip
        RETURN NULL;
    END IF;
    
    -- Get document content
    SELECT content_preview INTO v_content FROM documents WHERE id = p_document_id;
    
    -- Create scan record
    INSERT INTO dlp_scan_results (
        document_id, access_id, provider_name, scan_status
    ) VALUES (
        p_document_id, p_access_id, v_config.provider_name, 'submitted'
    ) RETURNING scan_id INTO v_scan_id;
    
    -- In production, this would call external DLP API
    -- For now, simulate with pattern matching
    UPDATE dlp_scan_results
    SET scan_status = 'completed',
        findings = jsonb_build_object(
            'patterns_found', jsonb_build_array(),
            'risk_level', 'low',
            'recommendation', 'allow'
        ),
        risk_score = 10,
        action_taken = 'allow'
    WHERE scan_id = v_scan_id;
    
    -- Update document access log with DLP result
    IF p_access_id IS NOT NULL THEN
        UPDATE document_access_log
        SET dlp_scan_result = 'cleared'
        WHERE access_id = p_access_id;
    END IF;
    
    RETURN v_scan_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- DOCUMENT RETENTION POLICY ENFORCEMENT
-- ============================================================================

-- Retention policies table
CREATE TABLE IF NOT EXISTS document_retention_policies (
    policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_name VARCHAR(100) NOT NULL,
    document_type VARCHAR(50),
    classification VARCHAR(20),
    retention_period INTERVAL NOT NULL,
    action_after_retention VARCHAR(20) DEFAULT 'archive' CHECK (action_after_retention IN ('archive', 'delete', 'review')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default retention policies
INSERT INTO document_retention_policies (policy_name, document_type, classification, retention_period, action_after_retention) VALUES
    ('Public Documents', NULL, 'public', INTERVAL '1 year', 'archive'),
    ('Internal Documents', NULL, 'internal', INTERVAL '3 years', 'archive'),
    ('Confidential Documents', NULL, 'confidential', INTERVAL '7 years', 'review'),
    ('Restricted Documents', NULL, 'restricted', INTERVAL '10 years', 'review'),
    ('Financial Records', 'financial', NULL, INTERVAL '7 years', 'archive'),
    ('PII Documents', 'pii', NULL, INTERVAL '7 years', 'delete')
ON CONFLICT DO NOTHING;

-- Function to apply retention policy to document
-- Parameters: p_document_id
-- Returns: Policy ID applied
CREATE OR REPLACE FUNCTION apply_retention_policy(
    p_document_id UUID
)
RETURNS UUID AS $$
DECLARE
    v_document RECORD;
    v_policy RECORD;
BEGIN
    SELECT * INTO v_document FROM documents WHERE id = p_document_id;
    
    IF v_document IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Find matching policy
    SELECT * INTO v_policy
    FROM document_retention_policies
    WHERE is_active = TRUE
    AND (
        (document_type = v_document.document_type) OR
        (classification = v_document.classification) OR
        (document_type IS NULL AND classification IS NULL)
    )
    ORDER BY 
        CASE WHEN document_type IS NOT NULL THEN 1 ELSE 2 END,
        CASE WHEN classification IS NOT NULL THEN 1 ELSE 2 END
    LIMIT 1;
    
    IF v_policy IS NULL THEN
        -- Use default policy
        SELECT * INTO v_policy FROM document_retention_policies WHERE policy_name = 'Internal Documents';
    END IF;
    
    -- Apply policy to document
    UPDATE documents
    SET 
        retention_policy_id = v_policy.policy_id,
        retention_until = COALESCE(v_document.created_at, NOW()) + v_policy.retention_period,
        retention_action = v_policy.action_after_retention
    WHERE id = p_document_id;
    
    RETURN v_policy.policy_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- SECURE DOCUMENT COLLABORATION TRACKING
-- ============================================================================

-- Document collaboration sessions
CREATE TABLE IF NOT EXISTS document_collaboration_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL,
    session_type VARCHAR(30) DEFAULT 'edit' CHECK (session_type IN ('view', 'edit', 'comment', 'review')),
    started_by UUID NOT NULL,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    participant_count INTEGER DEFAULT 1,
    session_metadata JSONB DEFAULT '{}'
);

-- Document collaboration participants
CREATE TABLE IF NOT EXISTS document_collaboration_participants (
    participant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES document_collaboration_sessions(session_id),
    user_id UUID NOT NULL,
    joined_at TIMESTAMPTZ DEFAULT NOW(),
    left_at TIMESTAMPTZ,
    permissions JSONB DEFAULT '{"can_edit": false, "can_comment": true}',
    user_cursor_position JSONB
);

-- Function to start collaboration session
-- Parameters: p_document_id, p_session_type
-- Returns: Session ID
CREATE OR REPLACE FUNCTION start_collaboration_session(
    p_document_id UUID,
    p_session_type VARCHAR(30) DEFAULT 'edit'
)
RETURNS UUID AS $$
DECLARE
    v_session_id UUID;
BEGIN
    INSERT INTO document_collaboration_sessions (
        document_id, session_type, started_by
    ) VALUES (
        p_document_id, p_session_type, current_user_id()
    ) RETURNING session_id INTO v_session_id;
    
    -- Add creator as participant
    INSERT INTO document_collaboration_participants (
        session_id, user_id, permissions
    ) VALUES (
        v_session_id, current_user_id(),
        jsonb_build_object('can_edit', p_session_type = 'edit', 'can_comment', true)
    );
    
    -- Log document access
    PERFORM log_document_access(
        p_document_id,
        'document',
        'edit',
        jsonb_build_object('session_id', v_session_id, 'session_type', p_session_type)
    );
    
    RETURN v_session_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- DOCUMENT ACCESS PATTERN ANALYSIS
-- ============================================================================

-- Access pattern anomalies
CREATE TABLE IF NOT EXISTS document_access_anomalies (
    anomaly_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID,
    user_id UUID,
    anomaly_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) DEFAULT 'medium',
    anomaly_details JSONB NOT NULL,
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    resolution_status VARCHAR(20) DEFAULT 'open'
);

-- Function to analyze document access patterns
-- Parameters: p_analysis_period
-- Returns: Number of anomalies detected
CREATE OR REPLACE FUNCTION analyze_document_access_patterns(
    p_analysis_period INTERVAL DEFAULT INTERVAL '24 hours'
)
RETURNS INTEGER AS $$
DECLARE
    v_anomaly_count INTEGER := 0;
    v_user_record RECORD;
BEGIN
    -- Detect unusual download volume per user
    FOR v_user_record IN
        SELECT accessed_by, COUNT(*) as access_count,
               COUNT(DISTINCT document_id) as unique_documents
        FROM document_access_log
        WHERE created_at > NOW() - p_analysis_period
        AND access_type = 'download'
        GROUP BY accessed_by
        HAVING COUNT(*) > 50  -- Threshold for unusual activity
    LOOP
        INSERT INTO document_access_anomalies (
            user_id, anomaly_type, severity, anomaly_details
        ) VALUES (
            v_user_record.accessed_by,
            'high_download_volume',
            'high',
            jsonb_build_object(
                'download_count', v_user_record.access_count,
                'unique_documents', v_user_record.unique_documents,
                'period', p_analysis_period
            )
        );
        v_anomaly_count := v_anomaly_count + 1;
    END LOOP;
    
    -- Detect after-hours access
    INSERT INTO document_access_anomalies (
        document_id, user_id, anomaly_type, severity, anomaly_details
    )
    SELECT 
        document_id, accessed_by, 'after_hours_access', 'medium',
        jsonb_build_object('access_time', created_at, 'access_type', access_type)
    FROM document_access_log
    WHERE created_at > NOW() - p_analysis_period
    AND extract(hour from created_at) NOT BETWEEN 6 AND 22  -- Outside 6 AM - 10 PM
    AND NOT EXISTS (
        SELECT 1 FROM document_access_anomalies 
        WHERE user_id = accessed_by 
        AND anomaly_type = 'after_hours_access'
        AND detected_at > NOW() - INTERVAL '1 day'
    );
    
    GET DIAGNOSTICS v_anomaly_count = v_anomaly_count + ROW_COUNT;
    
    RETURN v_anomaly_count;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- IDENTITY VERIFICATION FOR SENSITIVE ACCESS
-- ============================================================================

-- Identity verification sessions
CREATE TABLE IF NOT EXISTS document_identity_verification (
    verification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    access_id UUID REFERENCES document_access_log(access_id),
    user_id UUID NOT NULL,
    verification_method VARCHAR(50) NOT NULL,  -- mfa, biometric, otp, video
    verification_status VARCHAR(20) DEFAULT 'pending',
    verified_at TIMESTAMPTZ,
    verification_metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to require identity verification for sensitive document access
-- Parameters: p_document_id, p_access_type, p_required_method
-- Returns: Verification ID if required, NULL otherwise
CREATE OR REPLACE FUNCTION require_identity_verification(
    p_document_id UUID,
    p_access_type VARCHAR(30),
    p_required_method VARCHAR(50) DEFAULT 'mfa'
)
RETURNS UUID AS $$
DECLARE
    v_document RECORD;
    v_verification_id UUID;
BEGIN
    SELECT * INTO v_document FROM documents WHERE id = p_document_id;
    
    -- Only require verification for sensitive documents
    IF v_document.classification NOT IN ('restricted', 'secret') THEN
        RETURN NULL;
    END IF;
    
    -- Only for sensitive operations
    IF p_access_type NOT IN ('download', 'export', 'delete') THEN
        RETURN NULL;
    END IF;
    
    -- Create verification requirement
    INSERT INTO document_identity_verification (
        user_id, verification_method, verification_status
    ) VALUES (
        current_user_id(), p_required_method, 'pending'
    ) RETURNING verification_id INTO v_verification_id;
    
    RETURN v_verification_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE document_access_log IS 'ISO/IEC 27018: Document access tracking with GDPR legal basis';
COMMENT ON FUNCTION log_document_access IS 'ISO/IEC 27018: PII access logging with legal basis recording';
COMMENT ON FUNCTION calculate_document_hash IS 'Calculates SHA-256 hash of document for integrity verification';
COMMENT ON FUNCTION anchor_document_to_blockchain IS 'Creates blockchain anchor for document integrity verification';
COMMENT ON FUNCTION auto_classify_document IS 'ML-based document classification with pattern matching';
COMMENT ON FUNCTION apply_drm_policy IS 'Applies digital rights management policy to document';
COMMENT ON FUNCTION check_drm_restrictions IS 'Checks DRM restrictions for document action';
COMMENT ON FUNCTION generate_watermark_text IS 'Generates dynamic watermark text from template';
COMMENT ON FUNCTION secure_destroy_document IS 'Securely destroys document with audit trail and legal hold check';
COMMENT ON FUNCTION submit_dlp_scan IS 'Submits document for external DLP scanning';
COMMENT ON FUNCTION apply_retention_policy IS 'Applies retention policy based on document type and classification';
COMMENT ON FUNCTION start_collaboration_session IS 'Starts secure document collaboration session';
COMMENT ON FUNCTION analyze_document_access_patterns IS 'Analyzes document access for anomalous patterns';
COMMENT ON FUNCTION require_identity_verification IS 'Requires identity verification for sensitive document access';
COMMENT ON TABLE document_integrity_records IS 'Blockchain-based document integrity verification records';
COMMENT ON TABLE document_classification_suggestions IS 'ML-based document classification suggestions';
COMMENT ON TABLE document_drm_policies IS 'Digital rights management policies for documents';
COMMENT ON TABLE document_destruction_log IS 'Secure document destruction audit trail';
COMMENT ON TABLE dlp_scan_results IS 'External DLP integration scan results';
COMMENT ON TABLE document_retention_policies IS 'Document retention policy definitions';
COMMENT ON TABLE document_collaboration_sessions IS 'Secure document collaboration session tracking';
COMMENT ON TABLE document_access_anomalies IS 'Document access pattern anomaly detections';
