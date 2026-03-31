-- =============================================================================
-- CERTIFICATE MANAGEMENT
-- TLS certificate lifecycle management for secure connections
-- =============================================================================

-- =============================================================================
-- CERTIFICATE SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS cert_mgmt;

COMMENT ON SCHEMA cert_mgmt IS 'TLS certificate lifecycle management';

-- =============================================================================
-- CERTIFICATE STORE
-- =============================================================================
CREATE TABLE IF NOT EXISTS cert_mgmt.certificates (
    id SERIAL PRIMARY KEY,
    cert_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    cert_name VARCHAR(200) NOT NULL,
    cert_type VARCHAR(50) NOT NULL, -- SERVER, CLIENT, CA, INTERMEDIATE
    
    -- Certificate details
    common_name VARCHAR(255) NOT NULL,
    subject_alt_names TEXT[],
    
    -- Validity
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    
    -- Certificate data (encrypted at rest in production)
    cert_fingerprint_sha256 VARCHAR(64) NOT NULL,
    cert_reference VARCHAR(500) NOT NULL, -- Reference to secure storage
    private_key_reference VARCHAR(500), -- Reference to private key in HSM/vault
    
    -- Issuer info
    issuer_cert_id UUID REFERENCES cert_mgmt.certificates(cert_id),
    serial_number VARCHAR(100),
    
    -- State
    cert_state VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, EXPIRING, EXPIRED, REVOKED, RENEWING
    
    -- Renewal settings
    auto_renewal_enabled BOOLEAN DEFAULT TRUE,
    renewal_days_before INTEGER DEFAULT 30,
    renewed_by_cert_id UUID REFERENCES cert_mgmt.certificates(cert_id),
    
    -- Metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by VARCHAR(100) DEFAULT current_user,
    description TEXT,
    
    UNIQUE(cert_name, cert_type)
);

CREATE INDEX IF NOT EXISTS idx_certs_state 
ON cert_mgmt.certificates(cert_state) WHERE cert_state IN ('ACTIVE', 'EXPIRING');

CREATE INDEX IF NOT EXISTS idx_certs_expiry 
ON cert_mgmt.certificates(valid_until);

-- =============================================================================
-- CERTIFICATE USAGE LOG
-- =============================================================================
CREATE TABLE IF NOT EXISTS cert_mgmt.cert_usage_log (
    id BIGSERIAL PRIMARY KEY,
    cert_id UUID NOT NULL REFERENCES cert_mgmt.certificates(cert_id),
    usage_type VARCHAR(50) NOT NULL, -- TLS_HANDSHAKE, RENEWAL, REVOCATION_CHECK
    peer_address INET,
    success BOOLEAN DEFAULT TRUE,
    error_code VARCHAR(50),
    error_message TEXT,
    used_at TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB
);

-- =============================================================================
-- DEFAULT CERTIFICATES (templates)
-- =============================================================================
INSERT INTO cert_mgmt.certificates (
    cert_name, cert_type, common_name, subject_alt_names,
    valid_from, valid_until, cert_fingerprint_sha256, cert_reference,
    auto_renewal_enabled, description
) VALUES 
(
    'server-primary', 'SERVER',
    'db.ledger.internal',
    ARRAY['db.ledger.internal', '*.db.ledger.internal', 'localhost'],
    NOW(), NOW() + INTERVAL '1 year',
    'placeholder_fingerprint_to_be_replaced',
    'vault://pki/ledger/server-primary',
    TRUE,
    'Primary database server certificate'
),
(
    'client-app-primary', 'CLIENT',
    'ledger-app',
    ARRAY['ledger-app'],
    NOW(), NOW() + INTERVAL '1 year',
    'placeholder_fingerprint_to_be_replaced',
    'vault://pki/ledger/client-app-primary',
    TRUE,
    'Primary application client certificate'
),
(
    'ca-internal', 'CA',
    'Ledger Internal CA',
    ARRAY[],
    NOW(), NOW() + INTERVAL '10 years',
    'placeholder_fingerprint_to_be_replaced',
    'vault://pki/ledger/ca-internal',
    FALSE,
    'Internal certificate authority'
)
ON CONFLICT (cert_name, cert_type) DO UPDATE SET
    valid_until = EXCLUDED.valid_until,
    updated_at = NOW();

-- =============================================================================
-- FUNCTION: Register new certificate
-- =============================================================================
CREATE OR REPLACE FUNCTION cert_mgmt.register_certificate(
    p_cert_name VARCHAR,
    p_cert_type VARCHAR,
    p_common_name VARCHAR,
    p_valid_from TIMESTAMPTZ,
    p_valid_until TIMESTAMPTZ,
    p_fingerprint_sha256 VARCHAR,
    p_cert_reference VARCHAR,
    p_subject_alt_names TEXT[] DEFAULT NULL,
    p_issuer_cert_id UUID DEFAULT NULL,
    p_auto_renewal BOOLEAN DEFAULT TRUE,
    p_description TEXT DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_cert_id UUID := gen_random_uuid();
BEGIN
    INSERT INTO cert_mgmt.certificates (
        cert_id, cert_name, cert_type, common_name, subject_alt_names,
        valid_from, valid_until, cert_fingerprint_sha256, cert_reference,
        issuer_cert_id, auto_renewal_enabled, description
    ) VALUES (
        v_cert_id, p_cert_name, p_cert_type, p_common_name, p_subject_alt_names,
        p_valid_from, p_valid_until, p_fingerprint_sha256, p_cert_reference,
        p_issuer_cert_id, p_auto_renewal, p_description
    );
    
    RETURN v_cert_id;
EXCEPTION WHEN unique_violation THEN
    -- Update existing certificate (new version)
    UPDATE cert_mgmt.certificates
    SET cert_state = 'RENEWED',
        valid_until = NOW(),
        updated_at = NOW()
    WHERE cert_name = p_cert_name 
      AND cert_type = p_cert_type
      AND cert_state = 'ACTIVE';
    
    -- Insert new version
    INSERT INTO cert_mgmt.certificates (
        cert_id, cert_name, cert_type, common_name, subject_alt_names,
        valid_from, valid_until, cert_fingerprint_sha256, cert_reference,
        issuer_cert_id, auto_renewal_enabled, description
    ) VALUES (
        v_cert_id, p_cert_name, p_cert_type, p_common_name, p_subject_alt_names,
        p_valid_from, p_valid_until, p_fingerprint_sha256, p_cert_reference,
        p_issuer_cert_id, p_auto_renewal, p_description
    );
    
    RETURN v_cert_id;
END;
$$;

-- =============================================================================
-- FUNCTION: Get active certificate
-- =============================================================================
CREATE OR REPLACE FUNCTION cert_mgmt.get_active_certificate(
    p_cert_name VARCHAR,
    p_cert_type VARCHAR DEFAULT NULL
)
RETURNS TABLE(
    cert_id UUID,
    cert_reference VARCHAR,
    valid_until TIMESTAMPTZ,
    fingerprint VARCHAR
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        c.cert_id,
        c.cert_reference::VARCHAR(500),
        c.valid_until,
        c.cert_fingerprint_sha256::VARCHAR(64)
    FROM cert_mgmt.certificates c
    WHERE c.cert_name = p_cert_name
      AND (p_cert_type IS NULL OR c.cert_type = p_cert_type)
      AND c.cert_state IN ('ACTIVE', 'EXPIRING')
      AND c.valid_from <= NOW()
      AND c.valid_until > NOW()
    ORDER BY c.valid_from DESC
    LIMIT 1;
END;
$$;

-- =============================================================================
-- FUNCTION: Update certificate state
-- =============================================================================
CREATE OR REPLACE FUNCTION cert_mgmt.update_cert_state()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER := 0;
BEGIN
    -- Mark expiring certificates
    UPDATE cert_mgmt.certificates
    SET cert_state = 'EXPIRING',
        updated_at = NOW()
    WHERE cert_state = 'ACTIVE'
      AND auto_renewal_enabled = TRUE
      AND valid_until <= NOW() + (renewal_days_before || ' days')::INTERVAL
      AND valid_until > NOW();
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    
    -- Mark expired certificates
    UPDATE cert_mgmt.certificates
    SET cert_state = 'EXPIRED',
        updated_at = NOW()
    WHERE cert_state IN ('ACTIVE', 'EXPIRING')
      AND valid_until <= NOW();
    
    GET DIAGNOSTICS v_count = v_count + ROW_COUNT;
    
    RETURN v_count;
END;
$$;

-- =============================================================================
-- FUNCTION: Revoke certificate
-- =============================================================================
CREATE OR REPLACE FUNCTION cert_mgmt.revoke_certificate(
    p_cert_id UUID,
    p_reason TEXT DEFAULT NULL
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE cert_mgmt.certificates
    SET cert_state = 'REVOKED',
        valid_until = NOW(),
        updated_at = NOW(),
        description = COALESCE(description || '; Revoked: ' || p_reason, 'Revoked: ' || p_reason)
    WHERE cert_id = p_cert_id;
    
    IF FOUND THEN
        -- Log revocation
        INSERT INTO cert_mgmt.cert_usage_log (
            cert_id, usage_type, success, metadata
        ) VALUES (
            p_cert_id, 'REVOCATION_CHECK', TRUE,
            jsonb_build_object('reason', p_reason, 'action', 'REVOKED')
        );
        
        RETURN format('SUCCESS: Certificate %s revoked', p_cert_id);
    ELSE
        RETURN format('ERROR: Certificate %s not found', p_cert_id);
    END IF;
END;
$$;

-- =============================================================================
-- FUNCTION: Check certificate expiry status
-- =============================================================================
CREATE OR REPLACE FUNCTION cert_mgmt.check_expiry_status()
RETURNS TABLE(
    cert_name VARCHAR,
    cert_type VARCHAR,
    common_name VARCHAR,
    days_until_expiry INTEGER,
    cert_state VARCHAR,
    action_required TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
    -- Update states first
    PERFORM cert_mgmt.update_cert_state();
    
    RETURN QUERY
    SELECT 
        c.cert_name::VARCHAR(200),
        c.cert_type::VARCHAR(50),
        c.common_name::VARCHAR(255),
        EXTRACT(DAY FROM (c.valid_until - NOW()))::INTEGER as days_until_expiry,
        c.cert_state::VARCHAR(20),
        CASE 
            WHEN c.cert_state = 'EXPIRED' THEN 'IMMEDIATE: Certificate expired, replace now'
            WHEN c.cert_state = 'EXPIRING' AND c.auto_renewal_enabled THEN 'AUTO: Renewal in progress'
            WHEN c.cert_state = 'EXPIRING' THEN 'MANUAL: Schedule renewal'
            WHEN c.valid_until <= NOW() + INTERVAL '14 days' THEN 'WARNING: Plan renewal'
            ELSE 'OK: Certificate valid'
        END as action_required
    FROM cert_mgmt.certificates c
    WHERE c.cert_state IN ('ACTIVE', 'EXPIRING')
       OR (c.cert_state = 'EXPIRED' AND c.valid_until > NOW() - INTERVAL '7 days')
    ORDER BY c.valid_until;
END;
$$;

-- =============================================================================
-- FUNCTION: Get certificates needing renewal
-- =============================================================================
CREATE OR REPLACE FUNCTION cert_mgmt.get_renewal_candidates()
RETURNS TABLE(
    cert_id UUID,
    cert_name VARCHAR,
    cert_type VARCHAR,
    common_name VARCHAR,
    valid_until TIMESTAMPTZ,
    renewal_priority INTEGER
)
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM cert_mgmt.update_cert_state();
    
    RETURN QUERY
    SELECT 
        c.cert_id,
        c.cert_name::VARCHAR(200),
        c.cert_type::VARCHAR(50),
        c.common_name::VARCHAR(255),
        c.valid_until,
        CASE 
            WHEN c.cert_state = 'EXPIRED' THEN 1
            WHEN c.valid_until <= NOW() + INTERVAL '3 days' THEN 2
            WHEN c.valid_until <= NOW() + INTERVAL '7 days' THEN 3
            ELSE 4
        END as renewal_priority
    FROM cert_mgmt.certificates c
    WHERE c.auto_renewal_enabled = TRUE
      AND c.cert_state IN ('ACTIVE', 'EXPIRING', 'EXPIRED')
      AND (c.renewed_by_cert_id IS NULL OR c.cert_state = 'EXPIRED')
    ORDER BY renewal_priority, c.valid_until;
END;
$$;

-- =============================================================================
-- FUNCTION: Validate certificate chain
-- =============================================================================
CREATE OR REPLACE FUNCTION cert_mgmt.validate_chain(p_cert_id UUID)
RETURNS TABLE(
    cert_name VARCHAR,
    cert_type VARCHAR,
    valid BOOLEAN,
    chain_depth INTEGER,
    error_message TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_cert RECORD;
    v_depth INTEGER := 0;
    v_valid BOOLEAN := TRUE;
    v_error TEXT;
BEGIN
    -- Get starting certificate
    SELECT * INTO v_cert FROM cert_mgmt.certificates WHERE cert_id = p_cert_id;
    
    IF NOT FOUND THEN
        cert_name := 'NOT_FOUND';
        cert_type := 'UNKNOWN';
        valid := FALSE;
        chain_depth := 0;
        error_message := 'Certificate not found';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Walk the chain
    LOOP
        cert_name := v_cert.cert_name::VARCHAR(200);
        cert_type := v_cert.cert_type::VARCHAR(50);
        valid := v_cert.cert_state = 'ACTIVE' 
             AND v_cert.valid_from <= NOW() 
             AND v_cert.valid_until > NOW();
        chain_depth := v_depth;
        error_message := v_error;
        
        RETURN NEXT;
        
        EXIT WHEN v_cert.issuer_cert_id IS NULL;
        
        SELECT * INTO v_cert 
        FROM cert_mgmt.certificates 
        WHERE cert_id = v_cert.issuer_cert_id;
        
        IF NOT FOUND THEN
            v_valid := FALSE;
            v_error := 'Issuer certificate not found';
            EXIT;
        END IF;
        
        v_depth := v_depth + 1;
        
        -- Prevent infinite loops
        IF v_depth > 10 THEN
            v_valid := FALSE;
            v_error := 'Chain too deep or circular reference';
            EXIT;
        END IF;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Log TLS connection
-- =============================================================================
CREATE OR REPLACE FUNCTION cert_mgmt.log_tls_connection(
    p_cert_id UUID,
    p_peer_address INET,
    p_success BOOLEAN,
    p_error_message TEXT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO cert_mgmt.cert_usage_log (
        cert_id, usage_type, peer_address, success, error_message
    ) VALUES (
        p_cert_id, 'TLS_HANDSHAKE', p_peer_address, p_success, p_error_message
    );
END;
$$;

-- =============================================================================
-- VIEW: Certificate inventory
-- =============================================================================
CREATE OR REPLACE VIEW cert_mgmt.certificate_inventory AS
SELECT 
    c.cert_id,
    c.cert_name,
    c.cert_type,
    c.common_name,
    array_to_string(c.subject_alt_names, ', ') as san_list,
    c.valid_from,
    c.valid_until,
    c.cert_state,
    EXTRACT(DAY FROM (c.valid_until - NOW()))::INTEGER as days_until_expiry,
    c.auto_renewal_enabled,
    substring(c.cert_fingerprint_sha256, 1, 16) || '...' as fingerprint_short,
    ic.cert_name as issuer_name,
    c.serial_number,
    c.created_at,
    c.description
FROM cert_mgmt.certificates c
LEFT JOIN cert_mgmt.certificates ic ON ic.cert_id = c.issuer_cert_id
ORDER BY c.cert_type, c.valid_until;

-- =============================================================================
-- VIEW: Certificate usage statistics
-- =============================================================================
CREATE OR REPLACE VIEW cert_mgmt.usage_stats AS
SELECT 
    c.cert_id,
    c.cert_name,
    c.cert_type,
    COUNT(cul.id) as total_uses,
    COUNT(cul.id) FILTER (WHERE cul.success = FALSE) as failed_uses,
    MAX(cul.used_at) as last_used_at,
    COUNT(cul.id) FILTER (WHERE cul.used_at > NOW() - INTERVAL '24 hours') as uses_24h,
    COUNT(cul.id) FILTER (WHERE cul.used_at > NOW() - INTERVAL '7 days') as uses_7d
FROM cert_mgmt.certificates c
LEFT JOIN cert_mgmt.cert_usage_log cul ON cul.cert_id = c.cert_id
WHERE c.cert_state IN ('ACTIVE', 'EXPIRING')
GROUP BY c.cert_id, c.cert_name, c.cert_type;

-- =============================================================================
-- TRIGGER: Update timestamp
-- =============================================================================
CREATE TRIGGER trigger_certs_updated
    BEFORE UPDATE ON cert_mgmt.certificates
    FOR EACH ROW EXECUTE FUNCTION encryption.update_timestamp();

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA cert_mgmt TO cert_admin;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA cert_mgmt TO cert_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA cert_mgmt TO cert_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA cert_mgmt TO cert_admin;
