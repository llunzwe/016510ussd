-- =============================================================================
-- TLS CONFIGURATION
-- TLS/SSL configuration and connection security
-- =============================================================================

-- =============================================================================
-- TLS SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS tls_config;

COMMENT ON SCHEMA tls_config IS 'TLS/SSL configuration management';

-- =============================================================================
-- TLS CONFIGURATION TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS tls_config.settings (
    id SERIAL PRIMARY KEY,
    setting_name VARCHAR(100) NOT NULL UNIQUE,
    setting_value TEXT NOT NULL,
    setting_category VARCHAR(50) NOT NULL, -- CONNECTION, CERTIFICATE, CIPHER, PROTOCOL
    is_active BOOLEAN DEFAULT TRUE,
    requires_restart BOOLEAN DEFAULT FALSE,
    description TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by VARCHAR(100) DEFAULT current_user
);

-- =============================================================================
-- TLS CONNECTION RULES
-- =============================================================================
CREATE TABLE IF NOT EXISTS tls_config.connection_rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(100) NOT NULL UNIQUE,
    
    -- Matching criteria
    source_cidr CIDR,
    database_name VARCHAR(63),
    user_pattern VARCHAR(100), -- Regex for username matching
    application_name VARCHAR(100),
    
    -- TLS requirements
    ssl_mode VARCHAR(20) NOT NULL DEFAULT 'require', -- disable, allow, prefer, require, verify-ca, verify-full
    min_tls_version VARCHAR(10) DEFAULT '1.2',
    require_client_cert BOOLEAN DEFAULT FALSE,
    
    -- Certificate requirements
    allowed_cns TEXT[], -- Allowed Common Names
    allowed_ous TEXT[], -- Allowed Organizational Units
    
    -- Action
    action VARCHAR(20) DEFAULT 'ALLOW', -- ALLOW, REJECT, LOG
    log_level VARCHAR(20) DEFAULT 'INFO',
    
    is_active BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 100, -- Lower = higher priority
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================================================
-- CIPHER SUITES
-- =============================================================================
CREATE TABLE IF NOT EXISTS tls_config.cipher_suites (
    id SERIAL PRIMARY KEY,
    cipher_name VARCHAR(100) NOT NULL UNIQUE,
    openssl_name VARCHAR(100),
    iana_name VARCHAR(100),
    key_exchange VARCHAR(50),
    authentication VARCHAR(50),
    encryption_algorithm VARCHAR(50),
    hash_algorithm VARCHAR(50),
    
    -- Security assessment
    is_secure BOOLEAN DEFAULT TRUE,
    security_level VARCHAR(20) DEFAULT 'HIGH', -- HIGH, MEDIUM, LOW, BROKEN
    vulnerabilities TEXT[],
    
    -- Configuration
    is_enabled BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 100,
    
    notes TEXT
);

-- =============================================================================
-- DEFAULT TLS SETTINGS
-- =============================================================================
INSERT INTO tls_config.settings (setting_name, setting_value, setting_category, requires_restart, description) VALUES
    ('ssl', 'on', 'CONNECTION', TRUE, 'Enable SSL connections'),
    ('ssl_min_protocol_version', 'TLSv1.2', 'PROTOCOL', TRUE, 'Minimum TLS version'),
    ('ssl_max_protocol_version', 'TLSv1.3', 'PROTOCOL', TRUE, 'Maximum TLS version'),
    ('ssl_cert_file', '/etc/ssl/certs/server.crt', 'CERTIFICATE', TRUE, 'Server certificate file'),
    ('ssl_key_file', '/etc/ssl/private/server.key', 'CERTIFICATE', TRUE, 'Server private key file'),
    ('ssl_ca_file', '/etc/ssl/certs/ca.crt', 'CERTIFICATE', TRUE, 'CA certificate file'),
    ('ssl_crl_file', '/etc/ssl/certs/ca.crl', 'CERTIFICATE', TRUE, 'Certificate revocation list'),
    ('ssl_ciphers', 'HIGH:!aNULL:!MD5', 'CIPHER', FALSE, 'Allowed SSL ciphers'),
    ('ssl_prefer_server_ciphers', 'on', 'CIPHER', FALSE, 'Prefer server ciphers'),
    ('ssl_ecdh_curve', 'prime256v1', 'CIPHER', TRUE, 'ECDH curve to use'),
    ('ssl_dh_params_file', '/etc/ssl/dhparams.pem', 'CERTIFICATE', TRUE, 'DH parameters file')
ON CONFLICT (setting_name) DO UPDATE SET
    setting_value = EXCLUDED.setting_value,
    updated_at = NOW();

-- =============================================================================
-- DEFAULT CONNECTION RULES
-- =============================================================================
INSERT INTO tls_config.connection_rules (
    rule_name, source_cidr, ssl_mode, min_tls_version, 
    require_client_cert, action, priority, description
) VALUES 
(
    'require_tls_all', '0.0.0.0/0', 'require', '1.2',
    FALSE, 'ALLOW', 100, 'Require TLS for all connections'
),
(
    'strict_tls_internal', '10.0.0.0/8', 'verify-full', '1.3',
    TRUE, 'ALLOW', 50, 'Strict TLS for internal network'
),
(
    'deny_clear_text', '0.0.0.0/0', 'disable', '1.0',
    FALSE, 'REJECT', 10, 'Reject clear text connections'
)
ON CONFLICT (rule_name) DO UPDATE SET
    ssl_mode = EXCLUDED.ssl_mode,
    min_tls_version = EXCLUDED.min_tls_version;

-- =============================================================================
-- DEFAULT CIPHER SUITES
-- =============================================================================
INSERT INTO tls_config.cipher_suites (
    cipher_name, openssl_name, key_exchange, encryption_algorithm, 
    hash_algorithm, is_secure, security_level, is_enabled, priority
) VALUES 
('TLS_AES_256_GCM_SHA384', 'TLS_AES_256_GCM_SHA384', 'ECDHE', 'AES-256-GCM', 'SHA384', TRUE, 'HIGH', TRUE, 1),
('TLS_CHACHA20_POLY1305_SHA256', 'TLS_CHACHA20_POLY1305_SHA256', 'ECDHE', 'ChaCha20-Poly1305', 'SHA256', TRUE, 'HIGH', TRUE, 2),
('TLS_AES_128_GCM_SHA256', 'TLS_AES_128_GCM_SHA256', 'ECDHE', 'AES-128-GCM', 'SHA256', TRUE, 'HIGH', TRUE, 3),
('ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE', 'AES-256-GCM', 'SHA384', TRUE, 'HIGH', TRUE, 4),
('ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE', 'AES-256-GCM', 'SHA384', TRUE, 'HIGH', TRUE, 5),
('ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE', 'AES-128-GCM', 'SHA256', TRUE, 'HIGH', TRUE, 6),
('DHE-RSA-AES256-GCM-SHA384', 'DHE-RSA-AES256-GCM-SHA384', 'DHE', 'AES-256-GCM', 'SHA384', TRUE, 'HIGH', TRUE, 10),
('ECDHE-RSA-AES256-SHA384', 'ECDHE-RSA-AES256-SHA384', 'ECDHE', 'AES-256-CBC', 'SHA384', TRUE, 'MEDIUM', FALSE, 20)
ON CONFLICT (cipher_name) DO UPDATE SET
    is_enabled = EXCLUDED.is_enabled,
    priority = EXCLUDED.priority;

-- =============================================================================
-- FUNCTION: Get effective SSL mode for connection
-- =============================================================================
CREATE OR REPLACE FUNCTION tls_config.get_ssl_mode(
    p_client_addr INET,
    p_database VARCHAR,
    p_username VARCHAR,
    p_application_name VARCHAR DEFAULT NULL
)
RETURNS TABLE(
    ssl_mode VARCHAR,
    min_tls_version VARCHAR,
    require_client_cert BOOLEAN,
    action VARCHAR
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_rule RECORD;
BEGIN
    -- Find matching rule (highest priority first)
    SELECT * INTO v_rule
    FROM tls_config.connection_rules
    WHERE is_active = TRUE
      AND (source_cidr IS NULL OR p_client_addr << source_cidr)
      AND (database_name IS NULL OR database_name = p_database)
      AND (user_pattern IS NULL OR p_username ~ user_pattern)
      AND (application_name IS NULL OR application_name = p_application_name)
    ORDER BY priority
    LIMIT 1;
    
    IF FOUND THEN
        ssl_mode := v_rule.ssl_mode;
        min_tls_version := v_rule.min_tls_version;
        require_client_cert := v_rule.require_client_cert;
        action := v_rule.action;
    ELSE
        -- Default: require TLS
        ssl_mode := 'require';
        min_tls_version := '1.2';
        require_client_cert := FALSE;
        action := 'ALLOW';
    END IF;
    
    RETURN NEXT;
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Generate pg_hba.conf SSL entries
-- =============================================================================
CREATE OR REPLACE FUNCTION tls_config.generate_hba_entries()
RETURNS TABLE(entry_text TEXT, comment TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_rule RECORD;
    v_entry TEXT;
BEGIN
    -- Header
    entry_text := '# TLS Connection Rules - Generated ' || NOW()::TEXT;
    comment := 'Header';
    RETURN NEXT;
    
    FOR v_rule IN 
        SELECT * FROM tls_config.connection_rules 
        WHERE is_active = TRUE 
        ORDER BY priority
    LOOP
        IF v_rule.source_cidr IS NOT NULL THEN
            v_entry := format('hostssl all all %s %s',
                v_rule.source_cidr,
                CASE v_rule.ssl_mode
                    WHEN 'disable' THEN 'reject'
                    WHEN 'allow' THEN 'md5'
                    WHEN 'prefer' THEN 'md5'
                    WHEN 'require' THEN 'md5'
                    WHEN 'verify-ca' THEN 'cert'
                    WHEN 'verify-full' THEN 'cert'
                    ELSE 'md5'
                END
            );
            
            entry_text := v_entry;
            comment := v_rule.rule_name;
            RETURN NEXT;
        END IF;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Validate TLS settings
-- =============================================================================
CREATE OR REPLACE FUNCTION tls_config.validate_settings()
RETURNS TABLE(
    setting_name VARCHAR,
    setting_value TEXT,
    is_valid BOOLEAN,
    warning_message TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_setting RECORD;
    v_valid BOOLEAN;
    v_warning TEXT;
BEGIN
    FOR v_setting IN SELECT * FROM tls_config.settings WHERE is_active = TRUE LOOP
        setting_name := v_setting.setting_name::VARCHAR(100);
        setting_value := v_setting.setting_value;
        v_valid := TRUE;
        v_warning := NULL;
        
        -- Validate specific settings
        CASE v_setting.setting_name
            WHEN 'ssl_min_protocol_version' THEN
                IF v_setting.setting_value NOT IN ('TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3') THEN
                    v_valid := FALSE;
                    v_warning := 'Invalid TLS version';
                ELSIF v_setting.setting_value < 'TLSv1.2' THEN
                    v_valid := TRUE;
                    v_warning := 'WARNING: TLS version below 1.2 is not recommended';
                END IF;
                
            WHEN 'ssl' THEN
                IF v_setting.setting_value NOT IN ('on', 'off') THEN
                    v_valid := FALSE;
                    v_warning := 'Value must be on or off';
                END IF;
                
            WHEN 'ssl_cert_file', 'ssl_key_file', 'ssl_ca_file' THEN
                -- File existence would be checked by external script
                v_valid := TRUE;
                
            ELSE
                v_valid := TRUE;
        END CASE;
        
        is_valid := v_valid;
        warning_message := v_warning;
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Get recommended cipher list
-- =============================================================================
CREATE OR REPLACE FUNCTION tls_config.get_recommended_ciphers()
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_ciphers TEXT;
BEGIN
    SELECT string_agg(cipher_name, ':')
    INTO v_ciphers
    FROM tls_config.cipher_suites
    WHERE is_enabled = TRUE AND is_secure = TRUE
    ORDER BY priority;
    
    RETURN v_ciphers;
END;
$$;

-- =============================================================================
-- FUNCTION: Check connection TLS status
-- =============================================================================
CREATE OR REPLACE FUNCTION tls_config.check_connection_status()
RETURNS TABLE(
    pid INTEGER,
    usename VARCHAR,
    client_addr INET,
    ssl BOOLEAN,
    ssl_version VARCHAR,
    ssl_cipher VARCHAR,
    ssl_bits INTEGER,
    ssl_client_dn VARCHAR,
    ssl_issuer_dn VARCHAR
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        s.pid,
        s.usename::VARCHAR(63),
        s.client_addr,
        s.ssl,
        s.ssl_version::VARCHAR(50),
        s.ssl_cipher::VARCHAR(100),
        s.ssl_bits,
        s.ssl_client_dn::VARCHAR(500),
        s.ssl_issuer_dn::VARCHAR(500)
    FROM pg_stat_ssl s
    JOIN pg_stat_activity a ON a.pid = s.pid
    WHERE a.datname = current_database();
END;
$$;

-- =============================================================================
-- FUNCTION: Log TLS connection attempt
-- =============================================================================
CREATE OR REPLACE FUNCTION tls_config.log_connection(
    p_client_addr INET,
    p_username VARCHAR,
    p_ssl_used BOOLEAN,
    p_ssl_version VARCHAR DEFAULT NULL,
    p_ssl_cipher VARCHAR DEFAULT NULL,
    p_success BOOLEAN DEFAULT TRUE
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    -- This would integrate with audit logging
    INSERT INTO audit.audit_log (
        event_type, entity_type, action, metadata
    ) VALUES (
        'CONNECTION',
        'DATABASE',
        CASE WHEN p_success THEN 'CONNECT' ELSE 'CONNECT_FAILED' END,
        jsonb_build_object(
            'client_addr', p_client_addr::TEXT,
            'username', p_username,
            'ssl_used', p_ssl_used,
            'ssl_version', p_ssl_version,
            'ssl_cipher', p_ssl_cipher
        )
    );
EXCEPTION WHEN OTHERS THEN
    -- Don't fail if audit logging fails
    NULL;
END;
$$;

-- =============================================================================
-- VIEW: TLS configuration summary
-- =============================================================================
CREATE OR REPLACE VIEW tls_config.configuration_summary AS
SELECT 
    setting_name,
    setting_value,
    setting_category,
    requires_restart,
    description,
    updated_at,
    updated_by
FROM tls_config.settings
WHERE is_active = TRUE
ORDER BY setting_category, setting_name;

-- =============================================================================
-- VIEW: Connection security status
-- =============================================================================
CREATE OR REPLACE VIEW tls_config.connection_security_status AS
SELECT 
    ssl_version as tls_version,
    ssl_cipher as cipher,
    COUNT(*) as connection_count,
    COUNT(*) FILTER (WHERE ssl) as ssl_connections,
    COUNT(*) FILTER (WHERE NOT ssl) as non_ssl_connections,
    MIN(ssl_bits) as min_bits,
    MAX(ssl_bits) as max_bits
FROM pg_stat_ssl s
JOIN pg_stat_activity a ON a.pid = s.pid
WHERE a.datname = current_database()
GROUP BY ssl_version, ssl_cipher;

-- =============================================================================
-- VIEW: Cipher suite recommendations
-- =============================================================================
CREATE OR REPLACE VIEW tls_config.cipher_recommendations AS
SELECT 
    cipher_name,
    openssl_name,
    encryption_algorithm,
    hash_algorithm,
    security_level,
    is_enabled,
    priority,
    CASE 
        WHEN security_level = 'BROKEN' THEN 'DISABLE_IMMEDIATELY'
        WHEN security_level = 'LOW' THEN 'CONSIDER_DISABLING'
        WHEN is_enabled AND security_level = 'HIGH' THEN 'RECOMMENDED'
        WHEN NOT is_enabled AND security_level = 'HIGH' THEN 'ENABLE'
        ELSE 'OK'
    END as recommendation
FROM tls_config.cipher_suites
ORDER BY 
    CASE security_level 
        WHEN 'HIGH' THEN 1 
        WHEN 'MEDIUM' THEN 2 
        WHEN 'LOW' THEN 3 
        ELSE 4 
    END,
    priority;

-- =============================================================================
-- TRIGGER: Update timestamp
-- =============================================================================
CREATE TRIGGER trigger_tls_settings_updated
    BEFORE UPDATE ON tls_config.settings
    FOR EACH ROW EXECUTE FUNCTION encryption.update_timestamp();

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA tls_config TO tls_admin;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA tls_config TO tls_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA tls_config TO tls_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA tls_config TO tls_admin;
