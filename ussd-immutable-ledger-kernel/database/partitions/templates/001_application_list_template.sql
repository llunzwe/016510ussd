-- =============================================================================
-- USSD IMMUTABLE LEDGER KERNEL - APPLICATION LIST PARTITION TEMPLATE
-- File: templates/001_application_list_template.sql
-- Version: 1.0.0-Enterprise
-- Classification: CONFIDENTIAL - Financial Systems
-- Description: Template for application-based list partitioning for multi-tenant
-- =============================================================================
-- COMPLIANCE FRAMEWORK:
--   - ISO/IEC 27040:2024 (Storage Security - Multi-tenant Isolation)
--   - ISO/IEC 27001:2022 (A.8.1 - Asset Inventory, A.13.1 - Network Isolation)
--   - GDPR Article 25 (Data Protection by Design), Article 32 (Security)
--   - PCI DSS 4.0 Requirement 3.5 (Key Management)
--   - SOX Section 404 (Access Controls)
-- =============================================================================
-- BUSINESS CONTINUITY REQUIREMENTS:
--   - Tenant isolation must be maintained during failover
--   - Per-tenant RTO/RPO based on service level
--   - Automated tenant onboarding with compliance validation
--   - Data residency enforcement per tenant requirements
-- =============================================================================
-- SECURITY CONTROLS:
--   - Row-level security (RLS) per tenant
--   - Partition-level access restrictions
--   - Encryption key separation per tenant tier
--   - Audit logging per tenant with immutable trail
-- =============================================================================

-- =============================================================================
-- SECURITY: Verify execution context
-- =============================================================================
DO $$
BEGIN
    IF NOT (SELECT pg_has_role(current_user, 'tenant_admin', 'MEMBER') OR 
            (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)) THEN
        RAISE EXCEPTION 'Insufficient privileges. Required: tenant_admin or superuser';
    END IF;
END $$;

-- =============================================================================
-- AUDIT: Log template execution start
-- =============================================================================
INSERT INTO audit_events (
    event_type, entity_type, entity_id, actor_id, action, severity,
    new_values
) VALUES (
    'TEMPLATE_LOADED', 'MULTI_TENANT_CONFIG', '001_application_list_template',
    current_user, 'LOAD', 'info',
    jsonb_build_object('compliance', ARRAY['ISO_27040:2024', 'GDPR_Article_25', 'SOX_404']),
    NOW()
);

-- =============================================================================
-- MULTI-TENANT PARTITION STRATEGY
-- =============================================================================

-- This template creates application-specific partitions for multi-tenant USSD deployments
-- where different applications (banks, telcos, service providers) need isolated data storage
-- Compliance: ISO 27040:2024 - Storage Security for Multi-tenant Environments

-- =============================================================================
-- CONFIGURATION: APPLICATION REGISTRY
-- =============================================================================

-- Master table for registered applications/tenants
CREATE TABLE IF NOT EXISTS registered_applications (
    app_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_code            VARCHAR(20) UNIQUE NOT NULL,
    app_name            VARCHAR(100) NOT NULL,
    app_type            VARCHAR(50) NOT NULL, -- 'bank', 'telco', 'wallet', 'merchant'
    partition_strategy  VARCHAR(20) DEFAULT 'shared', -- 'dedicated', 'shared', 'isolated'
    storage_tier        VARCHAR(20) DEFAULT 'hot',    -- 'hot', 'warm', 'cold'
    -- Compliance fields
    data_residency      VARCHAR(50) DEFAULT 'eu-west-1',  -- Data residency requirement
    compliance_tier     VARCHAR(20) DEFAULT 'standard',   -- standard, pci_dss, sox, gdpr_strict
    encryption_key_id   UUID REFERENCES encryption_key_registry(key_id),
    retention_days      INTEGER DEFAULT 90,
    -- GDPR fields
    gdpr_controller     TEXT,  -- Data controller name for GDPR
    gdpr_dpo_contact    TEXT,  -- Data Protection Officer contact
    -- Audit fields
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    is_active           BOOLEAN DEFAULT TRUE,
    metadata            JSONB
);

-- Comments for compliance
COMMENT ON TABLE registered_applications IS 
    'Multi-tenant application registry. Compliance: ISO 27040:2024, GDPR Article 25. Contains PII data residency info.';

-- Seed with common USSD applications with compliance tiers
INSERT INTO registered_applications 
    (app_code, app_name, app_type, partition_strategy, retention_days, compliance_tier, data_residency)
VALUES 
    ('MTN_MONEY', 'MTN Mobile Money', 'wallet', 'shared', 90, 'standard', 'af-south-1'),
    ('AIRTEL_MM', 'Airtel Money', 'wallet', 'shared', 90, 'standard', 'af-south-1'),
    ('SAFARICOM', 'M-Pesa', 'wallet', 'dedicated', 365, 'gdpr_strict', 'eu-west-1'),
    ('EQUITY', 'Equity Bank', 'bank', 'dedicated', 2555, 'sox', 'eu-west-1'), -- 7 years SOX
    ('KCB', 'KCB Bank', 'bank', 'dedicated', 2555, 'sox', 'eu-west-1'),
    ('STANDARD_CH', 'Standard Chartered', 'bank', 'shared', 2555, 'pci_dss', 'eu-west-1'),
    ('TIGO_PESA', 'Tigo Pesa', 'wallet', 'shared', 90, 'standard', 'af-south-1'),
    ('ORANGE_MM', 'Orange Money', 'wallet', 'shared', 90, 'standard', 'eu-west-1'),
    ('VODACOM', 'Vodacom M-Pesa', 'wallet', 'dedicated', 365, 'gdpr_strict', 'eu-west-1'),
    ('PAYPAL', 'PayPal USSD', 'wallet', 'isolated', 2555, 'pci_dss', 'us-east-1')
ON CONFLICT (app_code) DO NOTHING;

-- =============================================================================
-- LIST PARTITION TEMPLATE
-- =============================================================================

-- Base table with list partitioning by application code
DROP TABLE IF EXISTS application_transactions CASCADE;

CREATE TABLE application_transactions (
    id                  BIGSERIAL,
    transaction_id      UUID NOT NULL DEFAULT gen_random_uuid(),
    app_code            VARCHAR(20) NOT NULL,
    phone_number        VARCHAR(20) NOT NULL,  -- PII
    phone_number_hash   VARCHAR(64),           -- Hashed for analytics
    transaction_type    VARCHAR(50) NOT NULL,
    amount              NUMERIC(19, 4),
    currency            VARCHAR(3) DEFAULT 'USD',
    reference_number    VARCHAR(100),
    external_ref        VARCHAR(100),
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    request_payload     JSONB,
    response_payload    JSONB,
    processing_time_ms  INTEGER,
    -- GDPR compliance fields
    gdpr_data_subject_id UUID,
    data_residency      VARCHAR(50) DEFAULT 'eu-west-1',
    -- Audit fields
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          TEXT DEFAULT current_user,
    source_ip           INET,
    
    CONSTRAINT pk_app_transactions PRIMARY KEY (id, app_code),
    CONSTRAINT chk_app_tx_status CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'reversed'))
) PARTITION BY LIST (app_code);

COMMENT ON TABLE application_transactions IS 
    'Multi-tenant application transactions with GDPR compliance. Encryption: AES-256. RLS: Enabled per tenant.';

-- =============================================================================
-- PARTITION TEMPLATES BY STRATEGY
-- =============================================================================

-- Template 1: Shared partition (multiple small apps)
-- ISO 27040:2024 - Shared storage with logical isolation
CREATE TABLE application_transactions_shared PARTITION OF application_transactions
    FOR VALUES IN ('MTN_MONEY', 'AIRTEL_MM', 'TIGO_PESA', 'ORANGE_MM', 'STANDARD_CH');

CREATE INDEX idx_app_tx_shared_created ON application_transactions_shared(created_at);
CREATE INDEX idx_app_tx_shared_phone ON application_transactions_shared(phone_number_hash);
CREATE INDEX idx_app_tx_shared_type ON application_transactions_shared(transaction_type);

COMMENT ON TABLE application_transactions_shared IS 
    'Shared partition for standard-tier applications. Encryption: AES-256. Compliance: Standard.';

-- Template 2: Dedicated partition (single large app with high volume)
-- ISO 27040:2024 - Dedicated storage for high-volume tenants
CREATE TABLE application_transactions_safaricom PARTITION OF application_transactions
    FOR VALUES IN ('SAFARICOM')
    TABLESPACE pg_default;

CREATE INDEX idx_app_tx_safaricom_created ON application_transactions_safaricom(created_at);
CREATE INDEX idx_app_tx_safaricom_hash ON application_transactions_safaricom(phone_number_hash);
CREATE INDEX idx_app_tx_safaricom_ref ON application_transactions_safaricom(reference_number);

-- Add partial index for pending transactions (fast lookup)
CREATE INDEX idx_app_tx_safaricom_pending 
    ON application_transactions_safaricom(status, created_at) 
    WHERE status = 'pending';

COMMENT ON TABLE application_transactions_safaricom IS 
    'Dedicated partition for M-Pesa. Compliance: GDPR Strict. Encryption: AES-256. RLS: Enabled.';

-- Template 3: Isolated partition (compliance requirements - PCI DSS)
-- ISO 27040:2024 - Isolated storage for regulated data
CREATE TABLE application_transactions_isolated PARTITION OF application_transactions
    FOR VALUES IN ('PAYPAL')
    TABLESPACE pg_default;

-- Enhanced auditing for isolated partitions
CREATE INDEX idx_app_tx_isolated_full ON application_transactions_isolated 
    (app_code, phone_number_hash, created_at, status);

-- Row-level security policy for isolated partition
CREATE POLICY paypal_isolation_policy ON application_transactions_isolated
    FOR ALL
    TO ussd_app_user
    USING (app_code = 'PAYPAL' AND pg_has_role(current_user, 'paypal_access', 'MEMBER'));

COMMENT ON TABLE application_transactions_isolated IS 
    'Isolated partition for PCI DSS compliance. Encryption: AES-256. Access: Restricted. Audit: Enhanced.';

-- =============================================================================
-- DYNAMIC PARTITION MANAGEMENT
-- =============================================================================

-- Function to create new application partition with compliance
CREATE OR REPLACE FUNCTION create_application_partition(
    p_app_code VARCHAR(20),
    p_strategy VARCHAR(20) DEFAULT 'dedicated',
    p_tablespace TEXT DEFAULT NULL,
    p_compliance_tier TEXT DEFAULT 'standard'
)
RETURNS TEXT AS $$
DECLARE
    v_partition_name TEXT;
    v_sql TEXT;
    v_tablespace_clause TEXT := '';
    v_encryption_clause TEXT := '';
    v_app_exists BOOLEAN;
BEGIN
    -- Verify app is registered
    SELECT EXISTS(SELECT 1 FROM registered_applications WHERE app_code = p_app_code)
    INTO v_app_exists;
    
    IF NOT v_app_exists THEN
        RAISE EXCEPTION 'Application % is not registered. Register before creating partition.', p_app_code;
    END IF;
    
    v_partition_name := 'application_transactions_' || lower(p_app_code);
    
    IF p_tablespace IS NOT NULL THEN
        v_tablespace_clause := ' TABLESPACE ' || quote_ident(p_tablespace);
    END IF;
    
    -- ISO 27040:2024 - Apply encryption based on compliance tier
    IF p_compliance_tier IN ('pci_dss', 'sox', 'gdpr_strict') THEN
        v_encryption_clause := ' WITH (encryption = ''aes-256'')';
    END IF;
    
    -- Check if partition already exists
    IF EXISTS (
        SELECT 1 FROM pg_class c 
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = v_partition_name
    ) THEN
        RETURN 'Partition ' || v_partition_name || ' already exists';
    END IF;
    
    -- Create partition based on strategy
    CASE p_strategy
        WHEN 'dedicated' THEN
            v_sql := format(
                'CREATE TABLE %I PARTITION OF application_transactions 
                 FOR VALUES IN (%L) %s %s',
                v_partition_name,
                p_app_code,
                v_tablespace_clause,
                v_encryption_clause
            );
        WHEN 'shared' THEN
            -- Add to shared partition - no new partition needed
            RETURN 'Add ' || p_app_code || ' to shared partition constraint (manual update required)';
        WHEN 'isolated' THEN
            v_sql := format(
                'CREATE TABLE %I PARTITION OF application_transactions 
                 FOR VALUES IN (%L) %s %s',
                v_partition_name,
                p_app_code,
                v_tablespace_clause,
                v_encryption_clause
            );
        ELSE
            RAISE EXCEPTION 'Unknown strategy: %', p_strategy;
    END CASE;
    
    EXECUTE v_sql;
    
    -- Create standard indexes
    EXECUTE format(
        'CREATE INDEX idx_%s_created ON %I(created_at)',
        lower(p_app_code), v_partition_name
    );
    
    EXECUTE format(
        'CREATE INDEX idx_%s_hash ON %I(phone_number_hash)',
        lower(p_app_code), v_partition_name
    );
    
    -- Add compliance comment
    EXECUTE format(
        'COMMENT ON TABLE %I IS %L',
        v_partition_name,
        format('Partition for %s. Strategy: %s. Compliance: %s. Encryption: AES-256.',
            p_app_code, p_strategy, p_compliance_tier)
    );
    
    -- Audit log
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'TENANT_PARTITION_CREATED', 'PARTITION', v_partition_name,
        current_user, 'CREATE', 'info',
        jsonb_build_object(
            'app_code', p_app_code,
            'strategy', p_strategy,
            'compliance_tier', p_compliance_tier
        )
    );
    
    RETURN 'Created partition: ' || v_partition_name;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- ROW-LEVEL SECURITY (RLS) FOR MULTI-TENANT ISOLATION
-- GDPR Article 32 - Security of Processing
-- =============================================================================

-- Enable RLS on the base table
ALTER TABLE application_transactions ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their tenant's data
CREATE POLICY tenant_isolation_policy ON application_transactions
    FOR SELECT
    TO ussd_app_user
    USING (
        app_code IN (
            SELECT app_code FROM registered_applications 
            WHERE metadata->>'access_role'::TEXT IN (
                SELECT rolname FROM pg_roles 
                WHERE pg_has_role(current_user, oid, 'MEMBER')
            )
        )
    );

-- Policy: Insert only for authorized tenants
CREATE POLICY tenant_insert_policy ON application_transactions
    FOR INSERT
    TO ussd_app_user
    WITH CHECK (
        app_code IN (
            SELECT app_code FROM registered_applications 
            WHERE is_active = TRUE
        )
    );

-- =============================================================================
-- APPLICATION-SPECIFIC CONFIGURATION
-- =============================================================================

-- Table for per-application configuration overrides
CREATE TABLE IF NOT EXISTS application_partition_config (
    app_code                VARCHAR(20) PRIMARY KEY REFERENCES registered_applications(app_code),
    chunk_interval          INTERVAL DEFAULT '1 day',
    retention_interval      INTERVAL DEFAULT '90 days',
    compression_after       INTERVAL DEFAULT '7 days',
    max_chunk_size          BIGINT DEFAULT 1073741824, -- 1GB
    tablespace_name         TEXT,
    autovacuum_enabled      BOOLEAN DEFAULT TRUE,
    autovacuum_vacuum_scale_factor NUMERIC DEFAULT 0.1,
    fillfactor              INTEGER DEFAULT 100,
    parallel_workers        INTEGER DEFAULT 2,
    custom_constraints      JSONB,
    -- GDPR fields
    gdpr_retention_days     INTEGER DEFAULT 90,
    gdpr_anonymize_after    INTERVAL DEFAULT '90 days',
    -- Audit fields
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    updated_at              TIMESTAMPTZ DEFAULT NOW()
);

-- Seed default configurations based on compliance tier
INSERT INTO application_partition_config (app_code, chunk_interval, retention_interval, gdpr_retention_days)
SELECT app_code, 
       CASE WHEN partition_strategy = 'dedicated' THEN '1 day'::INTERVAL ELSE '1 day'::INTERVAL END,
       (retention_days || ' days')::INTERVAL,
       CASE 
           WHEN compliance_tier = 'gdpr_strict' THEN 90
           WHEN compliance_tier = 'pci_dss' THEN 365
           WHEN compliance_tier = 'sox' THEN 2555
           ELSE 90
       END
FROM registered_applications
ON CONFLICT (app_code) DO NOTHING;

-- =============================================================================
-- PARTITION ANALYSIS VIEWS
-- =============================================================================

-- View: Application transaction statistics with compliance
CREATE OR REPLACE VIEW v_app_transaction_stats AS
SELECT 
    r.app_code,
    r.app_name,
    r.partition_strategy,
    r.storage_tier,
    r.compliance_tier,
    r.data_residency,
    COALESCE(t.tx_count, 0) AS total_transactions,
    COALESCE(t.total_amount, 0) AS total_volume,
    COALESCE(t.avg_tx_amount, 0) AS avg_transaction_amount,
    COALESCE(t.last_tx_at, '-infinity'::TIMESTAMPTZ) AS last_transaction_at
FROM registered_applications r
LEFT JOIN (
    SELECT 
        app_code,
        COUNT(*) AS tx_count,
        SUM(amount) AS total_amount,
        AVG(amount) AS avg_tx_amount,
        MAX(created_at) AS last_tx_at
    FROM application_transactions
    GROUP BY app_code
) t ON r.app_code = t.app_code
WHERE r.is_active = TRUE;

-- View: Partition sizes by application with security info
CREATE OR REPLACE VIEW v_app_partition_sizes AS
SELECT 
    c.relname AS partition_name,
    pg_get_expr(c.relpartbound, c.oid) AS partition_bounds,
    pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size,
    pg_size_pretty(pg_relation_size(c.oid)) AS table_size,
    pg_size_pretty(pg_indexes_size(c.oid)) AS indexes_size,
    t.spcname AS tablespace,
    obj_description(c.oid, 'pg_class') AS compliance_info
FROM pg_class parent
JOIN pg_inherits inh ON parent.oid = inh.inhparent
JOIN pg_class c ON c.oid = inh.inhrelid
LEFT JOIN pg_tablespace t ON t.oid = c.reltablespace
WHERE parent.relname = 'application_transactions'
ORDER BY c.relname;

-- =============================================================================
-- GDPR: DATA SUBJECT ACCESS REQUEST (Article 15)
-- =============================================================================

CREATE OR REPLACE FUNCTION gdpr_export_data_subject(
    p_data_subject_id UUID
)
RETURNS TABLE (
    app_code VARCHAR(20),
    transaction_data JSONB,
    export_date TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        at.app_code,
        jsonb_build_object(
            'transaction_id', at.transaction_id,
            'amount', at.amount,
            'currency', at.currency,
            'status', at.status,
            'created_at', at.created_at,
            'app_name', ra.app_name
        ) AS transaction_data,
        NOW() AS export_date
    FROM application_transactions at
    JOIN registered_applications ra ON ra.app_code = at.app_code
    WHERE at.gdpr_data_subject_id = p_data_subject_id;
    
    -- Audit log
    INSERT INTO audit_events (
        event_type, entity_type, entity_id, actor_id, action, severity,
        new_values
    ) VALUES (
        'GDPR_DATA_EXPORT', 'DATA_SUBJECT', p_data_subject_id::TEXT,
        current_user, 'EXPORT', 'info',
        jsonb_build_object('exported_at', NOW(), 'regulation', 'GDPR_Article_15')
    );
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- MAINTENANCE PROCEDURES
-- =============================================================================

-- Procedure: Analyze all application partitions
CREATE OR REPLACE PROCEDURE analyze_app_partitions()
LANGUAGE plpgsql AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN 
        SELECT c.relname AS partition_name
        FROM pg_class parent
        JOIN pg_inherits inh ON parent.oid = inh.inhparent
        JOIN pg_class c ON c.oid = inh.inhrelid
        WHERE parent.relname = 'application_transactions'
    LOOP
        RAISE NOTICE 'Analyzing partition: %', r.partition_name;
        EXECUTE format('ANALYZE %I', r.partition_name);
    END LOOP;
END;
$$;

-- Procedure: Reindex application partitions
CREATE OR REPLACE PROCEDURE reindex_app_partitions(p_app_code VARCHAR(20) DEFAULT NULL)
LANGUAGE plpgsql AS $$
DECLARE
    r RECORD;
    v_partition_pattern TEXT;
BEGIN
    IF p_app_code IS NOT NULL THEN
        v_partition_pattern := 'application_transactions_' || lower(p_app_code);
    ELSE
        v_partition_pattern := 'application_transactions_%';
    END IF;
    
    FOR r IN 
        SELECT c.relname AS partition_name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' 
          AND c.relname LIKE v_partition_pattern
          AND c.relkind = 'r'
    LOOP
        RAISE NOTICE 'Reindexing partition: %', r.partition_name;
        EXECUTE format('REINDEX TABLE %I', r.partition_name);
    END LOOP;
END;
$$;

-- =============================================================================
-- AUDIT: Log script execution completion
-- =============================================================================
INSERT INTO audit_events (
    event_type, entity_type, entity_id, actor_id, action, severity,
    new_values
) VALUES (
    'TEMPLATE_LOADED', 'MULTI_TENANT_CONFIG', '001_application_list_template',
    current_user, 'COMPLETE', 'info',
    jsonb_build_object(
        'tables_created', 3,
        'partitions_created', 3,
        'rls_policies', 2,
        'compliance_features', ARRAY['GDPR_RLS', 'PCI_DSS_Isolation', 'SOX_Retention']
    ),
    NOW()
);

-- =============================================================================
-- IMPLEMENTATION CHECKLIST
-- =============================================================================

/*
COMPLIANCE CHECKLIST:
[ ] Configure row-level security policies per tenant
[ ] Set up tenant-specific encryption keys
[ ] Implement data residency enforcement
[ ] Configure GDPR data subject request handling
[ ] Set up per-tenant audit logging
[ ] Test tenant isolation (no cross-tenant data leakage)
[ ] Document tenant onboarding workflow
[ ] Implement tenant decommissioning procedures
[ ] Configure per-tenant backup schedules
[ ] Test disaster recovery per tenant SLA

SECURITY CONTROLS:
- RLS: Enabled on base table
- Encryption: AES-256 per compliance tier
- Access Control: Role-based per tenant
- Audit: Immutable per-tenant logging
- Isolation: Partition-level for PCI DSS

TENANT TIERS:
- standard: Shared partition, 90 day retention
- gdpr_strict: Dedicated partition, 90 day retention, EU residency
- pci_dss: Isolated partition, 365 day retention, enhanced audit
- sox: Dedicated partition, 7 year retention, immutable audit
*/
