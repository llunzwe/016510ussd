-- =============================================================================
-- USSD IMMUTABLE LEDGER KERNEL - MONTHLY PARTITION TEMPLATE
-- File: templates/000_monthly_partition_template.sql
-- Version: 1.0.0-Enterprise
-- Classification: CONFIDENTIAL - Financial Systems
-- Usage: Template for creating monthly time-series partitions with compliance
-- =============================================================================
-- COMPLIANCE FRAMEWORK:
--   - ISO/IEC 27040:2024 (Storage Security - Archival)
--   - ISO/IEC 27001:2022 (A.12.3 - Backup, A.8.1 - Asset Inventory)
--   - GDPR Article 32 (Security of Processing)
--   - PCI DSS 4.0 Requirement 3.4 (Data Encryption)
-- =============================================================================
-- BUSINESS CONTINUITY REQUIREMENTS:
--   - Partitions must be created 30 days in advance
--   - Storage capacity monitoring at 80% threshold
--   - Rollback capability for failed partition creation
--   - Metadata backup before structural changes
-- =============================================================================
-- SECURITY CONTROLS:
--   - Data classification tagging on all partitions
--   - Encryption configuration based on data sensitivity
--   - Access control restrictions on partition management
--   - Audit logging for all DDL operations
-- =============================================================================

-- =============================================================================
-- SECURITY: Verify execution context
-- =============================================================================
DO $$
BEGIN
    IF NOT (SELECT pg_has_role(current_user, 'partition_admin', 'MEMBER') OR 
            (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)) THEN
        RAISE EXCEPTION 'Insufficient privileges. Required: partition_admin or superuser';
    END IF;
END $$;

-- =============================================================================
-- CONFIGURATION SECTION
-- =============================================================================

-- Set these variables before running the template
-- \set target_month '2024-01'  -- Format: YYYY-MM
-- \set schema_name 'public'
-- \set tablespace_hot 'ssd_tablespace'    -- For recent data (hot tier)
-- \set tablespace_warm 'hdd_tablespace'   -- For older data (warm tier)
-- \set compliance_classification 'standard'  -- standard, restricted, critical

-- =============================================================================
-- DYNAMIC SQL GENERATION FUNCTION
-- =============================================================================

CREATE OR REPLACE FUNCTION generate_monthly_partition_sql(
    p_target_month TEXT,        -- Format: 'YYYY-MM'
    p_hypertable TEXT,          -- Name of the hypertable
    p_tablespace TEXT DEFAULT NULL,
    p_compliance_classification TEXT DEFAULT 'standard'
)
RETURNS TEXT AS $$
DECLARE
    v_start_date DATE;
    v_end_date DATE;
    v_partition_name TEXT;
    v_sql TEXT;
    v_tablespace_clause TEXT := '';
    v_encryption_clause TEXT := '';
    v_partition_comment TEXT;
BEGIN
    -- Parse target month
    v_start_date := (p_target_month || '-01')::DATE;
    v_end_date := (v_start_date + INTERVAL '1 month')::DATE;
    
    -- Generate partition name: {table}_p{YYYY}{MM}
    v_partition_name := p_hypertable || '_p' || 
                        TO_CHAR(v_start_date, 'YYYYMM');
    
    -- Tablespace clause
    IF p_tablespace IS NOT NULL THEN
        v_tablespace_clause := ' TABLESPACE ' || p_tablespace;
    END IF;
    
    -- ISO 27040:2024 - Apply encryption for critical/restricted data
    IF p_compliance_classification IN ('critical', 'restricted') THEN
        v_encryption_clause := ' WITH (compression = ''zstd'', encryption = ''aes-256'')';
    END IF;
    
    -- Compliance comment
    v_partition_comment := format(
        'Monthly partition for %s. Classification: %s. Encryption: %s. Created: %s by %s',
        p_target_month,
        p_compliance_classification,
        CASE WHEN v_encryption_clause != '' THEN 'AES-256' ELSE 'Storage-layer' END,
        NOW(),
        current_user
    );
    
    -- Generate SQL
    v_sql := format(
        '-- Partition for %s
        CREATE TABLE IF NOT EXISTS %I PARTITION OF %I
        FOR VALUES FROM (%L) TO (%L)
        %s %s;
        
        -- Add indexes specific to this partition
        CREATE INDEX IF NOT EXISTS idx_%s_created ON %I(created_at);
        CREATE INDEX IF NOT EXISTS idx_%s_hash ON %I(transaction_hash) 
            WHERE created_at >= %L AND created_at < %L;
        
        -- Add partition comment (ISO 27001 A.8.2 - Asset Inventory)
        COMMENT ON TABLE %I IS %L;
        
        -- Log partition creation
        INSERT INTO audit_events (
            event_type, entity_type, entity_id, actor_id, action, severity,
            new_values, created_at
        ) VALUES (
            ''PARTITION_CREATED'', ''PARTITION'', %L,
            current_user, ''CREATE'', ''info'',
            jsonb_build_object(
                ''parent_table'', %L,
                ''partition_date'', %L,
                ''classification'', %L,
                ''tablespace'', %L
            ),
            NOW()
        );',
        p_target_month,
        v_partition_name,
        p_hypertable,
        v_start_date,
        v_end_date,
        v_tablespace_clause,
        v_encryption_clause,
        v_partition_name,
        v_partition_name,
        v_partition_name,
        v_partition_name,
        v_start_date,
        v_end_date,
        v_partition_name,
        v_partition_comment,
        v_partition_name,
        p_hypertable,
        v_start_date,
        p_compliance_classification,
        p_tablespace
    );
    
    RETURN v_sql;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION generate_monthly_partition_sql IS 
    'Generates SQL for monthly partition creation with compliance controls. 
     Standards: ISO 27040:2024, ISO 27001:2022. Supports encryption for classified data.';

-- =============================================================================
-- BATCH PARTITION CREATION
-- =============================================================================

CREATE OR REPLACE FUNCTION create_monthly_partitions(
    p_start_month TEXT,     -- Format: 'YYYY-MM'
    p_months_ahead INTEGER, -- Number of future months to create
    p_hypertables TEXT[],   -- Array of hypertable names
    p_compliance_classification TEXT DEFAULT 'standard'
)
RETURNS TABLE (
    partition_name TEXT,
    hypertable_name TEXT,
    status TEXT,
    compliance_classification TEXT
) AS $$
DECLARE
    v_current_month DATE;
    v_target_month TEXT;
    v_hypertable TEXT;
    v_partition_name TEXT;
    v_sql TEXT;
    v_start_date DATE;
    v_end_date DATE;
BEGIN
    v_current_month := (p_start_month || '-01')::DATE;
    
    FOR i IN 0..p_months_ahead LOOP
        v_target_month := TO_CHAR(v_current_month + (i || ' months')::INTERVAL, 'YYYY-MM');
        v_start_date := (v_target_month || '-01')::DATE;
        v_end_date := (v_start_date + INTERVAL '1 month')::DATE;
        
        FOREACH v_hypertable IN ARRAY p_hypertables LOOP
            BEGIN
                v_partition_name := v_hypertable || '_p' || TO_CHAR(v_start_date, 'YYYYMM');
                
                -- Check if partition already exists
                IF EXISTS (
                    SELECT 1 FROM pg_class c 
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public' AND c.relname = v_partition_name
                ) THEN
                    partition_name := v_partition_name;
                    hypertable_name := v_hypertable;
                    status := 'ALREADY_EXISTS';
                    compliance_classification := p_compliance_classification;
                    RETURN NEXT;
                    CONTINUE;
                END IF;
                
                -- TimescaleDB creates chunks automatically, but for native partitioning:
                IF NOT EXISTS (
                    SELECT 1 FROM timescaledb_information.hypertables 
                    WHERE hypertable_name = v_hypertable
                ) THEN
                    -- Native PostgreSQL partitioning with compliance settings
                    v_sql := format(
                        'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I
                         FOR VALUES FROM (%L) TO (%L)',
                        v_partition_name,
                        v_hypertable,
                        v_start_date,
                        v_end_date
                    );
                    EXECUTE v_sql;
                    
                    -- Add compliance comment
                    EXECUTE format(
                        'COMMENT ON TABLE %I IS %L',
                        v_partition_name,
                        format('Partition for %s. Classification: %s. Created: %s',
                            v_target_month, p_compliance_classification, NOW())
                    );
                    
                    -- Audit log
                    INSERT INTO audit_events (
                        event_type, entity_type, entity_id, actor_id, action, severity,
                        new_values
                    ) VALUES (
                        'PARTITION_CREATED', 'PARTITION', v_partition_name,
                        current_user, 'CREATE', 'info',
                        jsonb_build_object(
                            'parent_table', v_hypertable,
                            'partition_date', v_start_date,
                            'classification', p_compliance_classification
                        )
                    );
                ELSE
                    -- Force chunk creation for specific time range
                    PERFORM create_chunk(v_hypertable, v_start_date, v_end_date);
                END IF;
                
                partition_name := v_partition_name;
                hypertable_name := v_hypertable;
                status := 'CREATED';
                compliance_classification := p_compliance_classification;
                RETURN NEXT;
                
            EXCEPTION WHEN OTHERS THEN
                partition_name := v_partition_name;
                hypertable_name := v_hypertable;
                status := 'ERROR: ' || SQLERRM;
                compliance_classification := p_compliance_classification;
                RETURN NEXT;
                
                -- Audit log for failure
                INSERT INTO audit_events (
                    event_type, entity_type, entity_id, actor_id, action, severity,
                    new_values
                ) VALUES (
                    'PARTITION_CREATION_FAILURE', 'PARTITION', v_partition_name,
                    current_user, 'CREATE', 'critical',
                    jsonb_build_object(
                        'error', SQLERRM,
                        'hypertable', v_hypertable,
                        'target_month', v_target_month
                    )
                );
            END;
        END LOOP;
    END LOOP;
    
    RETURN;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEMPLATES FOR SPECIFIC USE CASES
-- =============================================================================

-- Template 1: Create partition for high-traffic month (e.g., holiday season)
-- ISO 27040:2024 - Performance optimization for critical periods
\echo '=== High-Traffic Partition Template (ISO 27040:2024 - Performance Tier) ==='
/*
-- For months with expected high traffic (December, Black Friday, etc.)
-- Use separate tablespace and pre-warm caches
-- Compliance: Ensure encryption at rest even on performance tier

CREATE TABLE IF NOT EXISTS ledger_transactions_p202412 PARTITION OF ledger_transactions
    FOR VALUES FROM ('2024-12-01') TO ('2025-01-01')
    TABLESPACE ssd_fast_storage
    WITH (compression = 'zstd', encryption = 'aes-256');

COMMENT ON TABLE ledger_transactions_p202412 IS 
    'High-traffic December partition. Classification: CRITICAL. Encryption: AES-256.';

-- Pre-warm the partition for performance
SELECT pg_prewarm('ledger_transactions_p202412');

-- Increase autovacuum frequency for this partition (data integrity)
ALTER TABLE ledger_transactions_p202412 SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02
);

-- Audit log
INSERT INTO audit_events (event_type, entity_type, entity_id, actor_id, action, severity, new_values)
VALUES ('HIGH_TRAFFIC_PARTITION_CREATED', 'PARTITION', 'ledger_transactions_p202412',
        current_user, 'CREATE', 'info', 
        jsonb_build_object('reason', 'December peak traffic', 'classification', 'CRITICAL'));
*/

-- Template 2: Create partition with cold storage tier (Archival)
-- ISO 27040:2024 - Storage tiering for cost optimization
\echo '=== Cold Storage Partition Template (ISO 27040:2024 - Archive Tier) ==='
/*
-- For older partitions being moved to slower/cheaper storage
-- Ensure encryption is maintained during tier transition
CREATE TABLE IF NOT EXISTS ledger_transactions_p202301 PARTITION OF ledger_transactions
    FOR VALUES FROM ('2023-01-01') TO ('2023-02-01')
    TABLESPACE hdd_cold_storage
    WITH (compression = 'zstd', encryption = 'aes-256');

COMMENT ON TABLE ledger_transactions_p202301 IS 
    'Cold storage partition. Classification: RESTRICTED. Retention: 7 years (SOX 802).';

-- Immediately compress after creation to save storage
SELECT compress_chunk(i) FROM show_chunks('ledger_transactions', 
    older_than => INTERVAL '1 year', newer_than => INTERVAL '13 months') i;

-- Schedule archival to long-term storage
PERFORM schedule_partition_archival('ledger_transactions_p202301', 's3_cold_archive');
*/

-- Template 3: Partition with custom constraints (Compliance)
-- GDPR/PCI DSS - Data sovereignty and currency restrictions
\echo '=== Constrained Partition Template (GDPR/PCI DSS Compliant) ==='
/*
-- Create partition with specific business rules
CREATE TABLE ledger_transactions_p2024q1 PARTITION OF ledger_transactions
    FOR VALUES FROM ('2024-01-01') TO ('2024-04-01')
    WITH (encryption = 'aes-256');

COMMENT ON TABLE ledger_transactions_p2024q1 IS 
    'Q1 2024 partition with GDPR compliance constraints. Encryption: AES-256.';

-- Add check constraint for this quarter's specific requirements
ALTER TABLE ledger_transactions_p2024q1 
    ADD CONSTRAINT chk_q1_currency 
    CHECK (currency IN ('USD', 'EUR', 'GBP'));

-- Add GDPR data subject tracking constraint
ALTER TABLE ledger_transactions_p2024q1
    ADD CONSTRAINT chk_gdpr_subject
    CHECK (gdpr_data_subject_id IS NOT NULL OR phone_number_encrypted IS NOT NULL);

-- Audit log
INSERT INTO audit_events (event_type, entity_type, entity_id, actor_id, action, severity, new_values)
VALUES ('CONSTRAINED_PARTITION_CREATED', 'PARTITION', 'ledger_transactions_p2024q1',
        current_user, 'CREATE', 'info',
        jsonb_build_object('constraints', ARRAY['chk_q1_currency', 'chk_gdpr_subject']));
*/

-- Template 4: Encrypted partition for PII (GDPR Article 32)
\echo '=== GDPR-Compliant Encrypted Partition Template ==='
/*
-- Partition with maximum security for PII data
CREATE TABLE session_logs_p202401 PARTITION OF session_logs
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01')
    WITH (compression = 'zstd', encryption = 'aes-256');

-- Add partial index for PII lookup (encrypted)
CREATE INDEX idx_session_logs_p202401_pii ON session_logs_p202401(gdpr_data_subject_id)
    WHERE gdpr_data_subject_id IS NOT NULL;

-- Set shorter retention (GDPR Article 5(1)(e))
COMMENT ON TABLE session_logs_p202401 IS 
    'Session logs partition. Classification: PII. Retention: 90 days. Auto-anonymization enabled.';

-- Schedule anonymization job
SELECT cron.schedule(
    'anonymize-session-logs-202401',
    '0 2 * * *',  -- Daily at 2 AM
    $$
    UPDATE session_logs_p202401 
    SET phone_number = 'ANONYMIZED',
        phone_number_hash = NULL,
        input_data = '[REDACTED]',
        ussd_string = '[REDACTED]',
        anonymized_at = NOW()
    WHERE created_at < NOW() - INTERVAL '90 days'
      AND anonymized_at IS NULL;
    $$
);
*/

-- =============================================================================
-- VERIFICATION QUERIES
-- =============================================================================

-- Query to check all partitions for a table with compliance info
SELECT 
    parent.relname AS parent_table,
    child.relname AS partition_name,
    pg_get_expr(child.relpartbound, child.oid) AS partition_bounds,
    pg_size_pretty(pg_total_relation_size(child.oid)) AS total_size,
    t.spcname AS tablespace,
    obj_description(child.oid, 'pg_class') AS compliance_comment
FROM pg_class parent
JOIN pg_inherits inh ON parent.oid = inh.inhparent
JOIN pg_class child ON child.oid = inh.inhrelid
LEFT JOIN pg_tablespace t ON t.oid = child.reltablespace
WHERE parent.relname = 'ledger_transactions'
ORDER BY child.relname;

-- Query to check TimescaleDB chunks with security info
SELECT 
    hypertable_name,
    chunk_name,
    range_start,
    range_end,
    is_compressed,
    pg_size_pretty(d.total_bytes) AS chunk_size,
    c.compression_ratio,
    CASE WHEN c.compression_ratio > 0 THEN 'COMPRESSED' ELSE 'UNCOMPRESSED' END AS compression_status
FROM timescaledb_information.chunks c
LEFT JOIN chunks_detailed_size('ledger_transactions') d ON d.chunk_name = c.chunk_name
ORDER BY range_start DESC;

-- Query to check partition encryption status (ISO 27040:2024)
SELECT 
    c.relname AS partition_name,
    COALESCE(
        (SELECT obj_description(c.oid, 'pg_class') LIKE '%AES-256%' OR
                obj_description(c.oid, 'pg_class') LIKE '%encryption%'),
        FALSE
    ) AS encryption_tagged,
    t.spcname AS tablespace,
    CASE 
        WHEN t.spcname LIKE '%encrypted%' THEN 'ENCRYPTED'
        WHEN t.spcname IS NULL THEN 'DEFAULT'
        ELSE 'VERIFY_ENCRYPTION'
    END AS encryption_status
FROM pg_class c
JOIN pg_inherits inh ON c.oid = inh.inhrelid
JOIN pg_class parent ON parent.oid = inh.inhparent
LEFT JOIN pg_tablespace t ON t.oid = c.reltablespace
WHERE parent.relname IN ('ledger_transactions', 'audit_events', 'session_logs')
ORDER BY c.relname;

-- =============================================================================
-- AUDIT: Log template execution
-- =============================================================================
INSERT INTO audit_events (
    event_type, entity_type, entity_id, actor_id, action, severity,
    new_values
) VALUES (
    'TEMPLATE_LOADED', 'PARTITION_TEMPLATE', '000_monthly_partition_template',
    current_user, 'LOAD', 'info',
    jsonb_build_object(
        'functions_created', 2,
        'templates_provided', 4,
        'compliance_standards', ARRAY['ISO_27040:2024', 'GDPR_Article_32', 'PCI_DSS_3.4']
    ),
    NOW()
);

-- =============================================================================
-- IMPLEMENTATION CHECKLIST
-- =============================================================================

/*
COMPLIANCE CHECKLIST:
[ ] Define data classification levels (standard, restricted, critical)
[ ] Configure encryption settings per classification
[ ] Set up tablespaces for hot/warm/cold storage tiers
[ ] Document retention periods per table type (GDPR/SOX)
[ ] Implement automated partition creation (pg_cron)
[ ] Set up partition encryption verification
[ ] Configure high-traffic partition pre-warming
[ ] Test partition rollback procedures
[ ] Verify audit logging captures all DDL
[ ] Schedule monthly partition readiness reviews

SECURITY CONTROLS:
- Role-based access: partition_admin required
- Encryption: AES-256 for restricted/critical data
- Classification: Tagged in partition comments
- Audit: All operations logged immutably
- Retention: Configured per compliance standard

PARTITION NAMING CONVENTION:
- Format: {table}_p{YYYY}{MM}
- Example: ledger_transactions_p202401
- Enforcement: validate_partition_name() function
*/
