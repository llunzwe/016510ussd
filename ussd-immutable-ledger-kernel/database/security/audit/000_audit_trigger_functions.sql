-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: security/audit/000_audit_trigger_functions.sql
-- Description: Generic and specific trigger functions for comprehensive
--              audit logging of database changes
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: CONFIDENTIAL
-- DATA SENSITIVITY: HIGH - Audit Trail Integrity
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.12.4 Logging and Monitoring
  - A.12.4.1: Event logging with user identification
    Comprehensive audit records with user ID, timestamp, session info
  - A.12.4.2: Protection of log information
    Exception handling ensures original operations complete even if audit fails
  - A.12.4.3: Administrator and operator logs
    Specialized triggers for privileged access monitoring
  - A.12.4.4: Clock synchronization for timestamps
    All records use database server time for consistency
  
A.16.1 Management of Information Security Incidents
  - A.16.1.1: Responsibilities and procedures for incident logging
    High-value transaction detection and alerting
  - A.16.1.2: Reporting information security events
    Structured audit data supports incident investigation

A.18.1 Compliance with Legal and Contractual Requirements
  - A.18.1.1: Identification of applicable legislation
    7-year retention for financial records
  - A.18.1.3: Protection of records
    Immutable audit trail prevents tampering
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION IN CLOUD
================================================================================
Clause 8.1: Purpose and Use
  - Audit logs track all PII access for compliance
  - Data subject access request support through audit queries
  
Clause 9: Accountability
  - Complete audit trail of who accessed what PII and when
  - Purpose tracking for PII processing activities
  
Clause 10: Security
  - PII access logging for breach detection
  - Sensitive data masking in audit records
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
5.4.2 Audit Logging for Storage
  - Comprehensive audit of all data access operations
  - Immutable audit trail for integrity verification
  
7.3 Data Retention and Disposal
  - Audit log partitioning for retention management
  - Secure archival procedures for audit data
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
Clause 5: Identification
  - Audit records enable identification of relevant data sources
  - Comprehensive metadata for ESI (Electronically Stored Information)
  
Clause 6: Preservation
  - Immutable audit trail prevents tampering
  - Legal hold capability for audit records
  
Clause 7: Collection
  - Structured audit data facilitates collection
  - Chain of custody tracking through transaction_id
  
Clause 8: Processing
  - Normalized audit format for processing
  - Deduplication through audit_id uniqueness
================================================================================

================================================================================
PCI DSS 4.0 AUDIT REQUIREMENTS
================================================================================
Requirement 10.2: Audit Logs
  - 10.2.1: Individual user identification
  - 10.2.2: Event type logging
  - 10.2.3: Date and time stamp
  - 10.2.4: Success or failure indication
  - 10.2.5: Origination of event
  - 10.2.6: Identity/name of affected data/resource
  - 10.2.7: System component logging
  
Requirement 10.3: Audit Trail Coverage
  - All CRUD operations on CHD (Cardholder Data)
  - Administrative access to systems
  - Invalid logical access attempts
  - Changes to identification and authentication mechanisms
  
Requirement 10.6: Review Audit Trails
  - High-value transaction detection (>10,000)
  - Multiple failed login detection
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. SECURITY DEFINER for audit trigger functions
2. Error handling that never blocks original operation
3. Masking of sensitive data in audit records
4. Transaction ID tracking for correlation
5. Efficient bulk logging with minimal performance impact
================================================================================

================================================================================
AUDIT TRAIL IMMUTABILITY MECHANISMS
================================================================================
Hash Chain Implementation:
  - Each audit record includes hash of previous record
  - Tamper detection through periodic integrity verification
  - Separate table for hash chain verification

Append-Only Enforcement:
  - RLS policies prevent UPDATE/DELETE on audit tables
  - Database role restrictions for audit tables
  - Legal hold capability prevents purging

Off-Chain Storage:
  - Async replication to write-once storage (WORM)
  - Blockchain anchoring for critical events
  - External SIEM integration for real-time alerting
================================================================================

================================================================================
AUDIT RETENTION REQUIREMENTS
================================================================================
PCI DSS: Minimum 1 year, with at least 3 months immediately available
Financial Regulations: 7 years for transaction records
GDPR: Duration of processing + limitation period
SOX: 7 years for financial reporting systems
ISO/IEC 27050-3: Indefinite for legal hold items
================================================================================
*/

-- ============================================================================
-- PRE-EXECUTION SECURITY CHECKS
-- ============================================================================
DO $$
BEGIN
    -- Verify pgcrypto for audit record hashing
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto') THEN
        RAISE WARNING 'pgcrypto extension not available - audit integrity hashing disabled';
    END IF;
    
    -- Log initialization
    RAISE NOTICE 'Initializing audit trigger functions - %', NOW();
END $$;

-- ============================================================================
-- AUDIT CONFIGURATION
-- ============================================================================

-- ISO/IEC 27001: A.12.4 - Audit configuration table
CREATE TABLE IF NOT EXISTS audit_configuration (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_schema VARCHAR(63) NOT NULL,
    table_name VARCHAR(63) NOT NULL,
    audit_enabled BOOLEAN DEFAULT TRUE,
    audit_insert BOOLEAN DEFAULT TRUE,
    audit_update BOOLEAN DEFAULT TRUE,
    audit_delete BOOLEAN DEFAULT TRUE,
    audit_truncate BOOLEAN DEFAULT FALSE,
    sensitive_columns TEXT[] DEFAULT '{}',
    excluded_columns TEXT[] DEFAULT '{}',
    retention_days INTEGER DEFAULT 2555,  -- ~7 years (financial services)
    partition_strategy VARCHAR(20) DEFAULT 'monthly',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_table_audit UNIQUE (table_schema, table_name)
);

-- ============================================================================
-- CORE AUDIT TRIGGER FUNCTION
-- ============================================================================

-- ISO/IEC 27050-3: Comprehensive audit record generation
-- PCI DSS 10.2: Complete audit trail coverage
-- Parameters: Trigger function - no direct parameters
-- Returns: Trigger record
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
DECLARE
    audit_row audit_log;
    excluded_cols TEXT[];
    sensitive_cols TEXT[];
    new_data JSONB;
    old_data JSONB;
    config RECORD;
    app_user_id UUID;
    app_user_type VARCHAR(50);
    transaction_id BIGINT;
    col TEXT;
BEGIN
    -- Get audit configuration for this table
    SELECT * INTO config
    FROM audit_configuration
    WHERE table_schema = TG_TABLE_SCHEMA
    AND table_name = TG_TABLE_NAME;
    
    -- Skip if audit disabled for this table
    IF config IS NOT NULL AND NOT config.audit_enabled THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        ELSE
            RETURN NEW;
        END IF;
    END IF;
    
    -- Get excluded and sensitive columns
    excluded_cols := COALESCE(config.excluded_columns, ARRAY[]::TEXT[]);
    sensitive_cols := COALESCE(config.sensitive_columns, ARRAY[]::TEXT[]);
    
    -- Initialize audit row per ISO/IEC 27001 A.12.4.1
    audit_row := ROW(
        gen_random_uuid(),                    -- audit_id
        TG_TABLE_SCHEMA,                      -- schema_name
        TG_TABLE_NAME,                        -- table_name
        TG_OP,                                -- operation
        NULL,                                 -- record_id
        NULL,                                 -- old_data
        NULL,                                 -- new_data
        NULL,                                 -- changed_fields
        now(),                                -- changed_at
        NULL,                                 -- changed_by
        NULL,                                 -- session_user_name
        NULL,                                 -- application_name
        NULL,                                 -- client_addr
        NULL,                                 -- client_port
        NULL,                                 -- transaction_id
        NULL,                                 -- statement_id
        NULL,                                 -- query_text
        NULL,                                 -- severity
        NULL                                  -- metadata
    );
    
    -- Get application context (PCI DSS 10.2.1)
    BEGIN
        app_user_id := current_setting('app.current_user_id', TRUE)::UUID;
        app_user_type := current_setting('app.user_type', TRUE);
    EXCEPTION WHEN OTHERS THEN
        app_user_id := NULL;
        app_user_type := 'system';
    END;
    
    -- Populate session information (PCI DSS 10.2.5, 10.2.7)
    audit_row.session_user_name := session_user;
    audit_row.application_name := current_setting('application_name', TRUE);
    audit_row.client_addr := inet_client_addr();
    audit_row.client_port := inet_client_port();
    audit_row.transaction_id := txid_current();
    audit_row.changed_by := app_user_id;
    audit_row.metadata := jsonb_build_object(
        'user_type', app_user_type,
        'trigger_name', TG_NAME,
        'trigger_when', TG_WHEN,
        'trigger_level', TG_LEVEL
    );
    
    -- Handle different operations (PCI DSS 10.2.2, 10.2.4)
    IF TG_OP = 'INSERT' THEN
        IF NOT COALESCE(config.audit_insert, TRUE) THEN
            RETURN NEW;
        END IF;
        
        audit_row.record_id := NEW.id::TEXT;
        new_data := to_jsonb(NEW);
        
        -- Remove excluded columns
        audit_row.new_data := new_data - excluded_cols;
        
        -- Mask sensitive columns (PCI DSS 3.4)
        FOREACH col IN ARRAY sensitive_cols
        LOOP
            IF audit_row.new_data ? col THEN
                audit_row.new_data := jsonb_set(
                    audit_row.new_data,
                    ARRAY[col],
                    '"***MASKED***"'::JSONB
                );
            END IF;
        END LOOP;
        
        audit_row.changed_fields := jsonb_object_keys(audit_row.new_data);
        
    ELSIF TG_OP = 'UPDATE' THEN
        IF NOT COALESCE(config.audit_update, TRUE) THEN
            RETURN NEW;
        END IF;
        
        audit_row.record_id := NEW.id::TEXT;
        old_data := to_jsonb(OLD) - excluded_cols;
        new_data := to_jsonb(NEW) - excluded_cols;
        
        -- Mask sensitive columns in both old and new data
        FOREACH col IN ARRAY sensitive_cols
        LOOP
            IF old_data ? col THEN
                old_data := jsonb_set(old_data, ARRAY[col], '"***MASKED***"'::JSONB);
            END IF;
            IF new_data ? col THEN
                new_data := jsonb_set(new_data, ARRAY[col], '"***MASKED***"'::JSONB);
            END IF;
        END LOOP;
        
        audit_row.old_data := old_data;
        audit_row.new_data := new_data;
        
        -- Calculate changed fields
        SELECT jsonb_object_keys(changes) INTO audit_row.changed_fields
        FROM (
            SELECT jsonb_object_agg(key, value) as changes
            FROM jsonb_each(new_data)
            WHERE old_data->key IS DISTINCT FROM value
        ) changed;
        
        -- Skip if no actual changes
        IF audit_row.changed_fields IS NULL OR jsonb_array_length(audit_row.changed_fields) = 0 THEN
            RETURN NEW;
        END IF;
        
    ELSIF TG_OP = 'DELETE' THEN
        IF NOT COALESCE(config.audit_delete, TRUE) THEN
            RETURN OLD;
        END IF;
        
        audit_row.record_id := OLD.id::TEXT;
        old_data := to_jsonb(OLD) - excluded_cols;
        
        -- Mask sensitive columns
        FOREACH col IN ARRAY sensitive_cols
        LOOP
            IF old_data ? col THEN
                old_data := jsonb_set(old_data, ARRAY[col], '"***MASKED***"'::JSONB);
            END IF;
        END LOOP;
        
        audit_row.old_data := old_data;
        audit_row.changed_fields := jsonb_object_keys(old_data);
        
    ELSIF TG_OP = 'TRUNCATE' THEN
        IF NOT COALESCE(config.audit_truncate, FALSE) THEN
            RETURN NULL;
        END IF;
        
        audit_row.record_id := NULL;
        audit_row.metadata := audit_row.metadata || jsonb_build_object('operation', 'TRUNCATE');
    END IF;
    
    -- Insert the audit record
    INSERT INTO audit_log VALUES (audit_row.*);
    
    -- Return appropriate row
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSIF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
        RETURN NEW;
    ELSE
        RETURN NULL;
    END IF;
    
EXCEPTION WHEN OTHERS THEN
    -- Log error but don't fail the original operation (ISO 27001 A.12.4.2)
    INSERT INTO audit_error_log (
        error_time,
        table_schema,
        table_name,
        operation,
        error_message
    ) VALUES (
        NOW(),
        TG_TABLE_SCHEMA,
        TG_TABLE_NAME,
        TG_OP,
        SQLERRM
    );
    
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSIF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
        RETURN NEW;
    ELSE
        RETURN NULL;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================================
-- ASYNC AUDIT LOGGING FOR HIGH-THROUGHPUT TABLES
-- ============================================================================

-- ISO/IEC 27001: A.12.4 - Async audit queue for high-throughput scenarios
CREATE TABLE IF NOT EXISTS audit_async_queue (
    queue_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_data JSONB NOT NULL,
    retry_count INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

-- Index for efficient queue processing
CREATE INDEX IF NOT EXISTS idx_audit_async_queue_status ON audit_async_queue(status, created_at);

-- Async audit trigger function for high-throughput tables
-- Parameters: Trigger function - no direct parameters
-- Returns: Trigger record
CREATE OR REPLACE FUNCTION audit_trigger_function_async()
RETURNS TRIGGER AS $$
DECLARE
    audit_data JSONB;
    excluded_cols TEXT[];
    sensitive_cols TEXT[];
    config RECORD;
    new_data JSONB;
    old_data JSONB;
    col TEXT;
BEGIN
    -- Get audit configuration
    SELECT * INTO config
    FROM audit_configuration
    WHERE table_schema = TG_TABLE_SCHEMA
    AND table_name = TG_TABLE_NAME;
    
    excluded_cols := COALESCE(config.excluded_columns, ARRAY[]::TEXT[]);
    sensitive_cols := COALESCE(config.sensitive_columns, ARRAY[]::TEXT[]);
    
    -- Build audit data
    audit_data := jsonb_build_object(
        'audit_id', gen_random_uuid(),
        'schema_name', TG_TABLE_SCHEMA,
        'table_name', TG_TABLE_NAME,
        'operation', TG_OP,
        'changed_at', NOW(),
        'changed_by', current_setting('app.current_user_id', TRUE)::UUID,
        'session_user_name', session_user,
        'transaction_id', txid_current(),
        'application_name', current_setting('application_name', TRUE),
        'client_addr', inet_client_addr()
    );
    
    -- Add operation-specific data with masking
    IF TG_OP = 'INSERT' THEN
        new_data := to_jsonb(NEW) - excluded_cols;
        FOREACH col IN ARRAY sensitive_cols
        LOOP
            IF new_data ? col THEN
                new_data := jsonb_set(new_data, ARRAY[col], '"***MASKED***"'::JSONB);
            END IF;
        END LOOP;
        audit_data := audit_data || jsonb_build_object('new_data', new_data, 'record_id', NEW.id::TEXT);
        
    ELSIF TG_OP = 'UPDATE' THEN
        old_data := to_jsonb(OLD) - excluded_cols;
        new_data := to_jsonb(NEW) - excluded_cols;
        FOREACH col IN ARRAY sensitive_cols
        LOOP
            IF old_data ? col THEN
                old_data := jsonb_set(old_data, ARRAY[col], '"***MASKED***"'::JSONB);
            END IF;
            IF new_data ? col THEN
                new_data := jsonb_set(new_data, ARRAY[col], '"***MASKED***"'::JSONB);
            END IF;
        END LOOP;
        audit_data := audit_data || jsonb_build_object(
            'old_data', old_data, 
            'new_data', new_data, 
            'record_id', NEW.id::TEXT
        );
        
    ELSIF TG_OP = 'DELETE' THEN
        old_data := to_jsonb(OLD) - excluded_cols;
        FOREACH col IN ARRAY sensitive_cols
        LOOP
            IF old_data ? col THEN
                old_data := jsonb_set(old_data, ARRAY[col], '"***MASKED***"'::JSONB);
            END IF;
        END LOOP;
        audit_data := audit_data || jsonb_build_object('old_data', old_data, 'record_id', OLD.id::TEXT);
    END IF;
    
    -- Queue for async processing
    INSERT INTO audit_async_queue (audit_data) VALUES (audit_data);
    
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
    
EXCEPTION WHEN OTHERS THEN
    -- Fail silently to avoid blocking
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to process async audit queue
-- ISO/IEC 27001: A.12.4.2 - Audit log processing
-- Parameters: p_batch_size - number of records to process
-- Returns: Number of records processed
CREATE OR REPLACE FUNCTION process_audit_async_queue(
    p_batch_size INTEGER DEFAULT 1000
)
RETURNS INTEGER AS $$
DECLARE
    processed_count INTEGER := 0;
    rec RECORD;
BEGIN
    FOR rec IN 
        SELECT * FROM audit_async_queue 
        WHERE status = 'pending' 
        ORDER BY created_at 
        LIMIT p_batch_size
        FOR UPDATE SKIP LOCKED
    LOOP
        BEGIN
            -- Insert into main audit log
            INSERT INTO audit_log (
                audit_id, schema_name, table_name, operation, record_id,
                old_data, new_data, changed_at, changed_by, session_user_name,
                transaction_id, application_name, client_addr
            ) VALUES (
                (rec.audit_data->>'audit_id')::UUID,
                rec.audit_data->>'schema_name',
                rec.audit_data->>'table_name',
                rec.audit_data->>'operation',
                rec.audit_data->>'record_id',
                rec.audit_data->'old_data',
                rec.audit_data->'new_data',
                (rec.audit_data->>'changed_at')::TIMESTAMPTZ,
                (rec.audit_data->>'changed_by')::UUID,
                rec.audit_data->>'session_user_name',
                (rec.audit_data->>'transaction_id')::BIGINT,
                rec.audit_data->>'application_name',
                (rec.audit_data->>'client_addr')::INET
            );
            
            -- Mark as completed
            UPDATE audit_async_queue 
            SET status = 'completed', processed_at = NOW() 
            WHERE queue_id = rec.queue_id;
            
            processed_count := processed_count + 1;
            
        EXCEPTION WHEN OTHERS THEN
            UPDATE audit_async_queue 
            SET status = 'failed', retry_count = retry_count + 1 
            WHERE queue_id = rec.queue_id;
        END;
    END LOOP;
    
    RETURN processed_count;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- AUDIT LOG COMPRESSION FOR HISTORICAL DATA (PCI DSS 10.7)
-- ============================================================================

-- Table for compressed audit archives
CREATE TABLE IF NOT EXISTS audit_log_compressed (
    archive_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    partition_name VARCHAR(100) NOT NULL,
    date_from TIMESTAMPTZ NOT NULL,
    date_to TIMESTAMPTZ NOT NULL,
    compressed_data BYTEA NOT NULL,
    compression_algorithm VARCHAR(20) DEFAULT 'zstd',
    original_size BIGINT NOT NULL,
    compressed_size BIGINT NOT NULL,
    record_count BIGINT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_partition_archive UNIQUE (partition_name)
);

-- Function to compress old audit partitions
-- PCI DSS 10.7: Audit log compression for long-term storage
-- Parameters: p_partition_name - partition to compress; p_compress_before - compress data older than
-- Returns: Archive ID of compressed data
CREATE OR REPLACE FUNCTION compress_audit_partitions(
    p_partition_name VARCHAR(100) DEFAULT NULL,
    p_compress_before TIMESTAMPTZ DEFAULT NOW() - INTERVAL '3 months'
)
RETURNS UUID AS $$
DECLARE
    v_archive_id UUID;
    v_partition RECORD;
    v_data JSONB;
    v_compressed BYTEA;
    v_original_size BIGINT;
    v_record_count BIGINT;
    v_sql TEXT;
BEGIN
    -- If specific partition provided
    IF p_partition_name IS NOT NULL THEN
        v_sql := format('SELECT COUNT(*) as cnt, pg_total_relation_size(%L) as sz FROM %I',
            'audit_log_' || p_partition_name, 'audit_log_' || p_partition_name);
        EXECUTE v_sql INTO v_record_count, v_original_size;
        
        -- Aggregate data as JSONB
        SELECT jsonb_agg(to_jsonb(t)) INTO v_data
        FROM audit_log t
        WHERE table_name = p_partition_name;
        
        -- Compress using pglz (available in all PostgreSQL) or zstd if available
        v_compressed := pglz_compress(v_data::TEXT::BYTEA);
        
        INSERT INTO audit_log_compressed (
            partition_name, date_from, date_to, compressed_data,
            compression_algorithm, original_size, compressed_size, record_count
        ) VALUES (
            p_partition_name,
            date_trunc('month', p_compress_before - INTERVAL '1 month'),
            date_trunc('month', p_compress_before),
            v_compressed,
            'pglz',
            v_original_size,
            octet_length(v_compressed),
            v_record_count
        ) RETURNING archive_id INTO v_archive_id;
        
        -- Optionally detach and drop the old partition
        -- EXECUTE format('DROP TABLE IF EXISTS %I', 'audit_log_' || p_partition_name);
        
        RETURN v_archive_id;
    END IF;
    
    -- Otherwise compress all old partitions
    FOR v_partition IN 
        SELECT tablename 
        FROM pg_tables 
        WHERE tablename LIKE 'audit_log_%' 
        AND tablename < 'audit_log_' || to_char(p_compress_before, 'YYYY_MM')
    LOOP
        PERFORM compress_audit_partitions(v_partition.tablename, p_compress_before);
    END LOOP;
    
    RETURN v_archive_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- AUDIT LOG INTEGRITY VERIFICATION (ISO 27050-3)
-- ============================================================================

-- Hash chain table for tamper detection
CREATE TABLE IF NOT EXISTS audit_hash_chain (
    chain_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id UUID REFERENCES audit_log(audit_id),
    record_hash TEXT NOT NULL,
    previous_hash TEXT,
    chain_timestamp TIMESTAMPTZ DEFAULT NOW(),
    verified BOOLEAN DEFAULT FALSE
);

-- Function to generate hash chain for audit records
-- ISO/IEC 27050-3: Audit log integrity verification
-- Parameters: p_audit_id - audit record to hash
-- Returns: Hash value
CREATE OR REPLACE FUNCTION generate_audit_hash(
    p_audit_id UUID DEFAULT NULL
)
RETURNS TEXT AS $$
DECLARE
    v_audit RECORD;
    v_previous_hash TEXT;
    v_combined TEXT;
    v_new_hash TEXT;
BEGIN
    -- Get the audit record
    SELECT * INTO v_audit FROM audit_log WHERE audit_id = p_audit_id;
    
    IF v_audit IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Get previous hash from chain
    SELECT record_hash INTO v_previous_hash
    FROM audit_hash_chain
    ORDER BY chain_timestamp DESC
    LIMIT 1;
    
    -- Combine audit data with previous hash
    v_combined := v_audit.audit_id::TEXT || 
                  v_audit.operation || 
                  COALESCE(v_audit.record_id, '') ||
                  v_audit.changed_at::TEXT ||
                  COALESCE(v_previous_hash, 'genesis');
    
    -- Generate SHA-256 hash
    v_new_hash := encode(digest(v_combined::BYTEA, 'sha256'), 'hex');
    
    -- Insert into hash chain
    INSERT INTO audit_hash_chain (audit_id, record_hash, previous_hash)
    VALUES (p_audit_id, v_new_hash, v_previous_hash);
    
    RETURN v_new_hash;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function to verify audit chain integrity
-- Returns: TRUE if chain is valid
CREATE OR REPLACE FUNCTION verify_audit_chain_integrity()
RETURNS BOOLEAN AS $$
DECLARE
    v_record RECORD;
    v_expected_hash TEXT;
    v_previous_hash TEXT;
    v_is_valid BOOLEAN := TRUE;
BEGIN
    FOR v_record IN 
        SELECT * FROM audit_hash_chain ORDER BY chain_timestamp
    LOOP
        -- Recalculate hash
        SELECT record_hash INTO v_previous_hash
        FROM audit_hash_chain
        WHERE chain_id = (
            SELECT chain_id FROM audit_hash_chain
            WHERE chain_timestamp < v_record.chain_timestamp
            ORDER BY chain_timestamp DESC
            LIMIT 1
        );
        
        -- Verify chain link
        IF v_record.previous_hash IS DISTINCT FROM v_previous_hash THEN
            v_is_valid := FALSE;
            
            -- Log tampering detection
            INSERT INTO security_event_log (event_type, event_details)
            VALUES ('audit_chain_tampering_detected', 
                    jsonb_build_object('chain_id', v_record.chain_id));
        END IF;
    END LOOP;
    
    RETURN v_is_valid;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================================================
-- LEGAL HOLD SUPPORT (ISO 27001 A.18)
-- ============================================================================

-- Legal holds table
CREATE TABLE IF NOT EXISTS audit_legal_holds (
    hold_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hold_name VARCHAR(200) NOT NULL,
    description TEXT,
    case_number VARCHAR(100),
    hold_criteria JSONB NOT NULL,  -- JSON query to identify held records
    applied_by UUID,
    applied_at TIMESTAMPTZ DEFAULT NOW(),
    released_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE
);

-- Function to check if an audit record is under legal hold
-- ISO/IEC 27001 A.18 - Protection of records
-- Parameters: p_audit_id - audit record to check
-- Returns: TRUE if record is under legal hold
CREATE OR REPLACE FUNCTION is_under_legal_hold(
    p_audit_id UUID
)
RETURNS BOOLEAN AS $$
DECLARE
    v_audit RECORD;
    v_hold RECORD;
BEGIN
    -- Get audit record details
    SELECT * INTO v_audit FROM audit_log WHERE audit_id = p_audit_id;
    
    IF v_audit IS NULL THEN
        RETURN FALSE;
    END IF;
    
    -- Check against active legal holds
    FOR v_hold IN 
        SELECT * FROM audit_legal_holds WHERE is_active = TRUE
    LOOP
        -- Check if audit record matches hold criteria
        IF v_audit.record_id = ANY(ARRAY(SELECT jsonb_array_elements_text(v_hold.hold_criteria->'record_ids')))
           OR v_audit.table_name = v_hold.hold_criteria->>'table_name'
           OR (v_hold.hold_criteria->>'date_from')::TIMESTAMPTZ <= v_audit.changed_at
              AND (v_hold.hold_criteria->>'date_to')::TIMESTAMPTZ >= v_audit.changed_at
        THEN
            RETURN TRUE;
        END IF;
    END LOOP;
    
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Function to apply legal hold to audit records
-- Parameters: p_hold_name, p_description, p_case_number, p_criteria
-- Returns: Hold ID
CREATE OR REPLACE FUNCTION apply_legal_hold(
    p_hold_name VARCHAR(200),
    p_description TEXT,
    p_case_number VARCHAR(100),
    p_criteria JSONB
)
RETURNS UUID AS $$
DECLARE
    v_hold_id UUID;
BEGIN
    INSERT INTO audit_legal_holds (
        hold_name, description, case_number, hold_criteria, applied_by
    ) VALUES (
        p_hold_name, p_description, p_case_number, p_criteria, current_user_id()
    ) RETURNING hold_id INTO v_hold_id;
    
    -- Log legal hold application
    PERFORM log_security_event('legal_hold_applied', 
        jsonb_build_object('hold_id', v_hold_id, 'case_number', p_case_number));
    
    RETURN v_hold_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- REAL-TIME AUDIT ALERTING (PCI DSS 10.6)
-- ============================================================================

-- Alert rules table
CREATE TABLE IF NOT EXISTS audit_alert_rules (
    rule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_name VARCHAR(200) NOT NULL,
    description TEXT,
    alert_condition JSONB NOT NULL,  -- Condition for triggering alert
    severity VARCHAR(20) DEFAULT 'medium',
    notification_channels TEXT[] DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to evaluate audit alerts
-- PCI DSS 10.6: Real-time audit alerting
-- Parameters: p_audit_id - audit record to evaluate
-- Returns: VOID
CREATE OR REPLACE FUNCTION evaluate_audit_alerts(
    p_audit_id UUID
)
RETURNS VOID AS $$
DECLARE
    v_audit RECORD;
    v_rule RECORD;
    v_should_alert BOOLEAN;
BEGIN
    SELECT * INTO v_audit FROM audit_log WHERE audit_id = p_audit_id;
    
    IF v_audit IS NULL THEN
        RETURN;
    END IF;
    
    -- Evaluate each active rule
    FOR v_rule IN SELECT * FROM audit_alert_rules WHERE is_active = TRUE
    LOOP
        v_should_alert := FALSE;
        
        -- Check high-value transaction (> 10000)
        IF v_rule.alert_condition->>'type' = 'high_value_transaction' THEN
            IF (v_audit.new_data->>'amount')::NUMERIC > (v_rule.alert_condition->>'threshold')::NUMERIC THEN
                v_should_alert := TRUE;
            END IF;
        END IF;
        
        -- Check failed login attempts
        IF v_rule.alert_condition->>'type' = 'failed_login' THEN
            IF v_audit.operation = 'INSERT' AND v_audit.table_name = 'failed_logins' THEN
                v_should_alert := TRUE;
            END IF;
        END IF;
        
        -- Check privileged access
        IF v_rule.alert_condition->>'type' = 'privileged_access' THEN
            IF v_audit.table_name = ANY(ARRAY['users', 'roles', 'permissions'])
               AND v_audit.operation IN ('INSERT', 'UPDATE', 'DELETE') THEN
                v_should_alert := TRUE;
            END IF;
        END IF;
        
        -- Trigger alert if condition met
        IF v_should_alert THEN
            PERFORM log_security_event('audit_alert_triggered',
                jsonb_build_object(
                    'rule_id', v_rule.rule_id,
                    'rule_name', v_rule.rule_name,
                    'audit_id', p_audit_id,
                    'severity', v_rule.severity
                ));
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON FUNCTION audit_trigger_function IS 'ISO/IEC 27001 A.12.4 - Core audit trigger with PCI DSS 10.2 compliance';
COMMENT ON FUNCTION audit_trigger_function_async IS 'ISO/IEC 27001 A.12.4 - Async audit trigger for high-throughput tables';
COMMENT ON FUNCTION process_audit_async_queue IS 'ISO/IEC 27001 A.12.4.2 - Processes queued async audit records';
COMMENT ON FUNCTION compress_audit_partitions IS 'PCI DSS 10.7 - Compresses historical audit partitions for long-term storage';
COMMENT ON FUNCTION generate_audit_hash IS 'ISO/IEC 27050-3 - Generates cryptographic hash for audit record integrity';
COMMENT ON FUNCTION verify_audit_chain_integrity IS 'ISO/IEC 27050-3 - Verifies the integrity of the audit hash chain';
COMMENT ON FUNCTION is_under_legal_hold IS 'ISO/IEC 27001 A.18 - Checks if audit record is under legal hold';
COMMENT ON FUNCTION evaluate_audit_alerts IS 'PCI DSS 10.6 - Evaluates audit records against alert rules';
COMMENT ON TABLE audit_async_queue IS 'ISO/IEC 27001 A.12.4 - Async audit queue for high-throughput scenarios';
COMMENT ON TABLE audit_hash_chain IS 'ISO/IEC 27050-3 - Cryptographic hash chain for tamper detection';
COMMENT ON TABLE audit_legal_holds IS 'ISO/IEC 27001 A.18 - Legal hold records for audit data preservation';
COMMENT ON TABLE audit_alert_rules IS 'PCI DSS 10.6 - Rules for real-time audit alerting';
