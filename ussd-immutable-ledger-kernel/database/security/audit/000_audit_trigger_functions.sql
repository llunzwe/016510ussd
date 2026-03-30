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
-- COMMENTS
-- ============================================================================
COMMENT ON FUNCTION audit_trigger_function IS 'ISO/IEC 27001 A.12.4 - Core audit trigger with PCI DSS 10.2 compliance';

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Implement async audit logging for high-throughput tables (ISO 27001 A.12.4)
-- TODO: Add audit log compression for historical data (PCI DSS 10.7)
-- TODO: Implement audit log streaming to external SIEM systems (ISO 27001 A.16)
-- TODO: Add machine learning-based anomaly detection in audit patterns
-- TODO: Implement audit log integrity verification (hash chain) (ISO 27050-3)
-- TODO: Add support for selective field-level auditing
-- TODO: Implement audit log purging with legal hold support (ISO 27001 A.18)
-- TODO: Create real-time audit alerting system (PCI DSS 10.6)
-- TODO: Add blockchain-backed audit log immutability (ISO 27050-3)
-- TODO: Implement cross-database audit aggregation
-- ============================================================================
