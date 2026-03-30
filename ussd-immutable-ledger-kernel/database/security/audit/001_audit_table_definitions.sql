-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: security/audit/001_audit_table_definitions.sql
-- Description: Core audit log tables and partition management
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: RESTRICTED
-- DATA SENSITIVITY: CRITICAL - Immutable Audit Trail
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.12.4 Logging and Monitoring
  - A.12.4.1: Event logging covering all security-relevant events
  - A.12.4.2: Protection of log information from tampering
  - A.12.4.3: System administrator and operator logs
  
A.16.1 Management of Information Security Incidents
  - A.16.1.1: Incident logging with forensic value
  - A.16.1.7: Collection of evidence for legal proceedings

A.18.1 Compliance with Legal and Contractual Requirements
  - A.18.1.3: Protection of records (7-year retention)
  - A.18.1.4: Privacy and protection of PII in audit logs
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION IN CLOUD
================================================================================
- Audit logs track all PII access for compliance
- Data subject access request support through audit queries
- Secure handling of PII in audit records with masking
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
5.4.2 Audit Logging for Storage
  - Partitioning for performance and retention management
  - Compression for long-term archival
  - Encryption at rest for audit records
  
7.3 Data Retention and Disposal
  - Automated partition lifecycle management
  - Legal hold capability preventing deletion
  - Secure purge procedures for expired data
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
Clause 4: EDRM Reference Model Alignment
  - Information Management: Structured audit schema
  - Identification: Indexed fields for e-discovery queries
  - Preservation: Immutable storage with legal hold
  - Collection: Partitioned tables for efficient export
  - Processing: Normalized JSONB for standard formats
  - Review: Views for compliance officer access
  - Production: Export functions for litigation support
  - Presentation: Time-series views for timeline analysis
================================================================================

================================================================================
PCI DSS 4.0 AUDIT REQUIREMENTS
================================================================================
Requirement 10.3.1: Retain audit trail history for minimum 1 year
Requirement 10.3.2: Immediate availability of at least 3 months of logs
Requirement 10.3.3: Secure storage preventing modification
Requirement 10.3.4: Centralized logging for critical systems
Requirement 10.3.5: File integrity monitoring on audit logs
Requirement 10.3.6: Synchronization of time across systems
Requirement 10.7: Retention policy for audit logs
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. Native partitioning by time range for performance
2. RLS policies preventing UPDATE/DELETE on audit tables
3. JSONB for flexible structured data storage
4. Appropriate indexes for common query patterns
5. Automated partition creation and archival
================================================================================

================================================================================
AUDIT TRAIL IMMUTABILITY
================================================================================
Enforcement Mechanisms:
  1. RLS policies: DENY UPDATE/DELETE on audit tables
  2. Database triggers: Block modification attempts
  3. Application role permissions: Read-only access
  4. WORM storage integration for archive partitions
  5. Cryptographic signing of audit batches

Integrity Verification:
  - Periodic hash chain verification
  - Automated integrity reports
  - External blockchain anchoring (optional)
================================================================================

================================================================================
RETENTION AND ARCHIVAL POLICY
================================================================================
Active Partition (Hot): Last 3 months on fast storage
Archive Partition (Warm): 3-12 months on standard storage
Cold Storage: 1-7 years on compressed/archival storage
Legal Hold: Indefinite retention for litigation holds
================================================================================
*/

-- ============================================================================
-- CORE AUDIT LOG TABLE
-- ============================================================================

-- ISO/IEC 27001: A.12.4.1 - Main audit log table
-- PCI DSS 10.3 - Native partitioning for retention management
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schema_name VARCHAR(63) NOT NULL,
    table_name VARCHAR(63) NOT NULL,
    operation VARCHAR(10) NOT NULL CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')),
    record_id TEXT,
    old_data JSONB,
    new_data JSONB,
    changed_fields JSONB,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by UUID,
    session_user_name VARCHAR(100),
    application_name VARCHAR(100),
    client_addr INET,
    client_port INTEGER,
    transaction_id BIGINT,
    statement_id BIGINT,
    query_text TEXT,
    severity VARCHAR(20) DEFAULT 'info',
    metadata JSONB DEFAULT '{}'
) PARTITION BY RANGE (changed_at);

-- Create initial partitions for current and next month
-- ISO/IEC 27040: Automated partition management
DO $$
DECLARE
    current_month TEXT;
    next_month TEXT;
BEGIN
    current_month := to_char(NOW(), 'YYYY_MM');
    next_month := to_char(NOW() + INTERVAL '1 month', 'YYYY_MM');
    
    -- Current month partition
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS audit_log_%s PARTITION OF audit_log
         FOR VALUES FROM (%L) TO (%L)',
        current_month,
        date_trunc('month', NOW()),
        date_trunc('month', NOW() + INTERVAL '1 month')
    );
    
    -- Next month partition
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS audit_log_%s PARTITION OF audit_log
         FOR VALUES FROM (%L) TO (%L)',
        next_month,
        date_trunc('month', NOW() + INTERVAL '1 month'),
        date_trunc('month', NOW() + INTERVAL '2 months')
    );
END $$;

-- Indexes on partitioned table (PCI DSS 10.3.4)
CREATE INDEX IF NOT EXISTS idx_audit_log_table_op ON audit_log(table_name, operation);
CREATE INDEX IF NOT EXISTS idx_audit_log_changed_by ON audit_log(changed_by);
CREATE INDEX IF NOT EXISTS idx_audit_log_record_id ON audit_log(record_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_changed_at ON audit_log(changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_transaction ON audit_log(transaction_id);

-- ============================================================================
-- SPECIALIZED AUDIT TABLES
-- ============================================================================

-- Transaction audit log (high-value/sensitive operations)
-- PCI DSS: Enhanced logging for CHD access
CREATE TABLE IF NOT EXISTS transaction_audit_log (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    operation VARCHAR(10) NOT NULL,
    audit_data JSONB NOT NULL,
    compliance_flags JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- Authentication audit log
-- ISO/IEC 27001: A.9.4.2 - Authentication monitoring
CREATE TABLE IF NOT EXISTS authentication_audit_log (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    event_details JSONB NOT NULL,
    risk_score INTEGER DEFAULT 0,
    alert_triggered BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- PII access audit log (GDPR/CCPA compliance)
-- ISO/IEC 27018: PII processing monitoring
CREATE TABLE IF NOT EXISTS pii_access_audit (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    data_subject_id TEXT NOT NULL,
    access_type VARCHAR(20) NOT NULL,
    legal_basis VARCHAR(50),
    consent_reference VARCHAR(100),
    access_context JSONB NOT NULL,
    retention_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- ============================================================================
-- AUDIT ERROR AND MAINTENANCE TABLES
-- ============================================================================

-- Audit error log (for failed audit writes)
-- ISO/IEC 27001: A.12.4.2 - Audit system reliability
CREATE TABLE IF NOT EXISTS audit_error_log (
    error_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    error_time TIMESTAMPTZ DEFAULT NOW(),
    table_schema VARCHAR(63),
    table_name VARCHAR(63),
    operation VARCHAR(10),
    error_message TEXT,
    original_data JSONB
);

-- Audit archive table (for old partitions)
-- ISO/IEC 27040: Long-term storage
CREATE TABLE IF NOT EXISTS audit_archive (
    LIKE audit_log INCLUDING ALL,
    archived_at TIMESTAMPTZ DEFAULT NOW(),
    archive_reason VARCHAR(50)
);

-- ============================================================================
-- RLS POLICIES FOR AUDIT TABLE PROTECTION
-- ============================================================================

-- Prevent modification of audit tables (immutability)
-- ISO/IEC 27001: A.12.4.2 - Protection of log information
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;

-- Policy: audit_immutable - Deny all modifications
CREATE POLICY audit_immutable ON audit_log
    FOR ALL
    TO PUBLIC
    USING (FALSE);

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE audit_log IS 'ISO/IEC 27001 A.12.4 - Main audit log table partitioned by month for retention management';
COMMENT ON TABLE transaction_audit_log IS 'PCI DSS - Specialized audit log for financial transactions with compliance flags';
COMMENT ON TABLE pii_access_audit IS 'ISO/IEC 27018 - GDPR/CCPA compliant PII access tracking with legal basis';
COMMENT ON POLICY audit_immutable ON audit_log IS 'ISO/IEC 27001 A.12.4.2 - Prevents modification of audit records';

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Implement automated partition compression for older data (ISO 27040)
-- TODO: Add foreign data wrapper for cross-region audit aggregation (ISO 27001)
-- TODO: Implement real-time materialized view refresh for dashboards
-- TODO: Add support for time-series database integration (TimescaleDB)
-- TODO: Implement audit log encryption at rest (PCI DSS 10.3.3)
-- TODO: Create automated backup and disaster recovery procedures (ISO 27001 A.12)
-- TODO: Add column-level statistics for audit optimization
-- TODO: Implement audit log anomaly detection materialized views
-- TODO: Create audit data lineage tracking (ISO 27050-3)
-- TODO: Add support for audit log digital signatures (ISO 27001 A.10)
-- ============================================================================
