-- =============================================================================
-- USSD KERNEL CORE SCHEMA - AUDIT TRAIL
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    029_audit_trail.sql
-- SCHEMA:      ussd_core
-- TABLE:       audit_trail
-- DESCRIPTION: Comprehensive audit trail for all data access and modifications
--              with immutable logging for compliance and forensic analysis.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Access logging
├── A.8.5 Secure authentication - Authentication audit
├── A.8.11 Data masking - Sensitive data handling
├── A.8.15 Logging - Comprehensive activity logging
└── A.8.16 Monitoring - Real-time monitoring

ISO/IEC 27040:2024 (Storage Security)
├── Immutable audit logs: WORM storage
├── Tamper detection: Hash chain verification
├── Long-term retention: 7+ years
└── Integrity verification: Cryptographic integrity

GDPR Compliance
├── Lawful basis: Legitimate interest for security
├── Data minimization: Minimal PII in logs
├── Retention limits: Defined retention periods
└── Subject access: Log access for data subjects

Financial Regulations
├── SOX: Change audit trail
├── PCI DSS: Access logging
├── AML: Activity monitoring
└── General: 7 year retention

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. AUDIT CATEGORIES
   - DATA_ACCESS: Read operations
   - DATA_CHANGE: Create/update/delete
   - SECURITY: Authentication/authorization
   - ADMIN: Administrative actions
   - SYSTEM: System events

2. AUDIT LEVELS
   - DEBUG: Detailed debugging info
   - INFO: Normal operations
   - WARNING: Suspicious activity
   - ERROR: Errors and failures
   - CRITICAL: Security incidents

3. DATA HANDLING
   - Sanitization of sensitive data
   - PII masking
   - Encryption of sensitive fields
   - Hash verification

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

AUDIT SECURITY:
- Immutable audit records
- Separate audit schema
- Audit table protection
- Hash chain verification

TAMPER DETECTION:
- Record hashing
- Chain verification
- Anomaly detection
- Alert on tampering

ACCESS CONTROL:
- Audit read restricted to auditors
- No delete access
- Append-only enforcement

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: audit_id
- TIME: created_at DESC
- CATEGORY: audit_category + created_at
- ACTOR: actor_account_id + created_at
- TABLE: table_name + record_id

PARTITIONING:
- Range partition by created_at (monthly)
- Auto-archive old partitions
- Compression for old data

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

MANDATORY EVENTS:
- All authentication attempts
- All authorization decisions
- All data modifications
- All administrative actions
- All security events
- All system events

RETENTION:
- Security events: 7 years
- Data changes: 7 years
- Access logs: 2 years
- Debug logs: 30 days

MONITORING:
- Real-time alerting
- Anomaly detection
- Compliance dashboards
- Forensic search

================================================================================
*/

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.audit_trail (
    -- Primary identifier
    audit_id BIGSERIAL,
    
    -- Audit classification
    audit_category VARCHAR(50) NOT NULL
        CHECK (audit_category IN ('DATA_ACCESS', 'DATA_CHANGE', 'SECURITY', 'ADMIN', 'SYSTEM')),
    audit_level VARCHAR(20) NOT NULL
        CHECK (audit_level IN ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')),
    audit_event VARCHAR(100) NOT NULL,
    
    -- Actor information
    actor_account_id UUID,
    actor_type VARCHAR(50),  -- 'USER', 'SYSTEM', 'API', 'BATCH'
    session_id TEXT,
    
    -- Action details
    action VARCHAR(50) NOT NULL,  -- 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'LOGIN', etc.
    action_status VARCHAR(20) NOT NULL,  -- 'SUCCESS', 'FAILURE', 'DENIED'
    
    -- Target object
    table_schema VARCHAR(50),
    table_name VARCHAR(100),
    record_id TEXT,
    
    -- Change data
    old_data JSONB,
    new_data JSONB,
    change_summary TEXT,
    
    -- Context
    application_id UUID,
    transaction_id UUID,
    correlation_id UUID,
    
    -- Client information
    client_ip INET,
    user_agent TEXT,
    request_id TEXT,
    
    -- Query information
    query_text TEXT,
    row_count INTEGER,
    execution_time_ms INTEGER,
    
    -- Integrity
    record_hash VARCHAR(64) NOT NULL,
    previous_audit_hash VARCHAR(64),  -- For hash chain
    
    -- Timing
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    
    -- Partition key
    partition_date DATE NOT NULL DEFAULT CURRENT_DATE,
    
    -- Constraints
    PRIMARY KEY (audit_id, partition_date)
) PARTITION BY RANGE (partition_date);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
