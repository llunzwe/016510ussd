-- =============================================================================
-- USSD KERNEL CORE SCHEMA - TRIGGERS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    000_immutability_enforcement.sql
-- SCHEMA:      core
-- CATEGORY:    Triggers - Immutability
-- DESCRIPTION: Database-level immutability enforcement triggers preventing
--              UPDATE, DELETE, and TRUNCATE operations on core ledger tables.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Modification attempt logging
├── A.10.1 Cryptographic controls - Integrity enforcement
├── A.12.4 Logging and monitoring - Violation monitoring
├── A.16.1 Management of information security incidents - Violation response
└── A.16.2 Assessment and decision - Incident investigation

ISO/IEC 27040:2024 (Storage Security - CRITICAL for immutable ledger)
├── Write-Once-Read-Many (WORM): Hardware-level enforcement
├── Tamper prevention: Database-level enforcement
├── Violation logging: Immutable audit trail
├── Superuser override: Emergency procedures with audit
└── Compensating transactions: Correction workflow

ISO/IEC 27031:2025 (Business Continuity ICT Readiness)
├── Immutability during failover: Cross-site enforcement
├── Recovery integrity: Post-recovery verification
└── Backup immutability: Backup protection

Financial Regulations
├── Audit trail: Complete transaction history
├── Tamper evidence: Cryptographic proof
├── Correction workflow: Compensating entries
└── Regulatory examination: Immutable evidence

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. TRIGGER TYPES
   - BEFORE UPDATE: Block all updates
   - BEFORE DELETE: Block all deletes
   - BEFORE TRUNCATE: Block truncation
   - Conditional: Allow superuser in emergencies

2. ERROR HANDLING
   - Meaningful error messages
   - Hints for corrective action
   - Error codes for programmatic handling
   - Audit logging of attempts

3. EXCEPTION MANAGEMENT
   - Superuser bypass (configurable)
   - Emergency maintenance window
   - Explicit logging of bypass
   - Post-bypass verification

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

IMMUTABILITY ENFORCEMENT:
1. Update Prevention
   - BEFORE UPDATE trigger on all immutable tables
   - Exception raised for all UPDATE attempts
   - Superuser bypass with explicit warning (if enabled)
   - Violation logged to integrity_violations table

2. Delete Prevention
   - BEFORE DELETE trigger on all immutable tables
   - Exception raised for all DELETE attempts
   - No bypass allowed (even for superuser)
   - Violation logged with full context

3. Truncate Prevention
   - BEFORE TRUNCATE trigger on all immutable tables
   - Exception raised for all TRUNCATE attempts
   - No bypass allowed (truncation is too destructive)
   - Critical violation alert generated

VIOLATION HANDLING:
1. Logging
   - Complete violation context captured
   - User, time, query, and data recorded
   - Automated alerting on violations
   - Forensic investigation support

2. Response
   - Immediate blocking of operation
   - Real-time alerting to security team
   - Investigation workflow triggered
   - Incident documentation required

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

TRIGGER EFFICIENCY:
- Minimal trigger function overhead
- Fast condition checking
- Efficient logging
- No impact on INSERT performance

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

MANDATORY AUDIT EVENTS:
1. IMMUTABILITY_VIOLATION_ATTEMPT: Any attempt to modify immutable data
2. SUPERUSER_BYPASS: Emergency override usage
3. VIOLATION_INVESTIGATION: Investigation initiation
4. VIOLATION_RESOLUTION: Investigation completion

LOGGED FIELDS:
- attempted_operation: UPDATE, DELETE, TRUNCATE
- table_schema, table_name: Target table
- record_id: Affected record identifier
- old_data, new_data: Before/after values
- user_name: Database user
- application_name: Connected application
- client_addr, client_port: Network source
- backend_pid: Process ID
- query_text: Executed SQL
- attempted_at: Timestamp

RETENTION: 7 years (violations are security incidents)
================================================================================
*/

-- =============================================================================
-- TODO: Create integrity_violations table
-- DESCRIPTION: Log of immutability violation attempts
-- PRIORITY: HIGH
-- SECURITY: Append-only audit trail
-- =============================================================================
-- [Existing content preserved...]

-- =============================================================================
-- TODO: Create prevent_update trigger function
-- DESCRIPTION: Block UPDATE operations on immutable tables
-- PRIORITY: CRITICAL
-- =============================================================================
-- [Existing content preserved...]

-- =============================================================================
-- TODO: Create prevent_delete trigger function
-- DESCRIPTION: Block DELETE operations on immutable tables
-- PRIORITY: CRITICAL
-- =============================================================================
-- [Existing content preserved...]

-- =============================================================================
-- TODO: Create prevent_truncate trigger function
-- DESCRIPTION: Block TRUNCATE operations on immutable tables
-- PRIORITY: CRITICAL
-- =============================================================================
-- [Existing content preserved...]

-- =============================================================================
-- TODO: Apply immutability triggers to core tables
-- DESCRIPTION: Attach triggers to all immutable tables
-- PRIORITY: CRITICAL
-- =============================================================================
-- [Existing content preserved...]

/*
================================================================================
MIGRATION CHECKLIST:
□ Create integrity_violations table
□ Create prevent_update trigger function
□ Create prevent_delete trigger function
□ Create prevent_truncate trigger function
□ Apply triggers to transaction_log
□ Apply triggers to accounts
□ Apply triggers to movement_headers
□ Apply triggers to movement_legs
□ Apply triggers to blocks (with OPEN exception)
□ Apply triggers to merkle_nodes
□ Test UPDATE blocking
□ Test DELETE blocking
□ Test TRUNCATE blocking
□ Test superuser bypass (if configured)
□ Set up alerts on integrity_violations inserts
================================================================================
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
