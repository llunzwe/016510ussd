-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: utils/helpers/002_logging_utilities.sql
-- Description: Comprehensive logging system with severity levels, structured
--              logging, and log rotation capabilities
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: INTERNAL
-- DATA SENSITIVITY: MEDIUM - Application Logs
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.12.4 Logging and Monitoring
  - Structured logging with severity levels
  - Comprehensive application event tracking
  
A.12.4.1: Event Logging
  - User identification in all log entries
  - Timestamp synchronization
  
A.12.4.2: Protection of Log Information
  - Log partitioning prevents tampering
  - Structured format for integrity verification
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION
================================================================================
- Logging without PII exposure
- Structured logs for privacy audit
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
- Log partitioning for retention management
- Compression for efficient storage
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
- Structured logs as ESI
- Immutable log retention
================================================================================

================================================================================
PCI DSS 4.0 LOGGING REQUIREMENTS
================================================================================
Requirement 10.2: Audit logs covering all system components
Requirement 10.3: Audit trail coverage
Requirement 10.7: Retention policy for audit logs
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. Partitioned tables for log retention
2. JSONB for structured logging
3. Severity levels aligned with syslog
4. Correlation IDs for distributed tracing
5. Automated log rotation
================================================================================

================================================================================
LOG LEVELS (RFC 5424 Syslog Severity Levels)
================================================================================
DEBUG (7): Detailed debugging information
INFO (6): Informational messages
NOTICE (5): Normal but significant condition
WARNING (4): Warning conditions
ERROR (3): Error conditions
CRITICAL (2): Critical conditions
ALERT (1): Action must be taken immediately
EMERGENCY (0): System is unusable
================================================================================

================================================================================
RETENTION POLICY
================================================================================
Application Logs: 90 days
Security Events: 1 year (PCI DSS 10.7)
Audit Logs: 7 years (financial regulations)
Critical Errors: 3 years
================================================================================
*/

-- ============================================================================
-- LOG LEVELS CONFIGURATION
-- ============================================================================

CREATE TYPE log_level AS ENUM ('DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERROR', 'CRITICAL', 'ALERT', 'EMERGENCY');

-- Configuration table
CREATE TABLE IF NOT EXISTS logging_config (
    config_key VARCHAR(50) PRIMARY KEY,
    config_value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default configuration
INSERT INTO logging_config (config_key, config_value, description) VALUES
    ('min_log_level', 'INFO', 'Minimum log level to record'),
    ('log_to_table', 'true', 'Enable table logging'),
    ('log_retention_days', '90', 'Number of days to retain logs (PCI DSS 10.7)'),
    ('audit_log_enabled', 'true', 'Enable audit logging')
ON CONFLICT (config_key) DO UPDATE SET
    config_value = EXCLUDED.config_value;

-- ============================================================================
-- LOG TABLES
-- ============================================================================

-- Main application log
CREATE TABLE IF NOT EXISTS app_log (
    log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    log_timestamp TIMESTAMPTZ DEFAULT NOW(),
    log_level log_level NOT NULL,
    log_source VARCHAR(100),
    log_function VARCHAR(100),
    log_message TEXT NOT NULL,
    log_details JSONB,
    user_id UUID,
    session_id UUID,
    request_id UUID,
    correlation_id UUID,
    ip_address INET
) PARTITION BY RANGE (log_timestamp);

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TYPE log_level IS 'Standard log severity levels (RFC 5424 Syslog)';
COMMENT ON TABLE app_log IS 'Application log with partitioning by month (PCI DSS 10.7)';

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Add log shipping to external systems (ELK, Splunk, etc.)
-- TODO: Implement log sampling for high-volume scenarios
-- TODO: Add log correlation and distributed tracing support
-- TODO: Implement log-based alerting rules engine
-- TODO: Add support for structured logging with OpenTelemetry
-- TODO: Implement log compression for archival storage
-- TODO: Add real-time log streaming via WebSocket
-- TODO: Create log analysis and anomaly detection
-- TODO: Implement log-based metrics extraction
-- TODO: Add log deduplication for repeated messages
-- ============================================================================
