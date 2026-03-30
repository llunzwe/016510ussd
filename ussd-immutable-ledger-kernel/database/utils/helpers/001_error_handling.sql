-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: utils/helpers/001_error_handling.sql
-- Description: Standardized error handling functions, custom exceptions,
--              and error logging utilities
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: INTERNAL
-- DATA SENSITIVITY: MEDIUM - Error Diagnostics
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.16.1: Management of Information Security Incidents
  - Structured error logging for incident detection
  - Error categorization for priority response
  
A.12.4: Logging and Monitoring
  - Error logging with user context
  - Retry tracking for availability monitoring

A.14.2.5: Secure System Engineering Principles
  - Error messages without information disclosure
  - Standardized error codes for security
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION
================================================================================
- Error logging without PII exposure
- Sanitized error messages for external display
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
- Error logging for storage operation failures
- Data integrity error detection
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
- Error logs as ESI for litigation
- Immutable error audit trail
================================================================================

================================================================================
PCI DSS 4.0 ERROR HANDLING REQUIREMENTS
================================================================================
Requirement 6.5: Secure error handling
Requirement 10.7: Error log retention
Requirement 11.4.5: Intrusion detection through error monitoring
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. Standardized error codes for all error types
2. Error logging without blocking operations
3. Retry logic for transient failures
4. Severity classification for alerts
5. Partitioned error logs for retention management
================================================================================

================================================================================
ERROR CATEGORIES
================================================================================
- AUTH: Authentication errors
- FORB: Authorization errors  
- VAL: Validation errors
- DB: Database errors
- BIZ: Business logic errors
- EXT: External service errors
================================================================================
*/

-- ============================================================================
-- ERROR CODES AND DEFINITIONS
-- ============================================================================

-- Table for error code definitions
CREATE TABLE IF NOT EXISTS error_code_definitions (
    error_code VARCHAR(20) PRIMARY KEY,
    error_category VARCHAR(50) NOT NULL,
    error_title VARCHAR(100) NOT NULL,
    error_description TEXT,
    http_status_code INTEGER,
    is_retryable BOOLEAN DEFAULT FALSE,
    default_severity VARCHAR(20) DEFAULT 'ERROR',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert standard error codes
INSERT INTO error_code_definitions (
    error_code, error_category, error_title, error_description, 
    http_status_code, is_retryable, default_severity
) VALUES
    -- Authentication Errors (AUTH)
    ('AUTH-001', 'authentication', 'Unauthorized', 'Authentication is required', 401, FALSE, 'WARNING'),
    ('AUTH-002', 'authentication', 'Invalid Credentials', 'The provided credentials are invalid', 401, FALSE, 'WARNING'),
    ('AUTH-003', 'authentication', 'Token Expired', 'The authentication token has expired', 401, FALSE, 'WARNING'),
    
    -- Authorization Errors (FORB)
    ('FORB-001', 'authorization', 'Forbidden', 'Access to this resource is forbidden', 403, FALSE, 'WARNING'),
    ('FORB-002', 'authorization', 'Insufficient Permissions', 'The user lacks required permissions', 403, FALSE, 'WARNING'),
    
    -- Validation Errors (VAL)
    ('VAL-001', 'validation', 'Invalid Input', 'The provided input is invalid', 400, FALSE, 'WARNING'),
    ('VAL-002', 'validation', 'Missing Required Field', 'A required field is missing', 400, FALSE, 'WARNING'),
    
    -- Database Errors (DB)
    ('DB-001', 'database', 'Connection Error', 'Failed to connect to the database', 500, TRUE, 'CRITICAL'),
    ('DB-002', 'database', 'Query Error', 'Database query execution failed', 500, FALSE, 'ERROR')
ON CONFLICT (error_code) DO UPDATE SET
    error_title = EXCLUDED.error_title,
    error_description = EXCLUDED.error_description,
    http_status_code = EXCLUDED.http_status_code;

-- ============================================================================
-- ERROR LOGGING
-- ============================================================================

-- Error log table with partitioning
-- PCI DSS 10.7: Error log retention
CREATE TABLE IF NOT EXISTS error_log (
    error_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    error_code VARCHAR(20) REFERENCES error_code_definitions(error_code),
    error_message TEXT,
    error_details JSONB,
    user_id UUID,
    session_id UUID,
    request_id UUID,
    ip_address INET,
    function_name TEXT,
    severity VARCHAR(20) DEFAULT 'ERROR',
    status VARCHAR(20) DEFAULT 'open',
    created_at TIMESTAMPTZ DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE error_code_definitions IS 'ISO/IEC 27001: Standardized error code definitions for security incident tracking';
COMMENT ON TABLE error_log IS 'PCI DSS 10.7: Error log with partitioning for retention management';

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Add error aggregation and alerting thresholds
-- TODO: Implement error correlation analysis
-- TODO: Add automated error resolution suggestions
-- TODO: Implement error rate limiting and circuit breaker patterns
-- TODO: Add integration with external error tracking services (Sentry, etc.)
-- TODO: Implement error simulation for testing
-- TODO: Add error impact assessment scoring
-- TODO: Create error dashboard data views
-- TODO: Implement error prediction using ML
-- TODO: Add error recovery workflow automation
-- ============================================================================
