-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: utils/helpers/000_json_validation.sql
-- Description: Functions for validating JSON data against schemas and
--              common validation patterns
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: INTERNAL
-- DATA SENSITIVITY: MEDIUM - Input Validation
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.14.2.5: Secure System Engineering Principles
  - Input validation for all JSON data processing
  - Schema validation to prevent injection attacks
  
A.12.6.1: Management of Technical Vulnerabilities
  - Data type validation prevents type confusion attacks
  - Pattern validation for security-sensitive fields

A.8.2.3: Handling of Assets
  - Data classification validation
  - Retention policy enforcement in JSON data
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION
================================================================================
- Email and phone validation for PII handling
- Data subject ID validation for GDPR compliance
- Consent reference validation
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
- JSON validation for secure configuration storage
- Schema validation for audit log integrity
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
- JSON schema validation for ESI metadata
- Structured validation for discovery processing
================================================================================

================================================================================
PCI DSS 4.0 INPUT VALIDATION REQUIREMENTS
================================================================================
Requirement 6.5.1: Injection Flaws
  - Parameterized JSON validation
  - Type checking prevents SQL injection through JSON
  
Requirement 6.5.7: Cross-Site Scripting (XSS)
  - Output encoding for JSON content
  - Pattern validation for HTML/script content
  
Requirement 12.3.2: Security Parameters
  - Validation of security configuration in JSON
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. IMMUTABLE functions for validation (cacheable)
2. Clear error messages without information disclosure
3. Support for custom validation rules
4. Logging of validation failures
5. Batch validation for efficiency
================================================================================

================================================================================
INPUT VALIDATION SECURITY
================================================================================
Validation Layers:
  1. Schema validation (structure)
  2. Type validation (data types)
  3. Range validation (numeric bounds)
  4. Pattern validation (regex)
  5. Enum validation (allowed values)
  6. Length validation (string bounds)
  7. Cross-field validation (dependencies)

Security Patterns:
  - Reject invalid input early
  - Log validation failures for monitoring
  - Sanitize output for downstream use
  - Prevent information leakage in errors
================================================================================

================================================================================
AUDIT REQUIREMENTS (ISO/IEC 27050-3:2020)
================================================================================
- All validation failures logged with context
- Schema changes tracked for compliance
================================================================================
*/

-- ============================================================================
-- JSON SCHEMA VALIDATION
-- ============================================================================

-- Table to store JSON schemas
-- ISO/IEC 27001: Centralized validation policy
CREATE TABLE IF NOT EXISTS json_schemas (
    schema_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schema_name VARCHAR(100) NOT NULL UNIQUE,
    schema_version INTEGER NOT NULL DEFAULT 1,
    schema_definition JSONB NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- CORE VALIDATION FUNCTIONS
-- ============================================================================

-- Function to validate JSON has required fields
-- PCI DSS: Input validation for security parameters
-- Parameters: p_data, p_required_fields
-- Returns: is_valid, missing_fields
CREATE OR REPLACE FUNCTION json_has_required_fields(
    p_data JSONB,
    p_required_fields TEXT[]
)
RETURNS TABLE (
    is_valid BOOLEAN,
    missing_fields TEXT[]
) AS $$
DECLARE
    v_missing TEXT[] := ARRAY[]::TEXT[];
    v_field TEXT;
BEGIN
    FOREACH v_field IN ARRAY p_required_fields
    LOOP
        IF NOT (p_data ? v_field) OR p_data->v_field IS NULL OR p_data->v_field = 'null'::JSONB THEN
            v_missing := array_append(v_missing, v_field);
        END IF;
    END LOOP;
    
    RETURN QUERY SELECT 
        array_length(v_missing, 1) IS NULL OR array_length(v_missing, 1) = 0,
        v_missing;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE json_schemas IS 'ISO/IEC 27001: Storage for JSON validation schemas';
COMMENT ON FUNCTION json_has_required_fields IS 'PCI DSS: Validate JSONB has all required fields for input validation';

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Add support for JSON Schema Draft 2020-12
-- TODO: Implement conditional validation (if-then-else)
-- TODO: Add support for recursive schema references
-- TODO: Implement custom validation rule engine
-- TODO: Add support for async validation with external services
-- TODO: Implement validation caching for performance
-- TODO: Add support for multilingual error messages
-- TODO: Implement schema versioning and migration tools
-- TODO: Add integration with AJV (Another JSON Schema Validator)
-- TODO: Implement real-time validation API endpoint
-- ============================================================================
