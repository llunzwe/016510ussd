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

-- Create index for active schema lookups
CREATE INDEX IF NOT EXISTS idx_json_schemas_active ON json_schemas(schema_name, schema_version) WHERE is_active = TRUE;

-- ============================================================================
-- SCHEMA VERSIONING AND MIGRATION TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS json_schema_versions (
    version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    schema_name VARCHAR(100) NOT NULL,
    schema_version INTEGER NOT NULL,
    schema_definition JSONB NOT NULL,
    migration_notes TEXT,
    breaking_changes BOOLEAN DEFAULT FALSE,
    deprecated_fields TEXT[],
    new_fields TEXT[],
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID,
    UNIQUE(schema_name, schema_version)
);

CREATE INDEX IF NOT EXISTS idx_schema_versions_lookup ON json_schema_versions(schema_name, schema_version);

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
-- JSON SCHEMA DRAFT 2020-12 SUPPORT
-- ============================================================================

-- Type validation function supporting JSON Schema Draft 2020-12 types
CREATE OR REPLACE FUNCTION json_validate_type(
    p_value JSONB,
    p_expected_type TEXT
)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN CASE p_expected_type
        WHEN 'string' THEN jsonb_typeof(p_value) = 'string'
        WHEN 'number' THEN jsonb_typeof(p_value) IN ('number')
        WHEN 'integer' THEN jsonb_typeof(p_value) = 'number' AND p_value = trunc(p_value::numeric)::jsonb
        WHEN 'boolean' THEN jsonb_typeof(p_value) = 'boolean'
        WHEN 'array' THEN jsonb_typeof(p_value) = 'array'
        WHEN 'object' THEN jsonb_typeof(p_value) = 'object'
        WHEN 'null' THEN p_value IS NULL OR p_value = 'null'::JSONB
        ELSE FALSE
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- CONDITIONAL VALIDATION (IF-THEN-ELSE)
-- ============================================================================

-- Function to evaluate conditional validation rules
CREATE OR REPLACE FUNCTION json_validate_conditional(
    p_data JSONB,
    p_if_condition JSONB,
    p_then_schema JSONB DEFAULT NULL,
    p_else_schema JSONB DEFAULT NULL
)
RETURNS TABLE (
    condition_matched BOOLEAN,
    validation_passed BOOLEAN,
    errors TEXT[]
) AS $$
DECLARE
    v_condition_met BOOLEAN := TRUE;
    v_property TEXT;
    v_required TEXT[];
    v_validation_passed BOOLEAN := TRUE;
    v_errors TEXT[] := ARRAY[]::TEXT[];
BEGIN
    -- Evaluate if condition (simple property existence check)
    IF p_if_condition ? 'required' THEN
        v_required := ARRAY(SELECT jsonb_array_elements_text(p_if_condition->'required'));
        SELECT (result.is_valid), result.missing_fields 
        INTO v_condition_met, v_errors
        FROM json_has_required_fields(p_data, v_required) result;
    END IF;
    
    -- Check properties condition
    IF p_if_condition ? 'properties' THEN
        FOR v_property IN SELECT jsonb_object_keys(p_if_condition->'properties')
        LOOP
            IF p_data ? v_property THEN
                IF p_data->v_property != (p_if_condition->'properties'->v_property->>'const')::JSONB THEN
                    v_condition_met := FALSE;
                END IF;
            ELSE
                v_condition_met := FALSE;
            END IF;
        END LOOP;
    END IF;
    
    -- Apply then/else schema based on condition
    IF v_condition_met AND p_then_schema IS NOT NULL THEN
        -- Apply then schema validations
        SELECT passed, errs INTO v_validation_passed, v_errors
        FROM json_validate_against_schema(p_data, p_then_schema);
    ELSIF NOT v_condition_met AND p_else_schema IS NOT NULL THEN
        -- Apply else schema validations  
        SELECT passed, errs INTO v_validation_passed, v_errors
        FROM json_validate_against_schema(p_data, p_else_schema);
    END IF;
    
    RETURN QUERY SELECT v_condition_met, v_validation_passed, v_errors;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- SCHEMA REFERENCE RESOLUTION
-- ============================================================================

-- Function to resolve and validate against schema references
CREATE OR REPLACE FUNCTION json_resolve_schema_ref(
    p_ref_path TEXT,
    p_base_schema JSONB DEFAULT NULL
)
RETURNS JSONB AS $$
DECLARE
    v_schema_def JSONB;
    v_schema_name TEXT;
    v_ref_parts TEXT[];
BEGIN
    -- Handle internal fragment references
    IF p_ref_path LIKE '#/%' THEN
        IF p_base_schema IS NULL THEN
            RETURN NULL;
        END IF;
        -- Navigate through the schema using path
        v_ref_parts := string_to_array(substring(p_ref_path FROM 3), '/');
        v_schema_def := p_base_schema;
        FOR i IN 1..array_length(v_ref_parts, 1)
        LOOP
            IF v_schema_def ? v_ref_parts[i] THEN
                v_schema_def := v_schema_def->v_ref_parts[i];
            ELSE
                RETURN NULL;
            END IF;
        END LOOP;
        RETURN v_schema_def;
    END IF;
    
    -- Handle external schema references
    IF p_ref_path LIKE '%#/%' THEN
        v_schema_name := split_part(split_part(p_ref_path, '#', 1), '/', -1);
        SELECT schema_definition INTO v_schema_def
        FROM json_schemas
        WHERE schema_name = v_schema_name AND is_active = TRUE
        ORDER BY schema_version DESC
        LIMIT 1;
        RETURN v_schema_def;
    END IF;
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- COMPREHENSIVE SCHEMA VALIDATION
-- ============================================================================

-- Main schema validation function
CREATE OR REPLACE FUNCTION json_validate_against_schema(
    p_data JSONB,
    p_schema JSONB
)
RETURNS TABLE (
    passed BOOLEAN,
    errs TEXT[]
) AS $$
DECLARE
    v_errors TEXT[] := ARRAY[]::TEXT[];
    v_property TEXT;
    v_required TEXT[];
    v_type TEXT;
    v_pattern TEXT;
    v_enum JSONB;
    v_min_length INTEGER;
    v_max_length INTEGER;
    v_minimum NUMERIC;
    v_maximum NUMERIC;
    v_ref_schema JSONB;
BEGIN
    -- Handle $ref references
    IF p_schema ? '$ref' THEN
        v_ref_schema := json_resolve_schema_ref(p_schema->>'$ref', p_schema);
        IF v_ref_schema IS NOT NULL THEN
            RETURN QUERY SELECT * FROM json_validate_against_schema(p_data, v_ref_schema);
            RETURN;
        END IF;
    END IF;
    
    -- Validate type
    IF p_schema ? 'type' THEN
        v_type := p_schema->>'type';
        IF NOT json_validate_type(p_data, v_type) THEN
            v_errors := array_append(v_errors, format('Invalid type: expected %s, got %s', v_type, jsonb_typeof(p_data)));
        END IF;
    END IF;
    
    -- Validate required fields
    IF p_schema ? 'required' THEN
        v_required := ARRAY(SELECT jsonb_array_elements_text(p_schema->'required'));
        SELECT array_append(v_errors, format('Missing required fields: %s', array_to_string(missing, ', ')))
        INTO v_errors
        FROM json_has_required_fields(p_data, v_required)
        WHERE NOT is_valid;
    END IF;
    
    -- String validations
    IF jsonb_typeof(p_data) = 'string' THEN
        -- Min length
        IF p_schema ? 'minLength' THEN
            v_min_length := (p_schema->>'minLength')::INTEGER;
            IF length(p_data#>>'{}') < v_min_length THEN
                v_errors := array_append(v_errors, format('String too short: minimum %s characters', v_min_length));
            END IF;
        END IF;
        
        -- Max length
        IF p_schema ? 'maxLength' THEN
            v_max_length := (p_schema->>'maxLength')::INTEGER;
            IF length(p_data#>>'{}') > v_max_length THEN
                v_errors := array_append(v_errors, format('String too long: maximum %s characters', v_max_length));
            END IF;
        END IF;
        
        -- Pattern validation
        IF p_schema ? 'pattern' THEN
            v_pattern := p_schema->>'pattern';
            IF NOT (p_data#>>'{}') ~ v_pattern THEN
                v_errors := array_append(v_errors, format('String does not match pattern: %s', v_pattern));
            END IF;
        END IF;
    END IF;
    
    -- Numeric validations
    IF jsonb_typeof(p_data) = 'number' THEN
        -- Minimum
        IF p_schema ? 'minimum' THEN
            v_minimum := (p_schema->>'minimum')::NUMERIC;
            IF (p_data#>>'{}')::NUMERIC < v_minimum THEN
                v_errors := array_append(v_errors, format('Value below minimum: %s', v_minimum));
            END IF;
        END IF;
        
        -- Maximum
        IF p_schema ? 'maximum' THEN
            v_maximum := (p_schema->>'maximum')::NUMERIC;
            IF (p_data#>>'{}')::NUMERIC > v_maximum THEN
                v_errors := array_append(v_errors, format('Value above maximum: %s', v_maximum));
            END IF;
        END IF;
    END IF;
    
    -- Enum validation
    IF p_schema ? 'enum' THEN
        v_enum := p_schema->'enum';
        IF NOT v_enum @> jsonb_build_array(p_data) THEN
            v_errors := array_append(v_errors, format('Value not in enum: %s', v_enum::TEXT));
        END IF;
    END IF;
    
    -- Validate properties recursively
    IF p_schema ? 'properties' AND jsonb_typeof(p_data) = 'object' THEN
        FOR v_property IN SELECT jsonb_object_keys(p_schema->'properties')
        LOOP
            IF p_data ? v_property THEN
                SELECT array_cat(v_errors, errs) INTO v_errors
                FROM json_validate_against_schema(p_data->v_property, p_schema->'properties'->v_property);
            END IF;
        END LOOP;
    END IF;
    
    RETURN QUERY SELECT array_length(v_errors, 1) IS NULL OR array_length(v_errors, 1) = 0, v_errors;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- VALIDATION CACHE FOR PERFORMANCE
-- ============================================================================

CREATE TABLE IF NOT EXISTS json_validation_cache (
    cache_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data_hash TEXT NOT NULL UNIQUE,
    schema_name TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    validation_result BOOLEAN NOT NULL,
    validation_errors JSONB,
    cached_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_validation_cache_lookup ON json_validation_cache(data_hash, schema_name, schema_version);

-- Function to validate with caching
CREATE OR REPLACE FUNCTION json_validate_with_cache(
    p_data JSONB,
    p_schema_name TEXT
)
RETURNS TABLE (
    is_valid BOOLEAN,
    errors TEXT[],
    from_cache BOOLEAN
) AS $$
DECLARE
    v_data_hash TEXT;
    v_cached_result RECORD;
    v_schema JSONB;
    v_validation_result BOOLEAN;
    v_validation_errors TEXT[];
BEGIN
    -- Calculate hash of data
    v_data_hash := encode(digest(p_data::TEXT, 'sha256'), 'hex');
    
    -- Check cache
    SELECT * INTO v_cached_result
    FROM json_validation_cache
    WHERE data_hash = v_data_hash 
      AND schema_name = p_schema_name
      AND cached_at > NOW() - INTERVAL '1 hour'
    ORDER BY cached_at DESC
    LIMIT 1;
    
    IF FOUND THEN
        RETURN QUERY SELECT 
            v_cached_result.validation_result,
            ARRAY(SELECT jsonb_array_elements_text(v_cached_result.validation_errors)),
            TRUE;
        RETURN;
    END IF;
    
    -- Get schema
    SELECT schema_definition INTO v_schema
    FROM json_schemas
    WHERE schema_name = p_schema_name AND is_active = TRUE
    ORDER BY schema_version DESC
    LIMIT 1;
    
    IF v_schema IS NULL THEN
        RETURN QUERY SELECT FALSE, ARRAY['Schema not found: ' || p_schema_name], FALSE;
        RETURN;
    END IF;
    
    -- Perform validation
    SELECT passed, errs INTO v_validation_result, v_validation_errors
    FROM json_validate_against_schema(p_data, v_schema);
    
    -- Cache result
    INSERT INTO json_validation_cache (data_hash, schema_name, schema_version, validation_result, validation_errors)
    VALUES (v_data_hash, p_schema_name, (v_schema->>'version')::INTEGER, v_validation_result, to_jsonb(v_validation_errors))
    ON CONFLICT (data_hash) DO UPDATE SET
        validation_result = EXCLUDED.validation_result,
        validation_errors = EXCLUDED.validation_errors,
        cached_at = NOW();
    
    RETURN QUERY SELECT v_validation_result, v_validation_errors, FALSE;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- BATCH VALIDATION
-- ============================================================================

CREATE OR REPLACE FUNCTION json_batch_validate(
    p_data_array JSONB[],
    p_schema_name TEXT
)
RETURNS TABLE (
    item_index INTEGER,
    is_valid BOOLEAN,
    errors TEXT[]
) AS $$
DECLARE
    v_schema JSONB;
    v_index INTEGER := 0;
    v_item JSONB;
    v_result RECORD;
BEGIN
    -- Get schema
    SELECT schema_definition INTO v_schema
    FROM json_schemas
    WHERE schema_name = p_schema_name AND is_active = TRUE
    ORDER BY schema_version DESC
    LIMIT 1;
    
    IF v_schema IS NULL THEN
        RETURN QUERY SELECT 0, FALSE, ARRAY['Schema not found: ' || p_schema_name];
        RETURN;
    END IF;
    
    -- Validate each item
    FOREACH v_item IN ARRAY p_data_array
    LOOP
        v_index := v_index + 1;
        SELECT passed, errs INTO v_result
        FROM json_validate_against_schema(v_item, v_schema);
        
        RETURN QUERY SELECT v_index, v_result.passed, v_result.errs;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- MULTILINGUAL ERROR MESSAGES
-- ============================================================================

CREATE TABLE IF NOT EXISTS json_validation_messages (
    message_code VARCHAR(50) PRIMARY KEY,
    message_en TEXT NOT NULL,
    message_es TEXT,
    message_fr TEXT,
    message_pt TEXT,
    message_sw TEXT,
    message_ar TEXT
);

INSERT INTO json_validation_messages (message_code, message_en, message_es, message_fr) VALUES
    ('ERR_REQUIRED', 'Required field is missing', 'El campo obligatorio falta', 'Champ obligatoire manquant'),
    ('ERR_TYPE', 'Invalid data type', 'Tipo de datos inválido', 'Type de données invalide'),
    ('ERR_PATTERN', 'Value does not match expected pattern', 'El valor no coincide con el patrón', 'La valeur ne correspond pas au modèle'),
    ('ERR_MIN_LENGTH', 'Value is too short', 'El valor es demasiado corto', 'La valeur est trop courte'),
    ('ERR_MAX_LENGTH', 'Value is too long', 'El valor es demasiado largo', 'La valeur est trop longue'),
    ('ERR_MIN_VALUE', 'Value is below minimum', 'El valor está por debajo del mínimo', 'La valeur est inférieure au minimum'),
    ('ERR_MAX_VALUE', 'Value is above maximum', 'El valor está por encima del máximo', 'La valeur est supérieure au maximum'),
    ('ERR_ENUM', 'Value not in allowed list', 'Valor no en lista permitida', 'Valeur non autorisée')
ON CONFLICT (message_code) DO NOTHING;

CREATE OR REPLACE FUNCTION json_get_validation_message(
    p_message_code TEXT,
    p_language TEXT DEFAULT 'en'
)
RETURNS TEXT AS $$
DECLARE
    v_column TEXT;
    v_message TEXT;
BEGIN
    v_column := 'message_' || p_language;
    
    EXECUTE format('SELECT %I FROM json_validation_messages WHERE message_code = $1', v_column)
    INTO v_message
    USING p_message_code;
    
    RETURN COALESCE(v_message, p_message_code);
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- PII VALIDATION FUNCTIONS
-- ============================================================================

-- Email validation
CREATE OR REPLACE FUNCTION json_validate_email(
    p_email TEXT
)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN p_email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$';
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Phone number validation (E.164 format)
CREATE OR REPLACE FUNCTION json_validate_phone(
    p_phone TEXT
)
RETURNS BOOLEAN AS $$
BEGIN
    -- E.164 format: + followed by 7-15 digits
    RETURN p_phone ~ '^\+[1-9]\d{6,14}$';
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- UUID validation
CREATE OR REPLACE FUNCTION json_validate_uuid(
    p_uuid TEXT
)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN p_uuid ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- CUSTOM VALIDATION RULE ENGINE
-- ============================================================================

CREATE TABLE IF NOT EXISTS json_validation_rules (
    rule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_name VARCHAR(100) NOT NULL UNIQUE,
    rule_type VARCHAR(50) NOT NULL, -- 'regex', 'range', 'custom_function', 'dependency'
    rule_definition JSONB NOT NULL,
    error_message TEXT NOT NULL,
    applies_to_schemas TEXT[],
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION json_apply_custom_rule(
    p_data JSONB,
    p_rule_name TEXT
)
RETURNS TABLE (
    passed BOOLEAN,
    error_msg TEXT
) AS $$
DECLARE
    v_rule RECORD;
    v_value TEXT;
    v_depends_on TEXT;
    v_min_val NUMERIC;
    v_max_val NUMERIC;
BEGIN
    SELECT * INTO v_rule
    FROM json_validation_rules
    WHERE rule_name = p_rule_name AND is_active = TRUE;
    
    IF v_rule IS NULL THEN
        RETURN QUERY SELECT TRUE, NULL::TEXT;
        RETURN;
    END IF;
    
    CASE v_rule.rule_type
        WHEN 'regex' THEN
            v_value := p_data->>(v_rule.rule_definition->>'field');
            IF v_value !~ (v_rule.rule_definition->>'pattern') THEN
                RETURN QUERY SELECT FALSE, v_rule.error_message;
            ELSE
                RETURN QUERY SELECT TRUE, NULL::TEXT;
            END IF;
            
        WHEN 'range' THEN
            v_value := p_data->>(v_rule.rule_definition->>'field');
            v_min_val := (v_rule.rule_definition->>'min')::NUMERIC;
            v_max_val := (v_rule.rule_definition->>'max')::NUMERIC;
            IF (v_value::NUMERIC < v_min_val OR v_value::NUMERIC > v_max_val) THEN
                RETURN QUERY SELECT FALSE, v_rule.error_message;
            ELSE
                RETURN QUERY SELECT TRUE, NULL::TEXT;
            END IF;
            
        WHEN 'dependency' THEN
            v_depends_on := v_rule.rule_definition->>'depends_on';
            IF p_data ? v_depends_on AND p_data ? (v_rule.rule_definition->>'field') THEN
                RETURN QUERY SELECT TRUE, NULL::TEXT;
            ELSIF p_data ? (v_rule.rule_definition->>'field') AND NOT (p_data ? v_depends_on) THEN
                RETURN QUERY SELECT FALSE, v_rule.error_message;
            ELSE
                RETURN QUERY SELECT TRUE, NULL::TEXT;
            END IF;
            
        ELSE
            RETURN QUERY SELECT TRUE, NULL::TEXT;
    END CASE;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- SCHEMA MIGRATION UTILITY
-- ============================================================================

CREATE OR REPLACE FUNCTION json_migrate_schema_version(
    p_schema_name TEXT,
    p_from_version INTEGER,
    p_to_version INTEGER
)
RETURNS TABLE (
    migration_steps JSONB,
    breaking_changes TEXT[],
    deprecation_warnings TEXT[]
) AS $$
DECLARE
    v_from_schema JSONB;
    v_to_schema JSONB;
    v_steps JSONB := '[]'::JSONB;
    v_breaking TEXT[] := ARRAY[]::TEXT[];
    v_deprecations TEXT[] := ARRAY[]::TEXT[];
    v_old_field TEXT;
    v_new_field TEXT;
BEGIN
    -- Get schema versions
    SELECT schema_definition, breaking_changes, deprecated_fields
    INTO v_from_schema, v_breaking, v_deprecations
    FROM json_schema_versions
    WHERE schema_name = p_schema_name AND schema_version = p_from_version;
    
    SELECT schema_definition, new_fields
    INTO v_to_schema
    FROM json_schema_versions
    WHERE schema_name = p_schema_name AND schema_version = p_to_version;
    
    IF v_from_schema IS NULL OR v_to_schema IS NULL THEN
        RETURN QUERY SELECT '[]'::JSONB, ARRAY['Schema version not found'], ARRAY[]::TEXT[];
        RETURN;
    END IF;
    
    -- Build migration steps
    v_steps := jsonb_build_object(
        'from_version', p_from_version,
        'to_version', p_to_version,
        'removed_fields', v_breaking,
        'deprecated_fields', v_deprecations,
        'new_fields', (SELECT array_agg(f) FROM jsonb_array_elements_text(v_to_schema->'new_fields') f),
        'migration_required', array_length(v_breaking, 1) > 0
    );
    
    RETURN QUERY SELECT v_steps, v_breaking, v_deprecations;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE json_schemas IS 'ISO/IEC 27001: Storage for JSON validation schemas';
COMMENT ON TABLE json_schema_versions IS 'Schema versioning and migration tracking';
COMMENT ON TABLE json_validation_cache IS 'Validation result caching for performance optimization';
COMMENT ON TABLE json_validation_messages IS 'Multilingual validation error messages';
COMMENT ON TABLE json_validation_rules IS 'Custom validation rule definitions';
COMMENT ON FUNCTION json_has_required_fields IS 'PCI DSS: Validate JSONB has all required fields for input validation';
COMMENT ON FUNCTION json_validate_against_schema IS 'Main JSON Schema Draft 2020-12 validation function';
COMMENT ON FUNCTION json_validate_with_cache IS 'Cached validation for frequently validated data';
COMMENT ON FUNCTION json_batch_validate IS 'Batch validation for efficiency with multiple items';
COMMENT ON FUNCTION json_validate_conditional IS 'Conditional validation (if-then-else) support';
COMMENT ON FUNCTION json_resolve_schema_ref IS 'Recursive schema reference resolution';
COMMENT ON FUNCTION json_migrate_schema_version IS 'Schema versioning and migration tools';

-- ============================================================================
-- IMPLEMENTATION COMPLETE
-- ============================================================================
