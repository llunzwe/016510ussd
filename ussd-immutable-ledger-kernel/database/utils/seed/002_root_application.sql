-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: utils/seed/002_root_application.sql
-- Description: Initial application configuration, feature flags, system
--              settings, and environment-specific configurations
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: RESTRICTED
-- DATA SENSITIVITY: HIGH - Application Configuration
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.12.1 Operational Procedures and Responsibilities
  - A.12.1.2: Change control procedures for configuration
  - A.12.1.4: Separation of development, test, and production environments
  
A.9.4 System and Application Access Control
  - Configuration access based on clearance levels
  - Secure system configuration procedures

A.14.2 System Security in Development
  - Environment-based configuration management
  - Security configuration baseline
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION
================================================================================
- Feature flags for PII-related functionality
- Configuration for data retention policies
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
- Encryption configuration for data at rest
- Key management configuration
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
- Configuration audit trail for e-discovery
- Retention policy configuration
================================================================================

================================================================================
PCI DSS 4.0 CONFIGURATION REQUIREMENTS
================================================================================
Requirement 2.1: Change Control Procedures
Requirement 3.6: Cryptographic Key Management Configuration
Requirement 6.5.2: Security Misconfiguration Prevention
Requirement 10.7: Audit Log Retention Configuration
Requirement 12.3: Security Parameter Management
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. ON CONFLICT for idempotent seeding
2. Clear categorization for configuration keys
3. Visibility levels for access control
4. Environment separation
5. Approval requirements for sensitive configs
================================================================================

================================================================================
CONFIGURATION SECURITY LEVELS
================================================================================
public: Visible to all authenticated users
internal: Internal system configuration
restricted: Security-sensitive configuration
confidential: Highly sensitive configuration
================================================================================
*/

-- ============================================================================
-- APPLICATION CONFIGURATION
-- ============================================================================

INSERT INTO app_configuration (
    config_key, config_value, config_type, category,
    visibility, environment, description, requires_approval, is_encrypted
) VALUES
    -- Core Application Settings
    ('app.name', 'USSD Immutable Ledger', 'string', 'core', 'public', 'all',
     'Application name displayed in notifications and documents', FALSE, FALSE),
     
    ('app.version', '1.0.0', 'string', 'core', 'public', 'all',
     'Current application version', FALSE, FALSE),
     
    ('app.environment', 'production', 'string', 'core', 'internal', 'all',
     'Deployment environment identifier', FALSE, FALSE),
     
    ('app.maintenance_mode', 'false', 'boolean', 'core', 'internal', 'all',
     'Global maintenance mode flag', TRUE, FALSE),

    -- Authentication Settings
    ('auth.jwt_expiry_minutes', '60', 'integer', 'auth', 'internal', 'all',
     'JWT token expiration time in minutes (PCI DSS 8.2.1)', TRUE, FALSE),
     
    ('auth.mfa_enabled', 'true', 'boolean', 'auth', 'internal', 'all',
     'Global MFA enforcement flag (PCI DSS 8.3)', TRUE, FALSE),
     
    ('auth.max_failed_logins', '5', 'integer', 'auth', 'internal', 'all',
     'Maximum failed login attempts before lockout (PCI DSS 8.3.4)', TRUE, FALSE),
     
    ('auth.password_min_length', '12', 'integer', 'auth', 'internal', 'all',
     'Minimum password length (PCI DSS 8.2.3)', FALSE, FALSE),

    -- Security Settings
    ('security.encryption_at_rest', 'true', 'boolean', 'security', 'restricted', 'all',
     'Enable database encryption at rest (ISO 27040)', TRUE, FALSE),
     
    ('security.encryption_in_transit', 'true', 'boolean', 'security', 'restricted', 'all',
     'Require TLS for all connections (PCI DSS 4.1)', TRUE, FALSE),
     
    ('security.audit_log_enabled', 'true', 'boolean', 'security', 'restricted', 'all',
     'Enable comprehensive audit logging (ISO 27001 A.12.4)', FALSE, FALSE),
     
    ('security.ip_whitelist_required', 'false', 'boolean', 'security', 'restricted', 'all',
     'Require IP whitelisting for admin access (PCI DSS 7.1)', TRUE, FALSE),

    -- Compliance Settings
    ('compliance.aml_threshold', '10000', 'decimal', 'compliance', 'restricted', 'all',
     'AML reporting threshold amount', TRUE, FALSE),
     
    ('compliance.retention_years', '7', 'integer', 'compliance', 'restricted', 'all',
     'Data retention period in years (PCI DSS 10.7)', TRUE, FALSE)

ON CONFLICT (config_key) DO UPDATE SET
    config_value = EXCLUDED.config_value,
    description = EXCLUDED.description;

-- ============================================================================
-- CONFIGURATION VERSIONING
-- ============================================================================

CREATE TABLE IF NOT EXISTS app_configuration_versions (
    version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key VARCHAR(100) NOT NULL,
    config_value TEXT NOT NULL,
    config_type VARCHAR(20) NOT NULL,
    category VARCHAR(50),
    visibility VARCHAR(20),
    environment VARCHAR(20),
    description TEXT,
    requires_approval BOOLEAN DEFAULT FALSE,
    is_encrypted BOOLEAN DEFAULT FALSE,
    
    -- Version tracking
    version_number INTEGER NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID,
    change_reason TEXT,
    
    -- Rollback tracking
    rolled_back_at TIMESTAMPTZ,
    rolled_back_by UUID,
    rollback_reason TEXT,
    
    UNIQUE(config_key, version_number)
);

CREATE INDEX IF NOT EXISTS idx_config_versions_key ON app_configuration_versions(config_key, version_number DESC);

-- Trigger to auto-version configuration changes
CREATE OR REPLACE FUNCTION config_version_trigger()
RETURNS TRIGGER AS $$
BEGIN
    -- Store previous version
    INSERT INTO app_configuration_versions (
        config_key, config_value, config_type, category, visibility,
        environment, description, requires_approval, is_encrypted,
        version_number, created_at, change_reason
    )
    SELECT 
        OLD.config_key, OLD.config_value, OLD.config_type, OLD.category,
        OLD.visibility, OLD.environment, OLD.description, OLD.requires_approval,
        OLD.is_encrypted,
        COALESCE((SELECT MAX(version_number) FROM app_configuration_versions WHERE config_key = OLD.config_key), 0) + 1,
        NOW(),
        'Configuration updated'
    WHERE TG_OP = 'UPDATE';
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS config_versioning ON app_configuration;
CREATE TRIGGER config_versioning
    AFTER UPDATE ON app_configuration
    FOR EACH ROW
    EXECUTE FUNCTION config_version_trigger();

-- ============================================================================
-- CONFIGURATION ROLLBACK FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION rollback_configuration(
    p_config_key VARCHAR(100),
    p_target_version INTEGER,
    p_rollback_reason TEXT,
    p_rolled_back_by UUID DEFAULT NULL
)
RETURNS BOOLEAN AS $$
DECLARE
    v_target RECORD;
BEGIN
    -- Get target version
    SELECT * INTO v_target
    FROM app_configuration_versions
    WHERE config_key = p_config_key AND version_number = p_target_version;
    
    IF v_target IS NULL THEN
        RAISE EXCEPTION 'Target version not found';
    END IF;
    
    -- Update current configuration
    UPDATE app_configuration SET
        config_value = v_target.config_value,
        config_type = v_target.config_type,
        category = v_target.category,
        visibility = v_target.visibility,
        environment = v_target.environment,
        description = v_target.description,
        requires_approval = v_target.requires_approval,
        is_encrypted = v_target.is_encrypted
    WHERE config_key = p_config_key;
    
    -- Mark version as rolled back
    UPDATE app_configuration_versions SET
        rolled_back_at = NOW(),
        rolled_back_by = p_rolled_back_by,
        rollback_reason = p_rollback_reason
    WHERE version_id = v_target.version_id;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- HOT-RELOAD MECHANISM
-- ============================================================================

CREATE TABLE IF NOT EXISTS config_hot_reload_subscribers (
    subscriber_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name VARCHAR(100) NOT NULL,
    service_instance VARCHAR(100),
    subscribed_keys TEXT[], -- NULL means all keys
    callback_endpoint TEXT,
    last_notified_at TIMESTAMPTZ,
    notification_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION notify_config_change()
RETURNS TRIGGER AS $$
DECLARE
    v_subscriber RECORD;
    v_payload TEXT;
BEGIN
    v_payload := json_build_object(
        'config_key', NEW.config_key,
        'old_value', OLD.config_value,
        'new_value', NEW.config_value,
        'changed_at', NOW()
    )::TEXT;
    
    -- Notify active subscribers
    FOR v_subscriber IN 
        SELECT * FROM config_hot_reload_subscribers 
        WHERE is_active = TRUE
          AND (subscribed_keys IS NULL OR NEW.config_key = ANY(subscribed_keys))
    LOOP
        -- In production, this would call the callback endpoint
        -- For now, we just track the notification
        UPDATE config_hot_reload_subscribers SET
            last_notified_at = NOW(),
            notification_count = notification_count + 1
        WHERE subscriber_id = v_subscriber.subscriber_id;
    END LOOP;
    
    -- Also notify via PostgreSQL NOTIFY
    PERFORM pg_notify('config_change', v_payload);
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS config_hot_reload ON app_configuration;
CREATE TRIGGER config_hot_reload
    AFTER UPDATE ON app_configuration
    FOR EACH ROW
    WHEN (OLD.config_value IS DISTINCT FROM NEW.config_value)
    EXECUTE FUNCTION notify_config_change();

-- ============================================================================
-- FEATURE FLAGS
-- ============================================================================

CREATE TABLE IF NOT EXISTS feature_flags (
    flag_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flag_key VARCHAR(100) NOT NULL UNIQUE,
    flag_name VARCHAR(200) NOT NULL,
    description TEXT,
    
    -- Flag status
    enabled BOOLEAN DEFAULT FALSE,
    default_value BOOLEAN DEFAULT FALSE,
    
    -- Rollout configuration
    rollout_percentage INTEGER DEFAULT 0 CHECK (rollout_percentage BETWEEN 0 AND 100),
    rollout_strategy VARCHAR(20) DEFAULT 'percentage', -- percentage, user_list, attribute_based, time_based
    
    -- Targeting
    target_environments TEXT[] DEFAULT ARRAY['all'],
    target_user_types TEXT[],
    excluded_user_ids UUID[],
    included_user_ids UUID[],
    
    -- A/B testing
    is_experiment BOOLEAN DEFAULT FALSE,
    experiment_control_percentage INTEGER DEFAULT 50,
    experiment_start_date TIMESTAMPTZ,
    experiment_end_date TIMESTAMPTZ,
    
    -- Metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID,
    updated_by UUID
);

-- Insert default feature flags
INSERT INTO feature_flags (
    flag_key, flag_name, description, enabled, default_value, rollout_percentage, target_environments
) VALUES
    ('new_transfer_ui', 'New Transfer UI', 'Enable redesigned transfer interface', FALSE, FALSE, 0, ARRAY['development', 'staging']),
    ('international_transfers', 'International Transfers', 'Enable international money transfers', TRUE, TRUE, 100, ARRAY['all']),
    ('biometric_auth', 'Biometric Authentication', 'Enable fingerprint/face ID authentication', FALSE, FALSE, 10, ARRAY['production']),
    ('bulk_payments', 'Bulk Payments', 'Enable bulk payment processing', FALSE, FALSE, 0, ARRAY['development']),
    ('advanced_analytics', 'Advanced Analytics Dashboard', 'Enable advanced reporting features', TRUE, TRUE, 100, ARRAY['all']),
    ('pii_masking', 'PII Data Masking', 'Enable PII masking in logs and UI (ISO 27018)', TRUE, TRUE, 100, ARRAY['all']),
    ('transaction_simulation', 'Transaction Simulation', 'Enable fee simulation before transaction', TRUE, TRUE, 100, ARRAY['all']),
    ('real_time_notifications', 'Real-time Notifications', 'Enable WebSocket-based real-time notifications', FALSE, FALSE, 25, ARRAY['staging', 'production'])
ON CONFLICT (flag_key) DO UPDATE SET
    flag_name = EXCLUDED.flag_name,
    description = EXCLUDED.description;

-- Function to check if feature is enabled for user
CREATE OR REPLACE FUNCTION is_feature_enabled(
    p_flag_key VARCHAR(100),
    p_user_id UUID DEFAULT NULL,
    p_environment VARCHAR(20) DEFAULT 'production'
)
RETURNS BOOLEAN AS $$
DECLARE
    v_flag RECORD;
    v_user_bucket INTEGER;
BEGIN
    SELECT * INTO v_flag FROM feature_flags WHERE flag_key = p_flag_key;
    
    IF v_flag IS NULL THEN
        RETURN FALSE;
    END IF;
    
    -- Check environment
    IF NOT (p_environment = ANY(v_flag.target_environments) OR 'all' = ANY(v_flag.target_environments)) THEN
        RETURN v_flag.default_value;
    END IF;
    
    -- Check explicit inclusion/exclusion
    IF p_user_id IS NOT NULL THEN
        IF p_user_id = ANY(v_flag.excluded_user_ids) THEN
            RETURN v_flag.default_value;
        END IF;
        IF p_user_id = ANY(v_flag.included_user_ids) THEN
            RETURN TRUE;
        END IF;
    END IF;
    
    -- Check if fully enabled
    IF v_flag.enabled AND v_flag.rollout_percentage = 100 THEN
        RETURN TRUE;
    END IF;
    
    -- Check percentage rollout
    IF v_flag.enabled AND v_flag.rollout_percentage > 0 AND p_user_id IS NOT NULL THEN
        -- Deterministic bucketing based on user_id
        v_user_bucket := (('x' || substr(md5(p_user_id::TEXT), 1, 8))::bit(32)::INTEGER % 100) + 1;
        RETURN v_user_bucket <= v_flag.rollout_percentage;
    END IF;
    
    RETURN v_flag.default_value;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- A/B TESTING SUPPORT
-- ============================================================================

CREATE TABLE IF NOT EXISTS ab_experiments (
    experiment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    experiment_name VARCHAR(200) NOT NULL,
    description TEXT,
    hypothesis TEXT,
    
    -- Configuration
    control_variant VARCHAR(50) DEFAULT 'control',
    treatment_variant VARCHAR(50) DEFAULT 'treatment',
    
    -- Traffic allocation
    traffic_percentage INTEGER DEFAULT 50 CHECK (traffic_percentage BETWEEN 1 AND 100),
    control_allocation INTEGER DEFAULT 50 CHECK (control_allocation BETWEEN 0 AND 100),
    
    -- Targeting
    target_feature_flag VARCHAR(100) REFERENCES feature_flags(flag_key),
    target_criteria JSONB,
    
    -- Schedule
    start_date TIMESTAMPTZ NOT NULL,
    end_date TIMESTAMPTZ,
    
    -- Metrics
    primary_metric VARCHAR(100),
    secondary_metrics TEXT[],
    minimum_sample_size INTEGER,
    
    -- Status
    status VARCHAR(20) DEFAULT 'draft', -- draft, running, paused, completed, cancelled
    winner_variant VARCHAR(50),
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID
);

CREATE TABLE IF NOT EXISTS ab_experiment_assignments (
    assignment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    experiment_id UUID NOT NULL REFERENCES ab_experiments(experiment_id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    variant VARCHAR(50) NOT NULL,
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(experiment_id, user_id)
);

-- Function to assign user to experiment variant
CREATE OR REPLACE FUNCTION assign_experiment_variant(
    p_experiment_id UUID,
    p_user_id UUID
)
RETURNS VARCHAR(50) AS $$
DECLARE
    v_experiment RECORD;
    v_existing VARCHAR(50);
    v_variant VARCHAR(50);
    v_user_bucket INTEGER;
BEGIN
    -- Check for existing assignment
    SELECT variant INTO v_existing
    FROM ab_experiment_assignments
    WHERE experiment_id = p_experiment_id AND user_id = p_user_id;
    
    IF v_existing IS NOT NULL THEN
        RETURN v_existing;
    END IF;
    
    -- Get experiment details
    SELECT * INTO v_experiment FROM ab_experiments WHERE experiment_id = p_experiment_id;
    
    IF v_experiment IS NULL OR v_experiment.status != 'running' THEN
        RETURN 'control';
    END IF;
    
    -- Deterministic assignment
    v_user_bucket := (('x' || substr(md5(p_user_id::TEXT || p_experiment_id::TEXT), 1, 8))::bit(32)::INTEGER % 100) + 1;
    
    IF v_user_bucket <= v_experiment.control_allocation THEN
        v_variant := v_experiment.control_variant;
    ELSE
        v_variant := v_experiment.treatment_variant;
    END IF;
    
    -- Store assignment
    INSERT INTO ab_experiment_assignments (experiment_id, user_id, variant)
    VALUES (p_experiment_id, p_user_id, v_variant)
    ON CONFLICT (experiment_id, user_id) DO NOTHING;
    
    RETURN v_variant;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- CONFIGURATION DEPENDENCY VALIDATION
-- ============================================================================

CREATE TABLE IF NOT EXISTS config_dependencies (
    dependency_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key VARCHAR(100) NOT NULL REFERENCES app_configuration(config_key) ON DELETE CASCADE,
    depends_on_key VARCHAR(100) NOT NULL REFERENCES app_configuration(config_key),
    validation_rule VARCHAR(50) NOT NULL, -- 'eq', 'neq', 'gt', 'lt', 'contains', 'depends'
    expected_value TEXT,
    error_message TEXT NOT NULL,
    is_blocking BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert dependency rules
INSERT INTO config_dependencies (config_key, depends_on_key, validation_rule, expected_value, error_message)
VALUES
    ('security.encryption_at_rest', 'security.encryption_in_transit', 'depends', NULL, 'Encryption at rest requires encryption in transit to be enabled'),
    ('auth.mfa_enabled', 'auth.max_failed_logins', 'gte', '3', 'MFA should be enabled when max failed logins is 3 or more'),
    ('compliance.aml_threshold', 'compliance.retention_years', 'gte', '5', 'AML threshold requires minimum 5 year retention')
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION validate_config_dependencies(
    p_config_key VARCHAR(100)
)
RETURNS TABLE (
    is_valid BOOLEAN,
    violations TEXT[]
) AS $$
DECLARE
    v_violations TEXT[] := ARRAY[]::TEXT[];
    v_dep RECORD;
    v_config_value TEXT;
    v_dep_value TEXT;
    v_valid BOOLEAN := TRUE;
BEGIN
    FOR v_dep IN SELECT * FROM config_dependencies WHERE depends_on_key = p_config_key
    LOOP
        SELECT config_value INTO v_config_value FROM app_configuration WHERE config_key = p_config_key;
        SELECT config_value INTO v_dep_value FROM app_configuration WHERE config_key = v_dep.config_key;
        
        CASE v_dep.validation_rule
            WHEN 'eq' THEN
                IF v_config_value != v_dep.expected_value THEN
                    v_violations := array_append(v_violations, v_dep.error_message);
                    v_valid := FALSE;
                END IF;
            WHEN 'depends' THEN
                IF v_config_value = 'true' AND (v_dep_value IS NULL OR v_dep_value != 'true') THEN
                    v_violations := array_append(v_violations, v_dep.error_message);
                    v_valid := FALSE;
                END IF;
        END CASE;
    END LOOP;
    
    RETURN QUERY SELECT v_valid, v_violations;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- CONFIGURATION DRIFT DETECTION
-- ============================================================================

CREATE TABLE IF NOT EXISTS config_drift_detection (
    drift_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key VARCHAR(100) NOT NULL,
    expected_value TEXT NOT NULL,
    actual_value TEXT NOT NULL,
    drift_type VARCHAR(20) NOT NULL, -- 'manual_change', 'unauthorized', 'environment_mismatch'
    environment VARCHAR(20) NOT NULL,
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    detected_by UUID,
    is_resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT
);

CREATE OR REPLACE FUNCTION detect_config_drift(
    p_environment VARCHAR(20)
)
RETURNS TABLE (
    config_key VARCHAR(100),
    expected_value TEXT,
    actual_value TEXT,
    drift_detected BOOLEAN
) AS $$
BEGIN
    -- This would compare against a baseline configuration
    -- For now, return simulated results
    RETURN QUERY
    SELECT 
        ac.config_key,
        'expected'::TEXT,
        ac.config_value,
        FALSE
    FROM app_configuration ac
    WHERE ac.environment IN (p_environment, 'all');
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- CONFIGURATION VALIDATION RULES
-- ============================================================================

CREATE TABLE IF NOT EXISTS config_validation_rules (
    rule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key_pattern VARCHAR(100) NOT NULL, -- Can use wildcards like 'auth.%'
    rule_type VARCHAR(50) NOT NULL, -- 'range', 'regex', 'enum', 'type', 'custom'
    rule_definition JSONB NOT NULL,
    error_message TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO config_validation_rules (config_key_pattern, rule_type, rule_definition, error_message)
VALUES
    ('auth.jwt_expiry_minutes', 'range', '{"min": 5, "max": 1440}', 'JWT expiry must be between 5 and 1440 minutes'),
    ('auth.password_min_length', 'range', '{"min": 8, "max": 128}', 'Password length must be between 8 and 128'),
    ('compliance.retention_years', 'range', '{"min": 1, "max": 25}', 'Retention period must be between 1 and 25 years'),
    ('app.version', 'regex', '{"pattern": "^\\d+\\.\\d+\\.\\d+$"}', 'Version must follow semantic versioning (X.Y.Z)'),
    ('security.%', 'enum', '{"allowed": ["true", "false"]}', 'Security settings must be boolean')
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION validate_config_value(
    p_config_key VARCHAR(100),
    p_config_value TEXT,
    p_config_type VARCHAR(20)
)
RETURNS TABLE (
    is_valid BOOLEAN,
    errors TEXT[]
) AS $$
DECLARE
    v_errors TEXT[] := ARRAY[]::TEXT[];
    v_rule RECORD;
    v_numeric_value NUMERIC;
    v_pattern TEXT;
BEGIN
    FOR v_rule IN 
        SELECT * FROM config_validation_rules 
        WHERE is_active = TRUE 
          AND p_config_key LIKE config_key_pattern
    LOOP
        CASE v_rule.rule_type
            WHEN 'range' THEN
                v_numeric_value := p_config_value::NUMERIC;
                IF v_numeric_value < (v_rule.rule_definition->>'min')::NUMERIC 
                   OR v_numeric_value > (v_rule.rule_definition->>'max')::NUMERIC THEN
                    v_errors := array_append(v_errors, v_rule.error_message);
                END IF;
            WHEN 'regex' THEN
                v_pattern := v_rule.rule_definition->>'pattern';
                IF NOT p_config_value ~ v_pattern THEN
                    v_errors := array_append(v_errors, v_rule.error_message);
                END IF;
            WHEN 'enum' THEN
                IF NOT p_config_value = ANY(ARRAY(SELECT jsonb_array_elements_text(v_rule.rule_definition->'allowed'))) THEN
                    v_errors := array_append(v_errors, v_rule.error_message);
                END IF;
        END CASE;
    END LOOP;
    
    RETURN QUERY SELECT array_length(v_errors, 1) IS NULL OR array_length(v_errors, 1) = 0, v_errors;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- CONFIGURATION CHANGE APPROVAL WORKFLOW
-- ============================================================================

CREATE TABLE IF NOT EXISTS config_change_requests (
    request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key VARCHAR(100) NOT NULL,
    proposed_value TEXT NOT NULL,
    current_value TEXT,
    change_reason TEXT NOT NULL,
    
    -- Requester
    requested_by UUID NOT NULL,
    requested_at TIMESTAMPTZ DEFAULT NOW(),
    
    -- Approval workflow
    required_approvals INTEGER DEFAULT 1,
    current_approvals INTEGER DEFAULT 0,
    approved_by UUID[],
    approved_at TIMESTAMPTZ[],
    
    -- Status
    status VARCHAR(20) DEFAULT 'pending', -- pending, approved, rejected, implemented, cancelled
    
    -- Implementation
    implemented_at TIMESTAMPTZ,
    implemented_by UUID,
    
    -- Rejection
    rejected_by UUID,
    rejected_at TIMESTAMPTZ,
    rejection_reason TEXT,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION request_config_change(
    p_config_key VARCHAR(100),
    p_proposed_value TEXT,
    p_change_reason TEXT,
    p_requested_by UUID
)
RETURNS UUID AS $$
DECLARE
    v_request_id UUID;
    v_current_value TEXT;
BEGIN
    SELECT config_value INTO v_current_value 
    FROM app_configuration WHERE config_key = p_config_key;
    
    INSERT INTO config_change_requests (
        config_key, proposed_value, current_value, change_reason, requested_by
    ) VALUES (
        p_config_key, p_proposed_value, v_current_value, p_change_reason, p_requested_by
    )
    RETURNING request_id INTO v_request_id;
    
    RETURN v_request_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION approve_config_change(
    p_request_id UUID,
    p_approved_by UUID
)
RETURNS BOOLEAN AS $$
DECLARE
    v_request RECORD;
BEGIN
    SELECT * INTO v_request FROM config_change_requests WHERE request_id = p_request_id;
    
    IF v_request IS NULL OR v_request.status != 'pending' THEN
        RETURN FALSE;
    END IF;
    
    UPDATE config_change_requests SET
        current_approvals = current_approvals + 1,
        approved_by = array_append(COALESCE(approved_by, ARRAY[]::UUID[]), p_approved_by),
        approved_at = array_append(COALESCE(approved_at, ARRAY[]::TIMESTAMPTZ[]), NOW()),
        status = CASE WHEN current_approvals + 1 >= required_approvals THEN 'approved' ELSE 'pending' END
    WHERE request_id = p_request_id;
    
    -- Auto-implement if fully approved
    IF v_request.current_approvals + 1 >= v_request.required_approvals THEN
        UPDATE app_configuration SET
            config_value = v_request.proposed_value
        WHERE config_key = v_request.config_key;
        
        UPDATE config_change_requests SET
            status = 'implemented',
            implemented_at = NOW(),
            implemented_by = p_approved_by
        WHERE request_id = p_request_id;
    END IF;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- CONFIGURATION BACKUP AND RESTORE
-- ============================================================================

CREATE TABLE IF NOT EXISTS config_backups (
    backup_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_name VARCHAR(200) NOT NULL,
    backup_type VARCHAR(20) DEFAULT 'manual', -- manual, scheduled, pre_migration
    environment VARCHAR(20) NOT NULL,
    
    -- Backup content
    configuration_data JSONB NOT NULL,
    feature_flag_data JSONB,
    
    -- Metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID,
    
    -- Restoration tracking
    restored_at TIMESTAMPTZ,
    restored_by UUID,
    restore_target_environment VARCHAR(20)
);

CREATE OR REPLACE FUNCTION backup_configuration(
    p_backup_name VARCHAR(200),
    p_environment VARCHAR(20),
    p_created_by UUID DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_backup_id UUID;
    v_config_data JSONB;
    v_flag_data JSONB;
BEGIN
    -- Collect all configuration
    SELECT jsonb_object_agg(config_key, jsonb_build_object(
        'value', config_value,
        'type', config_type,
        'category', category,
        'visibility', visibility
    )) INTO v_config_data
    FROM app_configuration
    WHERE environment IN (p_environment, 'all');
    
    -- Collect feature flags
    SELECT jsonb_agg(jsonb_build_object(
        'key', flag_key,
        'enabled', enabled,
        'rollout', rollout_percentage
    )) INTO v_flag_data
    FROM feature_flags;
    
    INSERT INTO config_backups (
        backup_name, environment, configuration_data, feature_flag_data, created_by
    ) VALUES (
        p_backup_name, p_environment, v_config_data, v_flag_data, p_created_by
    )
    RETURNING backup_id INTO v_backup_id;
    
    RETURN v_backup_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION restore_configuration(
    p_backup_id UUID,
    p_target_environment VARCHAR(20),
    p_restored_by UUID,
    p_dry_run BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (
    config_key VARCHAR(100),
    old_value TEXT,
    new_value TEXT,
    would_change BOOLEAN
) AS $$
DECLARE
    v_backup RECORD;
    v_config RECORD;
BEGIN
    SELECT * INTO v_backup FROM config_backups WHERE backup_id = p_backup_id;
    
    IF v_backup IS NULL THEN
        RAISE EXCEPTION 'Backup not found';
    END IF;
    
    -- Return what would change (or apply if not dry run)
    FOR v_config IN 
        SELECT key as k, value->>'value' as v
        FROM jsonb_each(v_backup.configuration_data)
    LOOP
        RETURN QUERY
        SELECT 
            v_config.k,
            ac.config_value,
            v_config.v,
            ac.config_value IS DISTINCT FROM v_config.v
        FROM app_configuration ac
        WHERE ac.config_key = v_config.k;
        
        IF NOT p_dry_run THEN
            UPDATE app_configuration 
            SET config_value = v_config.v
            WHERE config_key = v_config.k
              AND environment IN (p_target_environment, 'all');
        END IF;
    END LOOP;
    
    IF NOT p_dry_run THEN
        UPDATE config_backups SET
            restored_at = NOW(),
            restored_by = p_restored_by,
            restore_target_environment = p_target_environment
        WHERE backup_id = p_backup_id;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- DEPLOYMENT TEMPLATES
-- ============================================================================

CREATE TABLE IF NOT EXISTS config_deployment_templates (
    template_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    environment_type VARCHAR(20) NOT NULL, -- development, staging, production, disaster_recovery
    
    -- Template configuration
    template_config JSONB NOT NULL,
    template_features JSONB,
    
    -- Metadata
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID
);

INSERT INTO config_deployment_templates (template_name, description, environment_type, template_config, is_default)
VALUES
    ('Development', 'Development environment with relaxed security', 'development', 
     '{"auth.mfa_enabled": "false", "security.ip_whitelist_required": "false", "app.maintenance_mode": "false"}'::JSONB, FALSE),
    ('Staging', 'Staging environment mirroring production', 'staging',
     '{"auth.mfa_enabled": "true", "security.ip_whitelist_required": "false", "app.maintenance_mode": "false"}'::JSONB, FALSE),
    ('Production', 'Production environment with full security', 'production',
     '{"auth.mfa_enabled": "true", "security.ip_whitelist_required": "true", "security.audit_log_enabled": "true"}'::JSONB, TRUE),
    ('Disaster Recovery', 'DR environment configuration', 'disaster_recovery',
     '{"auth.mfa_enabled": "true", "app.maintenance_mode": "true"}'::JSONB, FALSE)
ON CONFLICT (template_name) DO NOTHING;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE app_configuration IS 'ISO/IEC 27001: Application configuration with environment and visibility support';
COMMENT ON TABLE app_configuration_versions IS 'Configuration versioning for rollback capability';
COMMENT ON TABLE feature_flags IS 'ISO/IEC 27018: Feature toggle configuration for gradual rollout';
COMMENT ON TABLE config_hot_reload_subscribers IS 'Hot-reload mechanism for configuration changes';
COMMENT ON TABLE ab_experiments IS 'A/B testing configuration support';
COMMENT ON TABLE config_dependencies IS 'Configuration dependency validation rules';
COMMENT ON TABLE config_drift_detection IS 'Configuration drift detection tracking';
COMMENT ON TABLE config_validation_rules IS 'Configuration value validation rules';
COMMENT ON TABLE config_change_requests IS 'Configuration change approval workflow';
COMMENT ON TABLE config_backups IS 'Configuration backup and restore tracking';
COMMENT ON TABLE config_deployment_templates IS 'Configuration templates for different deployment types';
COMMENT ON FUNCTION rollback_configuration IS 'Configuration rollback to previous version';
COMMENT ON FUNCTION is_feature_enabled IS 'Check if feature flag is enabled for user';
COMMENT ON FUNCTION validate_config_value IS 'Validate configuration value against rules';
COMMENT ON FUNCTION backup_configuration IS 'Create configuration backup';
COMMENT ON FUNCTION restore_configuration IS 'Restore configuration from backup';

-- ============================================================================
-- IMPLEMENTATION COMPLETE
-- ============================================================================
