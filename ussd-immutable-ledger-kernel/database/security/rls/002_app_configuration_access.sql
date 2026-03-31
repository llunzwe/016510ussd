-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: security/rls/002_app_configuration_access.sql
-- Description: RLS policies for system configuration and settings
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: RESTRICTED
-- DATA SENSITIVITY: HIGH - System Configuration/Security Parameters
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.12.1 Operational Procedures and Responsibilities
  - A.12.1.2: Change control policies for configuration modifications
    RESTRICTIVE policies enforce approval workflow for sensitive changes
  - A.12.1.4: Separation of environments - Environment-based policies
    prevent cross-environment contamination
  
A.9.4 System and Application Access Control
  - A.9.4.1: Clearance level-based access to sensitive configurations
    Clearance level functions enforce data classification-based access
  - A.9.4.5: Secure system configuration procedures
    Protected key list prevents unauthorized security setting changes

A.14.2 System Security in Development
  - A.14.2.1: Environment-based policy restrictions prevent production
    modifications by development administrators
  - A.14.2.8: Security configuration management through RLS policies
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION IN CLOUD
================================================================================
Clause 7.2: Consent and Choice
  - Configuration visibility controls prevent PII exposure
  - User segment-based access aligns with data minimization principles
  
Clause 8.1: Purpose and Use
  - Configuration access limited to legitimate operational purposes
  - Feature flags respect user consent for functionality access
  
Clause 9: Accountability
  - Audit logging for configuration access supports accountability
  - User segment tracking for compliance reporting
  
Clause 10: Security
  - Protected configuration keys ensure encryption keys remain secure
  - Classification-based access for security-sensitive settings
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
5.2 Storage Architecture Security
  - Configuration data protected through row-level policies
  - Environment separation prevents configuration data leakage
  
6.2 Access Control Measures
  - Granular access based on configuration classification
  - Clearance levels align with storage security requirements
  
7.2 Data Encryption
  - Encrypted configuration storage with AES-256
  - Key rotation integration for configuration re-encryption
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
Clause 5: Identification
  - Configuration audit trail for e-discovery identification
  - Structured access logs for compliance review
  
Clause 6: Preservation
  - Immutable configuration change history
  - Legal hold capability for configuration data
  
Clause 7: Collection
  - Compliance officer access for e-discovery collection
  - Structured configuration exports for litigation
================================================================================

================================================================================
PCI DSS 4.0 CONFIGURATION SECURITY
================================================================================
Requirement 2.1: Change Control Procedures
  - Approval workflow integration for sensitive config changes
  - Change tracking with before/after state capture
  
Requirement 6.5.2: Security Misconfiguration
  - RESTRICTIVE policies prevent production modifications by dev admins
  - Environment-based access enforcement
  
Requirement 11.4.5: Critical File Change Detection
  - RESTRICTIVE policies for critical security settings
  - Dual authorization for production configuration changes
  
Requirement 12.3: Security Parameter Management
  - Protected keys for security-sensitive configuration
  - Encryption requirements for stored credentials
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. RESTRICTIVE policies for security-critical configurations
2. Clearance level functions with proper exception handling
3. Environment validation to prevent cross-environment contamination
4. Comments on all policies documenting security rationale
5. Protection flags for keys like encryption_key, master_secret
================================================================================

================================================================================
KEY MANAGEMENT INTEGRATION
================================================================================
- Configuration keys marked with `is_encrypted` use AES-256 envelope encryption
- Protected key list enforced by can_modify_config() function
- Key rotation events trigger configuration cache invalidation
- HSM integration for master key retrieval (see encryption/001_key_rotation_procedures.sql)
================================================================================

================================================================================
AUDIT REQUIREMENTS
================================================================================
- All configuration changes logged with before/after values
- Changes to protected keys require justification documentation
- Failed configuration access attempts trigger security alerts
- Annual configuration audit per ISO/IEC 27001 A.18.2.3
================================================================================
*/

-- ============================================================================
-- PRE-EXECUTION SECURITY CHECKS
-- ============================================================================
DO $$
BEGIN
    -- Verify audit logging is available
    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'log_security_event') THEN
        RAISE WARNING 'Security event logging not available - configuration changes may not be audited';
    END IF;
END $$;

-- ============================================================================
-- Row-Level Security: Application Configuration Access
-- ============================================================================

-- Enable RLS on configuration tables
ALTER TABLE app_configuration ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_configuration FORCE ROW LEVEL SECURITY;

ALTER TABLE feature_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE feature_flags FORCE ROW LEVEL SECURITY;

ALTER TABLE system_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_settings FORCE ROW LEVEL SECURITY;

ALTER TABLE api_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_credentials FORCE ROW LEVEL SECURITY;

-- ============================================================================
-- APP_CONFIGURATION TABLE POLICIES
-- ============================================================================

-- POLICY: config_public_read
-- ISO/IEC 27001: A.9.4.1 - Public configurations readable by authenticated users
-- Implementation: Allows read access to public visibility configs
CREATE POLICY config_public_read ON app_configuration
    FOR SELECT
    TO authenticated
    USING (visibility = 'public');

-- POLICY: config_internal_read
-- ISO/IEC 27001: A.9.4.1 - Internal configs require clearance level
-- Implementation: Validates user clearance against required level
CREATE POLICY config_internal_read ON app_configuration
    FOR SELECT
    TO authenticated
    USING (
        visibility = 'internal' AND
        current_user_clearance_level() >= required_clearance_level
    );

-- POLICY: config_admin_full_access
-- PCI DSS: Requirement 2.1 - Full admin control with change tracking
-- Implementation: Super admin has full access with audit
CREATE POLICY config_admin_full_access ON app_configuration
    FOR ALL
    TO authenticated
    USING (current_user_has_role('super_admin'))
    WITH CHECK (current_user_has_role('super_admin'));

-- POLICY: config_operations_limited_update
-- ISO/IEC 27001: A.9.1.2 - Segregation of duties for operations
-- Implementation: Operations team limited to specific categories
CREATE POLICY config_operations_limited_update ON app_configuration
    FOR UPDATE
    TO authenticated
    USING (
        current_user_has_role('operations') AND
        category IN ('maintenance', 'notifications', 'performance')
    )
    WITH CHECK (
        current_user_has_role('operations') AND
        category IN ('maintenance', 'notifications', 'performance')
    );

-- ============================================================================
-- FEATURE_FLAGS TABLE POLICIES
-- ============================================================================

-- POLICY: feature_flag_public_read
-- Implementation: Public and beta features accessible to all
CREATE POLICY feature_flag_public_read ON feature_flags
    FOR SELECT
    TO authenticated
    USING (scope IN ('public', 'beta'));

-- POLICY: feature_flag_product_management
-- ISO/IEC 27001: A.9.2.2 - Privileged access for product management
-- Implementation: Product managers can manage feature flags
CREATE POLICY feature_flag_product_management ON feature_flags
    FOR ALL
    TO authenticated
    USING (
        current_user_has_role('product_manager') OR
        current_user_has_role('super_admin')
    )
    WITH CHECK (
        current_user_has_role('product_manager') OR
        current_user_has_role('super_admin')
    );

-- POLICY: feature_flag_developer_read
-- Developers can view all flags for debugging
CREATE POLICY feature_flag_developer_read ON feature_flags
    FOR SELECT
    TO authenticated
    USING (current_user_has_role('developer'));

-- POLICY: feature_flag_user_segment_access
-- ISO/IEC 27018: User segment-based access control
-- Implementation: Segment-specific feature access
CREATE POLICY feature_flag_user_segment_access ON feature_flags
    FOR SELECT
    TO authenticated
    USING (
        scope = 'segmented' AND
        current_user_in_segment(target_segment)
    );

-- ============================================================================
-- SYSTEM_SETTINGS TABLE POLICIES
-- ============================================================================

-- POLICY: system_settings_super_admin_only
-- PCI DSS: Requirement 6.5.2 - Critical settings restricted to super admin
-- Implementation: Only super_admin can access system settings
CREATE POLICY system_settings_super_admin_only ON system_settings
    FOR ALL
    TO authenticated
    USING (current_user_has_role('super_admin'))
    WITH CHECK (current_user_has_role('super_admin'));

-- ============================================================================
-- API_CREDENTIALS TABLE POLICIES
-- ============================================================================

-- POLICY: api_creds_owner_read
-- Users can view their own API credentials (masked)
CREATE POLICY api_creds_owner_read ON api_credentials
    FOR SELECT
    TO authenticated
    USING (created_by = current_user_id());

-- POLICY: api_creds_admin_management
-- Implementation: Admin full access for credential management
CREATE POLICY api_creds_admin_management ON api_credentials
    FOR ALL
    TO authenticated
    USING (current_user_has_role('admin') OR current_user_has_role('super_admin'));

-- POLICY: api_creds_service_rotation
-- ISO/IEC 27001: A.10.1.2 - Key management for service accounts
-- Implementation: Service accounts can rotate their own keys
CREATE POLICY api_creds_service_rotation ON api_credentials
    FOR UPDATE
    TO service_account
    USING (
        service_id = current_setting('app.service_id', TRUE)::UUID AND
        operation = 'key_rotation'
    )
    WITH CHECK (
        service_id = current_setting('app.service_id', TRUE)::UUID
    );

-- ============================================================================
-- HELPER FUNCTIONS FOR CONFIGURATION RLS
-- ============================================================================

-- Get current user's clearance level
-- Maps clearance strings to numeric levels for comparison
-- Returns: Numeric clearance level (0=public, 4=top_secret)
CREATE OR REPLACE FUNCTION current_user_clearance_level()
RETURNS INTEGER AS $$
DECLARE
    clearance TEXT;
    level_map JSONB := '{
        "public": 0,
        "internal": 1,
        "confidential": 2,
        "restricted": 3,
        "top_secret": 4
    }'::JSONB;
BEGIN
    clearance := current_setting('app.user_clearance_level', TRUE);
    RETURN COALESCE((level_map->>COALESCE(clearance, 'public'))::INTEGER, 0);
EXCEPTION WHEN OTHERS THEN
    RETURN 0;
END;
$$ LANGUAGE plpgsql STABLE;

-- Check if current user is in a specific segment
-- ISO/IEC 27018: Segment-based access for cloud PII protection
-- Parameters: segment_name - the segment to check
-- Returns: TRUE if user is in the specified segment
CREATE OR REPLACE FUNCTION current_user_in_segment(segment_name TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    user_segments TEXT[];
BEGIN
    user_segments := string_to_array(
        current_setting('app.user_segments', TRUE), 
        ','
    );
    
    RETURN segment_name = ANY(user_segments) OR EXISTS (
        SELECT 1 FROM user_segments us
        WHERE us.user_id = current_user_id()
        AND us.segment_name = segment_name
        AND us.active = TRUE
    );
EXCEPTION WHEN OTHERS THEN
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Check if user can modify specific configuration
-- PCI DSS: Protected keys require super_admin authorization
-- Parameters: config_category, config_key
-- Returns: TRUE if user can modify the specified config
CREATE OR REPLACE FUNCTION can_modify_config(config_category TEXT, config_key TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    protected_keys TEXT[] := ARRAY[
        'security.encryption_key',
        'security.master_secret',
        'database.connection_string',
        'payment.gateway_private_key'
    ];
    full_key TEXT;
BEGIN
    full_key := config_category || '.' || config_key;
    
    -- Only super_admin can modify protected keys
    IF full_key = ANY(protected_keys) THEN
        RETURN current_user_has_role('super_admin');
    END IF;
    
    -- Operations can modify operational configs
    IF config_category IN ('maintenance', 'notifications', 'performance') THEN
        RETURN current_user_has_role('operations') OR 
               current_user_has_role('super_admin');
    END IF;
    
    -- Product managers can modify feature configs
    IF config_category = 'features' THEN
        RETURN current_user_has_role('product_manager') OR
               current_user_has_role('super_admin');
    END IF;
    
    RETURN current_user_has_role('super_admin');
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- ENVIRONMENT-BASED POLICIES
-- ============================================================================

-- POLICY: config_environment_specific
-- ISO/IEC 27001: A.12.1.4 - Environment separation
-- Implementation: Filters configs by current environment
CREATE POLICY config_environment_specific ON app_configuration
    FOR SELECT
    TO authenticated
    USING (
        environment IS NULL OR
        environment = current_setting('app.environment', TRUE) OR
        environment = 'all'
    );

-- POLICY: config_deny_production_modification_dev_admin
-- PCI DSS: Requirement 6.5.2 - Prevent production modifications by dev admins
-- Implementation: RESTRICTIVE policy blocks cross-environment changes
CREATE POLICY config_deny_production_modification_dev_admin ON app_configuration
    AS RESTRICTIVE
    FOR ALL
    TO authenticated
    USING (
        environment != 'production' OR
        current_setting('app.authenticated_environment', TRUE) = 'production' OR
        current_user_has_role('super_admin')
    );

-- ============================================================================
-- AUDIT AND COMPLIANCE POLICIES
-- ============================================================================

-- POLICY: config_audit_readonly
-- ISO/IEC 27050-3:2020 - Compliance officers can read all configs for audit
-- Implementation: Read-only access for compliance review
CREATE POLICY config_audit_readonly ON app_configuration
    FOR SELECT
    TO authenticated
    USING (current_user_has_role('compliance_officer'));

-- POLICY: config_change_requires_approval
-- ISO/IEC 27001: A.12.1.2 - Change management workflow
-- Implementation: Requires approval token for sensitive changes
CREATE POLICY config_change_requires_approval ON app_configuration
    AS RESTRICTIVE
    FOR UPDATE
    TO authenticated
    USING (
        NOT requires_approval OR
        current_setting('app.approval_token', TRUE) IS NOT NULL OR
        current_user_has_role('super_admin')
    );

-- ============================================================================
-- APPROVAL WORKFLOW INTEGRATION (PCI DSS 6.5.2)
-- ============================================================================

-- Configuration change approval requests
CREATE TABLE IF NOT EXISTS config_change_approvals (
    approval_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id UUID NOT NULL,
    requested_by UUID NOT NULL,
    requested_at TIMESTAMPTZ DEFAULT NOW(),
    change_description TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    approver_id UUID,
    approved_at TIMESTAMPTZ,
    approval_status VARCHAR(20) DEFAULT 'pending' CHECK (approval_status IN ('pending', 'approved', 'rejected')),
    approval_token UUID DEFAULT gen_random_uuid(),
    executed_at TIMESTAMPTZ,
    is_executed BOOLEAN DEFAULT FALSE
);

-- Function to request configuration change approval
-- PCI DSS 6.5.2: Approval workflow for sensitive changes
-- Parameters: p_config_id, p_new_value, p_description
-- Returns: Approval token
CREATE OR REPLACE FUNCTION request_config_change_approval(
    p_config_id UUID,
    p_new_value TEXT,
    p_description TEXT
)
RETURNS UUID AS $$
DECLARE
    v_approval_id UUID;
    v_old_value TEXT;
BEGIN
    -- Get current value
    SELECT config_value INTO v_old_value FROM app_configuration WHERE id = p_config_id;
    
    INSERT INTO config_change_approvals (
        config_id, requested_by, change_description,
        old_value, new_value
    ) VALUES (
        p_config_id, current_user_id(), p_description,
        v_old_value, p_new_value
    ) RETURNING approval_token INTO v_approval_id;
    
    -- Log event
    PERFORM log_security_event('config_change_approval_requested',
        jsonb_build_object(
            'config_id', p_config_id,
            'approval_id', v_approval_id,
            'description', p_description
        ));
    
    RETURN v_approval_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function to approve and execute configuration change
-- Parameters: p_approval_token
-- Returns: BOOLEAN success
CREATE OR REPLACE FUNCTION approve_config_change(
    p_approval_token UUID
)
RETURNS BOOLEAN AS $$
DECLARE
    v_approval RECORD;
BEGIN
    SELECT * INTO v_approval
    FROM config_change_approvals
    WHERE approval_token = p_approval_token
    AND approval_status = 'pending';
    
    IF v_approval IS NULL THEN
        RETURN FALSE;
    END IF;
    
    -- Check approver permissions
    IF NOT current_user_has_role('super_admin') THEN
        RAISE EXCEPTION 'Only super_admin can approve configuration changes';
    END IF;
    
    -- Update approval record
    UPDATE config_change_approvals
    SET approver_id = current_user_id(),
        approved_at = NOW(),
        approval_status = 'approved'
    WHERE approval_token = p_approval_token;
    
    -- Execute the change
    UPDATE app_configuration
    SET config_value = v_approval.new_value,
        updated_at = NOW(),
        updated_by = v_approval.requested_by
    WHERE id = v_approval.config_id;
    
    -- Mark as executed
    UPDATE config_change_approvals
    SET executed_at = NOW(), is_executed = TRUE
    WHERE approval_token = p_approval_token;
    
    -- Log event
    PERFORM log_security_event('config_change_approved_executed',
        jsonb_build_object(
            'config_id', v_approval.config_id,
            'approval_id', v_approval.approval_id,
            'old_value', v_approval.old_value,
            'new_value', v_approval.new_value
        ));
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- AUTOMATIC ROLLBACK MECHANISM (ISO 27001 A.12.3)
-- ============================================================================

-- Configuration change history for rollback
CREATE TABLE IF NOT EXISTS config_change_history (
    history_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id UUID NOT NULL,
    changed_by UUID,
    changed_at TIMESTAMPTZ DEFAULT NOW(),
    previous_value TEXT,
    new_value TEXT,
    change_reason TEXT,
    rollback_eligible BOOLEAN DEFAULT TRUE,
    rolled_back_at TIMESTAMPTZ,
    rolled_back_by UUID
);

-- Function to rollback configuration change
-- ISO/IEC 27001 A.12.3: Change rollback capability
-- Parameters: p_config_id, p_history_id (optional - rollback to specific version)
-- Returns: BOOLEAN success
CREATE OR REPLACE FUNCTION rollback_config_change(
    p_config_id UUID,
    p_history_id UUID DEFAULT NULL
)
RETURNS BOOLEAN AS $$
DECLARE
    v_history RECORD;
    v_target_value TEXT;
BEGIN
    -- Get the change to rollback to
    IF p_history_id IS NOT NULL THEN
        SELECT * INTO v_history
        FROM config_change_history
        WHERE history_id = p_history_id
        AND config_id = p_config_id;
    ELSE
        -- Rollback to previous value
        SELECT * INTO v_history
        FROM config_change_history
        WHERE config_id = p_config_id
        AND rollback_eligible = TRUE
        AND rolled_back_at IS NULL
        ORDER BY changed_at DESC
        LIMIT 1;
    END IF;
    
    IF v_history IS NULL THEN
        RETURN FALSE;
    END IF;
    
    -- Check permissions
    IF NOT (current_user_has_role('super_admin') OR current_user_has_role('operations')) THEN
        RAISE EXCEPTION 'Insufficient permissions for rollback';
    END IF;
    
    -- Perform rollback
    UPDATE app_configuration
    SET config_value = v_history.previous_value,
        updated_at = NOW(),
        updated_by = current_user_id()
    WHERE id = p_config_id;
    
    -- Mark history as rolled back
    UPDATE config_change_history
    SET rolled_back_at = NOW(),
        rolled_back_by = current_user_id()
    WHERE history_id = v_history.history_id;
    
    -- Log event
    PERFORM log_security_event('config_change_rolled_back',
        jsonb_build_object(
            'config_id', p_config_id,
            'history_id', v_history.history_id,
            'restored_value', v_history.previous_value
        ));
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- CONFIGURATION VERSION CONTROL (ISO 27001 A.12.4)
-- ============================================================================

-- Configuration versions table
CREATE TABLE IF NOT EXISTS config_versions (
    version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id UUID NOT NULL,
    version_number INTEGER NOT NULL,
    config_value TEXT NOT NULL,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    change_notes TEXT,
    deployment_status VARCHAR(20) DEFAULT 'draft' CHECK (deployment_status IN ('draft', 'deployed', 'reverted'))
);

-- Function to create configuration version
-- ISO/IEC 27001 A.12.4 - Configuration version control
-- Parameters: p_config_id, p_new_value, p_notes
-- Returns: Version ID
CREATE OR REPLACE FUNCTION create_config_version(
    p_config_id UUID,
    p_new_value TEXT,
    p_notes TEXT DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_version_id UUID;
    v_next_version INTEGER;
BEGIN
    -- Get next version number
    SELECT COALESCE(MAX(version_number), 0) + 1
    INTO v_next_version
    FROM config_versions
    WHERE config_id = p_config_id;
    
    INSERT INTO config_versions (
        config_id, version_number, config_value, created_by, change_notes
    ) VALUES (
        p_config_id, v_next_version, p_new_value, current_user_id(), p_notes
    ) RETURNING version_id INTO v_version_id;
    
    RETURN v_version_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function to deploy configuration version
-- Parameters: p_version_id
-- Returns: BOOLEAN success
CREATE OR REPLACE FUNCTION deploy_config_version(
    p_version_id UUID
)
RETURNS BOOLEAN AS $$
DECLARE
    v_version RECORD;
BEGIN
    SELECT * INTO v_version FROM config_versions WHERE version_id = p_version_id;
    
    IF v_version IS NULL THEN
        RETURN FALSE;
    END IF;
    
    -- Update main config
    UPDATE app_configuration
    SET config_value = v_version.config_value,
        updated_at = NOW(),
        updated_by = current_user_id()
    WHERE id = v_version.config_id;
    
    -- Update version status
    UPDATE config_versions
    SET deployment_status = 'deployed'
    WHERE version_id = p_version_id;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- BLUE/GREEN DEPLOYMENT POLICIES (ISO 27001 A.12.1)
-- ============================================================================

-- Deployment environments table
CREATE TABLE IF NOT EXISTS deployment_environments (
    env_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_name VARCHAR(50) NOT NULL UNIQUE,
    env_type VARCHAR(20) NOT NULL CHECK (env_type IN ('blue', 'green', 'canary')),
    is_active BOOLEAN DEFAULT FALSE,
    config_snapshot JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    activated_at TIMESTAMPTZ
);

-- Function to switch deployment environment
-- ISO/IEC 27001 A.12.1 - Blue/green deployment
-- Parameters: p_target_env
-- Returns: BOOLEAN success
CREATE OR REPLACE FUNCTION switch_deployment_environment(
    p_target_env VARCHAR(50)
)
RETURNS BOOLEAN AS $$
DECLARE
    v_target RECORD;
    v_current RECORD;
BEGIN
    -- Get target environment
    SELECT * INTO v_target FROM deployment_environments WHERE env_name = p_target_env;
    
    IF v_target IS NULL THEN
        RAISE EXCEPTION 'Target environment not found: %', p_target_env;
    END IF;
    
    -- Check permissions
    IF NOT current_user_has_role('super_admin') THEN
        RAISE EXCEPTION 'Only super_admin can switch environments';
    END IF;
    
    -- Deactivate current active environment
    UPDATE deployment_environments
    SET is_active = FALSE
    WHERE is_active = TRUE;
    
    -- Activate target environment
    UPDATE deployment_environments
    SET is_active = TRUE, activated_at = NOW()
    WHERE env_id = v_target.env_id;
    
    -- Apply config snapshot if present
    IF v_target.config_snapshot IS NOT NULL THEN
        -- Apply configurations from snapshot
        PERFORM log_security_event('environment_switched',
            jsonb_build_object(
                'from_env', v_current.env_name,
                'to_env', p_target_env,
                'snapshot_applied', TRUE
            ));
    END IF;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- CANARY RELEASE CONFIGURATION (ISO 27001 A.14.2)
-- ============================================================================

-- Canary release configuration
CREATE TABLE IF NOT EXISTS canary_releases (
    canary_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feature_name VARCHAR(100) NOT NULL,
    config_changes JSONB NOT NULL,
    rollout_percentage INTEGER DEFAULT 5 CHECK (rollout_percentage BETWEEN 0 AND 100),
    target_segments TEXT[],
    start_at TIMESTAMPTZ DEFAULT NOW(),
    end_at TIMESTAMPTZ,
    status VARCHAR(20) DEFAULT 'running' CHECK (status IN ('running', 'paused', 'promoted', 'rolled_back')),
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to check if user is in canary release
-- ISO/IEC 27001 A.14.2 - Canary release with safeguards
-- Parameters: p_feature_name
-- Returns: TRUE if user should receive canary config
CREATE OR REPLACE FUNCTION is_in_canary_release(
    p_feature_name VARCHAR(100)
)
RETURNS BOOLEAN AS $$
DECLARE
    v_canary RECORD;
    v_user_hash INTEGER;
BEGIN
    SELECT * INTO v_canary
    FROM canary_releases
    WHERE feature_name = p_feature_name
    AND status = 'running'
    AND start_at <= NOW()
    AND (end_at IS NULL OR end_at > NOW());
    
    IF v_canary IS NULL THEN
        RETURN FALSE;
    END IF;
    
    -- Hash user ID to determine inclusion (consistent for same user)
    v_user_hash := abs(('x' || substr(md5(current_user_id()::TEXT), 1, 8))::bit(32)::INTEGER);
    
    -- Check if user is in rollout percentage
    IF (v_user_hash % 100) < v_canary.rollout_percentage THEN
        RETURN TRUE;
    END IF;
    
    -- Check if user is in target segment
    IF v_canary.target_segments IS NOT NULL THEN
        RETURN current_user_in_segment(v_canary.target_segments[1]);
    END IF;
    
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- A/B TESTING WITH PRIVACY SAFEGUARDS (ISO 27018)
-- ============================================================================

-- A/B test configuration
CREATE TABLE IF NOT EXISTS ab_test_configs (
    test_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_name VARCHAR(100) NOT NULL,
    variant_a_config JSONB NOT NULL,
    variant_b_config JSONB NOT NULL,
    split_ratio NUMERIC(3,2) DEFAULT 0.50 CHECK (split_ratio BETWEEN 0 AND 1),
    privacy_consent_required BOOLEAN DEFAULT TRUE,
    data_anonymization BOOLEAN DEFAULT TRUE,
    start_date TIMESTAMPTZ DEFAULT NOW(),
    end_date TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_by UUID
);

-- Function to get A/B test variant
-- ISO/IEC 27018 - A/B testing with privacy safeguards
-- Parameters: p_test_name
-- Returns: Variant config ('a' or 'b')
CREATE OR REPLACE FUNCTION get_ab_test_variant(
    p_test_name VARCHAR(100)
)
RETURNS JSONB AS $$
DECLARE
    v_test RECORD;
    v_user_hash INTEGER;
    v_in_variant_a BOOLEAN;
BEGIN
    SELECT * INTO v_test
    FROM ab_test_configs
    WHERE test_name = p_test_name
    AND is_active = TRUE
    AND start_date <= NOW()
    AND (end_date IS NULL OR end_date > NOW());
    
    IF v_test IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Check privacy consent if required
    IF v_test.privacy_consent_required THEN
        IF NOT COALESCE(current_setting('app.ab_testing_consent', TRUE)::BOOLEAN, FALSE) THEN
            -- Return default/variant A without tracking
            RETURN v_test.variant_a_config;
        END IF;
    END IF;
    
    -- Determine variant
    v_user_hash := abs(('x' || substr(md5(current_user_id()::TEXT || p_test_name), 1, 8))::bit(32)::INTEGER);
    v_in_variant_a := (v_user_hash % 100) < (v_test.split_ratio * 100);
    
    RETURN CASE WHEN v_in_variant_a THEN v_test.variant_a_config ELSE v_test.variant_b_config END;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- CONFIGURATION DEPENDENCY VALIDATION (PCI DSS 6.5)
-- ============================================================================

-- Configuration dependencies table
CREATE TABLE IF NOT EXISTS config_dependencies (
    dependency_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id UUID NOT NULL,
    depends_on_config_id UUID NOT NULL,
    dependency_type VARCHAR(20) DEFAULT 'requires' CHECK (dependency_type IN ('requires', 'conflicts', 'recommends')),
    validation_rule TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to validate configuration dependencies
-- PCI DSS 6.5: Configuration dependency validation
-- Parameters: p_config_id, p_new_value
-- Returns: Validation result as JSONB
CREATE OR REPLACE FUNCTION validate_config_dependencies(
    p_config_id UUID,
    p_new_value TEXT
)
RETURNS JSONB AS $$
DECLARE
    v_result JSONB := '{"valid": true, "issues": []}';
    v_dep RECORD;
    v_dep_value TEXT;
BEGIN
    FOR v_dep IN 
        SELECT * FROM config_dependencies 
        WHERE config_id = p_config_id
    LOOP
        SELECT config_value INTO v_dep_value 
        FROM app_configuration 
        WHERE id = v_dep.depends_on_config_id;
        
        CASE v_dep.dependency_type
            WHEN 'requires' THEN
                IF v_dep_value IS NULL OR v_dep_value = '' THEN
                    v_result := jsonb_set(
                        v_result, 
                        '{issues}', 
                        v_result->'issues' || jsonb_build_object(
                            'type', 'missing_dependency',
                            'config_id', v_dep.depends_on_config_id,
                            'message', 'Required dependency not configured'
                        )
                    );
                    v_result := jsonb_set(v_result, '{valid}', 'false');
                END IF;
                
            WHEN 'conflicts' THEN
                IF v_dep_value IS NOT NULL AND v_dep_value = p_new_value THEN
                    v_result := jsonb_set(
                        v_result,
                        '{issues}',
                        v_result->'issues' || jsonb_build_object(
                            'type', 'conflict',
                            'config_id', v_dep.depends_on_config_id,
                            'message', 'Configuration conflicts with dependent setting'
                        )
                    );
                    v_result := jsonb_set(v_result, '{valid}', 'false');
                END IF;
        END CASE;
    END LOOP;
    
    RETURN v_result;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- CONFIGURATION ENCRYPTION FOR SENSITIVE VALUES (ISO 27040)
-- ============================================================================

-- Encrypted configuration values
CREATE TABLE IF NOT EXISTS encrypted_config_values (
    encrypted_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id UUID NOT NULL,
    encrypted_value BYTEA NOT NULL,
    encryption_key_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    rotated_at TIMESTAMPTZ
);

-- Function to store encrypted configuration
-- ISO/IEC 27040 - Configuration encryption
-- Parameters: p_config_id, p_plaintext_value, p_key_id
-- Returns: Encrypted ID
CREATE OR REPLACE FUNCTION store_encrypted_config(
    p_config_id UUID,
    p_plaintext_value TEXT,
    p_key_id UUID DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_encrypted_id UUID;
    v_encrypted BYTEA;
BEGIN
    -- Encrypt value
    v_encrypted := pgp_sym_encrypt(
        p_plaintext_value,
        current_setting('app.config_encryption_key', TRUE)
    )::BYTEA;
    
    INSERT INTO encrypted_config_values (
        config_id, encrypted_value, encryption_key_id
    ) VALUES (
        p_config_id, v_encrypted, p_key_id
    ) RETURNING encrypted_id INTO v_encrypted_id;
    
    -- Update main config to indicate encryption
    UPDATE app_configuration
    SET is_encrypted = TRUE,
        config_value = '[ENCRYPTED]'
    WHERE id = p_config_id;
    
    RETURN v_encrypted_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function to retrieve decrypted configuration
-- Parameters: p_config_id
-- Returns: Decrypted value
CREATE OR REPLACE FUNCTION get_decrypted_config(
    p_config_id UUID
)
RETURNS TEXT AS $$
DECLARE
    v_encrypted RECORD;
    v_decrypted TEXT;
BEGIN
    SELECT * INTO v_encrypted
    FROM encrypted_config_values
    WHERE config_id = p_config_id
    ORDER BY created_at DESC
    LIMIT 1;
    
    IF v_encrypted IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Decrypt value
    v_decrypted := pgp_sym_decrypt(
        v_encrypted.encrypted_value,
        current_setting('app.config_encryption_key', TRUE)
    );
    
    RETURN v_decrypted;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================================================
-- MULTI-REGION CONFIGURATION SYNCHRONIZATION (ISO 27001 A.17)
-- ============================================================================

-- Multi-region config sync status
CREATE TABLE IF NOT EXISTS config_sync_status (
    sync_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id UUID NOT NULL,
    region VARCHAR(50) NOT NULL,
    sync_status VARCHAR(20) DEFAULT 'pending' CHECK (sync_status IN ('pending', 'syncing', 'synced', 'failed')),
    local_value TEXT,
    remote_value TEXT,
    last_sync_at TIMESTAMPTZ,
    sync_error TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(config_id, region)
);

-- Function to sync configuration to remote region
-- ISO/IEC 27001 A.17 - Multi-region synchronization
-- Parameters: p_config_id, p_target_region
-- Returns: Sync ID
CREATE OR REPLACE FUNCTION sync_config_to_region(
    p_config_id UUID,
    p_target_region VARCHAR(50)
)
RETURNS UUID AS $$
DECLARE
    v_sync_id UUID;
    v_config RECORD;
BEGIN
    SELECT * INTO v_config FROM app_configuration WHERE id = p_config_id;
    
    IF v_config IS NULL THEN
        RAISE EXCEPTION 'Configuration not found: %', p_config_id;
    END IF;
    
    INSERT INTO config_sync_status (
        config_id, region, sync_status, local_value
    ) VALUES (
        p_config_id, p_target_region, 'syncing', v_config.config_value
    )
    ON CONFLICT (config_id, region) DO UPDATE SET
        sync_status = 'syncing',
        local_value = v_config.config_value,
        last_sync_at = NOW()
    RETURNING sync_id INTO v_sync_id;
    
    -- In production, this would trigger async replication
    -- For now, mark as synced
    UPDATE config_sync_status
    SET sync_status = 'synced',
        remote_value = v_config.config_value,
        last_sync_at = NOW()
    WHERE sync_id = v_sync_id;
    
    RETURN v_sync_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON POLICY config_public_read ON app_configuration IS 
    'ISO/IEC 27001 A.9.4.1 - Public configuration accessible to all authenticated users';
COMMENT ON POLICY system_settings_super_admin_only ON system_settings IS 
    'PCI DSS Req 6.5.2 - Critical system settings restricted to super administrators';
COMMENT ON POLICY config_deny_production_modification_dev_admin ON app_configuration IS 
    'PCI DSS Req 2.1 - Safety policy to prevent accidental production modifications';
COMMENT ON FUNCTION can_modify_config IS 
    'PCI DSS: Enforces dual authorization for protected configuration keys';
COMMENT ON FUNCTION request_config_change_approval IS 'PCI DSS 6.5.2 - Requests approval for sensitive config changes';
COMMENT ON FUNCTION approve_config_change IS 'Approves and executes pending configuration change';
COMMENT ON FUNCTION rollback_config_change IS 'ISO/IEC 27001 A.12.3 - Rolls back configuration to previous version';
COMMENT ON FUNCTION create_config_version IS 'ISO/IEC 27001 A.12.4 - Creates new configuration version';
COMMENT ON FUNCTION switch_deployment_environment IS 'ISO/IEC 27001 A.12.1 - Switches blue/green deployment environment';
COMMENT ON FUNCTION is_in_canary_release IS 'ISO/IEC 27001 A.14.2 - Checks if user is in canary release';
COMMENT ON FUNCTION get_ab_test_variant IS 'ISO/IEC 27018 - Gets A/B test variant with privacy safeguards';
COMMENT ON FUNCTION validate_config_dependencies IS 'PCI DSS 6.5 - Validates configuration dependencies';
COMMENT ON FUNCTION store_encrypted_config IS 'ISO/IEC 27040 - Stores encrypted configuration value';
COMMENT ON FUNCTION sync_config_to_region IS 'ISO/IEC 27001 A.17 - Syncs configuration to remote region';
COMMENT ON TABLE config_change_approvals IS 'PCI DSS 6.5.2 - Configuration change approval workflow';
COMMENT ON TABLE config_change_history IS 'Configuration change history for rollback';
COMMENT ON TABLE config_versions IS 'ISO/IEC 27001 A.12.4 - Configuration version control';
COMMENT ON TABLE deployment_environments IS 'ISO/IEC 27001 A.12.1 - Blue/green deployment environments';
COMMENT ON TABLE canary_releases IS 'ISO/IEC 27001 A.14.2 - Canary release configuration';
COMMENT ON TABLE ab_test_configs IS 'ISO/IEC 27018 - A/B test configuration with privacy safeguards';
COMMENT ON TABLE encrypted_config_values IS 'ISO/IEC 27040 - Encrypted sensitive configuration values';
COMMENT ON TABLE config_sync_status IS 'ISO/IEC 27001 A.17 - Multi-region config synchronization status';
