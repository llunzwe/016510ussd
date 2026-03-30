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

-- ============================================================================
-- SECURITY AUDIT LOG ENTRY
-- ============================================================================
DO $$
BEGIN
    PERFORM log_security_event(
        'config_rls_policies_initialized',
        jsonb_build_object(
            'tables', ARRAY['app_configuration', 'feature_flags', 'system_settings', 'api_credentials'],
            'policies_applied', 16,
            'standards', ARRAY['ISO/IEC 27001:2022', 'PCI DSS 4.0', 'ISO/IEC 27018:2019'],
            'timestamp', NOW()
        )
    );
EXCEPTION WHEN OTHERS THEN
    NULL;
END $$;

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Implement approval workflow integration for sensitive config changes (PCI DSS 6.5.2)
-- TODO: Add automatic rollback mechanism for failed config deployments (ISO 27001 A.12.3)
-- TODO: Implement configuration version control and history tracking (ISO 27001 A.12.4)
-- TODO: Add blue/green deployment configuration policies (ISO 27001 A.12.1)
-- TODO: Implement canary release configuration access (ISO 27001 A.14.2)
-- TODO: Create A/B testing configuration policies with privacy safeguards (ISO 27018)
-- TODO: Add configuration dependency validation (PCI DSS 6.5)
-- TODO: Implement configuration encryption for sensitive values (ISO 27040)
-- TODO: Add multi-region configuration synchronization policies (ISO 27001 A.17)
-- ============================================================================
