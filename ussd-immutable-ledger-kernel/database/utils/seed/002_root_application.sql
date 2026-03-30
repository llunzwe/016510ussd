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
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE app_configuration IS 'ISO/IEC 27001: Application configuration with environment and visibility support';
COMMENT ON TABLE feature_flags IS 'ISO/IEC 27018: Feature toggle configuration for gradual rollout';
COMMENT ON TABLE system_settings IS 'PCI DSS: Critical system settings with access control';

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Add configuration versioning and rollback capability
-- TODO: Implement configuration hot-reload mechanism
-- TODO: Add configuration A/B testing support
-- TODO: Create configuration dependency validation
-- TODO: Implement configuration drift detection
-- TODO: Add configuration encryption for sensitive values
-- TODO: Create configuration templates for different deployment types
-- TODO: Implement configuration validation rules
-- TODO: Add configuration change approval workflow
-- TODO: Create configuration backup and restore procedures
-- ============================================================================
