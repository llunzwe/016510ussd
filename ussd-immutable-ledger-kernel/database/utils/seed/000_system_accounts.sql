-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: utils/seed/000_system_accounts.sql
-- Description: Initial system accounts, service accounts, and administrative
--              user templates for USSD immutable ledger
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: RESTRICTED
-- DATA SENSITIVITY: CRITICAL - System Account Initialization
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.9.2 User Access Management
  - A.9.2.1: User registration and provisioning
  - A.9.2.2: Privilege management
  - A.9.2.3: Access rights revocation
  
A.9.4 System and Application Access Control
  - Service account isolation
  - Privileged account templates

A.12.1 Operational Procedures
  - System account documentation
  - Change management for accounts
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION
================================================================================
- System accounts have minimal PII
- Service account separation from user accounts
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
- System account data protection
- Audit trail for account creation
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
- System account records for litigation hold
- Immutable audit trail for account provisioning
================================================================================

================================================================================
PCI DSS 4.0 SERVICE ACCOUNT REQUIREMENTS
================================================================================
Requirement 8.6.3: Service account monitoring
Requirement 8.2.1: Strong authentication for service accounts
Requirement 10.2: Audit trail for service account usage
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. UUID generation for all accounts
2. ON CONFLICT handling for idempotency
3. Clear documentation for each account purpose
4. Role assignment documentation
5. Expiration dates for service accounts
================================================================================

================================================================================
SECURITY CONSIDERATIONS
================================================================================
- System accounts have UUIDs starting with 00000000 for identification
- Service accounts have UUIDs starting with 10000000
- Admin templates have UUIDs starting with a0000000
- System ledger accounts have UUIDs starting with 20000000
- All service accounts require IP whitelisting in production
- API keys must be generated using crypto_generate_api_key() during deployment
================================================================================

================================================================================
ACCOUNT TYPES
================================================================================
system: Internal system processes
anonymous: Unauthenticated user representation
service: External service integrations
admin: Administrative users
support: Customer support users
================================================================================
*/

-- ============================================================================
-- SYSTEM USERS
-- ============================================================================

-- System user for automated processes
-- ISO/IEC 27001: A.9.2.1 - System account provisioning
INSERT INTO users (
    id, email, phone_number, full_name, status, user_type,
    email_verified, phone_verified, created_at, updated_at
) VALUES (
    '00000000-0000-0000-0000-000000000001'::UUID,
    'system@ussd-ledger.local',
    '+000000000001',
    'System Account',
    'active',
    'system',
    TRUE, TRUE, NOW(), NOW()
)
ON CONFLICT (id) DO NOTHING;

-- Anonymous user for unauthenticated operations
INSERT INTO users (
    id, email, phone_number, full_name, status, user_type,
    email_verified, phone_verified, created_at, updated_at
) VALUES (
    '00000000-0000-0000-0000-000000000000'::UUID,
    'anonymous@ussd-ledger.local',
    '+000000000000',
    'Anonymous User',
    'active',
    'anonymous',
    FALSE, FALSE, NOW(), NOW()
)
ON CONFLICT (id) DO NOTHING;

-- Audit system user for audit trail operations
INSERT INTO users (
    id, email, phone_number, full_name, status, user_type,
    email_verified, phone_verified, created_at, updated_at
) VALUES (
    '00000000-0000-0000-0000-000000000002'::UUID,
    'audit@ussd-ledger.local',
    '+000000000002',
    'Audit System',
    'active',
    'system',
    TRUE, TRUE, NOW(), NOW()
)
ON CONFLICT (id) DO NOTHING;

-- Scheduler system user for automated tasks
INSERT INTO users (
    id, email, phone_number, full_name, status, user_type,
    email_verified, phone_verified, created_at, updated_at
) VALUES (
    '00000000-0000-0000-0000-000000000003'::UUID,
    'scheduler@ussd-ledger.local',
    '+000000000003',
    'Scheduler System',
    'active',
    'system',
    TRUE, TRUE, NOW(), NOW()
)
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- SERVICE ACCOUNTS
-- ============================================================================

-- USSD Gateway Service Account
-- PCI DSS 8.6.3: Service account with restricted permissions
INSERT INTO service_accounts (
    id, service_name, service_type, description, api_key_hash,
    permissions, rate_limit_requests_per_minute, rate_limit_requests_per_hour,
    allowed_ips, status, created_at, expires_at
) VALUES (
    '10000000-0000-0000-0000-000000000001'::UUID,
    'ussd-gateway', 'integration',
    'USSD Gateway integration service for mobile network operators',
    encode(digest('DEPLOYMENT_PLACEHOLDER_' || gen_random_uuid()::TEXT, 'sha256'), 'hex'),
    ARRAY['transactions:read', 'transactions:write', 'accounts:read', 'sessions:manage'],
    1000, 50000,  -- Rate limits
    ARRAY['10.0.0.0/8', '172.16.0.0/12'],  -- Internal networks only
    'active', NOW(), NOW() + INTERVAL '1 year'
)
ON CONFLICT (id) DO NOTHING;

-- Mobile Money Operator Service Account
INSERT INTO service_accounts (
    id, service_name, service_type, description, api_key_hash,
    permissions, rate_limit_requests_per_minute, rate_limit_requests_per_hour,
    allowed_ips, status, created_at, expires_at
) VALUES (
    '10000000-0000-0000-0000-000000000002'::UUID,
    'mmo-integration', 'integration',
    'Mobile Money Operator integration for wallet funding and cash out',
    encode(digest('DEPLOYMENT_PLACEHOLDER_' || gen_random_uuid()::TEXT, 'sha256'), 'hex'),
    ARRAY['transactions:write', 'accounts:read', 'webhooks:receive'],
    500, 25000,
    ARRAY['10.0.0.0/8'],
    'active', NOW(), NOW() + INTERVAL '1 year'
)
ON CONFLICT (id) DO NOTHING;

-- Banking Partner Service Account
INSERT INTO service_accounts (
    id, service_name, service_type, description, api_key_hash,
    permissions, rate_limit_requests_per_minute, rate_limit_requests_per_hour,
    allowed_ips, status, created_at, expires_at
) VALUES (
    '10000000-0000-0000-0000-000000000003'::UUID,
    'banking-partner', 'integration',
    'Banking partner integration for bank transfers and settlements',
    encode(digest('DEPLOYMENT_PLACEHOLDER_' || gen_random_uuid()::TEXT, 'sha256'), 'hex'),
    ARRAY['transactions:read', 'transactions:write', 'settlements:manage'],
    200, 10000,
    ARRAY['10.0.0.0/8', '192.168.0.0/16'],
    'active', NOW(), NOW() + INTERVAL '1 year'
)
ON CONFLICT (id) DO NOTHING;

-- KYC Verification Service Account
INSERT INTO service_accounts (
    id, service_name, service_type, description, api_key_hash,
    permissions, rate_limit_requests_per_minute, rate_limit_requests_per_hour,
    allowed_ips, status, created_at, expires_at
) VALUES (
    '10000000-0000-0000-0000-000000000004'::UUID,
    'kyc-provider', 'integration',
    'External KYC/Identity verification service',
    encode(digest('DEPLOYMENT_PLACEHOLDER_' || gen_random_uuid()::TEXT, 'sha256'), 'hex'),
    ARRAY['kyc:read', 'kyc:write', 'users:read'],
    100, 5000,
    ARRAY['0.0.0.0/0'], -- Restricted by API gateway in production
    'active', NOW(), NOW() + INTERVAL '1 year'
)
ON CONFLICT (id) DO NOTHING;

-- Notification Service Account
INSERT INTO service_accounts (
    id, service_name, service_type, description, api_key_hash,
    permissions, rate_limit_requests_per_minute, rate_limit_requests_per_hour,
    allowed_ips, status, created_at, expires_at
) VALUES (
    '10000000-0000-0000-0000-000000000005'::UUID,
    'notification-service', 'internal',
    'Internal notification service for SMS, email, push notifications',
    encode(digest('DEPLOYMENT_PLACEHOLDER_' || gen_random_uuid()::TEXT, 'sha256'), 'hex'),
    ARRAY['notifications:send', 'users:read'],
    10000, 1000000,
    ARRAY['127.0.0.1/32', '::1/128'], -- Localhost only
    'active', NOW(), NOW() + INTERVAL '2 years'
)
ON CONFLICT (id) DO NOTHING;

-- Reporting Service Account
INSERT INTO service_accounts (
    id, service_name, service_type, description, api_key_hash,
    permissions, rate_limit_requests_per_minute, rate_limit_requests_per_hour,
    allowed_ips, status, created_at, expires_at
) VALUES (
    '10000000-0000-0000-0000-000000000006'::UUID,
    'reporting-service', 'internal',
    'Internal reporting and analytics service with read-only access',
    encode(digest('DEPLOYMENT_PLACEHOLDER_' || gen_random_uuid()::TEXT, 'sha256'), 'hex'),
    ARRAY['reports:read', 'analytics:read'],
    60, 1000,
    ARRAY['10.0.0.0/8'],
    'active', NOW(), NOW() + INTERVAL '2 years'
)
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- SERVICE ACCOUNT KEY MANAGEMENT
-- ============================================================================

CREATE TABLE IF NOT EXISTS service_account_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_account_id UUID NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL,
    key_prefix TEXT NOT NULL, -- First 8 chars of key for identification
    key_name VARCHAR(100),
    issued_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    usage_count INTEGER DEFAULT 0,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID,
    revoke_reason TEXT,
    rotated_from_key_id UUID,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_service_account_keys_account ON service_account_keys(service_account_id);
CREATE INDEX IF NOT EXISTS idx_service_account_keys_active ON service_account_keys(service_account_id, is_active) WHERE is_active = TRUE;

-- Key rotation schedule (PCI DSS 3.6.4)
CREATE TABLE IF NOT EXISTS service_account_key_rotation_schedule (
    schedule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_account_id UUID NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    rotation_interval_months INTEGER DEFAULT 12,
    last_rotated_at TIMESTAMPTZ,
    next_rotation_due TIMESTAMPTZ,
    auto_rotate_enabled BOOLEAN DEFAULT FALSE,
    notification_days_before INTEGER DEFAULT 30,
    notification_sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Initialize rotation schedule for existing service accounts
INSERT INTO service_account_key_rotation_schedule (service_account_id, rotation_interval_months, next_rotation_due)
SELECT id, 12, NOW() + INTERVAL '11 months'
FROM service_accounts
ON CONFLICT (service_account_id) DO NOTHING;

-- ============================================================================
-- SERVICE ACCOUNT MONITORING
-- ============================================================================

CREATE TABLE IF NOT EXISTS service_account_monitoring (
    monitoring_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_account_id UUID NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    
    -- Activity tracking
    last_activity_at TIMESTAMPTZ,
    last_activity_ip INET,
    last_activity_endpoint TEXT,
    
    -- Usage metrics
    requests_today INTEGER DEFAULT 0,
    requests_this_week INTEGER DEFAULT 0,
    requests_this_month INTEGER DEFAULT 0,
    failed_requests_today INTEGER DEFAULT 0,
    
    -- Anomaly detection
    unusual_activity_detected BOOLEAN DEFAULT FALSE,
    anomaly_detected_at TIMESTAMPTZ,
    anomaly_description TEXT,
    
    -- Alert configuration
    alert_on_inactive_days INTEGER DEFAULT 7,
    alert_on_error_rate_percent INTEGER DEFAULT 50,
    
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_service_account_monitoring ON service_account_monitoring(service_account_id);

-- Initialize monitoring for existing service accounts
INSERT INTO service_account_monitoring (service_account_id)
SELECT id FROM service_accounts
ON CONFLICT (service_account_id) DO NOTHING;

-- ============================================================================
-- ADMINISTRATIVE USER TEMPLATES
-- ============================================================================

-- Super Admin Template (manual activation required)
-- ISO/IEC 27001: A.9.2.2 - Privileged access management
INSERT INTO users (
    id, email, phone_number, full_name, status, user_type,
    email_verified, phone_verified, created_at, updated_at
) VALUES (
    'a0000000-0000-0000-0000-000000000001'::UUID,
    'admin@ussd-ledger.local',
    '+000000000101',
    'System Administrator',
    'pending_activation',  -- Requires manual activation per PCI DSS
    'admin',
    FALSE, FALSE, NOW(), NOW()
)
ON CONFLICT (id) DO NOTHING;

-- Security Administrator Template
INSERT INTO users (
    id, email, phone_number, full_name, status, user_type,
    email_verified, phone_verified, created_at, updated_at
) VALUES (
    'a0000000-0000-0000-0000-000000000002'::UUID,
    'security-admin@ussd-ledger.local',
    '+000000000102',
    'Security Administrator',
    'pending_activation',
    'admin',
    FALSE, FALSE, NOW(), NOW()
)
ON CONFLICT (id) DO NOTHING;

-- Compliance Administrator Template
INSERT INTO users (
    id, email, phone_number, full_name, status, user_type,
    email_verified, phone_verified, created_at, updated_at
) VALUES (
    'a0000000-0000-0000-0000-000000000003'::UUID,
    'compliance-admin@ussd-ledger.local',
    '+000000000103',
    'Compliance Administrator',
    'pending_activation',
    'admin',
    FALSE, FALSE, NOW(), NOW()
)
ON CONFLICT (id) DO NOTHING;

-- Operations Administrator Template
INSERT INTO users (
    id, email, phone_number, full_name, status, user_type,
    email_verified, phone_verified, created_at, updated_at
) VALUES (
    'a0000000-0000-0000-0000-000000000004'::UUID,
    'ops-admin@ussd-ledger.local',
    '+000000000104',
    'Operations Administrator',
    'pending_activation',
    'admin',
    FALSE, FALSE, NOW(), NOW()
)
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- ADMIN ROLES AND PERMISSIONS
-- ============================================================================

CREATE TABLE IF NOT EXISTS admin_roles (
    role_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_name VARCHAR(50) NOT NULL UNIQUE,
    role_description TEXT,
    permissions TEXT[] NOT NULL,
    is_super_admin BOOLEAN DEFAULT FALSE,
    requires_mfa BOOLEAN DEFAULT TRUE,
    max_session_duration_minutes INTEGER DEFAULT 480,
    allowed_ip_ranges TEXT[],
    allowed_time_ranges TEXT[], -- JSON time windows
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO admin_roles (role_name, role_description, permissions, is_super_admin, requires_mfa) VALUES
    ('super_admin', 'Full system access with all permissions', 
     ARRAY['*:*'], TRUE, TRUE),
    ('security_admin', 'Security configuration and audit access', 
     ARRAY['security:*', 'audit:*', 'users:read', 'logs:read'], FALSE, TRUE),
    ('compliance_admin', 'Compliance reporting and policy management', 
     ARRAY['compliance:*', 'reports:read', 'audit:read'], FALSE, TRUE),
    ('ops_admin', 'Operations and support functions', 
     ARRAY['operations:*', 'support:*', 'users:read', 'transactions:read'], FALSE, TRUE),
    ('readonly_admin', 'Read-only access for auditors', 
     ARRAY['*:read'], FALSE, TRUE)
ON CONFLICT (role_name) DO NOTHING;

-- ============================================================================
-- ADMIN MFA REQUIREMENTS
-- ============================================================================

CREATE TABLE IF NOT EXISTS admin_mfa_enrollment (
    enrollment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mfa_type VARCHAR(20) NOT NULL, -- 'totp', 'sms', 'email', 'hardware'
    mfa_secret_encrypted TEXT,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    enrolled_at TIMESTAMPTZ,
    last_verified_at TIMESTAMPTZ,
    backup_codes_generated BOOLEAN DEFAULT FALSE,
    backup_codes_used INTEGER DEFAULT 0,
    requires_reenrollment BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_mfa_user ON admin_mfa_enrollment(user_id);

-- ============================================================================
-- BREAK-GLASS EMERGENCY ACCESS
-- ============================================================================

CREATE TABLE IF NOT EXISTS break_glass_accounts (
    account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_name VARCHAR(100) NOT NULL,
    
    -- Access control
    activation_reason TEXT,
    activated_at TIMESTAMPTZ,
    activated_by UUID,
    expires_at TIMESTAMPTZ,
    
    -- Usage tracking
    last_used_at TIMESTAMPTZ,
    usage_count INTEGER DEFAULT 0,
    
    -- Security
    requires_additional_approval BOOLEAN DEFAULT TRUE,
    approved_by UUID,
    approved_at TIMESTAMPTZ,
    
    -- Notification
    notification_sent_to TEXT[],
    
    -- Status
    status VARCHAR(20) DEFAULT 'inactive', -- inactive, pending_approval, active, expired, revoked
    revoked_at TIMESTAMPTZ,
    revoked_by UUID,
    revoke_reason TEXT,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_break_glass_status ON break_glass_accounts(status);

-- ============================================================================
-- SYSTEM ACCOUNTS (LEDGER)
-- ============================================================================

-- System suspense account for pending transactions
INSERT INTO accounts (
    id, account_number, account_type, account_name, currency,
    status, owner_user_id, is_system_account, created_at
) VALUES (
    '20000000-0000-0000-0000-000000000001'::UUID,
    'SYSTEM-SUSPENSE-001',
    'system',
    'System Suspense Account',
    'USD',
    'active',
    '00000000-0000-0000-0000-000000000001'::UUID,
    TRUE,
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- Revenue/Fee collection account
INSERT INTO accounts (
    id, account_number, account_type, account_name, currency,
    status, owner_user_id, is_system_account, created_at
) VALUES (
    '20000000-0000-0000-0000-000000000002'::UUID,
    'SYSTEM-REVENUE-001',
    'system',
    'System Revenue Account',
    'USD',
    'active',
    '00000000-0000-0000-0000-000000000001'::UUID,
    TRUE,
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- Escrow/Hold account
INSERT INTO accounts (
    id, account_number, account_type, account_name, currency,
    status, owner_user_id, is_system_account, created_at
) VALUES (
    '20000000-0000-0000-0000-000000000003'::UUID,
    'SYSTEM-ESCROW-001',
    'system',
    'System Escrow Account',
    'USD',
    'active',
    '00000000-0000-0000-0000-000000000001'::UUID,
    TRUE,
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- Reserve account for liquidity
INSERT INTO accounts (
    id, account_number, account_type, account_name, currency,
    status, owner_user_id, is_system_account, created_at
) VALUES (
    '20000000-0000-0000-0000-000000000004'::UUID,
    'SYSTEM-RESERVE-001',
    'system',
    'System Reserve Account',
    'USD',
    'active',
    '00000000-0000-0000-0000-000000000001'::UUID,
    TRUE,
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- Intercompany settlement account
INSERT INTO accounts (
    id, account_number, account_type, account_name, currency,
    status, owner_user_id, is_system_account, created_at
) VALUES (
    '20000000-0000-0000-0000-000000000005'::UUID,
    'SYSTEM-SETTLEMENT-001',
    'system',
    'System Settlement Account',
    'USD',
    'active',
    '00000000-0000-0000-0000-000000000001'::UUID,
    TRUE,
    NOW()
)
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- SYSTEM ACCOUNT ACTIVATION PROCEDURES
-- ============================================================================

CREATE OR REPLACE FUNCTION activate_admin_account(
    p_user_id UUID,
    p_activated_by UUID,
    p_mfa_type VARCHAR(20) DEFAULT 'totp'
)
RETURNS BOOLEAN AS $$
DECLARE
    v_user RECORD;
    v_mfa_id UUID;
BEGIN
    -- Get user details
    SELECT * INTO v_user FROM users WHERE id = p_user_id AND user_type = 'admin';
    
    IF v_user IS NULL THEN
        RAISE EXCEPTION 'Admin user not found';
    END IF;
    
    IF v_user.status != 'pending_activation' THEN
        RAISE EXCEPTION 'Account is not in pending activation state';
    END IF;
    
    -- Update user status
    UPDATE users SET 
        status = 'active',
        email_verified = TRUE,
        phone_verified = TRUE,
        updated_at = NOW()
    WHERE id = p_user_id;
    
    -- Create MFA enrollment
    INSERT INTO admin_mfa_enrollment (user_id, mfa_type, requires_reenrollment)
    VALUES (p_user_id, p_mfa_type, TRUE)
    RETURNING enrollment_id INTO v_mfa_id;
    
    -- Log activation
    PERFORM app_log_write(
        'INFO',
        format('Admin account activated: %s', p_user_id),
        'admin_activation',
        'activate_admin_account',
        jsonb_build_object('user_id', p_user_id, 'activated_by', p_activated_by, 'mfa_enrollment_id', v_mfa_id),
        p_user_id
    );
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- EMERGENCY ACCESS PROCEDURE
-- ============================================================================

CREATE OR REPLACE FUNCTION request_break_glass_access(
    p_user_id UUID,
    p_reason TEXT,
    p_requested_by UUID,
    p_duration_hours INTEGER DEFAULT 4
)
RETURNS UUID AS $$
DECLARE
    v_account_id UUID;
BEGIN
    INSERT INTO break_glass_accounts (
        user_id,
        account_name,
        activation_reason,
        activated_by,
        expires_at,
        status,
        notification_sent_to
    ) VALUES (
        p_user_id,
        'Emergency Break-Glass Access',
        p_reason,
        p_requested_by,
        NOW() + (p_duration_hours || ' hours')::INTERVAL,
        'pending_approval',
        ARRAY['security@ussd-ledger.local', 'oncall@ussd-ledger.local']
    )
    RETURNING account_id INTO v_account_id;
    
    -- Log emergency access request
    PERFORM app_log_write(
        'ALERT',
        format('Break-glass access requested: %s', p_reason),
        'security',
        'request_break_glass_access',
        jsonb_build_object(
            'break_glass_id', v_account_id,
            'user_id', p_user_id,
            'requested_by', p_requested_by,
            'duration_hours', p_duration_hours
        ),
        p_user_id
    );
    
    RETURN v_account_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE service_accounts IS 'ISO/IEC 27001: Service accounts for system integrations (PCI DSS 8.6.3)';
COMMENT ON TABLE service_account_keys IS 'API key management for service accounts';
COMMENT ON TABLE service_account_key_rotation_schedule IS 'PCI DSS 3.6.4: Automated key rotation scheduling';
COMMENT ON TABLE service_account_monitoring IS 'Service account usage monitoring and anomaly detection';
COMMENT ON TABLE admin_roles IS 'Administrative role definitions with permissions';
COMMENT ON TABLE admin_mfa_enrollment IS 'MFA enrollment status for admin accounts (PCI DSS 8.3)';
COMMENT ON TABLE break_glass_accounts IS 'Emergency break-glass access accounts (ISO 27001)';
COMMENT ON FUNCTION activate_admin_account IS 'Secure admin account activation with MFA setup';
COMMENT ON FUNCTION request_break_glass_access IS 'Emergency access request procedure';

-- ============================================================================
-- IMPLEMENTATION COMPLETE
-- ============================================================================
