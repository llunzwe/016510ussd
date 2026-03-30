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
    'PLACEHOLDER_HASH',  -- Replace with actual hash during deployment
    ARRAY['transactions:read', 'transactions:write', 'accounts:read', 'sessions:manage'],
    1000, 50000,  -- Rate limits
    ARRAY['10.0.0.0/8', '172.16.0.0/12'],  -- Internal networks only
    'active', NOW(), NOW() + INTERVAL '1 year'
)
ON CONFLICT (id) DO NOTHING;

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

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE service_accounts IS 'ISO/IEC 27001: Service accounts for system integrations (PCI DSS 8.6.3)';

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Generate actual API keys using crypto_generate_api_key() during deployment
-- TODO: Configure actual IP whitelist for production environment
-- TODO: Set up proper MFA for admin accounts before activation (PCI DSS)
-- TODO: Configure email/SMS notifications for admin activation
-- TODO: Implement service account key rotation schedule (PCI DSS 3.6.4)
-- TODO: Add monitoring alerts for system account usage
-- TODO: Create runbook for emergency admin access
-- TODO: Implement break-glass procedures for admin access (ISO 27001)
-- TODO: Add integration with corporate identity provider for admin accounts
-- TODO: Configure automated credential expiration notifications
-- ============================================================================
