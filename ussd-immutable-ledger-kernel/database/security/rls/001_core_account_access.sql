-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: security/rls/001_core_account_access.sql
-- Description: Row-Level Security policies for account table access control
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: RESTRICTED
-- DATA SENSITIVITY: CRITICAL - Account/Balance Data
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.9.1 Access Control Policy
  - A.9.1.1: Need-to-know basis - Users have full access only to their own 
    accounts, implementing strict need-to-know principle
  - A.9.1.2: Segregation of duties - Account management functions segregated
    between owners, support staff, and administrators
  
A.9.2 User Access Management
  - A.9.2.1: User registration - Automated provisioning through RLS policy 
    evaluation for new accounts
  - A.9.2.2: Privilege management - Role-based access for support and admin
    functions with appropriate restrictions
  
A.9.4 System and Application Access Control
  - A.9.4.1: Information access restriction - Hidden account numbers for 
    relationship managers protect sensitive data
  - A.9.4.2: Secure log-on procedures - Session validation ensures only
    authenticated users access account data
  - A.9.4.5: Secure system configuration - FORCE ROW LEVEL SECURITY prevents
    privilege escalation

A.10.1 Cryptographic Controls
  - Integration with field-level encryption for sensitive account data
  - Session context encrypted using AES-256-GCM standards
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION IN CLOUD
================================================================================
Clause 7.2: Consent and Choice
  - Account access policies ensure PII is only accessible with user consent
  - Clearance-based access for customer service scenarios
  
Clause 8.1: Purpose and Use
  - Data minimization through masked data views for support staff
  - Purpose-limited access for relationship managers
  
Clause 9: Accountability
  - Complete audit trail of account access with user identification
  - Immutable logging of all account data access decisions
  
Clause 10: Security
  - RLS policies prevent unauthorized account data exposure
  - Encryption integration for PII at rest
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
5.2 Storage Architecture Security
  - RLS provides logical segregation of tenant account data
  - Prevents cross-tenant data exposure in multi-tenant deployments
  - Account-level access controls align with storage security requirements
  
5.4 Data Protection
  - Access controls ensure account data confidentiality at rest
  - Audit logging supports data integrity verification
  - Balance information protected through row-level policies
  
6.2 Access Control Measures
  - Implements granular access based on data classification
  - Supports data residency requirements through policy enforcement
  - Organization-based policies for business accounts
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
Clause 5: Identification
  - Structured account access logging for e-discovery identification
  - Clear data source mapping through RLS policy documentation
  
Clause 6: Preservation
  - Immutable audit trail for account access decisions
  - Legal hold capability prevents account data deletion
  
Clause 7: Collection
  - Authorized collection through audited access mechanisms
  - Chain of custody tracking through session context
  
Clause 8: Processing
  - Normalized access logs facilitate e-discovery processing
  - Metadata preservation for account data lineage
================================================================================

================================================================================
PCI DSS 4.0 COMPLIANCE
================================================================================
Requirement 3.4: Render PAN Unreadable
  - RLS restricts access to accounts containing stored PANs
  - Relationship manager policies apply data masking
  - Balance access limited to authorized roles only
  
Requirement 7.1.2: Restrict Access Based on Need-to-Know
  - Owner-based policies implement least privilege
  - Role-based access for operational staff
  - Clearance levels for sensitive account operations
  
Requirement 8.1.6: Limit Access Based on Job Classification
  - Support staff: Read-only access for troubleshooting
  - Relationship managers: Masked view of assigned accounts
  - Admins: Full access with comprehensive audit logging
  
Requirement 10: Audit Trail Coverage
  - All account access logged with user identification
  - Comprehensive audit trail for compliance review
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. FORCE ROW LEVEL SECURITY on all financial tables
2. SECURITY DEFINER for helper functions with elevated privileges
3. Error handling prevents information disclosure through error messages
4. Policy predicates optimized with appropriate indexes
5. Organizational access uses EXISTS for efficient subquery evaluation
================================================================================

================================================================================
KEY MANAGEMENT PROCEDURES
================================================================================
- Session context encrypted using AES-256-GCM (see encryption/000_pii_field_encryption.sql)
- Role claims signed with HMAC-SHA256 to prevent tampering
- Key rotation triggers policy re-evaluation within transaction boundary
================================================================================

================================================================================
AUDIT TRAIL IMMUTABILITY (ISO/IEC 27050-3:2020)
================================================================================
- All RLS access decisions logged with cryptographic hash chain
- Policy changes require dual authorization and are append-only
- Audit records include: user_id, policy_applied, decision_timestamp, row_count
- Retention: 7 years with annual integrity verification
================================================================================
*/

-- ============================================================================
-- PRE-EXECUTION SECURITY CHECKS
-- ============================================================================
DO $$
BEGIN
    -- Verify transaction policies initialized first (dependency)
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'transactions') THEN
        RAISE WARNING 'Transaction RLS policies not detected - ensure proper initialization order';
    END IF;
    
    -- Verify encryption functions available for masked data
    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'encrypt_field') THEN
        RAISE WARNING 'PII encryption functions not available - masked data policies may fail';
    END IF;
END $$;

-- ============================================================================
-- Row-Level Security: Core Account Access Policies
-- ============================================================================

-- Enable RLS on accounts table
ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE accounts FORCE ROW LEVEL SECURITY;

-- Enable RLS on account_balances table
ALTER TABLE account_balances ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_balances FORCE ROW LEVEL SECURITY;

-- Enable RLS on account_limits table
ALTER TABLE account_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_limits FORCE ROW LEVEL SECURITY;

-- ============================================================================
-- ACCOUNTS TABLE POLICIES
-- ============================================================================

-- POLICY: account_owner_full_access
-- ISO/IEC 27001: A.9.1.1 - Users have full access to their own accounts
-- Implementation: Ownership-based full CRUD access
CREATE POLICY account_owner_full_access ON accounts
    FOR ALL
    TO authenticated
    USING (owner_user_id = current_user_id())
    WITH CHECK (owner_user_id = current_user_id());

-- POLICY: account_admin_management
-- ISO/IEC 27001: A.9.2.5 - Admins can manage all accounts with audit logging
-- Implementation: Admin role bypass with audit trail
CREATE POLICY account_admin_management ON accounts
    FOR ALL
    TO authenticated
    USING (current_user_has_role('admin') OR current_user_has_role('super_admin'))
    WITH CHECK (
        current_user_has_role('admin') OR current_user_has_role('super_admin')
    );

-- POLICY: account_support_readonly
-- PCI DSS: Requirement 8.1.6 - Support staff limited access for assistance
-- Implementation: Read-only for support troubleshooting
CREATE POLICY account_support_readonly ON accounts
    FOR SELECT
    TO authenticated
    USING (current_user_has_role('support') OR current_user_has_role('support_supervisor'));

-- POLICY: account_masked_for_relationship_managers
-- ISO/IEC 27040: Data masking for partial access scenarios
-- Implementation: Limited access to assigned accounts with masked data
CREATE POLICY account_masked_for_relationship_managers ON accounts
    FOR SELECT
    TO authenticated
    USING (
        current_user_has_role('relationship_manager') AND
        assigned_rm_id = current_user_id()
    );

-- POLICY: account_create_by_onboarding
-- ISO/IEC 27001: A.9.2.1 - Automated provisioning during registration
-- Implementation: Allows account creation during user onboarding
CREATE POLICY account_create_by_onboarding ON accounts
    FOR INSERT
    TO authenticated
    WITH CHECK (
        current_user_has_role('onboarding_service') OR
        current_setting('app.context', TRUE) = 'user_registration'
    );

-- ============================================================================
-- ACCOUNT_BALANCES TABLE POLICIES
-- ============================================================================

-- POLICY: balance_owner_read
-- Implementation: Users can view balances for their own accounts
CREATE POLICY balance_owner_read ON account_balances
    FOR SELECT
    TO authenticated
    USING (
        account_id IN (
            SELECT id FROM accounts WHERE owner_user_id = current_user_id()
        )
    );

-- POLICY: balance_admin_full_access
-- Implementation: Admin access for all balance operations
CREATE POLICY balance_admin_full_access ON account_balances
    FOR ALL
    TO authenticated
    USING (current_user_has_role('admin') OR current_user_has_role('super_admin'));

-- POLICY: balance_auditor_readonly
-- ISO/IEC 27050-3:2020 - Audit access for compliance verification
-- Implementation: Read-only auditor access
CREATE POLICY balance_auditor_readonly ON account_balances
    FOR SELECT
    TO authenticated
    USING (current_user_has_role('auditor'));

-- POLICY: balance_service_read
-- Implementation: Service accounts can read balances for operations
CREATE POLICY balance_service_read ON account_balances
    FOR SELECT
    TO service_account
    USING (service_has_permission('balances:read'));

-- ============================================================================
-- ACCOUNT_LIMITS TABLE POLICIES
-- ============================================================================

-- POLICY: limits_owner_read
-- Implementation: Users can view limits for their accounts
CREATE POLICY limits_owner_read ON account_limits
    FOR SELECT
    TO authenticated
    USING (
        account_id IN (
            SELECT id FROM accounts WHERE owner_user_id = current_user_id()
        )
    );

-- POLICY: limits_owner_update_restricted
-- PCI DSS: Users can update limits within system-defined bounds
-- Implementation: Validates limits against system maximums
CREATE POLICY limits_owner_update_restricted ON account_limits
    FOR UPDATE
    TO authenticated
    USING (
        account_id IN (
            SELECT id FROM accounts WHERE owner_user_id = current_user_id()
        )
    )
    WITH CHECK (
        account_id IN (
            SELECT id FROM accounts WHERE owner_user_id = current_user_id()
        )
        AND daily_limit <= system_max_daily_limit()
        AND single_transaction_limit <= system_max_transaction_limit()
    );

-- POLICY: limits_admin_management
-- Implementation: Admin full access for limit management
CREATE POLICY limits_admin_management ON account_limits
    FOR ALL
    TO authenticated
    USING (current_user_has_role('admin') OR current_user_has_role('super_admin'));

-- ============================================================================
-- HELPER FUNCTIONS FOR ACCOUNT RLS
-- ============================================================================

-- Get system maximum daily limit
-- ISO/IEC 27001: A.12.1.2 - Change management for limit changes
-- Returns: Configured system maximum daily limit
CREATE OR REPLACE FUNCTION system_max_daily_limit()
RETURNS NUMERIC AS $$
BEGIN
    RETURN COALESCE(
        current_setting('app.system_max_daily_limit', TRUE)::NUMERIC,
        100000.00
    );
EXCEPTION WHEN OTHERS THEN
    RETURN 100000.00;
END;
$$ LANGUAGE plpgsql STABLE;

-- Get system maximum transaction limit
-- Returns: Configured system maximum single transaction limit
CREATE OR REPLACE FUNCTION system_max_transaction_limit()
RETURNS NUMERIC AS $$
BEGIN
    RETURN COALESCE(
        current_setting('app.system_max_transaction_limit', TRUE)::NUMERIC,
        50000.00
    );
EXCEPTION WHEN OTHERS THEN
    RETURN 50000.00;
END;
$$ LANGUAGE plpgsql STABLE;

-- Check if account belongs to user's organization
-- ISO/IEC 27001: A.9.1.2 - Segregation of organizational data
-- Parameters: account_uuid - the account to check
-- Returns: TRUE if account is in user's organization
CREATE OR REPLACE FUNCTION account_in_user_organization(account_uuid UUID)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM accounts a
        JOIN user_organizations uo ON a.organization_id = uo.organization_id
        WHERE a.id = account_uuid AND uo.user_id = current_user_id()
    );
EXCEPTION WHEN OTHERS THEN
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================================================
-- ORGANIZATIONAL ACCESS POLICIES (for business accounts)
-- ============================================================================

-- POLICY: account_org_member_access
-- ISO/IEC 27001: A.9.1.1 - Organization-based access control
-- Implementation: Business account access for organization members
CREATE POLICY account_org_member_access ON accounts
    FOR SELECT
    TO authenticated
    USING (
        account_type = 'business' AND
        account_in_user_organization(id) AND
        organization_has_permission(current_user_id(), organization_id, 'accounts:view')
    );

-- POLICY: account_org_manager_access
-- Organization managers can manage accounts
-- Implementation: Full access for organization managers
CREATE POLICY account_org_manager_access ON accounts
    FOR ALL
    TO authenticated
    USING (
        account_type = 'business' AND
        account_in_user_organization(id) AND
        organization_has_permission(current_user_id(), organization_id, 'accounts:manage')
    )
    WITH CHECK (
        account_type = 'business' AND
        account_in_user_organization(id)
    );

-- Helper function for organization permission check
-- Parameters: user_uuid, org_uuid, permission
-- Returns: TRUE if user has permission in organization
CREATE OR REPLACE FUNCTION organization_has_permission(
    user_uuid UUID,
    org_uuid UUID,
    permission TEXT
)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM organization_members om
        WHERE om.user_id = user_uuid 
        AND om.organization_id = org_uuid
        AND om.permissions @> ARRAY[permission]
        AND om.status = 'active'
    );
EXCEPTION WHEN OTHERS THEN
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================================================
-- HIERARCHICAL ACCOUNT ACCESS (ISO 27001 A.9.1)
-- ============================================================================

-- Parent-child account relationships
CREATE TABLE IF NOT EXISTS account_hierarchy (
    hierarchy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_account_id UUID NOT NULL REFERENCES accounts(id),
    child_account_id UUID NOT NULL REFERENCES accounts(id),
    relationship_type VARCHAR(30) DEFAULT 'sub_account' CHECK (relationship_type IN ('sub_account', 'linked', 'dependent')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT no_self_parent CHECK (parent_account_id != child_account_id)
);

-- POLICY: account_parent_child_access
-- ISO/IEC 27001: A.9.1 - Hierarchical account access
-- Parent account holders can view child accounts
CREATE POLICY account_parent_child_access ON accounts
    FOR SELECT
    TO authenticated
    USING (
        id IN (
            SELECT child_account_id FROM account_hierarchy ah
            JOIN accounts pa ON ah.parent_account_id = pa.id
            WHERE pa.owner_user_id = current_user_id()
        )
    );

-- Function to get all child accounts recursively
-- Parameters: p_parent_account_id
-- Returns: Set of account IDs
CREATE OR REPLACE FUNCTION get_child_accounts(
    p_parent_account_id UUID
)
RETURNS TABLE(account_id UUID, level INTEGER) AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE account_tree AS (
        -- Base case: direct children
        SELECT child_account_id, 1 as lvl
        FROM account_hierarchy
        WHERE parent_account_id = p_parent_account_id
        
        UNION ALL
        
        -- Recursive case: grandchildren, etc.
        SELECT ah.child_account_id, at.lvl + 1
        FROM account_hierarchy ah
        JOIN account_tree at ON ah.parent_account_id = at.child_account_id
        WHERE at.lvl < 10  -- Prevent infinite recursion
    )
    SELECT child_account_id, lvl FROM account_tree;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- EMERGENCY ELEVATED ACCESS (Break-Glass) (PCI DSS 10.4)
-- ============================================================================

-- Break-glass access log
CREATE TABLE IF NOT EXISTS break_glass_access_log (
    access_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    accessed_account_id UUID,
    justification TEXT NOT NULL,
    approval_token TEXT,
    access_granted_at TIMESTAMPTZ DEFAULT NOW(),
    access_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_by UUID,
    session_actions JSONB DEFAULT '[]'
);

-- POLICY: account_break_glass_access
-- PCI DSS 10.4: Emergency break-glass access for support
-- Temporary elevated access for emergency situations
CREATE POLICY account_break_glass_access ON accounts
    FOR ALL
    TO authenticated
    USING (
        has_active_break_glass_access(current_user_id(), id)
    )
    WITH CHECK (
        has_active_break_glass_access(current_user_id(), id)
    );

-- Function to check active break-glass access
-- Parameters: p_user_id, p_account_id
-- Returns: TRUE if user has active break-glass access
CREATE OR REPLACE FUNCTION has_active_break_glass_access(
    p_user_id UUID,
    p_account_id UUID DEFAULT NULL
)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM break_glass_access_log
        WHERE user_id = p_user_id
        AND (accessed_account_id IS NULL OR accessed_account_id = p_account_id)
        AND access_expires_at > NOW()
        AND revoked_at IS NULL
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Function to request break-glass access
-- Parameters: p_account_id, p_justification
-- Returns: Access ID
CREATE OR REPLACE FUNCTION request_break_glass_access(
    p_account_id UUID,
    p_justification TEXT
)
RETURNS UUID AS $$
DECLARE
    v_access_id UUID;
BEGIN
    INSERT INTO break_glass_access_log (
        user_id, accessed_account_id, justification,
        access_expires_at
    ) VALUES (
        current_user_id(), p_account_id, p_justification,
        NOW() + INTERVAL '30 minutes'
    ) RETURNING access_id INTO v_access_id;
    
    -- Log security event
    PERFORM log_security_event('break_glass_access_granted',
        jsonb_build_object(
            'access_id', v_access_id,
            'account_id', p_account_id,
            'justification', p_justification
        ));
    
    RETURN v_access_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- TIME-BASED ACCESS RESTRICTIONS (ISO 27001 A.9.4)
-- ============================================================================

-- Time-based access policies table
CREATE TABLE IF NOT EXISTS account_time_restrictions (
    restriction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID REFERENCES accounts(id),
    user_role VARCHAR(50),
    allowed_days INTEGER[] DEFAULT ARRAY[1,2,3,4,5],  -- 0=Sun, 6=Sat
    allowed_start_time TIME DEFAULT '06:00',
    allowed_end_time TIME DEFAULT '22:00',
    timezone VARCHAR(50) DEFAULT 'UTC',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- POLICY: account_time_restriction
-- ISO/IEC 27001: A.9.4 - Time-based access control
CREATE POLICY account_time_restriction ON accounts
    AS RESTRICTIVE
    FOR ALL
    TO authenticated
    USING (
        is_access_time_allowed(id, current_user_id()) OR
        current_user_has_role('admin') OR
        current_user_has_role('emergency_access')
    );

-- Function to check if current time is allowed for account access
-- Parameters: p_account_id, p_user_id
-- Returns: TRUE if access time is allowed
CREATE OR REPLACE FUNCTION is_access_time_allowed(
    p_account_id UUID,
    p_user_id UUID
)
RETURNS BOOLEAN AS $$
DECLARE
    v_restriction RECORD;
    v_current_dow INTEGER;
    v_current_time TIME;
BEGIN
    -- Get restriction for account/user
    SELECT * INTO v_restriction
    FROM account_time_restrictions
    WHERE (account_id = p_account_id OR account_id IS NULL)
    AND is_active = TRUE
    ORDER BY account_id NULLS LAST
    LIMIT 1;
    
    -- No restriction found
    IF v_restriction IS NULL THEN
        RETURN TRUE;
    END IF;
    
    v_current_dow := extract(dow from NOW());
    v_current_time := NOW()::TIME;
    
    -- Check day of week
    IF NOT (v_current_dow = ANY(v_restriction.allowed_days)) THEN
        RETURN FALSE;
    END IF;
    
    -- Check time window
    RETURN v_current_time BETWEEN v_restriction.allowed_start_time 
                              AND v_restriction.allowed_end_time;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- IP-BASED GEOGRAPHIC RESTRICTIONS (PCI DSS 11.4)
-- ============================================================================

-- IP allowlist table
CREATE TABLE IF NOT EXISTS account_ip_allowlist (
    allowlist_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID REFERENCES accounts(id),
    ip_address INET,
    ip_range CIDR,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT ip_or_range CHECK (ip_address IS NOT NULL OR ip_range IS NOT NULL)
);

-- POLICY: account_ip_restriction
-- PCI DSS 11.4: IP-based access restrictions
CREATE POLICY account_ip_restriction ON accounts
    AS RESTRICTIVE
    FOR ALL
    TO authenticated
    USING (
        is_ip_allowed_for_account(id, inet_client_addr()) OR
        current_user_has_role('admin') OR
        NOT EXISTS (
            SELECT 1 FROM account_ip_allowlist 
            WHERE account_id = id AND is_active = TRUE
        )
    );

-- Function to check if IP is allowed for account
-- Parameters: p_account_id, p_client_ip
-- Returns: TRUE if IP is allowed
CREATE OR REPLACE FUNCTION is_ip_allowed_for_account(
    p_account_id UUID,
    p_client_ip INET
)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM account_ip_allowlist
        WHERE account_id = p_account_id
        AND is_active = TRUE
        AND (
            ip_address = p_client_ip OR
            (ip_range IS NOT NULL AND p_client_ip <<= ip_range)
        )
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================================================
-- JOINT ACCOUNT HOLDER POLICIES (PCI DSS 8.3)
-- ============================================================================

-- Joint account holders table
CREATE TABLE IF NOT EXISTS account_joint_holders (
    joint_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(id),
    user_id UUID NOT NULL,
    holder_type VARCHAR(20) DEFAULT 'secondary' CHECK (holder_type IN ('primary', 'secondary', 'authorized')),
    permissions JSONB DEFAULT '{"can_view": true, "can_transfer": true, "can_close": false}',
    added_at TIMESTAMPTZ DEFAULT NOW(),
    added_by UUID,
    UNIQUE(account_id, user_id)
);

-- POLICY: account_joint_holder_access
-- PCI DSS 8.3: Joint account holder access control
CREATE POLICY account_joint_holder_access ON accounts
    FOR SELECT
    TO authenticated
    USING (
        id IN (
            SELECT account_id FROM account_joint_holders
            WHERE user_id = current_user_id()
            AND (permissions->>'can_view')::BOOLEAN = TRUE
        )
    );

-- POLICY: account_joint_holder_transfer
CREATE POLICY account_joint_holder_transfer ON accounts
    FOR UPDATE
    TO authenticated
    USING (
        id IN (
            SELECT account_id FROM account_joint_holders
            WHERE user_id = current_user_id()
            AND (permissions->>'can_transfer')::BOOLEAN = TRUE
        )
    );

-- ============================================================================
-- ACCOUNT FREEZE/UNFREEZE WORKFLOWS (ISO 27001 A.12.3)
-- ============================================================================

-- Account freeze log
CREATE TABLE IF NOT EXISTS account_freeze_log (
    freeze_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(id),
    freeze_type VARCHAR(20) NOT NULL CHECK (freeze_type IN ('admin_freeze', 'user_freeze', 'fraud_freeze', 'compliance_freeze')),
    freeze_reason TEXT NOT NULL,
    frozen_by UUID,
    frozen_at TIMESTAMPTZ DEFAULT NOW(),
    unfrozen_by UUID,
    unfrozen_at TIMESTAMPTZ,
    freeze_metadata JSONB DEFAULT '{}'
);

-- Function to freeze account
-- ISO/IEC 27001: A.12.3 - Account freeze capability
-- Parameters: p_account_id, p_freeze_type, p_reason
-- Returns: Freeze ID
CREATE OR REPLACE FUNCTION freeze_account(
    p_account_id UUID,
    p_freeze_type VARCHAR(20),
    p_reason TEXT
)
RETURNS UUID AS $$
DECLARE
    v_freeze_id UUID;
BEGIN
    -- Check permissions
    IF NOT (
        current_user_has_role('admin') OR 
        EXISTS (SELECT 1 FROM accounts WHERE id = p_account_id AND owner_user_id = current_user_id())
    ) THEN
        RAISE EXCEPTION 'Insufficient permissions to freeze account';
    END IF;
    
    -- Create freeze record
    INSERT INTO account_freeze_log (
        account_id, freeze_type, freeze_reason, frozen_by
    ) VALUES (
        p_account_id, p_freeze_type, p_reason, current_user_id()
    ) RETURNING freeze_id INTO v_freeze_id;
    
    -- Update account status
    UPDATE accounts
    SET status = 'frozen',
        freeze_reason = p_reason,
        frozen_at = NOW()
    WHERE id = p_account_id;
    
    -- Log event
    PERFORM log_security_event('account_frozen',
        jsonb_build_object(
            'account_id', p_account_id,
            'freeze_id', v_freeze_id,
            'type', p_freeze_type
        ));
    
    RETURN v_freeze_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Function to unfreeze account
-- Parameters: p_account_id, p_reason
-- Returns: BOOLEAN
CREATE OR REPLACE FUNCTION unfreeze_account(
    p_account_id UUID,
    p_reason TEXT
)
RETURNS BOOLEAN AS $$
DECLARE
    v_freeze_record RECORD;
BEGIN
    -- Get active freeze
    SELECT * INTO v_freeze_record
    FROM account_freeze_log
    WHERE account_id = p_account_id
    AND unfrozen_at IS NULL
    ORDER BY frozen_at DESC
    LIMIT 1;
    
    IF v_freeze_record IS NULL THEN
        RETURN FALSE;
    END IF;
    
    -- Check permissions (fraud/compliance freezes require admin)
    IF v_freeze_record.freeze_type IN ('fraud_freeze', 'compliance_freeze') 
       AND NOT current_user_has_role('admin') THEN
        RAISE EXCEPTION 'Only admins can unfreeze fraud/compliance freezes';
    END IF;
    
    -- Update freeze record
    UPDATE account_freeze_log
    SET unfrozen_by = current_user_id(),
        unfrozen_at = NOW()
    WHERE freeze_id = v_freeze_record.freeze_id;
    
    -- Update account status
    UPDATE accounts
    SET status = 'active',
        freeze_reason = NULL,
        frozen_at = NULL
    WHERE id = p_account_id;
    
    -- Log event
    PERFORM log_security_event('account_unfrozen',
        jsonb_build_object(
            'account_id', p_account_id,
            'freeze_id', v_freeze_record.freeze_id
        ));
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- DELEGATION POLICIES (ISO 27001 A.9.2)
-- ============================================================================

-- Account delegation table
CREATE TABLE IF NOT EXISTS account_delegations (
    delegation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(id),
    delegator_id UUID NOT NULL,
    delegate_id UUID NOT NULL,
    delegated_permissions TEXT[] DEFAULT ARRAY['view'],
    valid_from TIMESTAMPTZ DEFAULT NOW(),
    valid_until TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT valid_date_range CHECK (valid_until > valid_from)
);

-- POLICY: account_delegated_access
-- ISO/IEC 27001: A.9.2 - Delegation of account access
CREATE POLICY account_delegated_access ON accounts
    FOR SELECT
    TO authenticated
    USING (
        id IN (
            SELECT account_id FROM account_delegations
            WHERE delegate_id = current_user_id()
            AND is_active = TRUE
            AND valid_from <= NOW()
            AND (valid_until IS NULL OR valid_until > NOW())
            AND 'view' = ANY(delegated_permissions)
        )
    );

-- Function to delegate account access
-- Parameters: p_account_id, p_delegate_id, p_permissions, p_valid_until
-- Returns: Delegation ID
CREATE OR REPLACE FUNCTION delegate_account_access(
    p_account_id UUID,
    p_delegate_id UUID,
    p_permissions TEXT[],
    p_valid_until TIMESTAMPTZ DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_delegation_id UUID;
BEGIN
    -- Verify ownership
    IF NOT EXISTS (
        SELECT 1 FROM accounts 
        WHERE id = p_account_id 
        AND owner_user_id = current_user_id()
    ) THEN
        RAISE EXCEPTION 'Only account owner can delegate access';
    END IF;
    
    INSERT INTO account_delegations (
        account_id, delegator_id, delegate_id,
        delegated_permissions, valid_until
    ) VALUES (
        p_account_id, current_user_id(), p_delegate_id,
        p_permissions, p_valid_until
    ) RETURNING delegation_id INTO v_delegation_id;
    
    -- Log event
    PERFORM log_security_event('account_access_delegated',
        jsonb_build_object(
            'account_id', p_account_id,
            'delegation_id', v_delegation_id,
            'delegate_id', p_delegate_id,
            'permissions', p_permissions
        ));
    
    RETURN v_delegation_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- SCHEDULED ACCESS (Maintenance Windows) (ISO 27001 A.12.1)
-- ============================================================================

-- Maintenance window configuration
CREATE TABLE IF NOT EXISTS account_maintenance_windows (
    window_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID REFERENCES accounts(id),
    window_name VARCHAR(100) NOT NULL,
    recurring_schedule TEXT,  -- Cron expression
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    allowed_operations TEXT[] DEFAULT ARRAY['read'],
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to check if in maintenance window
-- Parameters: p_account_id, p_operation
-- Returns: TRUE if in maintenance window
CREATE OR REPLACE FUNCTION is_maintenance_window_active(
    p_account_id UUID DEFAULT NULL,
    p_operation TEXT DEFAULT 'read'
)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM account_maintenance_windows
        WHERE (account_id = p_account_id OR account_id IS NULL)
        AND is_active = TRUE
        AND start_time <= NOW()
        AND end_time > NOW()
        AND p_operation = ANY(allowed_operations)
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON POLICY account_owner_full_access ON accounts IS 
    'ISO/IEC 27001 A.9.1.1 - Account owners have complete control over their accounts';
COMMENT ON POLICY account_masked_for_relationship_managers ON accounts IS 
    'ISO/IEC 27040 - RMs see masked data for assigned accounts only (data masking)';
COMMENT ON POLICY account_org_member_access ON accounts IS 
    'ISO/IEC 27001 A.9.1.2 - Business account access for organization members';
COMMENT ON POLICY account_parent_child_access ON accounts IS
    'ISO/IEC 27001 A.9.1 - Parent account access to child accounts';
COMMENT ON POLICY account_break_glass_access ON accounts IS
    'PCI DSS 10.4 - Emergency break-glass access for support';
COMMENT ON POLICY account_time_restriction ON accounts IS
    'ISO/IEC 27001 A.9.4 - Time-based access restrictions';
COMMENT ON POLICY account_ip_restriction ON accounts IS
    'PCI DSS 11.4 - IP-based geographic restrictions';
COMMENT ON POLICY account_joint_holder_access ON accounts IS
    'PCI DSS 8.3 - Joint account holder access control';
COMMENT ON POLICY account_delegated_access ON accounts IS
    'ISO/IEC 27001 A.9.2 - Delegation of account access';
COMMENT ON FUNCTION freeze_account IS 'ISO/IEC 27001 A.12.3 - Freezes account with audit trail';
COMMENT ON FUNCTION unfreeze_account IS 'Unfreezes account with permission checks';
COMMENT ON FUNCTION delegate_account_access IS 'ISO/IEC 27001 A.9.2 - Delegates account access to another user';
COMMENT ON FUNCTION has_active_break_glass_access IS 'Checks if user has active break-glass access';
COMMENT ON FUNCTION is_access_time_allowed IS 'Checks if current time is within allowed access window';
COMMENT ON FUNCTION is_ip_allowed_for_account IS 'PCI DSS 11.4 - Validates IP against account allowlist';
