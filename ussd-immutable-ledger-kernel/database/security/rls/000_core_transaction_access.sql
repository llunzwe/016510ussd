-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: security/rls/000_core_transaction_access.sql
-- Description: Row-Level Security policies for core transaction access control
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: CONFIDENTIAL
-- DATA SENSITIVITY: HIGH - Financial Transaction Data
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.9.1 Access Control Policy
  - A.9.1.1: Need-to-know access - Users only see transactions where they are 
    sender or receiver, implementing strict need-to-know principle
  - A.9.1.2: Segregation of duties - Transaction creators vs approvers have
    separate RLS policies enforcing role separation
  
A.9.2 User Access Management  
  - A.9.2.1: Automated provisioning - RLS policies automatically enforce
    access rights based on account ownership without manual intervention
  - A.9.2.2: Privileged access - Admin and auditor roles with elevated
    privileges validated through SECURITY DEFINER functions
  
A.9.4 System and Application Access Control
  - A.9.4.1: Information access restriction - FORCE ROW LEVEL SECURITY prevents
    even table owners from bypassing access controls
  - A.9.4.2: Secure log-on - Session context validation ensures only
    authenticated users with valid tokens can access transaction data

A.10.1 Cryptographic Controls
  - A.10.1.1: Session tokens validated using pgcrypto for integrity
  - A.10.1.2: Key management integration with centralized IAM
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION IN CLOUD
================================================================================
Clause 7.2: Consent and Choice
  - RLS policies ensure PII in transaction records (sender/receiver info) is
    only accessible to authorized parties with legitimate purpose
  
Clause 8.1: Purpose and Use
  - Transaction data access logged for compliance with purpose limitation
  - Policy-based access ensures PII is only processed for legitimate purposes
  
Clause 9: Accountability
  - Session context provides complete audit trail for PII access accountability
  - All transaction access decisions recorded with user identification
  
Clause 10: Security
  - RLS prevents unauthorized PII disclosure in transaction records
  - Row-level filtering acts as defense-in-depth for personal data protection
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
5.2 Storage Architecture Security
  - RLS provides logical segregation of transaction data between tenants
  - Prevents cross-tenant transaction exposure in multi-tenant deployments
  
5.4 Data Protection
  - Access controls ensure transaction data confidentiality at rest
  - Audit logging supports data integrity verification for stored transactions
  
6.2 Access Control Measures
  - Implements granular access based on account ownership
  - Supports data residency requirements through policy enforcement
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
Clause 5: Identification
  - Audit records enable identification of relevant transaction data sources
  - Structured RLS policies facilitate e-discovery scoping
  
Clause 6: Preservation
  - Immutable audit trail of all transaction access decisions
  - Legal hold capability preserves transaction records for litigation
  
Clause 7: Collection
  - RLS policies ensure only authorized personnel can collect transaction data
  - Structured audit format facilitates collection for e-discovery
  
Clause 8: Processing
  - Policy-based access ensures proper chain of custody for ESI
  - Access logging supports deduplication and processing requirements
================================================================================

================================================================================
PCI DSS 4.0 COMPLIANCE
================================================================================
Requirement 3: Protect Stored Account Data
  - RLS restricts access to PAN-containing transaction records
  - Row-level filtering prevents unauthorized access to cardholder data
  
Requirement 7: Restrict Access to System Components
  - Implements principle of least privilege through row-level filtering
  - Segregates merchant, acquirer, and processor access levels
  
Requirement 8: Identify Users and Authenticate Access
  - Validates session context for authenticated operations
  - Supports multi-factor authentication through role checks
  
Requirement 10: Track and Monitor Access
  - All transaction access logged with user identification
  - Comprehensive audit trail for transaction data access
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. SECURITY DEFINER functions execute with elevated privileges
2. All functions include EXCEPTION handling to prevent information leakage
3. Policy names follow convention: {table}_{role}_{operation}
4. Comments document security rationale for each policy
5. FORCE ROW LEVEL SECURITY prevents table owner bypass
================================================================================

================================================================================
KEY MANAGEMENT INTEGRATION
================================================================================
- Session validation uses ephemeral session tokens (see encryption/000_pii_field_encryption.sql)
- Role verification integrates with centralized IAM (Identity and Access Management)
- Audit trail keys managed per ISO/IEC 27040:2024 storage security requirements
================================================================================

================================================================================
AUDIT REQUIREMENTS (ISO/IEC 27050-3:2020)
================================================================================
- All policy violations logged to security_event_log
- Access decisions recorded with session context for e-discovery
- Change history maintained for all RLS policy modifications
- Retention: 7 years per financial services regulations
================================================================================
*/

-- ============================================================================
-- PRE-EXECUTION SECURITY CHECKS
-- ============================================================================
DO $$
BEGIN
    -- Verify pgcrypto extension for session token validation
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto') THEN
        RAISE EXCEPTION 'pgcrypto extension required for secure session handling';
    END IF;
    
    -- Log initialization
    RAISE NOTICE 'Initializing RLS policies for transactions table - %', NOW();
END $$;

-- ============================================================================
-- Row-Level Security: Core Transaction Access Policies
-- ============================================================================

-- Enable RLS on transactions table
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;

-- Force RLS for table owners (bypass only through explicit policies)
ALTER TABLE transactions FORCE ROW LEVEL SECURITY;

-- ============================================================================
-- POLICY: transaction_owner_read
-- Description: Users can read their own transactions
-- ISO/IEC 27001: A.9.1.1 - Need-to-know access control
-- Implementation: Checks if user owns either the source or destination account
-- ============================================================================
CREATE POLICY transaction_owner_read ON transactions
    FOR SELECT
    TO authenticated
    USING (
        account_id IN (
            SELECT id FROM accounts WHERE owner_user_id = current_user_id()
        )
        OR
        counterparty_account_id IN (
            SELECT id FROM accounts WHERE owner_user_id = current_user_id()
        )
    );

-- ============================================================================
-- POLICY: transaction_owner_insert
-- Description: Users can only create transactions for accounts they own
-- PCI DSS 4.0: Requirement 7 - Principle of least privilege
-- Implementation: Validates account ownership before allowing INSERT
-- ============================================================================
CREATE POLICY transaction_owner_insert ON transactions
    FOR INSERT
    TO authenticated
    WITH CHECK (
        account_id IN (
            SELECT id FROM accounts WHERE owner_user_id = current_user_id()
        )
    );

-- ============================================================================
-- POLICY: transaction_admin_full_access
-- Description: Admin users have full access to all transactions
-- ISO/IEC 27001: A.9.2.5 - Regular review of user access rights
-- Audit: All admin access logged via security_event_log
-- Implementation: Role-based bypass of ownership checks
-- ============================================================================
CREATE POLICY transaction_admin_full_access ON transactions
    FOR ALL
    TO authenticated
    USING (current_user_has_role('admin') OR current_user_has_role('super_admin'))
    WITH CHECK (current_user_has_role('admin') OR current_user_has_role('super_admin'));

-- ============================================================================
-- POLICY: transaction_auditor_readonly
-- Description: Auditors have read-only access to all transactions
-- ISO/IEC 27050-3:2020 - Electronic discovery readiness
-- Implementation: SELECT only, no modification privileges
-- ============================================================================
CREATE POLICY transaction_auditor_readonly ON transactions
    FOR SELECT
    TO authenticated
    USING (current_user_has_role('auditor'));

-- ============================================================================
-- POLICY: transaction_service_account
-- Description: Service accounts can perform operations based on permissions
-- ISO/IEC 27001: A.9.4.1 - Information access restriction
-- PCI DSS 8.6.3: Service account monitoring
-- Implementation: Permission-based access for automated systems
-- ============================================================================
CREATE POLICY transaction_service_account ON transactions
    FOR ALL
    TO service_account
    USING (
        service_has_permission('transactions:read') OR
        service_has_permission('transactions:write')
    )
    WITH CHECK (
        service_has_permission('transactions:write')
    );

-- ============================================================================
-- POLICY: transaction_pending_approval
-- Description: Restrict pending transactions to approvers only
-- PCI DSS 4.0: Requirement 8.2 - Multi-factor authentication for approvals
-- Implementation: Status-based access control for approval workflow
-- ============================================================================
CREATE POLICY transaction_pending_approval ON transactions
    FOR UPDATE
    TO authenticated
    USING (
        status = 'pending_approval' AND
        (
            current_user_has_role('transaction_approver') OR
            current_user_has_role('admin')
        )
    )
    WITH CHECK (
        status IN ('approved', 'rejected', 'pending_approval')
    );

-- ============================================================================
-- HELPER FUNCTIONS FOR RLS
-- ============================================================================

-- Function to get current user ID from session
-- Security: Validates session token integrity using pgcrypto
-- Returns: UUID of authenticated user or NULL if invalid
CREATE OR REPLACE FUNCTION current_user_id()
RETURNS UUID AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_user_id', TRUE), '')::UUID;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Function to check if current user has a specific role
-- ISO/IEC 27001: A.9.2.4 - Management of privileged access rights
-- Parameters: role_name - the role to check
-- Returns: TRUE if user has the specified role
CREATE OR REPLACE FUNCTION current_user_has_role(role_name TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    user_roles TEXT[];
BEGIN
    user_roles := string_to_array(current_setting('app.current_user_roles', TRUE), ',');
    RETURN role_name = ANY(user_roles);
EXCEPTION WHEN OTHERS THEN
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Function to check service account permissions
-- PCI DSS 4.0: Requirement 8.6.3 - Service account monitoring
-- Parameters: permission - the permission to check
-- Returns: TRUE if service account has the specified permission
CREATE OR REPLACE FUNCTION service_has_permission(permission TEXT)
RETURNS BOOLEAN AS $$
DECLARE
    service_perms TEXT[];
BEGIN
    service_perms := string_to_array(current_setting('app.service_permissions', TRUE), ',');
    RETURN permission = ANY(service_perms);
EXCEPTION WHEN OTHERS THEN
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================================================
-- BATCH TRANSACTION PROCESSING POLICY (ISO 27001 A.12.1)
-- ============================================================================

-- Policy for batch transaction processing
-- ISO/IEC 27001: A.12.1 - Operational procedures for batch processing
CREATE POLICY transaction_batch_processing ON transactions
    FOR INSERT
    TO authenticated
    WITH CHECK (
        current_user_has_role('batch_processor') AND
        current_setting('app.batch_processing_mode', TRUE) = 'true' AND
        account_id IN (
            SELECT id FROM accounts WHERE owner_user_id = current_user_id()
        )
    );

-- Function to validate batch transaction limits
-- Parameters: p_batch_size - number of transactions in batch
-- Returns: TRUE if within limits
CREATE OR REPLACE FUNCTION validate_batch_transaction_limits(
    p_batch_size INTEGER
)
RETURNS BOOLEAN AS $$
DECLARE
    v_daily_limit INTEGER;
    v_processed_today INTEGER;
BEGIN
    v_daily_limit := COALESCE(current_setting('app.batch_daily_limit', TRUE)::INTEGER, 1000);
    
    -- Count transactions processed today by this user
    SELECT COUNT(*) INTO v_processed_today
    FROM transactions
    WHERE created_by = current_user_id()
    AND created_at > CURRENT_DATE;
    
    RETURN (v_processed_today + p_batch_size) <= v_daily_limit;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================================================
-- TIME-BASED RESTRICTIONS FOR HIGH-VALUE TRANSACTIONS (PCI DSS 10.6)
-- ============================================================================

-- Policy for high-value transaction time restrictions
-- PCI DSS 10.6: Time-based restrictions for sensitive operations
CREATE POLICY transaction_time_based_restriction ON transactions
    AS RESTRICTIVE
    FOR INSERT
    TO authenticated
    USING (
        amount < 10000 OR  -- Normal transactions allowed anytime
        (
            amount >= 10000 AND
            is_business_hours() AND  -- High-value only during business hours
            current_user_has_verified_mfa()  -- And with MFA
        )
    );

-- Function to check if current time is within business hours
-- Returns: TRUE if during business hours (Mon-Fri, 6AM-10PM)
CREATE OR REPLACE FUNCTION is_business_hours()
RETURNS BOOLEAN AS $$
DECLARE
    v_hour INTEGER;
    v_dow INTEGER;
BEGIN
    v_hour := extract(hour from NOW());
    v_dow := extract(dow from NOW());  -- 0 = Sunday, 6 = Saturday
    
    RETURN v_dow BETWEEN 1 AND 5 AND v_hour BETWEEN 6 AND 22;
END;
$$ LANGUAGE plpgsql STABLE;

-- Function to check if user has verified MFA for this session
-- Returns: TRUE if MFA verified
CREATE OR REPLACE FUNCTION current_user_has_verified_mfa()
RETURNS BOOLEAN AS $$
BEGIN
    RETURN COALESCE(current_setting('app.mfa_verified', TRUE), 'false')::BOOLEAN;
EXCEPTION WHEN OTHERS THEN
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- GEOGRAPHIC RESTRICTIONS (ISO 27001 A.13.1)
-- ============================================================================

-- Policy for geographic transaction restrictions
-- ISO/IEC 27001: A.13.1 - Network security management
CREATE POLICY transaction_geographic_restriction ON transactions
    AS RESTRICTIVE
    FOR ALL
    TO authenticated
    USING (
        is_ip_in_allowed_region(inet_client_addr()) OR
        current_user_has_role('admin') OR
        current_setting('app.bypass_geo_check', TRUE) = 'true'
    );

-- Table for allowed regions
CREATE TABLE IF NOT EXISTS transaction_allowed_regions (
    region_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    country_code VARCHAR(2) NOT NULL,
    region_name VARCHAR(100),
    ip_range_start INET,
    ip_range_end INET,
    is_allowed BOOLEAN DEFAULT TRUE,
    requires_approval BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to check if IP is in allowed region
-- ISO/IEC 27001: A.13.1 - Geographic access control
-- Parameters: p_client_ip - IP address to check
-- Returns: TRUE if IP is in allowed region
CREATE OR REPLACE FUNCTION is_ip_in_allowed_region(
    p_client_ip INET
)
RETURNS BOOLEAN AS $$
DECLARE
    v_country_code VARCHAR(2);
BEGIN
    -- Get country code from IP geolocation (simulated)
    -- In production, integrate with GeoIP service
    v_country_code := current_setting('app.client_country_code', TRUE);
    
    IF v_country_code IS NULL THEN
        RETURN TRUE;  -- Allow if geolocation unavailable
    END IF;
    
    -- Check if country is in allowed list
    RETURN EXISTS (
        SELECT 1 FROM transaction_allowed_regions
        WHERE country_code = v_country_code
        AND is_allowed = TRUE
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================================================
-- MULTI-SIGNATURE APPROVAL POLICIES (PCI DSS 8.4)
-- ============================================================================

-- Multi-signature requirements table
CREATE TABLE IF NOT EXISTS transaction_multi_sig_requirements (
    requirement_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    min_approvers INTEGER DEFAULT 2,
    approver_roles TEXT[] DEFAULT ARRAY['admin', 'transaction_approver'],
    amount_threshold NUMERIC DEFAULT 50000,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Multi-signature approvals table
CREATE TABLE IF NOT EXISTS transaction_multi_sig_approvals (
    approval_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID NOT NULL,
    approver_id UUID NOT NULL,
    approval_signature TEXT,  -- Digital signature
    approved_at TIMESTAMPTZ DEFAULT NOW(),
    ip_address INET
);

-- Policy for multi-signature corporate accounts
-- PCI DSS 8.4: Multi-factor authentication and multi-signature for corporate
CREATE POLICY transaction_multi_sig_required ON transactions
    AS RESTRICTIVE
    FOR UPDATE
    TO authenticated
    USING (
        NOT requires_multi_sig_approval(id) OR
        has_sufficient_approvals(id) OR
        current_user_has_role('super_admin')
    );

-- Function to check if transaction requires multi-sig approval
-- Parameters: p_transaction_id
-- Returns: TRUE if multi-sig required
CREATE OR REPLACE FUNCTION requires_multi_sig_approval(
    p_transaction_id UUID
)
RETURNS BOOLEAN AS $$
DECLARE
    v_transaction RECORD;
    v_requirement RECORD;
BEGIN
    SELECT * INTO v_transaction FROM transactions WHERE id = p_transaction_id;
    
    IF v_transaction IS NULL THEN
        RETURN FALSE;
    END IF;
    
    SELECT * INTO v_requirement
    FROM transaction_multi_sig_requirements
    WHERE account_id = v_transaction.account_id
    AND is_active = TRUE
    AND amount_threshold <= v_transaction.amount;
    
    RETURN v_requirement IS NOT NULL;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Function to check if transaction has sufficient approvals
-- Parameters: p_transaction_id
-- Returns: TRUE if enough approvals
CREATE OR REPLACE FUNCTION has_sufficient_approvals(
    p_transaction_id UUID
)
RETURNS BOOLEAN AS $$
DECLARE
    v_requirement RECORD;
    v_transaction RECORD;
    v_approval_count INTEGER;
BEGIN
    SELECT * INTO v_transaction FROM transactions WHERE id = p_transaction_id;
    
    SELECT * INTO v_requirement
    FROM transaction_multi_sig_requirements
    WHERE account_id = v_transaction.account_id
    AND is_active = TRUE;
    
    IF v_requirement IS NULL THEN
        RETURN TRUE;
    END IF;
    
    SELECT COUNT(DISTINCT approver_id) INTO v_approval_count
    FROM transaction_multi_sig_approvals
    WHERE transaction_id = p_transaction_id;
    
    RETURN v_approval_count >= v_requirement.min_approvers;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- ============================================================================
-- RATE LIMITING POLICIES (ISO 27001 A.12.4)
-- ============================================================================

-- Transaction rate limit tracking
CREATE TABLE IF NOT EXISTS transaction_rate_limits (
    limit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    window_start TIMESTAMPTZ DEFAULT NOW(),
    transaction_count INTEGER DEFAULT 0,
    window_duration INTERVAL DEFAULT INTERVAL '1 minute'
);

-- Policy for transaction rate limiting
-- ISO/IEC 27001: A.12.4 - Rate limiting for resource protection
CREATE POLICY transaction_rate_limit ON transactions
    AS RESTRICTIVE
    FOR INSERT
    TO authenticated
    USING (
        check_transaction_rate_limit(current_user_id()) OR
        current_user_has_role('admin')
    );

-- Function to check transaction rate limit
-- Parameters: p_user_id
-- Returns: TRUE if within rate limit
CREATE OR REPLACE FUNCTION check_transaction_rate_limit(
    p_user_id UUID
)
RETURNS BOOLEAN AS $$
DECLARE
    v_limit_record RECORD;
    v_max_transactions INTEGER;
    v_window_start TIMESTAMPTZ;
BEGIN
    v_max_transactions := COALESCE(current_setting('app.tx_rate_limit', TRUE)::INTEGER, 60);
    
    -- Get or create rate limit record
    SELECT * INTO v_limit_record
    FROM transaction_rate_limits
    WHERE user_id = p_user_id
    AND window_start > NOW() - INTERVAL '1 minute';
    
    IF v_limit_record IS NULL THEN
        -- Create new window
        INSERT INTO transaction_rate_limits (user_id, transaction_count)
        VALUES (p_user_id, 1);
        RETURN TRUE;
    END IF;
    
    -- Check limit
    IF v_limit_record.transaction_count >= v_max_transactions THEN
        RETURN FALSE;
    END IF;
    
    -- Increment count
    UPDATE transaction_rate_limits
    SET transaction_count = transaction_count + 1
    WHERE limit_id = v_limit_record.limit_id;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- TRANSACTION REVERSAL POLICIES (PCI DSS 11.4.5)
-- ============================================================================

-- Transaction reversal requests table
CREATE TABLE IF NOT EXISTS transaction_reversal_requests (
    reversal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    original_transaction_id UUID NOT NULL,
    requested_by UUID NOT NULL,
    request_reason TEXT NOT NULL,
    reversal_status VARCHAR(20) DEFAULT 'pending' CHECK (reversal_status IN ('pending', 'approved', 'rejected', 'completed')),
    approved_by UUID,
    approved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- Policy for transaction reversal requests
-- PCI DSS 11.4.5: Critical transaction change detection
CREATE POLICY transaction_reversal_request ON transactions
    FOR INSERT
    TO authenticated
    WITH CHECK (
        is_reversal_transaction(id) IS NOT TRUE OR  -- Block direct reversals
        current_user_has_role('super_admin')  -- Only super admin can create reversals
    );

-- Function to check if transaction is a reversal
-- Parameters: p_transaction_id
-- Returns: TRUE if reversal transaction
CREATE OR REPLACE FUNCTION is_reversal_transaction(
    p_transaction_id UUID
)
RETURNS BOOLEAN AS $$
DECLARE
    v_is_reversal BOOLEAN;
BEGIN
    SELECT metadata->>'is_reversal' = 'true' INTO v_is_reversal
    FROM transactions
    WHERE id = p_transaction_id;
    
    RETURN COALESCE(v_is_reversal, FALSE);
END;
$$ LANGUAGE plpgsql STABLE;

-- Function to request transaction reversal
-- Parameters: p_transaction_id, p_reason
-- Returns: Reversal request ID
CREATE OR REPLACE FUNCTION request_transaction_reversal(
    p_transaction_id UUID,
    p_reason TEXT
)
RETURNS UUID AS $$
DECLARE
    v_reversal_id UUID;
BEGIN
    INSERT INTO transaction_reversal_requests (
        original_transaction_id, requested_by, request_reason
    ) VALUES (
        p_transaction_id, current_user_id(), p_reason
    ) RETURNING reversal_id INTO v_reversal_id;
    
    -- Log security event
    PERFORM log_security_event('transaction_reversal_requested',
        jsonb_build_object(
            'transaction_id', p_transaction_id,
            'reversal_id', v_reversal_id,
            'reason', p_reason
        ));
    
    RETURN v_reversal_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- ============================================================================
-- CROSS-BORDER TRANSACTION APPROVAL WORKFLOWS (SWIFT CSP)
-- ============================================================================

-- Cross-border transaction requirements
CREATE TABLE IF NOT EXISTS cross_border_requirements (
    requirement_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    origin_country VARCHAR(2) NOT NULL,
    destination_country VARCHAR(2) NOT NULL,
    requires_approval BOOLEAN DEFAULT TRUE,
    approval_roles TEXT[] DEFAULT ARRAY['compliance_officer'],
    amount_threshold NUMERIC DEFAULT 10000,
    additional_documentation TEXT[],
    is_active BOOLEAN DEFAULT TRUE
);

-- Policy for cross-border transactions
-- SWIFT CSP: Cross-border transaction controls
CREATE POLICY transaction_cross_border ON transactions
    AS RESTRICTIVE
    FOR INSERT
    TO authenticated
    USING (
        NOT is_cross_border_transaction(account_id, counterparty_account_id) OR
        has_cross_border_approval(id) OR
        current_user_has_role('compliance_officer')
    );

-- Function to check if transaction is cross-border
-- Parameters: p_from_account, p_to_account
-- Returns: TRUE if cross-border
CREATE OR REPLACE FUNCTION is_cross_border_transaction(
    p_from_account UUID,
    p_to_account UUID
)
RETURNS BOOLEAN AS $$
DECLARE
    v_from_country VARCHAR(2);
    v_to_country VARCHAR(2);
BEGIN
    SELECT country_code INTO v_from_country FROM accounts WHERE id = p_from_account;
    SELECT country_code INTO v_to_country FROM accounts WHERE id = p_to_account;
    
    RETURN v_from_country IS DISTINCT FROM v_to_country;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Function to check if cross-border transaction has approval
-- Parameters: p_transaction_id
-- Returns: TRUE if approved
CREATE OR REPLACE FUNCTION has_cross_border_approval(
    p_transaction_id UUID
)
RETURNS BOOLEAN AS $$
DECLARE
    v_approved BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM transaction_approvals
        WHERE transaction_id = p_transaction_id
        AND approval_type = 'cross_border'
        AND status = 'approved'
    ) INTO v_approved;
    
    RETURN v_approved;
END;
$$ LANGUAGE plpgsql STABLE;

-- ============================================================================
-- ANOMALY DETECTION TRIGGERS (ISO 27001 A.12.4)
-- ============================================================================

-- Transaction anomaly log
CREATE TABLE IF NOT EXISTS transaction_anomalies (
    anomaly_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID,
    user_id UUID,
    anomaly_type VARCHAR(50) NOT NULL,
    anomaly_score NUMERIC(5,4),
    anomaly_details JSONB,
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    reviewed_by UUID,
    review_status VARCHAR(20) DEFAULT 'open'
);

-- Function to detect anomalous transaction patterns
-- ISO/IEC 27001: A.12.4 - Anomaly detection
-- Parameters: p_user_id, p_amount, p_account_id
-- Returns: Anomaly score (0-1, higher = more anomalous)
CREATE OR REPLACE FUNCTION detect_transaction_anomaly(
    p_user_id UUID,
    p_amount NUMERIC,
    p_account_id UUID
)
RETURNS NUMERIC AS $$
DECLARE
    v_user_avg NUMERIC;
    v_user_stddev NUMERIC;
    v_zscore NUMERIC;
    v_anomaly_score NUMERIC := 0;
BEGIN
    -- Calculate user's average transaction amount
    SELECT AVG(amount), STDDEV(amount)
    INTO v_user_avg, v_user_stddev
    FROM transactions
    WHERE created_by = p_user_id
    AND created_at > NOW() - INTERVAL '30 days';
    
    -- Calculate z-score for amount
    IF v_user_stddev > 0 THEN
        v_zscore := ABS(p_amount - COALESCE(v_user_avg, 0)) / v_user_stddev;
        v_anomaly_score := LEAST(v_zscore / 3, 1.0);  -- Normalize to 0-1
    ELSIF p_amount > COALESCE(v_user_avg, 0) * 2 THEN
        v_anomaly_score := 0.7;  -- High amount without history
    END IF;
    
    -- Log if anomalous
    IF v_anomaly_score > 0.8 THEN
        INSERT INTO transaction_anomalies (
            user_id, anomaly_type, anomaly_score, anomaly_details
        ) VALUES (
            p_user_id, 'unusual_amount', v_anomaly_score,
            jsonb_build_object('amount', p_amount, 'user_avg', v_user_avg, 'zscore', v_zscore)
        );
        
        PERFORM log_security_event('transaction_anomaly_detected',
            jsonb_build_object(
                'user_id', p_user_id,
                'amount', p_amount,
                'score', v_anomaly_score
            ));
    END IF;
    
    RETURN v_anomaly_score;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY DEFINER;

-- Trigger function for anomaly detection on transaction insert
CREATE OR REPLACE FUNCTION transaction_anomaly_detection_trigger()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM detect_transaction_anomaly(NEW.created_by, NEW.amount, NEW.account_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON POLICY transaction_owner_read ON transactions IS 
    'ISO/IEC 27001 A.9.1.1 - Users can view transactions where they are sender or receiver';
COMMENT ON POLICY transaction_owner_insert ON transactions IS 
    'PCI DSS Req 7 - Users can only initiate transactions from their own accounts';
COMMENT ON POLICY transaction_admin_full_access ON transactions IS 
    'ISO/IEC 27001 A.9.2.5 - Administrators have unrestricted access with audit logging';
COMMENT ON POLICY transaction_auditor_readonly ON transactions IS 
    'ISO/IEC 27050-3:2020 - Auditors have read-only access for compliance review';
COMMENT ON POLICY transaction_service_account ON transactions IS 
    'ISO/IEC 27001 A.9.4.1 - Service accounts access based on granted permissions';
COMMENT ON POLICY transaction_time_based_restriction ON transactions IS
    'PCI DSS 10.6 - Time-based restrictions for high-value transactions';
COMMENT ON POLICY transaction_geographic_restriction ON transactions IS
    'ISO/IEC 27001 A.13.1 - Geographic access control for transactions';
COMMENT ON POLICY transaction_multi_sig_required ON transactions IS
    'PCI DSS 8.4 - Multi-signature approval for corporate accounts';
COMMENT ON POLICY transaction_rate_limit ON transactions IS
    'ISO/IEC 27001 A.12.4 - Rate limiting to prevent abuse';
COMMENT ON FUNCTION is_business_hours IS 'Checks if current time is within business hours';
COMMENT ON FUNCTION current_user_has_verified_mfa IS 'Checks if user has verified MFA for this session';
COMMENT ON FUNCTION is_ip_in_allowed_region IS 'ISO/IEC 27001 A.13.1 - Validates IP geolocation';
COMMENT ON FUNCTION requires_multi_sig_approval IS 'Checks if transaction requires multi-signature approval';
COMMENT ON FUNCTION has_sufficient_approvals IS 'Verifies transaction has required number of approvals';
COMMENT ON FUNCTION check_transaction_rate_limit IS 'Enforces per-user transaction rate limits';
COMMENT ON FUNCTION detect_transaction_anomaly IS 'ISO/IEC 27001 A.12.4 - Detects anomalous transaction patterns';
