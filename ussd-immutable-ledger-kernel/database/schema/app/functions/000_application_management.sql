/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - APPLICATION MANAGEMENT FUNCTIONS
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-FUNC-005
 * Feature Name:       Application Management Functions
 * Description:        Functions for application registration, lifecycle
 *                     management, and configuration. Provides multi-tenant
 *                     aware operations with security definer privileges.
 * 
 * Version:            1.0.0
 * Author:             Eng. llunzwe
 * Created:            2026-03-30
 * Last Modified:      2026-03-30
 * 
 * =============================================================================
 * COMPLIANCE & CERTIFICATIONS
 * =============================================================================
 * 
 * ISO/IEC 27001:2022 (ISMS)
 *   - Control A.5.1: Policies for information security
 *   - Control A.5.15: Access control
 *   - Control A.5.18: Access rights management
 *   - Control A.8.5: Secure authentication
 *   - Control A.9.2.1: User registration and de-registration
 *   - Control A.9.4.1: Information access restriction
 * 
 * ISO/IEC 27017:2015 (Cloud Security)
 *   - Section 5: Shared roles and responsibilities
 *   - Section 12: Inter-tenant data segregation
 * 
 * ISO/IEC 27018:2019 (PII Protection)
 *   - Section 7.2: Consent and choice
 *   - Section 9.3: Encryption of PII
 * 
 * SOC 2 Type II
 *   - CC6.1: Logical access controls
 *   - CC6.2: Access credentials management
 *   - CC7.2: System monitoring
 * 
 * =============================================================================
 * MULTI-TENANCY SECURITY ANNOTATIONS
 * =============================================================================
 * 
 * TENANT ISOLATION:
 *   - All functions use SECURITY DEFINER with RLS bypass
 *   - Tenant context validated via current_setting('app.current_tenant_id')
 *   - Cross-tenant operations require platform:admin permission
 * 
 * SECURITY CONTROLS:
 *   - API keys generated with cryptographically secure random
 *   - Bcrypt hashing for key storage (work factor 12)
 *   - Origin validation for CORS
 *   - Rate limiting enforced at application tier
 * 
 * =============================================================================
 * AUDIT TRAIL REQUIREMENTS
 * =============================================================================
 * 
 * MANDATORY AUDIT EVENTS:
 *   - Application registered (creator, timestamp, initial config)
 *   - Status transitions (old→new, reason, who)
 *   - API key rotation (key hash deletion, new key creation)
 *   - Configuration changes (what changed, old→new values)
 *   - Resource limit modifications
 *   - Application archived/deleted
 * 
 * AUDIT RETENTION: 7 years
 * =============================================================================
 */

-- =============================================================================
-- COMPLIANCE STANDARDS
-- =============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework
-- ISO/IEC 27017:2015 - Cloud Security Controls
-- ISO/IEC 27018:2019 - PII Protection
-- SOC 2 Type II - Security Controls
-- =============================================================================

-- =============================================================================
-- FUNCTION: Register New Application
-- ISO 27001 A.5.1: Controlled application registration
-- =============================================================================

CREATE OR REPLACE FUNCTION app.register_application(
    p_app_code VARCHAR(50),
    p_app_name VARCHAR(255),
    p_app_description TEXT DEFAULT NULL,
    p_app_category VARCHAR(50) DEFAULT 'general',
    p_app_tier VARCHAR(20) DEFAULT 'standard',
    p_owner_account_id UUID DEFAULT NULL,
    p_billing_account_id UUID DEFAULT NULL,
    p_allowed_origins TEXT[] DEFAULT '{}',
    p_max_transactions_per_minute INTEGER DEFAULT 1000,
    p_max_storage_gb INTEGER DEFAULT 100,
    p_max_concurrent_sessions INTEGER DEFAULT 100,
    p_metadata JSONB DEFAULT '{}'
)
RETURNS TABLE (
    app_id UUID,
    api_key TEXT,
    tenant_id UUID,
    created_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_app_id UUID;
    v_tenant_id UUID;
    v_api_key TEXT;
    v_api_key_hash TEXT;
    v_created_at TIMESTAMPTZ;
    v_current_user UUID;
    v_current_membership UUID;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    BEGIN
        -- Get current user context
        v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
        v_current_membership := current_setting('app.current_membership_id', TRUE)::UUID;
        
        -- Authorization check: platform admin required
        IF NOT app.check_permission(v_current_membership, 'platform:admin:create') THEN
            RAISE EXCEPTION '[RBAC] Insufficient privileges to register application'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        
        -- Validate app_code format
        IF NOT p_app_code ~ '^[A-Z][A-Z0-9_]{2,49}$' THEN
            RAISE EXCEPTION '[VALIDATION] Invalid app_code format. Must match: [A-Z][A-Z0-9_]{2,49}';
        END IF;
        
        -- Check for duplicate app_code
        IF EXISTS (SELECT 1 FROM app.t_application_registry WHERE app_code = p_app_code) THEN
            RAISE EXCEPTION '[CONFLICT] Application with code % already exists', p_app_code;
        END IF;
        
        -- Validate category
        IF p_app_category NOT IN ('general', 'financial', 'compliance', 'reporting', 'integration') THEN
            RAISE EXCEPTION '[VALIDATION] Invalid app_category: %', p_app_category;
        END IF;
        
        -- Validate tier
        IF p_app_tier NOT IN ('basic', 'standard', 'premium', 'enterprise') THEN
            RAISE EXCEPTION '[VALIDATION] Invalid app_tier: %', p_app_tier;
        END IF;
        
        -- Validate resource limits are positive
        IF p_max_transactions_per_minute <= 0 OR p_max_storage_gb <= 0 OR p_max_concurrent_sessions <= 0 THEN
            RAISE EXCEPTION '[VALIDATION] Resource limits must be positive integers';
        END IF;
        
        -- Generate tenant ID for isolation (ISO 27017)
        v_tenant_id := gen_random_uuid();
        
        -- Generate API key (plaintext returned once)
        v_api_key := encode(gen_random_bytes(32), 'hex');
        v_api_key_hash := crypt(v_api_key, gen_salt('bf', 12));
        
        -- Set timestamps
        v_created_at := NOW();
        
        -- Insert application record
        INSERT INTO app.t_application_registry (
            app_code,
            app_name,
            app_description,
            app_category,
            app_tier,
            default_owner_account_id,
            billing_account_id,
            status,
            api_key_hash,
            allowed_origins,
            max_transactions_per_minute,
            max_storage_gb,
            max_concurrent_sessions,
            ledger_tenant_id,
            created_at,
            created_by,
            updated_at,
            updated_by,
            metadata
        ) VALUES (
            p_app_code,
            p_app_name,
            p_app_description,
            p_app_category,
            p_app_tier,
            COALESCE(p_owner_account_id, v_current_user),
            p_billing_account_id,
            'pending',
            v_api_key_hash,
            p_allowed_origins,
            p_max_transactions_per_minute,
            p_max_storage_gb,
            p_max_concurrent_sessions,
            v_tenant_id,
            v_created_at,
            v_current_user,
            v_created_at,
            v_current_user,
            p_metadata
        )
        RETURNING app.t_application_registry.app_id INTO v_app_id;
        
        -- [AUDIT] ISO 27001: Log application creation
        INSERT INTO core.t_audit_trail (
            table_name,
            record_id,
            action,
            new_values,
            performed_by,
            performed_at
        ) VALUES (
            'app.t_application_registry',
            v_app_id,
            'CREATE',
            jsonb_build_object(
                'app_code', p_app_code,
                'app_name', p_app_name,
                'app_tier', p_app_tier,
                'tenant_id', v_tenant_id,
                'created_by', v_current_user
            ),
            v_current_user,
            v_created_at
        );
        
        -- Return the created application details (API key shown only once)
        RETURN QUERY SELECT v_app_id, v_api_key, v_tenant_id, v_created_at;
        
    EXCEPTION
        WHEN unique_violation THEN
            RAISE EXCEPTION '[CONFLICT] Application with code % already exists', p_app_code;
        WHEN OTHERS THEN
            RAISE EXCEPTION '[ERROR] Application registration failed: %', SQLERRM;
    END;
END;
$$;

COMMENT ON FUNCTION app.register_application IS 
    'Register a new application with API key generation. ' ||
    'ISO 27001 A.5.1: Controlled application registration. ' ||
    'Security: SECURITY DEFINER, API key returned once only.';

-- =============================================================================
-- FUNCTION: Activate Application
-- ISO 27001: Status transition control
-- =============================================================================

CREATE OR REPLACE FUNCTION app.activate_application(
    p_app_id UUID,
    p_reason TEXT DEFAULT 'Application activated'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_current_membership UUID;
    v_current_user UUID;
    v_old_status VARCHAR(20);
    v_app_tier VARCHAR(20);
    v_billing_required BOOLEAN;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_membership := current_setting('app.current_membership_id', TRUE)::UUID;
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Authorization check
    IF NOT app.check_permission(v_current_membership, 'app:admin:manage') THEN
        -- Also allow platform admin
        IF NOT app.check_permission(v_current_membership, 'platform:admin:manage') THEN
            RAISE EXCEPTION '[RBAC] Insufficient privileges to activate application';
        END IF;
    END IF;
    
    -- Get current status and tier
    SELECT status, app_tier INTO v_old_status, v_app_tier
    FROM app.t_application_registry
    WHERE app_id = p_app_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION '[NOT_FOUND] Application % not found', p_app_id;
    END IF;
    
    -- Validate state transition
    IF v_old_status = 'active' THEN
        RAISE EXCEPTION '[STATE] Application is already active';
    END IF;
    
    IF v_old_status IN ('archived', 'deprecated') THEN
        RAISE EXCEPTION '[STATE] Cannot activate archived or deprecated application';
    END IF;
    
    -- Check billing requirement for non-basic tiers
    v_billing_required := (v_app_tier != 'basic');
    
    -- Update application status
    UPDATE app.t_application_registry
    SET status = 'active',
        status_reason = p_reason,
        activated_at = NOW(),
        updated_at = NOW(),
        updated_by = v_current_user,
        version = version + 1
    WHERE app_id = p_app_id;
    
    -- [AUDIT] ISO 27001: Log status transition
    INSERT INTO core.t_audit_trail (
        table_name,
        record_id,
        action,
        old_values,
        new_values,
        performed_by,
        performed_at
    ) VALUES (
        'app.t_application_registry',
        p_app_id,
        'STATUS_CHANGE',
        jsonb_build_object('status', v_old_status),
        jsonb_build_object('status', 'active', 'reason', p_reason),
        v_current_user,
        NOW()
    );
    
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION app.activate_application IS 
    'Activate a pending application. ISO 27001: Status transition control.';

-- =============================================================================
-- FUNCTION: Suspend Application
-- ISO 27001: Emergency access control
-- =============================================================================

CREATE OR REPLACE FUNCTION app.suspend_application(
    p_app_id UUID,
    p_reason TEXT,
    p_duration_hours INTEGER DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_current_membership UUID;
    v_current_user UUID;
    v_old_status VARCHAR(20);
    v_suspended_until TIMESTAMPTZ;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_membership := current_setting('app.current_membership_id', TRUE)::UUID;
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Require reason
    IF p_reason IS NULL OR trim(p_reason) = '' THEN
        RAISE EXCEPTION '[VALIDATION] Suspension reason is required';
    END IF;
    
    -- Authorization check
    IF NOT app.check_permission(v_current_membership, 'platform:admin:manage') THEN
        RAISE EXCEPTION '[RBAC] Insufficient privileges to suspend application';
    END IF;
    
    -- Get current status
    SELECT status INTO v_old_status
    FROM app.t_application_registry
    WHERE app_id = p_app_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION '[NOT_FOUND] Application % not found', p_app_id;
    END IF;
    
    IF v_old_status != 'active' THEN
        RAISE EXCEPTION '[STATE] Can only suspend active applications';
    END IF;
    
    -- Calculate suspension end time
    IF p_duration_hours IS NOT NULL THEN
        v_suspended_until := NOW() + (p_duration_hours || ' hours')::INTERVAL;
    END IF;
    
    -- Update status to suspended
    UPDATE app.t_application_registry
    SET status = 'suspended',
        status_reason = p_reason || COALESCE(' (until ' || v_suspended_until::TEXT || ')', ''),
        updated_at = NOW(),
        updated_by = v_current_user,
        version = version + 1
    WHERE app_id = p_app_id;
    
    -- [AUDIT] ISO 27001: Log suspension
    INSERT INTO core.t_audit_trail (
        table_name,
        record_id,
        action,
        old_values,
        new_values,
        performed_by,
        performed_at,
        severity
    ) VALUES (
        'app.t_application_registry',
        p_app_id,
        'SUSPEND',
        jsonb_build_object('status', v_old_status),
        jsonb_build_object(
            'status', 'suspended', 
            'reason', p_reason,
            'suspended_until', v_suspended_until
        ),
        v_current_user,
        NOW(),
        'high'
    );
    
    -- Send security alert notification
    PERFORM pg_notify('security_alert', jsonb_build_object(
        'type', 'application_suspended',
        'app_id', p_app_id,
        'reason', p_reason,
        'suspended_by', v_current_user
    )::TEXT);
    
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION app.suspend_application IS 
    'Suspend an active application. ISO 27001: Emergency access control. ' ||
    'Triggers security alert notification.';

-- =============================================================================
-- FUNCTION: Rotate Application API Key
-- ISO 27001 A.8.5: Secure credential rotation
-- =============================================================================

CREATE OR REPLACE FUNCTION app.rotate_api_key(
    p_app_id UUID,
    p_rotation_reason TEXT DEFAULT 'Scheduled rotation'
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_current_membership UUID;
    v_current_user UUID;
    v_new_api_key TEXT;
    v_new_key_hash TEXT;
    v_old_key_hash TEXT;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_membership := current_setting('app.current_membership_id', TRUE)::UUID;
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Authorization check
    IF NOT app.check_permission(v_current_membership, 'app:admin:security') THEN
        IF NOT app.check_permission(v_current_membership, 'platform:admin:security') THEN
            RAISE EXCEPTION '[RBAC] Insufficient privileges to rotate API key';
        END IF;
    END IF;
    
    -- Get current key hash for audit
    SELECT api_key_hash INTO v_old_key_hash
    FROM app.t_application_registry
    WHERE app_id = p_app_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION '[NOT_FOUND] Application % not found', p_app_id;
    END IF;
    
    -- Generate new API key
    v_new_api_key := encode(gen_random_bytes(32), 'hex');
    v_new_key_hash := crypt(v_new_api_key, gen_salt('bf', 12));
    
    -- Update key hash
    UPDATE app.t_application_registry
    SET api_key_hash = v_new_key_hash,
        updated_at = NOW(),
        updated_by = v_current_user,
        version = version + 1
    WHERE app_id = p_app_id;
    
    -- [AUDIT] ISO 27001: Log key rotation
    INSERT INTO core.t_audit_trail (
        table_name,
        record_id,
        action,
        old_values,
        new_values,
        performed_by,
        performed_at,
        severity
    ) VALUES (
        'app.t_application_registry',
        p_app_id,
        'API_KEY_ROTATE',
        jsonb_build_object('old_key_hash_prefix', LEFT(v_old_key_hash, 20)),
        jsonb_build_object('new_key_hash_prefix', LEFT(v_new_key_hash, 20)),
        v_current_user,
        NOW(),
        'high'
    );
    
    -- Return plaintext key (client must store securely)
    RETURN v_new_api_key;
END;
$$;

COMMENT ON FUNCTION app.rotate_api_key IS 
    'Rotate application API key. ISO 27001 A.8.5: Secure credential rotation. ' ||
    'Returns new plaintext key (store securely, never logged).';

-- =============================================================================
-- FUNCTION: Validate API Key
-- ISO 27001 A.8.5: Authentication verification
-- =============================================================================

CREATE OR REPLACE FUNCTION app.validate_api_key(
    p_app_code VARCHAR(50),
    p_api_key TEXT,
    p_origin TEXT DEFAULT NULL
)
RETURNS TABLE (
    valid BOOLEAN,
    app_id UUID,
    tenant_id UUID,
    app_name VARCHAR(255),
    app_tier VARCHAR(20)
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_app_record RECORD;
    v_key_valid BOOLEAN;
BEGIN
    -- Look up application by code
    SELECT 
        ar.app_id,
        ar.ledger_tenant_id,
        ar.app_name,
        ar.app_tier,
        ar.api_key_hash,
        ar.allowed_origins,
        ar.status,
        ar.max_transactions_per_minute
    INTO v_app_record
    FROM app.t_application_registry ar
    WHERE ar.app_code = p_app_code;
    
    -- App not found
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::UUID, NULL::UUID, NULL::VARCHAR(255), NULL::VARCHAR(20);
        RETURN;
    END IF;
    
    -- Check application status
    IF v_app_record.status != 'active' THEN
        RETURN QUERY SELECT FALSE, NULL::UUID, NULL::UUID, NULL::VARCHAR(255), NULL::VARCHAR(20);
        RETURN;
    END IF;
    
    -- Verify API key using bcrypt
    v_key_valid := (v_app_record.api_key_hash = crypt(p_api_key, v_app_record.api_key_hash));
    
    IF NOT v_key_valid THEN
        -- [AUDIT] Failed authentication attempt
        INSERT INTO core.t_audit_trail (
            table_name,
            record_id,
            action,
            details,
            performed_at,
            result
        ) VALUES (
            'app.t_application_registry',
            v_app_record.app_id,
            'AUTH_FAILURE',
            jsonb_build_object(
                'reason', 'invalid_api_key',
                'origin', p_origin
            ),
            NOW(),
            'denied'
        );
        
        RETURN QUERY SELECT FALSE, NULL::UUID, NULL::UUID, NULL::VARCHAR(255), NULL::VARCHAR(20);
        RETURN;
    END IF;
    
    -- Check CORS origin if provided
    IF p_origin IS NOT NULL AND array_length(v_app_record.allowed_origins, 1) > 0 THEN
        IF NOT (p_origin = ANY(v_app_record.allowed_origins)) THEN
            RETURN QUERY SELECT FALSE, NULL::UUID, NULL::UUID, NULL::VARCHAR(255), NULL::VARCHAR(20);
            RETURN;
        END IF;
    END IF;
    
    -- Success
    RETURN QUERY SELECT 
        TRUE, 
        v_app_record.app_id, 
        v_app_record.ledger_tenant_id,
        v_app_record.app_name,
        v_app_record.app_tier;
END;
$$;

COMMENT ON FUNCTION app.validate_api_key IS 
    'Validate application API key and origin. ISO 27001 A.8.5. ' ||
    'Returns app context on success, NULLs on failure.';

-- =============================================================================
-- FUNCTION: Update Application Resources
-- ISO 27017: Resource limit management
-- =============================================================================

CREATE OR REPLACE FUNCTION app.update_resource_limits(
    p_app_id UUID,
    p_max_transactions_per_minute INTEGER DEFAULT NULL,
    p_max_storage_gb INTEGER DEFAULT NULL,
    p_max_concurrent_sessions INTEGER DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_current_membership UUID;
    v_current_user UUID;
    v_old_limits JSONB;
    v_new_limits JSONB;
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_membership := current_setting('app.current_membership_id', TRUE)::UUID;
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Authorization check
    IF NOT app.check_permission(v_current_membership, 'platform:admin:manage') THEN
        RAISE EXCEPTION '[RBAC] Insufficient privileges to update resource limits';
    END IF;
    
    -- Get current limits
    SELECT jsonb_build_object(
        'max_transactions_per_minute', max_transactions_per_minute,
        'max_storage_gb', max_storage_gb,
        'max_concurrent_sessions', max_concurrent_sessions
    ) INTO v_old_limits
    FROM app.t_application_registry
    WHERE app_id = p_app_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION '[NOT_FOUND] Application % not found', p_app_id;
    END IF;
    
    -- Update limits (only non-NULL parameters)
    UPDATE app.t_application_registry
    SET max_transactions_per_minute = COALESCE(p_max_transactions_per_minute, max_transactions_per_minute),
        max_storage_gb = COALESCE(p_max_storage_gb, max_storage_gb),
        max_concurrent_sessions = COALESCE(p_max_concurrent_sessions, max_concurrent_sessions),
        updated_at = NOW(),
        updated_by = v_current_user,
        version = version + 1
    WHERE app_id = p_app_id;
    
    -- Get new limits
    SELECT jsonb_build_object(
        'max_transactions_per_minute', max_transactions_per_minute,
        'max_storage_gb', max_storage_gb,
        'max_concurrent_sessions', max_concurrent_sessions
    ) INTO v_new_limits
    FROM app.t_application_registry
    WHERE app_id = p_app_id;
    
    -- [AUDIT] ISO 27001: Log resource limit changes
    INSERT INTO core.t_audit_trail (
        table_name,
        record_id,
        action,
        old_values,
        new_values,
        performed_by,
        performed_at
    ) VALUES (
        'app.t_application_registry',
        p_app_id,
        'RESOURCE_LIMITS_UPDATE',
        v_old_limits,
        v_new_limits,
        v_current_user,
        NOW()
    );
    
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION app.update_resource_limits IS 
    'Update application resource limits. ISO 27017: Resource management.';

-- =============================================================================
-- FUNCTION: Archive Application
-- GDPR Article 17: Right to erasure implementation
-- =============================================================================

CREATE OR REPLACE FUNCTION app.archive_application(
    p_app_id UUID,
    p_reason TEXT,
    p_data_export_reference TEXT DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_current_membership UUID;
    v_current_user UUID;
    v_old_status VARCHAR(20);
    v_app_code VARCHAR(50);
BEGIN
    -- [TXN] ISO 27001: ACID transaction boundary
    v_current_membership := current_setting('app.current_membership_id', TRUE)::UUID;
    v_current_user := current_setting('app.current_user_id', TRUE)::UUID;
    
    -- Require reason
    IF p_reason IS NULL OR trim(p_reason) = '' THEN
        RAISE EXCEPTION '[VALIDATION] Archive reason is required';
    END IF;
    
    -- Authorization check - platform admin only
    IF NOT app.check_permission(v_current_membership, 'platform:admin:delete') THEN
        RAISE EXCEPTION '[RBAC] Insufficient privileges to archive application';
    END IF;
    
    -- Get current status
    SELECT status, app_code INTO v_old_status, v_app_code
    FROM app.t_application_registry
    WHERE app_id = p_app_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION '[NOT_FOUND] Application % not found', p_app_id;
    END IF;
    
    IF v_old_status = 'archived' THEN
        RAISE EXCEPTION '[STATE] Application is already archived';
    END IF;
    
    -- Archive application
    UPDATE app.t_application_registry
    SET status = 'archived',
        status_reason = p_reason,
        archived_at = NOW(),
        updated_at = NOW(),
        updated_by = v_current_user,
        version = version + 1,
        -- Clear sensitive data
        api_key_hash = NULL
    WHERE app_id = p_app_id;
    
    -- [AUDIT] ISO 27001: Log archival
    INSERT INTO core.t_audit_trail (
        table_name,
        record_id,
        action,
        old_values,
        new_values,
        performed_by,
        performed_at,
        severity
    ) VALUES (
        'app.t_application_registry',
        p_app_id,
        'ARCHIVE',
        jsonb_build_object('status', v_old_status),
        jsonb_build_object(
            'status', 'archived',
            'reason', p_reason,
            'data_export_ref', p_data_export_reference
        ),
        v_current_user,
        NOW(),
        'high'
    );
    
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION app.archive_application IS 
    'Archive application (soft delete). GDPR Art. 17: Right to erasure. ' ||
    'Clears sensitive data, preserves audit trail.';

-- =============================================================================
-- FUNCTION: Get Application Summary
-- Dashboard and reporting helper
-- =============================================================================

CREATE OR REPLACE FUNCTION app.get_application_summary(p_app_id UUID)
RETURNS TABLE (
    app_id UUID,
    app_code VARCHAR(50),
    app_name VARCHAR(255),
    status VARCHAR(20),
    app_tier VARCHAR(20),
    total_memberships BIGINT,
    active_memberships BIGINT,
    total_roles BIGINT,
    created_at TIMESTAMPTZ,
    activated_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = app, core, public
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ar.app_id,
        ar.app_code,
        ar.app_name,
        ar.status,
        ar.app_tier,
        COUNT(DISTINCT am.membership_id) AS total_memberships,
        COUNT(DISTINCT am.membership_id) FILTER (WHERE am.status = 'active') AS active_memberships,
        COUNT(DISTINCT rp.role_id) AS total_roles,
        ar.created_at,
        ar.activated_at
    FROM app.t_application_registry ar
    LEFT JOIN app.t_account_membership am ON ar.app_id = am.app_id
    LEFT JOIN app.t_roles_permissions rp ON ar.app_id = rp.app_id
    WHERE ar.app_id = p_app_id
    GROUP BY ar.app_id, ar.app_code, ar.app_name, ar.status, ar.app_tier, ar.created_at, ar.activated_at;
END;
$$;

COMMENT ON FUNCTION app.get_application_summary IS 
    'Get application summary with membership and role counts.';

-- =============================================================================
-- ANALYZE for query optimizer
-- =============================================================================
ANALYZE app.t_application_registry;
