-- ============================================================================
-- App Schema - Application Operations
-- ============================================================================

-- Function: Register new application
CREATE OR REPLACE FUNCTION app.register_application(
    p_application_name VARCHAR(100),
    p_description TEXT DEFAULT NULL,
    p_tier VARCHAR(16) DEFAULT 'STANDARD'
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, public
AS $$
DECLARE
    v_application_id UUID;
BEGIN
    v_application_id := gen_random_uuid();

    INSERT INTO app.application_registry (
        application_id,
        application_name,
        description,
        api_key_hash,
        status,
        tier,
        max_users,
        max_transactions_monthly,
        data_retention_days,
        encryption_required,
        mfa_required,
        ip_whitelist_enabled,
        created_at,
        created_by
    ) VALUES (
        v_application_id,
        p_application_name,
        p_description,
        encode(digest(gen_random_uuid()::text, 'sha256'), 'hex'),
        'PENDING',
        p_tier,
        CASE p_tier 
            WHEN 'BASIC' THEN 10
            WHEN 'STANDARD' THEN 100
            WHEN 'ENTERPRISE' THEN 1000
            ELSE 100
        END,
        CASE p_tier
            WHEN 'BASIC' THEN 10000
            WHEN 'STANDARD' THEN 100000
            WHEN 'ENTERPRISE' THEN 1000000
            ELSE 100000
        END,
        2555, -- 7 years default
        TRUE,
        p_tier IN ('ENTERPRISE', 'GOVERNMENT'),
        FALSE,
        now(),
        current_user
    );

    RETURN v_application_id;
END;
$$;

COMMENT ON FUNCTION app.register_application IS 'Registers a new multi-tenant application';

-- Function: Activate application
CREATE OR REPLACE FUNCTION app.activate_application(
    p_application_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, public
AS $$
BEGIN
    UPDATE app.application_registry
    SET status = 'ACTIVE',
        activated_at = now(),
        valid_from = now()
    WHERE application_id = p_application_id
    AND status = 'PENDING';

    RETURN FOUND;
END;
$$;

COMMENT ON FUNCTION app.activate_application IS 'Activates a pending application';

-- Function: Enroll account in application
CREATE OR REPLACE FUNCTION app.enroll_account(
    p_application_id UUID,
    p_account_id UUID,
    p_role_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, public
AS $$
DECLARE
    v_membership_id UUID;
BEGIN
    v_membership_id := gen_random_uuid();

    INSERT INTO app.account_membership (
        membership_id,
        account_id,
        application_id,
        role_id,
        status,
        enrolled_at,
        enrolled_by
    ) VALUES (
        v_membership_id,
        p_account_id,
        p_application_id,
        p_role_id,
        'ACTIVE',
        now(),
        current_user
    );

    RETURN v_membership_id;
END;
$$;

COMMENT ON FUNCTION app.enroll_account IS 'Enrolls an account in an application';
