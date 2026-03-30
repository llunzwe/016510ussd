-- ============================================================================
-- USSD KERNEL APP SCHEMA - APPLICATION REGISTRY
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Application registry with immutable versioning, lifecycle
--              management, and enterprise multi-tenancy support.
-- Immutability: Application definitions are versioned/append-only
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. APPLICATIONS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.applications (
    -- Primary identifier
    application_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Application identification
    app_code VARCHAR(50) NOT NULL UNIQUE,  -- e.g., 'transport', 'health', 'payments'
    name VARCHAR(100) NOT NULL,
    description TEXT,
    
    -- Ownership
    owner_account_id UUID REFERENCES ussd_core.account_registry(account_id),
    owner_organization VARCHAR(255),
    technical_contact_email VARCHAR(255),
    business_contact_email VARCHAR(255),
    
    -- Classification
    category VARCHAR(50),  -- e.g., 'fintech', 'logistics', 'healthcare'
    tier VARCHAR(20) DEFAULT 'standard' CHECK (tier IN ('free', 'standard', 'premium', 'enterprise')),
    
    -- Versioning (immutable versioning of app definition)
    version INTEGER NOT NULL DEFAULT 1,
    
    -- Status lifecycle
    status ussd_app.application_status DEFAULT 'draft',
    
    -- USSD routing configuration
    ussd_short_code VARCHAR(20),  -- e.g., '*384*1#'
    ussd_menu_config JSONB DEFAULT '{}',  -- Menu tree definition
    default_language VARCHAR(5) DEFAULT 'en',
    supported_languages TEXT[] DEFAULT ARRAY['en'],
    
    -- Branding
    branding_config JSONB DEFAULT '{}',  -- Logo, colors, etc.
    
    -- Feature flags (current state)
    feature_flags JSONB DEFAULT '{}',
    
    -- Immutable versioning
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    created_by UUID,
    superseded_by UUID REFERENCES ussd_app.applications(application_id),
    valid_from TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    valid_to TIMESTAMPTZ,  -- NULL means current version
    
    -- Audit
    record_hash VARCHAR(64) NOT NULL
);

-- ----------------------------------------------------------------------------
-- 2. APPLICATION VERSIONS TABLE
-- ----------------------------------------------------------------------------
-- Detailed version history with change tracking
CREATE TABLE ussd_app.application_versions (
    version_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    application_id UUID NOT NULL,
    
    version_number INTEGER NOT NULL,
    version_name VARCHAR(100),  -- e.g., "v1.2.0 - Multi-currency support"
    changelog TEXT,
    
    -- Version-specific configuration
    config_snapshot JSONB NOT NULL,
    
    -- Status
    status VARCHAR(20) DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'deprecated', 'retired')),
    
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    published_at TIMESTAMPTZ,
    published_by UUID,
    deprecated_at TIMESTAMPTZ,
    
    -- Reference to transaction that published this version
    published_in_transaction_id BIGINT,
    
    UNIQUE(application_id, version_number)
);

-- ----------------------------------------------------------------------------
-- 3. APPLICATION LIFECYCLE STATE MACHINE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.application_lifecycle_log (
    log_id BIGSERIAL PRIMARY KEY,
    application_id UUID NOT NULL REFERENCES ussd_app.applications(application_id),
    
    from_status VARCHAR(20),
    to_status VARCHAR(20) NOT NULL,
    
    reason TEXT,
    triggered_by UUID,  -- Account that triggered the change
    
    -- For suspension: details
    suspension_reason TEXT,
    suspension_until TIMESTAMPTZ,
    
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now()
);

-- ----------------------------------------------------------------------------
-- 4. INDEXES
-- ----------------------------------------------------------------------------
CREATE UNIQUE INDEX idx_applications_active_code 
    ON ussd_app.applications(app_code) 
    WHERE valid_to IS NULL;

CREATE INDEX idx_applications_owner ON ussd_app.applications(owner_account_id);
CREATE INDEX idx_applications_status ON ussd_app.applications(status) WHERE valid_to IS NULL;
CREATE INDEX idx_applications_tier ON ussd_app.applications(tier);
CREATE INDEX idx_applications_ussd ON ussd_app.applications(ussd_short_code);

CREATE INDEX idx_app_versions_app ON ussd_app.application_versions(application_id);
CREATE INDEX idx_app_versions_status ON ussd_app.application_versions(status);

CREATE INDEX idx_lifecycle_app ON ussd_app.application_lifecycle_log(application_id);
CREATE INDEX idx_lifecycle_time ON ussd_app.application_lifecycle_log(created_at DESC);

-- ----------------------------------------------------------------------------
-- 5. IMMUTABILITY TRIGGERS
-- ----------------------------------------------------------------------------
CREATE TRIGGER trg_applications_prevent_update
    BEFORE UPDATE ON ussd_app.applications
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_update();

CREATE TRIGGER trg_applications_prevent_delete
    BEFORE DELETE ON ussd_app.applications
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_delete();

CREATE TRIGGER trg_app_versions_prevent_update
    BEFORE UPDATE ON ussd_app.application_versions
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_update();

-- ----------------------------------------------------------------------------
-- 6. HASH COMPUTATION
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd_app.compute_application_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_data TEXT;
BEGIN
    v_data := NEW.application_id::TEXT || 
              NEW.app_code || 
              NEW.version::TEXT ||
              NEW.created_at::TEXT;
    NEW.record_hash := ussd_core.generate_hash(v_data);
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_applications_compute_hash
    BEFORE INSERT ON ussd_app.applications
    FOR EACH ROW
    EXECUTE FUNCTION ussd_app.compute_application_hash();

-- ----------------------------------------------------------------------------
-- 7. LIFECYCLE MANAGEMENT FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to create new application version
CREATE OR REPLACE FUNCTION ussd_app.create_application_version(
    p_application_id UUID,
    p_new_config JSONB DEFAULT NULL,
    p_changelog TEXT DEFAULT NULL,
    p_triggered_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_old_app ussd_app.applications%ROWTYPE;
    v_new_app_id UUID;
    v_new_version INTEGER;
BEGIN
    -- Get current version
    SELECT * INTO v_old_app
    FROM ussd_app.applications
    WHERE application_id = p_application_id AND valid_to IS NULL;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Application not found or already superseded: %', p_application_id;
    END IF;
    
    v_new_version := v_old_app.version + 1;
    
    -- Close old version
    UPDATE ussd_app.applications
    SET valid_to = ussd_core.precise_now(),
        superseded_by = v_new_app_id
    WHERE application_id = p_application_id;
    
    -- Create new version
    INSERT INTO ussd_app.applications (
        app_code,
        name,
        description,
        owner_account_id,
        owner_organization,
        technical_contact_email,
        business_contact_email,
        category,
        tier,
        version,
        status,
        ussd_short_code,
        ussd_menu_config,
        default_language,
        supported_languages,
        branding_config,
        feature_flags,
        created_by,
        valid_from
    ) VALUES (
        v_old_app.app_code,
        v_old_app.name,
        v_old_app.description,
        v_old_app.owner_account_id,
        v_old_app.owner_organization,
        v_old_app.technical_contact_email,
        v_old_app.business_contact_email,
        v_old_app.category,
        v_old_app.tier,
        v_new_version,
        'draft',  -- New versions start as draft
        v_old_app.ussd_short_code,
        COALESCE(p_new_config->'ussd_menu_config', v_old_app.ussd_menu_config),
        v_old_app.default_language,
        v_old_app.supported_languages,
        v_old_app.branding_config,
        COALESCE(p_new_config->'feature_flags', v_old_app.feature_flags),
        COALESCE(p_triggered_by, v_old_app.owner_account_id),
        ussd_core.precise_now()
    )
    RETURNING application_id INTO v_new_app_id;
    
    -- Record in versions table
    INSERT INTO ussd_app.application_versions (
        application_id,
        version_number,
        changelog,
        config_snapshot,
        status,
        created_at
    ) VALUES (
        v_new_app_id,
        v_new_version,
        p_changelog,
        COALESCE(p_new_config, to_jsonb(v_old_app)),
        'draft',
        ussd_core.precise_now()
    );
    
    -- Audit log
    PERFORM ussd_audit.log_audit_event(
        'ussd_app', 'applications',
        v_new_app_id::TEXT,
        'UPDATE',
        to_jsonb(v_old_app),
        NULL,
        p_changelog
    );
    
    RETURN v_new_app_id;
END;
$$;

-- Function to change application status
CREATE OR REPLACE FUNCTION ussd_app.change_application_status(
    p_application_id UUID,
    p_new_status ussd_app.application_status,
    p_reason TEXT DEFAULT NULL,
    p_triggered_by UUID DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_old_status ussd_app.application_status;
    v_valid_transition BOOLEAN := FALSE;
BEGIN
    SELECT status INTO v_old_status
    FROM ussd_app.applications
    WHERE application_id = p_application_id AND valid_to IS NULL;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Application not found: %', p_application_id;
    END IF;
    
    -- Validate state transition
    v_valid_transition := CASE
        WHEN v_old_status = 'draft' AND p_new_status IN ('active', 'archived') THEN TRUE
        WHEN v_old_status = 'active' AND p_new_status IN ('suspended', 'deprecated', 'archived') THEN TRUE
        WHEN v_old_status = 'suspended' AND p_new_status IN ('active', 'deprecated', 'archived') THEN TRUE
        WHEN v_old_status = 'deprecated' AND p_new_status IN ('archived') THEN TRUE
        ELSE FALSE
    END;
    
    IF NOT v_valid_transition THEN
        RAISE EXCEPTION 'Invalid status transition: % to %', v_old_status, p_new_status;
    END IF;
    
    -- Update status (using security definer to bypass immutability)
    UPDATE ussd_app.applications
    SET status = p_new_status
    WHERE application_id = p_application_id;
    
    -- Log lifecycle event
    INSERT INTO ussd_app.application_lifecycle_log (
        application_id,
        from_status,
        to_status,
        reason,
        triggered_by
    ) VALUES (
        p_application_id,
        v_old_status,
        p_new_status,
        p_reason,
        p_triggered_by
    );
    
    -- Audit log
    PERFORM ussd_audit.log_audit_event(
        'ussd_app', 'applications',
        p_application_id::TEXT,
        'CONFIG_CHANGE',
        jsonb_build_object('status', v_old_status),
        jsonb_build_object('status', p_new_status),
        p_reason
    );
END;
$$;

-- Function to register new application
CREATE OR REPLACE FUNCTION ussd_app.register_application(
    p_app_code VARCHAR,
    p_name VARCHAR,
    p_owner_account_id UUID,
    p_category VARCHAR DEFAULT NULL,
    p_ussd_short_code VARCHAR DEFAULT NULL,
    p_created_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_app_id UUID;
BEGIN
    -- Check if app code exists
    IF EXISTS (SELECT 1 FROM ussd_app.applications WHERE app_code = p_app_code AND valid_to IS NULL) THEN
        RAISE EXCEPTION 'Application code already exists: %', p_app_code;
    END IF;
    
    INSERT INTO ussd_app.applications (
        app_code,
        name,
        owner_account_id,
        category,
        ussd_short_code,
        created_by,
        status,
        valid_from
    ) VALUES (
        p_app_code,
        p_name,
        p_owner_account_id,
        p_category,
        p_ussd_short_code,
        COALESCE(p_created_by, p_owner_account_id),
        'draft',
        ussd_core.precise_now()
    )
    RETURNING application_id INTO v_app_id;
    
    -- Create initial version record
    INSERT INTO ussd_app.application_versions (
        application_id,
        version_number,
        changelog,
        config_snapshot,
        status
    ) VALUES (
        v_app_id,
        1,
        'Initial application registration',
        '{}'::JSONB,
        'draft'
    );
    
    -- Audit log
    PERFORM ussd_audit.log_audit_event(
        'ussd_app', 'applications',
        v_app_id::TEXT,
        'INSERT',
        NULL,
        jsonb_build_object('app_code', p_app_code, 'name', p_name),
        'Application registered'
    );
    
    RETURN v_app_id;
END;
$$;

-- ----------------------------------------------------------------------------
-- 8. VIEWS
-- ----------------------------------------------------------------------------

-- Active applications
CREATE VIEW ussd_app.active_applications AS
SELECT *
FROM ussd_app.applications
WHERE valid_to IS NULL
  AND status IN ('active', 'draft', 'suspended');

-- Applications by owner
CREATE VIEW ussd_app.my_applications AS
SELECT *
FROM ussd_app.applications
WHERE owner_account_id = NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID
  AND valid_to IS NULL;

-- Application with current version info
CREATE VIEW ussd_app.application_details AS
SELECT 
    a.*,
    v.version_id as current_version_id,
    v.published_at as version_published_at,
    (SELECT COUNT(*) FROM ussd_app.account_memberships am 
     WHERE am.application_id = a.application_id AND am.valid_to IS NULL) as enrolled_accounts
FROM ussd_app.applications a
LEFT JOIN ussd_app.application_versions v ON a.application_id = v.application_id 
    AND v.version_number = a.version
WHERE a.valid_to IS NULL;

-- USSD routing map
CREATE VIEW ussd_app.ussd_routing_map AS
SELECT 
    ussd_short_code,
    application_id,
    app_code,
    name,
    ussd_menu_config,
    default_language,
    status
FROM ussd_app.applications
WHERE valid_to IS NULL
  AND ussd_short_code IS NOT NULL
  AND status = 'active';

-- ----------------------------------------------------------------------------
-- 9. ROW LEVEL SECURITY
-- ----------------------------------------------------------------------------
ALTER TABLE ussd_app.applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd_app.application_versions ENABLE ROW LEVEL SECURITY;

-- Application owners can see their apps
CREATE POLICY applications_owner ON ussd_app.applications
    FOR ALL USING (owner_account_id = NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID);

-- Active applications are readable by all authenticated users
CREATE POLICY applications_public ON ussd_app.applications
    FOR SELECT USING (status = 'active' AND valid_to IS NULL);

-- App versions follow application access
CREATE POLICY app_versions_owner ON ussd_app.application_versions
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM ussd_app.applications a
            WHERE a.application_id = application_versions.application_id
              AND a.owner_account_id = NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID
        )
    );

-- ----------------------------------------------------------------------------
-- 10. INITIAL APPLICATIONS
-- ----------------------------------------------------------------------------
INSERT INTO ussd_app.applications (
    application_id,
    app_code,
    name,
    description,
    owner_account_id,
    category,
    tier,
    status,
    created_by,
    record_hash
) VALUES (
    '20000000-0000-0000-0000-000000000001'::UUID,
    'kernel_admin',
    'USSD Kernel Administration',
    'System administration application for kernel management',
    '00000000-0000-0000-0000-000000000001'::UUID,
    'system',
    'enterprise',
    'active',
    '00000000-0000-0000-0000-000000000001'::UUID,
    ussd_core.generate_hash('kernel_admin')
);

-- ----------------------------------------------------------------------------
-- 11. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_app.applications IS 
    'Application registry with immutable versioning for multi-tenancy';
COMMENT ON TABLE ussd_app.application_versions IS 
    'Detailed version history with full configuration snapshots';
COMMENT ON FUNCTION ussd_app.create_application_version IS 
    'Creates new immutable version of application configuration';
