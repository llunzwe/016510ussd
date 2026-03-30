-- ============================================================================
-- USSD KERNEL APP SCHEMA - ACCOUNT MEMBERSHIPS
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Links core accounts to applications with immutable versioning
--              for enrollment history and application-specific metadata.
-- Immutability: Membership records are versioned (valid_from/valid_to)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. ACCOUNT MEMBERSHIPS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.account_memberships (
    membership_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Relationships
    account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    application_id UUID NOT NULL,
    
    -- Membership type
    membership_type VARCHAR(30) DEFAULT 'standard' CHECK (membership_type IN ('standard', 'premium', 'admin', 'readonly')),
    
    -- Application-specific identity
    app_account_id VARCHAR(100),  -- External ID in app's system
    app_account_nickname VARCHAR(100),
    
    -- Application-specific metadata
    membership_metadata JSONB DEFAULT '{}',
    
    -- Preferences
    preferences JSONB DEFAULT '{}',  -- e.g., notification preferences, language
    
    -- Status
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('pending', 'active', 'suspended', 'terminated')),
    
    -- Lifecycle
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    enrolled_by UUID,  -- Who enrolled this account
    
    -- Immutable versioning
    valid_from TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    valid_to TIMESTAMPTZ,  -- NULL = current version
    superseded_by UUID REFERENCES ussd_app.account_memberships(membership_id),
    
    -- Version tracking
    version INTEGER DEFAULT 1,
    
    -- Audit
    record_hash VARCHAR(64) NOT NULL,
    created_in_transaction_id BIGINT
);

-- ----------------------------------------------------------------------------
-- 2. MEMBERSHIP HISTORY TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.membership_history (
    history_id BIGSERIAL PRIMARY KEY,
    membership_id UUID NOT NULL,
    
    action VARCHAR(20) NOT NULL,  -- 'enrolled', 'updated', 'suspended', 'terminated', 'reinstated'
    
    -- Previous values (for updates)
    previous_metadata JSONB,
    new_metadata JSONB,
    
    -- Reason/context
    reason TEXT,
    performed_by UUID,
    
    -- Timestamp
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now()
);

-- ----------------------------------------------------------------------------
-- 3. MEMBERSHIP REQUESTS (For approval workflows)
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.membership_requests (
    request_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    application_id UUID NOT NULL,
    
    -- Request details
    request_type VARCHAR(20) DEFAULT 'enrollment' CHECK (request_type IN ('enrollment', 'upgrade', 'reinstatement')),
    requested_membership_type VARCHAR(30) DEFAULT 'standard',
    
    -- Application data provided at request time
    request_metadata JSONB DEFAULT '{}',
    
    -- Status
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    
    -- Approval tracking
    requested_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    requested_by UUID,
    reviewed_at TIMESTAMPTZ,
    reviewed_by UUID,
    rejection_reason TEXT,
    
    -- Result
    resulting_membership_id UUID REFERENCES ussd_app.account_memberships(membership_id),
    
    -- Expiration
    expires_at TIMESTAMPTZ DEFAULT (ussd_core.precise_now() + INTERVAL '7 days')
);

-- ----------------------------------------------------------------------------
-- 4. INDEXES
-- ----------------------------------------------------------------------------
CREATE UNIQUE INDEX idx_memberships_active 
    ON ussd_app.account_memberships(account_id, application_id) 
    WHERE valid_to IS NULL;

CREATE INDEX idx_memberships_account ON ussd_app.account_memberships(account_id);
CREATE INDEX idx_memberships_app ON ussd_app.account_memberships(application_id);
CREATE INDEX idx_memberships_status ON ussd_app.account_memberships(status) WHERE valid_to IS NULL;
CREATE INDEX idx_memberships_valid_range ON ussd_app.account_memberships(valid_from, valid_to);
CREATE INDEX idx_memberships_app_account ON ussd_app.account_memberships(app_account_id) WHERE app_account_id IS NOT NULL;

CREATE INDEX idx_membership_history_membership ON ussd_app.membership_history(membership_id);
CREATE INDEX idx_membership_history_time ON ussd_app.membership_history(created_at DESC);

CREATE INDEX idx_membership_requests_account ON ussd_app.membership_requests(account_id);
CREATE INDEX idx_membership_requests_app ON ussd_app.membership_requests(application_id);
CREATE INDEX idx_membership_requests_status ON ussd_app.membership_requests(status) WHERE status = 'pending';

-- ----------------------------------------------------------------------------
-- 5. IMMUTABILITY TRIGGERS
-- ----------------------------------------------------------------------------
CREATE TRIGGER trg_memberships_prevent_update
    BEFORE UPDATE ON ussd_app.account_memberships
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_update();

CREATE TRIGGER trg_memberships_prevent_delete
    BEFORE DELETE ON ussd_app.account_memberships
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_delete();

-- ----------------------------------------------------------------------------
-- 6. HASH COMPUTATION
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd_app.compute_membership_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_data TEXT;
BEGIN
    v_data := NEW.membership_id::TEXT || 
              NEW.account_id::TEXT || 
              NEW.application_id::TEXT ||
              NEW.enrolled_at::TEXT ||
              NEW.valid_from::TEXT;
    NEW.record_hash := ussd_core.generate_hash(v_data);
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_memberships_compute_hash
    BEFORE INSERT ON ussd_app.account_memberships
    FOR EACH ROW
    EXECUTE FUNCTION ussd_app.compute_membership_hash();

-- ----------------------------------------------------------------------------
-- 7. MEMBERSHIP MANAGEMENT FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to enroll account in application
CREATE OR REPLACE FUNCTION ussd_app.enroll_account(
    p_account_id UUID,
    p_application_id UUID,
    p_membership_type VARCHAR DEFAULT 'standard',
    p_metadata JSONB DEFAULT '{}',
    p_enrolled_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_membership_id UUID;
    v_app_code VARCHAR;
    v_transaction_id BIGINT;
BEGIN
    -- Check if application exists and is active
    SELECT app_code INTO v_app_code
    FROM ussd_app.applications
    WHERE application_id = p_application_id AND valid_to IS NULL;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Application not found: %', p_application_id;
    END IF;
    
    -- Check if already enrolled
    IF EXISTS (
        SELECT 1 FROM ussd_app.account_memberships
        WHERE account_id = p_account_id 
          AND application_id = p_application_id 
          AND valid_to IS NULL
    ) THEN
        RAISE EXCEPTION 'Account already enrolled in application';
    END IF;
    
    -- Get current transaction ID if in a transaction
    v_transaction_id := txid_current();
    
    INSERT INTO ussd_app.account_memberships (
        account_id,
        application_id,
        membership_type,
        membership_metadata,
        enrolled_by,
        created_in_transaction_id
    ) VALUES (
        p_account_id,
        p_application_id,
        p_membership_type,
        p_metadata,
        COALESCE(p_enrolled_by, p_account_id),
        v_transaction_id
    )
    RETURNING membership_id INTO v_membership_id;
    
    -- Log history
    INSERT INTO ussd_app.membership_history (
        membership_id,
        action,
        new_metadata,
        performed_by
    ) VALUES (
        v_membership_id,
        'enrolled',
        p_metadata,
        COALESCE(p_enrolled_by, p_account_id)
    );
    
    -- Audit log
    PERFORM ussd_audit.log_audit_event(
        'ussd_app', 'account_memberships',
        v_membership_id::TEXT,
        'INSERT',
        NULL,
        jsonb_build_object(
            'account_id', p_account_id,
            'application_id', p_application_id,
            'membership_type', p_membership_type
        ),
        'Account enrolled in application'
    );
    
    RETURN v_membership_id;
END;
$$;

-- Function to update membership (creates new version)
CREATE OR REPLACE FUNCTION ussd_app.update_membership(
    p_membership_id UUID,
    p_new_metadata JSONB DEFAULT NULL,
    p_new_type VARCHAR DEFAULT NULL,
    p_new_status VARCHAR DEFAULT NULL,
    p_reason TEXT DEFAULT NULL,
    p_updated_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_old_record ussd_app.account_memberships%ROWTYPE;
    v_new_membership_id UUID;
BEGIN
    SELECT * INTO v_old_record
    FROM ussd_app.account_memberships
    WHERE membership_id = p_membership_id AND valid_to IS NULL;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Membership not found: %', p_membership_id;
    END IF;
    
    -- Close old record
    UPDATE ussd_app.account_memberships
    SET valid_to = ussd_core.precise_now(),
        superseded_by = v_new_membership_id
    WHERE membership_id = p_membership_id;
    
    -- Create new version
    INSERT INTO ussd_app.account_memberships (
        account_id,
        application_id,
        membership_type,
        app_account_id,
        app_account_nickname,
        membership_metadata,
        preferences,
        status,
        enrolled_at,
        enrolled_by,
        version,
        valid_from
    ) VALUES (
        v_old_record.account_id,
        v_old_record.application_id,
        COALESCE(p_new_type, v_old_record.membership_type),
        v_old_record.app_account_id,
        v_old_record.app_account_nickname,
        COALESCE(p_new_metadata, v_old_record.membership_metadata),
        v_old_record.preferences,
        COALESCE(p_new_status, v_old_record.status),
        v_old_record.enrolled_at,
        v_old_record.enrolled_by,
        v_old_record.version + 1,
        ussd_core.precise_now()
    )
    RETURNING membership_id INTO v_new_membership_id;
    
    -- Log history
    INSERT INTO ussd_app.membership_history (
        membership_id,
        action,
        previous_metadata,
        new_metadata,
        reason,
        performed_by
    ) VALUES (
        v_new_membership_id,
        'updated',
        v_old_record.membership_metadata,
        COALESCE(p_new_metadata, v_old_record.membership_metadata),
        p_reason,
        COALESCE(p_updated_by, v_old_record.account_id)
    );
    
    -- Audit log
    PERFORM ussd_audit.log_audit_event(
        'ussd_app', 'account_memberships',
        v_new_membership_id::TEXT,
        'UPDATE',
        to_jsonb(v_old_record),
        NULL,
        p_reason
    );
    
    RETURN v_new_membership_id;
END;
$$;

-- Function to terminate membership
CREATE OR REPLACE FUNCTION ussd_app.terminate_membership(
    p_membership_id UUID,
    p_reason TEXT DEFAULT NULL,
    p_terminated_by UUID DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_record ussd_app.account_memberships%ROWTYPE;
BEGIN
    SELECT * INTO v_record
    FROM ussd_app.account_memberships
    WHERE membership_id = p_membership_id AND valid_to IS NULL;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Membership not found: %', p_membership_id;
    END IF;
    
    -- Update status (bypass immutability via security definer)
    UPDATE ussd_app.account_memberships
    SET status = 'terminated',
        valid_to = ussd_core.precise_now()
    WHERE membership_id = p_membership_id;
    
    -- Log history
    INSERT INTO ussd_app.membership_history (
        membership_id,
        action,
        reason,
        performed_by
    ) VALUES (
        p_membership_id,
        'terminated',
        p_reason,
        COALESCE(p_terminated_by, v_record.account_id)
    );
    
    -- Audit log
    PERFORM ussd_audit.log_audit_event(
        'ussd_app', 'account_memberships',
        p_membership_id::TEXT,
        'UPDATE',
        jsonb_build_object('status', v_record.status),
        jsonb_build_object('status', 'terminated'),
        p_reason
    );
END;
$$;

-- Function to request membership
CREATE OR REPLACE FUNCTION ussd_app.request_membership(
    p_account_id UUID,
    p_application_id UUID,
    p_request_type VARCHAR DEFAULT 'enrollment',
    p_requested_type VARCHAR DEFAULT 'standard',
    p_metadata JSONB DEFAULT '{}',
    p_requested_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_request_id UUID;
BEGIN
    INSERT INTO ussd_app.membership_requests (
        account_id,
        application_id,
        request_type,
        requested_membership_type,
        request_metadata,
        requested_by
    ) VALUES (
        p_account_id,
        p_application_id,
        p_request_type,
        p_requested_type,
        p_metadata,
        COALESCE(p_requested_by, p_account_id)
    )
    RETURNING request_id INTO v_request_id;
    
    RETURN v_request_id;
END;
$$;

-- Function to approve membership request
CREATE OR REPLACE FUNCTION ussd_app.approve_membership_request(
    p_request_id UUID,
    p_approved_by UUID,
    p_membership_type VARCHAR DEFAULT NULL  -- Override requested type
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_request ussd_app.membership_requests%ROWTYPE;
    v_membership_id UUID;
BEGIN
    SELECT * INTO v_request
    FROM ussd_app.membership_requests
    WHERE request_id = p_request_id AND status = 'pending';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Request not found or not pending: %', p_request_id;
    END IF;
    
    IF v_request.expires_at < NOW() THEN
        UPDATE ussd_app.membership_requests SET status = 'expired' WHERE request_id = p_request_id;
        RAISE EXCEPTION 'Request has expired';
    END IF;
    
    -- Create membership
    v_membership_id := ussd_app.enroll_account(
        v_request.account_id,
        v_request.application_id,
        COALESCE(p_membership_type, v_request.requested_membership_type),
        v_request.request_metadata,
        p_approved_by
    );
    
    -- Update request
    UPDATE ussd_app.membership_requests
    SET status = 'approved',
        reviewed_at = ussd_core.precise_now(),
        reviewed_by = p_approved_by,
        resulting_membership_id = v_membership_id
    WHERE request_id = p_request_id;
    
    RETURN v_membership_id;
END;
$$;

-- ----------------------------------------------------------------------------
-- 8. VIEWS
-- ----------------------------------------------------------------------------

-- Current active memberships
CREATE VIEW ussd_app.active_memberships AS
SELECT 
    am.*,
    a.app_code,
    a.name as application_name,
    ar.display_name as account_name,
    ar.primary_identifier_hash
FROM ussd_app.account_memberships am
JOIN ussd_app.applications a ON am.application_id = a.application_id
JOIN ussd_core.account_registry ar ON am.account_id = ar.account_id
WHERE am.valid_to IS NULL
  AND am.status = 'active'
  AND a.valid_to IS NULL;

-- Memberships by account (for account dashboard)
CREATE VIEW ussd_app.my_memberships AS
SELECT 
    am.*,
    a.app_code,
    a.name as application_name,
    a.ussd_short_code,
    a.status as app_status
FROM ussd_app.account_memberships am
JOIN ussd_app.applications a ON am.application_id = a.application_id
WHERE am.account_id = NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID
  AND am.valid_to IS NULL
  AND a.valid_to IS NULL;

-- Application enrollment statistics
CREATE VIEW ussd_app.enrollment_statistics AS
SELECT 
    a.application_id,
    a.app_code,
    a.name,
    COUNT(am.membership_id) FILTER (WHERE am.status = 'active' AND am.valid_to IS NULL) as active_members,
    COUNT(am.membership_id) FILTER (WHERE am.status = 'pending' AND am.valid_to IS NULL) as pending_members,
    COUNT(am.membership_id) FILTER (WHERE am.status = 'suspended' AND am.valid_to IS NULL) as suspended_members,
    COUNT(am.membership_id) as total_enrollments
FROM ussd_app.applications a
LEFT JOIN ussd_app.account_memberships am ON a.application_id = am.application_id
WHERE a.valid_to IS NULL
GROUP BY a.application_id, a.app_code, a.name;

-- Pending membership requests
CREATE VIEW ussd_app.pending_membership_requests AS
SELECT 
    mr.*,
    ar.display_name as account_name,
    a.app_code,
    a.name as application_name
FROM ussd_app.membership_requests mr
JOIN ussd_core.account_registry ar ON mr.account_id = ar.account_id
JOIN ussd_app.applications a ON mr.application_id = a.application_id
WHERE mr.status = 'pending'
  AND mr.expires_at > NOW();

-- ----------------------------------------------------------------------------
-- 9. ROW LEVEL SECURITY
-- ----------------------------------------------------------------------------
ALTER TABLE ussd_app.account_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd_app.membership_requests ENABLE ROW LEVEL SECURITY;

-- Users can see their own memberships
CREATE POLICY memberships_own ON ussd_app.account_memberships
    FOR SELECT USING (account_id = NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID);

-- App owners can see memberships in their apps
CREATE POLICY memberships_app_owner ON ussd_app.account_memberships
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM ussd_app.applications a
            WHERE a.application_id = account_memberships.application_id
              AND a.owner_account_id = NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID
        )
    );

-- Membership requests
CREATE POLICY membership_requests_own ON ussd_app.membership_requests
    FOR SELECT USING (account_id = NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID);

CREATE POLICY membership_requests_app_owner ON ussd_app.membership_requests
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM ussd_app.applications a
            WHERE a.application_id = membership_requests.application_id
              AND a.owner_account_id = NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID
        )
    );

-- ----------------------------------------------------------------------------
-- 10. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_app.account_memberships IS 
    'Links accounts to applications with immutable versioning for enrollment history';
COMMENT ON TABLE ussd_app.membership_requests IS 
    'Pending membership requests with approval workflow';
COMMENT ON FUNCTION ussd_app.enroll_account IS 
    'Enrolls an account in an application, creating initial membership record';
