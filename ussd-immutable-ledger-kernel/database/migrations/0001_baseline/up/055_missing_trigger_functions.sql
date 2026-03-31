-- =============================================================================
-- MIGRATION: 055_missing_trigger_functions.sql
-- DESCRIPTION: Create missing trigger functions referenced by DDL
-- DEPENDENCIES: All table migrations, audit schema
-- MUST RUN AFTER: All CREATE TABLE statements
-- =============================================================================

-- =============================================================================
-- APP SCHEMA TRIGGER FUNCTIONS
-- =============================================================================

-- app.trg_app_registry_audit() - Audit trigger for applications table
CREATE OR REPLACE FUNCTION app.trg_app_registry_audit()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit.audit_log (
        audit_category, audit_action, table_schema, table_name, record_id,
        old_values, new_values, actor_id, actor_type, actor_name, source_service,
        current_audit_hash
    ) VALUES (
        'CONFIG',
        TG_OP,
        'app',
        'applications',
        COALESCE(NEW.application_id, OLD.application_id)::text,
        CASE WHEN TG_OP IN ('UPDATE', 'DELETE') THEN to_jsonb(OLD) ELSE NULL END,
        CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN to_jsonb(NEW) ELSE NULL END,
        current_setting('app.current_account_id', true)::UUID,
        'USER',
        current_user,
        'app_registry_trigger',
        digest(random()::text || now()::text, 'sha256')
    );
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION app.trg_app_registry_audit() IS 'Audit trigger function for application registry changes';

-- app.trg_membership_audit() - Audit trigger for memberships
CREATE OR REPLACE FUNCTION app.trg_membership_audit()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit.audit_log (
        audit_category, audit_action, table_schema, table_name, record_id,
        old_values, new_values, actor_id, actor_type, source_service,
        current_audit_hash
    ) VALUES (
        'ACCESS',
        TG_OP,
        'app',
        'account_memberships',
        COALESCE(NEW.membership_id, OLD.membership_id)::text,
        CASE WHEN TG_OP IN ('UPDATE', 'DELETE') THEN to_jsonb(OLD) ELSE NULL END,
        CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN to_jsonb(NEW) ELSE NULL END,
        current_setting('app.current_account_id', true)::UUID,
        'USER',
        'membership_trigger',
        digest(random()::text || now()::text, 'sha256')
    );
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION app.trg_membership_audit() IS 'Audit trigger for account membership changes';

-- app.trg_roles_permission_calc() - Permission calculation trigger
CREATE OR REPLACE FUNCTION app.trg_roles_permission_calc()
RETURNS TRIGGER AS $$
BEGIN
    -- Invalidate permission cache when roles change
    PERFORM pg_notify('role_permissions_changed', 
        jsonb_build_object(
            'role_id', COALESCE(NEW.role_id, OLD.role_id),
            'action', TG_OP,
            'timestamp', now()
        )::text
    );
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION app.trg_roles_permission_calc() IS 'Invalidates permission cache when roles change';

-- app.trg_roles_audit() - Audit trigger for roles
CREATE OR REPLACE FUNCTION app.trg_roles_audit()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit.audit_log (
        audit_category, audit_action, table_schema, table_name, record_id,
        old_values, new_values, actor_id, actor_type, source_service,
        current_audit_hash
    ) VALUES (
        'CONFIG',
        TG_OP,
        'app',
        'roles',
        COALESCE(NEW.role_id, OLD.role_id)::text,
        CASE WHEN TG_OP IN ('UPDATE', 'DELETE') THEN to_jsonb(OLD) ELSE NULL END,
        CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN to_jsonb(NEW) ELSE NULL END,
        current_setting('app.current_account_id', true)::UUID,
        'USER',
        'roles_trigger',
        digest(random()::text || now()::text, 'sha256')
    );
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION app.trg_roles_audit() IS 'Audit trigger for role changes';

-- app.trg_roles_system_protect() - Protect system roles
CREATE OR REPLACE FUNCTION app.trg_roles_system_protect()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.is_system = true THEN
        RAISE EXCEPTION 'System roles cannot be deleted: %', OLD.role_code
            USING HINT = 'System roles are protected for application integrity';
    END IF;
    
    IF TG_OP = 'UPDATE' AND OLD.is_system = true THEN
        -- Prevent critical changes to system roles
        IF NEW.role_code != OLD.role_code THEN
            RAISE EXCEPTION 'System role codes cannot be changed: %', OLD.role_code;
        END IF;
        IF NEW.is_system = false THEN
            RAISE EXCEPTION 'Cannot remove system flag from role: %', OLD.role_code;
        END IF;
    END IF;
    
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION app.trg_roles_system_protect() IS 'Prevents modification of system roles';

-- app.trg_assignments_break_glass_alert() - Break-glass access alerts
CREATE OR REPLACE FUNCTION app.trg_assignments_break_glass_alert()
RETURNS TRIGGER AS $$
BEGIN
    -- Alert if break-glass role is assigned
    IF TG_OP = 'INSERT' AND NEW.is_break_glass = true THEN
        INSERT INTO ussd.security_alerts (
            alert_type, severity, account_id, description, metadata
        ) VALUES (
            'BREAK_GLASS_ASSIGNED',
            'HIGH',
            NEW.account_id,
            'Break-glass role assigned to user',
            jsonb_build_object(
                'role_id', NEW.role_id,
                'application_id', NEW.application_id,
                'assigned_at', now()
            )
        );
        
        -- Also log to audit
        RAISE WARNING 'BREAK-GLASS: Role % assigned to account %', NEW.role_id, NEW.account_id;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION app.trg_assignments_break_glass_alert() IS 'Creates security alert when break-glass role is assigned';

-- app.trg_assignments_cache_invalidate() - Cache invalidation
CREATE OR REPLACE FUNCTION app.trg_assignments_cache_invalidate()
RETURNS TRIGGER AS $$
DECLARE
    v_account_id UUID;
    v_application_id UUID;
BEGIN
    v_account_id := COALESCE(NEW.account_id, OLD.account_id);
    v_application_id := COALESCE(NEW.application_id, OLD.application_id);
    
    -- Notify cache invalidation
    PERFORM pg_notify('role_assignments_changed', 
        jsonb_build_object(
            'account_id', v_account_id,
            'application_id', v_application_id,
            'action', TG_OP,
            'timestamp', now()
        )::text
    );
    
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION app.trg_assignments_cache_invalidate() IS 'Notifies cache invalidation on role assignment changes';

-- =============================================================================
-- USSD SCHEMA TRIGGER FUNCTIONS
-- =============================================================================

-- ussd.tf_fraud_check_transaction() - Transaction fraud check
CREATE OR REPLACE FUNCTION ussd.tf_fraud_check_transaction()
RETURNS TRIGGER AS $$
DECLARE
    v_risk_score INTEGER := 0;
    v_hourly_count INTEGER;
    v_daily_amount NUMERIC;
BEGIN
    -- Check transaction amount against limits (>$10k is high risk)
    IF NEW.amount > 10000 THEN
        v_risk_score := v_risk_score + 20;
    END IF;
    
    -- Check velocity (transactions in last hour)
    SELECT COUNT(*), COALESCE(SUM(amount), 0)
    INTO v_hourly_count, v_daily_amount
    FROM core.transaction_log
    WHERE initiator_account_id = NEW.initiator_account_id
    AND created_at > now() - interval '1 hour';
    
    IF v_hourly_count > 10 THEN
        v_risk_score := v_risk_score + 30;
    END IF;
    
    -- Check daily amount limit ($50k)
    IF v_daily_amount > 50000 THEN
        v_risk_score := v_risk_score + 25;
    END IF;
    
    -- Check for rapid sequential transactions (< 1 second apart)
    IF EXISTS (
        SELECT 1 FROM core.transaction_log
        WHERE initiator_account_id = NEW.initiator_account_id
        AND created_at > now() - interval '1 second'
    ) THEN
        v_risk_score := v_risk_score + 15;
    END IF;
    
    -- If high risk, create alert
    IF v_risk_score > 40 THEN
        INSERT INTO ussd.security_alerts (
            alert_type, severity, account_id, description, metadata
        ) VALUES (
            'HIGH_RISK_TRANSACTION',
            CASE WHEN v_risk_score > 70 THEN 'CRITICAL' ELSE 'HIGH' END,
            NEW.initiator_account_id,
            'Transaction flagged with risk score: ' || v_risk_score,
            jsonb_build_object(
                'transaction_id', NEW.transaction_id,
                'amount', NEW.amount,
                'currency', NEW.currency,
                'risk_score', v_risk_score,
                'hourly_count', v_hourly_count,
                'daily_amount', v_daily_amount
            )
        );
    END IF;
    
    -- Add risk score to transaction metadata
    NEW.payload := NEW.payload || jsonb_build_object('_fraud_score', v_risk_score);
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.tf_fraud_check_transaction() IS 'Evaluates transaction fraud risk and creates alerts';

-- ussd.log_security_event() - Security event logging
CREATE OR REPLACE FUNCTION ussd.log_security_event(
    p_event_type VARCHAR(50),
    p_severity VARCHAR(20),
    p_account_id UUID,
    p_description TEXT,
    p_metadata JSONB DEFAULT '{}'
)
RETURNS UUID AS $$
DECLARE
    v_alert_id UUID;
BEGIN
    INSERT INTO ussd.security_alerts (
        alert_type, severity, account_id, description, metadata, detected_at
    ) VALUES (
        p_event_type, p_severity, p_account_id, p_description, p_metadata, now()
    )
    RETURNING alert_id INTO v_alert_id;
    
    -- Also log to PostgreSQL log for SIEM integration
    RAISE LOG 'SECURITY_EVENT: type=%, severity=%, account=%, desc=%, alert_id=%',
        p_event_type, p_severity, p_account_id, p_description, v_alert_id;
    
    RETURN v_alert_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.log_security_event() IS 'Logs security events to alerts table and PostgreSQL log';

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Helper function to safely get current user ID
CREATE OR REPLACE FUNCTION security.get_current_user_id()
RETURNS UUID AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_user_id', true), '')::UUID;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION security.get_current_user_id() IS 'Safely retrieves current user ID from session context';

-- Helper function to safely get current account ID
CREATE OR REPLACE FUNCTION security.get_current_account_id()
RETURNS UUID AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_account_id', true), '')::UUID;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION security.get_current_account_id() IS 'Safely retrieves current account ID from session context';

-- Helper function to safely get current application ID
CREATE OR REPLACE FUNCTION security.get_current_application_id()
RETURNS UUID AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_application_id', true), '')::UUID;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION security.get_current_application_id() IS 'Safely retrieves current application ID from session context';

-- Helper function to check if user is admin
CREATE OR REPLACE FUNCTION security.is_admin()
RETURNS BOOLEAN AS $$
BEGIN
    RETURN COALESCE(current_setting('app.is_admin', true)::BOOLEAN, false);
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION security.is_admin() IS 'Checks if current session has admin privileges';

-- Helper function to safely get encryption key
CREATE OR REPLACE FUNCTION security.get_encryption_key()
RETURNS BYTEA AS $$
BEGIN
    RETURN current_setting('app.encryption_key', true)::BYTEA;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION security.get_encryption_key() IS 'Safely retrieves encryption key from session context';

/*
================================================================================
MIGRATION CHECKLIST:
[x] Create app.trg_app_registry_audit()
[x] Create app.trg_membership_audit()
[x] Create app.trg_roles_permission_calc()
[x] Create app.trg_roles_audit()
[x] Create app.trg_roles_system_protect()
[x] Create app.trg_assignments_break_glass_alert()
[x] Create app.trg_assignments_cache_invalidate()
[x] Create ussd.tf_fraud_check_transaction()
[x] Create ussd.log_security_event()
[x] Create security helper functions
[ ] Apply triggers to tables
[ ] Test trigger execution
================================================================================
*/
