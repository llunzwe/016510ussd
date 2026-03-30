-- ============================================================================
-- USSD KERNEL APP SCHEMA - AUDIT INFRASTRUCTURE
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Audit logging for application-level changes.
--              Core ledger immutability is handled in ussd_core schema.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. APPLICATION AUDIT LOG
-- ----------------------------------------------------------------------------
-- For tracking changes to app-level configuration and mutable data
CREATE TABLE ussd_app.application_audit_log (
    audit_id BIGSERIAL,
    
    -- What changed
    table_name VARCHAR(63) NOT NULL,
    record_id TEXT NOT NULL,
    action VARCHAR(20) NOT NULL,  -- INSERT, UPDATE, DELETE
    
    -- Data
    old_values JSONB,
    new_values JSONB,
    changed_fields TEXT[],
    
    -- Context
    application_id UUID,
    account_id UUID,
    session_id TEXT,
    
    -- Timing
    changed_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    
    PRIMARY KEY (audit_id, changed_at)
);

-- Convert to hypertable for time-series optimization
-- Note: Run this after creating the table
-- SELECT create_hypertable('ussd_app.application_audit_log', 'changed_at', chunk_time_interval => INTERVAL '1 day');

-- ----------------------------------------------------------------------------
-- 2. API ACCESS LOG
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.api_access_log (
    log_id BIGSERIAL,
    
    -- Request
    api_key_id UUID,
    application_id UUID,
    endpoint VARCHAR(255),
    method VARCHAR(10),
    request_payload JSONB,
    
    -- Response
    response_status INTEGER,
    response_time_ms INTEGER,
    
    -- Context
    client_ip INET,
    user_agent TEXT,
    request_id UUID,  -- For tracing
    
    -- Timing
    requested_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    
    PRIMARY KEY (log_id, requested_at)
);

-- ----------------------------------------------------------------------------
-- 3. INDEXES
-- ----------------------------------------------------------------------------
CREATE INDEX idx_app_audit_app ON ussd_app.application_audit_log(application_id);
CREATE INDEX idx_app_audit_table ON ussd_app.application_audit_log(table_name);
CREATE INDEX idx_app_audit_time ON ussd_app.application_audit_log(changed_at DESC);

CREATE INDEX idx_api_log_app ON ussd_app.api_access_log(application_id);
CREATE INDEX idx_api_log_time ON ussd_app.api_access_log(requested_at DESC);
CREATE INDEX idx_api_log_key ON ussd_app.api_access_log(api_key_id);

-- ----------------------------------------------------------------------------
-- 4. AUDIT LOGGING FUNCTION
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd_app.log_app_change(
    p_table_name VARCHAR,
    p_record_id TEXT,
    p_action VARCHAR,
    p_old_values JSONB,
    p_new_values JSONB
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO ussd_app.application_audit_log (
        table_name, record_id, action, old_values, new_values,
        changed_fields, application_id, account_id, session_id
    ) VALUES (
        p_table_name, p_record_id, p_action, p_old_values, p_new_values,
        CASE 
            WHEN p_old_values IS NOT NULL AND p_new_values IS NOT NULL THEN
                ARRAY(
                    SELECT jsonb_object_keys(p_new_values)
                    EXCEPT
                    SELECT jsonb_object_keys(p_old_values)
                    UNION
                    SELECT key FROM jsonb_each(p_old_values)
                    WHERE p_new_values->key IS DISTINCT FROM p_old_values->key
                )
            ELSE NULL
        END,
        NULLIF(current_setting('app.application_id', TRUE), '')::UUID,
        NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID,
        current_setting('app.session_id', TRUE)
    );
END;
$$;

-- ----------------------------------------------------------------------------
-- 5. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_app.application_audit_log IS 
    'Audit trail for application-level configuration changes';
COMMENT ON TABLE ussd_app.api_access_log IS 
    'API access logging for rate limiting and security monitoring';
