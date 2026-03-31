-- =============================================================================
-- PASSWORD POLICIES
-- Comprehensive password policy enforcement for database users
-- =============================================================================

-- =============================================================================
-- PASSWORD POLICY SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS password_policy;

COMMENT ON SCHEMA password_policy IS 'Password policy configuration and enforcement';

-- =============================================================================
-- POLICY CONFIGURATION TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS password_policy.config (
    id SERIAL PRIMARY KEY,
    policy_name VARCHAR(100) NOT NULL UNIQUE,
    policy_type VARCHAR(50) NOT NULL DEFAULT 'GLOBAL', -- GLOBAL, ROLE, USER
    applies_to VARCHAR(100), -- NULL = global, or specific role/user name
    
    -- Complexity requirements
    min_length INTEGER NOT NULL DEFAULT 12,
    max_length INTEGER DEFAULT 128,
    require_uppercase BOOLEAN DEFAULT TRUE,
    require_lowercase BOOLEAN DEFAULT TRUE,
    require_digits BOOLEAN DEFAULT TRUE,
    require_special_chars BOOLEAN DEFAULT TRUE,
    special_chars_set TEXT DEFAULT '!@#$%^&*()_+-=[]{}|;:,.<>?',
    
    -- History and reuse
    password_history_count INTEGER DEFAULT 5, -- Cannot reuse last N passwords
    min_password_age_days INTEGER DEFAULT 1, -- Cannot change before N days
    max_password_age_days INTEGER DEFAULT 90, -- Must change after N days
    
    -- Lockout settings
    max_failed_attempts INTEGER DEFAULT 5,
    lockout_duration_minutes INTEGER DEFAULT 30,
    reset_lockout_after_minutes INTEGER DEFAULT 30,
    
    -- Session settings
    session_timeout_minutes INTEGER DEFAULT 480, -- 8 hours
    idle_timeout_minutes INTEGER DEFAULT 30,
    concurrent_sessions_limit INTEGER DEFAULT 3,
    
    -- MFA settings
    mfa_required BOOLEAN DEFAULT FALSE,
    mfa_methods_allowed TEXT[] DEFAULT ARRAY['TOTP', 'HARDWARE_KEY'],
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    priority INTEGER DEFAULT 100 -- Lower = higher priority
);

COMMENT ON TABLE password_policy.config IS 'Password policy configurations';

-- =============================================================================
-- PASSWORD HISTORY TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS password_policy.history (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    password_hash TEXT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by VARCHAR(100) DEFAULT current_user,
    reason VARCHAR(50) DEFAULT 'USER_CHANGE' -- USER_CHANGE, EXPIRED, ADMIN_RESET, POLICY_VIOLATION
);

CREATE INDEX IF NOT EXISTS idx_password_history_user 
ON password_policy.history(username, changed_at DESC);

-- =============================================================================
-- LOGIN ATTEMPTS LOG
-- =============================================================================
CREATE TABLE IF NOT EXISTS password_policy.login_attempts (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    client_ip INET,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(100),
    session_id VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_user 
ON password_policy.login_attempts(username, attempt_at DESC);

CREATE INDEX IF NOT EXISTS idx_login_attempts_failed 
ON password_policy.login_attempts(username, success, attempt_at) 
WHERE success = FALSE;

-- =============================================================================
-- ACCOUNT LOCKOUTS
-- =============================================================================
CREATE TABLE IF NOT EXISTS password_policy.account_lockouts (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    locked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_until TIMESTAMPTZ NOT NULL,
    failed_attempts INTEGER DEFAULT 0,
    lockout_reason VARCHAR(100) DEFAULT 'MAX_ATTEMPTS',
    unlocked_by VARCHAR(100),
    unlocked_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_lockouts_active 
ON password_policy.account_lockouts(username) 
WHERE is_active = TRUE;

-- =============================================================================
-- DEFAULT POLICIES
-- =============================================================================
INSERT INTO password_policy.config (
    policy_name, policy_type, applies_to, min_length, require_uppercase, 
    require_lowercase, require_digits, require_special_chars,
    password_history_count, max_password_age_days, max_failed_attempts,
    mfa_required, priority
) VALUES 
(
    'GLOBAL_DEFAULT', 'GLOBAL', NULL,
    12, TRUE, TRUE, TRUE, TRUE,
    5, 90, 5,
    FALSE, 100
),
(
    'ADMIN_POLICY', 'ROLE', 'admin',
    16, TRUE, TRUE, TRUE, TRUE,
    10, 60, 3,
    TRUE, 50
),
(
    'REPLICATION_POLICY', 'ROLE', 'replication',
    32, TRUE, TRUE, TRUE, TRUE,
    20, 30, 3,
    FALSE, 40
),
(
    'APP_SERVICE_POLICY', 'ROLE', 'app_service',
    32, TRUE, TRUE, TRUE, TRUE,
    0, 365, 10,
    FALSE, 60
),
(
    'READONLY_POLICY', 'ROLE', 'readonly_user',
    8, TRUE, TRUE, TRUE, FALSE,
    3, 180, 10,
    FALSE, 80
)
ON CONFLICT (policy_name) DO UPDATE SET
    min_length = EXCLUDED.min_length,
    max_password_age_days = EXCLUDED.max_password_age_days,
    mfa_required = EXCLUDED.mfa_required;

-- =============================================================================
-- FUNCTION: Get applicable policy for user
-- =============================================================================
CREATE OR REPLACE FUNCTION password_policy.get_policy(p_username VARCHAR)
RETURNS TABLE(
    min_length INTEGER,
    require_uppercase BOOLEAN,
    require_lowercase BOOLEAN,
    require_digits BOOLEAN,
    require_special_chars BOOLEAN,
    password_history_count INTEGER,
    max_password_age_days INTEGER,
    max_failed_attempts INTEGER,
    mfa_required BOOLEAN
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_role VARCHAR(100);
BEGIN
    -- Find most specific matching policy (USER > ROLE > GLOBAL)
    RETURN QUERY
    SELECT 
        c.min_length,
        c.require_uppercase,
        c.require_lowercase,
        c.require_digits,
        c.require_special_chars,
        c.password_history_count,
        c.max_password_age_days,
        c.max_failed_attempts,
        c.mfa_required
    FROM password_policy.config c
    WHERE c.is_active = TRUE
      AND (
          (c.policy_type = 'GLOBAL' AND c.applies_to IS NULL)
          OR (c.policy_type = 'ROLE' AND c.applies_to = ANY(
              SELECT b.rolname::VARCHAR(100)
              FROM pg_auth_members m
              JOIN pg_roles b ON b.oid = m.roleid
              JOIN pg_roles u ON u.oid = m.member
              WHERE u.rolname = p_username
          ))
          OR (c.policy_type = 'USER' AND c.applies_to = p_username)
      )
    ORDER BY c.priority, 
             CASE c.policy_type 
                 WHEN 'USER' THEN 1 
                 WHEN 'ROLE' THEN 2 
                 ELSE 3 
             END
    LIMIT 1;
END;
$$;

-- =============================================================================
-- FUNCTION: Validate password strength
-- =============================================================================
CREATE OR REPLACE FUNCTION password_policy.validate_password(
    p_username VARCHAR,
    p_password TEXT
)
RETURNS TABLE(valid BOOLEAN, error_message TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_policy RECORD;
BEGIN
    -- Get policy
    SELECT * INTO v_policy FROM password_policy.get_policy(p_username);
    
    IF NOT FOUND THEN
        valid := FALSE;
        error_message := 'No password policy found';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Check minimum length
    IF LENGTH(p_password) < v_policy.min_length THEN
        valid := FALSE;
        error_message := format('Password must be at least %s characters', v_policy.min_length);
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Check maximum length
    IF LENGTH(p_password) > 128 THEN
        valid := FALSE;
        error_message := 'Password exceeds maximum length of 128 characters';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Check uppercase
    IF v_policy.require_uppercase AND p_password !~ '[A-Z]' THEN
        valid := FALSE;
        error_message := 'Password must contain at least one uppercase letter';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Check lowercase
    IF v_policy.require_lowercase AND p_password !~ '[a-z]' THEN
        valid := FALSE;
        error_message := 'Password must contain at least one lowercase letter';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Check digits
    IF v_policy.require_digits AND p_password !~ '[0-9]' THEN
        valid := FALSE;
        error_message := 'Password must contain at least one digit';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Check special characters
    IF v_policy.require_special_chars AND p_password !~ '[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]' THEN
        valid := FALSE;
        error_message := 'Password must contain at least one special character';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Check username not in password (case-insensitive)
    IF p_password ILIKE ('%' || p_username || '%') THEN
        valid := FALSE;
        error_message := 'Password cannot contain username';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Check common weak passwords
    IF LOWER(p_password) IN ('password', 'password123', 'qwerty', '123456', 'admin', 'ledger') THEN
        valid := FALSE;
        error_message := 'Password is too common or weak';
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Check password history
    IF v_policy.password_history_count > 0 THEN
        IF EXISTS (
            SELECT 1 FROM password_policy.history h
            WHERE h.username = p_username
              AND h.changed_at > NOW() - INTERVAL '365 days'
              AND encryption.verify_password(p_password, h.password_hash)
            ORDER BY h.changed_at DESC
            LIMIT v_policy.password_history_count
        ) THEN
            valid := FALSE;
            error_message := format('Cannot reuse last %s passwords', v_policy.password_history_count);
            RETURN NEXT;
            RETURN;
        END IF;
    END IF;
    
    valid := TRUE;
    error_message := NULL;
    RETURN NEXT;
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Record password change
-- =============================================================================
CREATE OR REPLACE FUNCTION password_policy.record_password_change(
    p_username VARCHAR,
    p_password_hash TEXT,
    p_reason VARCHAR DEFAULT 'USER_CHANGE'
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO password_policy.history (
        username, password_hash, reason
    ) VALUES (
        p_username, p_password_hash, p_reason
    );
    
    -- Clean old history (keep only what's needed for policy + buffer)
    DELETE FROM password_policy.history
    WHERE id IN (
        SELECT id FROM password_policy.history
        WHERE username = p_username
        ORDER BY changed_at DESC
        OFFSET 20
    );
END;
$$;

-- =============================================================================
-- FUNCTION: Log login attempt
-- =============================================================================
CREATE OR REPLACE FUNCTION password_policy.log_login_attempt(
    p_username VARCHAR,
    p_client_ip INET,
    p_success BOOLEAN,
    p_failure_reason VARCHAR DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_policy RECORD;
    v_recent_failures INTEGER;
BEGIN
    -- Log the attempt
    INSERT INTO password_policy.login_attempts (
        username, client_ip, success, failure_reason
    ) VALUES (
        p_username, p_client_ip, p_success, p_failure_reason
    );
    
    -- If failed, check for lockout
    IF NOT p_success THEN
        SELECT * INTO v_policy FROM password_policy.get_policy(p_username);
        
        IF FOUND THEN
            -- Count recent failures
            SELECT COUNT(*) INTO v_recent_failures
            FROM password_policy.login_attempts
            WHERE username = p_username
              AND success = FALSE
              AND attempt_at > NOW() - (v_policy.reset_lockout_after_minutes || ' minutes')::INTERVAL;
            
            -- Lock account if threshold reached
            IF v_recent_failures >= v_policy.max_failed_attempts THEN
                INSERT INTO password_policy.account_lockouts (
                    username, locked_until, failed_attempts, lockout_reason
                ) VALUES (
                    p_username,
                    NOW() + (v_policy.lockout_duration_minutes || ' minutes')::INTERVAL,
                    v_recent_failures,
                    'MAX_ATTEMPTS'
                )
                ON CONFLICT (username) DO UPDATE SET
                    locked_at = NOW(),
                    locked_until = NOW() + (v_policy.lockout_duration_minutes || ' minutes')::INTERVAL,
                    failed_attempts = v_recent_failures,
                    is_active = TRUE,
                    unlocked_at = NULL,
                    unlocked_by = NULL;
            END IF;
        END IF;
    END IF;
END;
$$;

-- =============================================================================
-- FUNCTION: Check if account is locked
-- =============================================================================
CREATE OR REPLACE FUNCTION password_policy.is_account_locked(p_username VARCHAR)
RETURNS TABLE(locked BOOLEAN, locked_until TIMESTAMPTZ, reason VARCHAR)
LANGUAGE plpgsql
AS $$
DECLARE
    v_lockout RECORD;
BEGIN
    SELECT * INTO v_lockout
    FROM password_policy.account_lockouts
    WHERE username = p_username
      AND is_active = TRUE;
    
    IF NOT FOUND THEN
        locked := FALSE;
        locked_until := NULL;
        reason := NULL;
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Check if lockout has expired
    IF v_lockout.locked_until <= NOW() THEN
        -- Auto-unlock
        UPDATE password_policy.account_lockouts
        SET is_active = FALSE,
            unlocked_at = NOW(),
            unlocked_by = 'SYSTEM_AUTO'
        WHERE id = v_lockout.id;
        
        locked := FALSE;
        locked_until := NULL;
        reason := NULL;
    ELSE
        locked := TRUE;
        locked_until := v_lockout.locked_until;
        reason := v_lockout.lockout_reason::VARCHAR(100);
    END IF;
    
    RETURN NEXT;
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Unlock account
-- =============================================================================
CREATE OR REPLACE FUNCTION password_policy.unlock_account(
    p_username VARCHAR,
    p_unlocked_by VARCHAR DEFAULT current_user
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE password_policy.account_lockouts
    SET is_active = FALSE,
        unlocked_at = NOW(),
        unlocked_by = p_unlocked_by
    WHERE username = p_username
      AND is_active = TRUE;
    
    IF FOUND THEN
        RETURN format('SUCCESS: Account %s unlocked by %s', p_username, p_unlocked_by);
    ELSE
        RETURN format('INFO: Account %s was not locked', p_username);
    END IF;
END;
$$;

-- =============================================================================
-- FUNCTION: Check password expiry
-- =============================================================================
CREATE OR REPLACE FUNCTION password_policy.check_password_expiry(p_username VARCHAR)
RETURNS TABLE(
    expired BOOLEAN,
    days_until_expiry INTEGER,
    expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_policy RECORD;
    v_last_change TIMESTAMPTZ;
BEGIN
    SELECT * INTO v_policy FROM password_policy.get_policy(p_username);
    
    IF NOT FOUND THEN
        expired := FALSE;
        days_until_expiry := NULL;
        expires_at := NULL;
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Get last password change
    SELECT changed_at INTO v_last_change
    FROM password_policy.history
    WHERE username = p_username
    ORDER BY changed_at DESC
    LIMIT 1;
    
    IF v_last_change IS NULL THEN
        expired := FALSE;
        days_until_expiry := NULL;
        expires_at := NULL;
        RETURN NEXT;
        RETURN;
    END IF;
    
    expires_at := v_last_change + (v_policy.max_password_age_days || ' days')::INTERVAL;
    days_until_expiry := EXTRACT(DAY FROM (expires_at - NOW()))::INTEGER;
    expired := days_until_expiry < 0;
    
    RETURN NEXT;
    RETURN;
END;
$$;

-- =============================================================================
-- VIEW: Policy summary
-- =============================================================================
CREATE OR REPLACE VIEW password_policy.policy_summary AS
SELECT 
    policy_name,
    policy_type,
    applies_to,
    min_length,
    CASE 
        WHEN require_uppercase AND require_lowercase AND require_digits AND require_special_chars 
        THEN 'High (upper, lower, digit, special)'
        WHEN require_uppercase AND require_lowercase AND require_digits 
        THEN 'Medium (upper, lower, digit)'
        ELSE 'Basic'
    END as complexity,
    password_history_count as history,
    max_password_age_days as max_age,
    max_failed_attempts as max_attempts,
    mfa_required,
    is_active,
    priority
FROM password_policy.config
ORDER BY priority, policy_name;

-- =============================================================================
-- VIEW: Account security status
-- =============================================================================
CREATE OR REPLACE VIEW password_policy.account_security_status AS
SELECT 
    username,
    MAX(changed_at) as last_password_change,
    COUNT(*) as password_changes,
    EXISTS (
        SELECT 1 FROM password_policy.account_lockouts al
        WHERE al.username = password_policy.history.username
          AND al.is_active = TRUE
    ) as currently_locked,
    (
        SELECT failed_attempts 
        FROM password_policy.account_lockouts al
        WHERE al.username = password_policy.history.username
          AND al.is_active = TRUE
    ) as lockout_failed_attempts
FROM password_policy.history
GROUP BY username;

-- =============================================================================
-- TRIGGER: Update timestamp
-- =============================================================================
CREATE TRIGGER trigger_policy_config_updated
    BEFORE UPDATE ON password_policy.config
    FOR EACH ROW EXECUTE FUNCTION encryption.update_timestamp();

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA password_policy TO security_admin;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA password_policy TO security_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA password_policy TO security_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA password_policy TO security_admin;
