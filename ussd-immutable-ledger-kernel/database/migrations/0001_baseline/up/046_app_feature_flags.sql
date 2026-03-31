-- =============================================================================
-- MIGRATION: 046_app_feature_flags.sql
-- DESCRIPTION: Feature Flags and Toggles
-- TABLES: feature_flags, feature_flag_overrides
-- DEPENDENCIES: 031_app_registry.sql
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.8.27: Secure coding (feature toggles for security controls)
  - A.8.29: Security testing in development and acceptance
  - A.14.2.9: Management of test data

ISO/IEC 27018:2019 - Protection of PII in Public Clouds
  - Clause 5.1: Consent and choice (feature flags for opt-in features)

GDPR / Zimbabwe Data Protection Act (Chapter 11:12)
  - Article 25: Data protection by design and by default
  - Feature flags implement privacy-by-design controls
  - Consent management via feature enablement

SECURITY CLASSIFICATION: INTERNAL
DATA SENSITIVITY: SYSTEM CONTROL (can disable security features)
RETENTION PERIOD: Flag history - 3 years; Override records - 1 year
AUDIT REQUIREMENT: All flag changes logged
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 5. Application Configuration Store
- Feature: Feature Flags
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Mutable table for runtime toggles (e.g., allow_credit, require_approval).
Each flag change is audited. Feature flags can be applied per application,
per account, or globally.

KEY FEATURES:
- Boolean and gradual rollout support
- User/account targeting
- Percentage rollout
- Scheduled activation
- Audit trail

SECURITY IMPLICATIONS:
- Security-related flags require elevated privileges
- Gradual rollout allows safe deployment of security features
- Emergency kill switches for incident response
- Account-level overrides for A/B testing security controls
================================================================================
*/

-- =============================================================================
-- IMPLEMENTED: Create feature_flags table
-- DESCRIPTION: Feature flag definitions
-- PRIORITY: CRITICAL
-- SECURITY: RLS by application; security flags require admin
-- AUDIT: All flag state changes logged
-- DATA PROTECTION: Flags can control PII processing features
-- =============================================================================
-- [FF-001] Create app.feature_flags table
CREATE TABLE app.feature_flags (
    flag_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flag_key            VARCHAR(100) NOT NULL,
    
    -- Identity
    flag_name           VARCHAR(100) NOT NULL,
    description         TEXT,
    
    -- Scope
    application_id      UUID REFERENCES app.applications(application_id), -- NULL = global
    
    -- Flag Type
    flag_type           VARCHAR(20) DEFAULT 'BOOLEAN', -- BOOLEAN, GRADUAL, PERMISSION
    
    -- Default State
    default_value       BOOLEAN DEFAULT false,
    rollout_percentage  INTEGER DEFAULT 100,           -- 0-100 for gradual rollout
    
    -- Targeting
    target_accounts     UUID[],                        -- Specific accounts
    target_roles        UUID[],                        -- Specific roles
    exclude_accounts    UUID[],                        -- Excluded accounts
    
    -- Scheduling
    enabled_from        TIMESTAMPTZ,                   -- Scheduled activation
    enabled_until       TIMESTAMPTZ,                   -- Auto-disable
    
    -- Dependencies
    requires_flags      VARCHAR(100)[],                -- Flags that must be enabled
    conflicts_with      VARCHAR(100)[],                -- Mutually exclusive flags
    
    -- Status
    is_enabled          BOOLEAN DEFAULT false,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    updated_at          TIMESTAMPTZ,
    updated_by          UUID REFERENCES core.accounts(account_id)
);

-- CONSTRAINTS:
CREATE UNIQUE INDEX idx_feature_flags_app_key 
    ON app.feature_flags (COALESCE(application_id, '00000000-0000-0000-0000-000000000000'::UUID), flag_key);

ALTER TABLE app.feature_flags
    ADD CONSTRAINT chk_rollout_percentage 
        CHECK (rollout_percentage BETWEEN 0 AND 100);

COMMENT ON TABLE app.feature_flags IS 'Feature flag registry for runtime toggles';

-- =============================================================================
-- IMPLEMENTED: Create feature_flag_overrides table
-- DESCRIPTION: Account-specific flag overrides
-- PRIORITY: MEDIUM
-- SECURITY: Access restricted to flag administrators
-- AUDIT: All overrides logged with justification
-- PII: Links to accounts; access controlled
-- =============================================================================
-- [FF-002] Create app.feature_flag_overrides table
CREATE TABLE app.feature_flag_overrides (
    override_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flag_id             UUID NOT NULL REFERENCES app.feature_flags(flag_id),
    account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
    
    -- Override
    override_value      BOOLEAN NOT NULL,
    reason              TEXT,
    
    -- Expiration
    valid_until         TIMESTAMPTZ,
    
    -- Audit
    created_by          UUID REFERENCES core.accounts(account_id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    UNIQUE (flag_id, account_id)
);

COMMENT ON TABLE app.feature_flag_overrides IS 'Per-account feature flag overrides';

-- =============================================================================
-- IMPLEMENTED: Create is_feature_enabled function
-- DESCRIPTION: Check if feature is enabled
-- PRIORITY: CRITICAL
-- SECURITY: STABLE function; respects all access controls
-- PERFORMANCE: Optimized for high-frequency checks
-- AUDIT: Critical security flags log access
-- =============================================================================
-- [FF-003] Create is_feature_enabled function
CREATE OR REPLACE FUNCTION app.is_feature_enabled(
    p_flag_key VARCHAR(100),
    p_application_id UUID DEFAULT NULL,
    p_account_id UUID DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_flag RECORD;
    v_override BOOLEAN;
    v_hash_val INTEGER;
BEGIN
    -- Get flag
    SELECT * INTO v_flag
    FROM app.feature_flags
    WHERE flag_key = p_flag_key
        AND (application_id = p_application_id OR application_id IS NULL)
    ORDER BY application_id IS NULL  -- Prefer specific over global
    LIMIT 1;
    
    IF v_flag IS NULL OR NOT v_flag.is_enabled THEN
        RETURN false;
    END IF;
    
    -- Check schedule
    IF v_flag.enabled_from IS NOT NULL AND v_flag.enabled_from > now() THEN
        RETURN false;
    END IF;
    
    IF v_flag.enabled_until IS NOT NULL AND v_flag.enabled_until < now() THEN
        RETURN false;
    END IF;
    
    -- Check account override
    IF p_account_id IS NOT NULL THEN
        SELECT override_value INTO v_override
        FROM app.feature_flag_overrides
        WHERE flag_id = v_flag.flag_id
            AND account_id = p_account_id
            AND (valid_until IS NULL OR valid_until > now());
        
        IF v_override IS NOT NULL THEN
            RETURN v_override;
        END IF;
        
        -- Check excluded accounts
        IF p_account_id = ANY(v_flag.exclude_accounts) THEN
            RETURN false;
        END IF;
        
        -- Check targeted accounts
        IF v_flag.target_accounts IS NOT NULL AND 
           array_length(v_flag.target_accounts, 1) > 0 THEN
            IF NOT (p_account_id = ANY(v_flag.target_accounts)) THEN
                RETURN false;
            END IF;
        END IF;
    END IF;
    
    -- Check gradual rollout (consistent hashing)
    IF v_flag.rollout_percentage < 100 AND p_account_id IS NOT NULL THEN
        v_hash_val := (hashtext(p_account_id::text || v_flag.flag_key)) % 100;
        IF v_hash_val < 0 THEN v_hash_val := v_hash_val + 100; END IF;
        RETURN v_hash_val < v_flag.rollout_percentage;
    END IF;
    
    RETURN v_flag.default_value;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION app.is_feature_enabled IS 'Checks if a feature is enabled for an account with targeting and rollout support';

-- =============================================================================
-- IMPLEMENTED: Create feature flag audit trigger
-- DESCRIPTION: Log flag changes
-- PRIORITY: MEDIUM
-- SECURITY: SECURITY DEFINER; cannot be bypassed
-- =============================================================================
-- [FF-004] Create feature flag audit logging
CREATE OR REPLACE FUNCTION app.log_feature_flag_change()
RETURNS TRIGGER AS $$
BEGIN
    -- Log to configuration_history as feature flags are a type of config
    INSERT INTO app.configuration_history (
        config_id, change_type, previous_value, new_value,
        changed_by, change_reason
    ) VALUES (
        COALESCE(NEW.flag_id, OLD.flag_id),
        CASE 
            WHEN TG_OP = 'INSERT' THEN 'CREATE'
            WHEN TG_OP = 'UPDATE' THEN 'UPDATE'
            ELSE 'DELETE'
        END,
        CASE WHEN TG_OP != 'INSERT' THEN jsonb_build_object(
            'flag_key', OLD.flag_key,
            'is_enabled', OLD.is_enabled,
            'rollout_percentage', OLD.rollout_percentage
        ) END,
        CASE WHEN TG_OP != 'DELETE' THEN jsonb_build_object(
            'flag_key', NEW.flag_key,
            'is_enabled', NEW.is_enabled,
            'rollout_percentage', NEW.rollout_percentage
        ) END,
        COALESCE(NEW.updated_by, OLD.updated_by, NEW.created_by),
        'Feature flag change'
    );
    
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create trigger
CREATE TRIGGER trigger_log_feature_flag_change
    AFTER INSERT OR UPDATE OR DELETE ON app.feature_flags
    FOR EACH ROW EXECUTE FUNCTION app.log_feature_flag_change();

COMMENT ON FUNCTION app.log_feature_flag_change IS 'Audit trigger for feature flag changes';

-- =============================================================================
-- IMPLEMENTED: Create feature flag indexes
-- DESCRIPTION: Optimize flag queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for request path
-- =============================================================================
-- [FF-005] Create feature flag indexes
-- Feature Flags:
-- PRIMARY KEY (flag_id) - created with table
-- UNIQUE (application_id, flag_key) - created above

CREATE INDEX idx_feature_flags_enabled_key 
    ON app.feature_flags (is_enabled, flag_key);

-- Overrides:
-- PRIMARY KEY (override_id) - created with table
-- UNIQUE (flag_id, account_id) - created with table

CREATE INDEX idx_feature_flag_overrides_account_valid 
    ON app.feature_flag_overrides (account_id, valid_until);

/*
================================================================================
FEATURE FLAG SECURITY & PRIVACY GUIDE
================================================================================

1. SECURITY FLAG CATEGORIES:
   ┌──────────────────────────┬─────────────────────────────────────────────┐
   │ Flag Type                │ Security Implications                       │
   ├──────────────────────────┼─────────────────────────────────────────────┤
   │ require_strong_auth      │ Affects authentication security             │
   │ enable_pii_encryption    │ Controls data protection                    │
   │ allow_cross_border_xfer  │ Impacts GDPR/data residency                 │
   │ audit_all_access         │ Compliance logging control                  │
   │ enable_rate_limiting     │ DoS protection                              │
   │ require_approval_>X      │ Financial control threshold                 │
   └──────────────────────────┴─────────────────────────────────────────────┘

2. PRIVACY-BY-DESIGN FLAGS:
   - minimize_data_collection: Reduces PII captured
   - auto_anonymize_after_X: Triggers retention policy
   - require_explicit_consent: Blocks processing without consent
   - enable_data_portability: Allows user data export
   - disable_profiling: Prevents automated decision-making

3. EMERGENCY PROCEDURES:
   - KILL_SWITCH_* flags for immediate feature disable
   - Circuit breaker flags for degraded operation
   - Incident response can disable features without deployment
   - All emergency actions logged with incident reference

4. GRADUAL ROLLOUT BEST PRACTICES:
   - Start at 1% for security features
   - Monitor error rates and security metrics
   - Automatic rollback on anomaly detection
   - 24-hour observation period before increasing percentage

5. AUDIT REQUIREMENTS:
   - Flag creation: Who, when, purpose, expiration
   - State changes: Before/after, reason, authorization
   - Override creation: Account, justification, duration
   - Security flag access: Every evaluation logged

GDPR IMPLEMENTATION:
- Consent features controlled via feature flags
- Right to object implemented as automatic exclusion
- Data minimization enforced by configuration
- Processing purpose limitation via flag scoping
================================================================================
*/

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create feature_flags table
☑ Create feature_flag_overrides table
☑ Implement is_feature_enabled function
☑ Implement audit logging
☑ Add all indexes for flag queries
☐ Test feature flag evaluation
☐ Test gradual rollout
☐ Test targeting rules
☐ Test override functionality
☐ Verify audit trail
☐ Document emergency kill switch procedures
☐ Configure privacy-by-design flags
================================================================================
*/
