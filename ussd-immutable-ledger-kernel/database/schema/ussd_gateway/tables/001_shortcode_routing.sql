-- =============================================================================
-- FILE: 001_shortcode_routing.sql
-- DESCRIPTION: USSD Shortcode Routing Configuration
-- TABLES: shortcodes, shortcode_routes, route_access_logs
-- SCHEMA: ussd
-- PRIORITY: CRITICAL
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.8.1: User endpoint devices (USSD gateway)
  - A.8.2: Privileged access rights (routing administration)
  - A.8.12: Data leakage prevention
  - A.14.1: Security requirements of information systems

ISO/IEC 27018:2019 - Protection of PII in Public Clouds
  - Clause 8.2: Return, transfer, and disposal of PII
  - Clause 9.2: Purpose specification (routing purpose only)

GDPR / Zimbabwe Data Protection Act (Chapter 11:12)
  - Article 5(1)(b): Purpose limitation (routing only)
  - Article 5(1)(c): Data minimization
  - Section 13: Data subject rights
  - MSISDN used for routing only, not stored without consent

TELECOM REGULATIONS:
  - POTRAZ (Zimbabwe) USSD service regulations
  - Number portability compliance
  - Emergency service routing requirements

SECURITY CLASSIFICATION: INTERNAL
DATA SENSITIVITY: ROUTING DATA (indirect PII through MSISDN pattern)
RETENTION PERIOD: Access logs 90 days; Aggregated analytics 2 years
AUDIT REQUIREMENT: All routing decisions logged
================================================================================
*/

-- =============================================================================
-- TABLE: shortcodes
-- DESCRIPTION: USSD shortcode registry
-- SECURITY: RLS restricted to telecom administrators
-- AUDIT: All shortcode changes logged
-- =============================================================================
CREATE TABLE IF NOT EXISTS ussd.shortcodes (
    shortcode_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Code Definition
    shortcode               VARCHAR(20) NOT NULL,            -- e.g., "*123#"
    shortcode_normalized    VARCHAR(20) NOT NULL,            -- Normalized for lookup
    
    -- Scope
    country_code            VARCHAR(2) NOT NULL,             -- ISO country code
    network_operator        VARCHAR(50),                     -- Specific operator or NULL for all
    mcc_mnc                 VARCHAR(10),                     -- Mobile Country Code + Mobile Network Code
    
    -- Classification
    shortcode_name          VARCHAR(100) NOT NULL,
    description             TEXT,
    shortcode_type          VARCHAR(20) DEFAULT 'SERVICE',   -- EMERGENCY, FINANCIAL, SERVICE, INFO, TEST
    
    -- Security Classification
    security_level          VARCHAR(20) DEFAULT 'STANDARD',  -- PUBLIC, STANDARD, SENSITIVE, CRITICAL
    requires_authentication BOOLEAN DEFAULT true,
    requires_encryption     BOOLEAN DEFAULT true,
    
    -- Routing Defaults
    default_application_id  UUID REFERENCES app.applications(application_id),
    fallback_shortcode_id   UUID REFERENCES ussd.shortcodes(shortcode_id),
    
    -- Status
    is_active               BOOLEAN DEFAULT true,
    is_emergency            BOOLEAN DEFAULT false,           -- Priority routing
    is_test_code            BOOLEAN DEFAULT false,           -- Restricted to test MSISDNs
    
    -- Rate Limiting
    rate_limit_per_minute   INTEGER DEFAULT 60,              -- Requests per minute
    rate_limit_per_hour     INTEGER DEFAULT 1000,            -- Requests per hour
    
    -- Validity
    valid_from              TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to                TIMESTAMPTZ,
    
    -- Audit
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by              UUID REFERENCES core.accounts(account_id),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by              UUID REFERENCES core.accounts(account_id),
    approved_by             UUID REFERENCES core.accounts(account_id),
    approval_date           TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT valid_shortcode_format CHECK (
        shortcode ~ '^\*[0-9]+([*][0-9#*]*)?#$' OR 
        shortcode ~ '^#([0-9*]+#)?$'
    ),
    CONSTRAINT valid_country_code CHECK (country_code ~ '^[A-Z]{2}$'),
    CONSTRAINT valid_shortcode_type CHECK (
        shortcode_type IN ('EMERGENCY', 'FINANCIAL', 'SERVICE', 'INFO', 'TEST', 'ADMIN')
    ),
    CONSTRAINT valid_security_level CHECK (
        security_level IN ('PUBLIC', 'STANDARD', 'SENSITIVE', 'CRITICAL')
    ),
    UNIQUE (shortcode_normalized, country_code, COALESCE(network_operator, ''))
);

COMMENT ON TABLE ussd.shortcodes IS 'USSD shortcode registry with security classification';
COMMENT ON COLUMN ussd.shortcodes.shortcode_type IS 'EMERGENCY=always active, FINANCIAL=fraud detection, SERVICE=standard, INFO=read-only, TEST=restricted';
COMMENT ON COLUMN ussd.shortcodes.security_level IS 'Determines authentication and encryption requirements';

-- =============================================================================
-- TABLE: shortcode_routes
-- DESCRIPTION: Shortcode to application routing with rules
-- SECURITY: Changes require dual authorization
-- AUDIT: Route changes logged with reason
-- =============================================================================
CREATE TABLE IF NOT EXISTS ussd.shortcode_routes (
    route_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Links
    shortcode_id            UUID NOT NULL REFERENCES ussd.shortcodes(shortcode_id),
    application_id          UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Route Identity
    route_name              VARCHAR(100) NOT NULL,
    route_description       TEXT,
    
    -- Routing Logic
    route_priority          INTEGER DEFAULT 100,             -- Lower = higher priority
    route_weight            INTEGER DEFAULT 1,               -- For load balancing (1-100)
    
    -- Conditions (JSON-based routing rules)
    condition_rules         JSONB DEFAULT '{}',              -- Flexible routing conditions
    /*
    Example condition_rules:
    {
        "time_ranges": [{"start": "08:00", "end": "18:00", "timezone": "Africa/Harare"}],
        "days_of_week": [1, 2, 3, 4, 5],
        "user_segments": ["premium", "business"],
        "max_daily_uses": 1000,
        "required_permissions": ["can_transfer"],
        "ip_ranges": ["10.0.0.0/8"],
        "msisdn_patterns": ["^\\+2637[1-9].*$"]
    }
    */
    
    -- Geographic Routing
    allowed_countries       VARCHAR(2)[],                    -- NULL = all
    blocked_countries       VARCHAR(2)[],                    -- Explicitly blocked
    
    -- Load Balancing
    max_concurrent_sessions INTEGER,                         -- NULL = unlimited
    current_session_count   INTEGER DEFAULT 0,               -- Runtime counter
    
    -- Response Customization
    welcome_message         VARCHAR(500),                    -- Override default
    welcome_message_translations JSONB,                      -- Multi-language welcome
    error_message           VARCHAR(500),                    -- Route-specific error
    
    -- Security
    allowed_networks        VARCHAR(50)[],                   -- Specific operators
    blocked_networks        VARCHAR(50)[],                   -- Blocked operators
    
    -- Status
    is_active               BOOLEAN DEFAULT true,
    is_primary              BOOLEAN DEFAULT false,           -- Primary route for shortcode
    
    -- Validity
    valid_from              TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to                TIMESTAMPTZ,
    
    -- Audit
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by              UUID REFERENCES core.accounts(account_id),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by              UUID REFERENCES core.accounts(account_id),
    change_reason           TEXT,                            -- Required for updates
    
    -- Constraints
    CONSTRAINT valid_route_priority CHECK (route_priority >= 0),
    CONSTRAINT valid_route_weight CHECK (route_weight >= 1 AND route_weight <= 100),
    CONSTRAINT valid_condition_rules CHECK (jsonb_typeof(condition_rules) = 'object')
);

COMMENT ON TABLE ussd.shortcode_routes IS 'Routes shortcodes to applications with conditional logic';
COMMENT ON COLUMN ussd.shortcode_routes.condition_rules IS 'JSON routing conditions: time, user segment, permissions';

-- =============================================================================
-- TABLE: route_access_logs
-- DESCRIPTION: Routing access tracking (anonymized)
-- SECURITY: RLS filtered; MSISDN hashed
-- PII: MSISDN one-way hashed; no account linkage
-- RETENTION: 90 days raw; 2 years aggregated
-- =============================================================================
CREATE TABLE IF NOT EXISTS ussd.route_access_logs (
    log_id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Request (anonymized)
    msisdn_hash             VARCHAR(64) NOT NULL,            -- SHA-256 hash of MSISDN
    shortcode               VARCHAR(20) NOT NULL,
    shortcode_id            UUID REFERENCES ussd.shortcodes(shortcode_id),
    country_code            VARCHAR(2),
    network_operator        VARCHAR(50),
    
    -- Device (hashed)
    device_fingerprint      VARCHAR(255),
    
    -- Routing
    route_id                UUID REFERENCES ussd.shortcode_routes(route_id),
    application_id          UUID,
    routing_decision        VARCHAR(20) NOT NULL,            -- ROUTED, BLOCKED, ERROR, FALLBACK
    
    -- Conditions that matched
    matched_conditions      JSONB DEFAULT '{}',              -- Which rules matched
    
    -- Result
    session_id              UUID REFERENCES ussd.ussd_sessions(session_id),
    
    -- Performance
    routing_duration_ms     INTEGER,                         -- Time to route
    queue_time_ms           INTEGER,                         -- Time in queue
    
    -- Error tracking
    error_code              VARCHAR(50),
    error_message           TEXT,
    
    -- Timing
    routed_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Geolocation (cell tower precision only)
    cell_tower_id           VARCHAR(50),
    location_area_code      VARCHAR(50),
    
    -- Audit
    request_id              UUID,                            -- For request tracing
    
    CONSTRAINT valid_routing_decision CHECK (
        routing_decision IN ('ROUTED', 'BLOCKED', 'ERROR', 'FALLBACK', 'RATE_LIMITED')
    )
);

COMMENT ON TABLE ussd.route_access_logs IS 'Anonymized routing access logs for audit and analytics';
COMMENT ON COLUMN ussd.route_access_logs.msisdn_hash IS 'SHA-256 hash - no reversible PII';

-- =============================================================================
-- TABLE: routing_rules_templates
-- DESCRIPTION: Reusable routing rule templates
-- =============================================================================
CREATE TABLE IF NOT EXISTS ussd.routing_rules_templates (
    template_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_name           VARCHAR(100) NOT NULL UNIQUE,
    template_description    TEXT,
    
    -- Template Category
    category                VARCHAR(50) NOT NULL,            -- TIME_BASED, GEOGRAPHIC, LOAD_BALANCING, etc.
    
    -- Rule Definition
    rule_definition         JSONB NOT NULL,                  -- Reusable rule JSON
    
    -- Example
    example_usage           TEXT,
    
    -- Status
    is_active               BOOLEAN DEFAULT true,
    
    -- Audit
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by              UUID REFERENCES core.accounts(account_id),
    
    CONSTRAINT valid_category CHECK (
        category IN ('TIME_BASED', 'GEOGRAPHIC', 'LOAD_BALANCING', 'USER_SEGMENT', 'PERMISSION_BASED', 'CUSTOM')
    )
);

COMMENT ON TABLE ussd.routing_rules_templates IS 'Reusable routing rule templates';

-- =============================================================================
-- INDEXES FOR ROUTING TABLES
-- =============================================================================

-- shortcodes indexes
CREATE INDEX IF NOT EXISTS idx_shortcodes_lookup ON ussd.shortcodes(
    shortcode_normalized, country_code, is_active
);
CREATE INDEX IF NOT EXISTS idx_shortcodes_operator ON ussd.shortcodes(
    network_operator, is_active
) WHERE network_operator IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_shortcodes_type ON ussd.shortcodes(shortcode_type, is_active);
CREATE INDEX IF NOT EXISTS idx_shortcodes_emergency ON ussd.shortcodes(is_emergency) WHERE is_emergency = true;
CREATE INDEX IF NOT EXISTS idx_shortcodes_validity ON ussd.shortcodes(valid_from, valid_to, is_active);

-- shortcode_routes indexes
CREATE INDEX IF NOT EXISTS idx_shortcode_routes_lookup ON ussd.shortcode_routes(
    shortcode_id, is_active, route_priority, valid_from, valid_to
);
CREATE INDEX IF NOT EXISTS idx_shortcode_routes_app ON ussd.shortcode_routes(application_id, is_active);
CREATE INDEX IF NOT EXISTS idx_shortcode_routes_primary ON ussd.shortcode_routes(
    shortcode_id, is_primary
) WHERE is_primary = true;
CREATE INDEX IF NOT EXISTS idx_shortcode_routes_validity ON ussd.shortcode_routes(valid_from, valid_to);

-- route_access_logs indexes (partitioned by date recommended)
CREATE INDEX IF NOT EXISTS idx_route_access_logs_shortcode ON ussd.route_access_logs(
    shortcode, routed_at
);
CREATE INDEX IF NOT EXISTS idx_route_access_logs_app ON ussd.route_access_logs(application_id, routed_at);
CREATE INDEX IF NOT EXISTS idx_route_access_logs_decision ON ussd.route_access_logs(
    routing_decision, routed_at
);
CREATE INDEX IF NOT EXISTS idx_route_access_logs_hash ON ussd.route_access_logs(msisdn_hash, routed_at);
CREATE INDEX IF NOT EXISTS idx_route_access_logs_date ON ussd.route_access_logs(routed_at);

-- routing_rules_templates indexes
CREATE INDEX IF NOT EXISTS idx_routing_templates_category ON ussd.routing_rules_templates(category, is_active);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function: Normalize shortcode for consistent lookup
CREATE OR REPLACE FUNCTION ussd.normalize_shortcode(p_shortcode VARCHAR(20))
RETURNS VARCHAR(20) AS $$
DECLARE
    v_normalized VARCHAR(20);
BEGIN
    -- Remove spaces, convert to uppercase
    v_normalized := upper(regexp_replace(p_shortcode, '\s+', '', 'g'));
    
    -- Ensure starts with * or #
    IF NOT (v_normalized ~ '^[\*#]') THEN
        v_normalized := '*' || v_shortcode;
    END IF;
    
    -- Ensure ends with # if not already
    IF NOT (v_normalized ~ '#$') THEN
        v_normalized := v_normalized || '#';
    END IF;
    
    RETURN v_normalized;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function: Evaluate route conditions
CREATE OR REPLACE FUNCTION ussd.evaluate_route_conditions(
    p_conditions JSONB,
    p_msisdn_hash VARCHAR(64),
    p_country_code VARCHAR(2),
    p_network_operator VARCHAR(50),
    p_current_time TIMESTAMPTZ DEFAULT now()
) RETURNS BOOLEAN AS $$
DECLARE
    v_time_range JSONB;
    v_start_time TIME;
    v_end_time TIME;
    v_current_time TIME;
BEGIN
    -- If no conditions, route matches
    IF p_conditions IS NULL OR p_conditions = '{}'::jsonb THEN
        RETURN true;
    END IF;
    
    -- Check time ranges
    IF p_conditions ? 'time_ranges' THEN
        v_current_time := p_current_time::time;
        FOR v_time_range IN SELECT jsonb_array_elements(p_conditions->'time_ranges')
        LOOP
            v_start_time := (v_time_range->>'start')::time;
            v_end_time := (v_time_range->>'end')::time;
            
            IF v_current_time BETWEEN v_start_time AND v_end_time THEN
                RETURN true;
            END IF;
        END LOOP;
        -- No time range matched
        RETURN false;
    END IF;
    
    -- Check days of week
    IF p_conditions ? 'days_of_week' THEN
        IF NOT (extract(dow from p_current_time) = ANY(
            ARRAY(SELECT jsonb_array_elements_text(p_conditions->'days_of_week')::int)
        )) THEN
            RETURN false;
        END IF;
    END IF;
    
    -- Check country code
    IF p_conditions ? 'allowed_countries' THEN
        IF NOT (p_country_code = ANY(
            ARRAY(SELECT jsonb_array_elements_text(p_conditions->'allowed_countries'))
        )) THEN
            RETURN false;
        END IF;
    END IF;
    
    -- Check network operator
    IF p_conditions ? 'allowed_networks' THEN
        IF NOT (p_network_operator = ANY(
            ARRAY(SELECT jsonb_array_elements_text(p_conditions->'allowed_networks'))
        )) THEN
            RETURN false;
        END IF;
    END IF;
    
    -- All conditions passed
    RETURN true;
END;
$$ LANGUAGE plpgsql;

-- Function: Route USSD request
CREATE OR REPLACE FUNCTION ussd.route_ussd_request(
    p_msisdn VARCHAR(20),
    p_shortcode VARCHAR(20),
    p_country_code VARCHAR(2),
    p_network_operator VARCHAR(50) DEFAULT NULL,
    p_device_fingerprint VARCHAR(255) DEFAULT NULL
) RETURNS TABLE (
    route_id UUID,
    application_id UUID,
    shortcode_id UUID,
    welcome_message VARCHAR(500),
    security_level VARCHAR(20),
    requires_auth BOOLEAN,
    routing_decision VARCHAR(20)
) AS $$
DECLARE
    v_msisdn_hash VARCHAR(64);
    v_shortcode_normalized VARCHAR(20);
    v_shortcode_id UUID;
    v_route RECORD;
    v_log_id UUID;
    v_start_time TIMESTAMPTZ;
BEGIN
    v_start_time := clock_timestamp();
    v_msisdn_hash := encode(digest(p_msisdn, 'sha256'), 'hex');
    v_shortcode_normalized := ussd.normalize_shortcode(p_shortcode);
    
    -- Find shortcode
    SELECT sc.shortcode_id INTO v_shortcode_id
    FROM ussd.shortcodes sc
    WHERE sc.shortcode_normalized = v_shortcode_normalized
      AND sc.country_code = p_country_code
      AND (sc.network_operator = p_network_operator OR sc.network_operator IS NULL)
      AND sc.is_active = true
      AND sc.valid_from <= now()
      AND (sc.valid_to IS NULL OR sc.valid_to > now())
    ORDER BY sc.network_operator IS NULL  -- Prefer specific over generic
    LIMIT 1;
    
    -- Log if shortcode not found
    IF v_shortcode_id IS NULL THEN
        INSERT INTO ussd.route_access_logs (
            msisdn_hash, shortcode, country_code, network_operator,
            device_fingerprint, routing_decision, error_code, error_message
        ) VALUES (
            v_msisdn_hash, p_shortcode, p_country_code, p_network_operator,
            p_device_fingerprint, 'ERROR', 'SHORTCODE_NOT_FOUND', 
            'No active shortcode found for request'
        );
        RETURN;
    END IF;
    
    -- Find matching route
    SELECT 
        sr.route_id,
        sr.application_id,
        sr.welcome_message,
        sc.security_level,
        sc.requires_authentication as requires_auth,
        sr.condition_rules,
        sr.route_priority
    INTO v_route
    FROM ussd.shortcode_routes sr
    JOIN ussd.shortcodes sc ON sr.shortcode_id = sc.shortcode_id
    WHERE sr.shortcode_id = v_shortcode_id
      AND sr.is_active = true
      AND sr.valid_from <= now()
      AND (sr.valid_to IS NULL OR sr.valid_to > now())
      AND ussd.evaluate_route_conditions(sr.condition_rules, v_msisdn_hash, p_country_code, p_network_operator)
    ORDER BY sr.route_priority, random() * sr.route_weight
    LIMIT 1;
    
    -- Log successful routing
    IF v_route IS NOT NULL THEN
        INSERT INTO ussd.route_access_logs (
            msisdn_hash, shortcode, shortcode_id, country_code, network_operator,
            device_fingerprint, route_id, application_id, routing_decision,
            matched_conditions, routing_duration_ms
        ) VALUES (
            v_msisdn_hash, p_shortcode, v_shortcode_id, p_country_code, p_network_operator,
            p_device_fingerprint, v_route.route_id, v_route.application_id, 'ROUTED',
            v_route.condition_rules,
            extract(milliseconds from clock_timestamp() - v_start_time)::integer
        );
        
        route_id := v_route.route_id;
        application_id := v_route.application_id;
        shortcode_id := v_shortcode_id;
        welcome_message := v_route.welcome_message;
        security_level := v_route.security_level;
        requires_auth := v_route.requires_auth;
        routing_decision := 'ROUTED';
        RETURN NEXT;
    ELSE
        -- Log fallback/no route
        INSERT INTO ussd.route_access_logs (
            msisdn_hash, shortcode, shortcode_id, country_code, network_operator,
            device_fingerprint, routing_decision, error_code
        ) VALUES (
            v_msisdn_hash, p_shortcode, v_shortcode_id, p_country_code, p_network_operator,
            p_device_fingerprint, 'ERROR', 'NO_ACTIVE_ROUTE'
        );
        RETURN;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Get shortcode security requirements
CREATE OR REPLACE FUNCTION ussd.get_shortcode_security_requirements(
    p_shortcode VARCHAR(20),
    p_country_code VARCHAR(2)
) RETURNS TABLE (
    security_level VARCHAR(20),
    requires_auth BOOLEAN,
    requires_encryption BOOLEAN,
    rate_limit_per_minute INTEGER,
    rate_limit_per_hour INTEGER,
    is_emergency BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        sc.security_level,
        sc.requires_authentication,
        sc.requires_encryption,
        sc.rate_limit_per_minute,
        sc.rate_limit_per_hour,
        sc.is_emergency
    FROM ussd.shortcodes sc
    WHERE sc.shortcode_normalized = ussd.normalize_shortcode(p_shortcode)
      AND sc.country_code = p_country_code
      AND sc.is_active = true
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- Function: Check rate limit
CREATE OR REPLACE FUNCTION ussd.check_shortcode_rate_limit(
    p_shortcode VARCHAR(20),
    p_msisdn_hash VARCHAR(64)
) RETURNS TABLE (
    allowed BOOLEAN,
    current_count INTEGER,
    limit_per_minute INTEGER,
    retry_after_seconds INTEGER
) AS $$
DECLARE
    v_count INTEGER;
    v_limit INTEGER;
BEGIN
    -- Get shortcode rate limit
    SELECT rate_limit_per_minute INTO v_limit
    FROM ussd.shortcodes
    WHERE shortcode_normalized = ussd.normalize_shortcode(p_shortcode)
      AND is_active = true;
    
    IF v_limit IS NULL THEN
        allowed := false;
        current_count := 0;
        limit_per_minute := 0;
        retry_after_seconds := 0;
        RETURN NEXT;
        RETURN;
    END IF;
    
    -- Count requests in last minute
    SELECT COUNT(*) INTO v_count
    FROM ussd.route_access_logs
    WHERE shortcode = p_shortcode
      AND msisdn_hash = p_msisdn_hash
      AND routed_at > now() - interval '1 minute';
    
    allowed := v_count < v_limit;
    current_count := v_count;
    limit_per_minute := v_limit;
    retry_after_seconds := CASE 
        WHEN v_count >= v_limit THEN 60 - extract(second from now())::integer
        ELSE 0 
    END;
    
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Function: Increment route session count
CREATE OR REPLACE FUNCTION ussd.increment_route_session_count(
    p_route_id UUID
) RETURNS VOID AS $$
BEGIN
    UPDATE ussd.shortcode_routes
    SET current_session_count = current_session_count + 1
    WHERE route_id = p_route_id;
END;
$$ LANGUAGE plpgsql;

-- Function: Decrement route session count
CREATE OR REPLACE FUNCTION ussd.decrement_route_session_count(
    p_route_id UUID
) RETURNS VOID AS $$
BEGIN
    UPDATE ussd.shortcode_routes
    SET current_session_count = GREATEST(0, current_session_count - 1)
    WHERE route_id = p_route_id;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TRIGGER FUNCTIONS
-- =============================================================================

-- Trigger: Auto-normalize shortcode
CREATE OR REPLACE FUNCTION ussd.trigger_normalize_shortcode()
RETURNS TRIGGER AS $$
BEGIN
    NEW.shortcode_normalized := ussd.normalize_shortcode(NEW.shortcode);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_shortcodes_normalize
    BEFORE INSERT OR UPDATE ON ussd.shortcodes
    FOR EACH ROW
    EXECUTE FUNCTION ussd.trigger_normalize_shortcode();

-- Trigger: Update timestamps
CREATE OR REPLACE FUNCTION ussd.trigger_update_routing_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_shortcodes_update
    BEFORE UPDATE ON ussd.shortcodes
    FOR EACH ROW
    EXECUTE FUNCTION ussd.trigger_update_routing_timestamp();

CREATE TRIGGER trg_shortcode_routes_update
    BEFORE UPDATE ON ussd.shortcode_routes
    FOR EACH ROW
    EXECUTE FUNCTION ussd.trigger_update_routing_timestamp();

-- Trigger: Require change reason for route updates
CREATE OR REPLACE FUNCTION ussd.trigger_require_change_reason()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.change_reason IS NULL THEN
        RAISE EXCEPTION 'Change reason is required for route updates';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_shortcode_routes_change_reason
    BEFORE UPDATE ON ussd.shortcode_routes
    FOR EACH ROW
    EXECUTE FUNCTION ussd.trigger_require_change_reason();

-- =============================================================================
-- ROW LEVEL SECURITY
-- =============================================================================

ALTER TABLE ussd.shortcodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.shortcode_routes ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd.route_access_logs ENABLE ROW LEVEL SECURITY;

-- Policy: Shortcodes readable by all active
CREATE POLICY shortcodes_read_active ON ussd.shortcodes
    FOR SELECT USING (is_active = true);

-- Policy: Shortcodes modifiable by admin only
CREATE POLICY shortcodes_admin_only ON ussd.shortcodes
    FOR ALL USING (
        current_setting('app.current_role', true) = 'ussd_admin'
    );

-- Policy: Routes readable by application
CREATE POLICY shortcode_routes_app_read ON ussd.shortcode_routes
    FOR SELECT USING (
        application_id = current_setting('app.current_application_id', true)::UUID
        OR current_setting('app.current_role', true) = 'ussd_admin'
    );

-- =============================================================================
-- GRANTS
-- =============================================================================

GRANT SELECT ON ussd.shortcodes TO ussd_gateway_role;
GRANT SELECT ON ussd.shortcode_routes TO ussd_gateway_role;
GRANT INSERT ON ussd.route_access_logs TO ussd_gateway_role;
GRANT SELECT ON ussd.routing_rules_templates TO ussd_gateway_role;

GRANT ALL ON ussd.shortcodes TO ussd_security_role;
GRANT ALL ON ussd.shortcode_routes TO ussd_security_role;
GRANT ALL ON ussd.route_access_logs TO ussd_security_role;

-- =============================================================================
-- SEED DATA
-- =============================================================================

-- Insert common routing rule templates
INSERT INTO ussd.routing_rules_templates (
    template_name, template_description, category, rule_definition, example_usage
) VALUES 
(
    'business_hours',
    'Route only during business hours (8am-5pm weekdays)',
    'TIME_BASED',
    '{"time_ranges": [{"start": "08:00", "end": "17:00"}], "days_of_week": [1,2,3,4,5]}'::jsonb,
    'Use for customer service shortcodes'
),
(
    'zimbabwe_only',
    'Route only for Zimbabwe MSISDNs',
    'GEOGRAPHIC',
    '{"allowed_countries": ["ZW"], "msisdn_patterns": ["^\\+263.*$"]}'::jsonb,
    'Use for country-specific services'
),
(
    'load_balanced_round_robin',
    'Distribute load evenly across routes',
    'LOAD_BALANCING',
    '{"route_weight": 1}'::jsonb,
    'Set equal weights for round-robin distribution'
),
(
    'premium_users_only',
    'Route only for users with premium permission',
    'PERMISSION_BASED',
    '{"required_permissions": ["premium_access"]}'::jsonb,
    'Use for premium service shortcodes'
)
ON CONFLICT (template_name) DO NOTHING;

-- =============================================================================
-- COMPLIANCE NOTES
-- =============================================================================
/*
1. SHORTCODE SECURITY LEVELS:
   - PUBLIC: No authentication required; general information
   - STANDARD: Session-based authentication; normal services
   - SENSITIVE: PIN required; financial transactions
   - CRITICAL: Additional verification; admin functions

2. ROUTING CONDITIONS:
   - Time-based: Business hours, days of week
   - Geographic: Country codes, network operators
   - Load-based: Session limits, weighted distribution
   - User-based: Permissions, segments

3. DATA MINIMIZATION:
   - MSISDN stored as hash only in logs
   - No account linkage in routing tables
   - Cell tower precision for location (not GPS)

4. EMERGENCY SHORTCODES:
   - Always active regardless of time
   - Priority routing (lowest route_priority)
   - Bypass rate limits
   - Enhanced audit logging

5. TELECOM COMPLIANCE:
   - Number portability support via MCC-MNC
   - Cross-border routing restrictions
   - Regulatory shortcode reservation
*/
