-- ============================================================================
-- USSD SHORTCODE ROUTING CONFIGURATION
-- ============================================================================
-- Purpose: Map USSD shortcodes (*123#, *123*1#, etc.) to applications and
--          manage routing rules for the gateway layer.
-- Context: Shortcodes are the entry points for USSD services. They can be:
--          - Single level: *123# (main menu)
--          - Multi-level: *123*1*456# (deep link to specific function)
--          - Hierarchical: *123# -> option 1 -> option 2
--
-- COMPLIANCE & STANDARDS:
--   ISO/IEC 27001:2022 - Information Security Management
--     * A.8.22: Web filtering and secure routing configuration
--     * A.8.23: Web application security (SSRF prevention in endpoints)
--     * A.8.11: Secure session timeout configuration per route
--     * A.8.7: Malware protection (input validation on route conditions)
--
--   ISO/IEC 27018:2019 - PII Protection
--     * Route conditions must not store unencrypted PII
--     * MSISDN prefix whitelisting pseudonymization
--
--   ISO 31000:2018 - Risk Management
--     * Risk-based authentication requirements per route
--     * Velocity limits enforcement per shortcode
--     * Canary deployment for risk mitigation
--
--   PCI DSS v4.0:
--     * Strong authentication for payment routes (required_auth_level)
--     * Access controls for sensitive route changes
--
-- TELECOM CONTEXT:
--   - Shortcodes are leased from regulators (e.g., *123# costs $X/month)
--   - Some operators support wildcards (*123*)
--   - Shortcodes may be shared across operators or operator-specific
--
-- SECURITY REQUIREMENTS:
--   - SSRF prevention: application_endpoint whitelist validation
--   - Rate limiting configuration per route
--   - Dual authorization for sensitive route changes
--   - Configuration hash chain for tamper detection
-- ============================================================================

-- ----------------------------------------------------------------------------
-- TABLE: shortcode_routing
-- ----------------------------------------------------------------------------
-- Defines routing rules for USSD shortcodes to backend applications.
-- Supports complex routing logic including operator-specific rules,
-- time-based routing, and load balancing.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS shortcode_routing (
    -- Primary identifier
    route_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Shortcode pattern (may include wildcards for advanced routing)
    -- Examples: '*123#', '*123*1#', '*123*#' (wildcard)
    shortcode_pattern VARCHAR(50) NOT NULL,
    
    -- Normalized shortcode (base code without parameters)
    -- Example: '*123*1*456#' -> '*123#'
    base_shortcode VARCHAR(20) NOT NULL,
    
    -- Operator filter (NULL = all operators)
    operator_code VARCHAR(6),
    
    -- Target application identifier
    application_id VARCHAR(64) NOT NULL,
    
    -- Application endpoint (URL or internal service name)
    application_endpoint VARCHAR(512) NOT NULL,
    
    -- Routing method: DIRECT, LOAD_BALANCED, CANARY, A_B_TEST
    routing_method VARCHAR(20) DEFAULT 'DIRECT',
    
    -- Priority for route matching (higher = checked first)
    match_priority INT DEFAULT 100,
    
    -- Route conditions (JSON for complex rules)
    -- Example: {"time_range": "08:00-18:00", "whitelist_msisdn_prefix": ["+25571"]}
    route_conditions JSONB DEFAULT '{}',
    
    -- Load balancing weights (for LOAD_BALANCED routing)
    lb_weight INT DEFAULT 100 CHECK (lb_weight >= 0 AND lb_weight <= 1000),
    
    -- Feature flags for this route
    features_enabled JSONB DEFAULT '[]',
    -- Example: ["biometric_auth", "qr_code", "offline_mode"]
    
    -- Rate limiting configuration
    rate_limit_requests_per_minute INT DEFAULT 60,
    rate_limit_burst INT DEFAULT 10,
    
    -- Session configuration
    session_timeout_seconds INT DEFAULT 90,
    max_session_duration_seconds INT DEFAULT 600, -- 10 minutes absolute max
    allow_concurrent_sessions BOOLEAN DEFAULT FALSE,
    
    -- Authentication requirements
    required_auth_level VARCHAR(16) DEFAULT 'NONE',
    -- NONE, ANONYMOUS, PIN, OTP, BIOMETRIC
    
    -- Menu configuration reference
    default_menu_id VARCHAR(64),
    
    -- Response templates
    welcome_message TEXT,
    timeout_message TEXT,
    error_message TEXT,
    
    -- Status and lifecycle
    is_active BOOLEAN DEFAULT TRUE,
    effective_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    effective_to TIMESTAMPTZ,
    
    -- Audit fields
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(128) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by VARCHAR(128) NOT NULL,
    version INT DEFAULT 1,
    
    -- Immutable ledger tracking
    config_hash VARCHAR(64), -- SHA-256 of configuration for audit
    change_sequence BIGINT, -- Position in configuration changelog
    
    -- Constraints
    CONSTRAINT valid_shortcode_format CHECK (
        shortcode_pattern ~ '^\*[0-9]+([*][0-9#*]*)?#$'
    ),
    CONSTRAINT valid_base_shortcode CHECK (
        base_shortcode ~ '^\*[0-9]+#$'
    ),
    CONSTRAINT valid_routing_method CHECK (
        routing_method IN ('DIRECT', 'LOAD_BALANCED', 'CANARY', 'A_B_TEST', 'FAILOVER')
    ),
    CONSTRAINT valid_effective_dates CHECK (
        effective_to IS NULL OR effective_to > effective_from
    ),
    CONSTRAINT valid_session_timeouts CHECK (
        session_timeout_seconds > 0 AND 
        session_timeout_seconds <= max_session_duration_seconds AND
        max_session_duration_seconds <= 3600 -- Max 1 hour
    ),
    CONSTRAINT valid_required_auth CHECK (
        required_auth_level IN ('NONE', 'ANONYMOUS', 'PIN', 'OTP', 'BIOMETRIC', 'HARDWARE_TOKEN')
    ),
    
    -- Unique constraint for route matching order
    UNIQUE(shortcode_pattern, operator_code, match_priority)
);

-- ----------------------------------------------------------------------------
-- TABLE: shortcode_routing_history
-- ----------------------------------------------------------------------------
-- Immutable audit log of all routing configuration changes.
-- Required for compliance and rollback capabilities.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS shortcode_routing_history (
    history_id BIGSERIAL PRIMARY KEY,
    route_id UUID NOT NULL,
    change_type VARCHAR(10) NOT NULL, -- CREATE, UPDATE, DELETE, ACTIVATE, DEACTIVATE
    
    -- Full snapshot of configuration at this point in time
    configuration_snapshot JSONB NOT NULL,
    
    -- Change metadata
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by VARCHAR(128) NOT NULL,
    change_reason TEXT,
    
    -- Approval workflow (for sensitive changes)
    approved_by VARCHAR(128),
    approved_at TIMESTAMPTZ,
    
    -- Hash chain for tamper detection
    previous_hash VARCHAR(64),
    snapshot_hash VARCHAR(64) NOT NULL,
    
    -- Foreign key (optional, routes may be hard-deleted)
    -- CONSTRAINT fk_route FOREIGN KEY (route_id) REFERENCES shortcode_routing(route_id)
);

-- ----------------------------------------------------------------------------
-- TABLE: routing_metrics
-- ----------------------------------------------------------------------------
-- Aggregated metrics for routing performance monitoring.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS routing_metrics (
    metric_id BIGSERIAL PRIMARY KEY,
    route_id UUID NOT NULL,
    aggregation_period TIMESTAMPTZ NOT NULL, -- Hourly buckets
    
    -- Request metrics
    total_requests BIGINT DEFAULT 0,
    successful_requests BIGINT DEFAULT 0,
    failed_requests BIGINT DEFAULT 0,
    timeout_requests BIGINT DEFAULT 0,
    
    -- Response time metrics (in milliseconds)
    avg_response_time_ms INT,
    p50_response_time_ms INT,
    p95_response_time_ms INT,
    p99_response_time_ms INT,
    max_response_time_ms INT,
    
    -- Error breakdown
    error_4xx_count BIGINT DEFAULT 0,
    error_5xx_count BIGINT DEFAULT 0,
    network_error_count BIGINT DEFAULT 0,
    
    -- Session metrics
    sessions_created BIGINT DEFAULT 0,
    sessions_completed BIGINT DEFAULT 0,
    sessions_timeout BIGINT DEFAULT 0,
    
    -- Created at (for this record)
    recorded_at TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE(route_id, aggregation_period)
);

-- ----------------------------------------------------------------------------
-- TODO: IMPLEMENTATION INSTRUCTIONS
-- ----------------------------------------------------------------------------

/*
TODO [ROUTING-001]: Implement shortcode pattern matching function
  - Support wildcard matching: '*123*#' matches '*123*1#', '*123*2*5#'
  - Support parameter extraction: '*123*AMOUNT*PIN#' -> extract AMOUNT, PIN
  - Priority-based matching: More specific patterns match first
  
  Implementation in 000_resolve_shortcode.sql:
  ```sql
  CREATE OR REPLACE FUNCTION resolve_shortcode(
    p_ussd_string VARCHAR,
    p_operator_code VARCHAR
  ) RETURNS TABLE (...)
  ```

TODO [ROUTING-002]: Implement configuration change approval workflow
  - Sensitive routes (financial services) require dual authorization
  - Changes must be staged before activation
  - Automatic rollback on error rate spike
  
  Workflow states: DRAFT -> PENDING_APPROVAL -> APPROVED -> ACTIVE

TODO [ROUTING-003]: Implement canary deployment support
  - Gradual traffic shift: 1% -> 5% -> 25% -> 100%
  - Automatic rollback if error rate > threshold
  - Route based on MSISDN hash for consistent user experience
  
  Add columns:
    canary_percentage DECIMAL(5,2) DEFAULT 0,
    canary_msisdn_ranges TEXT[], -- ['+255700000000-+255799999999']

TODO [ROUTING-004]: Implement circuit breaker pattern
  - Track application health in routing_metrics
  - Auto-disable route if failure rate > threshold (e.g., 50%)
  - Exponential backoff for retries
  
  Add columns:
    circuit_breaker_threshold DECIMAL(3,2) DEFAULT 0.50,
    circuit_breaker_cooldown_seconds INT DEFAULT 60,
    last_failure_at TIMESTAMPTZ,
    consecutive_failures INT DEFAULT 0

TODO [ROUTING-005]: Implement multi-region routing
  - Geographic routing based on MSISDN prefix
  - Disaster recovery failover to secondary region
  - Data residency compliance (store EU data in EU)
  
  Add columns:
    primary_region VARCHAR(32),
    failover_region VARCHAR(32),
    data_residency_requirement VARCHAR(32)

TODO [ROUTING-006]: Implement A/B testing framework
  - Route traffic to different application versions
  - Track conversion metrics per variant
  - Automatic winner selection based on statistical significance
  
  Add columns:
    ab_test_variant VARCHAR(32), -- 'control', 'variant_a'
    ab_test_config JSONB
*/

-- ----------------------------------------------------------------------------
-- SECURITY CONSIDERATIONS
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.22 - Web filtering and secure routing
-- [ISO/IEC 27001:2022] A.8.23 - SSRF prevention
-- [ISO/IEC 27018:2019] PII protection in route conditions
-- [ISO 31000:2018] Risk-based authentication requirements
/*
1. CONFIGURATION INJECTION:
   - Validate all route_conditions JSONB against schema
   - Sanitize application_endpoint (whitelist allowed protocols)
   - Never allow file:// or other dangerous protocols

2. SSRF PREVENTION:
   - Restrict application_endpoint to internal service mesh
   - Validate endpoints don't point to metadata services (169.254.169.254)
   - Use service mesh sidecars for external calls

3. RATE LIMITING:
   - Enforce rate_limit_requests_per_minute at gateway layer
   - Per-MSISDN rate limiting (prevent enumeration attacks)
   - Global rate limiting per shortcode

4. AUTHENTICATION BYPASS:
   - required_auth_level must be enforced at gateway, not just application
   - Never downgrade authentication requirements dynamically
   - Log all authentication requirement changes to SIEM

5. CONFIGURATION TAMPERING:
   - All changes logged to shortcode_routing_history
   - Hash chain prevents undetected modifications
   - Regular integrity audits of configuration
*/

-- ----------------------------------------------------------------------------
-- SESSION TIMEOUT HANDLING
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.11 - Per-route timeout configuration
-- [PCI DSS v4.0] Payment route timeout restrictions
-- Risk-based timeout adjustment
/*
Per-route timeout configuration:

1. SHORTCODE-SPECIFIC TIMEOUTS:
   - Financial services: 120s (user needs time to verify)
   - Information services: 30s (quick lookups)
   - Registration flows: 300s (may require external verification)

2. DYNAMIC TIMEOUT ADJUSTMENT:
   - Extend timeout during PIN entry (security pause)
   - Reduce timeout for sensitive operations (faster expiration)
   - Maximum extension: 3x base timeout

3. CONCURRENT SESSION HANDLING:
   - allow_concurrent_sessions = FALSE:
     * Terminate existing session on new request
     * Notify user of previous session termination
   - allow_concurrent_sessions = TRUE:
     * Limit to maximum 3 concurrent sessions per MSISDN
     * Require session ID differentiation

4. IDLE DETECTION:
   - Track last activity per session
   - Warning at 80% of session_timeout_seconds
   - Force termination at 100% (no grace period for USSD)
*/

-- ----------------------------------------------------------------------------
-- SIM SWAP DETECTION LOGIC
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27035-2:2023] SIM swap detection integration
-- [ISO 31000:2018] Risk-based route restrictions
-- Post-swap routing: Enhanced verification routes
-- GSMA IR.71 compliance for swap detection
/*
Shortcode routing can be used to trigger SIM swap detection:

1. SENSITIVE ROUTE PROTECTION:
   - High-value transaction shortcodes (*123*5# for transfers)
   - First-time device detection triggers additional verification
   - Mandatory 24h cooling period for new device + high-value

2. ROUTE-BASED SIM SWAP CHECKS:
   - Add sim_swap_required BOOLEAN to routing table
   - When TRUE, query SIM swap detection before allowing access
   - Route to verification flow if swap detected within 72h

3. DYNAMIC ROUTING BASED ON RISK:
   - Low risk: Normal flow
   - Medium risk: Additional PIN required
   - High risk: Block, require in-branch verification
   
   Risk calculation in 002_detect_sim_swap.sql
*/

-- ----------------------------------------------------------------------------
-- INDEXES
-- ----------------------------------------------------------------------------

-- Fast lookup for active routes by shortcode
CREATE INDEX idx_routing_active_shortcode 
    ON shortcode_routing(base_shortcode, is_active, match_priority DESC);

-- Operator-specific route lookup
CREATE INDEX idx_routing_operator 
    ON shortcode_routing(operator_code, base_shortcode, is_active);

-- Time-based route validity
CREATE INDEX idx_routing_effective_dates 
    ON shortcode_routing(effective_from, effective_to) 
    WHERE effective_to IS NOT NULL;

-- History lookup for audit
CREATE INDEX idx_routing_history_route 
    ON shortcode_routing_history(route_id, changed_at DESC);

-- Metrics aggregation queries
CREATE INDEX idx_routing_metrics_period 
    ON routing_metrics(route_id, aggregation_period DESC);

-- ----------------------------------------------------------------------------
-- SAMPLE DATA (Development/Testing Only)
-- ----------------------------------------------------------------------------

/*
INSERT INTO shortcode_routing (
    shortcode_pattern, base_shortcode, operator_code,
    application_id, application_endpoint, routing_method,
    created_by, updated_by
) VALUES 
    ('*150#', '*150#', NULL, 'mobile_money', 'http://mm-service:8080/ussd', 'DIRECT', 'admin', 'admin'),
    ('*150*1#', '*150#', NULL, 'mobile_money', 'http://mm-service:8080/ussd', 'DIRECT', 'admin', 'admin'),
    ('*151#', '*151#', '64002', 'banking', 'http://bank-service:8080/ussd', 'LOAD_BALANCED', 'admin', 'admin');
*/
