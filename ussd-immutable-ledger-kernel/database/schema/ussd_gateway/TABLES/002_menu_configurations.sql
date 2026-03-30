-- ============================================================================
-- USSD MENU CONFIGURATION
-- ============================================================================
-- Purpose: Define USSD menu trees and navigation flows for interactive sessions.
-- Context: USSD menus are text-based, hierarchical interfaces presented as:
--          numbered lists (1. Check Balance, 2. Send Money, etc.)
--          with support for input fields and confirmation dialogs.
--
-- COMPLIANCE & STANDARDS:
--   ISO/IEC 27001:2022 - Information Security Management
--     * A.8.1: Endpoint security - menu-level PIN requirements
--     * A.8.5: Secure authentication for sensitive operations
--     * A.8.12: Audit logging for menu navigation (audit_log_view flag)
--     * A.8.16: Monitoring activities via menu analytics
--
--   ISO/IEC 27018:2019 - PII Protection
--     * Dynamic content config must not expose raw PII in templates
--     * Mask MSISDN in menu content ({{recipient_msisdn}} sanitized)
--     * Anonymize navigation analytics data
--
--   ISO 31000:2018 - Risk Management
--     * Risk-based menu access (sensitive_input flag)
--     * SIM swap detection integration for high-risk menus
--     * Behavioral biometrics tracking for anomaly detection
--
--   GDPR Compliance:
--     * User consent tracking for menu preferences
--     * Right to erasure: menu history anonymization
--
-- MENU CHARACTERISTICS:
--   - Limited to ~160-182 characters per screen (SMS-like constraints)
--   - No graphics, only text and basic formatting
--   - Navigation via number selection or shortcodes
--   - Support for "back" (0), "home" (#), and language switching
--
-- SECURITY FEATURES:
--   - require_pin: Enforces authentication before menu access
--   - sensitive_input: Masks user input (PIN entry screens)
--   - audit_log_view: All navigation logged for compliance
--   - Circular navigation prevention (depth tracking)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- TABLE: menu_configurations
-- ----------------------------------------------------------------------------
-- Stores menu definitions with multi-language support and dynamic content.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS menu_configurations (
    menu_id VARCHAR(64) PRIMARY KEY,
    
    -- Human-readable name for administration
    menu_name VARCHAR(128) NOT NULL,
    
    -- Application this menu belongs to
    application_id VARCHAR(64) NOT NULL,
    
    -- Menu type determines rendering and behavior
    menu_type VARCHAR(32) NOT NULL DEFAULT 'LIST',
    -- LIST: Numbered options (1. Option A, 2. Option B)
    -- INPUT: Free text input (Enter amount:)
    -- CONFIRM: Yes/No confirmation (Send X to Y? 1. Yes 2. No)
    -- DISPLAY: Information only (Your balance is...)
    -- PIN: PIN entry screen (masked input)
    -- LANGUAGE: Language selection menu
    -- ERROR: Error display with retry options
    
    -- Parent menu for hierarchical navigation (NULL = root)
    parent_menu_id VARCHAR(64),
    
    -- Menu position in parent (for ordering)
    display_order INT DEFAULT 0,
    
    -- Menu content with i18n support
    -- Structure: {"en": "...", "sw": "...", "fr": "..."}
    content_i18n JSONB NOT NULL DEFAULT '{}',
    
    -- Default language code
    default_language VARCHAR(5) DEFAULT 'en',
    
    -- Supported languages for this menu
    supported_languages TEXT[] DEFAULT ARRAY['en'],
    
    -- Dynamic content configuration
    -- References to external data sources for real-time content
    dynamic_content_config JSONB DEFAULT NULL,
    -- Example: {"type": "api", "endpoint": "/balance/{msisdn}", "cache_ttl": 30}
    
    -- Navigation rules
    -- Maps user input to next menu or action
    -- Structure: {"1": "menu:send_money", "2": "menu:check_balance", "0": "back", "#": "home"}
    navigation_rules JSONB NOT NULL DEFAULT '{}',
    
    -- Input validation rules (for INPUT type menus)
    -- Structure: {"type": "amount", "min": 100, "max": 1000000, "regex": "^[0-9]+$"}
    input_validation JSONB DEFAULT NULL,
    
    -- Action to execute when menu is displayed
    -- Structure: {"type": "log", "event": "menu_viewed"} or 
    --           {"type": "api", "endpoint": "/pre-fetch-data"}
    on_display_action JSONB DEFAULT NULL,
    
    -- Action to execute on user input
    -- Structure: {"type": "validate_pin", "next_success": "menu:confirm", "next_fail": "menu:error"}
    on_input_action JSONB DEFAULT NULL,
    
    -- Session context updates on navigation
    -- Structure: {"set": {"last_menu": "@menu_id"}, "clear": ["temp_input"]}
    context_updates JSONB DEFAULT NULL,
    
    -- Timeout behavior for this specific menu
    timeout_seconds INT, -- NULL = use route default
    timeout_menu_id VARCHAR(64), -- Where to go on timeout
    
    -- Error handling
    error_menu_id VARCHAR(64), -- Where to go on processing error
    invalid_input_message_i18n JSONB DEFAULT '{}', -- Custom error per menu
    
    -- Security settings
    require_pin BOOLEAN DEFAULT FALSE,
    sensitive_input BOOLEAN DEFAULT FALSE, -- Mask input (PIN entry)
    audit_log_view BOOLEAN DEFAULT TRUE, -- Log menu views
    
    -- UI formatting
    header_text_i18n JSONB DEFAULT '{}', -- Persistent header
    footer_text_i18n JSONB DEFAULT '{}', -- Persistent footer (e.g., "0. Back")
    separator_line VARCHAR(10) DEFAULT '-', -- Between header and content
    
    -- A/B testing support
    ab_test_variant VARCHAR(32) DEFAULT 'control',
    
    -- Status and lifecycle
    is_active BOOLEAN DEFAULT TRUE,
    effective_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    effective_to TIMESTAMPTZ,
    
    -- Version control
    version INT DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(128) NOT NULL,
    updated_by VARCHAR(128) NOT NULL,
    
    -- Configuration hash for audit
    config_hash VARCHAR(64),
    
    -- Constraints
    CONSTRAINT valid_menu_type CHECK (
        menu_type IN ('LIST', 'INPUT', 'CONFIRM', 'DISPLAY', 'PIN', 'LANGUAGE', 'ERROR', 'TERMINAL')
    ),
    CONSTRAINT valid_ab_test_variant CHECK (
        ab_test_variant IN ('control', 'variant_a', 'variant_b', 'variant_c')
    ),
    CONSTRAINT valid_display_order CHECK (display_order >= 0),
    CONSTRAINT valid_timeout CHECK (timeout_seconds IS NULL OR timeout_seconds > 0),
    
    -- Self-referential foreign key (enforced via trigger for circular prevention)
    CONSTRAINT valid_parent_menu CHECK (parent_menu_id IS NULL OR parent_menu_id != menu_id)
);

-- ----------------------------------------------------------------------------
-- TABLE: menu_navigation_history
-- ----------------------------------------------------------------------------
-- Audit log of user navigation through menus for session replay and analytics.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS menu_navigation_history (
    history_id BIGSERIAL PRIMARY KEY,
    session_id UUID NOT NULL,
    
    -- Navigation event
    from_menu_id VARCHAR(64),
    to_menu_id VARCHAR(64),
    user_input VARCHAR(400), -- What user entered/selected
    
    -- Navigation metadata
    navigation_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    navigation_duration_ms INT, -- Time spent on previous menu
    
    -- Context snapshot (for replay)
    context_snapshot JSONB,
    
    -- Device info
    device_fingerprint_id UUID,
    
    -- Audit
    ip_address INET,
    
    -- Indexes on session_id for cleanup
    CONSTRAINT fk_session FOREIGN KEY (session_id) 
        REFERENCES ussd_session_state(session_id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------------------
-- TABLE: menu_analytics
-- ----------------------------------------------------------------------------
-- Aggregated analytics for menu optimization.
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS menu_analytics (
    analytics_id BIGSERIAL PRIMARY KEY,
    menu_id VARCHAR(64) NOT NULL,
    aggregation_date DATE NOT NULL,
    
    -- Usage metrics
    total_views BIGINT DEFAULT 0,
    unique_users BIGINT DEFAULT 0,
    
    -- Navigation metrics
    total_navigations BIGINT DEFAULT 0,
    avg_time_on_menu_seconds INT,
    
    -- Input metrics (for INPUT type menus)
    total_inputs BIGINT DEFAULT 0,
    invalid_inputs BIGINT DEFAULT 0,
    avg_input_length INT,
    
    -- Drop-off metrics
    dropoff_count BIGINT DEFAULT 0, -- Sessions ending at this menu
    timeout_count BIGINT DEFAULT 0,
    error_count BIGINT DEFAULT 0,
    
    -- Option popularity (for LIST type menus)
    option_selections JSONB DEFAULT '{}', -- {"1": 500, "2": 300, "3": 200}
    
    -- A/B test metrics
    ab_test_variant VARCHAR(32),
    conversion_rate DECIMAL(5,4), -- Decimal percentage
    
    UNIQUE(menu_id, aggregation_date, ab_test_variant)
);

-- ----------------------------------------------------------------------------
-- TODO: IMPLEMENTATION INSTRUCTIONS
-- ----------------------------------------------------------------------------

/*
TODO [MENU-001]: Implement menu rendering engine
  - Parse content_i18n based on session language preference
  - Apply dynamic content substitution ({{balance}}, {{user_name}})
  - Enforce character limits per screen (typically 160 chars)
  - Handle pagination for long content
  
  Rendering algorithm:
  1. Select language from session context or use default_language
  2. Fetch content: content_i18n->>language
  3. Apply template substitution from context
  4. Execute on_display_action if configured
  5. Format with header/footer/separator
  6. Truncate if exceeds max length with "..." indicator

TODO [MENU-002]: Implement navigation engine
  - Parse navigation_rules JSONB
  - Handle special keywords: "back", "home", "exit", "repeat"
  - Support parameter passing: "menu:confirm?amount={amount}"
  - Validate user input against input_validation rules
  
  Navigation resolution:
  ```
  IF user_input IN navigation_rules:
      target = navigation_rules[user_input]
  ELSE IF input_validation exists:
      IF validate(user_input, input_validation):
          target = on_input_action.next_success
      ELSE:
          target = error_menu_id or current_menu with error
  ELSE:
      target = error_menu_id or default_error
  ```

TODO [MENU-003]: Implement input validation framework
  - Types: amount, phone_number, pin, text, number, date, regex
  - Cross-field validation (e.g., amount <= available_balance)
  - Sanitization: strip non-numeric from phone numbers
  - Localization: decimal separators, date formats
  
  Validation config example:
  {
    "type": "amount",
    "min": 100,
    "max": 1000000,
    "currency": "TZS",
    "step": 100,
    "error_message_i18n": {"en": "Amount must be 100-1,000,000 TZS"}
  }

TODO [MENU-004]: Implement menu caching
  - Cache rendered menus in Redis (TTL: 5 minutes)
  - Cache key: menu_id:language:context_hash
  - Invalidate on menu configuration update
  - Pre-render popular menus during low-traffic periods

TODO [MENU-005]: Implement circular navigation prevention
  - Track visited menus in session context
  - Detect loops (same menu visited > 3 times in 5 minutes)
  - Auto-redirect to home menu on loop detection
  - Alert security team on potential abuse

TODO [MENU-006]: Implement dynamic content fetching
  - Async fetch for balance, transaction history, etc.
  - Circuit breaker for external API calls
  - Fallback content on API failure
  - Cache dynamic content with short TTL

TODO [MENU-007]: Implement menu versioning and rollback
  - All changes create new version
  - Keep last 10 versions per menu
  - Instant rollback to previous version
  - Blue/green deployment support
*/

-- ----------------------------------------------------------------------------
-- SECURITY CONSIDERATIONS
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.1 - Endpoint security (menu-level PIN)
-- [ISO/IEC 27001:2022] A.8.5 - Authentication per menu
-- [ISO/IEC 27001:2022] A.8.12 - Menu navigation audit logging
-- [ISO/IEC 27018:2019] PII masking in menu content
/*
1. INPUT INJECTION:
   - Sanitize all user_input before logging (SQL injection, XSS)
   - Never execute user_input as code
   - Validate against whitelist regex patterns

2. INFORMATION DISCLOSURE:
   - Mask sensitive data in context_snapshot (full msisdn -> +255****1234)
   - Encrypt PIN entry screens with extra security
   - Clear sensitive context after use (single-use tokens)

3. MENU SPOOFING:
   - Sign menu configurations with HMAC
   - Verify config_hash on each render
   - Alert on hash mismatch (potential tampering)

4. ENUMERATION ATTACKS:
   - Rate limit navigation attempts per session
   - Log rapid sequential inputs (1,2,3,4,5...) as potential scanning
   - Implement CAPTCHA-equivalent for suspicious patterns

5. PRIVILEGE ESCALATION:
   - Validate user auth level before rendering protected menus
   - Re-check authorization on each navigation
   - Don't rely on client-side "hidden" menus
*/

-- ----------------------------------------------------------------------------
-- SESSION TIMEOUT HANDLING
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.11 - Menu-specific timeout behaviors
-- [PCI DSS v4.0] PIN entry timeout restrictions (30 sec max)
/*
Menu-specific timeout behaviors:

1. INPUT TYPE TIMEOUTS:
   - PIN entry: 30 seconds (security)
   - Amount entry: 60 seconds (user may need to check)
   - Phone number: 45 seconds
   - Extended for accessibility (elderly users)

2. CONFIRM TYPE TIMEOUTS:
   - Financial transactions: 60 seconds (deliberation time)
   - Non-financial: 30 seconds
   - Show countdown warning at 45 seconds

3. TIMEOUT RECOVERY:
   - Store partial input in context before timeout
   - Offer "resume" option on new session (within 5 minutes)
   - For sensitive operations, require full restart

4. IDLE DETECTION PER MENU:
   - Track keypress timing (if gateway supports)
   - Reset timeout on each keystroke for INPUT menus
   - Fixed timeout for DISPLAY menus
*/

-- ----------------------------------------------------------------------------
-- SIM SWAP DETECTION INTEGRATION
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27035-2:2023] Menu-level SIM swap protection
-- [ISO 31000:2018] Risk-based menu access control
-- Post-swap menu restrictions for 72 hours
/*
Menu-level SIM swap protections:

1. SENSITIVE MENU PROTECTION:
   - Mark high-risk menus with require_sim_swap_check = TRUE
   - Trigger check on navigation TO sensitive menu
   - Redirect to verification flow if risk detected
   
   Add column: sim_swap_risk_level VARCHAR(16) DEFAULT 'LOW'
   -- LOW: No check needed
   -- MEDIUM: Soft warning displayed
   -- HIGH: Mandatory verification before access

2. BEHAVIORAL BIOMETRICS IN MENUS:
   - Track navigation speed (too fast = bot)
   - Track input patterns (keystroke dynamics if available)
   - Compare against device_fingerprint baseline

3. POST-SIM SWAP RESTRICTIONS:
   - First session after SIM swap: limited menu access
   - Block high-value transaction menus for 72 hours
   - Show educational message about SIM swap protection
*/

-- ----------------------------------------------------------------------------
-- INDEXES
-- ----------------------------------------------------------------------------

CREATE INDEX idx_menu_config_app 
    ON menu_configurations(application_id, is_active, menu_type);

CREATE INDEX idx_menu_config_parent 
    ON menu_configurations(parent_menu_id, display_order);

CREATE INDEX idx_menu_nav_history_session 
    ON menu_navigation_history(session_id, navigation_at DESC);

CREATE INDEX idx_menu_nav_history_menu 
    ON menu_navigation_history(from_menu_id, to_menu_id, navigation_at);

CREATE INDEX idx_menu_analytics_menu_date 
    ON menu_analytics(menu_id, aggregation_date DESC);

-- ----------------------------------------------------------------------------
-- SAMPLE DATA (Development/Testing Only)
-- ----------------------------------------------------------------------------

/*
INSERT INTO menu_configurations (
    menu_id, menu_name, application_id, menu_type,
    content_i18n, navigation_rules, created_by, updated_by
) VALUES 
    ('main_menu', 'Main Menu', 'mobile_money', 'LIST',
     '{"en": "My Money\n1. Send Money\n2. Check Balance\n3. Buy Airtime\n0. Exit", 
       "sw": "Pesa Yangu\n1. Tuma Pesa\n2. Angalia Salio\n3. Nunua Airtime\n0. Toka"}',
     '{"1": "menu:send_money", "2": "menu:check_balance", "3": "menu:buy_airtime", "0": "exit"}',
     'admin', 'admin'),
    
    ('send_money', 'Send Money', 'mobile_money', 'INPUT',
     '{"en": "Enter recipient phone number:", "sw": "Weka namba ya simu ya mpokeaji:"}',
     '{}',
     'admin', 'admin'),
    
    ('confirm_send', 'Confirm Send', 'mobile_money', 'CONFIRM',
     '{"en": "Send {{amount}} to {{recipient}}?\n1. Yes\n2. No", 
       "sw": "Tuma {{amount}} kwa {{recipient}}?\n1. Ndio\n2. Hapana"}',
     '{"1": "action:execute_transfer", "2": "menu:main_menu"}',
     'admin', 'admin');
*/
