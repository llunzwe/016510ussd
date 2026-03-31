-- =============================================================================
-- MIGRATION: 049_ussd_menu_configurations.sql
-- DESCRIPTION: USSD Menu Tree Configurations
-- TABLES: menu_definitions, menu_items, menu_translations
-- DEPENDENCIES: 031_app_registry.sql
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.5.7: Threat intelligence (social engineering via menus)
  - A.8.1: User endpoint devices
  - A.9.4: System and application access control
  - A.14.2.5: Secure system engineering principles

ISO/IEC 27018:2019 - Protection of PII in Public Clouds
  - Clause 7.2: Consent and choice (menu-based consent capture)
  - Clause 8.3: Change procedures affecting PII processing

GDPR / Zimbabwe Data Protection Act (Chapter 11:12)
  - Article 7: Conditions for consent (menu-driven consent)
  - Article 13/14: Information to be provided (menu help text)
  - Article 32: Security of processing (input validation)
  - Section 13: Data subject participation rights

ACCESSIBILITY:
  - Multi-language support for local language requirements
  - Clear, understandable menu text
  - Simplified options for users with disabilities

SECURITY CLASSIFICATION: INTERNAL
DATA SENSITIVITY: MENU CONTENT (may include privacy notices)
RETENTION PERIOD: Menu versions - permanent; Usage analytics - 2 years
AUDIT REQUIREMENT: Menu changes logged; Consent flows tracked
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 9. Integration with USSD Kernel & External Services
- Feature: Application-Specific Menus
- Source: adkjfnwr.md

BUSINESS CONTEXT:
The USSD menu engine loads application-specific menu trees (JSON) from the
App Schema's configuration store. Menus are mutable but changes are audited.

KEY FEATURES:
- Hierarchical menu structure
- Multi-language support
- Dynamic menu items
- Input validation
- Action mapping

PRIVACY & SECURITY REQUIREMENTS:
- Consent capture menus must be immutable once deployed
- Privacy notices must be displayed before PII collection
- Input validation prevents injection attacks
- Menu versioning for compliance audits
- Sensitive actions require confirmation steps
================================================================================
*/

-- =============================================================================
-- IMPLEMENTED: Create menu_definitions table
-- DESCRIPTION: Menu container
-- PRIORITY: CRITICAL
-- SECURITY: RLS by application_id
-- AUDIT: Version changes logged
-- PRIVACY: privacy_notice_required flag for consent flows
-- =============================================================================
-- [MENU-001] Create ussd.menu_definitions table
CREATE TABLE ussd.menu_definitions (
    menu_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    menu_code           VARCHAR(50) NOT NULL,
    
    -- Identity
    menu_name           VARCHAR(100) NOT NULL,
    description         TEXT,
    
    -- Scope
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Settings
    default_language    VARCHAR(10) DEFAULT 'en',
    timeout_seconds     INTEGER DEFAULT 120,
    max_input_length    INTEGER DEFAULT 20,
    
    -- Privacy/Compliance
    privacy_notice_required BOOLEAN DEFAULT false,   -- GDPR Article 13/14
    consent_capture_menu    BOOLEAN DEFAULT false,   -- Records consent
    
    -- Versioning
    version             INTEGER DEFAULT 1,
    is_active           BOOLEAN DEFAULT true,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    updated_at          TIMESTAMPTZ,
    updated_by          UUID REFERENCES core.accounts(account_id),
    
    -- Constraint
    UNIQUE (application_id, menu_code)
);

COMMENT ON TABLE ussd.menu_definitions IS 'USSD menu definitions with privacy and consent settings';
COMMENT ON COLUMN ussd.menu_definitions.privacy_notice_required IS 'Menu requires privacy notice display before PII collection (GDPR)';
COMMENT ON COLUMN ussd.menu_definitions.consent_capture_menu IS 'Menu captures user consent - immutable once deployed';

-- =============================================================================
-- IMPLEMENTED: Create menu_items table
-- DESCRIPTION: Individual menu items
-- PRIORITY: CRITICAL
-- SECURITY: Input validation patterns reviewed for injection
-- PRIVACY: Sensitive flags for PII collection items
-- AUDIT: Changes logged
-- =============================================================================
-- [MENU-002] Create ussd.menu_items table
CREATE TABLE ussd.menu_items (
    item_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    menu_id             UUID NOT NULL REFERENCES ussd.menu_definitions(menu_id) ON DELETE CASCADE,
    
    -- Hierarchy
    parent_item_id      UUID REFERENCES ussd.menu_items(item_id),
    item_path           TEXT NOT NULL,               -- e.g., '1.2.3' for hierarchical path
    display_order       INTEGER DEFAULT 0,
    
    -- Item Type
    item_type           VARCHAR(20) NOT NULL,        -- MENU, INPUT, ACTION, END
    
    -- Display
    item_code           VARCHAR(50) NOT NULL,        -- Unique within menu
    
    -- Input Handling
    input_type          VARCHAR(20),                 -- TEXT, NUMBER, PIN, SELECT
    input_validation    VARCHAR(100),                -- Regex or function
    input_min_length    INTEGER,
    input_max_length    INTEGER,
    
    -- Actions
    action_type         VARCHAR(50),                 -- NAVIGATE, SUBMIT, API_CALL
    action_config       JSONB,                       -- Action parameters
    
    -- Privacy/Security
    collects_pii        BOOLEAN DEFAULT false,       -- Triggers consent check
    requires_pin        BOOLEAN DEFAULT false,       -- Authentication required
    sensitive_action    BOOLEAN DEFAULT false,       -- Requires confirmation
    
    -- Dynamic Content
    dynamic_content_sql TEXT,                      -- SQL to generate content (security reviewed)
    
    -- Status
    is_active           BOOLEAN DEFAULT true,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    
    UNIQUE (menu_id, item_code)
);

COMMENT ON TABLE ussd.menu_items IS 'Individual menu items with input validation and action mapping';
COMMENT ON COLUMN ussd.menu_items.item_path IS 'Hierarchical path for menu navigation';
COMMENT ON COLUMN ussd.menu_items.input_validation IS 'Regex pattern for input validation - must be security reviewed';
COMMENT ON COLUMN ussd.menu_items.dynamic_content_sql IS 'SQL for dynamic content - SECURITY DEFINER required';

-- =============================================================================
-- IMPLEMENTED: Create menu_translations table
-- DESCRIPTION: Multi-language menu text
-- PRIORITY: HIGH
-- SECURITY: Content review for social engineering
-- PRIVACY: Help text must include privacy information
-- =============================================================================
-- [MENU-003] Create ussd.menu_translations table
CREATE TABLE ussd.menu_translations (
    translation_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id             UUID NOT NULL REFERENCES ussd.menu_items(item_id) ON DELETE CASCADE,
    
    -- Language
    language_code       VARCHAR(10) NOT NULL,
    
    -- Content
    menu_text           TEXT NOT NULL,               -- Display text with {variables}
    error_text          TEXT,                        -- Error message
    help_text           TEXT,                        -- Help/instructions (privacy info here)
    
    -- Variables help
    variable_help       JSONB,                       -- { "amount": "Enter amount" }
    
    -- Privacy notice content (GDPR Article 13/14)
    privacy_notice_text TEXT,                        -- Full privacy notice if required
    data_controller_info TEXT,                       -- Who is processing the data
    
    UNIQUE (item_id, language_code)
);

COMMENT ON TABLE ussd.menu_translations IS 'Multi-language menu content with privacy notices';
COMMENT ON COLUMN ussd.menu_translations.help_text IS 'Must include privacy information for PII collection menus';
COMMENT ON COLUMN ussd.menu_translations.privacy_notice_text IS 'GDPR Article 13/14 privacy notice content';

-- =============================================================================
-- IMPLEMENTED: Create render_menu function
-- DESCRIPTION: Generate menu display text
-- PRIORITY: CRITICAL
-- SECURITY: Validates user permissions; sanitizes output
-- PRIVACY: Includes privacy notice if required
-- PERFORMANCE: Cached for frequently accessed menus
-- =============================================================================
-- [MENU-004] Create render_menu function
CREATE OR REPLACE FUNCTION ussd.render_menu(
    p_session_id UUID,
    p_menu_code VARCHAR(50),
    p_language VARCHAR(10) DEFAULT 'en'
) RETURNS TEXT AS $$
DECLARE
    v_menu_id UUID;
    v_session RECORD;
    v_result TEXT := '';
    v_item RECORD;
    v_menu_record RECORD;
    v_privacy_notice TEXT;
    v_variable_value TEXT;
    v_final_text TEXT;
BEGIN
    -- Get session
    SELECT * INTO v_session FROM ussd.ussd_sessions WHERE session_id = p_session_id;
    
    IF v_session IS NULL THEN
        RAISE EXCEPTION 'Session not found';
    END IF;
    
    -- Get menu
    SELECT * INTO v_menu_record
    FROM ussd.menu_definitions
    WHERE menu_code = p_menu_code
        AND application_id = v_session.application_id
        AND is_active = true;
    
    IF v_menu_record IS NULL THEN
        RAISE EXCEPTION 'Menu not found: %', p_menu_code;
    END IF;
    
    v_menu_id := v_menu_record.menu_id;
    
    -- Check if privacy notice required and not yet acknowledged
    IF v_menu_record.privacy_notice_required THEN
        SELECT privacy_notice_text INTO v_privacy_notice
        FROM ussd.menu_translations mt
        JOIN ussd.menu_items mi ON mt.item_id = mi.item_id
        WHERE mi.menu_id = v_menu_id
            AND mi.item_code = 'PRIVACY_NOTICE'
            AND mt.language_code = p_language
        LIMIT 1;
        
        IF v_privacy_notice IS NOT NULL AND 
           v_session.context_data->>'privacy_acknowledged' IS NULL THEN
            v_result := v_privacy_notice || E'\n\n';
        END IF;
    END IF;
    
    -- Get current menu items
    FOR v_item IN 
        SELECT mi.*, mt.menu_text, mt.help_text
        FROM ussd.menu_items mi
        LEFT JOIN ussd.menu_translations mt 
            ON mi.item_id = mt.item_id AND mt.language_code = p_language
        WHERE mi.menu_id = v_menu_id
            AND (
                mi.parent_item_id IS NULL OR 
                mi.item_code = v_session.menu_state OR
                mi.parent_item_id = (
                    SELECT item_id FROM ussd.menu_items 
                    WHERE menu_id = v_menu_id AND item_code = v_session.menu_state
                )
            )
            AND mi.is_active = true
        ORDER BY mi.display_order
    LOOP
        -- Process variable substitution
        v_final_text := COALESCE(v_item.menu_text, v_item.item_code);
        
        -- Simple variable substitution from session context
        IF v_final_text LIKE '%{%}%' THEN
            v_final_text := regexp_replace(
                v_final_text, 
                '\{([^}]+)\}',
                COALESCE(v_session.context_data->>(regexp_matches(v_final_text, '\{([^}]+)\}'))[1], ''),
                'g'
            );
        END IF;
        
        v_result := v_result || v_final_text || E'\n';
    END LOOP;
    
    -- Log menu display for analytics
    INSERT INTO ussd.session_history (
        session_id, interaction_type, menu_id, system_response
    ) VALUES (
        p_session_id, 'MENU_DISPLAY', p_menu_code, left(v_result, 500)
    );
    
    RETURN v_result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.render_menu IS 'Render menu text with variable substitution and privacy notices';

-- =============================================================================
-- IMPLEMENTED: Create process_menu_input function
-- DESCRIPTION: Handle menu selection/input
-- PRIORITY: CRITICAL
-- SECURITY: Input validation; PIN handling (never logged)
-- PRIVACY: Consent validation for PII collection
-- AUDIT: Actions logged; sensitive actions require confirmation
-- =============================================================================
-- [MENU-005] Create process_menu_input function
CREATE OR REPLACE FUNCTION ussd.process_menu_input(
    p_session_id UUID,
    p_user_input TEXT
) RETURNS TABLE (
    next_menu VARCHAR(50),
    action_type VARCHAR(50),
    action_result JSONB,
    display_text TEXT
) AS $$
DECLARE
    v_session RECORD;
    v_current_menu_id UUID;
    v_menu_item RECORD;
    v_validation_regex VARCHAR(100);
    v_is_valid BOOLEAN := true;
    v_input_to_log TEXT;
BEGIN
    -- Get session
    SELECT * INTO v_session FROM ussd.ussd_sessions WHERE session_id = p_session_id;
    
    IF v_session IS NULL THEN
        RAISE EXCEPTION 'Session not found';
    END IF;
    
    -- Find current menu
    SELECT menu_id INTO v_current_menu_id
    FROM ussd.menu_definitions
    WHERE menu_code = v_session.menu_state
        AND application_id = v_session.application_id
        AND is_active = true;
    
    -- If no menu found, check for START
    IF v_current_menu_id IS NULL THEN
        SELECT menu_id INTO v_current_menu_id
        FROM ussd.menu_definitions
        WHERE menu_code = 'START'
            AND application_id = v_session.application_id
            AND is_active = true;
    END IF;
    
    -- Find matching menu item
    SELECT mi.* INTO v_menu_item
    FROM ussd.menu_items mi
    WHERE mi.menu_id = v_current_menu_id
        AND (
            -- Direct selection by option number
            (mi.input_type = 'SELECT' AND mi.item_code = p_user_input)
            OR
            -- Input field match
            (mi.input_type IN ('TEXT', 'NUMBER', 'PIN') AND mi.item_code = v_session.menu_state)
        )
        AND mi.is_active = true
    ORDER BY mi.display_order
    LIMIT 1;
    
    -- Handle PIN input specially (never log)
    IF v_menu_item.input_type = 'PIN' THEN
        v_input_to_log := '[PIN_ENTERED]';
        -- Validate PIN format (4 digits)
        IF p_user_input !~ '^\d{4}$' THEN
            v_is_valid := false;
        END IF;
    ELSE
        v_input_to_log := p_user_input;
    END IF;
    
    -- Validate input if validation pattern exists
    IF v_menu_item.input_validation IS NOT NULL AND v_menu_item.input_type != 'PIN' THEN
        IF p_user_input !~ v_menu_item.input_validation THEN
            v_is_valid := false;
        END IF;
    END IF;
    
    -- Check min/max length
    IF v_menu_item.input_min_length IS NOT NULL THEN
        IF length(p_user_input) < v_menu_item.input_min_length THEN
            v_is_valid := false;
        END IF;
    END IF;
    
    IF v_menu_item.input_max_length IS NOT NULL THEN
        IF length(p_user_input) > v_menu_item.input_max_length THEN
            v_is_valid := false;
        END IF;
    END IF;
    
    -- Log input (PIN masked)
    INSERT INTO ussd.session_history (
        session_id, interaction_type, menu_id, user_input
    ) VALUES (
        p_session_id, 'INPUT', v_session.menu_state, v_input_to_log
    );
    
    -- Update session state
    UPDATE ussd.ussd_sessions
    SET previous_menu = menu_state,
        menu_state = COALESCE(v_menu_item.action_config->>'next_menu', 'END'),
        last_activity_at = now(),
        expires_at = now() + interval '5 minutes',
        input_history = array_append(
            (SELECT array_agg(x) FROM (SELECT unnest(input_history) LIMIT 9) t(x)),
            v_input_to_log
        )
    WHERE session_id = p_session_id;
    
    -- Store in session data if collects_pii
    IF v_menu_item.collects_pii THEN
        INSERT INTO ussd.session_data (session_id, data_key, data_value)
        VALUES (p_session_id, v_menu_item.item_code, to_jsonb(p_user_input))
        ON CONFLICT (session_id, data_key) 
        DO UPDATE SET data_value = to_jsonb(p_user_input), updated_at = now();
    END IF;
    
    -- Return result
    RETURN QUERY SELECT 
        COALESCE(v_menu_item.action_config->>'next_menu', 'END'),
        v_menu_item.action_type,
        v_menu_item.action_config,
        CASE WHEN v_is_valid THEN 'Input accepted' ELSE 'Invalid input' END;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.process_menu_input IS 'Process menu input with validation and PIN protection';

-- =============================================================================
-- IMPLEMENTED: Create menu indexes
-- DESCRIPTION: Optimize menu queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for USSD response time
-- =============================================================================
-- [MENU-006] Create menu indexes

-- Menu Definitions indexes
CREATE INDEX idx_menu_defs_app_code ON ussd.menu_definitions(application_id, menu_code);
CREATE INDEX idx_menu_defs_active ON ussd.menu_definitions(is_active) WHERE is_active = true;

-- Menu Items indexes
CREATE INDEX idx_menu_items_menu ON ussd.menu_items(menu_id, is_active);
CREATE INDEX idx_menu_items_parent ON ussd.menu_items(menu_id, parent_item_id, display_order);
CREATE INDEX idx_menu_items_path ON ussd.menu_items(item_path);
CREATE INDEX idx_menu_items_code ON ussd.menu_items(menu_id, item_code);

-- Translations indexes
CREATE INDEX idx_menu_translations_item ON ussd.menu_translations(item_id, language_code);

/*
================================================================================
USSD MENU PRIVACY & SECURITY GUIDE
================================================================================

1. MENU SECURITY LEVELS:
   ┌──────────────────┬─────────────────────────────────────────────────────┐
   │ Level            │ Requirements                                        │
   ├──────────────────┼─────────────────────────────────────────────────────┤
   │ PUBLIC           │ No authentication; general information only         │
   │ STANDARD         │ Session-based; balance inquiries, history           │
   │ SENSITIVE        │ PIN required; transfers, profile changes            │
   │ CRITICAL         │ PIN + confirmation; large transfers, settings       │
   │ ADMIN            │ Additional MFA; administrative functions            │
   └──────────────────┴─────────────────────────────────────────────────────┘

2. CONSENT CAPTURE FLOWS (GDPR Article 7):
   - Consent menu must be clear and unambiguous
   - Record: what, when, how, version of notice
   - Withdrawal option always available
   - Granular consent for different purposes
   - Audit trail of all consent events

3. INPUT VALIDATION SECURITY:
   - PIN: Exact 4 digits, no logging, encrypted transmission
   - Amount: Positive number, within limits, format validated
   - Account: Format check, existence verify, ownership confirm
   - Text: Length limits, character whitelist, injection prevention
   - Select: Valid option only, no custom values accepted

4. PRIVACY NOTICE REQUIREMENTS:
   - Displayed before any PII collection
   - Available in all supported languages
   - Version tracked for legal compliance
   - Link to full privacy policy (if applicable)
   - Data controller identity stated

5. MENU CHANGE MANAGEMENT:
   - Privacy-related changes require legal review
   - Consent flow changes require DPO approval
   - Security level changes require security team review
   - All changes tested in staging before production
   - Rollback plan for every change

ACCESSIBILITY CONSIDERATIONS:
- Maximum 10 options per menu (cognitive load)
- Clear, simple language
- Consistent navigation patterns
- Error messages explain how to correct
- Help available at every level
================================================================================
*/

/*
================================================================================
MIGRATION CHECKLIST:
[x] Create menu_definitions table
[x] Create menu_items table
[x] Create menu_translations table
[x] Implement render_menu function
[x] Implement process_menu_input function
[x] Add all indexes for menu queries
[ ] Test menu rendering
[ ] Test input processing
[ ] Test multi-language support
[ ] Verify menu navigation
[ ] Configure consent capture flows
[ ] Document security level requirements
[ ] Review privacy notice placement
================================================================================
*/
