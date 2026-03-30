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
-- TODO: Create menu_definitions table
-- DESCRIPTION: Menu container
-- PRIORITY: CRITICAL
-- SECURITY: RLS by application_id
-- AUDIT: Version changes logged
-- PRIVACY: privacy_notice_required flag for consent flows
-- =============================================================================
-- TODO: [MENU-001] Create ussd.menu_definitions table
-- INSTRUCTIONS:
--   - Menu header information
--   - Per-application menus
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE ussd.menu_definitions (
--       menu_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       menu_code           VARCHAR(50) NOT NULL,
--       
--       -- Identity
--       menu_name           VARCHAR(100) NOT NULL,
--       description         TEXT,
--       
--       -- Scope
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Settings
--       default_language    VARCHAR(10) DEFAULT 'en',
--       timeout_seconds     INTEGER DEFAULT 120,
--       max_input_length    INTEGER DEFAULT 20,
--       
--       -- Privacy/Compliance
--       privacy_notice_required BOOLEAN DEFAULT false,   -- GDPR Article 13/14
--       consent_capture_menu    BOOLEAN DEFAULT false,   -- Records consent
--       
--       -- Versioning
--       version             INTEGER DEFAULT 1,
--       is_active           BOOLEAN DEFAULT true,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id),
--       updated_at          TIMESTAMPTZ,
--       updated_by          UUID REFERENCES core.accounts(account_id)
--   );
--
-- CONSTRAINTS:
--   - UNIQUE (application_id, menu_code)

-- =============================================================================
-- TODO: Create menu_items table
-- DESCRIPTION: Individual menu items
-- PRIORITY: CRITICAL
-- SECURITY: Input validation patterns reviewed for injection
-- PRIVACY: Sensitive flags for PII collection items
-- AUDIT: Changes logged
-- =============================================================================
-- TODO: [MENU-002] Create ussd.menu_items table
-- INSTRUCTIONS:
--   - Menu tree structure
--   - Input handling
--   - Action configuration
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE ussd.menu_items (
--       item_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       menu_id             UUID NOT NULL REFERENCES ussd.menu_definitions(menu_id),
--       
--       -- Hierarchy
--       parent_item_id      UUID REFERENCES ussd.menu_items(item_id),
--       item_path           LTREE NOT NULL,
--       display_order       INTEGER DEFAULT 0,
--       
--       -- Item Type
--       item_type           VARCHAR(20) NOT NULL,        -- MENU, INPUT, ACTION, END
--       
--       -- Display
--       item_code           VARCHAR(50) NOT NULL,        -- Unique within menu
--       
--       -- Input Handling
--       input_type          VARCHAR(20),                 -- TEXT, NUMBER, PIN, SELECT
--       input_validation    VARCHAR(100),                -- Regex or function
--       input_min_length    INTEGER,
--       input_max_length    INTEGER,
--       
--       -- Actions
--       action_type         VARCHAR(50),                 -- NAVIGATE, SUBMIT, API_CALL
--       action_config       JSONB,                       -- Action parameters
--       
--       -- Privacy/Security
--       collects_pii        BOOLEAN DEFAULT false,       -- Triggers consent check
--       requires_pin        BOOLEAN DEFAULT false,       -- Authentication required
--       sensitive_action    BOOLEAN DEFAULT false,       -- Requires confirmation
--       
--       -- Dynamic Content
--       dynamic_content_sql TEXT,                      -- SQL to generate content
--       
--       -- Status
--       is_active           BOOLEAN DEFAULT true,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create menu_translations table
-- DESCRIPTION: Multi-language menu text
-- PRIORITY: HIGH
-- SECURITY: Content review for social engineering
-- PRIVACY: Help text must include privacy information
-- =============================================================================
-- TODO: [MENU-003] Create ussd.menu_translations table
-- INSTRUCTIONS:
--   - Translated menu text per language
--   - Supports variables
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE ussd.menu_translations (
--       translation_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       item_id             UUID NOT NULL REFERENCES ussd.menu_items(item_id),
--       
--       -- Language
--       language_code       VARCHAR(10) NOT NULL,
--       
--       -- Content
--       menu_text           TEXT NOT NULL,               -- Display text with {variables}
--       error_text          TEXT,                        -- Error message
--       help_text           TEXT,                        -- Help/instructions (privacy info here)
--       
--       -- Variables help
--       variable_help       JSONB,                       -- { "amount": "Enter amount" }
--       
--       UNIQUE (item_id, language_code)
--   );

-- =============================================================================
-- TODO: Create render_menu function
-- DESCRIPTION: Generate menu display text
-- PRIORITY: CRITICAL
-- SECURITY: Validates user permissions; sanitizes output
-- PRIVACY: Includes privacy notice if required
-- PERFORMANCE: Cached for frequently accessed menus
-- =============================================================================
-- TODO: [MENU-004] Create render_menu function
-- INSTRUCTIONS:
--   - Get menu items for current state
--   - Apply translations
--   - Substitute variables
--   - Format for USSD display
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION ussd.render_menu(
--       p_session_id UUID,
--       p_menu_code VARCHAR(50),
--       p_language VARCHAR(10) DEFAULT 'en'
--   ) RETURNS TEXT AS $$
--   DECLARE
--       v_menu_id UUID;
--       v_session RECORD;
--       v_result TEXT := '';
--       v_item RECORD;
--   BEGIN
--       -- Get session
--       SELECT * INTO v_session FROM ussd.ussd_sessions WHERE session_id = p_session_id;
--       
--       -- Get menu
--       SELECT menu_id INTO v_menu_id
--       FROM ussd.menu_definitions
--       WHERE menu_code = p_menu_code
--           AND application_id = v_session.application_id
--           AND is_active = true;
--       
--       -- Get current menu items
--       FOR v_item IN 
--           SELECT mi.*, mt.menu_text
--           FROM ussd.menu_items mi
--           LEFT JOIN ussd.menu_translations mt 
--               ON mi.item_id = mt.item_id AND mt.language_code = p_language
--           WHERE mi.menu_id = v_menu_id
--               AND (mi.parent_item_id IS NULL OR 
--                    mi.item_code = v_session.menu_state OR
--                    mi.parent_item_id = (
--                        SELECT item_id FROM ussd.menu_items 
--                        WHERE menu_id = v_menu_id AND item_code = v_session.menu_state
--                    ))
--               AND mi.is_active = true
--           ORDER BY mi.display_order
--       LOOP
--           -- Build menu text
--           v_result := v_result || COALESCE(v_item.menu_text, v_item.item_code) || E'\n';
--       END LOOP;
--       
--       RETURN v_result;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create process_menu_input function
-- DESCRIPTION: Handle menu selection/input
-- PRIORITY: CRITICAL
-- SECURITY: Input validation; PIN handling (never logged)
-- PRIVACY: Consent validation for PII collection
-- AUDIT: Actions logged; sensitive actions require confirmation
-- =============================================================================
-- TODO: [MENU-005] Create process_menu_input function
-- INSTRUCTIONS:
--   - Validate input
--   - Find matching menu item
--   - Execute action
--   - Update session state
--   - Return next menu or result

-- =============================================================================
-- TODO: Create menu indexes
-- DESCRIPTION: Optimize menu queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for USSD response time
-- =============================================================================
-- TODO: [MENU-006] Create menu indexes
-- INDEX LIST:
--   -- Menu Definitions:
--   - PRIMARY KEY (menu_id)
--   - UNIQUE (application_id, menu_code)
--   -- Menu Items:
--   - PRIMARY KEY (item_id)
--   - UNIQUE (menu_id, item_code)
--   - INDEX on (menu_id, parent_item_id, display_order)
--   - INDEX on (item_path)
--   -- Translations:
--   - PRIMARY KEY (translation_id)
--   - UNIQUE (item_id, language_code)

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
□ Create menu_definitions table
□ Create menu_items table
□ Create menu_translations table
□ Implement render_menu function
□ Implement process_menu_input function
□ Add all indexes for menu queries
□ Test menu rendering
□ Test input processing
□ Test multi-language support
□ Verify menu navigation
□ Configure consent capture flows
□ Document security level requirements
□ Review privacy notice placement
================================================================================
*/
