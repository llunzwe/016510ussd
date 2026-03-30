-- =============================================================================
-- MIGRATION: 048_ussd_shortcode_routing.sql
-- DESCRIPTION: USSD Shortcode Routing
-- TABLES: shortcodes, shortcode_routes, route_rules
-- DEPENDENCIES: 031_app_registry.sql
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

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 9. Integration with USSD Kernel & External Services
- Feature: Application Code Routing
- Source: adkjfnwr.md

BUSINESS CONTEXT:
The USSD kernel's service router maps a USSD short code or menu option to
an application_id. The App Schema provides the lookup table.

KEY FEATURES:
- Shortcode to application mapping
- Hierarchical routing (country -> service -> app)
- Time-based routing
- Load balancing
- Fallback routing

SECURITY & COMPLIANCE NOTES:
- Routing decisions logged for audit
- MSISDN used only for routing, not retained
- Geographic routing respects data residency
- Emergency shortcodes have priority routing
- All routing changes require authorization
================================================================================
*/

-- =============================================================================
-- TODO: Create shortcodes table
-- DESCRIPTION: Shortcode definitions
-- PRIORITY: CRITICAL
-- SECURITY: RLS restricted to telecom administrators
-- AUDIT: All shortcode changes logged
-- =============================================================================
-- TODO: [ROUTE-001] Create ussd.shortcodes table
-- INSTRUCTIONS:
--   - USSD shortcode registry
--   - Country and operator specific
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE ussd.shortcodes (
--       shortcode_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Code
--       shortcode           VARCHAR(20) NOT NULL,        -- e.g., "*123#"
--       
--       -- Scope
--       country_code        VARCHAR(2) NOT NULL,         -- ISO country
--       network_operator    VARCHAR(50),                 -- Specific operator or NULL for all
--       
--       -- Description
--       shortcode_name      VARCHAR(100) NOT NULL,
--       description         TEXT,
--       
--       -- Status
--       is_active           BOOLEAN DEFAULT true,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );
--
-- CONSTRAINTS:
--   - UNIQUE (shortcode, country_code, network_operator)

-- =============================================================================
-- TODO: Create shortcode_routes table
-- DESCRIPTION: Shortcode to application routing
-- PRIORITY: CRITICAL
-- SECURITY: Changes require dual authorization
-- AUDIT: Route changes logged with reason
-- =============================================================================
-- TODO: [ROUTE-002] Create ussd.shortcode_routes table
-- INSTRUCTIONS:
--   - Maps shortcodes to applications
--   - Supports rules and conditions
--   - Weighted for load balancing
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE ussd.shortcode_routes (
--       route_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Links
--       shortcode_id        UUID NOT NULL REFERENCES ussd.shortcodes(shortcode_id),
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Routing Logic
--       route_priority      INTEGER DEFAULT 100,         -- Lower = higher priority
--       route_weight        INTEGER DEFAULT 1,           -- For load balancing
--       
--       -- Conditions
--       condition_rules     JSONB,                       -- When to use this route
--       -- Example: {"time_range": {"start": "08:00", "end": "18:00"}}
--       
--       -- Response
--       welcome_message     VARCHAR(500),                -- Override default
--       
--       -- Status
--       is_active           BOOLEAN DEFAULT true,
--       
--       -- Validity
--       valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       valid_to            TIMESTAMPTZ,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create route_access_logs table
-- DESCRIPTION: Routing access tracking
-- PRIORITY: MEDIUM
-- SECURITY: RLS filtered; MSISDN hashed
-- PII: MSISDN one-way hashed; no account linkage
-- RETENTION: 90 days raw; 2 years aggregated
-- =============================================================================
-- TODO: [ROUTE-003] Create ussd.route_access_logs table
-- INSTRUCTIONS:
--   - Log each routing decision
--   - Analytics and debugging
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE ussd.route_access_logs (
--       log_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Request
--       msisdn_hash         VARCHAR(64) NOT NULL,        -- SHA-256 hash of MSISDN
--       shortcode           VARCHAR(20) NOT NULL,
--       country_code        VARCHAR(2),
--       network_operator    VARCHAR(50),
--       
--       -- Routing
--       route_id            UUID REFERENCES ussd.shortcode_routes(route_id),
--       application_id      UUID,
--       
--       -- Result
--       routed_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
--       session_id          UUID REFERENCES ussd.ussd_sessions(session_id),
--       
--       -- Performance
--       routing_duration_ms INTEGER
--   );

-- =============================================================================
-- TODO: Create route_request function
-- DESCRIPTION: Route USSD request to application
-- PRIORITY: CRITICAL
-- SECURITY: Validates shortcode permissions; logs access
-- DATA PROTECTION: MSISDN hashed in logs
-- PERFORMANCE: < 100ms response time target
-- =============================================================================
-- TODO: [ROUTE-004] Create route_ussd_request function
-- INSTRUCTIONS:
--   - Parse shortcode
--   - Evaluate route rules
--   - Select application
--   - Create session
--   - Log access (hashed MSISDN)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION ussd.route_ussd_request(
--       p_msisdn VARCHAR(20),
--       p_shortcode VARCHAR(20),
--       p_country_code VARCHAR(2),
--       p_operator VARCHAR(50) DEFAULT NULL
--   ) RETURNS TABLE (
--       application_id UUID,
--       session_id UUID,
--       welcome_message VARCHAR(500)
--   ) AS $$
--   DECLARE
--       v_shortcode_id UUID;
--       v_route RECORD;
--       v_session_id UUID;
--   BEGIN
--       -- Find shortcode
--       SELECT shortcode_id INTO v_shortcode_id
--       FROM ussd.shortcodes
--       WHERE shortcode = p_shortcode
--           AND country_code = p_country_code
--           AND (network_operator = p_operator OR network_operator IS NULL)
--           AND is_active = true
--       ORDER BY network_operator IS NULL  -- Prefer specific
--       LIMIT 1;
--       
--       IF v_shortcode_id IS NULL THEN
--           RAISE EXCEPTION 'Invalid shortcode';
--       END IF;
--       
--       -- Find active route
--       SELECT * INTO v_route
--       FROM ussd.shortcode_routes
--       WHERE shortcode_id = v_shortcode_id
--           AND is_active = true
--           AND valid_from <= now()
--           AND (valid_to IS NULL OR valid_to > now())
--           AND ussd.evaluate_route_conditions(condition_rules, p_msisdn, now())
--       ORDER BY route_priority, random() * route_weight
--       LIMIT 1;
--       
--       IF v_route IS NULL THEN
--           RAISE EXCEPTION 'No active route for shortcode';
--       END IF;
--       
--       -- Create session
--       v_session_id := ussd.get_or_create_session(
--           p_msisdn, gen_random_uuid()::text, v_route.application_id
--       );
--       
--       -- Log access (with hashed MSISDN)
--       INSERT INTO ussd.route_access_logs (
--           msisdn_hash, shortcode, country_code, network_operator,
--           route_id, application_id, session_id
--       ) VALUES (
--           encode(digest(p_msisdn, 'sha256'), 'hex'),
--           p_shortcode, p_country_code, p_operator,
--           v_route.route_id, v_route.application_id, v_session_id
--       );
--       
--       RETURN QUERY SELECT 
--           v_route.application_id, 
--           v_session_id, 
--           v_route.welcome_message;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create evaluate_route_conditions function
-- DESCRIPTION: Check route conditions
-- PRIORITY: HIGH
-- SECURITY: Validates condition evaluation
-- =============================================================================
-- TODO: [ROUTE-005] Create evaluate_route_conditions function
-- INSTRUCTIONS:
--   - Parse condition_rules JSON
--   - Evaluate time ranges
--   - Check user segments

-- =============================================================================
-- TODO: Create routing indexes
-- DESCRIPTION: Optimize routing queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for USSD response time
-- =============================================================================
-- TODO: [ROUTE-006] Create routing indexes
-- INDEX LIST:
--   -- Shortcodes:
--   - PRIMARY KEY (shortcode_id)
--   - UNIQUE (shortcode, country_code, network_operator)
--   - INDEX on (country_code, is_active)
--   -- Routes:
--   - PRIMARY KEY (route_id)
--   - INDEX on (shortcode_id, is_active, valid_from, valid_to)
--   - INDEX on (application_id, is_active)
--   -- Access Logs:
--   - PRIMARY KEY (log_id)
--   - INDEX on (shortcode, routed_at)
--   - INDEX on (application_id, routed_at)

/*
================================================================================
ROUTING SECURITY & DATA PROTECTION GUIDE
================================================================================

1. SHORTCODE SECURITY CLASSIFICATION:
   ┌─────────────────────┬──────────────────────────────────────────────────┐
   │ Shortcode Type      │ Security Requirements                            │
   ├─────────────────────┼──────────────────────────────────────────────────┤
   │ Emergency (*999#)   │ Always active; priority routing; audit all       │
   │ Financial (*123#)   │ Fraud detection; device fingerprinting required  │
   │ Service (*456#)     │ Standard authentication; session timeout 5 min   │
   │ Info (*789#)        │ Read-only; no authentication required            │
   │ Test (*000#)        │ Restricted to test MSISDNs; debug logging        │
   └─────────────────────┴──────────────────────────────────────────────────┘

2. ROUTING CONDITIONS (GDPR Purpose Limitation):
   - Time-based: Business hours routing (no PII used)
   - Geographic: Country code only (no precise location)
   - Load-based: Random distribution (no user profiling)
   - NEVER route based on user history or behavior

3. ACCESS LOGGING (Data Minimization):
   - MSISDN: SHA-256 hash only (irreversible)
   - No account_id in routing logs
   - No session context beyond session_id reference
   - Performance metrics aggregated

4. DATA RESIDENCY:
   - Country code determines data center routing
   - Cross-border routing flagged for review
   - EU MSISDNs route to EU data centers (GDPR)
   - Zimbabwe MSISDNs route to local infrastructure

5. SECURITY MONITORING:
   - Unusual routing patterns trigger alerts
   - High volume from single MSISDN = potential abuse
   - Shortcode squatting detection
   - Route hijacking prevention (checksum validation)

PRIVACY BY DESIGN:
- Routing decision uses minimal data (MSISDN hash + shortcode)
- No persistent storage of routing context
- Automatic log purging after retention period
- Data subject can request routing history (anonymized)
================================================================================
*/

/*
================================================================================
MIGRATION CHECKLIST:
□ Create shortcodes table
□ Create shortcode_routes table
□ Create route_access_logs table
□ Implement route_ussd_request function
□ Implement evaluate_route_conditions function
□ Add all indexes for routing queries
□ Test shortcode lookup
□ Test route selection
□ Test condition evaluation
□ Verify access logging
□ Configure MSISDN hashing
□ Set up geographic routing rules
□ Document emergency shortcode handling
================================================================================
*/
