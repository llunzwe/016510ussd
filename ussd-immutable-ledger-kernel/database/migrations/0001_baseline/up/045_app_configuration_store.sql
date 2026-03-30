-- =============================================================================
-- MIGRATION: 045_app_configuration_store.sql
-- DESCRIPTION: Application Configuration Store
-- TABLES: configuration, configuration_history
-- DEPENDENCIES: 031_app_registry.sql
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.5.36: Compliance with policies, rules and standards
  - A.8.5: Secure authentication
  - A.8.7: Protection against malware (config security)
  - A.9.4: Access to source code (config change control)

ISO/IEC 27018:2019 - Protection of PII in Public Clouds
  - Clause 8.3: Change procedures for PII handling
  - Clause 9.3: Customer access to PII (via configuration)

ISO/IEC 27050-3:2020 - Electronic Discovery
  - Section 7: Collection - configuration as evidence

GDPR / Zimbabwe Data Protection Act (Chapter 11:12)
  - Article 32: Security of processing (configuration controls)
  - Section 14: Security measures (access control via config)
  - Configuration changes affecting PII require impact assessment

SECURITY CLASSIFICATION: INTERNAL
DATA SENSITIVITY: SYSTEM CONFIGURATION (affects security posture)
RETENTION PERIOD: Current + 7 years history
AUDIT REQUIREMENT: Complete change history with integrity verification
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 5. Application Configuration Store
- Feature: Configuration Store and Audit Log
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Mutable table holding current JSON configuration per application (e.g.,
default_currency, fee_percentage, settlement_account_id). Direct updates
allowed but every change is logged in immutable audit table.

KEY FEATURES:
- Key-value configuration
- JSON value support
- Environment-specific settings
- Full audit trail
- Schema validation

SECURITY REQUIREMENTS:
- Sensitive config values encrypted at rest
- Change approval workflow for critical settings
- Config history immutable (blockchain-style hash chain)
- Access control by configuration category
================================================================================
*/

-- =============================================================================
-- TODO: Create configuration table
-- DESCRIPTION: Current configuration values
-- PRIORITY: CRITICAL
-- SECURITY: RLS by application_id; sensitive values masked
-- ENCRYPTION: is_sensitive values encrypted with application key
-- AUDIT: All changes trigger history record
-- =============================================================================
-- TODO: [CFG-001] Create app.configuration table
-- INSTRUCTIONS:
--   - Mutable configuration store
--   - Per-application settings
--   - Environment support
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE app.configuration (
--       config_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Scope
--       application_id      UUID REFERENCES app.applications(application_id), -- NULL = global
--       environment         VARCHAR(20) DEFAULT 'production', -- dev, staging, production
--       
--       -- Key
--       config_key          VARCHAR(100) NOT NULL,
--       config_category     VARCHAR(50) DEFAULT 'GENERAL', -- UI, SECURITY, INTEGRATION
--       
--       -- Value
--       config_value        JSONB NOT NULL,
--       value_type          VARCHAR(20) DEFAULT 'STRING', -- STRING, NUMBER, BOOLEAN, JSON
--       
--       -- Validation
--       schema_validation   JSONB,                       -- JSON Schema for validation
--       
--       -- Metadata
--       description         TEXT,
--       is_sensitive        BOOLEAN DEFAULT false,       -- Mask in logs; encrypt at rest
--       is_editable         BOOLEAN DEFAULT true,        -- Allow UI editing
--       
--       -- Status
--       is_active           BOOLEAN DEFAULT true,
--       
--       -- Audit (current state)
--       updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       updated_by          UUID REFERENCES core.accounts(account_id),
--       
--       -- Unique constraint
--       UNIQUE (application_id, environment, config_key)
--   );

-- =============================================================================
-- TODO: Create configuration_history table
-- DESCRIPTION: Immutable audit of config changes
-- PRIORITY: CRITICAL
-- SECURITY: Append-only; protected from modification
-- INTEGRITY: SHA-256 hash chain for tamper detection
-- RETENTION: Permanent - configuration history is audit evidence
-- =============================================================================
-- TODO: [CFG-002] Create app.configuration_history table
-- INSTRUCTIONS:
--   - Append-only audit log
--   - Cannot be modified (immutable)
--   - Full change tracking
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE app.configuration_history (
--       history_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       config_id           UUID NOT NULL REFERENCES app.configuration(config_id),
--       
--       -- Change Details
--       change_type         VARCHAR(20) NOT NULL,        -- CREATE, UPDATE, DELETE
--       previous_value      JSONB,
--       new_value           JSONB,
--       
--       -- Reason
--       change_reason       TEXT,
--       ticket_reference    VARCHAR(100),                -- JIRA, etc.
--       
--       -- Audit
--       changed_by          UUID NOT NULL REFERENCES core.accounts(account_id),
--       changed_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       client_ip           INET,
--       
--       -- Integrity (tamper-evident hash chain)
--       change_hash         BYTEA                        -- Hash of change record
--   );

-- =============================================================================
-- TODO: Create configuration audit trigger
-- DESCRIPTION: Log all config changes
-- PRIORITY: CRITICAL
-- SECURITY: SECURITY DEFINER; protected from bypass
-- ENCRYPTION: Sensitive values hashed in audit log
-- =============================================================================
-- TODO: [CFG-003] Create log_config_change trigger
-- INSTRUCTIONS:
--   - Trigger on configuration table
--   - Insert history record on change
--   - Calculate change hash
--
-- TRIGGER FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION app.log_config_change()
--   RETURNS TRIGGER AS $$
--   DECLARE
--       v_change_type VARCHAR(20);
--       v_old_value JSONB;
--       v_new_value JSONB;
--   BEGIN
--       IF TG_OP = 'INSERT' THEN
--           v_change_type := 'CREATE';
--           v_old_value := NULL;
--           v_new_value := to_jsonb(NEW);
--       ELSIF TG_OP = 'UPDATE' THEN
--           v_change_type := 'UPDATE';
--           v_old_value := to_jsonb(OLD);
--           v_new_value := to_jsonb(NEW);
--       ELSIF TG_OP = 'DELETE' THEN
--           v_change_type := 'DELETE';
--           v_old_value := to_jsonb(OLD);
--           v_new_value := NULL;
--       END IF;
--       
--       INSERT INTO app.configuration_history (
--           config_id, change_type, previous_value, new_value,
--           changed_by, client_ip, change_hash
--       ) VALUES (
--           COALESCE(NEW.config_id, OLD.config_id),
--           v_change_type,
--           v_old_value,
--           v_new_value,
--           COALESCE(NEW.updated_by, OLD.updated_by, current_setting('app.current_user_id')::UUID),
--           inet_client_addr(),
--           digest(v_old_value::text || v_new_value::text, 'sha256')
--       );
--       
--       RETURN COALESCE(NEW, OLD);
--   END;
--   $$ LANGUAGE plpgsql SECURITY DEFINER;

-- =============================================================================
-- TODO: Create get_config function
-- DESCRIPTION: Retrieve configuration value
-- PRIORITY: HIGH
-- SECURITY: RLS check; sensitive values decrypted on access
-- CACHING: Cache-friendly for performance
-- AUDIT: Access to sensitive configs logged
-- =============================================================================
-- TODO: [CFG-004] Create get_config function
-- INSTRUCTIONS:
--   - Get config with fallback
--   - Support type conversion
--   - Cache-friendly
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION app.get_config(
--       p_key VARCHAR(100),
--       p_default JSONB DEFAULT NULL,
--       p_application_id UUID DEFAULT NULL,
--       p_environment VARCHAR(20) DEFAULT 'production'
--   ) RETURNS JSONB AS $$
--   DECLARE
--       v_value JSONB;
--   BEGIN
--       -- Try specific app and environment
--       SELECT config_value INTO v_value
--       FROM app.configuration
--       WHERE config_key = p_key
--           AND application_id = p_application_id
--           AND environment = p_environment
--           AND is_active = true;
--       
--       -- Fallback to global app config
--       IF v_value IS NULL AND p_application_id IS NOT NULL THEN
--           SELECT config_value INTO v_value
--           FROM app.configuration
--           WHERE config_key = p_key
--               AND application_id = p_application_id
--               AND environment = 'production'
--               AND is_active = true;
--       END IF;
--       
--       -- Fallback to global
--       IF v_value IS NULL THEN
--           SELECT config_value INTO v_value
--           FROM app.configuration
--           WHERE config_key = p_key
--               AND application_id IS NULL
--               AND environment = 'production'
--               AND is_active = true;
--       END IF;
--       
--       RETURN COALESCE(v_value, p_default);
--   END;
--   $$ LANGUAGE plpgsql STABLE;

-- =============================================================================
-- TODO: Create set_config function
-- DESCRIPTION: Set configuration value
-- PRIORITY: HIGH
-- SECURITY: Validates user permissions; requires admin role for SECURITY configs
-- VALIDATION: Schema validation if configured
-- AUDIT: All changes logged with reason
-- =============================================================================
-- TODO: [CFG-005] Create set_config function
-- INSTRUCTIONS:
--   - Validate against schema if present
--   - Insert or update
--   - Record change reason
--   - Update timestamp

-- =============================================================================
-- TODO: Create configuration indexes
-- DESCRIPTION: Optimize config queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for application startup
-- =============================================================================
-- TODO: [CFG-006] Create configuration indexes
-- INDEX LIST:
--   -- Configuration:
--   - PRIMARY KEY (config_id)
--   - UNIQUE (application_id, environment, config_key)
--   - INDEX on (config_category, is_active)
--   -- History:
--   - PRIMARY KEY (history_id)
--   - INDEX on (config_id, changed_at)
--   - INDEX on (changed_by, changed_at)

/*
================================================================================
CONFIGURATION SECURITY GUIDE
================================================================================

1. CONFIGURATION CATEGORIES & SECURITY LEVELS:
   ┌──────────────────┬─────────────┬───────────────────────────────────────┐
   │ Category         │ Restriction │ Examples                              │
   ├──────────────────┼─────────────┼───────────────────────────────────────┤
   │ GENERAL          │ None        │ UI strings, feature flags             │
   │ SECURITY         │ Admin only  │ Password policies, encryption keys    │
   │ INTEGRATION      │ DevOps      │ API endpoints, webhook URLs           │
   │ FINANCIAL        │ Finance     │ Fee percentages, limits               │
   │ COMPLIANCE       │ Compliance  │ Retention periods, audit settings     │
   │ PII_HANDLING     │ DPO only    │ Anonymization rules, consent flows    │
   └──────────────────┴─────────────┴───────────────────────────────────────┘

2. SENSITIVE CONFIGURATION HANDLING:
   - Encrypted at rest using AES-256-GCM
   - Key rotation every 90 days
   - Decrypted only in secure memory
   - Never logged in plain text
   - Access requires elevated privileges

3. CHANGE CONTROL WORKFLOW:
   a. Change requested with business justification
   b. Impact assessment (especially for PII-related configs)
   c. Approval by category owner
   d. Implementation with change ticket reference
   e. Verification and rollback plan
   f. Post-change review within 24 hours

4. AUDIT REQUIREMENTS:
   - Who made the change
   - When (timestamp with timezone)
   - From where (IP address)
   - Previous and new values
   - Business reason for change
   - Related ticket reference

5. DISASTER RECOVERY:
   - Configurations backed up every 15 minutes
   - Point-in-time recovery available
   - Config history reconstructs any state
   - Cross-region replication for critical configs

GDPR CONSIDERATIONS:
- Configuration changes affecting PII processing require DPIA
- Data retention configs must align with Article 5
- Security configs must implement Article 32 requirements
- Consent-related configs require legal review
================================================================================
*/

/*
================================================================================
MIGRATION CHECKLIST:
□ Create configuration table
□ Create configuration_history table (immutable)
□ Implement log_config_change trigger
□ Implement get_config function
□ Implement set_config function
□ Add all indexes for config queries
□ Test configuration retrieval
□ Test change logging
□ Test schema validation
□ Verify immutability of history
□ Configure encryption for sensitive values
□ Document change control workflow
================================================================================
*/
