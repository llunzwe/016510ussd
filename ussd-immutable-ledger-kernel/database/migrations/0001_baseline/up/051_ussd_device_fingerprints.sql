-- =============================================================================
-- MIGRATION: 051_ussd_device_fingerprints.sql
-- DESCRIPTION: USSD Device Fingerprinting
-- TABLES: device_fingerprints, device_sessions, device_risk_scores
-- DEPENDENCIES: 003_core_account_registry.sql
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.5.23: Information security for use of cloud services
  - A.8.1: User endpoint devices
  - A.8.5: Secure authentication
  - A.8.15: Logging
  - A.12.6: Technical compliance checking

ISO/IEC 27018:2019 - Protection of PII in Public Clouds
  - Clause 6.2: Consent for secondary use (fraud detection)
  - Clause 9.4: Privacy policy notice (fingerprinting disclosure)

GDPR / Zimbabwe Data Protection Act (Chapter 11:12)
  - Article 6: Lawful basis for processing (legitimate interest for fraud)
  - Article 22: Automated decision-making (risk scoring)
  - Section 13: Data subject rights (access to profile)
  - Fingerprinting is profiling - requires transparency

FRAUD PREVENTION REGULATIONS:
  - Legitimate interest basis for fraud prevention
  - Proportionality requirements
  - Data subject notification obligations

SECURITY CLASSIFICATION: CONFIDENTIAL
DATA SENSITIVITY: INDIRECT PII (device + behavior patterns)
RETENTION PERIOD: Active devices 2 years; Risk events 7 years
AUDIT REQUIREMENT: All risk decisions logged with reasoning
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 5. Security & Access Control
- Feature: Device Fingerprinting
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Device fingerprinting for fraud detection and security. Tracks devices used
by accounts and calculates risk scores.

KEY FEATURES:
- Device fingerprint generation
- Account-device linking
- Risk scoring
- Suspicious activity detection
- Block/allow lists

PRIVACY & SECURITY REQUIREMENTS:
- Fingerprint is one-way hash (cannot reverse to device)
- Behavioral data anonymized
- Data subjects can request their device history
- Risk scoring logic transparent
- False positive appeal process
================================================================================
*/

-- =============================================================================
-- TODO: Create device_fingerprints table
-- DESCRIPTION: Known device records
-- PRIORITY: HIGH
-- SECURITY: Fingerprint is one-way hash; no device identification
-- PRIVACY: No direct PII; pattern-based identification only
-- RETENTION: 2 years for active; flagged devices permanent
-- =============================================================================
-- TODO: [DEV-001] Create ussd.device_fingerprints table
-- INSTRUCTIONS:
--   - Device identification
--   - Risk classification
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE ussd.device_fingerprints (
--       fingerprint_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       fingerprint_hash    VARCHAR(255) UNIQUE NOT NULL, -- Generated hash (irreversible)
--       
--       -- Device Info (non-identifying)
--       device_type         VARCHAR(50),                 -- MOBILE, FEATURE_PHONE
--       device_model_hash   VARCHAR(64),                 -- Hashed model
--       os_version_hash     VARCHAR(64),                 -- Hashed OS version
--       
--       -- Network (anonymized)
--       network_operator    VARCHAR(50),
--       country_code        VARCHAR(2),
--       
--       -- Status
--       trust_status        VARCHAR(20) DEFAULT 'UNKNOWN', -- TRUSTED, SUSPICIOUS, BLOCKED
--       
--       -- Risk (GDPR Article 22 - automated decision)
--       risk_score          INTEGER DEFAULT 0,
--       risk_factors        JSONB DEFAULT '{}',          -- Transparent factors
--       
--       -- Audit
--       first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
--       last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
--       seen_count          INTEGER DEFAULT 1
--   );

-- =============================================================================
-- TODO: Create account_device_links table
-- DESCRIPTION: Account-device associations
-- PRIORITY: HIGH
-- SECURITY: RLS by account_id
-- PRIVACY: Pseudonymized account reference
-- =============================================================================
-- TODO: [DEV-002] Create ussd.account_device_links table
-- INSTRUCTIONS:
--   - Which accounts use which devices
--   - Temporal tracking
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE ussd.account_device_links (
--       link_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Links (pseudonymized)
--       account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
--       fingerprint_id      UUID NOT NULL REFERENCES ussd.device_fingerprints(fingerprint_id),
--       
--       -- Usage
--       first_used_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
--       last_used_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
--       use_count           INTEGER DEFAULT 1,
--       
--       -- Status
--       is_trusted          BOOLEAN DEFAULT false,
--       is_blocked          BOOLEAN DEFAULT false,
--       block_reason        TEXT,
--       
--       -- Audit (for subject access requests)
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create generate_fingerprint function
-- DESCRIPTION: Create device fingerprint
-- PRIORITY: HIGH
-- SECURITY: One-way hash only; no reversible encoding
-- PRIVACY: Cannot identify specific device from hash
-- =============================================================================
-- TODO: [DEV-003] Create generate_device_fingerprint function
-- INSTRUCTIONS:
--   - Generate hash from device characteristics
--   - Normalize inputs
--   - Return fingerprint hash
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION ussd.generate_device_fingerprint(
--       p_msisdn VARCHAR(20),
--       p_network_operator VARCHAR(50),
--       p_country_code VARCHAR(2),
--       p_device_info JSONB DEFAULT '{}'
--   ) RETURNS VARCHAR(255) AS $$
--   DECLARE
--       v_fingerprint VARCHAR(255);
--   BEGIN
--       -- Generate hash from normalized inputs (one-way, irreversible)
--       v_fingerprint := encode(
--           digest(
--               COALESCE(p_msisdn, '') || '|' ||
--               COALESCE(p_network_operator, '') || '|' ||
--               COALESCE(p_country_code, '') || '|' ||
--               COALESCE(p_device_info->>'model', ''),
--               'sha256'
--           ),
--           'hex'
--       );
--       
--       RETURN v_fingerprint;
--   END;
--   $$ LANGUAGE plpgsql IMMUTABLE;

-- =============================================================================
-- TODO: Create record_device_usage function
-- DESCRIPTION: Track device usage
-- PRIORITY: HIGH
-- SECURITY: Validates permissions
-- PRIVACY: Updates risk score transparently
-- =============================================================================
-- TODO: [DEV-004] Create record_device_usage function
-- INSTRUCTIONS:
--   - Find or create fingerprint
--   - Link to account
--   - Update usage stats
--   - Calculate risk

-- =============================================================================
-- TODO: Create device risk assessment function
-- DESCRIPTION: Calculate device risk score
-- PRIORITY: MEDIUM
-- SECURITY: Automated decision with human override
-- PRIVACY: GDPR Article 22 compliance - right to contest
-- AUDIT: Risk factors logged for transparency
-- =============================================================================
-- TODO: [DEV-005] Create assess_device_risk function
-- INSTRUCTIONS:
--   - Analyze device patterns
--   - Check against known fraud patterns
--   - Update risk score
--   - Flag suspicious devices

-- =============================================================================
-- TODO: Create device fingerprint indexes
-- DESCRIPTION: Optimize device queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for login/transaction path
-- =============================================================================
-- TODO: [DEV-006] Create device fingerprint indexes
-- INDEX LIST:
--   -- Device Fingerprints:
--   - PRIMARY KEY (fingerprint_id)
--   - UNIQUE (fingerprint_hash)
--   - INDEX on (trust_status, risk_score)
--   - INDEX on (last_seen_at)
--   -- Account Links:
--   - PRIMARY KEY (link_id)
--   - UNIQUE (account_id, fingerprint_id)
--   - INDEX on (account_id, is_trusted)
--   - INDEX on (fingerprint_id, last_used_at)

/*
================================================================================
DEVICE FINGERPRINTING PRIVACY GUIDE
================================================================================

1. LAWFUL BASIS (GDPR Article 6):
   Primary: Legitimate interest (fraud prevention)
   Secondary: Consent (for enhanced tracking)
   Balance test: Necessary, proportionate, less intrusive alternatives

2. TRANSPARENCY REQUIREMENTS:
   - Privacy notice must disclose fingerprinting
   - Explain purpose: fraud prevention only
   - Describe data collected: device characteristics
   - Retention period: 2 years
   - Rights: Access, contest, erasure (where applicable)

3. AUTOMATED DECISION-MAKING (Article 22):
   - Risk scores may trigger automated blocks
   - Human review available on request
   - Right to contest automated decisions
   - Regular accuracy testing of risk models

4. DATA MINIMIZATION:
   ┌──────────────────────┬──────────────────────────────────────────────┐
   │ Data Element         │ Handling                                     │
   ├──────────────────────┼──────────────────────────────────────────────┤
   │ MSISDN               │ Included in hash only; never stored          │
   │ Device Model         │ Hashed; pattern detection only               │
   │ OS Version           │ Hashed; security patch level inferred        │
   │ Network Operator     │ Stored; geographic/regulatory info           │
   │ Usage Patterns       │ Anonymized; statistical analysis only        │
   └──────────────────────┴──────────────────────────────────────────────┘

5. RISK SCORING FACTORS (Transparent):
   - New device (never seen before): +10 points
   - Geographic anomaly (different country): +20 points
   - Velocity (multiple rapid transactions): +15 points
   - Time anomaly (unusual hour): +5 points
   - Known fraud pattern match: +50 points
   - Previously trusted device: -10 points
   
   Thresholds:
   - 0-20: Low risk, normal processing
   - 21-50: Medium risk, additional verification
   - 51+: High risk, block or manual review

6. SUBJECT RIGHTS IMPLEMENTATION:
   - Access: Device history with risk factors explained
   - Rectification: Challenge incorrect risk flags
   - Erasure: Delete device history (unless fraud investigation)
   - Portability: Export device history in standard format

SECURITY BENEFITS:
- Account takeover detection
- New device notifications
- Suspicious activity alerts
- Pattern-based fraud prevention
================================================================================
*/

/*
================================================================================
MIGRATION CHECKLIST:
□ Create device_fingerprints table
□ Create account_device_links table
□ Implement generate_device_fingerprint function
□ Implement record_device_usage function
□ Implement assess_device_risk function
□ Add all indexes for device queries
□ Test fingerprint generation
□ Test device linking
□ Test risk assessment
□ Verify unique fingerprint constraint
□ Configure risk scoring thresholds
□ Document privacy notice requirements
□ Set up automated device cleanup
□ Implement subject access request handler
================================================================================
*/
