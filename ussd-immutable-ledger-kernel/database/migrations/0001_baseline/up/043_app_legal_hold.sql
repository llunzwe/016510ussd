-- =============================================================================
-- MIGRATION: 043_app_legal_hold.sql
-- DESCRIPTION: Legal Hold Management
-- TABLES: legal_holds, legal_hold_entities
-- DEPENDENCIES: 031_app_registry.sql, 022_core_document_registry.sql
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.5.35: Information security legal and regulatory requirements
  - A.8.1: User endpoint devices (litigation holds)
  - A.8.16: Monitoring activities

ISO/IEC 27050-3:2020 - Electronic Discovery
  - Section 5: Identification of ESI
  - Section 6: Preservation requirements and mechanisms
  - Section 7: Collection and acquisition
  - Legal hold is PRIMARY preservation mechanism

GDPR / Zimbabwe Data Protection Act (Chapter 11:12)
  - Article 17(3)(e): Right to erasure exception for legal claims
  - Article 18: Right to restriction of processing
  - Section 13: Data subject rights (restricted by legal obligations)

Zimbabwe Legal Framework:
  - Civil Evidence Act (preservation of evidence)
  - Criminal Procedure and Evidence Act
  - Competition Act (investigation holds)

SECURITY CLASSIFICATION: CONFIDENTIAL - LEGAL PRIVILEGE
DATA SENSITIVITY: LITIGATION-RELATED DATA
RETENTION PERIOD: Until hold released + 7 years
AUDIT REQUIREMENT: Complete chain of custody
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 13. Archival & Data Lifecycle / 10. Document & Evidence Management
- Feature: Legal Hold
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Ability to mark specific records or documents for indefinite retention during
litigation or investigation. The hold prevents any automated purging or
archiving.

KEY FEATURES:
- Hold scope (accounts, transactions, documents)
- Reason and authorization tracking
- Automatic hold enforcement
- Hold release workflow
- Audit trail

LEGAL HOLD PRINCIPLES:
- Holds override all retention policies (ISO 27050-3)
- Dual authorization required for hold release
- Complete audit trail for e-discovery proceedings
- Immutable hold records for court admissibility
================================================================================
*/

-- =============================================================================
-- TODO: Create legal_holds table
-- DESCRIPTION: Legal hold definitions
-- PRIORITY: CRITICAL
-- SECURITY: RLS restricted to legal/compliance officers
-- AUDIT: Immutable hold records; dual authorization for release
-- ISO 27050-3: Primary preservation mechanism
-- =============================================================================
-- TODO: [LH-001] Create app.legal_holds table
-- INSTRUCTIONS:
--   - Legal hold records
--   - Scope and reason tracking
--   - Authorized by legal/compliance
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE app.legal_holds (
--       hold_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       hold_reference      VARCHAR(100) UNIQUE NOT NULL,
--       
--       -- Identification
--       hold_name           VARCHAR(200) NOT NULL,
--       description         TEXT,
--       
--       -- Reason (ISO 27050-3 Section 5)
--       hold_reason         VARCHAR(100) NOT NULL,       -- LITIGATION, INVESTIGATION, AUDIT
--       case_number         VARCHAR(100),                -- External case reference
--       jurisdiction        VARCHAR(100),                -- Legal jurisdiction
--       
--       -- Scope
--       hold_scope          VARCHAR(50) NOT NULL,        -- ACCOUNT, TRANSACTION_TYPE, DATE_RANGE, CUSTOM
--       scope_criteria      JSONB,                       -- Specific criteria
--       
--       -- Application
--       application_id      UUID REFERENCES app.applications(application_id),
--       
--       -- Dates
--       hold_date           DATE NOT NULL DEFAULT CURRENT_DATE,
--       expected_release    DATE,                        -- Estimated release date
--       released_at         TIMESTAMPTZ,
--       
--       -- Authorization (Dual authorization required)
--       requested_by        UUID NOT NULL REFERENCES core.accounts(account_id),
--       authorized_by       UUID NOT NULL REFERENCES core.accounts(account_id),
--       legal_counsel       VARCHAR(200),                -- External counsel name
--       
--       -- Status
--       status              VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, RELEASED, EXPIRED
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
--   );

-- =============================================================================
-- TODO: Create legal_hold_entities table
-- DESCRIPTION: Individual records under hold
-- PRIORITY: HIGH
-- SECURITY: Access logged for e-discovery proceedings
-- AUDIT: Immutable record of what is under hold
-- =============================================================================
-- TODO: [LH-002] Create app.legal_hold_entities table
-- INSTRUCTIONS:
--   - Specific entities covered by hold
--   - Can be added/removed individually
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE app.legal_hold_entities (
--       link_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       hold_id             UUID NOT NULL REFERENCES app.legal_holds(hold_id),
--       
--       -- Entity Reference
--       entity_type         VARCHAR(50) NOT NULL,        -- ACCOUNT, TRANSACTION, DOCUMENT
--       entity_id           UUID NOT NULL,
--       
--       -- Scope
--       date_range_start    DATE,                        -- For date range holds
--       date_range_end      DATE,
--       
--       -- Status
--       is_excluded         BOOLEAN DEFAULT false,       -- Manually excluded
--       exclusion_reason    TEXT,
--       
--       -- Audit
--       added_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
--       added_by            UUID REFERENCES core.accounts(account_id)
--   );

-- =============================================================================
-- TODO: Create apply_legal_hold function
-- DESCRIPTION: Apply hold to records
-- PRIORITY: CRITICAL
-- SECURITY: SECURITY DEFINER; requires legal_hold_manager role
-- AUDIT: Creates immutable hold record for court admissibility
-- DATA PROTECTION: Preserves data per Article 17(3)(e) GDPR exception
-- =============================================================================
-- TODO: [LH-003] Create apply_legal_hold function
-- INSTRUCTIONS:
--   - Mark records in scope
--   - Update document_registry legal_hold flags
--   - Create legal_hold_entities entries
--   - Prevent archival
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION app.apply_legal_hold(
--       p_hold_id UUID
--   ) RETURNS INTEGER AS $$
--   DECLARE
--       v_hold RECORD;
--       v_count INTEGER := 0;
--   BEGIN
--       -- Get hold
--       SELECT * INTO v_hold FROM app.legal_holds WHERE hold_id = p_hold_id;
--       
--       -- Apply based on scope
--       CASE v_hold.hold_scope
--           WHEN 'ACCOUNT' THEN
--               -- Mark account transactions
--               INSERT INTO app.legal_hold_entities (hold_id, entity_type, entity_id)
--               SELECT p_hold_id, 'TRANSACTION', transaction_id
--               FROM core.transaction_log
--               WHERE initiator_account_id = (v_hold.scope_criteria->>'account_id')::UUID;
--               
--               GET DIAGNOSTICS v_count = ROW_COUNT;
--               
--           WHEN 'DATE_RANGE' THEN
--               -- Mark transactions in date range
--               INSERT INTO app.legal_hold_entities (hold_id, entity_type, entity_id)
--               SELECT p_hold_id, 'TRANSACTION', transaction_id
--               FROM core.transaction_log
--               WHERE entry_date BETWEEN 
--                   (v_hold.scope_criteria->>'start_date')::DATE 
--                   AND (v_hold.scope_criteria->>'end_date')::DATE;
--               
--               GET DIAGNOSTICS v_count = ROW_COUNT;
--               
--           WHEN 'DOCUMENT' THEN
--               -- Mark documents
--               UPDATE core.document_registry
--               SET legal_hold = true,
--                   legal_hold_reason = v_hold.hold_name,
--                   legal_hold_set_at = now(),
--                   legal_hold_set_by = v_hold.authorized_by
--               WHERE document_id = ANY(
--                   SELECT (jsonb_array_elements_text(v_hold.scope_criteria->'document_ids'))::UUID
--               );
--       END CASE;
--       
--       RETURN v_count;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create release_legal_hold function
-- DESCRIPTION: Release legal hold
-- PRIORITY: HIGH
-- SECURITY: Requires dual authorization; logs all release actions
-- AUDIT: Immutable release record with reason
-- GDPR: Restores normal retention processing
-- =============================================================================
-- TODO: [LH-004] Create release_legal_hold function
-- INSTRUCTIONS:
--   - Update hold status
--   - Clear document_registry flags
--   - Record release reason

-- =============================================================================
-- TODO: Create check_legal_hold function
-- DESCRIPTION: Check if entity is on hold
-- PRIORITY: HIGH
-- SECURITY: STABLE function for retention policy checks
-- RETURNS: Hold status for e-discovery and retention decisions
-- =============================================================================
-- TODO: [LH-005] Create is_under_legal_hold function
-- INSTRUCTIONS:
--   - Check if entity is under any active hold
--   - Return hold details
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION app.is_under_legal_hold(
--       p_entity_type VARCHAR(50),
--       p_entity_id UUID
--   ) RETURNS TABLE (
--       is_on_hold BOOLEAN,
--       hold_id UUID,
--       hold_reference VARCHAR(100),
--       hold_name VARCHAR(200)
--   ) AS $$
--   BEGIN
--       RETURN QUERY
--       SELECT 
--           true,
--           lh.hold_id,
--           lh.hold_reference,
--           lh.hold_name
--       FROM app.legal_holds lh
--       JOIN app.legal_hold_entities lhe ON lh.hold_id = lhe.hold_id
--       WHERE lhe.entity_type = p_entity_type
--           AND lhe.entity_id = p_entity_id
--           AND lh.status = 'ACTIVE'
--           AND NOT lhe.is_excluded
--       LIMIT 1;
--       
--       IF NOT FOUND THEN
--           RETURN QUERY SELECT false, NULL::UUID, NULL::VARCHAR, NULL::VARCHAR;
--       END IF;
--   END;
--   $$ LANGUAGE plpgsql STABLE;

-- =============================================================================
-- TODO: Create legal hold indexes
-- DESCRIPTION: Optimize hold queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for retention policy performance
-- =============================================================================
-- TODO: [LH-006] Create legal hold indexes
-- INDEX LIST:
--   -- Legal Holds:
--   - PRIMARY KEY (hold_id)
--   - UNIQUE (hold_reference)
--   - INDEX on (application_id, status)
--   - INDEX on (hold_date, expected_release)
--   -- Entities:
--   - PRIMARY KEY (link_id)
--   - INDEX on (hold_id, entity_type, entity_id)
--   - INDEX on (entity_type, entity_id)

/*
================================================================================
LEGAL HOLD WORKFLOW - ISO/IEC 27050-3 COMPLIANT
================================================================================

1. HOLD INITIATION:
   ┌────────────────────────────────────────────────────────────────────┐
   │ Legal Counsel identifies need for hold                             │
   │ ↓                                                                  │
   │ Requester creates hold in system (status: PENDING)                 │
   │ ↓                                                                  │
   │ Authorizer reviews and approves (dual authorization)               │
   │ ↓                                                                  │
   │ apply_legal_hold() marks all in-scope records                      │
   │ ↓                                                                  │
   │ Retention policies bypass held records                             │
   └────────────────────────────────────────────────────────────────────┘

2. HOLD TYPES:
   - LITIGATION: Court proceedings or anticipated litigation
   - INVESTIGATION: Regulatory or internal investigation
   - AUDIT: Tax or compliance audit
   - REGULATORY: Statutory preservation requirement

3. SCOPE CRITERIA (JSONB):
   - ACCOUNT: { "account_id": "uuid" }
   - DATE_RANGE: { "start_date": "2024-01-01", "end_date": "2024-03-31" }
   - CUSTOM: Arbitrary JSON matching business logic

4. E-DISCOVERY EXPORT:
   - Export includes hold metadata
   - Chain of custody preserved
   - Hash verification for integrity
   - Format: EDRM XML or native

5. HOLD RELEASE:
   - Legal counsel approval required
   - 30-day cooling-off period recommended
   - Automatic notification to data protection officer
   - Normal retention resumes after release

GDPR CONSIDERATIONS:
- Legal hold is valid basis for retention beyond normal periods (Art 17(3)(e))
- Data subjects must be informed if hold affects their erasure requests
- Hold records are subject to data subject access requests
================================================================================
*/

/*
================================================================================
MIGRATION CHECKLIST:
□ Create legal_holds table
□ Create legal_hold_entities table
□ Implement apply_legal_hold function
□ Implement release_legal_hold function
□ Implement is_under_legal_hold function
□ Add all indexes for hold queries
□ Test hold application
□ Test hold release
□ Verify archival blocking
□ Test entity exclusion
□ Document dual authorization workflow
□ Configure e-discovery export format
================================================================================
*/
