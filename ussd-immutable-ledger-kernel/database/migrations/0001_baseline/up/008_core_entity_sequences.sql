-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Resource management)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Sequence isolation)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Reference anonymization)
-- ISO/IEC 27040:2024 - Storage Security (Gapless sequence tracking)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Sequence recovery)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Per-application sequence isolation
-- - Gapless sequence tracking for audit
-- - Advisory locking for concurrent allocation
-- - Format pattern validation
-- ============================================================================
-- =============================================================================
-- MIGRATION: 008_core_entity_sequences.sql
-- DESCRIPTION: Human-Readable Sequential Codes for Entities
-- TABLES: entity_sequences, sequence_allocations
-- DEPENDENCIES: 003_core_account_registry.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 1. Identity & Multi-Tenancy
- Feature: Entity Sequences (Human-readable codes)
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Generates tenant-scoped sequential codes for human-readable references.
USSD users see short, memorable references instead of UUIDs.
Helps with customer support and reconciliation.

KEY FEATURES:
- Per-application sequence isolation
- Customizable format patterns (CONT-2025-000123)
- Gapless or non-gapless sequences
- Pre-allocation for batch operations
- Year/month reset support

SEQUENCE PATTERNS:
- {PREFIX}-{YYYY}-{SEQ:6}  -> CONT-2025-000123
- {APP}-{SEQ:8}            -> SAV-00000456
- {TYPE}/{YYYY}/{SEQ:5}    -> LOAN/2025/00456
================================================================================
*/

-- =============================================================================
-- TODO: Create entity_sequences table
-- DESCRIPTION: Sequence definitions per entity type
-- PRIORITY: HIGH
-- SECURITY: Per-application isolation prevents cross-tenant access
-- ============================================================================
-- TODO: [SEQ-001] Create core.entity_sequences table
-- INSTRUCTIONS:
--   - Defines sequence behavior per entity type per application
--   - Supports custom format patterns
--   - Controls padding, year reset, etc.
--   - RLS POLICY: Tenant isolation by application_id
--   - ERROR HANDLING: Validate format patterns
-- COMPLIANCE: ISO/IEC 27001 (Resource Isolation)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.entity_sequences (
--       sequence_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Scope
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       entity_type         VARCHAR(50) NOT NULL,        -- 'CONTRIBUTION', 'LOAN', etc.
--       
--       -- Format Configuration
--       sequence_name       VARCHAR(100) NOT NULL,
--       format_pattern      VARCHAR(200) NOT NULL,       -- '{PREFIX}-{YYYY}-{SEQ:6}'
--       prefix              VARCHAR(20) DEFAULT '',      -- Static prefix value
--       
--       -- Sequence Behavior
--       start_value         BIGINT DEFAULT 1,
--       increment_by        INTEGER DEFAULT 1,
--       current_value       BIGINT DEFAULT 0,
--       max_value           BIGINT DEFAULT 999999,
--       
--       -- Reset Options
--       reset_period        VARCHAR(20),                 -- 'NEVER', 'YEAR', 'MONTH', 'DAY'
--       last_reset_at       TIMESTAMPTZ,
--       last_reset_value    BIGINT DEFAULT 0,            -- Value at last reset
--       
--       -- Padding
--       sequence_padding    INTEGER DEFAULT 6,           -- Minimum digits
--       padding_char        CHAR(1) DEFAULT '0',
--       
--       -- Control
--       is_active           BOOLEAN DEFAULT true,
--       is_gapless          BOOLEAN DEFAULT false,       -- true = no gaps (slower)
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id),
--       updated_at          TIMESTAMPTZ,
--       updated_by          UUID REFERENCES core.accounts(account_id)
--   );
--
-- CONSTRAINTS:
--   - UNIQUE (application_id, entity_type)

-- =============================================================================
-- TODO: Create sequence_allocations table
-- DESCRIPTION: Track allocated sequence numbers
-- PRIORITY: MEDIUM (for gapless sequences)
-- SECURITY: Audit trail of all sequence allocations
-- ============================================================================
-- TODO: [SEQ-002] Create core.sequence_allocations table
-- INSTRUCTIONS:
--   - Tracks each allocated sequence number
--   - Required for gapless sequences
--   - Records commit/rollback status
--   - AUDIT LOGGING: All allocations logged
-- COMPLIANCE: ISO/IEC 27040 (Gapless Tracking)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.sequence_allocations (
--       allocation_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       sequence_id         UUID NOT NULL REFERENCES core.entity_sequences(sequence_id),
--       
--       -- Allocated Number
--       sequence_number     BIGINT NOT NULL,
--       formatted_value     VARCHAR(100) NOT NULL,       -- Final formatted code
--       
--       -- Entity Reference
--       entity_id           UUID,                        -- ID of entity using this code
--       entity_table        VARCHAR(100),                -- Table name for entity
--       
--       -- Status
--       status              VARCHAR(20) DEFAULT 'ALLOCATED',
--                           -- ALLOCATED, COMMITTED, ROLLED_BACK
--       
--       -- Timing
--       allocated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
--       allocated_by        UUID REFERENCES core.accounts(account_id),
--       committed_at        TIMESTAMPTZ,
--       rolled_back_at      TIMESTAMPTZ,
--       
--       -- Correlation
--       session_id          UUID,                        -- For cleanup
--       transaction_id      UUID REFERENCES core.transaction_log(transaction_id)
--   );
--
-- CONSTRAINTS:
--   - UNIQUE (sequence_id, sequence_number)

-- =============================================================================
-- TODO: Create format_sequence function
-- DESCRIPTION: Format sequence number according to pattern
-- PRIORITY: HIGH
-- SECURITY: Validate pattern components
-- ============================================================================
-- TODO: [SEQ-003] Create format_sequence_code function
-- INSTRUCTIONS:
--   - Parse format_pattern
--   - Replace placeholders: {PREFIX}, {YYYY}, {MM}, {DD}, {SEQ:N}
--   - Return formatted string
--   - ERROR HANDLING: Handle invalid patterns
-- COMPLIANCE: ISO/IEC 27001 (Formatting Consistency)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.format_sequence_code(
--       p_pattern VARCHAR(200),
--       p_prefix VARCHAR(20),
--       p_sequence BIGINT,
--       p_padding INTEGER,
--       p_padding_char CHAR(1)
--   ) RETURNS VARCHAR(100) AS $$
--   DECLARE
--       v_result VARCHAR(200) := p_pattern;
--       v_seq_str VARCHAR(50);
--   BEGIN
--       -- Format sequence number with padding
--       v_seq_str := LPAD(p_sequence::text, p_padding, p_padding_char);
--       
--       -- Replace placeholders
--       v_result := REPLACE(v_result, '{PREFIX}', COALESCE(p_prefix, ''));
--       v_result := REPLACE(v_result, '{YYYY}', TO_CHAR(now(), 'YYYY'));
--       v_result := REPLACE(v_result, '{MM}', TO_CHAR(now(), 'MM'));
--       v_result := REPLACE(v_result, '{DD}', TO_CHAR(now(), 'DD'));
--       v_result := REPLACE(v_result, '{SEQ}', v_seq_str);
--       
--       -- Handle {SEQ:N} format
--       -- (additional parsing for dynamic padding)
--       
--       RETURN v_result;
--   END;
--   $$ LANGUAGE plpgsql IMMUTABLE;

-- =============================================================================
-- TODO: Create next_sequence_value function
-- DESCRIPTION: Get next sequence value with formatting
-- PRIORITY: CRITICAL
-- SECURITY: Advisory lock prevents duplicate allocation
-- ============================================================================
-- TODO: [SEQ-004] Create next_sequence_value function
-- INSTRUCTIONS:
--   - Lock sequence row for update
--   - Check reset period (year/month/day)
--   - Increment and return formatted value
--   - Handle gapless option
--   - ERROR HANDLING: Handle max_value exceeded
--   - TRANSACTION ISOLATION: Row-level lock for atomic increment
-- COMPLIANCE: ISO/IEC 27031 (Atomic Allocation)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.next_sequence_value(
--       p_application_id UUID,
--       p_entity_type VARCHAR(50),
--       p_entity_id UUID DEFAULT NULL,
--       p_session_id UUID DEFAULT NULL
--   ) RETURNS VARCHAR(100) AS $$
--   DECLARE
--       v_seq RECORD;
--       v_next_value BIGINT;
--       v_formatted VARCHAR(100);
--       v_needs_reset BOOLEAN := false;
--   BEGIN
--       -- Lock sequence row
--       SELECT * INTO v_seq
--       FROM core.entity_sequences
--       WHERE application_id = p_application_id 
--         AND entity_type = p_entity_type
--         AND is_active = true
--       FOR UPDATE;
--       
--       IF NOT FOUND THEN
--           RAISE EXCEPTION 'Sequence not found for %/%', p_application_id, p_entity_type;
--       END IF;
--       
--       -- Check reset condition
--       IF v_seq.reset_period = 'YEAR' AND 
--          (v_seq.last_reset_at IS NULL OR EXTRACT(YEAR FROM v_seq.last_reset_at) != EXTRACT(YEAR FROM now())) THEN
--           v_needs_reset := true;
--       END IF;
--       -- Similar for MONTH, DAY
--       
--       IF v_needs_reset THEN
--           v_next_value := v_seq.start_value;
--       ELSE
--           v_next_value := v_seq.current_value + v_seq.increment_by;
--       END IF;
--       
--       -- Format
--       v_formatted := core.format_sequence_code(
--           v_seq.format_pattern, v_seq.prefix, v_next_value,
--           v_seq.sequence_padding, v_seq.padding_char
--       );
--       
--       -- Update sequence
--       UPDATE core.entity_sequences
--       SET current_value = v_next_value,
--           last_reset_at = CASE WHEN v_needs_reset THEN now() ELSE last_reset_at END,
--           updated_at = now()
--       WHERE sequence_id = v_seq.sequence_id;
--       
--       -- Record allocation for gapless sequences
--       IF v_seq.is_gapless THEN
--           INSERT INTO core.sequence_allocations (
--               sequence_id, sequence_number, formatted_value,
--               entity_id, session_id, status
--           ) VALUES (
--               v_seq.sequence_id, v_next_value, v_formatted,
--               p_entity_id, p_session_id, 'ALLOCATED'
--           );
--       END IF;
--       
--       RETURN v_formatted;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create commit_sequence function
-- DESCRIPTION: Mark sequence as committed (gapless)
-- PRIORITY: MEDIUM
-- SECURITY: Verify allocation before commit
-- ============================================================================
-- TODO: [SEQ-005] Create commit_sequence_allocation function
-- INSTRUCTIONS:
--   - Update allocation status to COMMITTED
--   - Link to final entity
--   - Called after successful transaction
-- COMPLIANCE: ISO/IEC 27040 (Allocation Tracking)

-- =============================================================================
-- TODO: Create rollback_sequence function
-- DESCRIPTION: Return sequence to pool (gapless)
-- PRIORITY: MEDIUM
-- SECURITY: Audit rollback for investigation
-- ============================================================================
-- TODO: [SEQ-006] Create rollback_sequence_allocation function
-- INSTRUCTIONS:
--   - Mark allocation as ROLLED_BACK
--   - Make number available for reuse
--   - Called on transaction failure
--   - AUDIT LOGGING: Log rollback with reason
-- COMPLIANCE: ISO/IEC 27001 (Audit Trail)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create entity_sequences table with format patterns
□ Create sequence_allocations table for gapless tracking
□ Implement format_sequence_code function
□ Implement next_sequence_value function
□ Implement commit/rollback functions for gapless
□ Create sequence indexes for lookups
□ Test sequence generation with various patterns
□ Test year/month reset logic
□ Verify gapless sequence behavior
□ Add default sequences for common entity types
================================================================================
*/
