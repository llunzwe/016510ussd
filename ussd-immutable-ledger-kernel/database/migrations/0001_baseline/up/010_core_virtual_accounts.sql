-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Account segregation)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Virtual isolation)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Sub-account privacy)
-- ISO/IEC 27040:2024 - Storage Security (Virtual account integrity)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Virtual recovery)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Master/virtual account linkage validation
-- - Auto-sweep rule validation
-- - IBAN format validation
-- - Balance aggregation to master account
-- ============================================================================
-- =============================================================================
-- MIGRATION: 010_core_virtual_accounts.sql
-- DESCRIPTION: Virtual Accounts & Master Account Segregation
-- TABLES: virtual_accounts, virtual_account_rules, iban_mappings
-- DEPENDENCIES: 003_core_account_registry.sql, 006_core_movement_postings.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 2. Core Immutable Ledger
- Feature: Virtual Accounts & Master Account Segregation
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Enables virtual wallets for USSD users without creating separate physical
bank accounts. Virtual accounts linked to master container with auto-sweep
rules for fund consolidation.

KEY FEATURES:
- Virtual accounts linked to master accounts
- Auto-sweep rules (time-based or balance-based)
- IBAN generation/validation support
- Sub-ledger support for merchant reconciliation
- Virtual account lifecycle management
- Balance aggregation to master account

USSD USE CASES:
- Individual member wallets within savings group master account
- Sub-accounts for budget categories
- Temporary holding accounts for pending transactions
- Merchant virtual accounts for marketplace sellers
================================================================================
*/

-- =============================================================================
-- TODO: Create virtual_accounts table
-- DESCRIPTION: Virtual account definitions
-- PRIORITY: CRITICAL
-- SECURITY: IBAN validation, balance limits
-- ============================================================================
-- TODO: [VA-001] Create core.virtual_accounts table
-- INSTRUCTIONS:
--   - Links to master (physical) account
--   - Independent balance tracking
--   - Supports IBAN for external transfers
--   - RLS POLICY: Tenant isolation
--   - ERROR HANDLING: Validate IBAN format
-- COMPLIANCE: ISO/IEC 27018 (Account Protection)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.virtual_accounts (
--       virtual_account_id  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Display
--       virtual_account_number VARCHAR(50) UNIQUE NOT NULL,
--       virtual_account_name VARCHAR(200),
--       
--       -- Linkage
--       master_account_id   UUID NOT NULL REFERENCES core.accounts(account_id),
--       application_id      UUID NOT NULL REFERENCES app.applications(application_id),
--       
--       -- Type & Purpose
--       virtual_account_type VARCHAR(50) DEFAULT 'WALLET', -- WALLET, ESCROW, SAVINGS
--       purpose             TEXT,
--       
--       -- External Reference
--       iban                VARCHAR(34) UNIQUE,           -- International format
--       bban                VARCHAR(30),                  -- Basic format
--       bic_swift           VARCHAR(11),
--       
--       -- Balance Limits
--       max_balance         NUMERIC(20, 8),
--       min_balance         NUMERIC(20, 8) DEFAULT 0,
--       
--       -- Status
--       status              VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, FROZEN, CLOSED
--       opened_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
--       closed_at           TIMESTAMPTZ,
--       
--       -- Metadata
--       metadata            JSONB DEFAULT '{}',
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id)
--   );

-- =============================================================================
-- TODO: Create virtual_account_rules table
-- DESCRIPTION: Auto-sweep and behavior rules
-- PRIORITY: HIGH
-- SECURITY: Validate rule parameters to prevent abuse
-- ============================================================================
-- TODO: [VA-002] Create core.virtual_account_rules table
-- INSTRUCTIONS:
--   - Auto-sweep rules for fund consolidation
--   - Trigger conditions and actions
--   - Priority ordering for multiple rules
--   - ERROR HANDLING: Validate JSON rule conditions
-- COMPLIANCE: ISO/IEC 27001 (Automated Controls)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.virtual_account_rules (
--       rule_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       virtual_account_id  UUID NOT NULL REFERENCES core.virtual_accounts(virtual_account_id),
--       
--       -- Rule Definition
--       rule_name           VARCHAR(100) NOT NULL,
--       rule_type           VARCHAR(50) NOT NULL,        -- SWEEP, ALERT, BLOCK
--       
--       -- Trigger Conditions
--       trigger_event       VARCHAR(50),                 -- BALANCE_THRESHOLD, SCHEDULED
--       trigger_condition   JSONB,                       -- { "operator": ">", "amount": 1000 }
--       
--       -- Action
--       action_type         VARCHAR(50),                 -- TRANSFER, NOTIFY, FREEZE
--       action_params       JSONB,                       -- { "target_account": "...", "amount": "ALL" }
--       
--       -- Scheduling (for time-based rules)
--       schedule_expression VARCHAR(100),                -- Cron expression
--       timezone            VARCHAR(50) DEFAULT 'UTC',
--       
--       -- Control
--       priority            INTEGER DEFAULT 0,
--       is_active           BOOLEAN DEFAULT true,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       last_executed_at    TIMESTAMPTZ,
--       execution_count     INTEGER DEFAULT 0
--   );

-- =============================================================================
-- TODO: Create virtual_account_movements view
-- DESCRIPTION: Movements affecting virtual accounts
-- PRIORITY: HIGH
-- SECURITY: Filter by virtual account context
-- ============================================================================
-- TODO: [VA-003] Create virtual_account_movements view
-- INSTRUCTIONS:
--   - Union of movements from/to virtual accounts
--   - Derive from movement_legs with virtual account context
--   - Include running balance per virtual account
--   - RLS POLICY: Tenant and account isolation
-- COMPLIANCE: ISO/IEC 27018 (Virtual Data Access)
--
-- VIEW DEFINITION OUTLINE:
--   CREATE VIEW core.virtual_account_movements AS
--   SELECT 
--       ml.leg_id,
--       ml.movement_id,
--       va.virtual_account_id,
--       va.master_account_id,
--       ml.direction,
--       ml.amount,
--       ml.currency,
--       ml.coa_code,
--       ml.created_at
--   FROM core.movement_legs ml
--   JOIN core.virtual_accounts va ON ml.account_id = va.master_account_id
--   WHERE ml.metadata->>'virtual_account_id' IS NOT NULL;

-- =============================================================================
-- TODO: Create virtual account balance function
-- DESCRIPTION: Calculate current balance of virtual account
-- PRIORITY: HIGH
-- SECURITY: Parameter validation prevents injection
-- ============================================================================
-- TODO: [VA-004] Create get_virtual_account_balance function
-- INSTRUCTIONS:
--   - Sum all movements tagged with virtual_account_id
--   - Return current balance
--   - Support point-in-time queries
--   - ERROR HANDLING: Validate virtual_account_id exists
--   - SEARCH PATH: Explicitly set
-- COMPLIANCE: ISO/IEC 27031 (Balance Accuracy)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.get_virtual_account_balance(
--       p_virtual_account_id UUID,
--       p_as_of TIMESTAMPTZ DEFAULT now()
--   ) RETURNS NUMERIC AS $$
--   DECLARE
--       v_balance NUMERIC;
--   BEGIN
--       SELECT COALESCE(SUM(
--           CASE WHEN ml.direction = 'DEBIT' THEN ml.amount ELSE -ml.amount END
--       ), 0)
--       INTO v_balance
--       FROM core.movement_legs ml
--       JOIN core.movement_headers mh ON ml.movement_id = mh.movement_id
--       WHERE ml.metadata->>'virtual_account_id' = p_virtual_account_id::text
--         AND mh.status = 'POSTED'
--         AND mh.posted_at <= p_as_of;
--       
--       RETURN v_balance;
--   END;
--   $$ LANGUAGE plpgsql STABLE;

-- =============================================================================
-- TODO: Create sweep execution function
-- DESCRIPTION: Execute auto-sweep rules
-- PRIORITY: MEDIUM
-- SECURITY: Validate rule ownership before execution
-- ============================================================================
-- TODO: [VA-005] Create execute_sweep_rules function
-- INSTRUCTIONS:
--   - Evaluate all active sweep rules
--   - Create movements for triggered rules
--   - Record execution history
--   - Handle partial sweeps
--   - ERROR HANDLING: Rollback on sweep failure
-- COMPLIANCE: ISO/IEC 27001 (Automated Processing)

-- =============================================================================
-- TODO: Create IBAN validation function
-- DESCRIPTION: Validate IBAN format and checksum
-- PRIORITY: MEDIUM
-- SECURITY: ISO 13616 standard compliance
-- ============================================================================
-- TODO: [VA-006] Create validate_iban function
-- INSTRUCTIONS:
--   - Check IBAN format per country
--   - Validate checksum
--   - Return validation result
--   - ERROR HANDLING: Handle invalid characters
-- COMPLIANCE: ISO 13616 (IBAN Standard)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.validate_iban(p_iban VARCHAR(34))
--   RETURNS TABLE (
--       is_valid BOOLEAN,
--       country_code VARCHAR(2),
--       check_digits VARCHAR(2),
--       bban VARCHAR(30)
--   ) AS $$
--   DECLARE
--       v_rearranged VARCHAR(50);
--       v_numeric VARCHAR(100);
--       v_mod INTEGER;
--   BEGIN
--       -- Basic format check
--       IF p_iban !~ '^[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}$' THEN
--           RETURN QUERY SELECT false, NULL::VARCHAR, NULL::VARCHAR, NULL::VARCHAR;
--           RETURN;
--       END IF;
--       
--       -- Move first 4 chars to end
--       v_rearranged := substring(p_iban from 5) || substring(p_iban from 1 for 4);
--       
--       -- Convert letters to numbers (A=10, B=11, etc.)
--       -- Calculate mod 97
--       -- If result is 1, IBAN is valid
--       
--       RETURN QUERY SELECT true, 
--           substring(p_iban from 1 for 2),
--           substring(p_iban from 3 for 2),
--           substring(p_iban from 5);
--   END;
--   $$ LANGUAGE plpgsql IMMUTABLE;

/*
================================================================================
MIGRATION CHECKLIST:
□ Create virtual_accounts table with IBAN support
□ Create virtual_account_rules table for auto-sweep
□ Create virtual_account_movements view
□ Implement get_virtual_account_balance function
□ Implement sweep execution function
□ Implement IBAN validation function
□ Add indexes for virtual account lookups
□ Test auto-sweep rule evaluation
□ Test IBAN generation and validation
□ Verify master/virtual balance aggregation
================================================================================
*/
