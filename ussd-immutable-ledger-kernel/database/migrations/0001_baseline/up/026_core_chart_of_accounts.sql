-- =============================================================================
-- MIGRATION: 026_core_chart_of_accounts.sql
-- DESCRIPTION: Chart of Accounts (COA) - Hierarchical GL Structure
-- TABLES: chart_of_accounts, coa_balances, coa_account_mappings
-- DEPENDENCIES: 005_core_movement_legs.sql
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems - ISMS)
  - A.5.1: Information security policies
  - A.8.1: User endpoint devices
  - A.8.2: Privileged access rights
  - A.9.2: Access to networks and network services
  - A.12.1: Operational procedures and responsibilities
  - A.12.3: Information backup
  - A.12.4: Logging and monitoring
  - A.12.5: Control of operational software

ISO/IEC 27018:2019 (Protection of PII in Public Clouds)
  - Clause 7: Obligations to the customer
  - Clause 8: Information disclosure and access
  - Annex A: Personally Identifiable Information protection controls
  - PII Classification: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED

ISO/IEC 27040:2024 (Storage Security)
  - Section 5: Storage security architecture
  - Section 6: Data protection and encryption
  - Section 7: Access control and authentication
  - Section 8: Storage security monitoring

ISO 9001:2015 (Quality Management Systems)
  - Clause 7.1: Resources
  - Clause 7.5: Documented information
  - Clause 8.5: Production and service provision
  - Clause 9.1: Monitoring and measurement
  - Clause 10.2: Nonconformity and corrective action

ISO 31000:2018 (Risk Management Guidelines)
  - Principle 4: Integration into organizational processes
  - Principle 6: Based on best available information
  - Risk treatment: Avoid, Mitigate, Transfer, Accept

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

SECURITY BEST PRACTICES:
  [SECURITY-001] SECURITY DEFINER: Functions execute with owner's privileges
                  REQUIRED for: admin functions, cross-schema access, audit logging
  [SECURITY-002] Input validation: All parameters validated before processing
                  Use: CHECK constraints, domain types, function preconditions
  [SECURITY-003] Row-Level Security (RLS): Enabled for tenant isolation
                  Policy: CREATE POLICY tenant_isolation ON table USING (tenant_id = current_tenant())
  [SECURITY-004] Audit logging: All changes recorded in audit trail
                  Trigger: audit_trigger() on all tables logging to audit.audit_log
  [SECURITY-005] Encryption at rest: Sensitive data encrypted with AES-256
                  Use: pgcrypto extension, column-level encryption for PII

FUNCTION VOLATILITY DECLARATIONS:
  [VOLATILITY] IMMUTABLE: Function cannot modify database; returns same result
               for same arguments within single query
               Use for: pure calculations, formatting functions, hash computation
               Example: IMMUTABLE FUNCTION calculate_hash(data TEXT) RETURNS BYTEA
  
  [VOLATILITY] STABLE: Function cannot modify database; returns same result
               for same arguments within single statement
               Use for: lookups, current timestamp, configuration reads
               Example: STABLE FUNCTION get_exchange_rate(from_curr VARCHAR, to_curr VARCHAR)
  
  [VOLATILITY] VOLATILE: Function can modify database; result may vary
               Use for: DML operations, sequence access, random values
               Example: VOLATILE FUNCTION create_transaction(payload JSONB)

ERROR HANDLING PATTERNS:
  [ERROR-001] EXCEPTION WHEN OTHERS THEN: Catch-all error handler
              USE WITH CAUTION - always re-raise or log
              Pattern: EXCEPTION WHEN OTHERS THEN log_error(...); RAISE;
  
  [ERROR-002] RAISE EXCEPTION: Structured error messages with HINT
              Format: RAISE EXCEPTION 'Context: %', param USING HINT = 'Suggestion';
              SQLSTATE: Use custom codes for application errors
  
  [ERROR-003] RAISE NOTICE: Informational messages for debugging
              Use in development only; disable in production
  
  [ERROR-004] SQLSTATE handling: Specific error code catching
              Pattern: EXCEPTION WHEN unique_violation THEN ...
              Common: unique_violation, foreign_key_violation, check_violation

TRANSACTION CONTROL DOCUMENTATION:
  [TRANSACTION] BEGIN/COMMIT/ROLLBACK: Explicit transaction boundaries
                Use for: Multi-statement operations requiring atomicity
  
  [TRANSACTION] SAVEPOINT: Partial rollback capability
                Pattern: SAVEPOINT sp1; ...; ROLLBACK TO SAVEPOINT sp1;
                Use for: Nested operations with selective failure handling
  
  [TRANSACTION] ISOLATION LEVEL: Serializable for critical operations
                Syntax: SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
                Use for: Financial calculations, balance updates, inventory

AUDIT TRAIL INTEGRATION:
  [AUDIT] created_at, created_by: Record creation tracking
          Columns: created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                   created_by UUID REFERENCES core.accounts(account_id)
  
  [AUDIT] updated_at, updated_by: Modification tracking
          Trigger: update_timestamp_trigger() sets updated_at = now()
  
  [AUDIT] superseded_by, valid_from, valid_to: Temporal versioning
          Pattern: Append-only tables, new version supersedes old
          Query: WHERE valid_to IS NULL AND is_current = true
  
  [AUDIT] status, status_reason: State change tracking
          Pattern: status VARCHAR(20), status_reason TEXT, status_changed_at TIMESTAMPTZ

DATA RETENTION COMPLIANCE:
  [RETENTION] retention_until: Automatic purging after retention period
              Policy: DELETE FROM table WHERE retention_until < CURRENT_DATE AND legal_hold = false
              Audit: Log all purges to retention.audit_log
  
  [RETENTION] legal_hold: Override retention for legal requirements
              Flag: legal_hold BOOLEAN DEFAULT false
              Fields: legal_hold_reason TEXT, legal_hold_set_at TIMESTAMPTZ, legal_hold_set_by UUID
              Enforcement: Prevent deletion/purge when legal_hold = true
  
  [RETENTION] archive_manifest: Cold storage tracking
              Table: archive.archive_manifest tracks all archived records
              Fields: storage_provider, storage_bucket, storage_key, content_hash
              Verification: SHA-256 hash verification on restore
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 15. Financial Reporting & Accounting
- Feature: Chart of Accounts (COA)
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Hierarchical GL accounts (asset, liability, equity, income, expense) with
LTREE path. Each value container can be mapped to a COA account for
financial reporting. Implements ISO 9001 quality management for financial data.

KEY FEATURES:
- Hierarchical structure using LTREE for rollup reporting
- Automatic balance aggregation (ISO 9001 9.1 monitoring)
- Period-end closing with audit trail
- Multi-currency support with conversion
- Temporal validity for historical reporting

ACCOUNT TYPES:
- ASSET: Bank accounts, receivables (normal balance: DEBIT)
- LIABILITY: Payables, deposits (normal balance: CREDIT)
- EQUITY: Capital, retained earnings (normal balance: CREDIT)
- INCOME: Revenue, fees (normal balance: CREDIT)
- EXPENSE: Operating costs, interest (normal balance: DEBIT)

QUALITY CONTROLS (ISO 9001):
- [AUDIT] created_by, created_at: COA entry tracking
- [AUDIT] version control for COA changes
- [ERROR-002] Validation constraints on account codes
- Balance verification: debits = credits in trial balance
================================================================================
*/


-- =============================================================================
-- TODO: Create chart_of_accounts table
-- DESCRIPTION: Hierarchical GL account structure
-- PRIORITY: CRITICAL
-- =============================================================================
-- TODO: [COA-001] Create core.chart_of_accounts table
-- INSTRUCTIONS:
--   - Hierarchical accounts using LTREE
--   - Supports rollup reporting
--   - Versioned for changes
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.chart_of_accounts (
--       coa_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       coa_code            VARCHAR(50) NOT NULL,        -- Unique account code
--       
--       -- Hierarchy (LTREE)
--       parent_coa_id       UUID REFERENCES core.chart_of_accounts(coa_id),
--       coa_path            LTREE NOT NULL,
--       level               INTEGER NOT NULL DEFAULT 0,
--       
--       -- Classification
--       account_type        VARCHAR(20) NOT NULL,        -- ASSET, LIABILITY, EQUITY, INCOME, EXPENSE
--       account_category    VARCHAR(50),                 -- Sub-classification
--       
--       -- Names
--       account_name        VARCHAR(200) NOT NULL,
--       account_name_short  VARCHAR(50),
--       description         TEXT,
--       
--       -- Accounting
--       normal_balance      VARCHAR(6) NOT NULL,         -- DEBIT or CREDIT
--       is_bank_account     BOOLEAN DEFAULT false,
--       is_control_account  BOOLEAN DEFAULT false,       -- System-managed
--       
--       -- Currency
--       currency            VARCHAR(3),                  -- NULL = any currency
--       
--       -- Status
--       status              VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, INACTIVE, CLOSED
--       
--       -- Validity
--       valid_from          DATE NOT NULL DEFAULT CURRENT_DATE,
--       valid_to            DATE,
--       
--       -- Mapping
--       external_account_code VARCHAR(50),               -- For external system integration
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id)
--   );
--
-- CONSTRAINTS:
--   - UNIQUE (coa_code, valid_to) WHERE valid_to IS NULL
--   - CHECK (account_type IN ('ASSET', 'LIABILITY', 'EQUITY', 'INCOME', 'EXPENSE'))
--   - CHECK (normal_balance IN ('DEBIT', 'CREDIT'))

-- =============================================================================
-- TODO: Create coa_account_mappings table
-- DESCRIPTION: Link accounts to COA codes
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [COA-002] Create core.coa_account_mappings table
-- INSTRUCTIONS:
--   - Maps internal accounts to COA accounts
--   - Supports many-to-one mappings
--   - Temporal validity
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.coa_account_mappings (
--       mapping_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Account Link
--       account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
--       coa_id              UUID NOT NULL REFERENCES core.chart_of_accounts(coa_id),
--       
--       -- Mapping Type
--       mapping_type        VARCHAR(50) DEFAULT 'PRIMARY', -- PRIMARY, SECONDARY
--       
--       -- Validity
--       valid_from          DATE NOT NULL DEFAULT CURRENT_DATE,
--       valid_to            DATE,
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id),
--       
--       UNIQUE (account_id, coa_id, valid_from)
--   );

-- =============================================================================
-- TODO: Create coa_period_balances table
-- DESCRIPTION: Aggregated balances per COA per period
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [COA-003] Create core.coa_period_balances table
-- INSTRUCTIONS:
--   - Snapshot of opening/closing balances per period
--   - Supports trial balance generation
--   - Populated by EOD process
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.coa_period_balances (
--       balance_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- COA and Period
--       coa_id              UUID NOT NULL REFERENCES core.chart_of_accounts(coa_id),
--       fiscal_period_id    UUID NOT NULL REFERENCES app.fiscal_periods(period_id),
--       
--       -- Currency
--       currency            VARCHAR(3) NOT NULL,
--       
--       -- Balances
--       opening_balance     NUMERIC(20, 8) NOT NULL DEFAULT 0,
--       period_debits       NUMERIC(20, 8) NOT NULL DEFAULT 0,
--       period_credits      NUMERIC(20, 8) NOT NULL DEFAULT 0,
--       closing_balance     NUMERIC(20, 8) NOT NULL DEFAULT 0,
--       
--       -- Verification
--       is_balanced         BOOLEAN DEFAULT true,
--       
--       -- Audit
--       calculated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
--       calculated_by       UUID REFERENCES core.accounts(account_id),
--       
--       UNIQUE (coa_id, fiscal_period_id, currency)
--   );

-- =============================================================================
-- TODO: Create trial balance view
-- DESCRIPTION: Generate trial balance report
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [COA-004] Create trial_balance view
-- INSTRUCTIONS:
--   - Show all COA accounts with balances
--   - Verify debits = credits
--   - Support filtering by period
--
-- VIEW DEFINITION OUTLINE:
--   CREATE VIEW core.trial_balance AS
--   SELECT 
--       c.coa_code,
--       c.account_name,
--       c.account_type,
--       c.normal_balance,
--       cb.opening_balance,
--       cb.period_debits,
--       cb.period_credits,
--       cb.closing_balance,
--       cb.currency,
--       fp.period_name
--   FROM core.coa_period_balances cb
--   JOIN core.chart_of_accounts c ON cb.coa_id = c.coa_id
--   JOIN app.fiscal_periods fp ON cb.fiscal_period_id = fp.period_id
--   WHERE c.status = 'ACTIVE';

-- =============================================================================
-- TODO: Create balance aggregation function
-- DESCRIPTION: Aggregate balances up hierarchy
-- PRIORITY: MEDIUM
-- =============================================================================
-- TODO: [COA-005] Create aggregate_coa_balances function
-- INSTRUCTIONS:
--   - Sum child account balances to parents
--   - Used for hierarchical reporting
--   - Recursive aggregation up the tree

-- =============================================================================
-- TODO: Create COA indexes
-- DESCRIPTION: Optimize COA queries
-- PRIORITY: HIGH
-- =============================================================================
-- TODO: [COA-006] Create COA indexes
-- INDEX LIST:
--   -- Chart of Accounts:
--   - PRIMARY KEY (coa_id)
--   - UNIQUE (coa_code) WHERE valid_to IS NULL
--   - INDEX on (coa_path)
--   - INDEX on (account_type, coa_code)
--   - INDEX on (parent_coa_id)
--   -- Mappings:
--   - PRIMARY KEY (mapping_id)
--   - INDEX on (account_id, valid_from, valid_to)
--   - INDEX on (coa_id)
--   -- Balances:
--   - PRIMARY KEY (balance_id)
--   - UNIQUE (coa_id, fiscal_period_id, currency)
--   - INDEX on (fiscal_period_id)

/*
================================================================================
MIGRATION CHECKLIST:
□ Create chart_of_accounts table with LTREE hierarchy
□ Create coa_account_mappings table
□ Create coa_period_balances table
□ Create trial_balance view
□ Implement aggregate_coa_balances function
□ Add all indexes for COA queries
□ Test hierarchical queries
□ Test balance aggregation
□ Verify trial balance accuracy
□ Add seed COA structure
================================================================================
*/
