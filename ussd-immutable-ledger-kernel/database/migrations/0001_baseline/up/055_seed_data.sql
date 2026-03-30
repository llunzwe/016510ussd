-- =============================================================================
-- MIGRATION: 055_seed_data.sql
-- DESCRIPTION: Initial Seed Data
-- TABLES: All lookup tables
-- DEPENDENCIES: All previous migrations
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.5.9: Inventory of information and other associated assets
  - A.5.17: Classification of information
  - A.8.4: Removal of assets (seed data sanitization)
  - A.14.2.9: System acceptance testing

ISO/IEC 27018:2019 - Protection of PII in Public Clouds
  - Clause 7.1: Consent (default seed data must not contain real PII)

ISO/IEC 27050-3:2020 - Electronic Discovery
  - Section 6: Preservation of seed data for reproducibility

GDPR / Zimbabwe Data Protection Act (Chapter 11:12)
  - Article 25: Data protection by design (default configurations)
  - Article 32: Security defaults in seed configuration
  - Section 13: Data subject rights (no real PII in seed data)

SECURITY CLASSIFICATION: INTERNAL
DATA SENSITIVITY: SYSTEM DEFAULTS
RETENTION PERIOD: Permanent (baseline configuration)
AUDIT REQUIREMENT: Seed data versions tracked
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Data Seeding and Initial Setup
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Initial data required for system operation including account types,
transaction types, roles, permissions, and default configuration.

SEED CATEGORIES:
1. System Account Types
2. Core Transaction Types
3. Application Roles
4. Permissions
5. Chart of Accounts Structure
6. Default Configuration

SECURITY REQUIREMENTS:
- No real PII in seed data
- Default passwords must be changed on first use
- Security settings should be "secure by default"
- Seed data must be version controlled
================================================================================
*/

-- =============================================================================
-- TODO: Seed Account Types
-- DESCRIPTION: Core account classifications
-- PRIORITY: CRITICAL
-- SECURITY: Default KYC requirements enabled
-- AUDIT: Creation logged as system initialization
-- =============================================================================
-- TODO: [SEED-001] Insert account types
-- INSTRUCTIONS:
--   INSERT INTO core.account_types (type_code, type_name, description, 
--       account_class, can_have_balance, can_have_members, kyc_required) 
--   VALUES 
--       ('INDIVIDUAL', 'Individual Account', 'Personal user account',
--        'ASSET', true, false, true),
--       ('GROUP', 'Group Account', 'Savings group or collective account',
--        'ASSET', true, true, true),
--       ('MERCHANT', 'Merchant Account', 'Business or merchant account',
--        'ASSET', true, false, true),
--       ('SYSTEM', 'System Account', 'Internal system account',
--        'EQUITY', true, false, false),
--       ('VIRTUAL', 'Virtual Account', 'Virtual wallet linked to master',
--        'ASSET', true, false, false);

-- =============================================================================
-- TODO: Seed Transaction Types
-- DESCRIPTION: Core transaction classifications
-- PRIORITY: CRITICAL
-- SECURITY: Payload schemas validated; sensitive types require approval
-- COMPLIANCE: Audit logging enabled for all types
-- =============================================================================
-- TODO: [SEED-002] Insert transaction types
-- INSTRUCTIONS:
--   INSERT INTO core.transaction_types (type_code, type_name, description,
--       payload_schema, scope, required_approvals)
--   VALUES
--       ('TRANSFER', 'Transfer', 'Peer-to-peer value transfer',
--        '{"type": "object", "properties": {"to_account": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
--        'GLOBAL', 0),
--       ('CONTRIBUTION', 'Contribution', 'Savings group contribution',
--        '{"type": "object", "properties": {"group_id": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
--        'GLOBAL', 0),
--       ('LOAN_DISBURSEMENT', 'Loan Disbursement', 'Loan funds release',
--        '{"type": "object", "properties": {"loan_id": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
--        'GLOBAL', 1),
--       ('LOAN_REPAYMENT', 'Loan Repayment', 'Loan payment',
--        '{"type": "object", "properties": {"loan_id": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
--        'GLOBAL', 0),
--       ('RIDE_PAYMENT', 'Ride Payment', 'Transport service payment',
--        '{"type": "object", "properties": {"ride_id": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
--        'GLOBAL', 0),
--       ('PRODUCT_PURCHASE', 'Product Purchase', 'E-commerce transaction',
--        '{"type": "object", "properties": {"product_id": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
--        'GLOBAL', 0),
--       ('FEE', 'Fee', 'Service charge',
--        '{"type": "object", "properties": {"fee_type": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
--        'GLOBAL', 0),
--       ('INTEREST', 'Interest', 'Interest accrual or payment',
--        '{"type": "object", "properties": {"account_id": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
--        'GLOBAL', 0),
--       ('REVERSAL', 'Reversal', 'Correction of posted transaction',
--        '{"type": "object", "properties": {"original_tx_id": {"type": "string"}, "reason": {"type": "string"}}}'::jsonb,
--        'GLOBAL', 1);

-- =============================================================================
-- TODO: Seed Rejection Reasons
-- DESCRIPTION: Standard rejection codes
-- PRIORITY: HIGH
-- SECURITY: User messages sanitized (no system details)
-- PRIVACY: Error messages don't expose personal data
-- =============================================================================
-- TODO: [SEED-003] Insert rejection reasons
-- INSTRUCTIONS:
--   INSERT INTO core.rejection_reasons (reason_code, reason_category, reason_name,
--       user_message_template, severity, is_retryable)
--   VALUES
--       ('INSUFFICIENT_FUNDS', 'VALIDATION', 'Insufficient Funds',
--        'Your account does not have sufficient funds for this transaction.', 'ERROR', false),
--       ('INVALID_ACCOUNT', 'VALIDATION', 'Invalid Account',
--        'The destination account is invalid or not found.', 'ERROR', false),
--       ('INVALID_AMOUNT', 'VALIDATION', 'Invalid Amount',
--        'The transaction amount is invalid.', 'ERROR', true),
--       ('VALIDATION_FAILED', 'VALIDATION', 'Validation Failed',
--        'Transaction validation failed. Please check your input.', 'ERROR', true),
--       ('RATE_LIMIT_EXCEEDED', 'SYSTEM', 'Rate Limit Exceeded',
--        'Too many transactions. Please try again later.', 'WARNING', true),
--       ('DUPLICATE_TRANSACTION', 'VALIDATION', 'Duplicate Transaction',
--        'This transaction appears to be a duplicate.', 'ERROR', false),
--       ('COMPLIANCE_BLOCKED', 'COMPLIANCE', 'Compliance Blocked',
--        'Transaction blocked for compliance review.', 'ERROR', false),
--       ('SYSTEM_ERROR', 'SYSTEM', 'System Error',
--        'A system error occurred. Please try again.', 'ERROR', true);

-- =============================================================================
-- TODO: Seed Chart of Accounts
-- DESCRIPTION: Standard COA structure
-- PRIORITY: HIGH
-- AUDIT: COA changes require accounting approval
-- =============================================================================
-- TODO: [SEED-004] Insert COA accounts
-- INSTRUCTIONS:
--   -- Assets
--   INSERT INTO core.chart_of_accounts (coa_code, account_name, account_type, 
--       normal_balance, coa_path) VALUES
--   ('1', 'Assets', 'ASSET', 'DEBIT', '1'),
--   ('1.1', 'Cash and Bank', 'ASSET', 'DEBIT', '1.1'),
--   ('1.1.1', 'Cash on Hand', 'ASSET', 'DEBIT', '1.1.1'),
--   ('1.1.2', 'Bank Accounts', 'ASSET', 'DEBIT', '1.1.2'),
--   ('1.2', 'Receivables', 'ASSET', 'DEBIT', '1.2'),
--   ('1.2.1', 'Member Loans', 'ASSET', 'DEBIT', '1.2.1'),
--   ('1.2.2', 'Interest Receivable', 'ASSET', 'DEBIT', '1.2.2');
--   
--   -- Liabilities
--   INSERT INTO core.chart_of_accounts (coa_code, account_name, account_type,
--       normal_balance, coa_path) VALUES
--   ('2', 'Liabilities', 'LIABILITY', 'CREDIT', '2'),
--   ('2.1', 'Deposits', 'LIABILITY', 'CREDIT', '2.1'),
--   ('2.1.1', 'Member Deposits', 'LIABILITY', 'CREDIT', '2.1.1'),
--   ('2.2', 'Payables', 'LIABILITY', 'CREDIT', '2.2');
--   
--   -- Equity, Income, Expense similar...

-- =============================================================================
-- TODO: Seed Global Permissions
-- DESCRIPTION: Standard permission catalog
-- PRIORITY: HIGH
-- SECURITY: Principle of least privilege
-- COMPLIANCE: Segregation of duties enforced
-- =============================================================================
-- TODO: [SEED-005] Insert global permissions
-- INSTRUCTIONS:
--   INSERT INTO app.permissions (permission_code, resource, action, scope,
--       permission_name, description)
--   VALUES
--       ('transaction:create', 'transaction', 'create', 'own', 'Create Transaction', 'Submit new transactions'),
--       ('transaction:read', 'transaction', 'read', 'own', 'Read Transaction', 'View own transactions'),
--       ('transaction:read:all', 'transaction', 'read', 'all', 'Read All Transactions', 'View all transactions'),
--       ('account:read', 'account', 'read', 'own', 'Read Account', 'View account details'),
--       ('account:update', 'account', 'update', 'own', 'Update Account', 'Update account settings'),
--       ('balance:read', 'balance', 'read', 'own', 'Read Balance', 'Check account balance'),
--       ('report:view', 'report', 'read', 'own', 'View Reports', 'Access reports'),
--       ('admin:full', 'admin', 'all', 'all', 'Full Admin', 'Administrative access');

-- =============================================================================
-- TODO: Seed Default Configuration
-- DESCRIPTION: System default settings
-- PRIORITY: HIGH
-- SECURITY: Secure by default settings
-- PRIVACY: Data protection defaults enabled
-- =============================================================================
-- TODO: [SEED-006] Insert default configuration
-- INSTRUCTIONS:
--   INSERT INTO app.configuration (config_key, config_value, value_type,
--       description, is_editable)
--   VALUES
--       ('transaction.max_amount', '100000', 'NUMBER', 'Maximum transaction amount', true),
--       ('transaction.daily_limit', '500000', 'NUMBER', 'Daily transaction limit', true),
--       ('session.timeout_minutes', '5', 'NUMBER', 'USSD session timeout', true),
--       ('pin.max_attempts', '3', 'NUMBER', 'Maximum PIN attempts', true),
--       ('ledger.base_currency', '"USD"', 'STRING', 'Base currency for ledger', false),
--       ('rejection.retention_days', '90', 'NUMBER', 'Days to retain rejection logs', true);

-- =============================================================================
-- TODO: Seed Provision Rates
-- DESCRIPTION: Default bad debt provision rates
-- PRIORITY: MEDIUM
-- AUDIT: Rate changes logged for accounting review
-- =============================================================================
-- TODO: [SEED-007] Insert provision rates
-- INSTRUCTIONS:
--   INSERT INTO core.provision_rates (aging_bucket, days_from, days_to, 
--       provision_rate, description)
--   VALUES
--       ('CURRENT', 0, 0, 0.005, 'Current - 0.5%'),
--       ('DAYS_1_30', 1, 30, 0.02, '1-30 days past due - 2%'),
--       ('DAYS_31_60', 31, 60, 0.10, '31-60 days past due - 10%'),
--       ('DAYS_61_90', 61, 90, 0.25, '61-90 days past due - 25%'),
--       ('DAYS_91_PLUS', 91, NULL, 0.50, 'Over 90 days past due - 50%');

-- =============================================================================
-- TODO: Seed System Accounts
-- DESCRIPTION: Required system accounts
-- PRIORITY: CRITICAL
-- SECURITY: System accounts have restricted access
-- AUDIT: All system account activity monitored
-- =============================================================================
-- TODO: [SEED-008] Insert system accounts
-- INSTRUCTIONS:
--   -- System fee account
--   INSERT INTO core.accounts (account_number, account_type_id, application_id,
--       display_name, status, metadata)
--   SELECT 
--       'SYSTEM-FEE-001',
--       (SELECT account_type_id FROM core.account_types WHERE type_code = 'SYSTEM'),
--       NULL,  -- Global
--       'System Fee Collection Account',
--       'ACTIVE',
--       '{"system": true, "purpose": "fee_collection"}'::jsonb;
--   
--   -- System suspense account
--   INSERT INTO core.accounts (account_number, account_type_id, application_id,
--       display_name, status, metadata)
--   SELECT 
--       'SYSTEM-SUSPENSE-001',
--       (SELECT account_type_id FROM core.account_types WHERE type_code = 'SYSTEM'),
--       NULL,
--       'System Suspense Account',
--       'ACTIVE',
--       '{"system": true, "purpose": "suspense"}'::jsonb;

/*
================================================================================
SEED DATA SECURITY GUIDE
================================================================================

1. SEED DATA CLASSIFICATION:
   ┌──────────────────┬─────────────────────────────────────────────────────┐
   │ Category         │ Security Requirements                               │
   ├──────────────────┼─────────────────────────────────────────────────────┤
   │ Account Types    │ Public; no sensitive data                           │
   │ Transaction Types│ Internal; payload schemas validated                 │
   │ Permissions      │ Restricted; affects access control                  │
   │ Configuration    │ Internal; secure defaults required                  │
   │ System Accounts  │ Confidential; credentials separate from seed        │
   │ COA Structure    │ Internal; accounting standards compliance           │
   └──────────────────┴─────────────────────────────────────────────────────┘

2. SECURE BY DEFAULT PRINCIPLES:
   - session.timeout_minutes: 5 (minimum viable)
   - pin.max_attempts: 3 (lockout protection)
   - transaction.max_amount: Conservative limit
   - audit.enabled: true (cannot disable)
   - encryption.at_rest: true (mandatory)
   - rls.enforced: true (tenant isolation)

3. PROHIBITED IN SEED DATA:
   - Real customer data
   - Production credentials
   - Actual MSISDNs or personal data
   - Test data that resembles real patterns
   - Hardcoded passwords (even for test)
   - Internal network details

4. ENVIRONMENT-SPECIFIC OVERRIDES:
   - Development: Relaxed limits, debug enabled
   - Staging: Production-like with test data
   - Production: Strict security, no debug
   - DR: Mirror of production with different keys

5. SEED DATA VALIDATION:
   - All foreign key references valid
   - No orphaned records
   - Required fields populated
   - Constraints satisfied
   - RLS policies applied after seeding

COMPLIANCE NOTES:
- ISO 27001: Asset inventory includes seed data
- GDPR: No personal data in seed configuration
- SOX: Financial configuration (COA) reviewed by accounting
- PCI DSS: No card data in any seed files

POST-SEEDING REQUIREMENTS:
- Change default passwords immediately
- Verify RLS policies are active
- Test audit logging is working
- Confirm encryption is enabled
- Run security baseline scan
================================================================================
*/

/*
================================================================================
MIGRATION CHECKLIST:
□ Seed account types
□ Seed transaction types
□ Seed rejection reasons
□ Seed chart of accounts
□ Seed global permissions
□ Seed default configuration
□ Seed provision rates
□ Seed system accounts
□ Verify foreign key references
□ Test data integrity
□ Validate secure defaults
□ Document seed data version
□ Verify no PII in seed data
□ Post-seed security baseline scan
================================================================================
*/
