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
-- IMPLEMENTED: Seed Account Types
-- DESCRIPTION: Core account classifications
-- PRIORITY: CRITICAL
-- SECURITY: Default KYC requirements enabled
-- AUDIT: Creation logged as system initialization
-- =============================================================================
-- [SEED-001] Insert account types
INSERT INTO core.account_types (type_code, type_name, description, 
    account_class, can_have_balance, can_have_members, kyc_required) 
VALUES 
    ('INDIVIDUAL', 'Individual Account', 'Personal user account',
     'ASSET', true, false, true),
    ('GROUP', 'Group Account', 'Savings group or collective account',
     'ASSET', true, true, true),
    ('MERCHANT', 'Merchant Account', 'Business or merchant account',
     'ASSET', true, false, true),
    ('SYSTEM', 'System Account', 'Internal system account',
     'EQUITY', true, false, false),
    ('VIRTUAL', 'Virtual Account', 'Virtual wallet linked to master',
     'ASSET', true, false, false)
ON CONFLICT (type_code) DO NOTHING;

-- =============================================================================
-- IMPLEMENTED: Seed Transaction Types
-- DESCRIPTION: Core transaction classifications
-- PRIORITY: CRITICAL
-- SECURITY: Payload schemas validated; sensitive types require approval
-- COMPLIANCE: Audit logging enabled for all types
-- =============================================================================
-- [SEED-002] Insert transaction types
INSERT INTO core.transaction_types (type_code, type_name, description,
    payload_schema, scope, required_approvals)
VALUES
    ('TRANSFER', 'Transfer', 'Peer-to-peer value transfer',
     '{"type": "object", "properties": {"to_account": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
     'GLOBAL', 0),
    ('CONTRIBUTION', 'Contribution', 'Savings group contribution',
     '{"type": "object", "properties": {"group_id": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
     'GLOBAL', 0),
    ('LOAN_DISBURSEMENT', 'Loan Disbursement', 'Loan funds release',
     '{"type": "object", "properties": {"loan_id": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
     'GLOBAL', 1),
    ('LOAN_REPAYMENT', 'Loan Repayment', 'Loan payment',
     '{"type": "object", "properties": {"loan_id": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
     'GLOBAL', 0),
    ('RIDE_REQUEST', 'Ride Request', 'Passenger requests a ride',
     '{"type": "object", "properties": {"pickup": {"type": "object"}, "destination": {"type": "object"}, "vehicle_type": {"type": "string"}}}'::jsonb,
     'GLOBAL', 0),
    ('DRIVER_ASSIGNMENT', 'Driver Assignment', 'System assigns driver to ride request',
     '{"type": "object", "properties": {"ride_request_tx_id": {"type": "string"}, "driver_account_id": {"type": "string"}}}'::jsonb,
     'GLOBAL', 0),
    ('TRIP_START', 'Trip Start', 'Driver marks trip as started',
     '{"type": "object", "properties": {"ride_request_tx_id": {"type": "string"}, "start_location": {"type": "object"}}}'::jsonb,
     'GLOBAL', 0),
    ('RIDE_PAYMENT', 'Ride Payment', 'Transport service payment',
     '{"type": "object", "properties": {"ride_id": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
     'GLOBAL', 0),
    ('TRIP_COMPLETE', 'Trip Complete', 'Driver marks trip as completed',
     '{"type": "object", "properties": {"ride_request_tx_id": {"type": "string"}, "final_fare": {"type": "number"}}}'::jsonb,
     'GLOBAL', 0),
    ('RATING', 'Rating', 'Mutual rating between rider and driver',
     '{"type": "object", "properties": {"trip_tx_id": {"type": "string"}, "stars": {"type": "integer"}, "comment": {"type": "string"}}}'::jsonb,
     'GLOBAL', 0),
    ('CANCELLATION_FEE', 'Cancellation Fee', 'Fee charged for trip cancellation',
     '{"type": "object", "properties": {"ride_request_tx_id": {"type": "string"}, "fee_amount": {"type": "number"}}}'::jsonb,
     'GLOBAL', 0),
    ('PAYOUT_REQUEST', 'Payout Request', 'Driver requests earnings payout',
     '{"type": "object", "properties": {"driver_account_id": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
     'GLOBAL', 1),
    ('PRODUCT_PURCHASE', 'Product Purchase', 'E-commerce transaction',
     '{"type": "object", "properties": {"product_id": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
     'GLOBAL', 0),
    ('FEE', 'Fee', 'Service charge',
     '{"type": "object", "properties": {"fee_type": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
     'GLOBAL', 0),
    ('INTEREST', 'Interest', 'Interest accrual or payment',
     '{"type": "object", "properties": {"account_id": {"type": "string"}, "amount": {"type": "number"}}}'::jsonb,
     'GLOBAL', 0),
    ('REVERSAL', 'Reversal', 'Correction of posted transaction',
     '{"type": "object", "properties": {"original_tx_id": {"type": "string"}, "reason": {"type": "string"}}}'::jsonb,
     'GLOBAL', 1)
ON CONFLICT (type_code) DO NOTHING;

-- =============================================================================
-- IMPLEMENTED: Seed Rejection Reasons
-- DESCRIPTION: Standard rejection codes
-- PRIORITY: HIGH
-- SECURITY: User messages sanitized (no system details)
-- PRIVACY: Error messages don't expose personal data
-- =============================================================================
-- [SEED-003] Insert rejection reasons
INSERT INTO core.rejection_reasons (reason_code, reason_category, reason_name,
    user_message_template, severity, is_retryable)
VALUES
    ('INSUFFICIENT_FUNDS', 'VALIDATION', 'Insufficient Funds',
     'Your account does not have sufficient funds for this transaction.', 'ERROR', false),
    ('INVALID_ACCOUNT', 'VALIDATION', 'Invalid Account',
     'The destination account is invalid or not found.', 'ERROR', false),
    ('INVALID_AMOUNT', 'VALIDATION', 'Invalid Amount',
     'The transaction amount is invalid.', 'ERROR', true),
    ('VALIDATION_FAILED', 'VALIDATION', 'Validation Failed',
     'Transaction validation failed. Please check your input.', 'ERROR', true),
    ('RATE_LIMIT_EXCEEDED', 'SYSTEM', 'Rate Limit Exceeded',
     'Too many transactions. Please try again later.', 'WARNING', true),
    ('DUPLICATE_TRANSACTION', 'VALIDATION', 'Duplicate Transaction',
     'This transaction appears to be a duplicate.', 'ERROR', false),
    ('COMPLIANCE_BLOCKED', 'COMPLIANCE', 'Compliance Blocked',
     'Transaction blocked for compliance review.', 'ERROR', false),
    ('SYSTEM_ERROR', 'SYSTEM', 'System Error',
     'A system error occurred. Please try again.', 'ERROR', true),
    ('INVALID_PIN', 'SECURITY', 'Invalid PIN',
     'The PIN entered is incorrect.', 'ERROR', true),
    ('PIN_ATTEMPTS_EXCEEDED', 'SECURITY', 'PIN Attempts Exceeded',
     'Maximum PIN attempts exceeded. Account temporarily locked.', 'ERROR', false),
    ('SIM_SWAP_DETECTED', 'SECURITY', 'SIM Swap Detected',
     'Please verify your identity due to SIM change detection.', 'WARNING', false),
    ('SESSION_TIMEOUT', 'SESSION', 'Session Timeout',
     'Your session has expired. Please start again.', 'WARNING', true)
ON CONFLICT (reason_code) DO NOTHING;

-- =============================================================================
-- IMPLEMENTED: Seed Chart of Accounts
-- DESCRIPTION: Standard COA structure
-- PRIORITY: HIGH
-- AUDIT: COA changes require accounting approval
-- =============================================================================
-- [SEED-004] Insert COA accounts

-- Assets
INSERT INTO core.chart_of_accounts (coa_code, account_name, account_type, 
    normal_balance, coa_path) VALUES
('1', 'Assets', 'ASSET', 'DEBIT', '1'),
('1.1', 'Cash and Bank', 'ASSET', 'DEBIT', '1.1'),
('1.1.1', 'Cash on Hand', 'ASSET', 'DEBIT', '1.1.1'),
('1.1.2', 'Bank Accounts', 'ASSET', 'DEBIT', '1.1.2'),
('1.2', 'Receivables', 'ASSET', 'DEBIT', '1.2'),
('1.2.1', 'Member Loans', 'ASSET', 'DEBIT', '1.2.1'),
('1.2.2', 'Interest Receivable', 'ASSET', 'DEBIT', '1.2.2')
ON CONFLICT (coa_code) DO NOTHING;

-- Liabilities
INSERT INTO core.chart_of_accounts (coa_code, account_name, account_type,
    normal_balance, coa_path) VALUES
('2', 'Liabilities', 'LIABILITY', 'CREDIT', '2'),
('2.1', 'Deposits', 'LIABILITY', 'CREDIT', '2.1'),
('2.1.1', 'Member Deposits', 'LIABILITY', 'CREDIT', '2.1.1'),
('2.2', 'Payables', 'LIABILITY', 'CREDIT', '2.2')
ON CONFLICT (coa_code) DO NOTHING;

-- Equity
INSERT INTO core.chart_of_accounts (coa_code, account_name, account_type,
    normal_balance, coa_path) VALUES
('3', 'Equity', 'EQUITY', 'CREDIT', '3'),
('3.1', 'Retained Earnings', 'EQUITY', 'CREDIT', '3.1'),
('3.2', 'Reserves', 'EQUITY', 'CREDIT', '3.2')
ON CONFLICT (coa_code) DO NOTHING;

-- Income
INSERT INTO core.chart_of_accounts (coa_code, account_name, account_type,
    normal_balance, coa_path) VALUES
('4', 'Income', 'INCOME', 'CREDIT', '4'),
('4.1', 'Transaction Fees', 'INCOME', 'CREDIT', '4.1'),
('4.2', 'Interest Income', 'INCOME', 'CREDIT', '4.2')
ON CONFLICT (coa_code) DO NOTHING;

-- Expenses
INSERT INTO core.chart_of_accounts (coa_code, account_name, account_type,
    normal_balance, coa_path) VALUES
('5', 'Expenses', 'EXPENSE', 'DEBIT', '5'),
('5.1', 'Operating Expenses', 'EXPENSE', 'DEBIT', '5.1'),
('5.2', 'Bad Debt Provision', 'EXPENSE', 'DEBIT', '5.2')
ON CONFLICT (coa_code) DO NOTHING;

-- =============================================================================
-- IMPLEMENTED: Seed Global Permissions
-- DESCRIPTION: Standard permission catalog
-- PRIORITY: HIGH
-- SECURITY: Principle of least privilege
-- COMPLIANCE: Segregation of duties enforced
-- =============================================================================
-- [SEED-005] Insert global permissions
INSERT INTO app.permissions (permission_code, resource, action, scope,
    permission_name, description)
VALUES
    ('transaction:create', 'transaction', 'create', 'own', 'Create Transaction', 'Submit new transactions'),
    ('transaction:read', 'transaction', 'read', 'own', 'Read Transaction', 'View own transactions'),
    ('transaction:read:all', 'transaction', 'read', 'all', 'Read All Transactions', 'View all transactions'),
    ('transaction:reverse', 'transaction', 'reverse', 'own', 'Reverse Transaction', 'Reverse own transactions'),
    ('account:read', 'account', 'read', 'own', 'Read Account', 'View account details'),
    ('account:update', 'account', 'update', 'own', 'Update Account', 'Update account settings'),
    ('account:create', 'account', 'create', 'own', 'Create Account', 'Create new accounts'),
    ('balance:read', 'balance', 'read', 'own', 'Read Balance', 'Check account balance'),
    ('report:view', 'report', 'read', 'own', 'View Reports', 'Access reports'),
    ('report:view:all', 'report', 'read', 'all', 'View All Reports', 'Access all application reports'),
    ('admin:full', 'admin', 'all', 'all', 'Full Admin', 'Administrative access'),
    ('admin:users', 'admin', 'manage', 'all', 'Manage Users', 'User management'),
    ('admin:config', 'admin', 'configure', 'all', 'Configure System', 'System configuration')
ON CONFLICT (permission_code) DO NOTHING;

-- =============================================================================
-- IMPLEMENTED: Seed Default Configuration
-- DESCRIPTION: System default settings
-- PRIORITY: HIGH
-- SECURITY: Secure by default settings
-- PRIVACY: Data protection defaults enabled
-- =============================================================================
-- [SEED-006] Insert default configuration
INSERT INTO app.configuration (config_key, config_value, value_type,
    description, is_editable, environment)
VALUES
    ('transaction.max_amount', '100000', 'NUMBER', 'Maximum transaction amount', true, 'production'),
    ('transaction.daily_limit', '500000', 'NUMBER', 'Daily transaction limit', true, 'production'),
    ('transaction.monthly_limit', '5000000', 'NUMBER', 'Monthly transaction limit', true, 'production'),
    ('session.timeout_minutes', '5', 'NUMBER', 'USSD session timeout', true, 'production'),
    ('session.max_input_history', '10', 'NUMBER', 'Maximum input history entries', false, 'production'),
    ('pin.max_attempts', '3', 'NUMBER', 'Maximum PIN attempts', true, 'production'),
    ('pin.lockout_minutes', '30', 'NUMBER', 'PIN lockout duration', true, 'production'),
    ('ledger.base_currency', 'USD', 'STRING', 'Base currency for ledger', false, 'production'),
    ('rejection.retention_days', '90', 'NUMBER', 'Days to retain rejection logs', true, 'production'),
    ('audit.retention_years', '7', 'NUMBER', 'Years to retain audit logs', false, 'production'),
    ('encryption.at_rest', 'true', 'BOOLEAN', 'Enable encryption at rest', false, 'production'),
    ('encryption.in_transit', 'true', 'BOOLEAN', 'Require TLS for all connections', false, 'production'),
    ('fraud.device_fingerprinting', 'true', 'BOOLEAN', 'Enable device fingerprinting', true, 'production'),
    ('fraud.sim_swap_detection', 'true', 'BOOLEAN', 'Enable SIM swap detection', true, 'production'),
    ('privacy.data_minimization', 'true', 'BOOLEAN', 'Enable data minimization', false, 'production'),
    ('rate_limit.transactions_per_minute', '10', 'NUMBER', 'Max transactions per minute per account', true, 'production')
ON CONFLICT (config_key, environment) DO UPDATE SET 
    config_value = EXCLUDED.config_value,
    description = EXCLUDED.description;

-- =============================================================================
-- IMPLEMENTED: Seed Provision Rates
-- DESCRIPTION: Default bad debt provision rates
-- PRIORITY: MEDIUM
-- AUDIT: Rate changes logged for accounting review
-- =============================================================================
-- [SEED-007] Insert provision rates
INSERT INTO core.provision_rates (aging_bucket, days_from, days_to, 
    provision_rate, description)
VALUES
    ('CURRENT', 0, 0, 0.005, 'Current - 0.5%'),
    ('DAYS_1_30', 1, 30, 0.02, '1-30 days past due - 2%'),
    ('DAYS_31_60', 31, 60, 0.10, '31-60 days past due - 10%'),
    ('DAYS_61_90', 61, 90, 0.25, '61-90 days past due - 25%'),
    ('DAYS_91_PLUS', 91, NULL, 0.50, 'Over 90 days past due - 50%')
ON CONFLICT (aging_bucket) DO NOTHING;

-- =============================================================================
-- IMPLEMENTED: Seed System Accounts
-- DESCRIPTION: Required system accounts
-- PRIORITY: CRITICAL
-- SECURITY: System accounts have restricted access
-- AUDIT: All system account activity monitored
-- =============================================================================
-- [SEED-008] Insert system accounts

-- System fee account
INSERT INTO core.accounts (account_number, account_type_id, application_id,
    display_name, status, metadata)
SELECT 
    'SYSTEM-FEE-001',
    (SELECT account_type_id FROM core.account_types WHERE type_code = 'SYSTEM'),
    NULL,  -- Global
    'System Fee Collection Account',
    'ACTIVE',
    '{"system": true, "purpose": "fee_collection"}'::jsonb
WHERE NOT EXISTS (
    SELECT 1 FROM core.accounts WHERE account_number = 'SYSTEM-FEE-001'
);

-- System suspense account
INSERT INTO core.accounts (account_number, account_type_id, application_id,
    display_name, status, metadata)
SELECT 
    'SYSTEM-SUSPENSE-001',
    (SELECT account_type_id FROM core.account_types WHERE type_code = 'SYSTEM'),
    NULL,
    'System Suspense Account',
    'ACTIVE',
    '{"system": true, "purpose": "suspense"}'::jsonb
WHERE NOT EXISTS (
    SELECT 1 FROM core.accounts WHERE account_number = 'SYSTEM-SUSPENSE-001'
);

-- System reserve account
INSERT INTO core.accounts (account_number, account_type_id, application_id,
    display_name, status, metadata)
SELECT 
    'SYSTEM-RESERVE-001',
    (SELECT account_type_id FROM core.account_types WHERE type_code = 'SYSTEM'),
    NULL,
    'System Reserve Account',
    'ACTIVE',
    '{"system": true, "purpose": "liquidity_reserve"}'::jsonb
WHERE NOT EXISTS (
    SELECT 1 FROM core.accounts WHERE account_number = 'SYSTEM-RESERVE-001'
);

-- Seed default applications
INSERT INTO app.applications (application_code, application_name, description,
    owner_name, base_currency, timezone, default_language, settings, status)
VALUES
    ('ROOT', 'Root Application', 'System root tenant', 'System Administrator', 'USD', 'UTC', 'en',
     '{"system": true}'::jsonb, 'ACTIVE'),
    ('TRANSPORT', 'Transport ZW', 'Zimbabwe ride-hailing and transport services',
     'Transport Platform Operator', 'USD', 'Africa/Harare', 'en',
     '{"industry": "transport", "country": "ZW", "supports_cash": true, "supports_wallet": true, "supports_mobile_money": true}'::jsonb, 'ACTIVE')
ON CONFLICT (application_code) DO NOTHING;

-- Seed initial USSD shortcodes
INSERT INTO ussd.shortcodes (shortcode, country_code, network_operator,
    shortcode_name, description, is_active)
VALUES
    ('*123#', 'ZW', NULL, 'Mobile Banking', 'Primary mobile banking USSD code', true),
    ('*234#', 'ZW', NULL, 'Savings Group', 'Savings group management USSD code', true),
    ('*456#', 'ZW', NULL, 'Transport', 'Ride hailing USSD code', true),
    ('*999#', 'ZW', NULL, 'Emergency', 'Emergency services USSD code', true)
ON CONFLICT DO NOTHING;

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
   - pin.lockout_minutes: 30 (account recovery)
   - transaction.max_amount: Conservative limit
   - audit.enabled: true (cannot disable)
   - encryption.at_rest: true (mandatory)
   - encryption.in_transit: true (mandatory)
   - rls.enforced: true (tenant isolation)
   - fraud.device_fingerprinting: true
   - fraud.sim_swap_detection: true

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
[x] Seed account types
[x] Seed transaction types
[x] Seed rejection reasons
[x] Seed chart of accounts
[x] Seed global permissions
[x] Seed default configuration
[x] Seed provision rates
[x] Seed system accounts
[x] Seed USSD shortcodes
[ ] Verify foreign key references
[ ] Test data integrity
[ ] Validate secure defaults
[ ] Document seed data version
[ ] Verify no PII in seed data
[ ] Post-seed security baseline scan
================================================================================
*/
