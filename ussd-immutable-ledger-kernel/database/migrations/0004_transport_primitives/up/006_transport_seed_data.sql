-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Asset inventory, Secure defaults)
-- ISO/IEC 27018:2019 - PII Protection (No real PII in seed data)
-- GDPR / Zimbabwe Data Protection Act - Data protection by design
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - No real PII in seed data
-- - Secure defaults for all configuration
-- - Version-controlled seed data
-- - Foreign key validation before insertion
-- ============================================================================
-- =============================================================================
-- MIGRATION: 006_transport_seed_data.sql
-- DESCRIPTION: Transport Business Seed Data
-- TABLES: All lookup and configuration tables
-- DEPENDENCIES: All previous transport primitive migrations
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: Seed Data and Initial Setup
- Feature: Transport-specific defaults for Zimbabwe market
- Source: Transport Business Application on USSD Immutable Ledger

BUSINESS CONTEXT:
Initial data required for transport application operation including:
- Transport-specific transaction types
- Vehicle document categories
- Transport roles and permissions
- Chart of accounts additions for transport
- Default fare parameters for Harare
- Default fee structure
- System accounts for transport operations

SECURITY REQUIREMENTS:
- No real PII in seed data
- Default configurations are secure by design
- All foreign key references validated
================================================================================
*/

-- =============================================================================
-- IMPLEMENTED: Seed Transport Transaction Types
-- DESCRIPTION: Core transaction classifications for transport business
-- PRIORITY: CRITICAL
-- ============================================================================
-- [SEED-TR-001] Insert transport transaction types

INSERT INTO core.transaction_types (type_code, type_name, description,
    payload_schema, scope, required_approvals)
VALUES
    ('RIDE_REQUEST', 'Ride Request', 'Passenger requests a ride',
     '{"type": "object", "required": ["pickup", "destination"], "properties": {"pickup": {"type": "object"}, "destination": {"type": "object"}, "vehicle_type": {"type": "string"}, "estimated_fare": {"type": "number"}}}'::jsonb,
     'GLOBAL', 0),
    ('DRIVER_ASSIGNMENT', 'Driver Assignment', 'System assigns driver to ride request',
     '{"type": "object", "required": ["ride_request_tx_id", "driver_account_id"], "properties": {"ride_request_tx_id": {"type": "string"}, "driver_account_id": {"type": "string"}, "vehicle_id": {"type": "string"}}}'::jsonb,
     'GLOBAL', 0),
    ('TRIP_START', 'Trip Start', 'Driver marks trip as started',
     '{"type": "object", "required": ["ride_request_tx_id"], "properties": {"ride_request_tx_id": {"type": "string"}, "start_odometer": {"type": "number"}, "start_location": {"type": "object"}}}'::jsonb,
     'GLOBAL', 0),
    ('TRIP_COMPLETE', 'Trip Complete', 'Driver marks trip as completed',
     '{"type": "object", "required": ["ride_request_tx_id"], "properties": {"ride_request_tx_id": {"type": "string"}, "end_odometer": {"type": "number"}, "end_location": {"type": "object"}, "actual_distance_km": {"type": "number"}, "actual_duration_minutes": {"type": "number"}, "final_fare": {"type": "number"}}}'::jsonb,
     'GLOBAL', 0),
    ('RATING', 'Rating', 'Mutual rating between rider and driver',
     '{"type": "object", "required": ["trip_tx_id", "rated_by_account_id", "rated_account_id", "stars"], "properties": {"trip_tx_id": {"type": "string"}, "rated_by_account_id": {"type": "string"}, "rated_account_id": {"type": "string"}, "stars": {"type": "integer", "minimum": 1, "maximum": 5}, "comment": {"type": "string"}}}'::jsonb,
     'GLOBAL', 0),
    ('CANCELLATION_FEE', 'Cancellation Fee', 'Fee charged for trip cancellation',
     '{"type": "object", "required": ["ride_request_tx_id", "cancelled_by"], "properties": {"ride_request_tx_id": {"type": "string"}, "cancelled_by": {"type": "string"}, "reason": {"type": "string"}, "fee_amount": {"type": "number"}}}'::jsonb,
     'GLOBAL', 0),
    ('PAYOUT_REQUEST', 'Payout Request', 'Driver requests earnings payout',
     '{"type": "object", "required": ["driver_account_id", "amount"], "properties": {"driver_account_id": {"type": "string"}, "amount": {"type": "number"}, "currency": {"type": "string"}, "settlement_method": {"type": "string"}}}'::jsonb,
     'GLOBAL', 1),
    ('PROMO_APPLIED', 'Promo Applied', 'Discount applied to trip fare',
     '{"type": "object", "required": ["promo_id", "discount_amount"], "properties": {"promo_id": {"type": "string"}, "discount_amount": {"type": "number"}, "original_fare": {"type": "number"}}}'::jsonb,
     'GLOBAL', 0)
ON CONFLICT (type_code) DO NOTHING;

-- =============================================================================
-- IMPLEMENTED: Seed Movement Types for Transport
-- DESCRIPTION: Double-entry movement classifications
-- PRIORITY: CRITICAL
-- ============================================================================
-- [SEED-TR-002] Insert transport movement types

INSERT INTO core.movement_types (type_code, type_name, description,
    transaction_type_id, min_legs, requires_balanced, default_debit_coa, default_credit_coa)
VALUES
    ('RIDE_PAYMENT', 'Ride Payment Movement', 'Fare payment for completed trip',
     (SELECT transaction_type_id FROM core.transaction_types WHERE type_code = 'TRIP_COMPLETE'),
     2, true, '1.1.1', '4.1'),
    ('CANCELLATION_FEE', 'Cancellation Fee Movement', 'Fee for cancelled ride',
     (SELECT transaction_type_id FROM core.transaction_types WHERE type_code = 'CANCELLATION_FEE'),
     2, true, '1.1.1', '4.1'),
    ('DRIVER_PAYOUT', 'Driver Payout Movement', 'Earnings disbursement to driver',
     (SELECT transaction_type_id FROM core.transaction_types WHERE type_code = 'PAYOUT_REQUEST'),
     2, true, '5.1', '1.1.2'),
    ('PLATFORM_FEE', 'Platform Fee Movement', 'Commission deducted from driver earnings',
     (SELECT transaction_type_id FROM core.transaction_types WHERE type_code = 'TRIP_COMPLETE'),
     2, true, '5.1', '4.1')
ON CONFLICT (type_code) DO NOTHING;

-- =============================================================================
-- IMPLEMENTED: Seed Document Categories for Transport
-- DESCRIPTION: Vehicle and driver document classifications
-- PRIORITY: HIGH
-- ============================================================================
-- [SEED-TR-003] Insert transport document categories

INSERT INTO core.document_categories (category_code, category_name, description,
    requires_encryption, pii_classification, retention_years, allowed_formats)
VALUES
    ('DRIVER_LICENSE', 'Driver License', 'Professional driving permit or ordinary license',
     true, 'RESTRICTED', 7, ARRAY['PDF', 'JPG', 'PNG']),
    ('VEHICLE_REGISTRATION', 'Vehicle Registration', 'Vehicle registration certificate',
     true, 'RESTRICTED', 10, ARRAY['PDF', 'JPG']),
    ('CRW', 'Certificate of Road Worthiness', 'VID road worthiness certificate',
     true, 'RESTRICTED', 3, ARRAY['PDF', 'JPG']),
    ('INSURANCE', 'Vehicle Insurance', 'Commercial passenger vehicle insurance',
     true, 'RESTRICTED', 3, ARRAY['PDF']),
    ('OPERATING_LICENSE', 'Operating License', 'ZTA public service vehicle license',
     true, 'RESTRICTED', 5, ARRAY['PDF']),
    ('PROFILE_PHOTO', 'Profile Photo', 'Driver profile picture',
     true, 'CONFIDENTIAL', 3, ARRAY['JPG', 'PNG'])
ON CONFLICT (category_code) DO NOTHING;

-- =============================================================================
-- IMPLEMENTED: Seed Transport Chart of Accounts
-- DESCRIPTION: Additional COA accounts for transport business
-- PRIORITY: HIGH
-- ============================================================================
-- [SEED-TR-004] Insert transport COA accounts

-- Transport-specific Income accounts
INSERT INTO core.chart_of_accounts (coa_code, account_name, account_type,
    normal_balance, coa_path, level) VALUES
('4.1.1', 'Ride Fare Income', 'INCOME', 'CREDIT', '4.1.1', 2),
('4.1.2', 'Cancellation Fee Income', 'INCOME', 'CREDIT', '4.1.2', 2),
('4.3', 'Platform Commission Income', 'INCOME', 'CREDIT', '4.3', 1),
('4.3.1', 'Driver Commission', 'INCOME', 'CREDIT', '4.3.1', 2)
ON CONFLICT (coa_code) DO NOTHING;

-- Transport-specific Expense accounts
INSERT INTO core.chart_of_accounts (coa_code, account_name, account_type,
    normal_balance, coa_path, level) VALUES
('5.1.1', 'Driver Payouts', 'EXPENSE', 'DEBIT', '5.1.1', 2),
('5.1.2', 'Settlement Fees', 'EXPENSE', 'DEBIT', '5.1.2', 2),
('5.1.3', 'Mobile Money Charges', 'EXPENSE', 'DEBIT', '5.1.3', 2),
('5.3', 'Promotional Discounts', 'EXPENSE', 'DEBIT', '5.3', 1),
('5.3.1', 'Promo Code Redemptions', 'EXPENSE', 'DEBIT', '5.3.1', 2)
ON CONFLICT (coa_code) DO NOTHING;

-- Transport-specific Liability accounts
INSERT INTO core.chart_of_accounts (coa_code, account_name, account_type,
    normal_balance, coa_path, level) VALUES
('2.3', 'Driver Payables', 'LIABILITY', 'CREDIT', '2.3', 1),
('2.3.1', 'Driver Earnings Payable', 'LIABILITY', 'CREDIT', '2.3.1', 2),
('2.3.2', 'Pending Settlements', 'LIABILITY', 'CREDIT', '2.3.2', 2),
('2.4', 'Customer Deposits', 'LIABILITY', 'CREDIT', '2.4', 1),
('2.4.1', 'Rider Wallet Balances', 'LIABILITY', 'CREDIT', '2.4.1', 2)
ON CONFLICT (coa_code) DO NOTHING;

-- =============================================================================
-- IMPLEMENTED: Seed Transport Permissions
-- DESCRIPTION: RBAC permissions for transport application
-- PRIORITY: HIGH
-- ============================================================================
-- [SEED-TR-005] Insert transport permissions

INSERT INTO app.permissions (permission_code, resource, action, scope,
    permission_name, description)
VALUES
    ('ride:request', 'ride', 'create', 'own', 'Request Ride', 'Book a ride'),
    ('ride:cancel', 'ride', 'cancel', 'own', 'Cancel Ride', 'Cancel own ride request'),
    ('ride:read', 'ride', 'read', 'own', 'View Rides', 'View own trip history'),
    ('ride:read:all', 'ride', 'read', 'all', 'View All Rides', 'View all trips as admin'),
    ('ride:assign', 'ride', 'assign', 'all', 'Assign Driver', 'Assign driver to ride'),
    ('ride:rate', 'ride', 'rate', 'own', 'Rate Trip', 'Rate completed trip'),
    ('driver:accept', 'driver', 'accept', 'own', 'Accept Ride', 'Accept ride request'),
    ('driver:reject', 'driver', 'reject', 'own', 'Reject Ride', 'Reject ride request'),
    ('driver:status', 'driver', 'update', 'own', 'Update Status', 'Toggle online/offline status'),
    ('driver:earnings:read', 'driver_earnings', 'read', 'own', 'View Earnings', 'View driver earnings'),
    ('driver:documents:manage', 'driver_documents', 'manage', 'own', 'Manage Documents', 'Upload and manage vehicle documents'),
    ('vehicle:read', 'vehicle', 'read', 'own', 'View Vehicles', 'View assigned vehicles'),
    ('vehicle:manage', 'vehicle', 'manage', 'all', 'Manage Vehicles', 'Manage all vehicles'),
    ('fleet:monitor', 'fleet', 'read', 'all', 'Monitor Fleet', 'Monitor fleet operations'),
    ('fleet:drivers:manage', 'fleet_drivers', 'manage', 'all', 'Manage Fleet Drivers', 'Onboard and manage drivers'),
    ('dispute:create', 'dispute', 'create', 'own', 'Create Dispute', 'Raise a trip dispute'),
    ('dispute:resolve', 'dispute', 'resolve', 'all', 'Resolve Dispute', 'Resolve trip disputes'),
    ('promo:manage', 'promo', 'manage', 'all', 'Manage Promotions', 'Create and manage promo codes'),
    ('fare:configure', 'fare', 'configure', 'all', 'Configure Fares', 'Update fare parameters'),
    ('report:transport', 'report', 'read', 'all', 'Transport Reports', 'Access transport analytics'),
    ('admin:transport', 'admin', 'all', 'all', 'Transport Admin', 'Full transport admin access')
ON CONFLICT (permission_code) DO NOTHING;

-- =============================================================================
-- IMPLEMENTED: Seed Transport Roles
-- DESCRIPTION: Predefined roles for transport application
-- PRIORITY: HIGH
-- ============================================================================
-- [SEED-TR-006] Insert transport roles

-- Note: These are global roles. Application-specific assignments happen via user_role_assignments.
INSERT INTO app.roles (role_code, role_name, description, is_system_role, is_default_role, status)
VALUES
    ('RIDER', 'Rider', 'Passenger requesting rides', true, true, 'ACTIVE'),
    ('DRIVER', 'Driver', 'Transport service provider', true, false, 'ACTIVE'),
    ('FLEET_MANAGER', 'Fleet Manager', 'Oversees multiple drivers and vehicles', true, false, 'ACTIVE'),
    ('TRANSPORT_ADMIN', 'Transport Admin', 'Platform operator for transport app', true, false, 'ACTIVE')
ON CONFLICT (role_code) WHERE valid_to IS NULL DO NOTHING;

-- =============================================================================
-- IMPLEMENTED: Seed Transport Role Permissions
-- DESCRIPTION: Permission grants for transport roles
-- PRIORITY: HIGH
-- ============================================================================
-- [SEED-TR-007] Insert transport role permissions

-- RIDER permissions
INSERT INTO app.role_permissions (role_id, permission_id, grant_type)
SELECT 
    (SELECT role_id FROM app.roles WHERE role_code = 'RIDER' AND valid_to IS NULL),
    permission_id,
    'ALLOW'
FROM app.permissions
WHERE permission_code IN ('ride:request', 'ride:cancel', 'ride:read', 'ride:rate', 'dispute:create', 'account:read', 'balance:read')
ON CONFLICT (role_id, permission_id) WHERE valid_to IS NULL DO NOTHING;

-- DRIVER permissions
INSERT INTO app.role_permissions (role_id, permission_id, grant_type)
SELECT 
    (SELECT role_id FROM app.roles WHERE role_code = 'DRIVER' AND valid_to IS NULL),
    permission_id,
    'ALLOW'
FROM app.permissions
WHERE permission_code IN (
    'driver:accept', 'driver:reject', 'driver:status', 'driver:earnings:read',
    'driver:documents:manage', 'vehicle:read', 'ride:read', 'ride:rate',
    'account:read', 'balance:read', 'dispute:create'
)
ON CONFLICT (role_id, permission_id) WHERE valid_to IS NULL DO NOTHING;

-- FLEET_MANAGER permissions
INSERT INTO app.role_permissions (role_id, permission_id, grant_type)
SELECT 
    (SELECT role_id FROM app.roles WHERE role_code = 'FLEET_MANAGER' AND valid_to IS NULL),
    permission_id,
    'ALLOW'
FROM app.permissions
WHERE permission_code IN (
    'fleet:monitor', 'fleet:drivers:manage', 'vehicle:manage', 'ride:read:all',
    'dispute:resolve', 'report:transport', 'account:read', 'balance:read'
)
ON CONFLICT (role_id, permission_id) WHERE valid_to IS NULL DO NOTHING;

-- TRANSPORT_ADMIN permissions
INSERT INTO app.role_permissions (role_id, permission_id, grant_type)
SELECT 
    (SELECT role_id FROM app.roles WHERE role_code = 'TRANSPORT_ADMIN' AND valid_to IS NULL),
    permission_id,
    'ALLOW'
FROM app.permissions
WHERE permission_code IN (
    'ride:read:all', 'ride:assign', 'vehicle:manage', 'fleet:monitor',
    'fleet:drivers:manage', 'dispute:resolve', 'promo:manage', 'fare:configure',
    'report:transport', 'admin:transport', 'admin:users', 'admin:config',
    'account:create', 'account:update', 'transaction:read:all'
)
ON CONFLICT (role_id, permission_id) WHERE valid_to IS NULL DO NOTHING;

-- =============================================================================
-- IMPLEMENTED: Seed Transport System Accounts
-- DESCRIPTION: Required system accounts for transport operations
-- PRIORITY: CRITICAL
-- ============================================================================
-- [SEED-TR-008] Insert transport system accounts

-- Transport fee collection account
INSERT INTO core.accounts (account_number, account_type_id, application_id,
    display_name, status, metadata)
SELECT 
    'SYSTEM-TRANSPORT-FEE-001',
    (SELECT account_type_id FROM core.account_types WHERE type_code = 'SYSTEM'),
    (SELECT application_id FROM app.applications WHERE application_code = 'TRANSPORT'),
    'Transport Platform Fee Account',
    'ACTIVE',
    '{"system": true, "purpose": "transport_platform_fees"}'::jsonb
WHERE NOT EXISTS (
    SELECT 1 FROM core.accounts WHERE account_number = 'SYSTEM-TRANSPORT-FEE-001'
)
AND EXISTS (SELECT 1 FROM app.applications WHERE application_code = 'TRANSPORT');

-- Transport promo/discount account
INSERT INTO core.accounts (account_number, account_type_id, application_id,
    display_name, status, metadata)
SELECT 
    'SYSTEM-TRANSPORT-PROMO-001',
    (SELECT account_type_id FROM core.account_types WHERE type_code = 'SYSTEM'),
    (SELECT application_id FROM app.applications WHERE application_code = 'TRANSPORT'),
    'Transport Promo Discount Account',
    'ACTIVE',
    '{"system": true, "purpose": "transport_promo_discounts"}'::jsonb
WHERE NOT EXISTS (
    SELECT 1 FROM core.accounts WHERE account_number = 'SYSTEM-TRANSPORT-PROMO-001'
)
AND EXISTS (SELECT 1 FROM app.applications WHERE application_code = 'TRANSPORT');

-- Transport settlement suspense account
INSERT INTO core.accounts (account_number, account_type_id, application_id,
    display_name, status, metadata)
SELECT 
    'SYSTEM-TRANSPORT-SETTLEMENT-001',
    (SELECT account_type_id FROM core.account_types WHERE type_code = 'SYSTEM'),
    (SELECT application_id FROM app.applications WHERE application_code = 'TRANSPORT'),
    'Transport Settlement Suspense Account',
    'ACTIVE',
    '{"system": true, "purpose": "transport_settlement_suspense"}'::jsonb
WHERE NOT EXISTS (
    SELECT 1 FROM core.accounts WHERE account_number = 'SYSTEM-TRANSPORT-SETTLEMENT-001'
)
AND EXISTS (SELECT 1 FROM app.applications WHERE application_code = 'TRANSPORT');

-- =============================================================================
-- IMPLEMENTED: Seed Default Fare Parameters
-- DESCRIPTION: Harare default fare configuration
-- PRIORITY: MEDIUM
-- ============================================================================
-- [SEED-TR-009] Insert default fare parameters

INSERT INTO core.fare_parameters (
    parameter_code, parameter_name, application_id,
    vehicle_type, base_fare, distance_rate_per_km, time_rate_per_minute,
    minimum_fare, cancellation_fee, surge_cap, free_waiting_minutes,
    waiting_rate_per_minute, currency, status, change_reason
)
SELECT 
    'ZW_HRE_STANDARD',
    'Harare Standard Vehicle Fare',
    app.application_id,
    'STANDARD',
    2.00,    -- base fare in USD
    0.80,    -- per km
    0.15,    -- per minute
    3.00,    -- minimum fare
    1.50,    -- cancellation fee
    2.50,    -- surge cap
    3,       -- free waiting minutes
    0.20,    -- waiting rate per minute
    'USD',
    'ACTIVE',
    'Initial seed data for Zimbabwe transport operations'
FROM app.applications app
WHERE app.application_code = 'TRANSPORT'
  AND NOT EXISTS (
      SELECT 1 FROM core.fare_parameters fp 
      WHERE fp.parameter_code = 'ZW_HRE_STANDARD'
  );

INSERT INTO core.fare_parameters (
    parameter_code, parameter_name, application_id,
    vehicle_type, base_fare, distance_rate_per_km, time_rate_per_minute,
    minimum_fare, cancellation_fee, surge_cap, free_waiting_minutes,
    waiting_rate_per_minute, currency, status, change_reason
)
SELECT 
    'ZW_HRE_PREMIUM',
    'Harare Premium Vehicle Fare',
    app.application_id,
    'PREMIUM',
    4.00,
    1.50,
    0.30,
    6.00,
    2.50,
    2.50,
    5,
    0.35,
    'USD',
    'ACTIVE',
    'Initial seed data for Zimbabwe transport operations'
FROM app.applications app
WHERE app.application_code = 'TRANSPORT'
  AND NOT EXISTS (
      SELECT 1 FROM core.fare_parameters fp 
      WHERE fp.parameter_code = 'ZW_HRE_PREMIUM'
  );

-- =============================================================================
-- IMPLEMENTED: Seed Default Fee Structure
-- DESCRIPTION: Platform commission and tax defaults
-- PRIORITY: MEDIUM
-- ============================================================================
-- [SEED-TR-010] Insert default fee structure

INSERT INTO core.fee_structures (
    structure_code, structure_name, application_id,
    platform_fee_type, platform_fee_value, platform_fee_cap,
    tax_rate, tax_coa_code, currency, status, change_reason
)
SELECT 
    'ZW_TRANSPORT_STD',
    'Zimbabwe Transport Standard Fee Structure',
    app.application_id,
    'PERCENTAGE',
    0.15,    -- 15% platform fee
    10.00,   -- USD 10 cap
    0.00,    -- Tax rate (update when applicable)
    '4.3.1',
    'USD',
    'ACTIVE',
    'Initial seed data for Zimbabwe transport operations'
FROM app.applications app
WHERE app.application_code = 'TRANSPORT'
  AND NOT EXISTS (
      SELECT 1 FROM core.fee_structures fs 
      WHERE fs.structure_code = 'ZW_TRANSPORT_STD'
  );

-- =============================================================================
-- IMPLEMENTED: Seed Default Regulatory Parameters
-- DESCRIPTION: ZTA and government compliance thresholds
-- PRIORITY: MEDIUM
-- ============================================================================
-- [SEED-TR-011] Insert default regulatory parameters

INSERT INTO core.regulatory_parameters (
    param_code, param_name, application_id,
    param_category, issuing_authority, param_value_numeric,
    param_unit, is_enforced, enforcement_action, status, change_reason
)
SELECT 
    'ZTA_SURGE_CAP',
    'ZTA Maximum Surge Multiplier',
    app.application_id,
    'SURGE_CAP',
    'ZTA',
    3.00,
    'MULTIPLIER',
    true,
    'BLOCK',
    'ACTIVE',
    'Zimbabwe Transport Authority maximum allowed surge multiplier'
FROM app.applications app
WHERE app.application_code = 'TRANSPORT'
  AND NOT EXISTS (
      SELECT 1 FROM core.regulatory_parameters rp 
      WHERE rp.param_code = 'ZTA_SURGE_CAP'
  );

INSERT INTO core.regulatory_parameters (
    param_code, param_name, application_id,
    param_category, issuing_authority, param_value_numeric,
    param_unit, is_enforced, enforcement_action, status, change_reason
)
SELECT 
    'VID_INSPECTION_INTERVAL_DAYS',
    'VID Inspection Interval',
    app.application_id,
    'INSPECTION_INTERVAL',
    'VID',
    180,
    'DAYS',
    true,
    'BLOCK',
    'ACTIVE',
    'Vehicle Inspection Department required inspection interval'
FROM app.applications app
WHERE app.application_code = 'TRANSPORT'
  AND NOT EXISTS (
      SELECT 1 FROM core.regulatory_parameters rp 
      WHERE rp.param_code = 'VID_INSPECTION_INTERVAL_DAYS'
  );

INSERT INTO core.regulatory_parameters (
    param_code, param_name, application_id,
    param_category, issuing_authority, param_value_numeric,
    param_unit, is_enforced, enforcement_action, status, change_reason
)
SELECT 
    'DRIVER_DAILY_PAYOUT_LIMIT',
    'Driver Daily Payout Limit',
    app.application_id,
    'DAILY_LIMIT',
    'PLATFORM',
    500.00,
    'USD',
    true,
    'BLOCK',
    'ACTIVE',
    'Maximum daily payout limit for driver earnings'
FROM app.applications app
WHERE app.application_code = 'TRANSPORT'
  AND NOT EXISTS (
      SELECT 1 FROM core.regulatory_parameters rp 
      WHERE rp.param_code = 'DRIVER_DAILY_PAYOUT_LIMIT'
  );

-- =============================================================================
-- IMPLEMENTED: Seed Default Zones
-- DESCRIPTION: Harare transport zones
-- PRIORITY: MEDIUM
-- ============================================================================
-- [SEED-TR-012] Insert default zones

INSERT INTO core.zones (
    zone_code, zone_name, zone_level, zone_type,
    application_id, status, municipal_authority, zta_permit_required
)
SELECT 
    'ZW_HRE',
    'Harare',
    1,
    'CITY',
    app.application_id,
    'ACTIVE',
    'Harare City Council',
    true
FROM app.applications app
WHERE app.application_code = 'TRANSPORT'
  AND NOT EXISTS (
      SELECT 1 FROM core.zones z 
      WHERE z.zone_code = 'ZW_HRE' AND z.zone_level = 1
  );

INSERT INTO core.zones (
    zone_code, zone_name, zone_level, zone_type,
    parent_zone_id, application_id, status, municipal_authority
)
SELECT 
    'ZW_HRE_CBD',
    'Harare CBD',
    2,
    'DISTRICT',
    z.zone_id,
    app.application_id,
    'ACTIVE',
    'Harare City Council'
FROM app.applications app, core.zones z
WHERE app.application_code = 'TRANSPORT'
  AND z.zone_code = 'ZW_HRE'
  AND z.zone_level = 1
  AND NOT EXISTS (
      SELECT 1 FROM core.zones z2 
      WHERE z2.zone_code = 'ZW_HRE_CBD' AND z2.zone_level = 2
  );

-- =============================================================================
-- IMPLEMENTED: Seed Default Promo Code
-- DESCRIPTION: Welcome promo for new riders
-- PRIORITY: LOW
-- ============================================================================
-- [SEED-TR-013] Insert welcome promo code

INSERT INTO app.promo_codes (
    promo_code, campaign_name, description,
    application_id, discount_type, discount_value,
    max_discount_amount, minimum_trip_fare,
    new_users_only, total_usage_limit, per_user_limit,
    valid_from, valid_to, status
)
SELECT 
    'WELCOMEZW',
    'Welcome to Transport ZW',
    '25% off first ride for new users',
    app.application_id,
    'PERCENTAGE',
    0.25,
    5.00,
    3.00,
    true,
    10000,
    1,
    now(),
    now() + interval '1 year',
    'ACTIVE'
FROM app.applications app
WHERE app.application_code = 'TRANSPORT'
  AND NOT EXISTS (
      SELECT 1 FROM app.promo_codes p 
      WHERE p.promo_code = 'WELCOMEZW'
  );

/*
================================================================================
MIGRATION CHECKLIST:
☑ Seed transport transaction types
☑ Seed transport movement types
☑ Seed transport document categories
☑ Seed transport chart of accounts
☑ Seed transport permissions
☑ Seed transport roles
☑ Seed transport role permissions
☑ Seed transport system accounts
☑ Seed default fare parameters for Harare
☑ Seed default fee structure
☑ Seed default regulatory parameters
☑ Seed default geographic zones
☑ Seed welcome promo code
☑ Verify all foreign key references
☑ Confirm no PII in seed data
================================================================================
*/
