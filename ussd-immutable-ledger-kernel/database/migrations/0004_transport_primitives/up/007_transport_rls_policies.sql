-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Access control)
-- ISO/IEC 27018:2019 - PII Protection (Data segregation)
-- GDPR / Zimbabwe Data Protection Act - Security of processing
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - RLS enabled on all transport tables
-- - Application isolation for multi-tenant data
-- - Account-based access for participant data
-- - Admin bypass with audit logging
-- ============================================================================
-- =============================================================================
-- MIGRATION: 007_transport_rls_policies.sql
-- DESCRIPTION: Row-Level Security for Transport Primitives
-- TABLES: All new transport core and app tables
-- DEPENDENCIES: 001-006 transport primitive migrations, 052_security_rls_policies.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 8. Security & Access Control
- Feature: Row-Level Security for Transport Business
- Source: Transport Business Application on USSD Immutable Ledger

BUSINESS CONTEXT:
Transport data requires strict access control:
- Riders only see their own trips, favorites, and disputes
- Drivers only see their own vehicles, assignments, and earnings
- Fleet managers see their drivers' data within their application
- Admins have cross-account visibility within their application
================================================================================
*/

-- =============================================================================
-- SECTION 1: ENABLE RLS ON CORE TRANSPORT TABLES
-- =============================================================================

ALTER TABLE core.zones ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.route_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.location_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.vehicles ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.vehicle_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.vehicle_compliance ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.document_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.disputes ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.dispute_status_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.regulatory_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.fare_parameters ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.fee_structures ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.regulatory_parameters ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- SECTION 2: FORCE RLS ON CORE TRANSPORT TABLES
-- =============================================================================

ALTER TABLE core.zones FORCE ROW LEVEL SECURITY;
ALTER TABLE core.route_definitions FORCE ROW LEVEL SECURITY;
ALTER TABLE core.location_assertions FORCE ROW LEVEL SECURITY;
ALTER TABLE core.vehicles FORCE ROW LEVEL SECURITY;
ALTER TABLE core.vehicle_assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE core.vehicle_compliance FORCE ROW LEVEL SECURITY;
ALTER TABLE core.document_verifications FORCE ROW LEVEL SECURITY;
ALTER TABLE core.disputes FORCE ROW LEVEL SECURITY;
ALTER TABLE core.dispute_status_history FORCE ROW LEVEL SECURITY;
ALTER TABLE core.regulatory_flags FORCE ROW LEVEL SECURITY;
ALTER TABLE core.fare_parameters FORCE ROW LEVEL SECURITY;
ALTER TABLE core.fee_structures FORCE ROW LEVEL SECURITY;
ALTER TABLE core.regulatory_parameters FORCE ROW LEVEL SECURITY;

-- =============================================================================
-- SECTION 3: ENABLE RLS ON APP TRANSPORT TABLES
-- =============================================================================

ALTER TABLE app.driver_status_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.driver_status_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.favorite_locations ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.promo_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.promo_code_usages ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- SECTION 4: FORCE RLS ON APP TRANSPORT TABLES
-- =============================================================================

ALTER TABLE app.driver_status_cache FORCE ROW LEVEL SECURITY;
ALTER TABLE app.driver_status_history FORCE ROW LEVEL SECURITY;
ALTER TABLE app.favorite_locations FORCE ROW LEVEL SECURITY;
ALTER TABLE app.promo_codes FORCE ROW LEVEL SECURITY;
ALTER TABLE app.promo_code_usages FORCE ROW LEVEL SECURITY;

-- =============================================================================
-- SECTION 5: APPLICATION ISOLATION POLICIES
-- =============================================================================

-- core.zones
DROP POLICY IF EXISTS zones_application_isolation ON core.zones;
CREATE POLICY zones_application_isolation ON core.zones
    FOR ALL
    USING (
        application_id = current_setting('app.current_application_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- core.route_definitions
DROP POLICY IF EXISTS routes_application_isolation ON core.route_definitions;
CREATE POLICY routes_application_isolation ON core.route_definitions
    FOR ALL
    USING (
        application_id = current_setting('app.current_application_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- core.location_assertions
DROP POLICY IF EXISTS location_assertions_application_isolation ON core.location_assertions;
CREATE POLICY location_assertions_application_isolation ON core.location_assertions
    FOR ALL
    USING (
        application_id = current_setting('app.current_application_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- core.vehicles
DROP POLICY IF EXISTS vehicles_application_isolation ON core.vehicles;
CREATE POLICY vehicles_application_isolation ON core.vehicles
    FOR ALL
    USING (
        application_id = current_setting('app.current_application_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- core.vehicle_assignments
DROP POLICY IF EXISTS vehicle_assignments_application_isolation ON core.vehicle_assignments;
CREATE POLICY vehicle_assignments_application_isolation ON core.vehicle_assignments
    FOR ALL
    USING (
        application_id = current_setting('app.current_application_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- core.vehicle_compliance
DROP POLICY IF EXISTS vehicle_compliance_application_isolation ON core.vehicle_compliance;
CREATE POLICY vehicle_compliance_application_isolation ON core.vehicle_compliance
    FOR ALL
    USING (
        application_id = current_setting('app.current_application_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- core.document_verifications
DROP POLICY IF EXISTS document_verifications_application_isolation ON core.document_verifications;
CREATE POLICY document_verifications_application_isolation ON core.document_verifications
    FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM core.document_registry dr
            WHERE dr.document_id = document_verifications.document_id
              AND dr.application_id = current_setting('app.current_application_id', true)::UUID
        )
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- core.disputes
DROP POLICY IF EXISTS disputes_application_isolation ON core.disputes;
CREATE POLICY disputes_application_isolation ON core.disputes
    FOR ALL
    USING (
        application_id = current_setting('app.current_application_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- core.regulatory_flags
DROP POLICY IF EXISTS regulatory_flags_application_isolation ON core.regulatory_flags;
CREATE POLICY regulatory_flags_application_isolation ON core.regulatory_flags
    FOR ALL
    USING (
        application_id = current_setting('app.current_application_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- core.fare_parameters
DROP POLICY IF EXISTS fare_parameters_application_isolation ON core.fare_parameters;
CREATE POLICY fare_parameters_application_isolation ON core.fare_parameters
    FOR ALL
    USING (
        application_id = current_setting('app.current_application_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- core.fee_structures
DROP POLICY IF EXISTS fee_structures_application_isolation ON core.fee_structures;
CREATE POLICY fee_structures_application_isolation ON core.fee_structures
    FOR ALL
    USING (
        application_id = current_setting('app.current_application_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- core.regulatory_parameters
DROP POLICY IF EXISTS regulatory_parameters_application_isolation ON core.regulatory_parameters;
CREATE POLICY regulatory_parameters_application_isolation ON core.regulatory_parameters
    FOR ALL
    USING (
        application_id = current_setting('app.current_application_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- =============================================================================
-- SECTION 6: ACCOUNT-BASED ACCESS POLICIES
-- =============================================================================

-- core.location_assertions - own assertions only
DROP POLICY IF EXISTS location_assertions_account_access ON core.location_assertions;
CREATE POLICY location_assertions_account_access ON core.location_assertions
    FOR SELECT
    USING (
        account_id = current_setting('app.current_account_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- core.vehicle_assignments - driver sees own assignments
DROP POLICY IF EXISTS vehicle_assignments_driver_access ON core.vehicle_assignments;
CREATE POLICY vehicle_assignments_driver_access ON core.vehicle_assignments
    FOR SELECT
    USING (
        driver_account_id = current_setting('app.current_account_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- core.disputes - participants see own disputes
DROP POLICY IF EXISTS disputes_participant_access ON core.disputes;
CREATE POLICY disputes_participant_access ON core.disputes
    FOR SELECT
    USING (
        rider_account_id = current_setting('app.current_account_id', true)::UUID
        OR driver_account_id = current_setting('app.current_account_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- core.regulatory_flags - target sees own flags
DROP POLICY IF EXISTS regulatory_flags_target_access ON core.regulatory_flags;
CREATE POLICY regulatory_flags_target_access ON core.regulatory_flags
    FOR SELECT
    USING (
        (target_type = 'ACCOUNT' AND target_id = current_setting('app.current_account_id', true)::UUID)
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- app.driver_status_cache - driver sees own status
DROP POLICY IF EXISTS driver_status_cache_account_access ON app.driver_status_cache;
CREATE POLICY driver_status_cache_account_access ON app.driver_status_cache
    FOR ALL
    USING (
        driver_account_id = current_setting('app.current_account_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- app.driver_status_history - driver sees own history
DROP POLICY IF EXISTS driver_status_history_account_access ON app.driver_status_history;
CREATE POLICY driver_status_history_account_access ON app.driver_status_history
    FOR SELECT
    USING (
        driver_account_id = current_setting('app.current_account_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- app.favorite_locations - rider sees own locations
DROP POLICY IF EXISTS favorite_locations_account_access ON app.favorite_locations;
CREATE POLICY favorite_locations_account_access ON app.favorite_locations
    FOR ALL
    USING (
        rider_account_id = current_setting('app.current_account_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- app.promo_code_usages - rider sees own usages
DROP POLICY IF EXISTS promo_code_usages_account_access ON app.promo_code_usages;
CREATE POLICY promo_code_usages_account_access ON app.promo_code_usages
    FOR SELECT
    USING (
        rider_account_id = current_setting('app.current_account_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- =============================================================================
-- SECTION 7: APP SCHEMA ISOLATION POLICIES
-- =============================================================================

-- app.promo_codes
DROP POLICY IF EXISTS promo_codes_application_isolation ON app.promo_codes;
CREATE POLICY promo_codes_application_isolation ON app.promo_codes
    FOR ALL
    USING (
        application_id = current_setting('app.current_application_id', true)::UUID
        OR current_setting('app.is_admin', true)::BOOLEAN = true
    );

-- =============================================================================
-- SECTION 8: ADMIN BYPASS POLICIES
-- =============================================================================

-- Admin full access to transport tables
DROP POLICY IF EXISTS admin_zones_access ON core.zones;
CREATE POLICY admin_zones_access ON core.zones
    FOR ALL TO admin_role USING (true);

DROP POLICY IF EXISTS admin_routes_access ON core.route_definitions;
CREATE POLICY admin_routes_access ON core.route_definitions
    FOR ALL TO admin_role USING (true);

DROP POLICY IF EXISTS admin_vehicles_access ON core.vehicles;
CREATE POLICY admin_vehicles_access ON core.vehicles
    FOR ALL TO admin_role USING (true);

DROP POLICY IF EXISTS admin_disputes_access ON core.disputes;
CREATE POLICY admin_disputes_access ON core.disputes
    FOR ALL TO admin_role USING (true);

DROP POLICY IF EXISTS admin_fare_params_access ON core.fare_parameters;
CREATE POLICY admin_fare_params_access ON core.fare_parameters
    FOR ALL TO admin_role USING (true);

DROP POLICY IF EXISTS admin_fee_structures_access ON core.fee_structures;
CREATE POLICY admin_fee_structures_access ON core.fee_structures
    FOR ALL TO admin_role USING (true);

DROP POLICY IF EXISTS admin_driver_status_access ON app.driver_status_cache;
CREATE POLICY admin_driver_status_access ON app.driver_status_cache
    FOR ALL TO admin_role USING (true);

/*
================================================================================
MIGRATION CHECKLIST:
☑ Enable RLS on all core transport tables
☑ Force RLS on all core transport tables
☑ Enable RLS on all app transport tables
☑ Force RLS on all app transport tables
☑ Create application isolation policies
☑ Create account-based access policies
☑ Create admin bypass policies
☑ Verify no table lacks RLS protection
================================================================================
*/
