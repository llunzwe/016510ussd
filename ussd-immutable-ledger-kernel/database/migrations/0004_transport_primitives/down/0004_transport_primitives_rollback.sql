-- ============================================================================
-- ROLLBACK: 0004_transport_primitives
-- DESCRIPTION: Remove all transport-specific primitives
-- WARNING: This will delete all transport business data
-- ============================================================================

-- Drop views
DROP VIEW IF EXISTS core.current_routes CASCADE;
DROP VIEW IF EXISTS core.current_zones CASCADE;
DROP VIEW IF EXISTS core.current_vehicle_assignments CASCADE;
DROP VIEW IF EXISTS core.vehicle_compliance_summary CASCADE;
DROP VIEW IF EXISTS core.active_regulatory_flags CASCADE;
DROP VIEW IF EXISTS core.open_disputes CASCADE;
DROP VIEW IF EXISTS core.current_fare_parameters CASCADE;
DROP VIEW IF EXISTS core.current_fee_structures CASCADE;
DROP VIEW IF EXISTS core.current_regulatory_parameters CASCADE;
DROP VIEW IF EXISTS app.available_drivers CASCADE;

-- Drop policies
DROP POLICY IF EXISTS zones_application_isolation ON core.zones;
DROP POLICY IF EXISTS routes_application_isolation ON core.route_definitions;
DROP POLICY IF EXISTS location_assertions_application_isolation ON core.location_assertions;
DROP POLICY IF EXISTS vehicles_application_isolation ON core.vehicles;
DROP POLICY IF EXISTS vehicle_assignments_application_isolation ON core.vehicle_assignments;
DROP POLICY IF EXISTS vehicle_compliance_application_isolation ON core.vehicle_compliance;
DROP POLICY IF EXISTS document_verifications_application_isolation ON core.document_verifications;
DROP POLICY IF EXISTS disputes_application_isolation ON core.disputes;
DROP POLICY IF EXISTS regulatory_flags_application_isolation ON core.regulatory_flags;
DROP POLICY IF EXISTS fare_parameters_application_isolation ON core.fare_parameters;
DROP POLICY IF EXISTS fee_structures_application_isolation ON core.fee_structures;
DROP POLICY IF EXISTS regulatory_parameters_application_isolation ON core.regulatory_parameters;
DROP POLICY IF EXISTS location_assertions_account_access ON core.location_assertions;
DROP POLICY IF EXISTS vehicle_assignments_driver_access ON core.vehicle_assignments;
DROP POLICY IF EXISTS disputes_participant_access ON core.disputes;
DROP POLICY IF EXISTS regulatory_flags_target_access ON core.regulatory_flags;
DROP POLICY IF EXISTS driver_status_cache_account_access ON app.driver_status_cache;
DROP POLICY IF EXISTS driver_status_history_account_access ON app.driver_status_history;
DROP POLICY IF EXISTS favorite_locations_account_access ON app.favorite_locations;
DROP POLICY IF EXISTS promo_code_usages_account_access ON app.promo_code_usages;
DROP POLICY IF EXISTS promo_codes_application_isolation ON app.promo_codes;
DROP POLICY IF EXISTS admin_zones_access ON core.zones;
DROP POLICY IF EXISTS admin_routes_access ON core.route_definitions;
DROP POLICY IF EXISTS admin_vehicles_access ON core.vehicles;
DROP POLICY IF EXISTS admin_disputes_access ON core.disputes;
DROP POLICY IF EXISTS admin_fare_params_access ON core.fare_parameters;
DROP POLICY IF EXISTS admin_fee_structures_access ON core.fee_structures;
DROP POLICY IF EXISTS admin_driver_status_access ON app.driver_status_cache;

-- Drop triggers
DROP TRIGGER IF EXISTS trg_location_assertions_insert_hook ON core.location_assertions;
DROP TRIGGER IF EXISTS trg_disputes_status_change ON core.disputes;
DROP TRIGGER IF EXISTS trg_driver_status_cache_change ON app.driver_status_cache;

-- Drop functions
DROP FUNCTION IF EXISTS core.compute_location_assertion_hash(UUID, NUMERIC, NUMERIC, TIMESTAMPTZ, VARCHAR) CASCADE;
DROP FUNCTION IF EXISTS core.location_assertion_insert_hook() CASCADE;
DROP FUNCTION IF EXISTS core.find_zone_for_point(NUMERIC, NUMERIC, UUID, VARCHAR) CASCADE;
DROP FUNCTION IF EXISTS core.check_vehicle_compliance(UUID, TIMESTAMPTZ) CASCADE;
DROP FUNCTION IF EXISTS core.is_vehicle_serviceable(UUID, TIMESTAMPTZ) CASCADE;
DROP FUNCTION IF EXISTS core.log_dispute_status_change() CASCADE;
DROP FUNCTION IF EXISTS core.check_account_eligibility(UUID, UUID, VARCHAR) CASCADE;
DROP FUNCTION IF EXISTS core.check_vehicle_regulatory_status(UUID, UUID) CASCADE;
DROP FUNCTION IF EXISTS core.calculate_trip_fare(UUID, UUID, VARCHAR, NUMERIC, NUMERIC, NUMERIC, NUMERIC, TIMESTAMPTZ) CASCADE;
DROP FUNCTION IF EXISTS core.calculate_fee_breakdown(UUID, NUMERIC, VARCHAR, TIMESTAMPTZ) CASCADE;
DROP FUNCTION IF EXISTS core.get_fare_parameters_at_time(UUID, UUID, VARCHAR, TIMESTAMPTZ) CASCADE;
DROP FUNCTION IF EXISTS app.log_driver_status_change() CASCADE;
DROP FUNCTION IF EXISTS app.validate_promo_code(VARCHAR, UUID, UUID, NUMERIC, VARCHAR, UUID) CASCADE;

-- Drop app tables
DROP TABLE IF EXISTS app.promo_code_usages CASCADE;
DROP TABLE IF EXISTS app.promo_codes CASCADE;
DROP TABLE IF EXISTS app.favorite_locations CASCADE;
DROP TABLE IF EXISTS app.driver_status_history CASCADE;
DROP TABLE IF EXISTS app.driver_status_cache CASCADE;

-- Drop core tables
DROP TABLE IF EXISTS core.regulatory_parameters CASCADE;
DROP TABLE IF EXISTS core.fee_structures CASCADE;
DROP TABLE IF EXISTS core.fare_parameters CASCADE;
DROP TABLE IF EXISTS core.dispute_status_history CASCADE;
DROP TABLE IF EXISTS core.disputes CASCADE;
DROP TABLE IF EXISTS core.regulatory_flags CASCADE;
DROP TABLE IF EXISTS core.document_verifications CASCADE;
DROP TABLE IF EXISTS core.vehicle_compliance CASCADE;
DROP TABLE IF EXISTS core.vehicle_assignments CASCADE;
DROP TABLE IF EXISTS core.vehicles CASCADE;
DROP TABLE IF EXISTS core.location_assertions CASCADE;
DROP TABLE IF EXISTS core.route_definitions CASCADE;
DROP TABLE IF EXISTS core.zones CASCADE;
