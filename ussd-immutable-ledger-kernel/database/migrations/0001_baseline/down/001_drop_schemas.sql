-- ============================================================================
-- Down Migration: Drop Schemas
-- WARNING: This will destroy all data!
-- ============================================================================

-- Drop in reverse order to handle dependencies
DROP SCHEMA IF EXISTS utils CASCADE;
DROP SCHEMA IF EXISTS ussd_archive CASCADE;
DROP SCHEMA IF EXISTS ussd_audit CASCADE;
DROP SCHEMA IF EXISTS ussd_security CASCADE;
DROP SCHEMA IF EXISTS ussd_gateway CASCADE;
DROP SCHEMA IF EXISTS app CASCADE;
DROP SCHEMA IF EXISTS core CASCADE;
