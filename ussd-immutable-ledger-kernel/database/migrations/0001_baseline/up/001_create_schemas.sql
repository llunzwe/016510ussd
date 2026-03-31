-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Controls A.5.1, A.8.1, A.9.2, A.12.1)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Multi-tenancy)
-- ISO/IEC 27040:2024 - Storage Security (Schema isolation)
-- ============================================================================
-- CODING PRACTICES:
-- - Use explicit schema qualification (schema.object)
-- - Set search_path explicitly in each function
-- - Use SECURITY DEFINER only for privileged operations
-- ============================================================================

-- Create schemas with proper ownership
CREATE SCHEMA IF NOT EXISTS core AUTHORIZATION postgres;
CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION postgres;
CREATE SCHEMA IF NOT EXISTS ussd_gateway AUTHORIZATION postgres;
CREATE SCHEMA IF NOT EXISTS ussd_security AUTHORIZATION postgres;
CREATE SCHEMA IF NOT EXISTS ussd_audit AUTHORIZATION postgres;
CREATE SCHEMA IF NOT EXISTS ussd_archive AUTHORIZATION postgres;
CREATE SCHEMA IF NOT EXISTS utils AUTHORIZATION postgres;

-- Set schema comments
COMMENT ON SCHEMA core IS 'Core immutable ledger schema - append-only tables with cryptographic verification';
COMMENT ON SCHEMA app IS 'Application configuration schema - mutable multi-tenant settings with versioning';
COMMENT ON SCHEMA ussd_gateway IS 'USSD gateway schema - session management and menu routing';
COMMENT ON SCHEMA ussd_security IS 'Security schema - encryption, access control, and audit';
COMMENT ON SCHEMA ussd_audit IS 'Audit schema - compliance logging and monitoring';
COMMENT ON SCHEMA ussd_archive IS 'Archive schema - cold storage and data retention';
COMMENT ON SCHEMA utils IS 'Utility schema - helper functions and common operations';

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "ltree";

-- Note: TimescaleDB extension requires superuser and is installed at database level
-- CREATE EXTENSION IF NOT EXISTS "timescaledb";
