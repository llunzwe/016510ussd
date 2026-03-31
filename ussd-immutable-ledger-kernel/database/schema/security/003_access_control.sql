-- ============================================================================
-- Access Control Setup
-- ============================================================================

-- Roles
CREATE ROLE IF NOT EXISTS readonly;
CREATE ROLE IF NOT EXISTS readwrite;
CREATE ROLE IF NOT EXISTS app_admin;
CREATE ROLE IF NOT EXISTS auditor;

-- Grant schema usage
GRANT USAGE ON SCHEMA core TO readonly, readwrite, app_admin, auditor;
GRANT USAGE ON SCHEMA app TO readonly, readwrite, app_admin, auditor;
GRANT USAGE ON SCHEMA ussd_gateway TO readonly, readwrite, app_admin, auditor;

-- Readonly permissions
GRANT SELECT ON ALL TABLES IN SCHEMA core TO readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO readonly;

-- Readwrite permissions
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA core TO readwrite;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA app TO readwrite;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA ussd_gateway TO readwrite;

-- Admin permissions
GRANT ALL ON ALL TABLES IN SCHEMA core TO app_admin;
GRANT ALL ON ALL TABLES IN SCHEMA app TO app_admin;
GRANT ALL ON ALL TABLES IN SCHEMA ussd_gateway TO app_admin;
GRANT ALL ON ALL TABLES IN SCHEMA ussd_security TO app_admin;

-- Auditor permissions (read-only on audit tables)
GRANT SELECT ON ALL TABLES IN SCHEMA core TO auditor;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO auditor;

-- Row Level Security policies are defined in individual schema policy files
