-- ============================================================================
-- Database Extensions
-- ============================================================================

-- Core extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "ltree";

-- Performance extensions
-- CREATE EXTENSION IF NOT EXISTS "timescaledb"; -- Requires superuser

-- Full-text search
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- JSON utilities
CREATE EXTENSION IF NOT EXISTS "hstore";

-- Job scheduling (if available)
-- CREATE EXTENSION IF NOT EXISTS "pg_cron";

-- Foreign data wrapper (for replication)
-- CREATE EXTENSION IF NOT EXISTS "postgres_fdw";
