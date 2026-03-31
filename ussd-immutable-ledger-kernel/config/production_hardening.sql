-- =============================================================================
-- USSD KERNEL - PRODUCTION HARDENING CONFIGURATION
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    production_hardening.sql
-- LOCATION:    config/production_hardening.sql
-- DESCRIPTION: PostgreSQL configuration for production deployment.
--              Apply these settings via postgresql.conf or ALTER SYSTEM.
-- =============================================================================

/*
================================================================================
PRODUCTION DEPLOYMENT CHECKLIST
================================================================================

Before applying these settings:
☐ Database backup completed
☐ Tested in staging environment
☐ Monitoring and alerting configured
☐ Failover/replication tested
☐ Incident response plan documented
☐ Security audit passed

================================================================================
CONFIGURATION SECTIONS
================================================================================

1. Connection & Authentication
2. Memory & Resource Management
3. WAL & Replication
4. Logging & Monitoring
5. Query Planning
6. Security Hardening
7. Kernel-Specific Settings

================================================================================
*/

-- =============================================================================
-- SECTION 1: CONNECTION & AUTHENTICATION
-- =============================================================================

-- Connection limits (adjust based on expected load)
-- max_connections = 200;                    -- Total connections allowed
-- superuser_reserved_connections = 3;       -- Reserved for superuser emergencies

-- Connection pooling recommendations:
-- Use PgBouncer in transaction mode for high-concurrency workloads
-- max_client_conn = 10000 (PgBouncer)
-- default_pool_size = 20 (PgBouncer)

-- Authentication settings
-- password_encryption = 'scram-sha-256';    -- Modern password hashing
-- ssl = on;                                 -- Require SSL/TLS
-- ssl_min_protocol_version = 'TLSv1.2';     -- Minimum TLS version

-- Connection timeouts
-- tcp_keepalives_idle = 60;                 -- TCP keepalive settings
-- tcp_keepalives_interval = 10;
-- tcp_keepalives_count = 6;

-- =============================================================================
-- SECTION 2: MEMORY & RESOURCE MANAGEMENT
-- =============================================================================

-- Shared memory
-- shared_buffers = 4GB;                     -- 25% of total RAM (adjust for your system)
-- effective_cache_size = 12GB;              -- 75% of total RAM (for query planning)
-- work_mem = 256MB;                         -- Per-operation memory (complex queries)
-- maintenance_work_mem = 1GB;               -- Maintenance operations (VACUUM, CREATE INDEX)

-- Kernel-specific memory for hash/Merkle operations
-- dynamic_shared_memory_type = posix;       -- Use POSIX shared memory

-- Resource limits
-- max_worker_processes = 8;                 -- Parallel workers
-- max_parallel_workers_per_gather = 4;
-- max_parallel_workers = 8;
-- max_parallel_maintenance_workers = 4;

-- Autovacuum tuning (critical for immutable ledger with high insert rate)
-- autovacuum = on;
-- autovacuum_max_workers = 4;
-- autovacuum_naptime = 30s;                 -- Check for work every 30s
-- autovacuum_vacuum_threshold = 50;
-- autovacuum_vacuum_scale_factor = 0.1;     -- Vacuum when 10% of table changes
-- autovacuum_analyze_threshold = 50;
-- autovacuum_analyze_scale_factor = 0.05;

-- Aggressive autovacuum for high-churn tables
-- autovacuum_vacuum_insert_threshold = 1000;
-- autovacuum_vacuum_insert_scale_factor = 0.2;

-- =============================================================================
-- SECTION 3: WAL (WRITE-AHEAD LOG) & REPLICATION
-- =============================================================================

-- WAL settings (critical for data durability)
-- wal_level = 'replica';                    -- Minimum for replication
-- wal_level = 'logical';                    -- Required for logical replication

-- fsync = on;                               -- Critical: ensures data durability
-- synchronous_commit = 'remote_apply';      -- Wait for replica to apply (strongest)
-- synchronous_commit = 'on';                -- Wait for local disk (balanced)
-- synchronous_commit = 'local';             -- Fastest, slight risk

-- WAL archiving for point-in-time recovery
-- archive_mode = on;
-- archive_command = 'cp %p /archive/%f';    -- Customize for your backup system
-- archive_timeout = 300;                    -- Force archive every 5 minutes

-- WAL retention
-- wal_keep_size = 16GB;                     -- Keep WAL for replication lag
-- max_slot_wal_keep_size = 32GB;            -- Max WAL to keep for slots

-- Replication slots (for streaming replicas)
-- max_replication_slots = 10;
-- max_wal_senders = 10;

-- =============================================================================
-- SECTION 4: LOGGING & MONITORING (CRITICAL FOR AUDIT)
-- =============================================================================

-- Log destination
-- log_destination = 'stderr';               -- or 'csvlog', 'syslog', 'jsonlog'
-- logging_collector = on;                   -- Enable log collection
-- log_directory = 'log';                    -- Log file location
-- log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log';
-- log_rotation_age = 1d;                    -- Rotate daily
-- log_rotation_size = 1GB;                  -- Or when size reached
-- log_truncate_on_rotation = off;           -- Append to existing

-- Log line format (detailed for audit)
-- log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h,txid=%x '
-- Format: timestamp [pid]: [line] user=,db=,app=,client=,txid=

-- What to log (comprehensive for security audit)
-- log_checkpoints = on;                     -- Log checkpoints
-- log_connections = on;                     -- Log all connection attempts
-- log_disconnections = on;                  -- Log disconnections
-- log_duration = on;                        -- Log query durations
-- log_lock_waits = on;                      -- Log lock waits > deadlock_timeout

-- Log statements (adjust based on compliance requirements)
-- log_statement = 'ddl';                    -- Log DDL (CREATE, ALTER, DROP)
-- log_statement = 'mod';                    -- Log DDL + DML (INSERT, UPDATE, DELETE)
-- log_statement = 'all';                    -- Log all statements (high volume)

-- Slow query logging
-- log_min_duration_statement = 1000;        -- Log queries > 1000ms
-- log_slow_statement = on;

-- Auto-explain for query analysis
-- auto_explain.log_min_duration = '10s';    -- Log slow query plans
-- auto_explain.log_analyze = true;          -- Include actual timing
-- auto_explain.log_buffers = true;          -- Include buffer usage

-- =============================================================================
-- SECTION 5: QUERY PLANNING & OPTIMIZATION
-- =============================================================================

-- Statistics collection
-- track_activities = on;                    -- Track running queries
-- track_counts = on;                        -- Track table/index access
-- track_io_timing = on;                     -- Track I/O timing (overhead)
-- track_functions = all;                    -- Track function usage

-- Query planner
-- random_page_cost = 1.1;                   -- For SSD storage (lower than default 4)
-- seq_page_cost = 1.0;
-- effective_io_concurrency = 200;           -- For SSD/NVMe

-- Enable optimizations
-- jit = on;                                 -- Just-in-time compilation
-- jit_above_cost = 100000;
-- jit_inline_above_cost = 500000;
-- jit_optimize_above_cost = 500000;

-- TimescaleDB-specific (if using)
-- timescaledb.telemetry_level = 'off';      -- Disable telemetry in production
-- timescaledb.max_background_workers = 8;

-- =============================================================================
-- SECTION 6: SECURITY HARDENING
-- =============================================================================

-- File permissions
-- unix_socket_permissions = '0770';         -- Restrict socket access
-- log_file_mode = '0600';                   -- Secure log files

-- Prevent loading external libraries
-- local_preload_libraries = '';             -- Only load trusted extensions
-- session_preload_libraries = '';
-- shared_preload_libraries = 'pg_stat_statements,pgcrypto,timescaledb';

-- Statement timeout (prevent runaway queries)
-- statement_timeout = '60s';                -- Kill queries > 60 seconds
-- lock_timeout = '30s';                     -- Give up on lock waits > 30s
-- idle_in_transaction_session_timeout = '10min'; -- Kill idle transactions

-- Restrict functions
-- check_function_bodies = on;               -- Validate functions on creation

-- Row-level security (must be explicitly enabled per table)
-- No global setting - use: ALTER TABLE ... ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- SECTION 7: IMMUTABLE LEDGER KERNEL SPECIFIC SETTINGS
-- =============================================================================

-- Hash calculation performance
-- enable_parallel_hash = on;                -- Parallel hash joins

-- JSONB performance (heavily used in kernel)
-- jsonb_pretty-print = off;                 -- Compact JSONB storage

-- Partitioning for time-series data (if not using TimescaleDB)
-- constraint_exclusion = partition;         -- Skip irrelevant partitions

-- TimescaleDB compression (recommended for transaction_log)
-- timescaledb.compress = on;
-- timescaledb.compress_segmentby = 'application_id';
-- timescaledb.compress_orderby = 'committed_at DESC';

-- =============================================================================
-- APPLY SETTINGS COMMAND REFERENCE
-- =============================================================================

-- Method 1: ALTER SYSTEM (persists across restarts, requires reload)
-- ALTER SYSTEM SET parameter_name = 'value';
-- SELECT pg_reload_conf();

-- Method 2: postgresql.conf (edit file, restart required for some)
-- Edit $PGDATA/postgresql.conf
-- systemctl restart postgresql

-- Method 3: Per-database or per-user settings
-- ALTER DATABASE ussd_kernel SET parameter_name = 'value';
-- ALTER USER kernel_admin SET parameter_name = 'value';

-- =============================================================================
-- RECOMMENDED SETTINGS FOR DIFFERENT DEPLOYMENT SIZES
-- =============================================================================

/*
SMALL (Single server, 8GB RAM, 4 cores):
  shared_buffers = 2GB
  effective_cache_size = 6GB
  work_mem = 128MB
  max_connections = 100

MEDIUM (Single server, 32GB RAM, 8 cores):
  shared_buffers = 8GB
  effective_cache_size = 24GB
  work_mem = 256MB
  max_connections = 200

LARGE (Primary + 2 replicas, 64GB RAM each, 16 cores):
  shared_buffers = 16GB
  effective_cache_size = 48GB
  work_mem = 512MB
  max_connections = 300
  wal_level = 'replica'
  max_wal_senders = 10

ENTERPRISE (HA cluster, 128GB+ RAM, 32+ cores, TimescaleDB):
  shared_buffers = 32GB
  effective_cache_size = 96GB
  work_mem = 1GB
  max_connections = 500
  wal_level = 'logical'
  max_wal_senders = 20
  max_worker_processes = 32
  timescaledb.max_background_workers = 16
*/

-- =============================================================================
-- IMMEDIATELY APPLICABLE SETTINGS (Run these now)
-- =============================================================================

-- These settings can be applied immediately without restart
ALTER SYSTEM SET log_checkpoints = on;
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;
ALTER SYSTEM SET log_lock_waits = on;

-- Reload configuration
SELECT pg_reload_conf();

-- Verify settings
SELECT name, setting, unit, context 
FROM pg_settings 
WHERE name IN (
    'log_checkpoints', 'log_connections', 'log_disconnections', 
    'log_lock_waits', 'shared_buffers', 'max_connections'
)
ORDER BY name;

-- =============================================================================
-- END OF CONFIGURATION
-- =============================================================================
