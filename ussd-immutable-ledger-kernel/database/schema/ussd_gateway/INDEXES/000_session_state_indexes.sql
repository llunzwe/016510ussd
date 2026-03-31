-- ============================================================================
-- USSD SESSION STATE INDEXES
-- ============================================================================
-- Purpose: Optimize query performance for USSD session operations including
--          session lookup, cleanup, audit queries, and reporting.
-- Context: USSD systems require high-performance lookups for active sessions
--          and efficient cleanup of expired data. These indexes support
--          the expected query patterns at scale (10M+ sessions/day).
--
-- COMPLIANCE & STANDARDS:
--   ISO/IEC 27001:2022 - Information Security Management
--     * A.8.1: Secure indexing of session data
--     * A.8.12: Audit query performance optimization
--     * A.8.16: Monitoring index for security analysis
--
--   ISO/IEC 27018:2019 - PII Protection
--     * MSISDN index considerations for privacy
--     * No encryption of indexed values (design trade-off)
--     * Access control on index usage statistics
--
--   GDPR Article 32 - Security of Processing
--     * Index security (timing attack awareness)
--     * Audit index access patterns
--     * Secure index cleanup on data deletion
--
-- INDEX DESIGN PRINCIPLES:
--   - Cover common query patterns
--   - Support cleanup and archival operations
--   - Enable efficient concurrency control
--   - Support audit and compliance queries
--   - Balance read performance with write overhead
--
-- ENTERPRISE POSTGRESQL PRACTICES:
--   - Partial indexes for conditional queries (reduces size)
--   - Covering indexes with INCLUDE clause
--   - BRIN indexes for time-series data consideration
--   - Concurrent index creation (CREATE INDEX CONCURRENTLY)
--   - Regular index maintenance and bloat monitoring
-- ============================================================================

-- ----------------------------------------------------------------------------
-- PRIMARY LOOKUP INDEXES
-- ----------------------------------------------------------------------------
-- These indexes support the most frequent operations: session lookup by
-- MSISDN and session ID validation.
-- ----------------------------------------------------------------------------

-- Primary lookup: Find active session by MSISDN (most common query)
-- Used by: create_session(), update_session_context(), resume_session()
CREATE INDEX IF NOT EXISTS idx_session_msisdn_active 
    ON ussd_session_state(msisdn, is_active, expires_at) 
    WHERE is_active = TRUE;

COMMENT ON INDEX idx_session_msisdn_active IS 
    'Primary lookup for active sessions by MSISDN. Used for session validation on every request.';

-- Composite index for session lookup with state filtering
-- Used by: Cleanup jobs, monitoring queries
CREATE INDEX IF NOT EXISTS idx_session_msisdn_state 
    ON ussd_session_state(msisdn, current_state, created_at DESC);

COMMENT ON INDEX idx_session_msisdn_state IS 
    'Supports queries filtering by MSISDN and state for audit and reporting.';

-- ----------------------------------------------------------------------------
-- EXPIRATION AND CLEANUP INDEXES
-- ----------------------------------------------------------------------------
-- These indexes support efficient cleanup of expired sessions,
-- which runs frequently (every 30 seconds in high-volume systems).
-- ----------------------------------------------------------------------------

-- Cleanup index: Find expired sessions efficiently
-- Used by: cleanup_expired_sessions()
CREATE INDEX IF NOT EXISTS idx_session_expires_active 
    ON ussd_session_state(expires_at, is_active) 
    WHERE is_active = TRUE;

COMMENT ON INDEX idx_session_expires_active IS 
    'Supports efficient cleanup of expired sessions. Critical for performance.';

-- Cleanup index: Find finalized old sessions for archival
-- Used by: cleanup_expired_sessions() archival phase
CREATE INDEX IF NOT EXISTS idx_session_finalized_date 
    ON ussd_session_state(is_finalized, completed_at) 
    WHERE is_finalized = TRUE;

COMMENT ON INDEX idx_session_finalized_date IS 
    'Supports archival of old finalized sessions.';

-- Partial index for timeout recovery candidates
-- Used by: resume_session()
CREATE INDEX IF NOT EXISTS idx_session_timeout_recovery 
    ON ussd_session_state(msisdn, completion_status, completed_at) 
    WHERE completion_status = 'TIMEOUT' 
    AND completed_at > NOW() - INTERVAL '5 minutes';

COMMENT ON INDEX idx_session_timeout_recovery IS 
    'Supports session resume functionality for recently timed out sessions.';

-- ----------------------------------------------------------------------------
-- APPLICATION AND ROUTING INDEXES
-- ----------------------------------------------------------------------------
-- These indexes support routing decisions and application-level queries.
-- ----------------------------------------------------------------------------

-- Application session tracking
-- Used by: Application analytics, load balancing
CREATE INDEX IF NOT EXISTS idx_session_application 
    ON ussd_session_state(application_id, created_at DESC);

COMMENT ON INDEX idx_session_application IS 
    'Supports application-level session tracking and analytics.';

-- Shortcode analysis
-- Used by: Routing analytics, shortcode usage reports
CREATE INDEX IF NOT EXISTS idx_session_shortcode 
    ON ussd_session_state(shortcode, created_at DESC);

COMMENT ON INDEX idx_session_shortcode IS 
    'Supports shortcode usage analytics and routing optimization.';

-- Operator-level analysis
-- Used by: Operator analytics, troubleshooting
CREATE INDEX IF NOT EXISTS idx_session_operator 
    ON ussd_session_state(operator_code, created_at DESC);

COMMENT ON INDEX idx_session_operator IS 
    'Supports operator-level session analysis and troubleshooting.';

-- ----------------------------------------------------------------------------
-- SECURITY AND AUDIT INDEXES
-- ----------------------------------------------------------------------------
-- These indexes support security monitoring, fraud detection, and audit queries.
-- ----------------------------------------------------------------------------

-- Device fingerprint correlation
-- Used by: verify_device_fingerprint(), fraud detection
CREATE INDEX IF NOT EXISTS idx_session_device_fp 
    ON ussd_session_state(device_fingerprint_id, created_at DESC) 
    WHERE device_fingerprint_id IS NOT NULL;

COMMENT ON INDEX idx_session_device_fp IS 
    'Supports device fingerprint correlation and security analysis.';

-- Source IP analysis (security monitoring)
-- Used by: check_velocity_limits(), DDoS detection
CREATE INDEX IF NOT EXISTS idx_session_source_ip 
    ON ussd_session_state(source_ip, created_at DESC);

COMMENT ON INDEX idx_session_source_ip IS 
    'Supports IP-based security analysis and rate limiting.';

-- Session hash chain lookup (audit)
-- Used by: Audit queries, integrity verification
CREATE INDEX IF NOT EXISTS idx_session_hash 
    ON ussd_session_state(session_hash, previous_session_hash);

COMMENT ON INDEX idx_session_hash IS 
    'Supports audit chain verification and integrity checks.';

-- Audit time range queries
-- Used by: Compliance queries, audit reports
CREATE INDEX IF NOT EXISTS idx_session_created_audit 
    ON ussd_session_state(created_at, msisdn);

COMMENT ON INDEX idx_session_created_audit IS 
    'Supports time-range audit queries.';

-- SIM swap session tracking
-- Used by: SIM swap detection, post-swap session analysis
CREATE INDEX IF NOT EXISTS idx_session_sim_swap 
    ON ussd_session_state(msisdn, created_at DESC, device_fingerprint_id)
    WHERE device_fingerprint_id IS NOT NULL;

COMMENT ON INDEX idx_session_sim_swap IS 
    'Supports SIM swap detection and post-swap session correlation.';

-- ----------------------------------------------------------------------------
-- TRANSACTION CORRELATION INDEXES
-- ----------------------------------------------------------------------------
-- These indexes support correlation with the pending_transactions table.
-- ----------------------------------------------------------------------------

-- Transaction session correlation
-- Used by: Transaction cleanup, session-transaction linkage
CREATE INDEX IF NOT EXISTS idx_session_transaction 
    ON ussd_session_state(session_id, is_active, expires_at) 
    INCLUDE (msisdn, application_id);

COMMENT ON INDEX idx_session_transaction IS 
    'Supports efficient session-transaction correlation queries.';

-- ----------------------------------------------------------------------------
-- MENU NAVIGATION INDEXES
-- ----------------------------------------------------------------------------
-- These indexes support the menu_navigation_history table.
-- ----------------------------------------------------------------------------

-- Session navigation history
-- Used by: Session replay, navigation analytics
CREATE INDEX IF NOT EXISTS idx_nav_history_session 
    ON menu_navigation_history(session_id, navigation_at DESC);

COMMENT ON INDEX idx_nav_history_session IS 
    'Primary lookup for session navigation history. Supports session replay.';

-- Menu usage analytics
-- Used by: Menu optimization, UX analysis
CREATE INDEX IF NOT EXISTS idx_nav_history_menu 
    ON menu_navigation_history(from_menu_id, to_menu_id, navigation_at);

COMMENT ON INDEX idx_nav_history_menu IS 
    'Supports menu flow analytics and optimization.';

-- Time-based navigation analysis
-- Used by: Usage pattern analysis, behavioral biometrics
CREATE INDEX IF NOT EXISTS idx_nav_history_time 
    ON menu_navigation_history(navigation_at, session_id);

COMMENT ON INDEX idx_nav_history_time IS 
    'Supports time-based navigation pattern analysis.';

-- Device fingerprint in navigation
-- Used by: Behavioral biometrics, fraud detection
CREATE INDEX IF NOT EXISTS idx_nav_history_device 
    ON menu_navigation_history(device_fingerprint_id, navigation_at DESC) 
    WHERE device_fingerprint_id IS NOT NULL;

COMMENT ON INDEX idx_nav_history_device IS 
    'Supports device-based navigation analysis for behavioral biometrics.';

-- ----------------------------------------------------------------------------
-- DEVICE FINGERPRINT INDEXES
-- ----------------------------------------------------------------------------
-- These indexes support the device_fingerprints table.
-- ----------------------------------------------------------------------------

-- Primary fingerprint lookup
-- Used by: verify_device_fingerprint(), session creation
CREATE INDEX IF NOT EXISTS idx_fp_msisdn_hash 
    ON device_fingerprints(msisdn, fingerprint_hash, status);

COMMENT ON INDEX idx_fp_msisdn_hash IS 
    'Primary lookup for device fingerprint verification.';

-- Active fingerprint lookup with recency
-- Used by: Trust score calculations, recent device queries
CREATE INDEX IF NOT EXISTS idx_fp_msisdn_active_recent 
    ON device_fingerprints(msisdn, status, last_session_at DESC) 
    WHERE status = 'ACTIVE';

COMMENT ON INDEX idx_fp_msisdn_active_recent IS 
    'Supports queries for recent active devices per MSISDN.';

-- SIM swap correlation lookup
-- Used by: SIM swap detection, post-swap restrictions
CREATE INDEX IF NOT EXISTS idx_fp_sim_swap 
    ON device_fingerprints(msisdn, post_sim_swap, sim_swap_detected_at) 
    WHERE post_sim_swap = TRUE;

COMMENT ON INDEX idx_fp_sim_swap IS 
    'Supports SIM swap correlation and post-swap restrictions.';

-- Trust score queries
-- Used by: Risk assessment, verification decisions
CREATE INDEX IF NOT EXISTS idx_fp_trust_level 
    ON device_fingerprints(trust_level, trust_score, status);

COMMENT ON INDEX idx_fp_trust_level IS 
    'Supports queries by trust level for risk assessment.';

-- First seen analytics
-- Used by: New device tracking, cohort analysis
CREATE INDEX IF NOT EXISTS idx_fp_first_seen 
    ON device_fingerprints(first_seen_at, msisdn);

COMMENT ON INDEX idx_fp_first_seen IS 
    'Supports new device analytics and cohort tracking.';

-- Blacklisted device monitoring
-- Used by: Security monitoring, fraud prevention
CREATE INDEX IF NOT EXISTS idx_fp_blacklisted 
    ON device_fingerprints(status, trust_level, updated_at)
    WHERE status IN ('SUSPENDED', 'REVOKED') OR trust_level = 'BLACKLISTED';

COMMENT ON INDEX idx_fp_blacklisted IS 
    'Supports monitoring of blacklisted or suspended devices.';

-- ----------------------------------------------------------------------------
-- PENDING TRANSACTIONS INDEXES
-- ----------------------------------------------------------------------------
-- These indexes support the pending_transactions table.
-- ----------------------------------------------------------------------------

-- Session-transaction lookup
-- Used by: Transaction cleanup, session finalization
CREATE INDEX IF NOT EXISTS idx_tx_session 
    ON pending_transactions(session_id, created_at DESC);

COMMENT ON INDEX idx_tx_session IS 
    'Primary lookup for transactions by session.';

-- Status-based polling queries
-- Used by: Transaction processor, cleanup
CREATE INDEX IF NOT EXISTS idx_tx_status_time 
    ON pending_transactions(status, expires_at) 
    WHERE status IN ('PENDING', 'PROCESSING', 'AWAITING_CALLBACK');

COMMENT ON INDEX idx_tx_status_time IS 
    'Supports polling queries for active transactions.';

-- MSISDN transaction history
-- Used by: User transaction history, fraud analysis
CREATE INDEX IF NOT EXISTS idx_tx_msisdn 
    ON pending_transactions(msisdn, created_at DESC);

COMMENT ON INDEX idx_tx_msisdn IS 
    'Supports MSISDN-based transaction queries.';

-- External reference lookup
-- Used by: Callback processing, reconciliation
CREATE INDEX IF NOT EXISTS idx_tx_external 
    ON pending_transactions(external_transaction_id, external_reference) 
    WHERE external_transaction_id IS NOT NULL;

COMMENT ON INDEX idx_tx_external IS 
    'Supports external transaction reference lookups.';

-- Idempotency key lookup
-- Used by: Duplicate transaction prevention
CREATE INDEX IF NOT EXISTS idx_tx_idempotency 
    ON pending_transactions(idempotency_key, idempotency_scope) 
    WHERE idempotency_key IS NOT NULL;

COMMENT ON INDEX idx_tx_idempotency IS 
    'Supports idempotency key lookups for duplicate prevention.';

-- Status tracking for analytics
-- Used by: Transaction metrics, monitoring dashboards
CREATE INDEX IF NOT EXISTS idx_tx_status_analytics 
    ON pending_transactions(status, transaction_type, created_at);

COMMENT ON INDEX idx_tx_status_analytics IS 
    'Supports transaction status analytics and monitoring.';

-- SIM swap tracking for transactions
-- Used by: Pre-transaction SIM swap checks
CREATE INDEX IF NOT EXISTS idx_tx_sim_swap_check 
    ON pending_transactions(msisdn, sim_swap_checked, created_at)
    WHERE sim_swap_checked = FALSE;

COMMENT ON INDEX idx_tx_sim_swap_check IS 
    'Supports pending SIM swap checks for transactions.';

-- ----------------------------------------------------------------------------
-- SIM SWAP CORRELATION INDEXES
-- ----------------------------------------------------------------------------
-- These indexes support the sim_swap_correlations table.
-- ----------------------------------------------------------------------------

-- MSISDN swap history
-- Used by: SIM swap detection, risk assessment
CREATE INDEX IF NOT EXISTS idx_swap_msisdn 
    ON sim_swap_correlations(msisdn, sim_swap_detected_at DESC);

COMMENT ON INDEX idx_swap_msisdn IS 
    'Primary lookup for SIM swap history by MSISDN.';

-- Recent unverified swaps
-- Used by: Restrictions, verification workflows
CREATE INDEX IF NOT EXISTS idx_swap_unverified 
    ON sim_swap_correlations(msisdn, sim_swap_detected_at, verified_legitimate) 
    WHERE verified_legitimate IS NOT TRUE 
    AND sim_swap_detected_at > NOW() - INTERVAL '7 days';

COMMENT ON INDEX idx_swap_unverified IS 
    'Supports queries for recent unverified SIM swaps.';

-- Risk level analysis
-- Used by: Fraud analytics, risk reporting
CREATE INDEX IF NOT EXISTS idx_swap_risk_level 
    ON sim_swap_correlations(risk_level, sim_swap_detected_at);

COMMENT ON INDEX idx_swap_risk_level IS 
    'Supports risk level-based swap analysis.';

-- Critical window tracking
-- Used by: 72-hour critical window monitoring
CREATE INDEX IF NOT EXISTS idx_swap_critical_window 
    ON sim_swap_correlations(msisdn, sim_swap_detected_at)
    WHERE sim_swap_detected_at > NOW() - INTERVAL '72 hours';

COMMENT ON INDEX idx_swap_critical_window IS 
    'Supports 72-hour critical window monitoring for SIM swaps.';

-- ----------------------------------------------------------------------------
-- EVENT LOG INDEXES
-- ----------------------------------------------------------------------------
-- These indexes support the fingerprint_events table.
-- ----------------------------------------------------------------------------

-- Fingerprint event history
-- Used by: Security audit, fraud investigation
CREATE INDEX IF NOT EXISTS idx_events_fingerprint 
    ON fingerprint_events(fingerprint_id, occurred_at DESC);

COMMENT ON INDEX idx_events_fingerprint IS 
    'Primary lookup for fingerprint events.';

-- MSISDN event history
-- Used by: User security history, investigation
CREATE INDEX IF NOT EXISTS idx_events_msisdn 
    ON fingerprint_events(msisdn, event_type, occurred_at DESC);

COMMENT ON INDEX idx_events_msisdn IS 
    'Supports MSISDN-based security event queries.';

-- Time-based event analysis
-- Used by: Security analytics, incident response
CREATE INDEX IF NOT EXISTS idx_events_time 
    ON fingerprint_events(occurred_at, event_severity);

COMMENT ON INDEX idx_events_time IS 
    'Supports time-based security event analysis.';

-- Severity-based alerts
-- Used by: Alerting system, security monitoring
CREATE INDEX IF NOT EXISTS idx_events_severity 
    ON fingerprint_events(event_severity, occurred_at DESC) 
    WHERE event_severity IN ('ALERT', 'CRITICAL');

COMMENT ON INDEX idx_events_severity IS 
    'Supports high-severity event alerting.';

-- SIM swap event tracking
-- Used by: SIM swap incident response
CREATE INDEX IF NOT EXISTS idx_events_sim_swap 
    ON fingerprint_events(event_type, occurred_at DESC)
    WHERE event_type IN ('SIM_SWAP_CORRELATED', 'SESSION_CREATED');

COMMENT ON INDEX idx_events_sim_swap IS 
    'Supports SIM swap event correlation and analysis.';

-- ----------------------------------------------------------------------------
-- ROUTING INDEXES
-- ----------------------------------------------------------------------------
-- These indexes support the shortcode_routing table.
-- ----------------------------------------------------------------------------

-- Active route lookup
-- Used by: resolve_shortcode()
CREATE INDEX IF NOT EXISTS idx_routing_active 
    ON shortcode_routing(base_shortcode, is_active, match_priority DESC) 
    WHERE is_active = TRUE;

COMMENT ON INDEX idx_routing_active IS 
    'Primary index for shortcode route resolution.';

-- Operator-specific routes
-- Used by: Operator-specific routing
CREATE INDEX IF NOT EXISTS idx_routing_operator 
    ON shortcode_routing(operator_code, base_shortcode, is_active);

COMMENT ON INDEX idx_routing_operator IS 
    'Supports operator-specific route lookups.';

-- Effective date range
-- Used by: Time-based routing
CREATE INDEX IF NOT EXISTS idx_routing_effective 
    ON shortcode_routing(effective_from, effective_to, is_active);

COMMENT ON INDEX idx_routing_effective IS 
    'Supports time-based route validity queries.';

-- Circuit breaker monitoring
-- Used by: Circuit breaker health checks
CREATE INDEX IF NOT EXISTS idx_routing_circuit_breaker 
    ON shortcode_routing(circuit_breaker_status, consecutive_failures)
    WHERE circuit_breaker_status != 'CLOSED';

COMMENT ON INDEX idx_routing_circuit_breaker IS 
    'Supports circuit breaker status monitoring and alerting.';

-- ----------------------------------------------------------------------------
-- MENU CONFIGURATION INDEXES
-- ----------------------------------------------------------------------------
-- These indexes support the menu_configurations table.
-- ----------------------------------------------------------------------------

-- Application menu lookup
-- Used by: Menu rendering, navigation
CREATE INDEX IF NOT EXISTS idx_menu_application 
    ON menu_configurations(application_id, is_active, menu_type);

COMMENT ON INDEX idx_menu_application IS 
    'Supports menu lookups by application.';

-- Parent-child navigation
-- Used by: Menu tree traversal
CREATE INDEX IF NOT EXISTS idx_menu_parent 
    ON menu_configurations(parent_menu_id, display_order) 
    WHERE parent_menu_id IS NOT NULL;

COMMENT ON INDEX idx_menu_parent IS 
    'Supports menu hierarchy navigation.';

-- SIM swap risk menu lookup
-- Used by: SIM swap access control for menus
CREATE INDEX IF NOT EXISTS idx_menu_sim_swap_risk 
    ON menu_configurations(sim_swap_risk_level, require_sim_swap_check)
    WHERE require_sim_swap_check = TRUE;

COMMENT ON INDEX idx_menu_sim_swap_risk IS 
    'Supports SIM swap risk-based menu access control.';

-- ----------------------------------------------------------------------------
-- PARTITIONING AND ARCHIVAL SUPPORT
-- ----------------------------------------------------------------------------
-- These indexes and comments support partitioning strategies.
-- ----------------------------------------------------------------------------

-- ============================================================================
-- IMPLEMENTED: Table Partitioning for High-Volume Tables
-- ============================================================================
-- Partitioning strategy for enterprise-scale USSD operations
-- Supports 10M+ sessions/day with efficient data lifecycle management
--
-- Partition maintenance functions created below
-- ============================================================================

-- Function: Create monthly partition for ussd_session_state
CREATE OR REPLACE FUNCTION create_ussd_session_partition(
    p_year INT,
    p_month INT
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_partition_name TEXT;
    v_start_date DATE;
    v_end_date DATE;
BEGIN
    v_partition_name := 'ussd_session_state_' || p_year || '_' || LPAD(p_month::TEXT, 2, '0');
    v_start_date := MAKE_DATE(p_year, p_month, 1);
    v_end_date := v_start_date + INTERVAL '1 month';
    
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF ussd_session_state
         FOR VALUES FROM (%L) TO (%L)
         PARTITION BY LIST (is_active)',
        v_partition_name,
        v_start_date,
        v_end_date
    );
    
    -- Create sub-partitions for active vs finalized
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I_active PARTITION OF %I
         FOR VALUES IN (TRUE)',
        v_partition_name,
        v_partition_name
    );
    
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I_finalized PARTITION OF %I
         FOR VALUES IN (FALSE)',
        v_partition_name,
        v_partition_name
    );
    
    RETURN v_partition_name;
END;
$$;

-- Function: Auto-create next month's partition
CREATE OR REPLACE FUNCTION auto_create_session_partitions()
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_next_month DATE;
    v_year INT;
    v_month INT;
BEGIN
    v_next_month := DATE_TRUNC('month', NOW() + INTERVAL '1 month');
    v_year := EXTRACT(YEAR FROM v_next_month)::INT;
    v_month := EXTRACT(MONTH FROM v_next_month)::INT;
    
    PERFORM create_ussd_session_partition(v_year, v_month);
    
    -- Also create partition for current month if not exists
    PERFORM create_ussd_session_partition(
        EXTRACT(YEAR FROM NOW())::INT,
        EXTRACT(MONTH FROM NOW())::INT
    );
END;
$$;

-- Function: Archive old partitions to cold storage
CREATE OR REPLACE FUNCTION archive_old_partitions(
    p_retention_months INT DEFAULT 3
)
RETURNS TABLE (
    partition_name TEXT,
    rows_archived BIGINT,
    archive_status TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_partition RECORD;
    v_cutoff_date DATE;
    v_row_count BIGINT;
BEGIN
    v_cutoff_date := DATE_TRUNC('month', NOW() - (p_retention_months || ' months')::INTERVAL);
    
    FOR v_partition IN 
        SELECT inhrelid::regclass::TEXT as part_name
        FROM pg_inherits
        WHERE inhparent = 'ussd_session_state'::regclass
        AND inhrelid::regclass::TEXT ~ '^ussd_session_state_\d{4}_\d{2}$'
    LOOP
        -- Extract date from partition name
        IF v_partition.part_name::TEXT < 'ussd_session_state_' || TO_CHAR(v_cutoff_date, 'YYYY_MM') THEN
            -- Get row count
            EXECUTE format('SELECT COUNT(*) FROM %I', v_partition.part_name) INTO v_row_count;
            
            -- Detach and prepare for archival
            EXECUTE format('ALTER TABLE ussd_session_state DETACH PARTITION %I', v_partition.part_name);
            
            partition_name := v_partition.part_name;
            rows_archived := v_row_count;
            archive_status := 'DETACHED_READY_FOR_ARCHIVAL';
            RETURN NEXT;
        END IF;
    END LOOP;
END;
$$;

-- Auto-create partitions on startup if needed
SELECT auto_create_session_partitions();

-- ----------------------------------------------------------------------------
-- INDEX MAINTENANCE FUNCTIONS
-- ----------------------------------------------------------------------------

-- ============================================================================
-- IMPLEMENTED: Index Maintenance Procedures
-- ============================================================================

-- Function: Analyze all USSD tables
CREATE OR REPLACE FUNCTION analyze_ussd_tables()
RETURNS TABLE (
    table_name TEXT,
    rows_analyzed BIGINT,
    analyze_duration_ms INT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_table TEXT;
    v_start_time TIMESTAMPTZ;
    v_row_count BIGINT;
BEGIN
    FOREACH v_table IN ARRAY ARRAY['ussd_session_state', 'device_fingerprints', 
                                    'pending_transactions', 'sim_swap_correlations',
                                    'menu_navigation_history', 'fingerprint_events']
    LOOP
        v_start_time := clock_timestamp();
        
        EXECUTE format('ANALYZE %I', v_table);
        
        EXECUTE format('SELECT COUNT(*) FROM %I', v_table) INTO v_row_count;
        
        table_name := v_table;
        rows_analyzed := v_row_count;
        analyze_duration_ms := EXTRACT(MILLISECONDS FROM (clock_timestamp() - v_start_time))::INT;
        RETURN NEXT;
    END LOOP;
END;
$$;

-- Function: Monitor index bloat
CREATE OR REPLACE FUNCTION get_index_bloat_stats(
    p_bloat_threshold DECIMAL DEFAULT 30.0
)
RETURNS TABLE (
    index_name TEXT,
    table_name TEXT,
    index_size_bytes BIGINT,
    bloat_pct DECIMAL,
    recommendation TEXT
)
LANGUAGE SQL
SECURITY DEFINER
AS $$
    SELECT 
        schemaname || '.' || indexrelname as index_name,
        schemaname || '.' || relname as table_name,
        pg_relation_size(indexrelid) as index_size_bytes,
        ROUND(100 * (pg_relation_size(indexrelid) - (
            SELECT SUM(pg_column_size(t.*)) 
            FROM pg_class c 
            JOIN LATERAL (SELECT * FROM c LIMIT 1000) t ON true
            WHERE c.oid = indrelid
        )::BIGINT / NULLIF(pg_relation_size(indexrelid), 0))::DECIMAL, 2) as bloat_pct,
        CASE 
            WHEN pg_relation_size(indexrelid) > 1073741824 THEN 'REINDEX CONCURRENTLY recommended - Large index'
            WHEN pg_relation_size(indexrelid) > 104857600 THEN 'Monitor - Medium index'
            ELSE 'OK - Small index'
        END as recommendation
    FROM pg_stat_user_indexes
    WHERE schemaname = 'public'
    AND pg_relation_size(indexrelid) > 10485760 -- Only indexes > 10MB
    ORDER BY pg_relation_size(indexrelid) DESC;
$$;

-- Function: Get unused indexes
CREATE OR REPLACE FUNCTION get_unused_indexes(
    p_min_days_old INT DEFAULT 7
)
RETURNS TABLE (
    index_name TEXT,
    table_name TEXT,
    index_size_bytes BIGINT,
    idx_scan BIGINT,
    idx_tup_read BIGINT,
    days_since_creation INT
)
LANGUAGE SQL
SECURITY DEFINER
AS $$
    SELECT 
        schemaname || '.' || indexrelname as index_name,
        schemaname || '.' || relname as table_name,
        pg_relation_size(indexrelid) as index_size_bytes,
        idx_scan,
        idx_tup_read,
        EXTRACT(DAY FROM NOW() - pg_stat_user_indexes.last_vacuum)::INT as days_since_creation
    FROM pg_stat_user_indexes
    JOIN pg_class ON pg_class.oid = indexrelid
    WHERE idx_scan = 0
    AND pg_relation_size(indexrelid) > 0
    AND pg_stat_user_indexes.last_vacuum < NOW() - (p_min_days_old || ' days')::INTERVAL
    ORDER BY pg_relation_size(indexrelid) DESC;
$$;

-- Function: Run index maintenance
CREATE OR REPLACE FUNCTION run_index_maintenance(
    p_reindex_bloat_threshold DECIMAL DEFAULT 30.0,
    p_dry_run BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (
    action TEXT,
    index_name TEXT,
    status TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_index RECORD;
BEGIN
    -- Reindex bloated indexes
    FOR v_index IN 
        SELECT * FROM get_index_bloat_stats(p_reindex_bloat_threshold)
        WHERE bloat_pct > p_reindex_bloat_threshold
    LOOP
        action := 'REINDEX';
        index_name := v_index.index_name;
        
        IF p_dry_run THEN
            status := 'WOULD_REINDEX (dry run)';
        ELSE
            BEGIN
                EXECUTE format('REINDEX INDEX CONCURRENTLY %I', split_part(v_index.index_name, '.', 2));
                status := 'REINDEXED';
            EXCEPTION WHEN OTHERS THEN
                status := 'FAILED: ' || SQLERRM;
            END;
        END IF;
        RETURN NEXT;
    END LOOP;
    
    -- Run ANALYZE on all tables
    action := 'ANALYZE';
    index_name := 'all_ussd_tables';
    
    IF p_dry_run THEN
        status := 'WOULD_ANALYZE (dry run)';
    ELSE
        PERFORM analyze_ussd_tables();
        status := 'ANALYZED';
    END IF;
    RETURN NEXT;
END;
$$;

-- ----------------------------------------------------------------------------
-- PERFORMANCE CONSIDERATIONS
-- ----------------------------------------------------------------------------

/*
1. WRITE OVERHEAD:
   - Each index adds overhead to INSERT/UPDATE
   - Balance read optimization with write performance
   - Consider dropping unused indexes
   - Use partial indexes where possible

2. INDEX SIZE:
   - Monitor index sizes regularly
   - Partial indexes reduce size for conditional queries
   - Consider BRIN indexes for time-series data
   - Compress indexes if supported

3. HOT UPDATES:
   - Design indexes to allow HOT updates
   - Avoid indexes on frequently updated columns
   - Include columns in indexes to avoid table lookups

4. CONCURRENT INDEXING:
   - Use CREATE INDEX CONCURRENTLY in production
   - Avoid locking tables during index creation
   - Schedule during maintenance windows

5. COVERING INDEXES:
   - Use INCLUDE clause for covering indexes
   - Reduces table lookups for common queries
   - Example: idx_session_msisdn_active INCLUDE (application_id, current_menu_id)
*/

-- ----------------------------------------------------------------------------
-- SECURITY INDEX CONSIDERATIONS
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.1 - Index security for access control
-- [ISO/IEC 27018:2019] Index privacy (timing attack awareness)
-- [GDPR] Secure index cleanup on data deletion
-- Audit index access patterns for anomaly detection
-- Encrypt sensitive indexed values where feasible

/*
1. INDEX PRIVACY:
   - Indexes may leak information via timing attacks
   - Be cautious with indexes on sensitive columns
   - Consider encrypting indexed values

2. AUDIT INDEX ACCESS:
   - Monitor index usage patterns
   - Detect unusual access (potential enumeration)
   - Log index-based queries for sensitive data

3. INDEX CLEANUP:
   - Securely clear index data on deletion
   - VACUUM after sensitive data removal
   - Consider index encryption
*/

-- ----------------------------------------------------------------------------
-- EXAMPLE USAGE AND QUERY PATTERNS
-- ----------------------------------------------------------------------------

/*
-- Example 1: Find active session by MSISDN
-- Uses: idx_session_msisdn_active
SELECT * FROM ussd_session_state
WHERE msisdn = '+255712345678'
AND is_active = TRUE;

-- Example 2: Find expired sessions for cleanup
-- Uses: idx_session_expires_active
SELECT * FROM ussd_session_state
WHERE is_active = TRUE
AND expires_at < NOW()
LIMIT 1000;

-- Example 3: Get session navigation history
-- Uses: idx_nav_history_session
SELECT * FROM menu_navigation_history
WHERE session_id = '550e8400-e29b-41d4-a716-446655440000'
ORDER BY navigation_at DESC;

-- Example 4: Find recent SIM swaps for MSISDN
-- Uses: idx_swap_msisdn
SELECT * FROM sim_swap_correlations
WHERE msisdn = '+255712345678'
AND sim_swap_detected_at > NOW() - INTERVAL '72 hours';

-- Example 5: Get active transactions for cleanup
-- Uses: idx_tx_status_time
SELECT * FROM pending_transactions
WHERE status IN ('PENDING', 'PROCESSING')
AND expires_at < NOW();

-- Example 6: Check for recent SIM swap sessions
-- Uses: idx_session_sim_swap
SELECT * FROM ussd_session_state s
JOIN sim_swap_correlations sw ON s.msisdn = sw.msisdn
WHERE sw.sim_swap_detected_at > NOW() - INTERVAL '72 hours'
AND s.created_at > sw.sim_swap_detected_at;
*/
