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

-- ----------------------------------------------------------------------------
-- PARTITIONING AND ARCHIVAL SUPPORT
-- ----------------------------------------------------------------------------
-- These indexes and comments support partitioning strategies.
-- ----------------------------------------------------------------------------

/*
TODO [PARTITION-001]: Implement table partitioning for high-volume tables

For ussd_session_state:
  - Partition by range on created_at (monthly)
  - Active sessions in current partition
  - Automated partition creation
  - Archive old partitions to cold storage

For pending_transactions:
  - Partition by range on created_at (weekly)
  - Separate partition for completed transactions
  - Fast drop of old completed transaction partitions

For fingerprint_events:
  - Partition by range on event_date (monthly)
  - Automated partition dropping after retention period

For menu_navigation_history:
  - Partition by range on navigation_at (monthly)
  - Compress old partitions

Example partition creation:
  CREATE TABLE ussd_session_state_2024_01 PARTITION OF ussd_session_state
  FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
*/

-- ----------------------------------------------------------------------------
-- TODO: INDEX MAINTENANCE
-- ----------------------------------------------------------------------------

/*
TODO [MAINT-001]: Implement index maintenance procedures

1. Regular ANALYZE:
   - Run ANALYZE on all tables after bulk operations
   - Update statistics for query planner
   - Schedule during low-traffic periods

2. Index bloat monitoring:
   - Monitor index bloat percentage
   - Reindex when bloat > 30%
   - Use CONCURRENTLY option to avoid locks

3. Unused index detection:
   - Query pg_stat_user_indexes for unused indexes
   - Evaluate and drop truly unused indexes
   - Document reason for each index

4. Index size monitoring:
   - Alert on indexes > 1GB
   - Consider partial indexes for large tables
   - Evaluate covering indexes for common queries

Maintenance script outline:
  - SELECT pg_size_pretty(pg_relation_size(indexrelid)) FROM pg_stat_user_indexes
  - REINDEX INDEX CONCURRENTLY idx_name;
  - ANALYZE table_name;
*/

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
*/
