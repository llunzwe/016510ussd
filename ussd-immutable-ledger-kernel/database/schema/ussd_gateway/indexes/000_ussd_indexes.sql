-- ============================================================================
-- USSD Gateway - Performance Indexes
-- High-volume USSD optimized indexes for fast lookups
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Sessions Table Indexes
-- ----------------------------------------------------------------------------

-- Primary session lookup by external session ID
CREATE INDEX IF NOT EXISTS idx_sessions_session_id 
ON ussd.sessions (session_id);

-- Active session queries (most critical for performance)
CREATE INDEX IF NOT EXISTS idx_sessions_active_expires 
ON ussd.sessions (is_active, expires_at) 
WHERE is_active = TRUE;

-- MSISDN hash lookups (for user-specific queries without decrypting)
CREATE INDEX IF NOT EXISTS idx_sessions_msisdn_hash 
ON ussd.sessions (msisdn_hash) 
WHERE is_active = TRUE;

-- State-based queries for session management
CREATE INDEX IF NOT EXISTS idx_sessions_state_active 
ON ussd.sessions (state, is_active, created_at);

-- Menu path navigation (LTREE indexing)
CREATE INDEX IF NOT EXISTS idx_sessions_menu_path 
ON ussd.sessions USING GIST (menu_path);

-- Time-based queries for cleanup and reporting
CREATE INDEX IF NOT EXISTS idx_sessions_created_at 
ON ussd.sessions (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_sessions_closed_at 
ON ussd.sessions (closed_at) 
WHERE closed_at IS NOT NULL;

-- Composite index for session lookup with transaction
CREATE INDEX IF NOT EXISTS idx_sessions_transaction 
ON ussd.sessions (transaction_id, is_active) 
WHERE transaction_id IS NOT NULL;

-- Network operator analytics
CREATE INDEX IF NOT EXISTS idx_sessions_operator_created 
ON ussd.sessions (network_operator, created_at DESC);

-- ----------------------------------------------------------------------------
-- Transactions Table Indexes
-- ----------------------------------------------------------------------------

-- Session-transaction relationship
CREATE INDEX IF NOT EXISTS idx_transactions_session_id 
ON ussd.transactions (session_id);

-- Status-based queries for queue processing
CREATE INDEX IF NOT EXISTS idx_transactions_status_created 
ON ussd.transactions (status, created_at) 
WHERE status IN ('PENDING', 'PENDING_AUTH');

-- Transaction expiry for cleanup
CREATE INDEX IF NOT EXISTS idx_transactions_expires_status 
ON ussd.transactions (expires_at, status) 
WHERE status IN ('PENDING', 'PENDING_AUTH');

-- Ledger reference (immutable link)
CREATE INDEX IF NOT EXISTS idx_transactions_ledger_entry 
ON ussd.transactions (ledger_entry_id) 
WHERE ledger_entry_id IS NOT NULL;

-- Transaction type analytics
CREATE INDEX IF NOT EXISTS idx_transactions_type_date 
ON ussd.transactions (transaction_type, created_at DESC);

-- Risk score queries for fraud analysis
CREATE INDEX IF NOT EXISTS idx_transactions_risk_score 
ON ussd.transactions (risk_score DESC, created_at) 
WHERE risk_score > 30;

-- Status and completion time for reporting
CREATE INDEX IF NOT EXISTS idx_transactions_status_completed 
ON ussd.transactions (status, completed_at) 
WHERE status = 'COMPLETED';

-- Composite index for transaction queue view
CREATE INDEX IF NOT EXISTS idx_transactions_queue_priority 
ON ussd.transactions (expires_at, status, created_at) 
WHERE status IN ('PENDING', 'PENDING_AUTH');

-- ----------------------------------------------------------------------------
-- User Profiles Table Indexes
-- ----------------------------------------------------------------------------

-- MSISDN hash unique lookup
CREATE INDEX IF NOT EXISTS idx_profiles_msisdn_hash 
ON ussd.user_profiles (msisdn_hash);

-- PIN attempt tracking for fraud detection
CREATE INDEX IF NOT EXISTS idx_profiles_pin_attempts 
ON ussd.user_profiles (pin_attempts, last_pin_attempt_at) 
WHERE pin_attempts > 0;

-- ----------------------------------------------------------------------------
-- Menus Table Indexes (LTREE Navigation)
-- ----------------------------------------------------------------------------

-- LTREE path lookup (primary navigation)
CREATE INDEX IF NOT EXISTS idx_menus_full_path 
ON ussd.menus USING GIST (full_path);

-- Parent-child relationship
CREATE INDEX IF NOT EXISTS idx_menus_parent_path 
ON ussd.menus USING GIST (parent_path);

-- Active menu lookup
CREATE INDEX IF NOT EXISTS idx_menus_active_code 
ON ussd.menus (menu_code, is_active) 
WHERE is_active = TRUE;

-- Sort order within parent
CREATE INDEX IF NOT EXISTS idx_menus_parent_sort 
ON ussd.menus (parent_path, sort_order, is_active) 
WHERE is_active = TRUE;

-- Menu type filtering
CREATE INDEX IF NOT EXISTS idx_menus_type_active 
ON ussd.menus (menu_type, is_active);

-- ----------------------------------------------------------------------------
-- Audit Logs Table Indexes
-- ----------------------------------------------------------------------------

-- Session audit trail
CREATE INDEX IF NOT EXISTS idx_audit_session_id 
ON ussd.audit_logs (session_id, created_at DESC);

-- Action type queries
CREATE INDEX IF NOT EXISTS idx_audit_action_date 
ON ussd.audit_logs (action, created_at DESC);

-- MSISDN hash audit lookup
CREATE INDEX IF NOT EXISTS idx_audit_msisdn_hash 
ON ussd.audit_logs (msisdn_hash, created_at DESC);

-- ----------------------------------------------------------------------------
-- Session Audit Logs Table Indexes
-- ----------------------------------------------------------------------------

-- Session audit trail
CREATE INDEX IF NOT EXISTS idx_session_audit_session_id 
ON ussd.session_audit_logs (session_id, performed_at DESC);

-- Operation type filtering
CREATE INDEX IF NOT EXISTS idx_session_audit_operation 
ON ussd.session_audit_logs (operation, performed_at DESC);

-- ----------------------------------------------------------------------------
-- OTP Records Table Indexes
-- ----------------------------------------------------------------------------

-- Transaction OTP lookup
CREATE INDEX IF NOT EXISTS idx_otp_transaction_id 
ON ussd.otp_records (transaction_id, created_at DESC);

-- Active OTP queries
CREATE INDEX IF NOT EXISTS idx_otp_active 
ON ussd.otp_records (verified, expires_at) 
WHERE verified = FALSE;

-- Reference code lookup
CREATE INDEX IF NOT EXISTS idx_otp_reference 
ON ussd.otp_records (reference);

-- ----------------------------------------------------------------------------
-- Ledger Entries Table Indexes
-- ----------------------------------------------------------------------------

-- Transaction link (immutable)
CREATE INDEX IF NOT EXISTS idx_ledger_transaction 
ON ussd.ledger_entries (transaction_id);

-- Entry type queries
CREATE INDEX IF NOT EXISTS idx_ledger_type_date 
ON ussd.ledger_entries (entry_type, created_at DESC);

-- Status queries
CREATE INDEX IF NOT EXISTS idx_ledger_status 
ON ussd.ledger_entries (status, created_at) 
WHERE status = 'COMMITTED';

-- ----------------------------------------------------------------------------
-- Security Events Table Indexes
-- ----------------------------------------------------------------------------

-- Severity-based queries for alerting
CREATE INDEX IF NOT EXISTS idx_security_severity_date 
ON ussd.security_events (severity, created_at DESC);

-- Event type analytics
CREATE INDEX IF NOT EXISTS idx_security_event_type 
ON ussd.security_events (event_type, created_at DESC);

-- MSISDN hash security lookup
CREATE INDEX IF NOT EXISTS idx_security_msisdn_hash 
ON ussd.security_events (msisdn_hash, created_at DESC);

-- ----------------------------------------------------------------------------
-- Fraud Checks Table Indexes
-- ----------------------------------------------------------------------------

-- Risk level queries
CREATE INDEX IF NOT EXISTS idx_fraud_risk_level 
ON ussd.fraud_checks (risk_level, created_at DESC);

-- Risk score analytics
CREATE INDEX IF NOT EXISTS idx_fraud_risk_score 
ON ussd.fraud_checks (risk_score DESC, created_at);

-- Session fraud lookup
CREATE INDEX IF NOT EXISTS idx_fraud_session_id 
ON ussd.fraud_checks (session_id, created_at DESC);

-- ----------------------------------------------------------------------------
-- Blocked Devices Table Indexes
-- ----------------------------------------------------------------------------

-- Active blocks lookup (critical for performance)
CREATE INDEX IF NOT EXISTS idx_blocked_active_msisdn 
ON ussd.blocked_devices (msisdn_hash, is_active, expires_at) 
WHERE is_active = TRUE;

-- IMEI hash lookup
CREATE INDEX IF NOT EXISTS idx_blocked_imei_hash 
ON ussd.blocked_devices (imei_hash, is_active) 
WHERE is_active = TRUE;

-- ----------------------------------------------------------------------------
-- Maintenance Logs Table Indexes
-- ----------------------------------------------------------------------------

-- Operation type queries
CREATE INDEX IF NOT EXISTS idx_maintenance_operation 
ON ussd.maintenance_logs (operation, created_at DESC);

-- Table name queries
CREATE INDEX IF NOT EXISTS idx_maintenance_table 
ON ussd.maintenance_logs (table_name, created_at DESC);

-- ----------------------------------------------------------------------------
-- Partial Indexes for High-Performance Lookups
-- ----------------------------------------------------------------------------

-- Active sessions only (most common query pattern)
CREATE INDEX IF NOT EXISTS idx_sessions_active_only 
ON ussd.sessions (session_id, msisdn_hash, state) 
WHERE is_active = TRUE;

-- Pending transactions (queue processing)
CREATE INDEX IF NOT EXISTS idx_transactions_pending_only 
ON ussd.transactions (id, session_id, requires_pin, requires_otp) 
WHERE status IN ('PENDING', 'PENDING_AUTH');

-- Critical security events (alerting)
CREATE INDEX IF NOT EXISTS idx_security_critical 
ON ussd.security_events (id, event_type, msisdn_hash) 
WHERE severity IN ('CRITICAL', 'HIGH');

-- ----------------------------------------------------------------------------
-- BRIN Indexes for Time-Series Data
-- ----------------------------------------------------------------------------

-- For very large audit log tables, BRIN indexes are more efficient
CREATE INDEX IF NOT EXISTS idx_audit_logs_brin 
ON ussd.audit_logs USING BRIN (created_at) 
WITH (pages_per_range = 128);

CREATE INDEX IF NOT EXISTS idx_session_audit_brin 
ON ussd.session_audit_logs USING BRIN (performed_at) 
WITH (pages_per_range = 128);

CREATE INDEX IF NOT EXISTS idx_security_events_brin 
ON ussd.security_events USING BRIN (created_at) 
WITH (pages_per_range = 128);

-- ----------------------------------------------------------------------------
-- GIN Indexes for JSONB Data
-- ----------------------------------------------------------------------------

-- Session data search
CREATE INDEX IF NOT EXISTS idx_sessions_data_gin 
ON ussd.sessions USING GIN (session_data jsonb_path_ops);

-- Transaction metadata search
CREATE INDEX IF NOT EXISTS idx_transactions_metadata_gin 
ON ussd.transactions USING GIN (metadata jsonb_path_ops);

-- Audit log details search
CREATE INDEX IF NOT EXISTS idx_audit_details_gin 
ON ussd.audit_logs USING GIN (details jsonb_path_ops);

-- Fraud check rules triggered
CREATE INDEX IF NOT EXISTS idx_fraud_rules_gin 
ON ussd.fraud_checks USING GIN (triggered_rules jsonb_path_ops);

-- ----------------------------------------------------------------------------
-- Statistics Update
-- ----------------------------------------------------------------------------

-- Update statistics for query planner
ANALYZE ussd.sessions;
ANALYZE ussd.transactions;
ANALYZE ussd.user_profiles;
ANALYZE ussd.menus;
ANALYZE ussd.audit_logs;
