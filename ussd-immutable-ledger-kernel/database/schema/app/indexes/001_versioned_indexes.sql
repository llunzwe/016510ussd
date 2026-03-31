/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - INDEXES: VERSIONED TABLES
 * =============================================================================
 * 
 * Feature:      CORE-APP-IDX-003
 * Description:  Specialized indexes for versioned records, audit trails,
 *               AI governance tables, and temporal queries. Optimized
 *               for immutable ledger integration and compliance reporting.
 * 
 * Version:      1.0.0
 * Author:       Platform Engineering Team
 * Created:      2026-03-30
 * Last Modified: 2026-03-30
 * 
 * =============================================================================
 * COMPLIANCE & CERTIFICATIONS
 * =============================================================================
 * 
 * EU AI Act (Regulation 2024/1689)
 *   - Article 12: Record-keeping performance
 * 
 * ISO/IEC 27001:2022 (ISMS)
 *   - Control A.8.15: Audit log performance
 *   - Control A.12.4: Logging and monitoring
 * 
 * GDPR (General Data Protection Regulation)
 *   - Article 30: Records of processing query performance
 * 
 * SOC 2 Type II
 *   - CC7.2: System monitoring performance
 * 
 * =============================================================================
 * INDEXING STRATEGY FOR VERSIONED TABLES
 * =============================================================================
 * 
 * TEMPORAL INDEXES:
 *   - created_at, updated_at for time-series queries
 *   - BRIN indexes for append-only tables
 *   - Partition key indexes for partitioned tables
 * 
 * LEDGER INTEGRATION:
 *   - ledger_sequence for chain verification
 *   - ledger_hash for integrity checks
 *   - previous_hash for chain linking
 * 
 * AI GOVERNANCE:
 *   - Model lookups by name/version
 *   - Inference request tracking
 *   - PII detection queries
 * 
 * FULL-TEXT SEARCH:
 *   - GIN indexes for text search
 *   - Trigram indexes for fuzzy matching
 * =============================================================================
 */

-- =============================================================================
-- COMPLIANCE STANDARDS
-- =============================================================================
-- EU AI Act - Record-keeping
-- ISO/IEC 27001:2022 - ISMS Framework
-- GDPR - Data Protection
-- SOC 2 Type II - Security Controls
-- =============================================================================

-- =============================================================================
-- TABLE: core.t_audit_trail (if in app schema context)
-- =============================================================================

-- Primary time-series index (most important)
CREATE INDEX IF NOT EXISTS idx_audit_performed_at 
    ON core.t_audit_trail(performed_at DESC);

-- Composite: Table + Time (audit queries by entity)
CREATE INDEX IF NOT EXISTS idx_audit_table_time 
    ON core.t_audit_trail(table_name, performed_at DESC);

-- Record lookup (all changes to specific record)
CREATE INDEX IF NOT EXISTS idx_audit_record 
    ON core.t_audit_trail(record_id, performed_at DESC);

-- App-scoped queries
CREATE INDEX IF NOT EXISTS idx_audit_app 
    ON core.t_audit_trail(app_id, performed_at DESC) 
    WHERE app_id IS NOT NULL;

-- Action type filtering
CREATE INDEX IF NOT EXISTS idx_audit_action 
    ON core.t_audit_trail(action, performed_at DESC);

-- Severity filtering (security events)
CREATE INDEX IF NOT EXISTS idx_audit_severity 
    ON core.t_audit_trail(severity, performed_at DESC) 
    WHERE severity IN ('critical', 'high');

-- Actor tracking (who did what)
CREATE INDEX IF NOT EXISTS idx_audit_actor 
    ON core.t_audit_trail(performed_by, performed_at DESC);

-- Correlation ID (distributed tracing)
CREATE INDEX IF NOT EXISTS idx_audit_correlation 
    ON core.t_audit_trail(correlation_id) 
    WHERE correlation_id IS NOT NULL;

-- Ledger sequence (immutability chain)
CREATE INDEX IF NOT EXISTS idx_audit_ledger_seq 
    ON core.t_audit_trail(ledger_sequence) 
    WHERE ledger_sequence IS NOT NULL;

-- Ledger hash verification
CREATE INDEX IF NOT EXISTS idx_audit_ledger_hash 
    ON core.t_audit_trail(ledger_hash) 
    WHERE ledger_hash IS NOT NULL;

-- Result filtering (denied actions)
CREATE INDEX IF NOT EXISTS idx_audit_result 
    ON core.t_audit_trail(result, performed_at DESC) 
    WHERE result = 'denied';

-- Retention management
CREATE INDEX IF NOT EXISTS idx_audit_retention 
    ON core.t_audit_trail(retention_until) 
    WHERE retention_until IS NOT NULL;

-- BRIN index for time-series optimization (large tables)
CREATE INDEX IF NOT EXISTS idx_audit_time_brin 
    ON core.t_audit_trail USING BRIN (performed_at);

-- GIN index for details JSONB
CREATE INDEX IF NOT EXISTS idx_audit_details 
    ON core.t_audit_trail USING GIN (details) 
    WHERE details IS NOT NULL;

-- GIN index for compliance frameworks array
CREATE INDEX IF NOT EXISTS idx_audit_compliance 
    ON core.t_audit_trail USING GIN (compliance_frameworks);

-- =============================================================================
-- TABLE: app.model_registry
-- =============================================================================

-- Model name lookup (case-insensitive)
CREATE INDEX IF NOT EXISTS idx_model_name_lower 
    ON app.model_registry USING btree (lower(name));

-- Name + Version unique constraint support
CREATE INDEX IF NOT EXISTS idx_model_name_version 
    ON app.model_registry(name, version);

-- Active production models
CREATE INDEX IF NOT EXISTS idx_model_active 
    ON app.model_registry(deployment_status) 
    WHERE deployment_status = 'production' AND deleted_at IS NULL;

-- Risk level filtering (compliance queries)
CREATE INDEX IF NOT EXISTS idx_model_risk 
    ON app.model_registry(risk_level, deployment_status) 
    WHERE deleted_at IS NULL;

-- High-risk models requiring oversight
CREATE INDEX IF NOT EXISTS idx_model_high_risk 
    ON app.model_registry(id) 
    WHERE risk_level = 'high' AND deleted_at IS NULL;

-- Approval status
CREATE INDEX IF NOT EXISTS idx_model_approved 
    ON app.model_registry(approved_by) 
    WHERE approved_by IS NOT NULL AND deleted_at IS NULL;

-- Framework and type filtering
CREATE INDEX IF NOT EXISTS idx_model_framework_type 
    ON app.model_registry(framework, type) 
    WHERE deleted_at IS NULL;

-- Bias audit tracking
CREATE INDEX IF NOT EXISTS idx_model_bias_audit 
    ON app.model_registry(bias_audit_completed) 
    WHERE bias_audit_completed = FALSE AND deleted_at IS NULL;

-- GIN index for metadata JSONB
CREATE INDEX IF NOT EXISTS idx_model_metadata 
    ON app.model_registry USING GIN (metadata jsonb_path_ops) 
    WHERE deleted_at IS NULL;

-- GIN index for performance metrics
CREATE INDEX IF NOT EXISTS idx_model_performance 
    ON app.model_registry USING GIN (performance_metrics jsonb_path_ops);

-- GIN index for training data provenance
CREATE INDEX IF NOT EXISTS idx_model_provenance 
    ON app.model_registry USING GIN (training_data_provenance jsonb_path_ops);

-- GIN index for compliance frameworks array
CREATE INDEX IF NOT EXISTS idx_model_compliance 
    ON app.model_registry USING GIN (compliance_frameworks);

-- Ledger verification
CREATE INDEX IF NOT EXISTS idx_model_ledger 
    ON app.model_registry(ledger_sequence) 
    WHERE ledger_sequence IS NOT NULL;

-- Soft delete filtering
CREATE INDEX IF NOT EXISTS idx_model_not_deleted 
    ON app.model_registry(created_at DESC) 
    WHERE deleted_at IS NULL;

-- Timeline queries for audit
CREATE INDEX IF NOT EXISTS idx_model_timeline 
    ON app.model_registry(created_at DESC, updated_at DESC) 
    WHERE deleted_at IS NULL;

-- =============================================================================
-- TABLE: app.inference_log
-- =============================================================================

-- Partition key index (required for partitioned tables)
CREATE INDEX IF NOT EXISTS idx_inference_partition 
    ON app.inference_log(partition_date DESC);

-- Primary query: Request ID
CREATE INDEX IF NOT EXISTS idx_inference_request 
    ON app.inference_log(request_id);

-- Model performance analysis
CREATE INDEX IF NOT EXISTS idx_inference_model_time 
    ON app.inference_log(model_id, request_timestamp DESC);

-- Model + Status composite
CREATE INDEX IF NOT EXISTS idx_inference_model_status 
    ON app.inference_log(model_id, status) 
    WHERE status != 'success';

-- Latency analysis
CREATE INDEX IF NOT EXISTS idx_inference_latency 
    ON app.inference_log(latency_ms) 
    WHERE status = 'success';

-- Error investigation
CREATE INDEX IF NOT EXISTS idx_inference_errors 
    ON app.inference_log(error_code, status) 
    WHERE status != 'success';

-- User activity audit
CREATE INDEX IF NOT EXISTS idx_inference_user 
    ON app.inference_log(user_id, request_timestamp DESC);

-- Correlation ID (distributed tracing)
CREATE INDEX IF NOT EXISTS idx_inference_correlation 
    ON app.inference_log USING HASH (correlation_id) 
    WHERE correlation_id IS NOT NULL;

-- PII detection queries
CREATE INDEX IF NOT EXISTS idx_inference_pii 
    ON app.inference_log(contains_pii, created_at) 
    WHERE contains_pii = TRUE;

-- Data classification
CREATE INDEX IF NOT EXISTS idx_inference_classification 
    ON app.inference_log(data_classification, created_at);

-- Ledger verification
CREATE INDEX IF NOT EXISTS idx_inference_ledger 
    ON app.inference_log(ledger_sequence) 
    WHERE ledger_sequence IS NOT NULL;

-- Previous hash chain verification
CREATE INDEX IF NOT EXISTS idx_inference_prev_hash 
    ON app.inference_log(previous_hash) 
    WHERE previous_hash IS NOT NULL;

-- Timestamp queries (partitioned)
CREATE INDEX IF NOT EXISTS idx_inference_timestamp 
    ON app.inference_log(request_timestamp DESC);

-- Confidence score analysis
CREATE INDEX IF NOT EXISTS idx_inference_confidence 
    ON app.inference_log(confidence_score) 
    WHERE status = 'success';

-- Low confidence detections
CREATE INDEX IF NOT EXISTS idx_inference_low_confidence 
    ON app.inference_log(model_id, confidence_score) 
    WHERE confidence_score < 0.5 AND status = 'success';

-- Cost analysis
CREATE INDEX IF NOT EXISTS idx_inference_cost 
    ON app.inference_log(billing_tag, created_at) 
    WHERE cost_estimate_usd IS NOT NULL;

-- Token usage
CREATE INDEX IF NOT EXISTS idx_inference_tokens 
    ON app.inference_log(tokens_input, tokens_output) 
    WHERE tokens_input IS NOT NULL;

-- Inference type filtering
CREATE INDEX IF NOT EXISTS idx_inference_type 
    ON app.inference_log(inference_type, created_at);

-- Retention management
CREATE INDEX IF NOT EXISTS idx_inference_retention 
    ON app.inference_log(retention_until) 
    WHERE retention_until IS NOT NULL;

-- Legal hold
CREATE INDEX IF NOT EXISTS idx_inference_legal_hold 
    ON app.inference_log(id) 
    WHERE legal_hold = TRUE;

-- Session tracking
CREATE INDEX IF NOT EXISTS idx_inference_session 
    ON app.inference_log(session_id, created_at) 
    WHERE session_id IS NOT NULL;

-- BRIN index for large time-series optimization
CREATE INDEX IF NOT EXISTS idx_inference_time_brin 
    ON app.inference_log USING BRIN (request_timestamp);

-- GIN index for input data (PII scanning)
CREATE INDEX IF NOT EXISTS idx_inference_input 
    ON app.inference_log USING GIN (input_data jsonb_path_ops);

-- GIN index for output data
CREATE INDEX IF NOT EXISTS idx_inference_output 
    ON app.inference_log USING GIN (output_data jsonb_path_ops);

-- GIN index for PII types array
CREATE INDEX IF NOT EXISTS idx_inference_pii_types 
    ON app.inference_log USING GIN (pii_types_detected);

-- GIN index for compliance frameworks
CREATE INDEX IF NOT EXISTS idx_inference_compliance 
    ON app.inference_log USING GIN (compliance_frameworks);

-- =============================================================================
-- TABLE: app.tool_catalog
-- =============================================================================

-- Tool name lookup
CREATE INDEX IF NOT EXISTS idx_tool_name_lower 
    ON app.tool_catalog USING btree (lower(name));

-- Active production tools
CREATE INDEX IF NOT EXISTS idx_tool_active 
    ON app.tool_catalog(name) 
    WHERE status = 'production' AND deleted_at IS NULL;

-- Category filtering
CREATE INDEX IF NOT EXISTS idx_tool_category 
    ON app.tool_catalog(category, status) 
    WHERE deleted_at IS NULL;

-- Permission-based filtering
CREATE INDEX IF NOT EXISTS idx_tool_permissions 
    ON app.tool_catalog USING GIN (required_permissions) 
    WHERE deleted_at IS NULL;

-- Data access level queries
CREATE INDEX IF NOT EXISTS idx_tool_data_access 
    ON app.tool_catalog(data_access_level, sensitive_data_access) 
    WHERE deleted_at IS NULL;

-- Owner/maintainer queries
CREATE INDEX IF NOT EXISTS idx_tool_maintainer 
    ON app.tool_catalog(maintained_by, status) 
    WHERE deleted_at IS NULL;

-- GIN index for execution config
CREATE INDEX IF NOT EXISTS idx_tool_exec_config 
    ON app.tool_catalog USING GIN (execution_config jsonb_path_ops);

-- GIN index for input schema
CREATE INDEX IF NOT EXISTS idx_tool_input_schema 
    ON app.tool_catalog USING GIN (input_schema jsonb_path_ops);

-- GIN index for security config
CREATE INDEX IF NOT EXISTS idx_tool_security_config 
    ON app.tool_catalog USING GIN (security_config jsonb_path_ops);

-- Version chain
CREATE INDEX IF NOT EXISTS idx_tool_version_chain 
    ON app.tool_catalog(previous_version_id) 
    WHERE previous_version_id IS NOT NULL;

-- Ledger integration
CREATE INDEX IF NOT EXISTS idx_tool_ledger 
    ON app.tool_catalog(ledger_sequence) 
    WHERE ledger_sequence IS NOT NULL;

-- Soft delete
CREATE INDEX IF NOT EXISTS idx_tool_not_deleted 
    ON app.tool_catalog(created_at DESC) 
    WHERE deleted_at IS NULL;

-- =============================================================================
-- TABLE: app.agent_sessions
-- =============================================================================

-- Session ID lookup
CREATE INDEX IF NOT EXISTS idx_session_session_id 
    ON app.agent_sessions(session_id);

-- User session listing
CREATE INDEX IF NOT EXISTS idx_session_user 
    ON app.agent_sessions(user_id, status, last_activity_at DESC);

-- Active sessions
CREATE INDEX IF NOT EXISTS idx_session_active 
    ON app.agent_sessions(status, last_activity_at) 
    WHERE status IN ('active', 'processing', 'waiting_input') AND deleted_at IS NULL;

-- Expiration tracking (cleanup jobs)
CREATE INDEX IF NOT EXISTS idx_session_expires 
    ON app.agent_sessions(expires_at) 
    WHERE expires_at IS NOT NULL AND deleted_at IS NULL;

-- Agent type filtering
CREATE INDEX IF NOT EXISTS idx_session_agent_type 
    ON app.agent_sessions(agent_type, status) 
    WHERE deleted_at IS NULL;

-- Model usage tracking
CREATE INDEX IF NOT EXISTS idx_session_model 
    ON app.agent_sessions(model_id, created_at DESC) 
    WHERE model_id IS NOT NULL AND deleted_at IS NULL;

-- Organization queries
CREATE INDEX IF NOT EXISTS idx_session_org 
    ON app.agent_sessions(organization_id, created_at DESC) 
    WHERE organization_id IS NOT NULL AND deleted_at IS NULL;

-- Security level filtering
CREATE INDEX IF NOT EXISTS idx_session_security 
    ON app.agent_sessions(security_level, status) 
    WHERE deleted_at IS NULL;

-- PII detection
CREATE INDEX IF NOT EXISTS idx_session_pii 
    ON app.agent_sessions(contains_pii, created_at) 
    WHERE contains_pii = TRUE AND deleted_at IS NULL;

-- Ledger verification
CREATE INDEX IF NOT EXISTS idx_session_ledger 
    ON app.agent_sessions(ledger_sequence) 
    WHERE ledger_sequence IS NOT NULL;

-- Activity tracking
CREATE INDEX IF NOT EXISTS idx_session_activity 
    ON app.agent_sessions(last_activity_at DESC) 
    WHERE status != 'expired' AND deleted_at IS NULL;

-- Resume token
CREATE INDEX IF NOT EXISTS idx_session_resume 
    ON app.agent_sessions(resume_token_hash) 
    WHERE resume_token_hash IS NOT NULL AND deleted_at IS NULL;

-- GIN index for session data
CREATE INDEX IF NOT EXISTS idx_session_data 
    ON app.agent_sessions USING GIN (session_data jsonb_path_ops);

-- GIN index for tool execution state
CREATE INDEX IF NOT EXISTS idx_session_tool_state 
    ON app.agent_sessions USING GIN (tool_execution_state jsonb_path_ops);

-- GIN index for available tools array
CREATE INDEX IF NOT EXISTS idx_session_tools 
    ON app.agent_sessions USING GIN (available_tools);

-- =============================================================================
-- TEMPORAL INDEXES (for time-travel queries)
-- =============================================================================

-- Effective period queries for configuration
CREATE INDEX IF NOT EXISTS idx_config_effective_period 
    ON app.t_configuration_store(effective_from, effective_until) 
    WHERE is_current = TRUE;

-- Version number sequence
CREATE INDEX IF NOT EXISTS idx_config_version 
    ON app.t_configuration_store(config_key, version_number DESC) 
    WHERE is_current = FALSE;

-- =============================================================================
-- HASH INDEXES (for equality lookups)
-- =============================================================================

-- Hash indexes for UUID lookups where range queries not needed
CREATE INDEX IF NOT EXISTS idx_inference_hash_user 
    ON app.inference_log USING HASH (user_id);

CREATE INDEX IF NOT EXISTS idx_inference_hash_model 
    ON app.inference_log USING HASH (model_id);

-- =============================================================================
-- PARTIAL INDEXES (for common filtered queries)
-- =============================================================================

-- Recent audit events only
CREATE INDEX IF NOT EXISTS idx_audit_recent 
    ON core.t_audit_trail(performed_at DESC) 
    WHERE performed_at > NOW() - INTERVAL '7 days';

-- Failed operations
CREATE INDEX IF NOT EXISTS idx_audit_failures 
    ON core.t_audit_trail(performed_at DESC) 
    WHERE result = 'denied' OR result = 'failure';

-- High severity security events
CREATE INDEX IF NOT EXISTS idx_audit_security 
    ON core.t_audit_trail(performed_at DESC) 
    WHERE severity IN ('critical', 'high');

-- =============================================================================
-- MAINTENANCE NOTES
-- =============================================================================
-- 1. Partitioned tables require indexes on each partition
-- 2. BRIN indexes most effective for append-only time-series data
-- 3. GIN indexes benefit from gin_fuzzy_search_limit setting
-- 4. Consider pg_trgm extension for fuzzy text matching
-- 5. Monitor bloat with pgstattuple extension
-- 6. Set appropriate fillfactor for update-heavy tables
-- =============================================================================

-- =============================================================================
-- ANALYZE after index creation
-- =============================================================================
ANALYZE core.t_audit_trail;
ANALYZE app.model_registry;
ANALYZE app.inference_log;
ANALYZE app.tool_catalog;
ANALYZE app.agent_sessions;
