-- =============================================================================
-- ULTIMATE SOFTWARE SECURITY SOLUTIONS & DEFI LIMITED
-- AI Inference Log Table
-- =============================================================================
-- Compliance: ISO 27001:2022 (A.8.9, A.12.4), ISO 27018:2019 (PII in cloud)
--             SOC 2 Type II (CC6.1, CC7.2), GDPR (Art. 5, 30 - Processing logs)
--             EU AI Act (Art. 12 - Record-keeping for high-risk AI)
-- Classification: RESTRICTED - Contains AI Processing Data
-- Retention: 7 years (configurable per compliance framework)
-- Version: 1.0.0
-- Author: Database Engineering Team
-- Last Modified: 2026-03-30
-- =============================================================================

-- -----------------------------------------------------------------------------
-- TABLE: inference_log
-- PURPOSE: Immutable audit trail of all AI model inferences
-- SECURITY: Append-only; encrypted sensitive fields; partition by time
-- NOTES: This table is WORM (Write Once Read Many) for compliance
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS app.inference_log (
    -- Primary Identifier
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Model Reference
    model_id UUID NOT NULL REFERENCES app.model_registry(id),
    
    -- Request Identification
    request_id UUID NOT NULL DEFAULT gen_random_uuid(),
    correlation_id VARCHAR(255),        -- For distributed tracing
    
    -- Unique constraint on request_id for idempotency
    CONSTRAINT uq_inference_log_request_id UNIQUE (request_id),
    
    -- Input Data (encrypted at application layer for sensitive data)
    input_data JSONB NOT NULL,
    input_hash VARCHAR(64) NOT NULL,    -- SHA-256 for integrity verification
    input_size_bytes INTEGER CHECK (input_size_bytes > 0),
    
    -- Output Data
    output_data JSONB NOT NULL,
    output_hash VARCHAR(64) NOT NULL,   -- SHA-256 for integrity verification
    output_size_bytes INTEGER CHECK (output_size_bytes >= 0),
    
    -- Model Confidence and Performance
    confidence_score NUMERIC(5,4) CHECK (
        confidence_score >= 0.0 AND confidence_score <= 1.0
    ),
    confidence_threshold NUMERIC(5,4) DEFAULT 0.5 CHECK (
        confidence_threshold >= 0.0 AND confidence_threshold <= 1.0
    ),
    
    -- Latency Metrics (milliseconds)
    latency_ms INTEGER NOT NULL CHECK (latency_ms >= 0),
    preprocessing_latency_ms INTEGER CHECK (preprocessing_latency_ms >= 0),
    inference_latency_ms INTEGER CHECK (inference_latency_ms >= 0),
    postprocessing_latency_ms INTEGER CHECK (postprocessing_latency_ms >= 0),
    
    -- Resource Utilization
    tokens_input INTEGER CHECK (tokens_input >= 0),
    tokens_output INTEGER CHECK (tokens_output >= 0),
    compute_units NUMERIC(10,2),
    
    -- Inference Context
    inference_type VARCHAR(50) NOT NULL DEFAULT 'realtime' CHECK (
        inference_type IN ('realtime', 'batch', 'streaming', 'async')
    ),
    batch_size INTEGER DEFAULT 1 CHECK (batch_size >= 1),
    
    -- PII Detection Flags (automated scanning)
    contains_pii BOOLEAN DEFAULT FALSE,
    pii_types_detected TEXT[],
    pii_redaction_applied BOOLEAN DEFAULT FALSE,
    
    -- Data Classification
    data_classification VARCHAR(20) DEFAULT 'internal' CHECK (
        data_classification IN ('public', 'internal', 'confidential', 'restricted')
    ),
    
    -- User and Session Context
    user_id UUID REFERENCES app.users(id),
    session_id UUID,
    ip_address INET,                    -- Client IP (hashed for privacy)
    user_agent_hash VARCHAR(64),        -- Hashed user agent string
    
    -- Geographic and Temporal Context
    timezone VARCHAR(50) DEFAULT 'UTC',
    request_timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Error Handling
    status VARCHAR(20) NOT NULL DEFAULT 'success' CHECK (
        status IN ('success', 'failure', 'timeout', 'validation_error', 
                   'rate_limited', 'content_filtered', 'error')
    ),
    error_code VARCHAR(50),
    error_message TEXT,
    retry_count INTEGER DEFAULT 0 CHECK (retry_count >= 0),
    
    -- Compliance and Governance
    compliance_frameworks TEXT[] DEFAULT '{}',
    retention_until DATE,               -- Auto-purge after this date (GDPR)
    legal_hold BOOLEAN DEFAULT FALSE,   -- Prevent deletion if true
    
    -- Cost Tracking
    cost_estimate_usd NUMERIC(10,6),
    billing_tag VARCHAR(100),
    
    -- Immutable Ledger Integration
    ledger_hash VARCHAR(64) NOT NULL,
    ledger_sequence BIGINT NOT NULL,
    previous_hash VARCHAR(64),          -- For blockchain-style chain verification
    
    -- Tamper Evidence
    record_signature VARCHAR(128),      -- HMAC-SHA256 of record fields
    
    -- Audit (created only - no updates allowed for immutability)
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES app.users(id),
    
    -- Partition key for time-based partitioning
    partition_date DATE NOT NULL DEFAULT CURRENT_DATE
) PARTITION BY RANGE (partition_date);

-- -----------------------------------------------------------------------------
-- PARTITIONS: Monthly partitions for efficient time-series data
-- -----------------------------------------------------------------------------

-- Create initial partitions (current month and next 2 months)
-- Note: Additional partitions should be created via scheduled job

CREATE TABLE IF NOT EXISTS app.inference_log_y2026m03 
    PARTITION OF app.inference_log
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

CREATE TABLE IF NOT EXISTS app.inference_log_y2026m04 
    PARTITION OF app.inference_log
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

CREATE TABLE IF NOT EXISTS app.inference_log_y2026m05 
    PARTITION OF app.inference_log
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

-- Default partition for overflow (should be rare)
CREATE TABLE IF NOT EXISTS app.inference_log_default 
    PARTITION OF app.inference_log DEFAULT;

-- -----------------------------------------------------------------------------
-- INDEXES: Optimized for audit queries and performance analysis
-- -----------------------------------------------------------------------------

-- Primary query pattern: by request_id
CREATE INDEX IF NOT EXISTS idx_inference_log_request 
    ON app.inference_log USING btree (request_id);

-- Model performance analysis
CREATE INDEX IF NOT EXISTS idx_inference_log_model_time 
    ON app.inference_log USING btree (model_id, request_timestamp DESC);

-- Latency analysis queries
CREATE INDEX IF NOT EXISTS idx_inference_log_latency 
    ON app.inference_log USING btree (model_id, latency_ms) 
    WHERE status = 'success';

-- Error investigation
CREATE INDEX IF NOT EXISTS idx_inference_log_errors 
    ON app.inference_log USING btree (model_id, status, error_code) 
    WHERE status != 'success';

-- User activity audit
CREATE INDEX IF NOT EXISTS idx_inference_log_user 
    ON app.inference_log USING btree (user_id, request_timestamp DESC);

-- Correlation ID for distributed tracing
CREATE INDEX IF NOT EXISTS idx_inference_log_correlation 
    ON app.inference_log USING hash (correlation_id) 
    WHERE correlation_id IS NOT NULL;

-- PII detection queries
CREATE INDEX IF NOT EXISTS idx_inference_log_pii 
    ON app.inference_log USING btree (contains_pii, created_at) 
    WHERE contains_pii = TRUE;

-- Ledger verification
CREATE INDEX IF NOT EXISTS idx_inference_log_ledger 
    ON app.inference_log USING btree (ledger_sequence);

-- Partition-local indexes for time-series queries
CREATE INDEX IF NOT EXISTS idx_inference_log_timestamp 
    ON app.inference_log USING btree (request_timestamp DESC);

-- Confidence score analysis
CREATE INDEX IF NOT EXISTS idx_inference_log_confidence 
    ON app.inference_log USING btree (model_id, confidence_score) 
    WHERE status = 'success';

-- Cost analysis
CREATE INDEX IF NOT EXISTS idx_inference_log_cost 
    ON app.inference_log USING btree (billing_tag, created_at) 
    WHERE cost_estimate_usd IS NOT NULL;

-- -----------------------------------------------------------------------------
-- ROW LEVEL SECURITY (RLS): Strict access control
-- -----------------------------------------------------------------------------

ALTER TABLE app.inference_log ENABLE ROW LEVEL SECURITY;

-- Force RLS for table owner
ALTER TABLE app.inference_log FORCE ROW LEVEL SECURITY;

-- Policy: Users can only view their own inferences unless admin
CREATE POLICY inference_log_select_policy ON app.inference_log
    FOR SELECT
    USING (
        app.has_permission(current_user, 'ai:inference:read:all')
        OR 
        user_id = current_setting('app.current_user_id', true)::UUID
        OR
        app.has_permission(current_user, 'system:admin')
    );

-- Policy: No direct inserts - must use logging function
CREATE POLICY inference_log_insert_policy ON app.inference_log
    FOR INSERT
    WITH CHECK (
        app.has_permission(current_user, 'ai:inference:log')
        OR
        app.has_permission(current_user, 'system:service')
    );

-- Policy: No updates allowed (WORM compliance)
CREATE POLICY inference_log_update_policy ON app.inference_log
    FOR UPDATE
    USING (FALSE);

-- Policy: No deletes allowed (immutable)
CREATE POLICY inference_log_delete_policy ON app.inference_log
    FOR DELETE
    USING (FALSE);

-- -----------------------------------------------------------------------------
-- TRIGGERS: Automated integrity and audit enforcement
-- -----------------------------------------------------------------------------

-- Trigger: Compute hashes and signatures on insert
CREATE OR REPLACE FUNCTION app.trigger_inference_log_inserted()
RETURNS TRIGGER AS $$
DECLARE
    record_data TEXT;
    hmac_key TEXT;
BEGIN
    -- Set created_by if not provided
    IF NEW.created_by IS NULL THEN
        NEW.created_by := current_setting('app.current_user_id', true)::UUID;
    END IF;
    
    -- Compute input hash if not provided (application should provide)
    IF NEW.input_hash IS NULL THEN
        NEW.input_hash := encode(
            digest(NEW.input_data::text, 'sha256'),
            'hex'
        );
    END IF;
    
    -- Compute output hash if not provided
    IF NEW.output_hash IS NULL THEN
        NEW.output_hash := encode(
            digest(NEW.output_data::text, 'sha256'),
            'hex'
        );
    END IF;
    
    -- Compute ledger hash
    record_data := NEW.id::text || NEW.model_id::text || 
                   NEW.request_id::text || NEW.request_timestamp::text ||
                   NEW.input_hash || NEW.output_hash;
    
    NEW.ledger_hash := encode(digest(record_data, 'sha256'), 'hex');
    
    -- Get HMAC key from secure configuration
    BEGIN
        hmac_key := current_setting('app.ledger_hmac_key', true);
    EXCEPTION WHEN OTHERS THEN
        hmac_key := 'default_key_change_in_production';
    END;
    
    -- Compute HMAC signature for tamper detection
    NEW.record_signature := encode(
        hmac(record_data::bytea, hmac_key::bytea, 'sha256'),
        'hex'
    );
    
    -- Link to previous record in ledger chain
    SELECT ledger_hash INTO NEW.previous_hash
    FROM app.inference_log
    WHERE ledger_sequence IS NOT NULL
    ORDER BY ledger_sequence DESC
    LIMIT 1;
    
    -- Get next ledger sequence
    SELECT COALESCE(MAX(ledger_sequence), 0) + 1 
    INTO NEW.ledger_sequence
    FROM app.inference_log;
    
    -- Set default retention period (7 years unless specified)
    IF NEW.retention_until IS NULL THEN
        NEW.retention_until := CURRENT_DATE + INTERVAL '7 years';
    END IF;
    
    -- Auto-classify if PII detected in content
    IF NEW.input_data::text ~* '(email|ssn|phone|credit.?card|password)' THEN
        NEW.contains_pii := TRUE;
        NEW.data_classification := 'restricted';
    END IF;
    
    -- Log to audit table
    INSERT INTO app.audit_log (
        table_name, record_id, action, 
        new_data, performed_by
    ) VALUES (
        'inference_log', NEW.id, 'INFERENCE',
        jsonb_build_object(
            'model_id', NEW.model_id,
            'request_id', NEW.request_id,
            'status', NEW.status,
            'latency_ms', NEW.latency_ms
        ),
        NEW.created_by
    );
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER inference_log_inserted
    BEFORE INSERT ON app.inference_log
    FOR EACH ROW
    EXECUTE FUNCTION app.trigger_inference_log_inserted();

-- Trigger: Prevent any modifications
CREATE OR REPLACE FUNCTION app.trigger_inference_log_prevent_modify()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Inference log is immutable. No modifications allowed.'
        USING HINT = 'This table is WORM (Write Once Read Many) for compliance';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER inference_log_prevent_update
    BEFORE UPDATE ON app.inference_log
    FOR EACH ROW
    EXECUTE FUNCTION app.trigger_inference_log_prevent_modify();

CREATE TRIGGER inference_log_prevent_delete
    BEFORE DELETE ON app.inference_log
    FOR EACH ROW
    EXECUTE FUNCTION app.trigger_inference_log_prevent_modify();

-- -----------------------------------------------------------------------------
-- COMPRESSION: Optimize storage for large JSONB columns
-- -----------------------------------------------------------------------------

ALTER TABLE app.inference_log ALTER COLUMN input_data SET STORAGE EXTERNAL;
ALTER TABLE app.inference_log ALTER COLUMN output_data SET STORAGE EXTERNAL;

-- -----------------------------------------------------------------------------
-- TABLE COMMENTS
-- -----------------------------------------------------------------------------

COMMENT ON TABLE app.inference_log IS 
    'Immutable audit trail of all AI model inferences. WORM-compliant storage 
     for regulatory requirements (GDPR, EU AI Act, SOC 2). Partitioned by month.';

COMMENT ON COLUMN app.inference_log.request_id IS 'Unique per-inference request ID';
COMMENT ON COLUMN app.inference_log.input_hash IS 'SHA-256 hash for input integrity';
COMMENT ON COLUMN app.inference_log.output_hash IS 'SHA-256 hash for output integrity';
COMMENT ON COLUMN app.inference_log.confidence_score IS 'Model prediction confidence (0-1)';
COMMENT ON COLUMN app.inference_log.latency_ms IS 'Total end-to-end latency';
COMMENT ON COLUMN app.inference_log.contains_pii IS 'Automated PII detection flag';
COMMENT ON COLUMN app.inference_log.ledger_hash IS 'Cryptographic integrity hash';
COMMENT ON COLUMN app.inference_log.record_signature IS 'HMAC for tamper detection';
COMMENT ON COLUMN app.inference_log.retention_until IS 'Auto-purge date (GDPR compliance)';
COMMENT ON COLUMN app.inference_log.legal_hold IS 'Prevents deletion when true';

-- -----------------------------------------------------------------------------
-- GRANTS: Minimal required permissions
-- -----------------------------------------------------------------------------

GRANT SELECT ON app.inference_log TO app_readonly;
GRANT SELECT, INSERT ON app.inference_log TO app_readwrite;
GRANT ALL ON app.inference_log TO app_admin;

-- =============================================================================
-- END OF FILE
-- =============================================================================
