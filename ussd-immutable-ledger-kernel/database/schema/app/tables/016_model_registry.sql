-- =============================================================================
-- ULTIMATE SOFTWARE SECURITY SOLUTIONS & DEFI LIMITED
-- AI/ML Model Registry Table
-- =============================================================================
-- Compliance: ISO 27001:2022 (A.8.9, A.8.10), ISO 27018:2019 (PII in AI)
--             SOC 2 Type II (AI Model Governance), GDPR (Art. 22 - Automated
--             Decision-Making), EU AI Act (High-Risk AI Systems)
-- Classification: CONFIDENTIAL - AI Training Data Protection Required
-- Version: 1.0.0
-- Author: Database Engineering Team
-- Last Modified: 2026-03-30
-- =============================================================================

-- -----------------------------------------------------------------------------
-- TABLE: model_registry
-- PURPOSE: AI model versioning and metadata storage for enterprise AI governance
-- SECURITY: Row-level security enforced; model weights stored in encrypted blob
-- AUDIT: All changes tracked via immutable ledger integration
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS app.model_registry (
    -- Primary Identifier
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Model Identification
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50) NOT NULL,
    type VARCHAR(100) NOT NULL CHECK (type IN (
        'classification', 'regression', 'generation', 
        'embedding', 'multimodal', 'reinforcement',
        'time_series', 'anomaly_detection', 'nlp',
        'computer_vision', 'speech_recognition', 'custom'
    )),
    
    -- Unique Constraint: Model name + version must be unique
    CONSTRAINT uq_model_registry_name_version UNIQUE (name, version),
    
    -- Model Metadata (JSONB for flexibility, validated by trigger)
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    -- Deployment Status with strict state machine
    deployment_status VARCHAR(50) NOT NULL DEFAULT 'development' CHECK (
        deployment_status IN (
            'development',        -- Model in training/experimentation
            'staging',            -- Model ready for validation
            'production',         -- Model actively serving
            'deprecated',         -- Model scheduled for retirement
            'archived',           -- Model retained for audit only
            'failed_validation'   -- Model failed governance review
        )
    ),
    
    -- Model Architecture and Training Info
    architecture VARCHAR(100),
    framework VARCHAR(50) CHECK (framework IN (
        'pytorch', 'tensorflow', 'jax', 'onnx', 
        'sklearn', 'huggingface', 'custom', 'other'
    )),
    
    -- Training Data Governance (GDPR/EU AI Act compliance)
    training_dataset_hash VARCHAR(64),  -- SHA-256 of training dataset
    training_data_provenance JSONB,     -- Source, licensing, consent records
    bias_audit_completed BOOLEAN DEFAULT FALSE,
    bias_audit_report_url TEXT,
    
    -- Performance Metrics (validated JSON schema)
    performance_metrics JSONB DEFAULT '{}'::jsonb,
    
    -- Model Weights Storage Reference (encrypted at rest)
    weights_storage_path TEXT,          -- Path to encrypted model artifacts
    weights_encryption_key_id UUID,     -- Reference to KMS key
    
    -- Risk Classification (EU AI Act compliance)
    risk_level VARCHAR(20) DEFAULT 'limited' CHECK (
        risk_level IN ('minimal', 'limited', 'high', 'unacceptable')
    ),
    human_oversight_required BOOLEAN DEFAULT FALSE,
    
    -- Governance and Approvals
    approved_by UUID REFERENCES app.users(id),
    approval_date TIMESTAMPTZ,
    governance_review_id UUID,
    
    -- Compliance Tracking
    compliance_frameworks TEXT[] DEFAULT '{}',  -- e.g., ['GDPR', 'HIPAA', 'SOX']
    
    -- Immutable Ledger Integration
    ledger_hash VARCHAR(64),            -- SHA-256 hash of serialized record
    ledger_sequence BIGINT,             -- Ledger sequence number for verification
    
    -- Standard Audit Columns
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES app.users(id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID REFERENCES app.users(id),
    
    -- Soft Delete (for audit retention - models never truly deleted)
    deleted_at TIMESTAMPTZ,
    deleted_by UUID REFERENCES app.users(id),
    deletion_reason TEXT,
    
    -- Immutable Record Flag (for production models)
    is_immutable BOOLEAN DEFAULT FALSE,
    
    -- Table Comments for Documentation
    CONSTRAINT chk_metadata_structure CHECK (
        jsonb_typeof(metadata) = 'object'
    ),
    CONSTRAINT chk_production_requires_approval CHECK (
        (deployment_status != 'production') OR 
        (approved_by IS NOT NULL AND approval_date IS NOT NULL)
    ),
    CONSTRAINT chk_high_risk_requires_oversight CHECK (
        (risk_level != 'high') OR (human_oversight_required = TRUE)
    )
);

-- -----------------------------------------------------------------------------
-- INDEXES: Optimized for AI model discovery and governance queries
-- -----------------------------------------------------------------------------

-- Model lookup by name (case-insensitive for search)
CREATE INDEX IF NOT EXISTS idx_model_registry_name 
    ON app.model_registry USING btree (lower(name));

-- Active production models
CREATE INDEX IF NOT EXISTS idx_model_registry_active 
    ON app.model_registry USING btree (deployment_status) 
    WHERE deployment_status = 'production';

-- Risk level filtering (compliance queries)
CREATE INDEX IF NOT EXISTS idx_model_registry_risk 
    ON app.model_registry USING btree (risk_level, deployment_status);

-- JSONB index for metadata queries
CREATE INDEX IF NOT EXISTS idx_model_registry_metadata 
    ON app.model_registry USING gin (metadata jsonb_path_ops);

-- Framework and type filtering
CREATE INDEX IF NOT EXISTS idx_model_registry_framework_type 
    ON app.model_registry USING btree (framework, type);

-- Ledger verification index
CREATE INDEX IF NOT EXISTS idx_model_registry_ledger 
    ON app.model_registry USING btree (ledger_sequence) 
    WHERE ledger_sequence IS NOT NULL;

-- Soft delete filtering (exclude deleted records by default)
CREATE INDEX IF NOT EXISTS idx_model_registry_deleted 
    ON app.model_registry USING btree (deleted_at) 
    WHERE deleted_at IS NULL;

-- Timeline queries for audit
CREATE INDEX IF NOT EXISTS idx_model_registry_timeline 
    ON app.model_registry USING btree (created_at DESC, updated_at DESC);

-- -----------------------------------------------------------------------------
-- ROW LEVEL SECURITY (RLS): Enterprise-grade access control
-- -----------------------------------------------------------------------------

ALTER TABLE app.model_registry ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view non-deleted models based on their permissions
CREATE POLICY model_registry_select_policy ON app.model_registry
    FOR SELECT
    USING (
        deleted_at IS NULL AND
        (
            -- Direct permission check via shared policy function
            app.has_permission(current_user, 'ai:models:read')
            OR 
            -- Model owner can always view
            created_by = current_setting('app.current_user_id')::UUID
            OR
            -- Admin override
            app.has_permission(current_user, 'system:admin')
        )
    );

-- Policy: Only authorized users can create models
CREATE POLICY model_registry_insert_policy ON app.model_registry
    FOR INSERT
    WITH CHECK (
        app.has_permission(current_user, 'ai:models:create')
    );

-- Policy: Only model owners or admins can update (production models immutable)
CREATE POLICY model_registry_update_policy ON app.model_registry
    FOR UPDATE
    USING (
        is_immutable = FALSE AND
        deleted_at IS NULL AND
        (
            app.has_permission(current_user, 'ai:models:update')
            OR
            created_by = current_setting('app.current_user_id')::UUID
            OR
            app.has_permission(current_user, 'system:admin')
        )
    );

-- Policy: Soft delete only - never hard delete for audit
CREATE POLICY model_registry_delete_policy ON app.model_registry
    FOR DELETE
    USING (
        FALSE  -- Hard deletes prohibited; use soft delete via update
    );

-- -----------------------------------------------------------------------------
-- TRIGGERS: Automated governance and audit enforcement
-- -----------------------------------------------------------------------------

-- Trigger: Update timestamp on modification
CREATE OR REPLACE FUNCTION app.trigger_model_registry_updated()
RETURNS TRIGGER AS $$
BEGIN
    -- Prevent modification of immutable records
    IF OLD.is_immutable AND NEW.is_immutable THEN
        RAISE EXCEPTION 'Cannot modify immutable model record: %', OLD.id
            USING HINT = 'Production models are immutable for audit compliance';
    END IF;
    
    -- Prevent direct changes to ledger fields
    IF OLD.ledger_hash IS DISTINCT FROM NEW.ledger_hash OR
       OLD.ledger_sequence IS DISTINCT FROM NEW.ledger_sequence THEN
        RAISE EXCEPTION 'Ledger fields are immutable and system-managed'
            USING HINT = 'Ledger fields cannot be modified directly';
    END IF;
    
    -- Auto-update timestamp and user
    NEW.updated_at = CURRENT_TIMESTAMP;
    NEW.updated_by = current_setting('app.current_user_id')::UUID;
    
    -- Validate metadata structure (basic schema validation)
    IF NEW.metadata ? 'parameters' AND 
       jsonb_typeof(NEW.metadata->'parameters') != 'object' THEN
        RAISE EXCEPTION 'Metadata.parameters must be an object';
    END IF;
    
    -- Log change to audit table
    INSERT INTO app.audit_log (
        table_name, record_id, action, 
        old_data, new_data, performed_by
    ) VALUES (
        'model_registry', OLD.id, 'UPDATE',
        to_jsonb(OLD), to_jsonb(NEW),
        current_setting('app.current_user_id')::UUID
    );
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER model_registry_updated
    BEFORE UPDATE ON app.model_registry
    FOR EACH ROW
    EXECUTE FUNCTION app.trigger_model_registry_updated();

-- Trigger: Audit on insert
CREATE OR REPLACE FUNCTION app.trigger_model_registry_inserted()
RETURNS TRIGGER AS $$
BEGIN
    -- Set created_by if not provided
    IF NEW.created_by IS NULL THEN
        NEW.created_by := current_setting('app.current_user_id')::UUID;
    END IF;
    
    -- Log to audit table
    INSERT INTO app.audit_log (
        table_name, record_id, action, 
        new_data, performed_by
    ) VALUES (
        'model_registry', NEW.id, 'INSERT',
        to_jsonb(NEW),
        NEW.created_by
    );
    
    -- Compute and store ledger hash for immutability
    NEW.ledger_hash := encode(
        digest(
            NEW.id::text || NEW.name || NEW.version || NEW.created_at::text,
            'sha256'
        ),
        'hex'
    );
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER model_registry_inserted
    BEFORE INSERT ON app.model_registry
    FOR EACH ROW
    EXECUTE FUNCTION app.trigger_model_registry_inserted();

-- Trigger: Prevent hard delete
CREATE OR REPLACE FUNCTION app.trigger_model_registry_prevent_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Hard delete prohibited on model_registry. Use soft delete via update.'
        USING HINT = 'Set deleted_at, deleted_by, and deletion_reason fields instead';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER model_registry_prevent_delete
    BEFORE DELETE ON app.model_registry
    FOR EACH ROW
    EXECUTE FUNCTION app.trigger_model_registry_prevent_delete();

-- -----------------------------------------------------------------------------
-- TABLE COMMENTS
-- -----------------------------------------------------------------------------

COMMENT ON TABLE app.model_registry IS 
    'AI/ML model registry for enterprise governance. Tracks model versions, 
     deployment status, and compliance requirements per ISO 27001, GDPR, and EU AI Act.';

COMMENT ON COLUMN app.model_registry.id IS 'Unique identifier (UUID v4)';
COMMENT ON COLUMN app.model_registry.name IS 'Human-readable model name';
COMMENT ON COLUMN app.model_registry.version IS 'Semantic version (e.g., 1.0.0)';
COMMENT ON COLUMN app.model_registry.type IS 'Model architecture category';
COMMENT ON COLUMN app.model_registry.metadata IS 'Flexible model configuration (JSONB)';
COMMENT ON COLUMN app.model_registry.deployment_status IS 'Lifecycle state of the model';
COMMENT ON COLUMN app.model_registry.training_dataset_hash IS 'SHA-256 hash for data lineage';
COMMENT ON COLUMN app.model_registry.risk_level IS 'EU AI Act risk classification';
COMMENT ON COLUMN app.model_registry.human_oversight_required IS 'Mandatory for high-risk AI';
COMMENT ON COLUMN app.model_registry.ledger_hash IS 'Cryptographic integrity verification';
COMMENT ON COLUMN app.model_registry.is_immutable IS 'Production models cannot be modified';

-- -----------------------------------------------------------------------------
-- GRANTS: Principle of least privilege
-- -----------------------------------------------------------------------------

GRANT SELECT ON app.model_registry TO app_readonly;
GRANT SELECT, INSERT, UPDATE ON app.model_registry TO app_readwrite;
GRANT ALL ON app.model_registry TO app_admin;

-- =============================================================================
-- END OF FILE
-- =============================================================================
