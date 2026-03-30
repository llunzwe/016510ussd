-- =============================================================================
-- ULTIMATE SOFTWARE SECURITY SOLUTIONS & DEFI LIMITED
-- Vector Store Table (pgvector Extension)
-- =============================================================================
-- Compliance: ISO 27001:2022 (A.8.2, A.12.3), ISO 27018:2019 (PII in cloud)
--             GDPR (Art. 17 - Right to erasure, Art. 25 - Privacy by design)
-- Classification: RESTRICTED - Contains AI Embeddings
-- Requirements: pgvector extension must be installed
-- Version: 1.0.0
-- Author: Database Engineering Team
-- Last Modified: 2026-03-30
-- =============================================================================

-- -----------------------------------------------------------------------------
-- EXTENSION CHECK: pgvector is required for this table
-- -----------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_extension WHERE extname = 'vector'
    ) THEN
        RAISE WARNING 'pgvector extension not installed. 
                       Vector store table will be created but vector 
                       operations will not function. Run: CREATE EXTENSION vector;';
    END IF;
END $$;

-- -----------------------------------------------------------------------------
-- TABLE: vector_store
-- PURPOSE: Storage for AI embeddings with metadata for RAG and semantic search
-- SECURITY: Row-level security; encrypted source text; access logging
-- NOTES: Vector dimensions configurable; supports multiple embedding models
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS app.vector_store (
    -- Primary Identifier
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Collection/Namespace Organization
    collection_name VARCHAR(255) NOT NULL DEFAULT 'default',
    namespace VARCHAR(100) DEFAULT 'public',
    
    -- Composite unique constraint for deduplication within namespace
    CONSTRAINT uq_vector_store_collection_doc UNIQUE (collection_name, namespace, document_id, chunk_index),
    
    -- Source Document Reference
    document_id VARCHAR(255) NOT NULL,  -- External document identifier
    chunk_index INTEGER DEFAULT 0,      -- Position within document (for chunked docs)
    total_chunks INTEGER DEFAULT 1,     -- Total chunks for this document
    
    -- Source Information
    source_type VARCHAR(50) NOT NULL CHECK (
        source_type IN ('document', 'webpage', 'database', 'api', 
                       'conversation', 'code', 'image', 'audio', 'video', 'custom')
    ),
    source_url TEXT,                    -- Original source URL/path
    source_metadata JSONB DEFAULT '{}'::jsonb,  -- Source-specific metadata
    
    -- Content (original text - encrypted for sensitive data)
    content_text TEXT,                  -- Original text content
    content_hash VARCHAR(64),           -- SHA-256 of content for integrity
    content_encrypted BOOLEAN DEFAULT FALSE,  -- Flag if content is encrypted
    
    -- Vector Embedding (pgvector type - 1536 dims default for OpenAI)
    -- Note: Dimension can be adjusted based on embedding model
    embedding VECTOR(1536),
    
    -- Embedding Model Information
    embedding_model VARCHAR(100) NOT NULL DEFAULT 'text-embedding-ada-002',
    embedding_version VARCHAR(50),
    embedding_dimensions INTEGER NOT NULL DEFAULT 1536,
    
    -- Search Metadata
    language VARCHAR(10) DEFAULT 'en',
    content_type VARCHAR(50) DEFAULT 'text/plain',
    
    -- Classification and Access Control
    classification VARCHAR(20) DEFAULT 'internal' CHECK (
        classification IN ('public', 'internal', 'confidential', 'restricted')
    ),
    access_control_list JSONB DEFAULT '{}'::jsonb,  -- Custom ACL rules
    
    -- PII and Sensitivity Analysis
    contains_pii BOOLEAN DEFAULT FALSE,
    sensitivity_score NUMERIC(3,2) CHECK (sensitivity_score >= 0.0 AND sensitivity_score <= 1.0),
    pii_detected_types TEXT[],
    
    -- Semantic Metadata (for filtered search)
    categories TEXT[],
    tags TEXT[],
    entities JSONB,                     -- Extracted named entities
    
    -- Search Statistics
    search_count INTEGER DEFAULT 0,     -- Times retrieved in search
    last_searched_at TIMESTAMPTZ,
    relevance_score_avg NUMERIC(5,4),   -- Average relevance in searches
    
    -- Expiration and Retention (GDPR compliance)
    expires_at TIMESTAMPTZ,             -- Auto-delete after this time
    retention_days INTEGER DEFAULT 2555, -- 7 years default (GDPR)
    
    -- Verification
    verified_at TIMESTAMPTZ,            -- Last human verification
    verified_by UUID REFERENCES app.users(id),
    verification_status VARCHAR(20) DEFAULT 'unverified' CHECK (
        verification_status IN ('unverified', 'pending', 'verified', 'rejected', 'outdated')
    ),
    
    -- Immutable Ledger Integration
    ledger_hash VARCHAR(64),
    ledger_sequence BIGINT,
    
    -- Audit Columns
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES app.users(id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID REFERENCES app.users(id),
    
    -- Soft Delete
    deleted_at TIMESTAMPTZ,
    deleted_by UUID REFERENCES app.users(id),
    deletion_reason TEXT,
    
    -- Constraints
    CONSTRAINT chk_chunk_index_valid CHECK (chunk_index >= 0),
    CONSTRAINT chk_total_chunks_valid CHECK (total_chunks >= 1),
    CONSTRAINT chk_chunk_index_range CHECK (chunk_index < total_chunks),
    CONSTRAINT chk_embedding_dimensions CHECK (
        embedding_dimensions > 0 AND embedding_dimensions <= 8192
    )
);

-- -----------------------------------------------------------------------------
-- INDEXES: Optimized for vector similarity search and metadata filtering
-- -----------------------------------------------------------------------------

-- Vector similarity search indexes (HNSW for approximate nearest neighbors)
-- Note: Requires pgvector extension
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector') THEN
        -- HNSW index for fast approximate similarity search (cosine distance)
        CREATE INDEX IF NOT EXISTS idx_vector_store_embedding_cosine 
            ON app.vector_store USING hnsw (embedding vector_cosine_ops)
            WITH (m = 16, ef_construction = 64);
        
        -- HNSW index for L2/Euclidean distance
        CREATE INDEX IF NOT EXISTS idx_vector_store_embedding_l2 
            ON app.vector_store USING hnsw (embedding vector_l2_ops)
            WITH (m = 16, ef_construction = 64);
        
        -- HNSW index for inner product
        CREATE INDEX IF NOT EXISTS idx_vector_store_embedding_ip 
            ON app.vector_store USING hnsw (embedding vector_ip_ops)
            WITH (m = 16, ef_construction = 64);
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Could not create HNSW indexes: %', SQLERRM;
END $$;

-- Collection and namespace lookups
CREATE INDEX IF NOT EXISTS idx_vector_store_collection 
    ON app.vector_store USING btree (collection_name, namespace);

-- Document retrieval
CREATE INDEX IF NOT EXISTS idx_vector_store_document 
    ON app.vector_store USING btree (document_id, chunk_index);

-- Source type filtering
CREATE INDEX IF NOT EXISTS idx_vector_store_source 
    ON app.vector_store USING btree (source_type, collection_name);

-- Classification filtering (for access control)
CREATE INDEX IF NOT EXISTS idx_vector_store_classification 
    ON app.vector_store USING btree (classification) 
    WHERE deleted_at IS NULL;

-- Tag-based filtering (for semantic search with filters)
CREATE INDEX IF NOT EXISTS idx_vector_store_tags 
    ON app.vector_store USING gin (tags);

-- Category filtering
CREATE INDEX IF NOT EXISTS idx_vector_store_categories 
    ON app.vector_store USING gin (categories);

-- JSONB metadata index
CREATE INDEX IF NOT EXISTS idx_vector_store_source_metadata 
    ON app.vector_store USING gin (source_metadata jsonb_path_ops);

-- Expiration tracking (for cleanup jobs)
CREATE INDEX IF NOT EXISTS idx_vector_store_expires 
    ON app.vector_store USING btree (expires_at) 
    WHERE expires_at IS NOT NULL AND deleted_at IS NULL;

-- PII detection queries
CREATE INDEX IF NOT EXISTS idx_vector_store_pii 
    ON app.vector_store USING btree (contains_pii, sensitivity_score) 
    WHERE contains_pii = TRUE;

-- Verification status for quality control
CREATE INDEX IF NOT EXISTS idx_vector_store_verification 
    ON app.vector_store USING btree (verification_status) 
    WHERE deleted_at IS NULL;

-- Language filtering
CREATE INDEX IF NOT EXISTS idx_vector_store_language 
    ON app.vector_store USING btree (language, collection_name);

-- Soft delete filtering
CREATE INDEX IF NOT EXISTS idx_vector_store_active 
    ON app.vector_store USING btree (deleted_at) 
    WHERE deleted_at IS NULL;

-- -----------------------------------------------------------------------------
-- ROW LEVEL SECURITY (RLS): Granular access control
-- -----------------------------------------------------------------------------

ALTER TABLE app.vector_store ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view vectors based on classification level
CREATE POLICY vector_store_select_policy ON app.vector_store
    FOR SELECT
    USING (
        deleted_at IS NULL AND
        (
            -- Public classification: all authenticated users
            classification = 'public'
            OR
            -- Internal classification: authenticated users with read permission
            (classification = 'internal' AND 
             app.has_permission(current_user, 'ai:vectors:read'))
            OR
            -- Confidential: specific permission required
            (classification = 'confidential' AND 
             app.has_permission(current_user, 'ai:vectors:read:confidential'))
            OR
            -- Restricted: elevated permission required
            (classification = 'restricted' AND 
             app.has_permission(current_user, 'ai:vectors:read:restricted'))
            OR
            -- Creator can always access their own vectors
            created_by = current_setting('app.current_user_id')::UUID
            OR
            -- Admin override
            app.has_permission(current_user, 'system:admin')
        )
    );

-- Policy: Insert requires appropriate permission
CREATE POLICY vector_store_insert_policy ON app.vector_store
    FOR INSERT
    WITH CHECK (
        app.has_permission(current_user, 'ai:vectors:create') AND
        classification IN ('public', 'internal', 'confidential')
    );

-- Policy: Update restricted to owners and admins
CREATE POLICY vector_store_update_policy ON app.vector_store
    FOR UPDATE
    USING (
        deleted_at IS NULL AND
        (
            created_by = current_setting('app.current_user_id')::UUID
            OR
            app.has_permission(current_user, 'ai:vectors:update')
            OR
            app.has_permission(current_user, 'system:admin')
        )
    );

-- Policy: Soft delete only
CREATE POLICY vector_store_delete_policy ON app.vector_store
    FOR DELETE
    USING (
        FALSE  -- Hard deletes prohibited
    );

-- -----------------------------------------------------------------------------
-- TRIGGERS: Automated governance and maintenance
-- -----------------------------------------------------------------------------

-- Trigger: Compute content hash and set audit fields
CREATE OR REPLACE FUNCTION app.trigger_vector_store_inserted()
RETURNS TRIGGER AS $$
BEGIN
    -- Set audit fields
    IF NEW.created_by IS NULL THEN
        NEW.created_by := current_setting('app.current_user_id')::UUID;
    END IF;
    
    -- Compute content hash for integrity
    IF NEW.content_text IS NOT NULL AND NEW.content_hash IS NULL THEN
        NEW.content_hash := encode(
            digest(NEW.content_text, 'sha256'),
            'hex'
        );
    END IF;
    
    -- Set expiration date based on retention policy
    IF NEW.expires_at IS NULL AND NEW.retention_days IS NOT NULL THEN
        NEW.expires_at := CURRENT_TIMESTAMP + (NEW.retention_days || ' days')::interval;
    END IF;
    
    -- Compute ledger hash
    NEW.ledger_hash := encode(
        digest(
            NEW.id::text || COALESCE(NEW.content_hash, '') || NEW.created_at::text,
            'sha256'
        ),
        'hex'
    );
    
    -- Get ledger sequence
    SELECT COALESCE(MAX(ledger_sequence), 0) + 1 
    INTO NEW.ledger_sequence
    FROM app.vector_store;
    
    -- Log to audit
    INSERT INTO app.audit_log (
        table_name, record_id, action,
        new_data, performed_by
    ) VALUES (
        'vector_store', NEW.id, 'INSERT',
        jsonb_build_object(
            'collection', NEW.collection_name,
            'document_id', NEW.document_id,
            'classification', NEW.classification
        ),
        NEW.created_by
    );
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER vector_store_inserted
    BEFORE INSERT ON app.vector_store
    FOR EACH ROW
    EXECUTE FUNCTION app.trigger_vector_store_inserted();

-- Trigger: Update modified timestamp
CREATE OR REPLACE FUNCTION app.trigger_vector_store_updated()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := CURRENT_TIMESTAMP;
    NEW.updated_by := current_setting('app.current_user_id')::UUID;
    
    -- Recompute content hash if text changed
    IF NEW.content_text IS DISTINCT FROM OLD.content_text THEN
        NEW.content_hash := encode(
            digest(NEW.content_text, 'sha256'),
            'hex'
        );
    END IF;
    
    -- Update verification status if content changed
    IF NEW.content_text IS DISTINCT FROM OLD.content_text AND 
       OLD.verification_status = 'verified' THEN
        NEW.verification_status := 'outdated';
    END IF;
    
    -- Log to audit
    INSERT INTO app.audit_log (
        table_name, record_id, action,
        old_data, new_data, performed_by
    ) VALUES (
        'vector_store', NEW.id, 'UPDATE',
        jsonb_build_object('content_hash', OLD.content_hash),
        jsonb_build_object('content_hash', NEW.content_hash),
        NEW.updated_by
    );
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER vector_store_updated
    BEFORE UPDATE ON app.vector_store
    FOR EACH ROW
    EXECUTE FUNCTION app.trigger_vector_store_updated();

-- Trigger: Soft delete enforcement
CREATE OR REPLACE FUNCTION app.trigger_vector_store_soft_delete()
RETURNS TRIGGER AS $$
BEGIN
    -- If deleted_at is being set, perform soft delete
    IF NEW.deleted_at IS NOT NULL AND OLD.deleted_at IS NULL THEN
        NEW.deleted_by := current_setting('app.current_user_id')::UUID;
        
        -- Log deletion
        INSERT INTO app.audit_log (
            table_name, record_id, action,
            old_data, performed_by
        ) VALUES (
            'vector_store', NEW.id, 'SOFT_DELETE',
            jsonb_build_object(
                'collection', OLD.collection_name,
                'document_id', OLD.document_id,
                'deletion_reason', NEW.deletion_reason
            ),
            NEW.deleted_by
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER vector_store_soft_delete
    BEFORE UPDATE OF deleted_at ON app.vector_store
    FOR EACH ROW
    EXECUTE FUNCTION app.trigger_vector_store_soft_delete();

-- Trigger: Prevent hard delete
CREATE OR REPLACE FUNCTION app.trigger_vector_store_prevent_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Hard delete prohibited. Use soft delete via UPDATE.'
        USING HINT = 'Set deleted_at, deleted_by, and deletion_reason instead';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER vector_store_prevent_delete
    BEFORE DELETE ON app.vector_store
    FOR EACH ROW
    EXECUTE FUNCTION app.trigger_vector_store_prevent_delete();

-- -----------------------------------------------------------------------------
-- TABLE COMMENTS
-- -----------------------------------------------------------------------------

COMMENT ON TABLE app.vector_store IS 
    'Vector embeddings storage for RAG and semantic search. Requires pgvector 
     extension. Supports multiple embedding models with metadata filtering.';

COMMENT ON COLUMN app.vector_store.embedding IS 'Vector embedding (1536 dims default)';
COMMENT ON COLUMN app.vector_store.collection_name IS 'Logical grouping namespace';
COMMENT ON COLUMN app.vector_store.document_id IS 'External source document ID';
COMMENT ON COLUMN app.vector_store.chunk_index IS 'Position within chunked document';
COMMENT ON COLUMN app.vector_store.content_text IS 'Original text (may be encrypted)';
COMMENT ON COLUMN app.vector_store.classification IS 'Data classification level';
COMMENT ON COLUMN app.vector_store.contains_pii IS 'PII detection flag';
COMMENT ON COLUMN app.vector_store.expires_at IS 'Auto-deletion timestamp (GDPR)';
COMMENT ON COLUMN app.vector_store.verification_status IS 'Human verification state';

-- -----------------------------------------------------------------------------
-- GRANTS
-- -----------------------------------------------------------------------------

GRANT SELECT ON app.vector_store TO app_readonly;
GRANT SELECT, INSERT, UPDATE ON app.vector_store TO app_readwrite;
GRANT ALL ON app.vector_store TO app_admin;

-- =============================================================================
-- END OF FILE
-- =============================================================================
