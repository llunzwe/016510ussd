-- ============================================================================
-- USSD KERNEL CORE SCHEMA - AGENT RELATIONSHIPS
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Generic graph relationships between accounts. This is a kernel
--              primitive for modeling any account-to-account linkage.
--              Applications define the semantics of relationship types.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. RELATIONSHIP TYPES (Configured by applications)
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_core.relationship_types (
    type_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Identification
    type_code VARCHAR(50) NOT NULL,
    type_name VARCHAR(100) NOT NULL,
    
    -- Scope
    application_id UUID,  -- NULL = kernel/system-wide
    
    -- Properties
    is_directional BOOLEAN DEFAULT TRUE,  -- A->B != B->A
    allows_cycles BOOLEAN DEFAULT FALSE,  -- Whether circular refs allowed
    
    -- Metadata schema (JSON schema for relationship attributes)
    attributes_schema JSONB DEFAULT '{}',
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Audit
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    created_by UUID,
    
    UNIQUE(type_code, application_id)
);

-- ----------------------------------------------------------------------------
-- 2. RELATIONSHIPS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_core.agent_relationships (
    relationship_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Relationship type
    type_id UUID NOT NULL REFERENCES ussd_core.relationship_types(type_id),
    
    -- Participants
    from_account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    to_account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    
    -- Attributes (type-specific data)
    attributes JSONB DEFAULT '{}',
    
    -- Weight/percentage if applicable
    weight NUMERIC(5, 2),  -- e.g., 50.00 for 50%
    
    -- Temporal validity
    valid_from TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    valid_to TIMESTAMPTZ,
    
    -- Status
    status VARCHAR(20) DEFAULT 'ACTIVE' CHECK (status IN ('PENDING', 'ACTIVE', 'SUSPENDED', 'EXPIRED')),
    
    -- Hierarchy path (for tree structures)
    hierarchy_path LTREE,
    
    -- Audit
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    created_by UUID,
    confirmed_at TIMESTAMPTZ,
    confirmed_by UUID,
    
    -- Integrity
    record_hash VARCHAR(64) NOT NULL
);

-- ----------------------------------------------------------------------------
-- 3. INDEXES
-- ----------------------------------------------------------------------------
CREATE INDEX idx_relationships_type ON ussd_core.agent_relationships(type_id);
CREATE INDEX idx_relationships_from ON ussd_core.agent_relationships(from_account_id);
CREATE INDEX idx_relationships_to ON ussd_core.agent_relationships(to_account_id);
CREATE INDEX idx_relationships_status ON ussd_core.agent_relationships(status) WHERE status = 'ACTIVE';
CREATE INDEX idx_relationships_path ON ussd_core.agent_relationships USING GIST(hierarchy_path);
CREATE INDEX idx_relationships_valid ON ussd_core.agent_relationships(valid_from, valid_to);

CREATE INDEX idx_rel_types_app ON ussd_core.relationship_types(application_id);

-- ----------------------------------------------------------------------------
-- 4. IMMUTABILITY TRIGGERS
-- ----------------------------------------------------------------------------
CREATE TRIGGER trg_agent_relationships_prevent_update
    BEFORE UPDATE ON ussd_core.agent_relationships
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_update();

CREATE TRIGGER trg_agent_relationships_prevent_delete
    BEFORE DELETE ON ussd_core.agent_relationships
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_delete();

-- ----------------------------------------------------------------------------
-- 5. HASH COMPUTATION
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd_core.compute_relationship_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := ussd_core.generate_hash(
        NEW.relationship_id::TEXT || 
        NEW.type_id::TEXT ||
        NEW.from_account_id::TEXT ||
        NEW.to_account_id::TEXT ||
        NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_agent_relationships_compute_hash
    BEFORE INSERT ON ussd_core.agent_relationships
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.compute_relationship_hash();

-- ----------------------------------------------------------------------------
-- 6. HIERARCHY PATH COMPUTATION
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd_core.compute_relationship_path()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_parent_path LTREE;
BEGIN
    SELECT hierarchy_path INTO v_parent_path
    FROM ussd_core.agent_relationships
    WHERE to_account_id = NEW.from_account_id
      AND status = 'ACTIVE'
      AND valid_to IS NULL
    LIMIT 1;
    
    IF v_parent_path IS NULL THEN
        NEW.hierarchy_path := text2ltree(NEW.from_account_id::TEXT);
    ELSE
        NEW.hierarchy_path := v_parent_path || NEW.to_account_id::TEXT;
    END IF;
    
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_agent_relationships_compute_path
    BEFORE INSERT ON ussd_core.agent_relationships
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.compute_relationship_path();

-- ----------------------------------------------------------------------------
-- 7. RELATIONSHIP FUNCTIONS
-- ----------------------------------------------------------------------------

-- Create relationship
CREATE OR REPLACE FUNCTION ussd_core.create_relationship(
    p_type_id UUID,
    p_from_account_id UUID,
    p_to_account_id UUID,
    p_attributes JSONB DEFAULT '{}',
    p_weight NUMERIC DEFAULT NULL,
    p_valid_from TIMESTAMPTZ DEFAULT NULL,
    p_valid_to TIMESTAMPTZ DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_rel_id UUID;
    v_type ussd_core.relationship_types%ROWTYPE;
BEGIN
    -- Get type info
    SELECT * INTO v_type FROM ussd_core.relationship_types WHERE type_id = p_type_id;
    
    IF NOT v_type.allows_cycles THEN
        -- Check for cycle
        IF EXISTS (
            SELECT 1 FROM ussd_core.agent_relationships
            WHERE from_account_id = p_to_account_id
              AND to_account_id = p_from_account_id
              AND status = 'ACTIVE'
        ) THEN
            RAISE EXCEPTION 'Circular relationship detected';
        END IF;
    END IF;
    
    INSERT INTO ussd_core.agent_relationships (
        type_id, from_account_id, to_account_id,
        attributes, weight, valid_from, valid_to
    ) VALUES (
        p_type_id, p_from_account_id, p_to_account_id,
        p_attributes, p_weight,
        COALESCE(p_valid_from, ussd_core.precise_now()),
        p_valid_to
    )
    RETURNING relationship_id INTO v_rel_id;
    
    RETURN v_rel_id;
END;
$$;

-- Find related accounts
CREATE OR REPLACE FUNCTION ussd_core.find_related_accounts(
    p_account_id UUID,
    p_type_id UUID DEFAULT NULL,
    p_direction VARCHAR DEFAULT 'BOTH'  -- 'OUT', 'IN', 'BOTH'
)
RETURNS TABLE (
    relationship_id UUID,
    related_account_id UUID,
    relationship_type_id UUID,
    direction VARCHAR,  -- 'OUTGOING' or 'INCOMING'
    attributes JSONB,
    weight NUMERIC
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    -- Outgoing relationships
    IF p_direction IN ('OUT', 'BOTH') THEN
        RETURN QUERY
        SELECT 
            ar.relationship_id,
            ar.to_account_id as related_account_id,
            ar.type_id as relationship_type_id,
            'OUTGOING'::VARCHAR as direction,
            ar.attributes,
            ar.weight
        FROM ussd_core.agent_relationships ar
        WHERE ar.from_account_id = p_account_id
          AND ar.status = 'ACTIVE'
          AND (p_type_id IS NULL OR ar.type_id = p_type_id)
          AND (ar.valid_to IS NULL OR ar.valid_to > ussd_core.precise_now());
    END IF;
    
    -- Incoming relationships
    IF p_direction IN ('IN', 'BOTH') THEN
        RETURN QUERY
        SELECT 
            ar.relationship_id,
            ar.from_account_id as related_account_id,
            ar.type_id as relationship_type_id,
            'INCOMING'::VARCHAR as direction,
            ar.attributes,
            ar.weight
        FROM ussd_core.agent_relationships ar
        WHERE ar.to_account_id = p_account_id
          AND ar.status = 'ACTIVE'
          AND (p_type_id IS NULL OR ar.type_id = p_type_id)
          AND (ar.valid_to IS NULL OR ar.valid_to > ussd_core.precise_now());
    END IF;
END;
$$;

-- Get descendants (for tree structures)
CREATE OR REPLACE FUNCTION ussd_core.get_relationship_descendants(
    p_account_id UUID,
    p_type_id UUID DEFAULT NULL
)
RETURNS TABLE (
    account_id UUID,
    depth INTEGER,
    path UUID[]
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE descendants AS (
        SELECT 
            ar.to_account_id as account_id,
            1 as depth,
            ARRAY[p_account_id, ar.to_account_id] as path
        FROM ussd_core.agent_relationships ar
        WHERE ar.from_account_id = p_account_id
          AND ar.status = 'ACTIVE'
          AND (p_type_id IS NULL OR ar.type_id = p_type_id)
        
        UNION ALL
        
        SELECT 
            ar.to_account_id,
            d.depth + 1,
            d.path || ar.to_account_id
        FROM ussd_core.agent_relationships ar
        JOIN descendants d ON ar.from_account_id = d.account_id
        WHERE ar.status = 'ACTIVE'
          AND (p_type_id IS NULL OR ar.type_id = p_type_id)
          AND NOT ar.to_account_id = ANY(d.path)  -- Prevent cycles
    )
    SELECT d.account_id, d.depth, d.path
    FROM descendants d;
END;
$$;

-- ----------------------------------------------------------------------------
-- 8. VIEWS
-- ----------------------------------------------------------------------------
CREATE VIEW ussd_core.active_relationships AS
SELECT 
    ar.*,
    rt.type_code,
    rt.type_name,
    from_acc.display_name as from_account_name,
    to_acc.display_name as to_account_name
FROM ussd_core.agent_relationships ar
JOIN ussd_core.relationship_types rt ON ar.type_id = rt.type_id
JOIN ussd_core.account_registry from_acc ON ar.from_account_id = from_acc.account_id
JOIN ussd_core.account_registry to_acc ON ar.to_account_id = to_acc.account_id
WHERE ar.status = 'ACTIVE'
  AND (ar.valid_to IS NULL OR ar.valid_to > ussd_core.precise_now());

-- ----------------------------------------------------------------------------
-- 9. INITIAL RELATIONSHIP TYPE (Generic)
-- ----------------------------------------------------------------------------
INSERT INTO ussd_core.relationship_types (type_code, type_name, is_directional, allows_cycles)
VALUES 
    ('PARENT_CHILD', 'Parent-Child Relationship', TRUE, FALSE),
    ('ASSOCIATE', 'Associate Relationship', FALSE, TRUE);

-- ----------------------------------------------------------------------------
-- 10. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_core.agent_relationships IS 
    'Generic graph relationships between accounts (business-agnostic)';
COMMENT ON TABLE ussd_core.relationship_types IS 
    'Configurable relationship types defined by applications';
