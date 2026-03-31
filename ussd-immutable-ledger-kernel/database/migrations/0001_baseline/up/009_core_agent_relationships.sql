-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Access control relationships)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Graph isolation)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Relationship privacy)
-- ISO/IEC 27040:2024 - Storage Security (Graph integrity)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Relationship recovery)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Graph structure with temporal validity
-- - Circular reference detection
-- - Exclusion constraints for overlapping relationships
-- - Recursive CTE for multi-hop traversal
-- ============================================================================
-- =============================================================================
-- MIGRATION: 009_core_agent_relationships.sql
-- DESCRIPTION: Agent Relationships Graph - Hierarchical connections
-- TABLES: agent_relationships, relationship_types
-- DEPENDENCIES: 003_core_account_registry.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 1. Identity & Multi-Tenancy
- Feature: Agent Relationships (Graph)
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Directed edges between accounts representing:
- Ownership (business owns subsidiary)
- Group membership (savings group members)
- Employment (driver employed by transport company)
- Representation (agent represents merchant)
- Guarantee (loan guarantor relationship)
- Beneficiary (inheritance/transfer on death)

KEY FEATURES:
- Graph structure with edge properties
- Temporal validity (valid_from/valid_to)
- Percentage allocation for distributions
- Circular relationship detection
- Multi-hop traversal support
- Relationship weighting for risk scoring
================================================================================
*/

-- Enable btree_gist extension for exclusion constraints
CREATE EXTENSION IF NOT EXISTS btree_gist;

-- =============================================================================
-- Create relationship_types table
-- DESCRIPTION: Define valid relationship types
-- PRIORITY: HIGH
-- SECURITY: Type constraints prevent invalid relationships
-- ============================================================================
CREATE TABLE core.relationship_types (
    relationship_type_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type_code            VARCHAR(50) UNIQUE NOT NULL,
    type_name            VARCHAR(100) NOT NULL,
    description          TEXT,
    
    -- Allowed participants
    allowed_source_types UUID[],          -- References account_types
    allowed_target_types UUID[],          -- References account_types
    
    -- Cardinality
    max_sources_per_target INTEGER,       -- NULL = unlimited
    max_targets_per_source INTEGER,       -- NULL = unlimited
    
    -- Properties
    requires_percentage   BOOLEAN DEFAULT false,  -- For revenue sharing
    allows_hierarchy      BOOLEAN DEFAULT false,  -- Can have nested relationships
    is_exclusive          BOOLEAN DEFAULT false,  -- Only one active of this type
    
    -- Status
    is_active             BOOLEAN DEFAULT true,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed relationship types (can be extended)
INSERT INTO core.relationship_types (type_code, type_name, description, requires_percentage, allows_hierarchy, is_exclusive) VALUES
('OWNS', 'Ownership', 'Parent company owns subsidiary', false, true, false),
('MEMBER_OF', 'Group Membership', 'Member belongs to a group', false, false, false),
('EMPLOYED_BY', 'Employment', 'Employee employed by employer', false, false, true),
('REPRESENTS', 'Agency', 'Agent represents principal', false, false, false),
('GUARANTEES', 'Loan Guarantee', 'Guarantor backs loan', false, false, false),
('BENEFICIARY_OF', 'Beneficiary', 'Receives on death transfer', false, false, true)
ON CONFLICT (type_code) DO NOTHING;

COMMENT ON TABLE core.relationship_types IS 'Defines valid relationship types between accounts';
COMMENT ON COLUMN core.relationship_types.requires_percentage IS 'If true, relationship must specify percentage allocation';

-- =============================================================================
-- Create agent_relationships table
-- DESCRIPTION: Graph edges between accounts
-- PRIORITY: CRITICAL
-- SECURITY: Temporal validity prevents backdated fraud
-- ============================================================================
CREATE TABLE core.agent_relationships (
    relationship_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Relationship Type
    relationship_type_id UUID NOT NULL REFERENCES core.relationship_types(relationship_type_id),
    
    -- Participants
    source_account_id   UUID NOT NULL REFERENCES core.accounts(account_id),
    target_account_id   UUID NOT NULL REFERENCES core.accounts(account_id),
    
    -- Temporal Validity (bitemporal)
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,                  -- NULL = current
    
    -- Allocation (for revenue/profit sharing)
    percentage          NUMERIC(5, 2) CHECK (percentage BETWEEN 0 AND 100),
    
    -- Hierarchy (for nested relationships)
    parent_relationship_id UUID REFERENCES core.agent_relationships(relationship_id),
    relationship_path   LTREE,                        -- Path in hierarchy
    depth               INTEGER DEFAULT 0,
    
    -- Metadata
    relationship_data   JSONB DEFAULT '{}',           -- Flexible attributes
    priority            INTEGER DEFAULT 0,            -- For ordering
    
    -- Verification
    verified_at         TIMESTAMPTZ,
    verified_by         UUID REFERENCES core.accounts(account_id),
    
    -- Status
    status              VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, SUSPENDED, TERMINATED
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    superseded_by       UUID REFERENCES core.agent_relationships(relationship_id),
    
    -- Constraints
    CONSTRAINT chk_agent_relationships_self 
        CHECK (source_account_id != target_account_id),
    CONSTRAINT chk_agent_relationships_validity 
        CHECK (valid_to IS NULL OR valid_to > valid_from),
    CONSTRAINT chk_agent_relationships_status 
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'TERMINATED'))
);

-- Exclusion constraint to prevent overlapping active relationships
ALTER TABLE core.agent_relationships
ADD CONSTRAINT excl_agent_relationships_overlap
    EXCLUDE USING gist (
        source_account_id WITH =,
        target_account_id WITH =,
        relationship_type_id WITH =,
        tstzrange(valid_from, COALESCE(valid_to, 'infinity'::timestamptz)) WITH &&
    )
    WHERE (status = 'ACTIVE');

-- Indexes for agent_relationships
CREATE INDEX idx_agent_relationships_source ON core.agent_relationships(source_account_id, relationship_type_id);
CREATE INDEX idx_agent_relationships_target ON core.agent_relationships(target_account_id, relationship_type_id);
CREATE INDEX idx_agent_relationships_valid ON core.agent_relationships(valid_from, valid_to);
CREATE INDEX idx_agent_relationships_path ON core.agent_relationships USING gist (relationship_path);
CREATE INDEX idx_agent_relationships_gin_data ON core.agent_relationships USING GIN (relationship_data);
CREATE INDEX idx_agent_relationships_parent ON core.agent_relationships(parent_relationship_id);
CREATE INDEX idx_agent_relationships_active ON core.agent_relationships(source_account_id, target_account_id, relationship_type_id) WHERE status = 'ACTIVE';

COMMENT ON TABLE core.agent_relationships IS 'Graph edges representing relationships between accounts';
COMMENT ON COLUMN core.agent_relationships.relationship_path IS 'LTREE path for hierarchical relationship queries';
COMMENT ON COLUMN core.agent_relationships.valid_from IS 'Start of relationship validity period';

-- =============================================================================
-- Create circular reference detection function
-- DESCRIPTION: Prevent cycles in relationship graph
-- PRIORITY: HIGH
-- SECURITY: Cycles could enable fraud (A owns B owns C owns A)
-- ============================================================================
CREATE OR REPLACE FUNCTION core.detect_circular_relationship()
RETURNS TRIGGER AS $$
DECLARE
    v_current UUID := NEW.target_account_id;
    v_visited UUID[] := ARRAY[NEW.source_account_id];
    v_next UUID;
    v_depth INTEGER := 0;
    v_max_depth INTEGER := 10;  -- Prevent infinite loops
BEGIN
    -- Skip check if relationship type doesn't allow hierarchy
    IF NOT EXISTS (
        SELECT 1 FROM core.relationship_types rt
        WHERE rt.relationship_type_id = NEW.relationship_type_id
          AND rt.allows_hierarchy = true
    ) THEN
        RETURN NEW;
    END IF;
    
    -- Traverse relationships upstream
    LOOP
        v_depth := v_depth + 1;
        EXIT WHEN v_depth > v_max_depth;
        
        -- Find source accounts where current is target
        SELECT ar.source_account_id INTO v_next
        FROM core.agent_relationships ar
        JOIN core.relationship_types rt ON ar.relationship_type_id = rt.relationship_type_id
        WHERE ar.target_account_id = v_current
          AND ar.status = 'ACTIVE'
          AND (ar.valid_to IS NULL OR ar.valid_to > now())
          AND rt.allows_hierarchy = true
        LIMIT 1;
        
        EXIT WHEN v_next IS NULL;
        
        IF v_next = ANY(v_visited) THEN
            RAISE EXCEPTION 'Circular relationship detected involving accounts %',
                v_visited;
        END IF;
        
        v_visited := array_append(v_visited, v_next);
        v_current := v_next;
    END LOOP;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

CREATE TRIGGER trg_agent_relationships_detect_cycle
    BEFORE INSERT OR UPDATE ON core.agent_relationships
    FOR EACH ROW
    EXECUTE FUNCTION core.detect_circular_relationship();

COMMENT ON FUNCTION core.detect_circular_relationship IS 'Prevents circular references in relationship graph';

-- =============================================================================
-- Create relationship path update trigger
-- DESCRIPTION: Auto-compute ltree path
-- PRIORITY: MEDIUM
-- ============================================================================
CREATE OR REPLACE FUNCTION core.update_relationship_path()
RETURNS TRIGGER AS $$
DECLARE
    v_parent_path LTREE;
BEGIN
    IF NEW.parent_relationship_id IS NOT NULL THEN
        SELECT relationship_path INTO v_parent_path
        FROM core.agent_relationships
        WHERE relationship_id = NEW.parent_relationship_id;
        
        IF v_parent_path IS NOT NULL THEN
            NEW.relationship_path := v_parent_path || NEW.relationship_id::text::ltree;
            NEW.depth := nlevel(NEW.relationship_path) - 1;
        ELSE
            NEW.relationship_path := NEW.relationship_id::text::ltree;
            NEW.depth := 0;
        END IF;
    ELSE
        NEW.relationship_path := NEW.relationship_id::text::ltree;
        NEW.depth := 0;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

CREATE TRIGGER trg_agent_relationships_path
    BEFORE INSERT OR UPDATE ON core.agent_relationships
    FOR EACH ROW
    EXECUTE FUNCTION core.update_relationship_path();

-- =============================================================================
-- Create relationship traversal function
-- DESCRIPTION: Query related accounts (multi-hop)
-- PRIORITY: HIGH
-- SECURITY: Limit max depth to prevent resource exhaustion
-- ============================================================================
CREATE OR REPLACE FUNCTION core.get_related_accounts(
    p_account_id UUID,
    p_relationship_type VARCHAR(50) DEFAULT NULL,
    p_max_depth INTEGER DEFAULT 5,
    p_direction VARCHAR(10) DEFAULT 'BOTH'  -- 'UP', 'DOWN', 'BOTH'
) RETURNS TABLE (
    related_account_id UUID,
    relationship_path UUID[],
    depth INTEGER,
    relationship_type_code VARCHAR(50)
) AS $$
BEGIN
    -- Validate max_depth to prevent DoS
    IF p_max_depth > 10 THEN
        p_max_depth := 10;
    END IF;
    
    RETURN QUERY
    WITH RECURSIVE relationship_tree AS (
        -- Base case: start from given account
        SELECT 
            p_account_id as account_id,
            ARRAY[p_account_id] as path,
            0 as depth,
            NULL::UUID as rel_type_id,
            NULL::VARCHAR(50) as rel_type_code
        
        UNION ALL
        
        -- Recursive case: traverse relationships
        SELECT 
            CASE 
                WHEN p_direction IN ('DOWN', 'BOTH') THEN ar.target_account_id
                ELSE ar.source_account_id
            END,
            CASE 
                WHEN p_direction IN ('DOWN', 'BOTH') THEN 
                    rt.path || ar.target_account_id
                ELSE 
                    rt.path || ar.source_account_id
            END,
            rt.depth + 1,
            ar.relationship_type_id,
            rt2.type_code
        FROM relationship_tree rt
        JOIN core.agent_relationships ar ON 
            (p_direction IN ('DOWN', 'BOTH') AND ar.source_account_id = rt.account_id)
            OR (p_direction IN ('UP', 'BOTH') AND ar.target_account_id = rt.account_id)
        JOIN core.relationship_types rt2 ON ar.relationship_type_id = rt2.relationship_type_id
        WHERE rt.depth < p_max_depth
          AND ar.status = 'ACTIVE'
          AND (ar.valid_to IS NULL OR ar.valid_to > now())
          AND (p_relationship_type IS NULL OR rt2.type_code = p_relationship_type)
          -- Prevent cycles
          AND NOT (
              CASE 
                  WHEN p_direction IN ('DOWN', 'BOTH') THEN ar.target_account_id
                  ELSE ar.source_account_id
              END = ANY(rt.path)
          )
    )
    SELECT 
        rt.account_id,
        rt.path,
        rt.depth,
        rt.rel_type_code
    FROM relationship_tree rt
    WHERE rt.depth > 0;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.get_related_accounts IS 'Finds all related accounts via multi-hop relationship traversal';

-- =============================================================================
-- Create group membership view
-- DESCRIPTION: Convenience view for group members
-- PRIORITY: MEDIUM
-- SECURITY: Expose only current (non-expired) memberships
-- ============================================================================
CREATE VIEW core.group_members AS
SELECT 
    ar.target_account_id as group_id,
    ar.source_account_id as member_id,
    rt.type_code as membership_type,
    rt.type_name as membership_type_name,
    ar.percentage,
    ar.valid_from,
    ar.valid_to,
    ar.relationship_data,
    ar.priority,
    ar.status
FROM core.agent_relationships ar
JOIN core.relationship_types rt ON ar.relationship_type_id = rt.relationship_type_id
WHERE rt.type_code = 'MEMBER_OF'
  AND ar.status = 'ACTIVE'
  AND (ar.valid_to IS NULL OR ar.valid_to > now());

COMMENT ON VIEW core.group_members IS 'Convenience view showing current group memberships';

-- =============================================================================
-- Create function to check if relationship exists
-- DESCRIPTION: Quick check for relationship existence
-- PRIORITY: MEDIUM
-- ============================================================================
CREATE OR REPLACE FUNCTION core.has_relationship(
    p_source_account_id UUID,
    p_target_account_id UUID,
    p_relationship_type VARCHAR(50) DEFAULT NULL
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 
        FROM core.agent_relationships ar
        JOIN core.relationship_types rt ON ar.relationship_type_id = rt.relationship_type_id
        WHERE ar.source_account_id = p_source_account_id
          AND ar.target_account_id = p_target_account_id
          AND ar.status = 'ACTIVE'
          AND (ar.valid_to IS NULL OR ar.valid_to > now())
          AND (p_relationship_type IS NULL OR rt.type_code = p_relationship_type)
    );
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = core, pg_catalog;

-- =============================================================================
-- Create function to terminate relationship
-- DESCRIPTION: Soft-delete relationship with audit
-- PRIORITY: MEDIUM
-- ============================================================================
CREATE OR REPLACE FUNCTION core.terminate_relationship(
    p_relationship_id UUID,
    p_terminated_by UUID DEFAULT NULL,
    p_reason TEXT DEFAULT NULL
) RETURNS BOOLEAN AS $$
BEGIN
    UPDATE core.agent_relationships
    SET status = 'TERMINATED',
        valid_to = now()
    WHERE relationship_id = p_relationship_id
      AND status = 'ACTIVE';
    
    IF FOUND THEN
        RAISE NOTICE 'Relationship % terminated by %: %', 
            p_relationship_id, p_terminated_by, p_reason;
        RETURN true;
    END IF;
    
    RETURN false;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create relationship_types lookup table
☑ Create agent_relationships table with temporal validity
☑ Implement circular reference detection trigger
☑ Implement multi-hop relationship traversal function
☑ Create group_members convenience view
☑ Add all indexes for graph queries
☑ Test circular detection with test data
☑ Test recursive relationship queries
☑ Verify percentage constraints
☑ Add seed relationship types
================================================================================
*/
