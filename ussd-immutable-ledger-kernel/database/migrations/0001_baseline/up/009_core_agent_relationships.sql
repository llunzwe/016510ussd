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

-- =============================================================================
-- TODO: Create relationship_types table
-- DESCRIPTION: Define valid relationship types
-- PRIORITY: HIGH
-- SECURITY: Type constraints prevent invalid relationships
-- ============================================================================
-- TODO: [REL-001] Create core.relationship_types table
-- INSTRUCTIONS:
--   - Immutable catalog of relationship types
--   - Defines allowed source/target account types
--   - Specifies cardinality constraints
--   - ERROR HANDLING: Validate type constraints
-- COMPLIANCE: ISO/IEC 27001 (Access Control Classification)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.relationship_types (
--       relationship_type_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       type_code            VARCHAR(50) UNIQUE NOT NULL,
--       type_name            VARCHAR(100) NOT NULL,
--       description          TEXT,
--       
--       -- Allowed participants
--       allowed_source_types UUID[],          -- References account_types
--       allowed_target_types UUID[],          -- References account_types
--       
--       -- Cardinality
--       max_sources_per_target INTEGER,       -- NULL = unlimited
--       max_targets_per_source INTEGER,       -- NULL = unlimited
--       
--       -- Properties
--       requires_percentage   BOOLEAN DEFAULT false,  -- For revenue sharing
--       allows_hierarchy      BOOLEAN DEFAULT false,  -- Can have nested relationships
--       is_exclusive          BOOLEAN DEFAULT false,  -- Only one active of this type
--       
--       -- Status
--       is_active             BOOLEAN DEFAULT true,
--       created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
--   );
--
-- SEED DATA (in 055_seed_data.sql):
--   - OWNS: Ownership relationship
--   - MEMBER_OF: Group membership
--   - EMPLOYED_BY: Employment
--   - REPRESENTS: Agency/representation
--   - GUARANTEES: Loan guarantee
--   - BENEFICIARY_OF: Transfer on death beneficiary

-- =============================================================================
-- TODO: Create agent_relationships table
-- DESCRIPTION: Graph edges between accounts
-- PRIORITY: CRITICAL
-- SECURITY: Temporal validity prevents backdated fraud
-- ============================================================================
-- TODO: [REL-002] Create core.agent_relationships table
-- INSTRUCTIONS:
--   - Versioned (valid_from/valid_to) for temporal accuracy
--   - Supports percentage allocation
--   - Includes relationship metadata
--   - Prevents circular references via trigger
--   - RLS POLICY: Tenant isolation
--   - EXCLUSION CONSTRAINT: Prevent overlapping active relationships
-- COMPLIANCE: ISO/IEC 27040 (Temporal Integrity)
--
-- TABLE STRUCTURE OUTLINE:
--   CREATE TABLE core.agent_relationships (
--       relationship_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--       
--       -- Relationship Type
--       relationship_type_id UUID NOT NULL REFERENCES core.relationship_types(relationship_type_id),
--       
--       -- Participants
--       source_account_id   UUID NOT NULL REFERENCES core.accounts(account_id),
--       target_account_id   UUID NOT NULL REFERENCES core.accounts(account_id),
--       
--       -- Temporal Validity (bitemporal)
--       valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       valid_to            TIMESTAMPTZ,                  -- NULL = current
--       
--       -- Allocation (for revenue/profit sharing)
--       percentage          NUMERIC(5, 2) CHECK (percentage BETWEEN 0 AND 100),
--       
--       -- Hierarchy (for nested relationships)
--       parent_relationship_id UUID REFERENCES core.agent_relationships(relationship_id),
--       relationship_path   LTREE,                        -- Path in hierarchy
--       depth               INTEGER DEFAULT 0,
--       
--       -- Metadata
--       relationship_data   JSONB DEFAULT '{}',           -- Flexible attributes
--       priority            INTEGER DEFAULT 0,            -- For ordering
--       
--       -- Verification
--       verified_at         TIMESTAMPTZ,
--       verified_by         UUID REFERENCES core.accounts(account_id),
--       
--       -- Status
--       status              VARCHAR(20) DEFAULT 'ACTIVE', -- ACTIVE, SUSPENDED, TERMINATED
--       
--       -- Audit
--       created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
--       created_by          UUID REFERENCES core.accounts(account_id),
--       superseded_by       UUID REFERENCES core.agent_relationships(relationship_id)
--   );
--
-- CONSTRAINTS:
--   - CHECK (source_account_id != target_account_id)  -- No self-relationships
--   - EXCLUDE USING gist (source_account_id WITH =, target_account_id WITH =, 
--                         relationship_type_id WITH =, 
--                         valid_during WITH &&) WHERE (valid_to IS NULL)
--   -- Prevents overlapping active relationships of same type

-- =============================================================================
-- TODO: Create circular reference detection function
-- DESCRIPTION: Prevent cycles in relationship graph
-- PRIORITY: HIGH
-- SECURITY: Cycles could enable fraud (A owns B owns C owns A)
-- ============================================================================
-- TODO: [REL-003] Create detect_circular_relationship function
-- INSTRUCTIONS:
--   - Trigger on INSERT/UPDATE of agent_relationships
--   - Traverse graph from target back to source
--   - Raise exception if cycle detected
--   - ERROR HANDLING: Limit traversal depth to prevent DoS
-- COMPLIANCE: ISO/IEC 27001 (Fraud Prevention)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.detect_circular_relationship()
--   RETURNS TRIGGER AS $$
--   DECLARE
--       v_current UUID := NEW.target_account_id;
--       v_visited UUID[] := ARRAY[NEW.source_account_id];
--       v_next UUID;
--   BEGIN
--       -- Traverse relationships upstream
--       LOOP
--           -- Find source accounts where current is target
--           SELECT source_account_id INTO v_next
--           FROM core.agent_relationships
--           WHERE target_account_id = v_current
--             AND status = 'ACTIVE'
--             AND (valid_to IS NULL OR valid_to > now())
--           LIMIT 1;
--           
--           EXIT WHEN v_next IS NULL;
--           
--           IF v_next = ANY(v_visited) THEN
--               RAISE EXCEPTION 'Circular relationship detected involving accounts %',
--                   v_visited;
--           END IF;
--           
--           v_visited := array_append(v_visited, v_next);
--           v_current := v_next;
--       END LOOP;
--       
--       RETURN NEW;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create relationship traversal function
-- DESCRIPTION: Query related accounts (multi-hop)
-- PRIORITY: HIGH
-- SECURITY: Limit max depth to prevent resource exhaustion
-- ============================================================================
-- TODO: [REL-004] Create get_related_accounts function
-- INSTRUCTIONS:
--   - Recursive CTE to find all related accounts
--   - Support max depth limit
--   - Filter by relationship type
--   - Return path and distance
--   - ERROR HANDLING: Statement timeout for large graphs
-- COMPLIANCE: ISO/IEC 27031 (Query Performance)
--
-- FUNCTION OUTLINE:
--   CREATE OR REPLACE FUNCTION core.get_related_accounts(
--       p_account_id UUID,
--       p_relationship_type VARCHAR(50) DEFAULT NULL,
--       p_max_depth INTEGER DEFAULT 5,
--       p_direction VARCHAR(10) DEFAULT 'BOTH'  -- 'UP', 'DOWN', 'BOTH'
--   ) RETURNS TABLE (
--       related_account_id UUID,
--       relationship_path UUID[],
--       depth INTEGER,
--       relationship_type VARCHAR(50)
--   ) AS $$
--   BEGIN
--       RETURN QUERY
--       WITH RECURSIVE relationship_tree AS (
--           -- Base case
--           SELECT 
--               source_account_id as account_id,
--               ARRAY[source_account_id] as path,
--               0 as depth,
--               NULL::UUID as rel_type
--           WHERE p_direction IN ('UP', 'BOTH')
--           
--           UNION ALL
--           
--           -- Recursive case
--           SELECT 
--               ar.source_account_id,
--               rt.path || ar.source_account_id,
--               rt.depth + 1,
--               ar.relationship_type_id
--           FROM relationship_tree rt
--           JOIN core.agent_relationships ar ON ar.target_account_id = rt.account_id
--           WHERE rt.depth < p_max_depth
--             AND ar.status = 'ACTIVE'
--             AND (ar.valid_to IS NULL OR ar.valid_to > now())
--       )
--       SELECT * FROM relationship_tree WHERE depth > 0;
--   END;
--   $$ LANGUAGE plpgsql;

-- =============================================================================
-- TODO: Create group membership view
-- DESCRIPTION: Convenience view for group members
-- PRIORITY: MEDIUM
-- SECURITY: Expose only current (non-expired) memberships
-- ============================================================================
-- TODO: [REL-005] Create group_members view
-- INSTRUCTIONS:
--   - Show all members of each group
--   - Include membership percentage if applicable
--   - Filter to current (non-expired) memberships only
--   - RLS POLICY: Apply tenant filter
-- COMPLIANCE: ISO/IEC 27018 (Current Data Only)
--
-- VIEW DEFINITION:
--   CREATE VIEW core.group_members AS
--   SELECT 
--       ar.target_account_id as group_id,
--       ar.source_account_id as member_id,
--       rt.type_name as membership_type,
--       ar.percentage,
--       ar.valid_from,
--       ar.valid_to,
--       ar.relationship_data
--   FROM core.agent_relationships ar
--   JOIN core.relationship_types rt ON ar.relationship_type_id = rt.relationship_type_id
--   WHERE rt.type_code = 'MEMBER_OF'
--     AND ar.status = 'ACTIVE'
--     AND (ar.valid_to IS NULL OR ar.valid_to > now());

-- =============================================================================
-- TODO: Create relationship indexes
-- DESCRIPTION: Optimize graph queries
-- PRIORITY: HIGH
-- SECURITY: Index on status for active relationship queries
-- ============================================================================
-- TODO: [REL-006] Create relationship indexes
-- INDEX LIST:
--   - PRIMARY KEY (relationship_id)
--   - INDEX on (source_account_id, relationship_type_id)
--   - INDEX on (target_account_id, relationship_type_id)
--   - INDEX on (valid_from, valid_to)
--   - GiST INDEX on relationship_path
--   - GIN INDEX on relationship_data

/*
================================================================================
MIGRATION CHECKLIST:
□ Create relationship_types lookup table
□ Create agent_relationships table with temporal validity
□ Implement circular reference detection trigger
□ Implement multi-hop relationship traversal function
□ Create group_members convenience view
□ Add all indexes for graph queries
□ Test circular detection with test data
□ Test recursive relationship queries
□ Verify percentage constraints
□ Add seed relationship types
================================================================================
*/
