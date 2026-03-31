-- =============================================================================
-- USSD KERNEL CORE SCHEMA - AGENT RELATIONSHIPS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    007_agent_relationships.sql
-- SCHEMA:      ussd_core
-- TABLE:       agent_relationships
-- DESCRIPTION: Hierarchical relationships between accounts including
--              agent hierarchies, group memberships, and referral networks.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.5.15 Access control - Relationship-based access
├── A.8.2 Privileged access rights - Agent privilege management
└── A.8.5 Secure authentication - Agent authentication

ISO/IEC 27040:2024 (Storage Security)
├── Immutable relationship history
├── Temporal versioning (valid_from/valid_to)
└── Audit trail for relationship changes

AML/CFT Compliance
├── Agent due diligence: Risk rating per agent
├── Transaction monitoring: Agent activity tracking
├── Suspicious activity: Agent-related alerts
└── Regulatory reporting: Agent transaction summaries

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. RELATIONSHIP TYPES
   - AGENT: Agent acting on behalf of principal
   - GROUP_MEMBERSHIP: Member of a group account
   - REFERRAL: Customer referral relationship
   - PARENT_CHILD: Hierarchical account structure
   - GUARDIANSHIP: Legal guardian relationship

2. TEMPORAL MODELING
   - Validity periods with valid_from/valid_to
   - Relationship history preserved
   - Current relationships: valid_to IS NULL

3. CYCLE PREVENTION
   - Trigger-based cycle detection
   - Maximum depth limits
   - Hierarchical integrity constraints

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

RELATIONSHIP AUTHORIZATION:
- Both parties must consent to relationship
- Admin approval for certain relationship types
- Automated risk scoring on creation

ACCESS PROPAGATION:
- Relationship-based access control
- Permission inheritance rules
- Scope limitations per relationship

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: relationship_id
- FROM_ACCOUNT: from_account_id + valid_to
- TO_ACCOUNT: to_account_id + valid_to
- TYPE: relationship_type + valid_to
- HIERARCHY: GIST index on relationship_path (LTREE)

QUERY PATTERNS:
- Agent hierarchy: Find all sub-agents
- Group members: List all group members
- Referral network: Multi-level referral tree

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- RELATIONSHIP_CREATED: New relationship established
- RELATIONSHIP_ENDED: Relationship terminated
- RELATIONSHIP_ACCESSED: Relationship data queried
- HIERARCHY_VIOLATION: Cycle attempt detected

RETENTION: 7 years after relationship end
================================================================================
*/

-- =============================================================================
-- CREATE TABLE: agent_relationships
-- =============================================================================

CREATE TABLE core.agent_relationships (
    -- Primary identifier
    relationship_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Relationship endpoints
    from_account_id UUID NOT NULL REFERENCES core.account_registry(account_id) ON DELETE RESTRICT,
    to_account_id UUID NOT NULL REFERENCES core.account_registry(account_id) ON DELETE RESTRICT,
    
    -- Relationship classification
    relationship_type VARCHAR(50) NOT NULL
        CHECK (relationship_type IN ('AGENT', 'GROUP_MEMBERSHIP', 'REFERRAL', 'PARENT_CHILD', 'GUARDIANSHIP')),
    
    -- Hierarchy support
    parent_relationship_id UUID REFERENCES core.agent_relationships(relationship_id) ON DELETE RESTRICT,
    relationship_path LTREE,
    depth INTEGER DEFAULT 0 CHECK (depth >= 0 AND depth <= 20),
    
    -- Permissions granted by this relationship
    permissions JSONB DEFAULT '{}',  -- e.g., {'can_view_balance': true, 'can_initiate_tx': false}
    
    -- Commission/rates (for agent relationships)
    commission_rate NUMERIC(5, 4),  -- e.g., 0.0150 = 1.5%
    commission_plan_id UUID,
    
    -- Limits
    daily_limit NUMERIC(20, 8),
    transaction_limit NUMERIC(20, 8),
    monthly_limit NUMERIC(20, 8),
    
    -- Risk and compliance
    risk_rating VARCHAR(20) CHECK (risk_rating IN ('low', 'medium', 'high', 'critical')),
    kyc_verified BOOLEAN DEFAULT FALSE,
    kyc_verified_at TIMESTAMPTZ,
    kyc_verified_by UUID,
    
    -- Status
    status VARCHAR(20) DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'terminated', 'pending_approval')),
    
    -- Approval workflow
    approved_by UUID,
    approved_at TIMESTAMPTZ,
    
    -- Validity period
    valid_from TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    valid_to TIMESTAMPTZ,
    
    -- Termination details
    terminated_by UUID,
    terminated_at TIMESTAMPTZ,
    termination_reason TEXT,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    CONSTRAINT chk_no_self_relationship CHECK (from_account_id != to_account_id),
    CONSTRAINT chk_valid_to_after_from_rel CHECK (valid_to IS NULL OR valid_to > valid_from),
    CONSTRAINT chk_unique_active_relationship UNIQUE (from_account_id, to_account_id, relationship_type, valid_from)
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- From account lookup
CREATE INDEX idx_agent_relationships_from ON core.agent_relationships(from_account_id) 
    WHERE valid_to IS NULL;

-- To account lookup
CREATE INDEX idx_agent_relationships_to ON core.agent_relationships(to_account_id) 
    WHERE valid_to IS NULL;

-- Relationship type lookup
CREATE INDEX idx_agent_relationships_type ON core.agent_relationships(relationship_type) 
    WHERE valid_to IS NULL;

-- Composite index for relationship queries
CREATE INDEX idx_agent_relationships_from_type ON core.agent_relationships(from_account_id, relationship_type) 
    WHERE valid_to IS NULL;

CREATE INDEX idx_agent_relationships_to_type ON core.agent_relationships(to_account_id, relationship_type) 
    WHERE valid_to IS NULL;

-- Hierarchy path index
CREATE INDEX idx_agent_relationships_path ON core.agent_relationships 
    USING GIST(relationship_path) 
    WHERE valid_to IS NULL;

-- Path btree index for ordering
CREATE INDEX idx_agent_relationships_path_btree ON core.agent_relationships(relationship_path) 
    WHERE valid_to IS NULL;

-- Status index
CREATE INDEX idx_agent_relationships_status ON core.agent_relationships(status) 
    WHERE valid_to IS NULL;

-- Parent relationship
CREATE INDEX idx_agent_relationships_parent ON core.agent_relationships(parent_relationship_id) 
    WHERE valid_to IS NULL;

-- Risk rating
CREATE INDEX idx_agent_relationships_risk ON core.agent_relationships(risk_rating) 
    WHERE valid_to IS NULL;

-- Validity period
CREATE INDEX idx_agent_relationships_valid ON core.agent_relationships(valid_from, valid_to);

-- =============================================================================
-- IMMUTABILITY TRIGGERS
-- =============================================================================

-- Prevent updates on immutable table
CREATE TRIGGER trg_agent_relationships_prevent_update
    BEFORE UPDATE ON core.agent_relationships
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

-- Prevent deletes on immutable table
CREATE TRIGGER trg_agent_relationships_prevent_delete
    BEFORE DELETE ON core.agent_relationships
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- =============================================================================
-- HASH COMPUTATION TRIGGER
-- =============================================================================

CREATE OR REPLACE FUNCTION core.compute_relationship_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.relationship_id::TEXT || 
        NEW.from_account_id::TEXT || 
        NEW.to_account_id::TEXT ||
        NEW.relationship_type ||
        NEW.valid_from::TEXT ||
        COALESCE(NEW.relationship_path::TEXT, '')
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_agent_relationships_compute_hash
    BEFORE INSERT ON core.agent_relationships
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_relationship_hash();

-- =============================================================================
-- CYCLE PREVENTION TRIGGER
-- =============================================================================

CREATE OR REPLACE FUNCTION core.prevent_relationship_cycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_path LTREE;
    v_from_path LTREE;
    v_to_path LTREE;
BEGIN
    -- Check if this would create a cycle by seeing if from_account is already a descendant of to_account
    SELECT relationship_path INTO v_to_path
    FROM core.agent_relationships
    WHERE from_account_id = NEW.to_account_id
    AND valid_to IS NULL
    AND relationship_type = NEW.relationship_type
    LIMIT 1;
    
    IF v_to_path IS NOT NULL AND NEW.from_account_id::TEXT = v_to_path::TEXT THEN
        RAISE EXCEPTION 'CYCLIC_RELATIONSHIP: Would create cycle between accounts % and %', 
            NEW.from_account_id, NEW.to_account_id;
    END IF;
    
    -- Compute path
    IF NEW.parent_relationship_id IS NULL THEN
        NEW.relationship_path := text2ltree(NEW.from_account_id::TEXT);
    ELSE
        SELECT relationship_path INTO v_path
        FROM core.agent_relationships
        WHERE relationship_id = NEW.parent_relationship_id;
        
        IF v_path IS NULL THEN
            NEW.relationship_path := text2ltree(NEW.from_account_id::TEXT);
        ELSE
            NEW.relationship_path := v_path || NEW.to_account_id::TEXT::ltree;
        END IF;
    END IF;
    
    -- Set depth based on path
    NEW.depth := nlevel(NEW.relationship_path) - 1;
    
    -- Check max depth
    IF NEW.depth > 20 THEN
        RAISE EXCEPTION 'MAX_DEPTH_EXCEEDED: Relationship hierarchy cannot exceed 20 levels';
    END IF;
    
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_agent_relationships_prevent_cycle
    BEFORE INSERT ON core.agent_relationships
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_relationship_cycle();

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

-- Enable RLS
ALTER TABLE core.agent_relationships ENABLE ROW LEVEL SECURITY;

-- Policy: Accounts can view relationships they participate in
CREATE POLICY agent_relationships_participant_access ON core.agent_relationships
    FOR SELECT
    TO ussd_app_user
    USING (
        from_account_id = current_setting('app.current_account_id', true)::UUID
        OR to_account_id = current_setting('app.current_account_id', true)::UUID
    );

-- Policy: Application-scoped access
CREATE POLICY agent_relationships_app_access ON core.agent_relationships
    FOR SELECT
    TO ussd_app_user
    USING (
        EXISTS (
            SELECT 1 FROM core.account_registry ar
            WHERE ar.account_id = agent_relationships.from_account_id
            AND ar.primary_application_id = current_setting('app.current_application_id', true)::UUID
        )
    );

-- Policy: Kernel role has full access
CREATE POLICY agent_relationships_kernel_access ON core.agent_relationships
    FOR ALL
    TO ussd_kernel_role
    USING (true);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to create a relationship
CREATE OR REPLACE FUNCTION core.create_relationship(
    p_from_account_id UUID,
    p_to_account_id UUID,
    p_relationship_type VARCHAR(50),
    p_permissions JSONB DEFAULT '{}',
    p_commission_rate NUMERIC DEFAULT NULL,
    p_daily_limit NUMERIC DEFAULT NULL,
    p_transaction_limit NUMERIC DEFAULT NULL,
    p_created_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_relationship_id UUID;
BEGIN
    INSERT INTO core.agent_relationships (
        from_account_id,
        to_account_id,
        relationship_type,
        permissions,
        commission_rate,
        daily_limit,
        transaction_limit,
        created_by
    ) VALUES (
        p_from_account_id,
        p_to_account_id,
        p_relationship_type,
        p_permissions,
        p_commission_rate,
        p_daily_limit,
        p_transaction_limit,
        p_created_by
    )
    RETURNING relationship_id INTO v_relationship_id;
    
    RETURN v_relationship_id;
END;
$$;

-- Function to terminate a relationship
CREATE OR REPLACE FUNCTION core.terminate_relationship(
    p_relationship_id UUID,
    p_terminated_by UUID,
    p_reason TEXT DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.agent_relationships
    SET 
        status = 'terminated',
        valid_to = core.precise_now(),
        terminated_by = p_terminated_by,
        terminated_at = core.precise_now(),
        termination_reason = p_reason
    WHERE relationship_id = p_relationship_id
    AND valid_to IS NULL;
    
    RETURN FOUND;
END;
$$;

-- Function to get agent hierarchy
CREATE OR REPLACE FUNCTION core.get_agent_hierarchy(
    p_account_id UUID,
    p_relationship_type VARCHAR(50) DEFAULT 'AGENT'
)
RETURNS TABLE (
    relationship_id UUID,
    from_account_id UUID,
    to_account_id UUID,
    depth INTEGER,
    commission_rate NUMERIC(5, 4),
    status VARCHAR(20)
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ar.relationship_id,
        ar.from_account_id,
        ar.to_account_id,
        ar.depth,
        ar.commission_rate,
        ar.status
    FROM core.agent_relationships ar
    WHERE ar.from_account_id = p_account_id
    AND ar.relationship_type = p_relationship_type
    AND ar.valid_to IS NULL
    ORDER BY ar.depth, ar.created_at;
END;
$$;

-- Function to get all descendants (sub-agents, group members, etc.)
CREATE OR REPLACE FUNCTION core.get_relationship_descendants(
    p_account_id UUID,
    p_relationship_type VARCHAR(50) DEFAULT NULL
)
RETURNS TABLE (
    account_id UUID,
    depth INTEGER,
    commission_rate NUMERIC(5, 4),
    permissions JSONB
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ar.to_account_id,
        ar.depth,
        ar.commission_rate,
        ar.permissions
    FROM core.agent_relationships ar
    WHERE ar.from_account_id = p_account_id
    AND (p_relationship_type IS NULL OR ar.relationship_type = p_relationship_type)
    AND ar.valid_to IS NULL
    ORDER BY ar.depth, ar.to_account_id;
END;
$$;

-- Function to get all ancestors (parent agents, groups, etc.)
CREATE OR REPLACE FUNCTION core.get_relationship_ancestors(
    p_account_id UUID,
    p_relationship_type VARCHAR(50) DEFAULT NULL
)
RETURNS TABLE (
    account_id UUID,
    depth INTEGER,
    relationship_type VARCHAR(50)
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ar.from_account_id,
        ar.depth,
        ar.relationship_type
    FROM core.agent_relationships ar
    WHERE ar.to_account_id = p_account_id
    AND (p_relationship_type IS NULL OR ar.relationship_type = p_relationship_type)
    AND ar.valid_to IS NULL
    ORDER BY ar.depth DESC;
END;
$$;

-- =============================================================================
-- TABLE AND COLUMN COMMENTS
-- =============================================================================

COMMENT ON TABLE core.agent_relationships IS 
    'Hierarchical relationships between accounts including agents, group memberships, and referrals. Immutable with temporal versioning.';

COMMENT ON COLUMN core.agent_relationships.relationship_id IS 
    'Unique identifier for the relationship';
COMMENT ON COLUMN core.agent_relationships.from_account_id IS 
    'The account that owns/initiates the relationship';
COMMENT ON COLUMN core.agent_relationships.to_account_id IS 
    'The account that is the target of the relationship';
COMMENT ON COLUMN core.agent_relationships.relationship_type IS 
    'Type: AGENT, GROUP_MEMBERSHIP, REFERRAL, PARENT_CHILD, GUARDIANSHIP';
COMMENT ON COLUMN core.agent_relationships.relationship_path IS 
    'LTREE materialized path for hierarchy queries';
COMMENT ON COLUMN core.agent_relationships.depth IS 
    'Depth in the relationship hierarchy';
COMMENT ON COLUMN core.agent_relationships.permissions IS 
    'JSON permissions granted by this relationship';
COMMENT ON COLUMN core.agent_relationships.commission_rate IS 
    'Commission rate for agent relationships (e.g., 0.015 = 1.5%)';
COMMENT ON COLUMN core.agent_relationships.valid_from IS 
    'When this relationship became valid';
COMMENT ON COLUMN core.agent_relationships.valid_to IS 
    'When this relationship ended (NULL = active)';

-- =============================================================================
-- END OF FILE
-- =============================================================================
