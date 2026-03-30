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

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.agent_relationships (
    -- Primary identifier
    relationship_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Relationship endpoints
    from_account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    to_account_id UUID NOT NULL REFERENCES ussd_core.account_registry(account_id),
    
    -- Relationship classification
    relationship_type VARCHAR(50) NOT NULL
        CHECK (relationship_type IN ('AGENT', 'GROUP_MEMBERSHIP', 'REFERRAL', 'PARENT_CHILD', 'GUARDIANSHIP')),
    
    -- Hierarchy support
    parent_relationship_id UUID REFERENCES ussd_core.agent_relationships(relationship_id),
    relationship_path LTREE,
    depth INTEGER DEFAULT 0,
    
    -- Permissions granted by this relationship
    permissions JSONB DEFAULT '{}',  -- e.g., {'can_view_balance': true, 'can_initiate_tx': false}
    
    -- Commission/rates (for agent relationships)
    commission_rate NUMERIC(5, 4),  -- e.g., 0.0150 = 1.5%
    commission_plan_id UUID,
    
    -- Limits
    daily_limit NUMERIC(20, 8),
    transaction_limit NUMERIC(20, 8),
    
    -- Risk and compliance
    risk_rating VARCHAR(20),
    kyc_verified BOOLEAN DEFAULT FALSE,
    kyc_verified_at TIMESTAMPTZ,
    
    -- Status
    status VARCHAR(20) DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'terminated')),
    
    -- Validity period
    valid_from TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    valid_to TIMESTAMPTZ,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    CHECK (from_account_id != to_account_id),  -- No self-relationships
    UNIQUE (from_account_id, to_account_id, relationship_type, valid_from)
);
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
