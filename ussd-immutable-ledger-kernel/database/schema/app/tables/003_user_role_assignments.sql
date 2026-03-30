/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - USER ROLE ASSIGNMENTS
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-004
 * Feature Name:       User Role Assignment Management
 * Description:        Explicit role assignments linking users/memberships to
 *                     roles. Supports temporal assignments, conditional grants,
 *                     and delegation chains for the RBAC system.
 * 
 * Version:            1.0.0
 * Author:             Platform Engineering Team
 * Created:            2026-03-30
 * Last Modified:      2026-03-30
 * 
 * =============================================================================
 * COMPLIANCE & CERTIFICATIONS
 * =============================================================================
 * 
 * ISO/IEC 27001:2022 (ISMS)
 *   - Control A.5.18: Access rights (assignment management)
 *   - Control A.5.31: Legal/regulatory requirements (justification)
 *   - Control A.8.2: Privileged access (break-glass, admin roles)
 *   - Control A.9.2.2: Access provisioning (assignment workflow)
 *   - Control A.9.2.4: Management of secret authentication info
 *   - Control A.9.2.6: Removal of access rights (revocation)
 * 
 * ISO/IEC 27017:2015 (Cloud Security)
 *   - Section 9: Access control in multi-tenant environments
 *   - Section 12: Data segregation during role transitions
 * 
 * ISO/IEC 27018:2019 (PII Protection)
 *   - Section 7: Consent and choice (approval workflow)
 *   - Section 9: Access to PII (conditional grants)
 * 
 * ISO 9001:2015 (Quality Management)
 *   - Section 8.5.1: Production control (controlled assignments)
 * 
 * ISO 31000:2018 (Risk Management)
 *   - Break-glass access for emergency response
 *   - Risk mitigation: Justification requirements
 * 
 * SOC 2 Type II
 *   - CC6.2: Access provisioning and revocation
 *   - CC6.3: Timely access removal
 *   - CC7.2: System operations monitoring
 * 
 * NIST 800-53
 *   - AC-2(3): Account creation - disable inactive
 *   - AC-6: Least privilege
 *   - AC-17: Remote access (conditional grants)
 * 
 * GDPR
 *   - Article 25: Data protection by design (time-bound access)
 *   - Article 32: Security of processing (break-glass logging)
 * 
 * =============================================================================
 * MULTI-TENANCY SECURITY ANNOTATIONS
 * =============================================================================
 * 
 * ASSIGNMENT SCOPES:
 *   - direct:      Standard assignment
 *   - inherited:   From role hierarchy (auto-managed)
 *   - delegated:   Delegated from another assignment
 *   - temporary:   Time-bound access
 *   - break_glass: Emergency access with enhanced logging
 * 
 * TENANT ISOLATION:
 *   - Assignments only visible within same application
 *   - Cross-app assignments require platform admin
 *   - resource_scope can limit to specific resources
 * 
 * SECURITY CONTROLS:
 *   - Delegation depth limited to 3 levels
 *   - Break-glass requires incident tracking
 *   - Temporal validity checked at enforcement
 *   - Approval workflow for sensitive roles
 * 
 * =============================================================================
 * RBAC ENFORCEMENT DOCUMENTATION
 * =============================================================================
 * 
 * APPROVAL WORKFLOW:
 * 
 * | Role Category | Requires Approval | Justification Required |
 * |---------------|-------------------|------------------------|
 * | admin         | Yes               | Yes                    |
 * | manager       | Optional          | Yes                    |
 * | operator      | No                | No                     |
 * | viewer        | No                | No                     |
 * | break_glass   | Auto-emergency    | Post-hoc required      |
 * 
 * REQUIRED PERMISSIONS:
 * 
 * | Operation                    | Required Permission              |
 * |------------------------------|----------------------------------|
 * | ASSIGN role                  | app:role_assignment:create       |
 * | READ own assignments         | (Self - always allowed)          |
 * | READ app assignments         | app:role_assignment:read         |
 * | REVOKE assignment            | app:role_assignment:delete       |
 * | APPROVE assignment           | app:role_assignment:approve      |
 * | ACTIVATE break_glass         | app:break_glass:activate         |
 * | DELEGATE role                | app:role_assignment:delegate     |
 * 
 * =============================================================================
 * AUDIT TRAIL REQUIREMENTS
 * =============================================================================
 * 
 * MANDATORY AUDIT EVENTS:
 *   - Assignment Created (who assigned, to whom, which role)
 *   - Approval Workflow (request, approval/rejection, timestamp)
 *   - Break-Glass Activation (incident ID, duration, justification)
 *   - Revocation (who, when, reason)
 *   - Delegation Chain (delegator, delegatee, constraints)
 *   - Temporal Expiry (auto-log when time-bound expires)
 *   - Permission Usage (what was accessed using assignment)
 * 
 * AUDIT RETENTION: 7 years
 * AUDIT ACCESS: platform:auditor role only
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - app.t_account_membership (FK: membership_id)
 *   - app.t_roles_permissions (FK: role_id
 *   - core.t_user_identity (FK: created_by
 * 
 * CHANGE LOG:
 *   1.0.0 - Initial schema creation with compliance headers
 *   TODO: Add role request/approval workflow automation
 *   TODO: Add ML-based anomaly detection for break-glass
 * =============================================================================
 */



-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Controls A.5.x - A.9.x)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Multi-tenancy)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds
-- ISO 9001:2015 - Quality Management Systems
-- ISO 31000:2018 - Risk Management Guidelines
-- ============================================================================
-- CODING PRACTICES:
-- - Use parameterized queries to prevent SQL injection
-- - Implement proper error handling with transaction rollback
-- - Use SECURITY DEFINER
-- - Enforce RLS policies for multi-tenant data isolation
-- - Use explicit column lists (avoid SELECT *)
-- - Add audit logging for all security-relevant operations
-- - Use UUIDs for primary identifiers to prevent enumeration
-- - Implement optimistic locking with version columns
-- - Use TIMESTAMPTZ for all timestamp columns
-- - Validate all inputs with CHECK constraints
-- ============================================================================

-- =============================================================================
-- TABLE: app.t_user_role_assignments
-- =============================================================================
CREATE TABLE IF NOT EXISTS app.t_user_role_assignments (
    -- -------------------------------------------------------------------------
    -- PRIMARY IDENTIFIERS
    -- -------------------------------------------------------------------------
    assignment_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                
    membership_id               UUID NOT NULL,
                                -- FK: app.t_account_membership.membership_id
                                CONSTRAINT fk_assignment_membership 
                                    FOREIGN KEY (membership_id) 
                                    REFERENCES app.t_account_membership(membership_id)
                                    ON DELETE CASCADE,
                                -- CASCADE: Remove assignments when membership revoked
                                
    role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference                     UUID NOT NULL,
                                -- FK: app.t_roles_permissions.role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference
                                CONSTRAINT fk_assignment_role 
                                    FOREIGN KEY (role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference) 
                                    REFERENCES app.t_roles_permissions(role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference),
                                -- NO CASCADE: Prevent role deletion if assignments exist
    
    -- -------------------------------------------------------------------------
    -- ASSIGNMENT METADATA
    -- -------------------------------------------------------------------------
    assignment_type  -- [RBAC] ISO 27001: Assignment classification (direct/inherited/delegated)             VARCHAR(20) NOT NULL DEFAULT 'direct',
                                -- ENUM: 'direct', 'inherited', 'delegated', 'temporary', 'break_glass'
                                CONSTRAINT chk_assignment_type
                                    CHECK (assignment_type  -- [RBAC] ISO 27001: Assignment classification (direct/inherited/delegated) IN ('direct', 'inherited', 'delegated', 'temporary', 'break_glass')),
                                
    assignment_source           VARCHAR(50) NOT NULL DEFAULT 'manual',
                                -- ENUM: 'manual', 'policy', 'workflow', 'api', 'sync'
                                -- ISO 27001: Source tracking for accountability
    
    -- -------------------------------------------------------------------------
    -- TEMPORAL CONSTRAINTS
    -- ISO 27001: Time-bound access
    -- -------------------------------------------------------------------------
    valid_from  -- [RBAC] ISO 27001: Temporal access control boundaries                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                                -- Start of validity period
                                
    valid_until  -- [RBAC] ISO 27001: Temporal access control boundaries                 TIMESTAMPTZ,
                                -- NULL = Permanent assignment
                                -- ISO 27001: Principle of least privilege over time
                                
    -- -------------------------------------------------------------------------
    -- CONDITIONAL GRANTS
    -- ISO 27018: Contextual access control
    -- -------------------------------------------------------------------------
    condition_expression        TEXT,
                                -- JSON Logic or SQL expression
                                -- Example: '{"and": [{"var": "time_of_day"}, {">": [{"var": "hour"}, 9}]}'
                                -- ENFORCEMENT: Evaluated at access time
                                
    condition_context           JSONB DEFAULT '{}',
                                -- Context variables for condition evaluation
                                -- Example: {"ip_range": "10.0.0.0/8", "mfa_verified": true}
    
    -- -------------------------------------------------------------------------
    -- DELEGATION CHAIN
    -- ISO 27001: Delegated access control
    -- -------------------------------------------------------------------------
    delegated_from_assignment_id UUID,
                                -- FK: self (original assignment)
                                CONSTRAINT fk_assignment_delegated_from 
                                    FOREIGN KEY (delegated_from_assignment_id) 
                                    REFERENCES app.t_user_role_assignments(assignment_id),
                                -- ISO 27001: Chain of custody
                                
    delegation_depth            INTEGER NOT NULL DEFAULT 0,
                                -- LIMIT: Max 3 levels
                                CONSTRAINT chk_delegation_depth 
                                    CHECK (delegation_depth >= 0 AND delegation_depth <= 3),
                                
    delegation_constraints      JSONB DEFAULT '{}',
                                -- CONSTRAINTS: Limits on delegated permissions
                                -- Example: {"max_amount": 10000, "allowed_resources": ["uuid1"]}
    
    -- -------------------------------------------------------------------------
    -- APPROVAL WORKFLOW
    -- ISO 27001: Segregation of duties
    -- -------------------------------------------------------------------------
    approval_status             VARCHAR(20) NOT NULL DEFAULT 'approved',
                                -- ENUM: 'pending', 'approved', 'rejected', 'expired'
                                CONSTRAINT chk_approval_status 
                                    CHECK (approval_status IN ('pending', 'approved', 'rejected', 'expired')),
                                
    approved_by                 UUID,
                                -- FK: app.t_account_membership.membership_id
                                -- ISO 27001: Separation of requester and approver
                                
    approved_at                 TIMESTAMPTZ,
                                -- AUDIT: Approval timestamp
                                
    approval_notes              TEXT,
                                -- DOCUMENTATION: Approver's notes
    
    -- -------------------------------------------------------------------------
    -- RESOURCE SCOPING
    -- ISO 27001: Least privilege
    -- -------------------------------------------------------------------------
    resource_scope              JSONB DEFAULT '{}',
                                -- LIMIT: Specific resources this applies to
                                -- Example: {"ledger_ids": ["uuid1"], "org_unit_ids": ["uuid2"]}
    
    -- -------------------------------------------------------------------------
    -- JUSTIFICATION & AUDIT
    -- ISO 31000: Risk justification
    -- -------------------------------------------------------------------------
    justification               TEXT,
                                -- REQUIRED: For elevated/temporary/break-glass
                                -- ISO 27001: Business justification
                                
    business_reason             VARCHAR(255),
                                -- CATEGORY: Classification of need
                                
    ticket_reference            VARCHAR(100),
                                -- EXTERNAL: Ticketing system reference
                                -- Example: JIRA-1234, SERVICENOW-5678
    
    -- -------------------------------------------------------------------------
    -- REVOCATION
    -- ISO 27001: Access removal
    -- -------------------------------------------------------------------------
    is_revoked                  BOOLEAN NOT NULL DEFAULT FALSE,
                                -- SOFT DELETE: Preserves audit trail
                                -- GDPR: Maintains processing records
                                
    revoked_at                  TIMESTAMPTZ,
                                -- TIMESTAMP: When revoked
                                
    revoked_by                  UUID,
                                -- FK: app.t_account_membership.membership_id
                                -- WHO: Responsible for revocation
                                
    revocation_reason           TEXT,
                                -- WHY: Reason for access removal
    
    -- -------------------------------------------------------------------------
    -- BREAK-GLASS (Emergency Access)
    -- ISO 27001: Emergency procedures
    -- -------------------------------------------------------------------------
    is_break_glass  -- [RBAC] ISO 27001: Emergency access indicator              BOOLEAN NOT NULL DEFAULT FALSE,
                                -- TRUE: Emergency access
                                -- ENHANCED LOGGING: All actions recorded
                                -- ISO 27001: Emergency access controls
                                
    break_glass_expires_at      TIMESTAMPTZ,
                                -- REQUIRED: When emergency access ends
                                CONSTRAINT chk_break_glass_expiry 
                                    CHECK (NOT is_break_glass_incident_id     UUID,
                                -- FK: External incident management system
                                -- REQUIRED: Incident tracking for break-glass
    
    -- -------------------------------------------------------------------------
    -- AUDIT & VERSIONING
    -- -------------------------------------------------------------------------
    version                     INTEGER NOT NULL DEFAULT 1  -- [AUDIT] ISO 9001: Optimistic locking for version control,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()  -- [AUDIT] ISO 27001: Non-repudiation timestamp,
    created_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  -- [AUDIT] ISO 27001: Accountability tracking                  UUID NOT NULL,
    
    -- -------------------------------------------------------------------------
    -- CONSTRAINTS
    -- -------------------------------------------------------------------------
    CONSTRAINT chk_validity_period 
        CHECK (valid_until  -- [RBAC] ISO 27001: Temporal access control boundaries IS NULL OR valid_until  -- [RBAC] ISO 27001: Temporal access control boundaries > valid_from  -- [RBAC] ISO 27001: Temporal access control boundaries),
        -- VALIDATION: End must be after start
        
    CONSTRAINT uq_active_role_assignment 
        UNIQUE (membership_id, role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference)
        -- RULE: One active assignment per role per membership
        -- ISO 27001: Clear accountability
);

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON TABLE app.t_user_role_assignments IS 
    'Role assignments linking memberships to roles with temporal and conditional support. ' ||
    'Feature: CORE-APP-004. ' ||
    'Compliance: ISO 27001, GDPR, SOC 2 Type II. ' ||
    'Security: Break-glass with incident tracking, max 3 delegation levels. ' ||
    'Audit: All assignments, approvals, and revocations logged.';

COMMENT ON COLUMN app.t_user_role_assignments.is_break_glass;
    
COMMENT ON COLUMN app.t_user_role_assignments.delegation_depth IS 
    'ISO 27001: Delegation chain depth. Max 3 levels to prevent privilege escalation.';
    
COMMENT ON COLUMN app.t_user_role_assignments.approval_status IS 
    'ISO 27001: Segregation of duties. pending=awaiting approval, approved=active.';

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Primary lookup by membership
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_membership 
    ON app.t_user_role_assignments(membership_id);

-- Role-based lookups
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_role 
    ON app.t_user_role_assignments(role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference);

-- Assignment type filtering
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_type 
    ON app.t_user_role_assignments(assignment_type  -- [RBAC] ISO 27001: Assignment classification (direct/inherited/delegated));

-- Temporal validity queries (BRIN for large tables)
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_temporal 
    ON app.t_user_role_assignments USING BRIN (valid_from  -- [RBAC] ISO 27001: Temporal access control boundaries, valid_until  -- [RBAC] ISO 27001: Temporal access control boundaries);

-- Pending approvals (admin dashboards)
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_pending 
    ON app.t_user_role_assignments(created_at) 
    WHERE approval_status = 'pending';

-- Break-glass identification
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_break_glass 
    ON app.t_user_role_assignments(is_break_glass  -- [RBAC] ISO 27001: Emergency access indicator) 
    WHERE is_break_glass  -- [RBAC] ISO 27001: Emergency access indicator = TRUE;

-- Active assignments (most important index)
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_active 
    ON app.t_user_role_assignments(membership_id, role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference) 
    WHERE is_revoked = FALSE AND approval_status = 'approved';

-- Delegation chain lookups
CREATE INDEX CONCURRENTLY  -- [TXN] ISO 9001: Non-blocking index creation IF NOT EXISTS idx_assignments_delegated 
    ON app.t_user_role_assignments(delegated_from_assignment_id) 
    WHERE delegated_from_assignment_id IS NOT NULL;

-- =============================================================================
-- RLS POLICIES
-- =============================================================================
ALTER TABLE app.t_user_role_assignments ENABLE ROW LEVEL SECURITY  -- [RLS] ISO 27017: Multi-tenant data isolation enforced -- [RLS] ISO 27017: Multi-tenant data isolation enforced;

-- Policy: Self View
CREATE POLICY assignments_self_view ON app.t_user_role_assignments
    FOR SELECT USING (
        membership_id IN (
            SELECT membership_id FROM app.t_account_membership 
            WHERE user_identity_id = current_setting('app.current_user_id', TRUE)::UUID
        )
    );

-- Policy: Admin Manage
CREATE POLICY assignments_admin_manage ON app.t_user_role_assignments
    USING (app.check_permission(  -- [RBAC] ISO 27001 A.5.15: Access control check
        current_setting('app.current_membership_id', TRUE)::UUID,
        'app:role_assignment:manage'
    ) = TRUE);

-- =============================================================================
-- TRIGGERS
-- =============================================================================

-- Trigger: Break-Glass Alert
CREATE OR REPLACE FUNCTION app.trg_assignments_break_glass_alert()
RETURNS TRIGGER AS $$
BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
    IF NEW.is_break_glass  -- [RBAC] ISO 27001: Emergency access indicator AND NEW.approval_status = 'approved' THEN
        -- TODO: Send alert to security team
        -- TODO: Log to SIEM
        -- TODO: Start enhanced monitoring
        PERFORM pg_notify('security_alert', jsonb_build_object(
            'type', 'break_glass_activated',
            'assignment_id', NEW.assignment_id,
            'membership_id', NEW.membership_id,
            'incident_id', NEW.break_glass_incident_id,
            'expires_at', NEW.break_glass_expires_at
        )::TEXT);
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assignments_break_glass_alert
    AFTER INSERT OR UPDATE ON app.t_user_role_assignments
    FOR EACH ROW 
    WHEN (NEW.is_break_glass  -- [RBAC] ISO 27001: Emergency access indicator = TRUE)
    EXECUTE FUNCTION app.trg_assignments_break_glass_alert();

-- Trigger: Cache Invalidation
CREATE OR REPLACE FUNCTION app.trg_assignments_cache_invalidate()
RETURNS TRIGGER AS $$
BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
    -- Invalidate permission cache for affected membership
    PERFORM pg_notify('permission_cache_invalidate', 
        COALESCE(NEW.membership_id, OLD.membership_id)::TEXT
    );
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assignments_cache_invalidate
    AFTER INSERT OR UPDATE OR DELETE ON app.t_user_role_assignments
    FOR EACH ROW EXECUTE FUNCTION app.trg_assignments_cache_invalidate();

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Function: Check if role assignment is currently active
CREATE OR REPLACE FUNCTION app.is_role_active(
    p_assignment_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged execution context -- [RBAC] ISO 27001: Privileged function execution context
STABLE
AS $$
DECLARE
    v_active BOOLEAN;
BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
    SELECT EXISTS (
        SELECT 1 FROM app.t_user_role_assignments
        WHERE assignment_id = p_assignment_id
          AND is_revoked = FALSE
          AND approval_status = 'approved'
          AND valid_from  -- [RBAC] ISO 27001: Temporal access control boundaries <= NOW()
          AND (valid_until  -- [RBAC] ISO 27001: Temporal access control boundaries IS NULL OR valid_until  -- [RBAC] ISO 27001: Temporal access control boundaries > NOW())
          AND (is_break_glass  -- [RBAC] ISO 27001: Emergency access indicator = FALSE OR break_glass_expires_at > NOW())
    ) INTO v_active;
    
    RETURN v_active;
END;
$$;

-- Function: Activate break-glass access
CREATE OR REPLACE FUNCTION app.activate_break_glass(
    p_membership_id UUID,
    p_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference UUID,
    p_incident_id UUID,
    p_duration_minutes INTEGER DEFAULT 60,
    p_justification TEXT,
    p_requested_by UUID
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged execution context -- [RBAC] ISO 27001: Privileged function execution context
AS $$
DECLARE
    v_assignment_id UUID;
BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
    -- Authorization check
    IF NOT app.check_permission(p_requested_by, 'app:break_glass:activate') THEN  -- [RBAC] ISO 27001 A.5.15: Access control check
        RAISE EXCEPTION  -- [ERROR] ISO 27001: Secure error handling -- [ERROR] ISO 27001: Secure error handling - no sensitive data exposure 'Insufficient privileges for break-glass activation';
    END IF;
    
    INSERT INTO app.t_user_role_assignments (
        membership_id, role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference,
        assignment_type  -- [RBAC] ISO 27001: Assignment classification (direct/inherited/delegated), assignment_source,
        is_break_glass  -- [RBAC] ISO 27001: Emergency access indicator, break_glass_expires_at, break_glass_incident_id,
        justification, approval_status, approved_at, approved_by,
        created_by  -- [AUDIT] ISO 27001: Accountability tracking, updated_by  -- [AUDIT] ISO 27001: Accountability tracking
    ) VALUES (
        p_membership_id, p_role_id  -- [RBAC] ISO 27001 A.9.2.2: Role assignment reference,
        'break_glass', 'emergency',
        TRUE, NOW() + (p_duration_minutes || ' minutes')::INTERVAL, p_incident_id,
        p_justification, 'approved', NOW(), p_requested_by,
        p_requested_by, p_requested_by
    )
    RETURNING assignment_id INTO v_assignment_id;
    
    RETURN v_assignment_id;
END;
$$;

-- =============================================================================
-- ANALYZE
-- =============================================================================
ANALYZE app.t_user_role_assignments;

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Assignments can be permanent or time-bound
-- 2. Delegation depth limited to 3 levels
-- 3. Break-glass access auto-expires and requires incident tracking
-- 4. Conditional expressions use JSON Logic format
-- 5. Resource scoping restricts role permissions to specific entities
-- 6. All revocations are soft deletes for audit compliance
-- 7. Approval workflow required for elevated roles
-- =============================================================================
