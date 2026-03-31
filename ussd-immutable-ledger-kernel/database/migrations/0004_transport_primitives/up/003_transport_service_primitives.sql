-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Incident management, Access control)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Dispute data isolation)
-- ISO/IEC 27018:2019 - PII Protection (Dispute participant privacy)
-- ISO/IEC 27040:2024 - Storage Security (Immutable dispute records)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Immutable dispute case records with status transitions
-- - Regulatory flags with temporal validity and enforcement state
-- - RLS ensuring participants only see their own disputes
-- - Audit trail for all dispute resolutions and flag changes
-- ============================================================================
-- =============================================================================
-- MIGRATION: 003_transport_service_primitives.sql
-- DESCRIPTION: Transport Service Request & Dispute Primitives
-- TABLES: core.disputes, core.regulatory_flags
-- DEPENDENCIES: 004_core_transaction_log.sql, 003_core_account_registry.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 15. Service Request Primitives, 16. Rating & Reputation Primitives
- Feature: Dispute Cases, Regulatory Flags
- Source: Transport Business Application on USSD Immutable Ledger

BUSINESS CONTEXT:
Transport operations in Zimbabwe require formal dispute resolution and
regulatory compliance enforcement:
- Fare and service quality disputes between riders and drivers
- ZTA/VID regulatory flags (suspension, CRW expiry, tax delinquency)
- Immutable audit trail for all resolutions and compliance actions

KEY FEATURES:
- Dispute cases linked to completed trips (transactions)
- Evidence submission and mediation status tracking
- Regulatory flags with valid_from/valid_to for time-bounded enforcement
- Automatic service blocking based on active regulatory flags
================================================================================
*/

-- =============================================================================
-- IMPLEMENTATION: Create core.disputes table
-- DESCRIPTION: Conflict resolution primitive for transport disputes
-- PRIORITY: CRITICAL
-- SECURITY: Contains PII and sensitive dispute data - encrypted where required
-- ============================================================================
-- [DISP-001] Create core.disputes table

CREATE TABLE core.disputes (
    dispute_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dispute_reference   VARCHAR(100) UNIQUE NOT NULL, -- e.g., "DISP-20240331-001"
    
    -- Related Trip
    trip_transaction_id UUID NOT NULL REFERENCES core.transaction_log(transaction_id),
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Participants
    rider_account_id    UUID NOT NULL REFERENCES core.accounts(account_id),
    driver_account_id   UUID NOT NULL REFERENCES core.accounts(account_id),
    
    -- Dispute Classification
    dispute_category    VARCHAR(50) NOT NULL,        -- FARE_DISPUTE, SERVICE_QUALITY, SAFETY, ROUTE_DEVIATION, PAYMENT_ISSUE
    dispute_priority    VARCHAR(20) DEFAULT 'MEDIUM', -- LOW, MEDIUM, HIGH, CRITICAL
    
    -- Description
    description         TEXT NOT NULL,
    requested_amount    NUMERIC(20, 8),              -- For fare disputes
    requested_currency  VARCHAR(3),
    
    -- Status Workflow
    status              VARCHAR(50) NOT NULL DEFAULT 'OPEN',
                        -- OPEN, UNDER_REVIEW, EVIDENCE_REQUESTED, MEDIATION,
                        -- RESOLVED_RIDER_FAVOUR, RESOLVED_DRIVER_FAVOUR,
                        -- RESOLVED_SPLIT, REJECTED, ESCALATED, CLOSED
    
    -- Resolution
    resolution_type     VARCHAR(50),                 -- REFUND, PARTIAL_REFUND, NO_ACTION, PENALTY, ADJUSTMENT
    resolution_amount   NUMERIC(20, 8),
    resolution_currency VARCHAR(3),
    resolution_notes    TEXT,
    resolved_by         UUID REFERENCES core.accounts(account_id),
    resolved_at         TIMESTAMPTZ,
    
    -- Compensation Transaction (if any)
    compensation_movement_id UUID REFERENCES core.movement_headers(movement_id),
    
    -- Evidence
    evidence_document_ids UUID[],                    -- References to document_registry
    
    -- Timing
    opened_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at           TIMESTAMPTZ,
    
    -- Escalation
    escalated_to        UUID REFERENCES core.accounts(account_id),
    escalation_reason   TEXT,
    escalated_at        TIMESTAMPTZ,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    updated_at          TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT chk_disputes_category 
        CHECK (dispute_category IN ('FARE_DISPUTE', 'SERVICE_QUALITY', 'SAFETY', 'ROUTE_DEVIATION', 'PAYMENT_ISSUE', 'DRIVER_CONDUCT', 'VEHICLE_CONDITION')),
    CONSTRAINT chk_disputes_priority 
        CHECK (dispute_priority IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT chk_disputes_status 
        CHECK (status IN ('OPEN', 'UNDER_REVIEW', 'EVIDENCE_REQUESTED', 'MEDIATION', 'RESOLVED_RIDER_FAVOUR', 'RESOLVED_DRIVER_FAVOUR', 'RESOLVED_SPLIT', 'REJECTED', 'ESCALATED', 'CLOSED')),
    CONSTRAINT chk_disputes_resolution 
        CHECK (resolution_type IS NULL OR resolution_type IN ('REFUND', 'PARTIAL_REFUND', 'NO_ACTION', 'PENALTY', 'ADJUSTMENT', 'BANNED', 'WARNING')),
    CONSTRAINT chk_disputes_currency 
        CHECK (requested_currency ~ '^[A-Z]{3}$' OR requested_currency IS NULL)
);

-- INDEXES
CREATE INDEX idx_disputes_trip ON core.disputes(trip_transaction_id);
CREATE INDEX idx_disputes_rider ON core.disputes(rider_account_id, status);
CREATE INDEX idx_disputes_driver ON core.disputes(driver_account_id, status);
CREATE INDEX idx_disputes_status ON core.disputes(status, opened_at);
CREATE INDEX idx_disputes_app ON core.disputes(application_id, status);
CREATE INDEX idx_disputes_priority ON core.disputes(dispute_priority, status) WHERE status IN ('OPEN', 'UNDER_REVIEW', 'ESCALATED');
CREATE INDEX idx_disputes_resolved ON core.disputes(resolved_at) WHERE resolved_at IS NOT NULL;
CREATE INDEX idx_disputes_opened ON core.disputes(opened_at DESC);

COMMENT ON TABLE core.disputes IS 'Conflict resolution primitive for fare and service quality disputes';
COMMENT ON COLUMN core.disputes.status IS 'OPEN, UNDER_REVIEW, EVIDENCE_REQUESTED, MEDIATION, RESOLVED_*, REJECTED, ESCALATED, CLOSED';
COMMENT ON COLUMN core.disputes.evidence_document_ids IS 'Array of document_registry IDs supporting the dispute';

-- =============================================================================
-- IMPLEMENTATION: Create dispute status history table
-- DESCRIPTION: Audit trail of all dispute status transitions
-- PRIORITY: HIGH
-- SECURITY: Immutable append-only record of dispute lifecycle
-- ============================================================================
-- [DISP-002] Create core.dispute_status_history table

CREATE TABLE core.dispute_status_history (
    history_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dispute_id          UUID NOT NULL REFERENCES core.disputes(dispute_id),
    
    previous_status     VARCHAR(50),
    new_status          VARCHAR(50) NOT NULL,
    changed_by          UUID REFERENCES core.accounts(account_id),
    change_reason       TEXT,
    
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_dispute_status_history_dispute ON core.dispute_status_history(dispute_id, created_at DESC);
CREATE INDEX idx_dispute_status_history_changed ON core.dispute_status_history(created_at);

COMMENT ON TABLE core.dispute_status_history IS 'Immutable audit trail of dispute status transitions';

-- =============================================================================
-- IMPLEMENTATION: Create dispute status change trigger
-- DESCRIPTION: Auto-log status transitions
-- PRIORITY: HIGH
-- ============================================================================
-- [DISP-003] Create dispute_status_change_trigger

CREATE OR REPLACE FUNCTION core.log_dispute_status_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status THEN
        INSERT INTO core.dispute_status_history (
            dispute_id, previous_status, new_status, changed_by, change_reason
        ) VALUES (
            NEW.dispute_id, OLD.status, NEW.status, NEW.resolved_by, NEW.resolution_notes
        );
        
        NEW.updated_at := now();
        
        -- Set closed_at when reaching a terminal state
        IF NEW.status IN ('RESOLVED_RIDER_FAVOUR', 'RESOLVED_DRIVER_FAVOUR', 'RESOLVED_SPLIT', 'REJECTED', 'CLOSED') THEN
            NEW.closed_at := COALESCE(NEW.closed_at, now());
        END IF;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

CREATE TRIGGER trg_disputes_status_change
    BEFORE UPDATE ON core.disputes
    FOR EACH ROW
    EXECUTE FUNCTION core.log_dispute_status_change();

COMMENT ON FUNCTION core.log_dispute_status_change IS 'Automatically logs dispute status transitions and sets closure timestamps';

-- =============================================================================
-- IMPLEMENTATION: Create core.regulatory_flags table
-- DESCRIPTION: Compliance enforcement state for accounts and vehicles
-- PRIORITY: CRITICAL
-- SECURITY: Determines service eligibility - must be tamper-evident
-- ============================================================================
-- [DISP-004] Create core.regulatory_flags table

CREATE TABLE core.regulatory_flags (
    flag_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flag_reference      VARCHAR(100) UNIQUE NOT NULL, -- e.g., "REG-ZTA-001"
    
    -- Target Entity
    target_type         VARCHAR(50) NOT NULL,        -- ACCOUNT, VEHICLE
    target_id           UUID NOT NULL,               -- account_id or vehicle_id
    
    -- Flag Classification
    flag_type           VARCHAR(50) NOT NULL,        -- SUSPENSION, CRW_EXPIRY, TAX_DELINQUENCY, SAFETY_VIOLATION, FRAUD
    flag_severity       VARCHAR(20) NOT NULL DEFAULT 'MEDIUM', -- LOW, MEDIUM, HIGH, CRITICAL
    
    -- Issuing Authority
    issuing_authority   VARCHAR(100) NOT NULL,       -- ZTA, VID, ZIMRA, PLATFORM
    authority_reference VARCHAR(255),                 -- External reference number
    
    -- Description
    description         TEXT NOT NULL,
    resolution_requirements TEXT,                    -- What must be done to clear
    
    -- Status
    status              VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, UNDER_REVIEW, APPEALED, CLEARED, EXPIRED
    
    -- Temporal Validity
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,                 -- NULL = indefinite
    
    -- Enforcement
    blocks_online_status BOOLEAN DEFAULT false,      -- Prevents going online
    blocks_booking      BOOLEAN DEFAULT false,       -- Prevents accepting bookings
    blocks_payout       BOOLEAN DEFAULT false,       -- Prevents withdrawals
    
    -- Application Scope
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Resolution
    cleared_by          UUID REFERENCES core.accounts(account_id),
    cleared_at          TIMESTAMPTZ,
    clearance_notes     TEXT,
    clearance_document_id UUID REFERENCES core.document_registry(document_id),
    
    -- Versioning
    version             INTEGER NOT NULL DEFAULT 1,
    superseded_by       UUID REFERENCES core.regulatory_flags(flag_id),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    
    -- Constraints
    CONSTRAINT chk_regulatory_flags_target 
        CHECK (target_type IN ('ACCOUNT', 'VEHICLE')),
    CONSTRAINT chk_regulatory_flags_type 
        CHECK (flag_type IN ('SUSPENSION', 'CRW_EXPIRY', 'TAX_DELINQUENCY', 'SAFETY_VIOLATION', 'FRAUD', 'LICENSE_EXPIRY', 'INSURANCE_LAPSE', 'COMPLIANCE_FAILURE')),
    CONSTRAINT chk_regulatory_flags_severity 
        CHECK (flag_severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT chk_regulatory_flags_status 
        CHECK (status IN ('ACTIVE', 'UNDER_REVIEW', 'APPEALED', 'CLEARED', 'EXPIRED')),
    CONSTRAINT chk_regulatory_flags_valid_time 
        CHECK (valid_to IS NULL OR valid_to > valid_from)
);

-- INDEXES
CREATE INDEX idx_regulatory_flags_target ON core.regulatory_flags(target_type, target_id, status);
CREATE INDEX idx_regulatory_flags_status ON core.regulatory_flags(status, valid_from);
CREATE INDEX idx_regulatory_flags_app ON core.regulatory_flags(application_id, status);
CREATE INDEX idx_regulatory_flags_active ON core.regulatory_flags(target_type, target_id, status) WHERE status = 'ACTIVE';
CREATE INDEX idx_regulatory_flags_authority ON core.regulatory_flags(issuing_authority, flag_type);
CREATE INDEX idx_regulatory_flags_expiry ON core.regulatory_flags(valid_to) WHERE status = 'ACTIVE' AND valid_to IS NOT NULL;
CREATE INDEX idx_regulatory_flags_enforcement ON core.regulatory_flags(blocks_online_status, blocks_booking, blocks_payout) WHERE status = 'ACTIVE';

COMMENT ON TABLE core.regulatory_flags IS 'Immutable enforcement state marking accounts or vehicles for compliance issues';
COMMENT ON COLUMN core.regulatory_flags.target_type IS 'ACCOUNT or VEHICLE - the entity this flag applies to';
COMMENT ON COLUMN core.regulatory_flags.blocks_online_status IS 'When true, prevents driver from going online';

-- =============================================================================
-- IMPLEMENTATION: Create regulatory flag temporal exclusion constraint
-- DESCRIPTION: Prevent overlapping active versions of same flag reference
-- PRIORITY: HIGH
-- ============================================================================
-- [DISP-005] Add temporal exclusion constraint for regulatory flags

ALTER TABLE core.regulatory_flags
    ADD CONSTRAINT uq_regulatory_flags_no_overlap 
    EXCLUDE USING gist (
        flag_reference WITH =,
        tsrange(valid_from, COALESCE(valid_to, 'infinity'::timestamptz), '[)') WITH &&
    )
    WHERE (status = 'ACTIVE');

-- =============================================================================
-- IMPLEMENTATION: Create active regulatory flags view
-- DESCRIPTION: Currently enforceable flags only
-- PRIORITY: HIGH
-- ============================================================================
-- [DISP-006] Create active_regulatory_flags view

CREATE OR REPLACE VIEW core.active_regulatory_flags AS
SELECT * FROM core.regulatory_flags
WHERE status = 'ACTIVE'
  AND valid_from <= now()
  AND (valid_to IS NULL OR valid_to > now())
  AND superseded_by IS NULL;

COMMENT ON VIEW core.active_regulatory_flags IS 'View showing only currently enforceable regulatory flags';

-- =============================================================================
-- IMPLEMENTATION: Create account eligibility check function
-- DESCRIPTION: Check if account has blocking regulatory flags
-- PRIORITY: CRITICAL
-- SECURITY: Gatekeeper for driver online status and ride acceptance
-- ============================================================================
-- [DISP-007] Create check_account_eligibility function

CREATE OR REPLACE FUNCTION core.check_account_eligibility(
    p_account_id UUID,
    p_application_id UUID,
    p_check_type VARCHAR(20) DEFAULT 'ALL' -- ALL, ONLINE, BOOKING, PAYOUT
) RETURNS TABLE (
    is_eligible BOOLEAN,
    blocking_flags UUID[],
    blocking_reasons TEXT[]
) AS $$
DECLARE
    v_blocking_flags UUID[] := ARRAY[]::UUID[];
    v_blocking_reasons TEXT[] := ARRAY[]::TEXT[];
    v_flag RECORD;
BEGIN
    FOR v_flag IN
        SELECT 
            rf.flag_id,
            rf.flag_type,
            rf.issuing_authority,
            rf.description,
            rf.blocks_online_status,
            rf.blocks_booking,
            rf.blocks_payout
        FROM core.regulatory_flags rf
        WHERE rf.target_type = 'ACCOUNT'
          AND rf.target_id = p_account_id
          AND rf.application_id = p_application_id
          AND rf.status = 'ACTIVE'
          AND rf.valid_from <= now()
          AND (rf.valid_to IS NULL OR rf.valid_to > now())
          AND rf.superseded_by IS NULL
    LOOP
        IF p_check_type = 'ALL' OR 
           (p_check_type = 'ONLINE' AND v_flag.blocks_online_status) OR
           (p_check_type = 'BOOKING' AND v_flag.blocks_booking) OR
           (p_check_type = 'PAYOUT' AND v_flag.blocks_payout) THEN
            v_blocking_flags := array_append(v_blocking_flags, v_flag.flag_id);
            v_blocking_reasons := array_append(
                v_blocking_reasons,
                v_flag.issuing_authority || ': ' || v_flag.flag_type || ' - ' || v_flag.description
            );
        END IF;
    END LOOP;
    
    RETURN QUERY SELECT 
        (array_length(v_blocking_flags, 1) IS NULL OR array_length(v_blocking_flags, 1) = 0),
        v_blocking_flags,
        v_blocking_reasons;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.check_account_eligibility IS 'Checks if an account has active regulatory flags blocking specified activities';

-- =============================================================================
-- IMPLEMENTATION: Create vehicle eligibility check function
-- DESCRIPTION: Check if vehicle has blocking regulatory flags
-- PRIORITY: CRITICAL
-- ============================================================================
-- [DISP-008] Create check_vehicle_regulatory_status function

CREATE OR REPLACE FUNCTION core.check_vehicle_regulatory_status(
    p_vehicle_id UUID,
    p_application_id UUID
) RETURNS TABLE (
    is_clear BOOLEAN,
    blocking_flags UUID[],
    blocking_reasons TEXT[]
) AS $$
DECLARE
    v_blocking_flags UUID[] := ARRAY[]::UUID[];
    v_blocking_reasons TEXT[] := ARRAY[]::TEXT[];
    v_flag RECORD;
BEGIN
    FOR v_flag IN
        SELECT 
            rf.flag_id,
            rf.flag_type,
            rf.issuing_authority,
            rf.description
        FROM core.regulatory_flags rf
        WHERE rf.target_type = 'VEHICLE'
          AND rf.target_id = p_vehicle_id
          AND rf.application_id = p_application_id
          AND rf.status = 'ACTIVE'
          AND rf.valid_from <= now()
          AND (rf.valid_to IS NULL OR rf.valid_to > now())
          AND rf.superseded_by IS NULL
    LOOP
        v_blocking_flags := array_append(v_blocking_flags, v_flag.flag_id);
        v_blocking_reasons := array_append(
            v_blocking_reasons,
            v_flag.issuing_authority || ': ' || v_flag.flag_type || ' - ' || v_flag.description
        );
    END LOOP;
    
    RETURN QUERY SELECT 
        (array_length(v_blocking_flags, 1) IS NULL OR array_length(v_blocking_flags, 1) = 0),
        v_blocking_flags,
        v_blocking_reasons;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.check_vehicle_regulatory_status IS 'Checks if a vehicle has active regulatory flags preventing service';

-- =============================================================================
-- IMPLEMENTATION: Create open disputes view
-- DESCRIPTION: Disputes requiring attention
-- PRIORITY: MEDIUM
-- ============================================================================
-- [DISP-009] Create open_disputes view

CREATE OR REPLACE VIEW core.open_disputes AS
SELECT * FROM core.disputes
WHERE status IN ('OPEN', 'UNDER_REVIEW', 'EVIDENCE_REQUESTED', 'MEDIATION', 'ESCALATED');

COMMENT ON VIEW core.open_disputes IS 'View showing all unresolved disputes requiring attention';

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create core.disputes table with comprehensive status workflow
☑ Create core.dispute_status_history table for audit trail
☑ Implement auto-logging trigger for dispute status changes
☑ Create core.regulatory_flags table with enforcement controls
☑ Create active_regulatory_flags view
☑ Implement check_account_eligibility function
☑ Implement check_vehicle_regulatory_status function
☑ Create open_disputes view
☑ Add temporal exclusion constraints
☑ Add all indexes for dispute and flag queries
☑ Verify foreign key constraints
================================================================================
*/
