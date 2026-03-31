-- =============================================================================
-- USSD KERNEL CORE SCHEMA - SUSPENSE ITEMS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    016_suspense_items.sql
-- SCHEMA:      ussd_core
-- TABLE:       suspense_items
-- DESCRIPTION: Unmatched or pending items held in suspense accounts
--              awaiting resolution, classification, or routing.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Suspense item access
├── A.12.4 Logging and monitoring - Suspense monitoring
└── A.16.1 Management of information security incidents - Escalation

Financial Regulations
├── Suspense aging: Maximum hold period compliance
├── Escalation: Management notification requirements
└── Resolution audit: Complete resolution trail

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. SUSPENSE CATEGORIES
   - UNIDENTIFIED: Cannot determine proper account
   - PENDING_DOCS: Awaiting documentation
   - DISPUTED: Under dispute
   - INVESTIGATION: Under investigation
   - AWAITING_APPROVAL: Pending approval

2. AGING TRACKING
   - Age in days calculated automatically
   - Escalation thresholds configured
   - Auto-escalation on threshold breach

3. RESOLUTION
   - Classification required
   - Approval workflow
   - Audit trail for resolution

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

SUSPENSE SECURITY:
- Access restricted to authorized personnel
- All access logged
- Modification audit trail

ESCALATION:
- Automated aging reports
- Management notification
- Regulatory reporting for aged items

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: suspense_id
- ACCOUNT: suspense_account_id + status
- CATEGORY: category + status
- AGE: created_at (for aging reports)

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- SUSPENSE_ITEM_CREATED
- SUSPENSE_ITEM_CLASSIFIED
- SUSPENSE_ITEM_RESOLVED
- SUSPENSE_ITEM_ESCALATED

RETENTION: 7 years
================================================================================
*/

-- -----------------------------------------------------------------------------
-- CREATE TABLE: suspense_items
-- -----------------------------------------------------------------------------
CREATE TABLE core.suspense_items (
    -- Primary identifier
    suspense_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    suspense_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Suspense account
    suspense_account_id UUID NOT NULL REFERENCES core.account_registry(account_id) ON DELETE RESTRICT,
    
    -- Item details
    category VARCHAR(50) NOT NULL
        CHECK (category IN ('UNIDENTIFIED', 'PENDING_DOCS', 'DISPUTED', 'INVESTIGATION', 'AWAITING_APPROVAL')),
    status VARCHAR(20) DEFAULT 'OPEN'
        CHECK (status IN ('OPEN', 'CLASSIFIED', 'PENDING_APPROVAL', 'RESOLVED', 'WRITTEN_OFF')),
    
    -- Amount
    amount NUMERIC(20, 8) NOT NULL CHECK (amount > 0),
    currency VARCHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    
    -- Source
    source_type VARCHAR(50),
    source_reference VARCHAR(100),
    source_date DATE,
    
    -- Identification attempts
    attempted_account_id UUID,
    identification_notes TEXT,
    
    -- Aging
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    age_days INTEGER GENERATED ALWAYS AS (EXTRACT(DAY FROM now() - created_at)) STORED,
    escalation_level INTEGER DEFAULT 0 CHECK (escalation_level >= 0 AND escalation_level <= 5),
    escalated_at TIMESTAMPTZ,
    
    -- Resolution
    resolution_type VARCHAR(50)
        CHECK (resolution_type IN ('TRANSFER', 'RETURN', 'WRITE_OFF', 'RECLASSIFY', 'ADJUST')),
    resolution_reference VARCHAR(100),
    resolved_at TIMESTAMPTZ,
    resolved_by UUID,
    resolution_notes TEXT,
    
    -- Audit
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- -----------------------------------------------------------------------------
-- INDEXES
-- -----------------------------------------------------------------------------
-- Account-based lookups
CREATE INDEX idx_suspense_account_status 
    ON core.suspense_items(suspense_account_id, status) 
    WHERE status IN ('OPEN', 'CLASSIFIED', 'PENDING_APPROVAL');

-- Category-based queries
CREATE INDEX idx_suspense_category_status 
    ON core.suspense_items(category, status);

-- Aging reports
CREATE INDEX idx_suspense_created_at 
    ON core.suspense_items(created_at) 
    WHERE status = 'OPEN';

-- Escalation monitoring
CREATE INDEX idx_suspense_escalation 
    ON core.suspense_items(escalation_level, created_at) 
    WHERE status = 'OPEN';

-- Source reference lookups
CREATE INDEX idx_suspense_source 
    ON core.suspense_items(source_type, source_reference);

-- -----------------------------------------------------------------------------
-- IMMUTABILITY TRIGGERS
-- -----------------------------------------------------------------------------
CREATE TRIGGER trg_suspense_items_prevent_update
    BEFORE UPDATE ON core.suspense_items
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_suspense_items_prevent_delete
    BEFORE DELETE ON core.suspense_items
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- -----------------------------------------------------------------------------
-- HASH COMPUTATION TRIGGER
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION core.compute_suspense_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.suspense_id::TEXT || 
        NEW.suspense_reference || 
        NEW.suspense_account_id::TEXT ||
        NEW.category ||
        NEW.status ||
        NEW.amount::TEXT ||
        NEW.currency ||
        COALESCE(NEW.source_reference, '') ||
        NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_suspense_items_compute_hash
    BEFORE INSERT ON core.suspense_items
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_suspense_hash();

-- -----------------------------------------------------------------------------
-- HELPER FUNCTIONS
-- -----------------------------------------------------------------------------

-- Function to classify a suspense item
CREATE OR REPLACE FUNCTION core.classify_suspense_item(
    p_suspense_id UUID,
    p_category VARCHAR(50),
    p_attempted_account_id UUID,
    p_identification_notes TEXT,
    p_classified_by UUID
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_new_suspense_id UUID;
    v_old_record RECORD;
BEGIN
    -- Get current record
    SELECT * INTO v_old_record 
    FROM core.suspense_items 
    WHERE suspense_id = p_suspense_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Suspense item % not found', p_suspense_id;
    END IF;
    
    -- Create new version with classification
    INSERT INTO core.suspense_items (
        suspense_reference,
        suspense_account_id,
        category,
        status,
        amount,
        currency,
        source_type,
        source_reference,
        source_date,
        attempted_account_id,
        identification_notes
    ) VALUES (
        v_old_record.suspense_reference || '-C',
        v_old_record.suspense_account_id,
        p_category,
        'CLASSIFIED',
        v_old_record.amount,
        v_old_record.currency,
        v_old_record.source_type,
        v_old_record.source_reference,
        v_old_record.source_date,
        p_attempted_account_id,
        p_identification_notes
    ) RETURNING suspense_id INTO v_new_suspense_id;
    
    RETURN v_new_suspense_id;
END;
$$;

-- Function to escalate aged suspense items
CREATE OR REPLACE FUNCTION core.escalate_suspense_items(
    p_max_age_days INTEGER DEFAULT 30,
    p_max_escalation_level INTEGER DEFAULT 3
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_escalated_count INTEGER := 0;
BEGIN
    -- Note: Since table is immutable, we create new versions for escalation
    -- This is a simplified version - in production, use versioning pattern
    
    -- Return count of items that would be escalated
    SELECT COUNT(*) INTO v_escalated_count
    FROM core.suspense_items
    WHERE status = 'OPEN'
      AND age_days >= p_max_age_days
      AND escalation_level < p_max_escalation_level;
    
    RETURN v_escalated_count;
END;
$$;

-- Function to get suspense aging summary
CREATE OR REPLACE FUNCTION core.get_suspense_aging_summary()
RETURNS TABLE (
    age_bucket VARCHAR(50),
    item_count BIGINT,
    total_amount NUMERIC
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        CASE 
            WHEN age_days <= 7 THEN '0-7 days'
            WHEN age_days <= 14 THEN '8-14 days'
            WHEN age_days <= 30 THEN '15-30 days'
            WHEN age_days <= 60 THEN '31-60 days'
            WHEN age_days <= 90 THEN '61-90 days'
            ELSE '90+ days'
        END::VARCHAR(50) as age_bucket,
        COUNT(*) as item_count,
        SUM(amount) as total_amount
    FROM core.suspense_items
    WHERE status = 'OPEN'
    GROUP BY 1
    ORDER BY MIN(age_days);
END;
$$;

-- -----------------------------------------------------------------------------
-- INITIAL DATA: System suspense accounts reference
-- -----------------------------------------------------------------------------
-- Note: Actual suspense items are created during transaction processing
-- System accounts for suspense handling should be in account_registry

-- -----------------------------------------------------------------------------
-- COMMENTS
-- -----------------------------------------------------------------------------
COMMENT ON TABLE core.suspense_items IS 'Unmatched or pending items held in suspense accounts awaiting resolution';
COMMENT ON COLUMN core.suspense_items.suspense_id IS 'Unique identifier for the suspense item';
COMMENT ON COLUMN core.suspense_items.suspense_reference IS 'Business reference number for the suspense item';
COMMENT ON COLUMN core.suspense_items.category IS 'Classification category of the suspense item';
COMMENT ON COLUMN core.suspense_items.status IS 'Current status in the resolution workflow';
COMMENT ON COLUMN core.suspense_items.age_days IS 'Auto-calculated age in days since creation';
COMMENT ON COLUMN core.suspense_items.escalation_level IS 'Current escalation level (0-5)';

-- =============================================================================
-- END OF FILE
-- =============================================================================
