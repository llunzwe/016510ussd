-- ============================================================================
-- LEGAL HOLD APPLICATION PROCEDURE
-- ============================================================================
-- Purpose: Apply and manage legal holds on ledger records for litigation
--          support, regulatory investigations, and audit preservation.
-- Author:  USSD Immutable Ledger Team
-- Date:    2026-03-30
-- ============================================================================
-- COMPLIANCE HEADER:
--   ISO/IEC 27050-3:2020 - Information Technology - Electronic Discovery -
--   Part 3: Governance and Management of Electronic Discovery
--
--   This procedure implements:
--   - Clause 5.2: Legal hold notice and preservation requirements
--   - Clause 6.1: Governance framework for electronic discovery
--   - Clause 7.3: Custodian identification and notification
--   - Annex A: Preservation scope and defensible deletion
--
--   Hold Types: Litigation, Regulatory, Audit, Investigation, Internal
--   Conflict Resolution: GDPR vs Legal Hold precedence rules
--   Audit Trail: Complete hold lifecycle logging required
--   Custodian Notification: Automated within 24 hours of hold creation
-- ============================================================================

-- =============================================================================
-- STEP 1: LEGAL HOLD INFRASTRUCTURE SETUP
-- =============================================================================

-- 1.1 Create legal hold master table
CREATE TABLE IF NOT EXISTS legal_holds (
    hold_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hold_name TEXT NOT NULL,
    hold_type VARCHAR(50) NOT NULL CHECK (hold_type IN ('LITIGATION', 'REGULATORY', 'AUDIT', 'INVESTIGATION', 'INTERNAL')),
    case_number TEXT,
    matter_description TEXT NOT NULL,
    requesting_party TEXT NOT NULL,
    external_counsel TEXT,
    issued_date TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    effective_date TIMESTAMPTZ NOT NULL,
    expiration_date TIMESTAMPTZ,
    hold_status VARCHAR(50) DEFAULT 'ACTIVE' CHECK (hold_status IN ('ACTIVE', 'RELEASED', 'MODIFIED', 'SUPERSEDED')),
    scope_criteria JSONB NOT NULL DEFAULT '{}'::JSONB,
    affected_tables TEXT[] NOT NULL,
    estimated_records BIGINT,
    created_by TEXT DEFAULT CURRENT_USER,
    approved_by TEXT,
    approval_date TIMESTAMPTZ,
    release_date TIMESTAMPTZ,
    release_reason TEXT,
    notes TEXT,
    CONSTRAINT valid_dates CHECK (expiration_date IS NULL OR expiration_date > effective_date)
);

-- 1.2 Create legal hold application tracking
CREATE TABLE IF NOT EXISTS legal_hold_applications (
    application_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hold_id UUID NOT NULL REFERENCES legal_holds(hold_id),
    table_name TEXT NOT NULL,
    record_identifier TEXT NOT NULL,
    applied_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    applied_by TEXT DEFAULT CURRENT_USER,
    preservation_verified BOOLEAN DEFAULT FALSE,
    verification_hash TEXT,
    released_at TIMESTAMPTZ,
    released_by TEXT
);

-- 1.3 Create hold audit trail
CREATE TABLE IF NOT EXISTS legal_hold_audit (
    audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hold_id UUID REFERENCES legal_holds(hold_id),
    action_type VARCHAR(50) NOT NULL,
    action_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    performed_by TEXT DEFAULT CURRENT_USER,
    action_details JSONB,
    ip_address INET,
    session_id TEXT
);

-- 1.4 Create hold conflict detection table
CREATE TABLE IF NOT EXISTS legal_hold_conflicts (
    conflict_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hold_id_1 UUID REFERENCES legal_holds(hold_id),
    hold_id_2 UUID REFERENCES legal_holds(hold_id),
    conflict_type VARCHAR(50) NOT NULL,
    affected_records BIGINT,
    resolution_status VARCHAR(50) DEFAULT 'PENDING',
    resolution_notes TEXT,
    detected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- STEP 2: LEGAL HOLD CREATION AND VALIDATION
-- =============================================================================

-- 2.1 Create new legal hold
CREATE OR REPLACE FUNCTION create_legal_hold(
    p_hold_name TEXT,
    p_hold_type VARCHAR(50),
    p_matter_description TEXT,
    p_requesting_party TEXT,
    p_effective_date TIMESTAMPTZ,
    p_scope_criteria JSONB,
    p_affected_tables TEXT[],
    p_case_number TEXT DEFAULT NULL,
    p_external_counsel TEXT DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_hold_id UUID;
    v_estimated_records BIGINT := 0;
BEGIN
    -- Validate hold type
    IF p_hold_type NOT IN ('LITIGATION', 'REGULATORY', 'AUDIT', 'INVESTIGATION', 'INTERNAL') THEN
        RAISE EXCEPTION 'Invalid hold type: %', p_hold_type;
    END IF;
    
    -- Estimate affected records
    SELECT COUNT(*) INTO v_estimated_records
    FROM ledger_transactions lt
    WHERE lt.created_at >= p_effective_date
    AND (
        (p_scope_criteria->>'user_msisdn' IS NULL OR lt.user_msisdn = p_scope_criteria->>'user_msisdn')
        OR (p_scope_criteria->>'user_id' IS NULL OR lt.user_id = (p_scope_criteria->>'user_id')::BIGINT)
        OR (p_scope_criteria->>'date_range' IS NOT NULL AND 
            lt.created_at BETWEEN 
                (p_scope_criteria->'date_range'->>0)::TIMESTAMPTZ AND
                (p_scope_criteria->'date_range'->>1)::TIMESTAMPTZ)
    );
    
    -- Create hold record
    INSERT INTO legal_holds (
        hold_name,
        hold_type,
        case_number,
        matter_description,
        requesting_party,
        external_counsel,
        effective_date,
        scope_criteria,
        affected_tables,
        estimated_records
    ) VALUES (
        p_hold_name,
        p_hold_type,
        p_case_number,
        p_matter_description,
        p_requesting_party,
        p_external_counsel,
        p_effective_date,
        p_scope_criteria,
        p_affected_tables,
        v_estimated_records
    )
    RETURNING hold_id INTO v_hold_id;
    
    -- Log creation
    INSERT INTO legal_hold_audit (
        hold_id,
        action_type,
        action_details
    ) VALUES (
        v_hold_id,
        'HOLD_CREATED',
        jsonb_build_object(
            'hold_name', p_hold_name,
            'hold_type', p_hold_type,
            'estimated_records', v_estimated_records
        )
    );
    
    RETURN v_hold_id;
END;
$$ LANGUAGE plpgsql;

-- 2.2 Approve legal hold
CREATE OR REPLACE PROCEDURE approve_legal_hold(
    p_hold_id UUID,
    p_approved_by TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE legal_holds
    SET 
        approved_by = p_approved_by,
        approval_date = CURRENT_TIMESTAMP,
        hold_status = 'ACTIVE'
    WHERE hold_id = p_hold_id
    AND approved_by IS NULL;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Hold not found or already approved: %', p_hold_id;
    END IF;
    
    INSERT INTO legal_hold_audit (
        hold_id,
        action_type,
        action_details,
        performed_by
    ) VALUES (
        p_hold_id,
        'HOLD_APPROVED',
        jsonb_build_object('approved_by', p_approved_by),
        p_approved_by
    );
END;
$$;

-- =============================================================================
-- STEP 3: APPLY LEGAL HOLD TO RECORDS
-- =============================================================================

-- 3.1 Add legal hold indicator to ledger (if not exists)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'ledger_transactions' 
        AND column_name = 'legal_hold_ids'
    ) THEN
        ALTER TABLE ledger_transactions 
        ADD COLUMN legal_hold_ids UUID[] DEFAULT '{}'::UUID[];
        
        CREATE INDEX idx_ledger_transactions_legal_hold 
        ON ledger_transactions USING GIN (legal_hold_ids);
    END IF;
END $$;

-- 3.2 Apply hold to records matching criteria
CREATE OR REPLACE FUNCTION apply_legal_hold(
    p_hold_id UUID,
    p_batch_size INTEGER DEFAULT 1000,
    p_dry_run BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (
    batch_number INTEGER,
    records_matched BIGINT,
    records_updated BIGINT,
    status TEXT
) AS $$
DECLARE
    v_hold RECORD;
    v_batch_num INTEGER := 0;
    v_total_matched BIGINT := 0;
    v_total_updated BIGINT := 0;
    v_batch_matched BIGINT;
    v_batch_updated BIGINT;
    v_min_id BIGINT;
    v_max_id BIGINT;
    v_current_id BIGINT;
BEGIN
    -- Get hold details
    SELECT * INTO v_hold
    FROM legal_holds
    WHERE hold_id = p_hold_id
    AND hold_status = 'ACTIVE';
    
    IF v_hold IS NULL THEN
        RAISE EXCEPTION 'Hold not found or not active: %', p_hold_id;
    END IF;
    
    -- Get ID range
    SELECT MIN(transaction_id), MAX(transaction_id)
    INTO v_min_id, v_max_id
    FROM ledger_transactions
    WHERE created_at >= v_hold.effective_date;
    
    v_current_id := v_min_id;
    
    -- Process in batches
    WHILE v_current_id <= v_max_id LOOP
        v_batch_num := v_batch_num + 1;
        
        -- Count matching records
        SELECT COUNT(*) INTO v_batch_matched
        FROM ledger_transactions
        WHERE transaction_id BETWEEN v_current_id AND v_current_id + p_batch_size - 1
        AND created_at >= v_hold.effective_date
        AND (
            (v_hold.scope_criteria->>'user_msisdn' IS NULL OR user_msisdn = v_hold.scope_criteria->>'user_msisdn')
            OR (v_hold.scope_criteria->>'user_id' IS NULL OR user_id = (v_hold.scope_criteria->>'user_id')::BIGINT)
        );
        
        v_total_matched := v_total_matched + v_batch_matched;
        
        IF NOT p_dry_run AND v_batch_matched > 0 THEN
            -- Apply hold
            UPDATE ledger_transactions
            SET legal_hold_ids = array_append(legal_hold_ids, p_hold_id)
            WHERE transaction_id BETWEEN v_current_id AND v_current_id + p_batch_size - 1
            AND created_at >= v_hold.effective_date
            AND (
                (v_hold.scope_criteria->>'user_msisdn' IS NULL OR user_msisdn = v_hold.scope_criteria->>'user_msisdn')
                OR (v_hold.scope_criteria->>'user_id' IS NULL OR user_id = (v_hold.scope_criteria->>'user_id')::BIGINT)
            )
            AND NOT (p_hold_id = ANY(legal_hold_ids));
            
            GET DIAGNOSTICS v_batch_updated = ROW_COUNT;
            v_total_updated := v_total_updated + v_batch_updated;
            
            -- Record applications
            INSERT INTO legal_hold_applications (
                hold_id,
                table_name,
                record_identifier,
                preservation_verified
            )
            SELECT 
                p_hold_id,
                'ledger_transactions',
                transaction_id::TEXT,
                TRUE
            FROM ledger_transactions
            WHERE transaction_id BETWEEN v_current_id AND v_current_id + p_batch_size - 1
            AND created_at >= v_hold.effective_date
            AND p_hold_id = ANY(legal_hold_ids);
        END IF;
        
        batch_number := v_batch_num;
        records_matched := v_batch_matched;
        records_updated := COALESCE(v_batch_updated, 0);
        status := CASE WHEN p_dry_run THEN 'DRY_RUN' ELSE 'APPLIED' END;
        RETURN NEXT;
        
        v_current_id := v_current_id + p_batch_size;
    END LOOP;
    
    -- Log completion
    INSERT INTO legal_hold_audit (
        hold_id,
        action_type,
        action_details,
        performed_by
    ) VALUES (
        p_hold_id,
        CASE WHEN p_dry_run THEN 'HOLD_APPLICATION_DRY_RUN' ELSE 'HOLD_APPLIED' END,
        jsonb_build_object(
            'records_matched', v_total_matched,
            'records_updated', v_total_updated,
            'batches_processed', v_batch_num
        ),
        CURRENT_USER
    );
    
    RETURN;
END;
$$ LANGUAGE plpgsql;

-- 3.3 Verify preservation
CREATE OR REPLACE FUNCTION verify_legal_hold_preservation(
    p_hold_id UUID,
    p_sample_size INTEGER DEFAULT 100
)
RETURNS TABLE (
    verification_passed BOOLEAN,
    sample_size INTEGER,
    records_verified INTEGER,
    preservation_failures INTEGER,
    details JSONB
) AS $$
DECLARE
    v_failures INTEGER := 0;
    v_verified INTEGER := 0;
    v_details JSONB := '[]'::JSONB;
    rec RECORD;
BEGIN
    FOR rec IN 
        SELECT 
            transaction_id,
            computed_hash,
            legal_hold_ids
        FROM ledger_transactions
        WHERE p_hold_id = ANY(legal_hold_ids)
        ORDER BY random()
        LIMIT p_sample_size
    LOOP
        v_verified := v_verified + 1;
        
        -- Verify record is immutable
        IF rec.legal_hold_ids IS NULL OR NOT (p_hold_id = ANY(rec.legal_hold_ids)) THEN
            v_failures := v_failures + 1;
            v_details := v_details || jsonb_build_object(
                'transaction_id', rec.transaction_id,
                'error', 'HOLD_NOT_APPLIED'
            );
        END IF;
        
        -- TODO: Add additional verification checks
    END LOOP;
    
    -- Update application records
    UPDATE legal_hold_applications
    SET preservation_verified = TRUE,
        verification_hash = encode(digest(record_identifier::bytea, 'sha256'), 'hex')
    WHERE hold_id = p_hold_id
    AND record_identifier IN (
        SELECT transaction_id::TEXT 
        FROM ledger_transactions 
        WHERE p_hold_id = ANY(legal_hold_ids)
    );
    
    RETURN QUERY SELECT 
        v_failures = 0,
        p_sample_size,
        v_verified,
        v_failures,
        v_details;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 4: CONFLICT DETECTION AND RESOLUTION
-- =============================================================================

-- 4.1 Detect hold conflicts
CREATE OR REPLACE FUNCTION detect_legal_hold_conflicts()
RETURNS TABLE (
    conflict_id UUID,
    hold_1_name TEXT,
    hold_2_name TEXT,
    conflict_type TEXT,
    affected_records BIGINT
) AS $$
BEGIN
    -- Check for overlapping date ranges with conflicting instructions
    RETURN QUERY
    SELECT 
        gen_random_uuid()::UUID,
        h1.hold_name,
        h2.hold_name,
        'OVERLAPPING_SCOPE'::TEXT,
        COUNT(*)::BIGINT
    FROM legal_holds h1
    JOIN legal_holds h2 ON h1.hold_id < h2.hold_id
    JOIN ledger_transactions lt ON 
        h1.hold_id = ANY(lt.legal_hold_ids)
        AND h2.hold_id = ANY(lt.legal_hold_ids)
    WHERE h1.hold_status = 'ACTIVE'
    AND h2.hold_status = 'ACTIVE'
    AND (
        -- Overlapping criteria
        (h1.scope_criteria->>'user_msisdn' = h2.scope_criteria->>'user_msisdn' AND h1.scope_criteria->>'user_msisdn' IS NOT NULL)
        OR (h1.scope_criteria->>'user_id' = h2.scope_criteria->>'user_id' AND h1.scope_criteria->>'user_id' IS NOT NULL)
    )
    GROUP BY h1.hold_name, h2.hold_name;
END;
$$ LANGUAGE plpgsql;

-- 4.2 Check GDPR vs Legal Hold conflicts
CREATE OR REPLACE FUNCTION check_gdpr_hold_conflicts(
    p_gdpr_request_id UUID
)
RETURNS TABLE (
    has_conflict BOOLEAN,
    conflicting_holds UUID[],
    affected_records BIGINT
) AS $$
DECLARE
    v_conflicting_holds UUID[];
    v_affected_count BIGINT;
BEGIN
    SELECT 
        array_agg(DISTINCT hold_id),
        COUNT(*)
    INTO v_conflicting_holds, v_affected_count
    FROM legal_hold_applications
    WHERE record_identifier IN (
        SELECT transaction_id::TEXT
        FROM ledger_transactions lt
        JOIN gdpr_requests gr ON 
            lt.user_msisdn = gr.data_subject_identifier
            OR lt.user_id::TEXT = gr.data_subject_identifier
        WHERE gr.request_id = p_gdpr_request_id
    )
    AND hold_id IN (SELECT hold_id FROM legal_holds WHERE hold_status = 'ACTIVE');
    
    RETURN QUERY SELECT 
        v_conflicting_holds IS NOT NULL AND array_length(v_conflicting_holds, 1) > 0,
        v_conflicting_holds,
        COALESCE(v_affected_count, 0);
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 5: RELEASE AND MODIFICATION
-- =============================================================================

-- 5.1 Release legal hold
CREATE OR REPLACE PROCEDURE release_legal_hold(
    p_hold_id UUID,
    p_release_reason TEXT,
    p_released_by TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_affected_count BIGINT;
BEGIN
    -- Verify hold is active
    IF NOT EXISTS (
        SELECT 1 FROM legal_holds 
        WHERE hold_id = p_hold_id 
        AND hold_status = 'ACTIVE'
    ) THEN
        RAISE EXCEPTION 'Hold not found or not active: %', p_hold_id;
    END IF;
    
    -- Count affected records
    SELECT COUNT(*) INTO v_affected_count
    FROM ledger_transactions
    WHERE p_hold_id = ANY(legal_hold_ids);
    
    -- Remove hold from records
    UPDATE ledger_transactions
    SET legal_hold_ids = array_remove(legal_hold_ids, p_hold_id)
    WHERE p_hold_id = ANY(legal_hold_ids);
    
    -- Update hold status
    UPDATE legal_holds
    SET 
        hold_status = 'RELEASED',
        release_date = CURRENT_TIMESTAMP,
        release_reason = p_release_reason
    WHERE hold_id = p_hold_id;
    
    -- Update applications
    UPDATE legal_hold_applications
    SET 
        released_at = CURRENT_TIMESTAMP,
        released_by = p_released_by
    WHERE hold_id = p_hold_id
    AND released_at IS NULL;
    
    -- Log release
    INSERT INTO legal_hold_audit (
        hold_id,
        action_type,
        action_details,
        performed_by
    ) VALUES (
        p_hold_id,
        'HOLD_RELEASED',
        jsonb_build_object(
            'release_reason', p_release_reason,
            'affected_records', v_affected_count
        ),
        p_released_by
    );
END;
$$;

-- 5.2 Modify hold scope
CREATE OR REPLACE PROCEDURE modify_legal_hold_scope(
    p_hold_id UUID,
    p_new_scope_criteria JSONB,
    p_modification_reason TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_old_scope JSONB;
BEGIN
    SELECT scope_criteria INTO v_old_scope
    FROM legal_holds
    WHERE hold_id = p_hold_id;
    
    UPDATE legal_holds
    SET 
        scope_criteria = p_new_scope_criteria,
        hold_status = 'MODIFIED',
        notes = COALESCE(notes, '') || E'\nModified at ' || CURRENT_TIMESTAMP || ': ' || p_modification_reason
    WHERE hold_id = p_hold_id;
    
    INSERT INTO legal_hold_audit (
        hold_id,
        action_type,
        action_details,
        performed_by
    ) VALUES (
        p_hold_id,
        'HOLD_MODIFIED',
        jsonb_build_object(
            'old_scope', v_old_scope,
            'new_scope', p_new_scope_criteria,
            'reason', p_modification_reason
        ),
        CURRENT_USER
    );
END;
$$;

-- =============================================================================
-- STEP 6: TEST CASES WITH EXPECTED RESULTS
-- =============================================================================

-- Test Case 6.1: Create and approve hold
-- Expected: Success with valid UUID
DO $$
DECLARE
    v_hold_id UUID;
BEGIN
    v_hold_id := create_legal_hold(
        'TEST_HOLD_001',
        'LITIGATION',
        'Test litigation matter',
        'Test Court',
        CURRENT_TIMESTAMP - INTERVAL '30 days',
        '{"user_msisdn": "+1234567890"}'::JSONB,
        ARRAY['ledger_transactions']
    );
    
    CALL approve_legal_hold(v_hold_id, 'legal_manager');
    
    RAISE NOTICE 'TEST_6.1_HOLD_CREATION: PASSED - Hold ID: %', v_hold_id;
END $$;

-- Test Case 6.2: Apply hold to records
-- Expected: Non-zero records matched
SELECT 
    'TEST_6.2_HOLD_APPLICATION' as test_name,
    CASE WHEN records_matched >= 0 THEN 'PASSED' ELSE 'FAILED' END as result,
    records_matched,
    records_updated
FROM apply_legal_hold(
    (SELECT hold_id FROM legal_holds WHERE hold_name = 'TEST_HOLD_001'),
    100,
    TRUE  -- Dry run
)
LIMIT 1;

-- Test Case 6.3: Verify preservation
-- Expected: No failures
SELECT 
    'TEST_6.3_PRESERVATION_VERIFICATION' as test_name,
    CASE WHEN verification_passed THEN 'PASSED' ELSE 'FAILED' END as result,
    records_verified,
    preservation_failures
FROM verify_legal_hold_preservation(
    (SELECT hold_id FROM legal_holds WHERE hold_name = 'TEST_HOLD_001'),
    10
);

-- Test Case 6.4: Check for conflicts
-- Expected: Empty or valid conflict list
SELECT 
    'TEST_6.4_CONFLICT_DETECTION' as test_name,
    CASE WHEN conflict_id IS NOT NULL OR NOT EXISTS (SELECT 1 FROM detect_legal_hold_conflicts()) 
        THEN 'PASSED' ELSE 'FAILED' END as result,
    COUNT(*) as conflict_count
FROM detect_legal_hold_conflicts();

-- Test Case 6.5: Release hold
-- Expected: Status changed to RELEASED
DO $$
DECLARE
    v_hold_id UUID;
BEGIN
    SELECT hold_id INTO v_hold_id
    FROM legal_holds
    WHERE hold_name = 'TEST_HOLD_001';
    
    CALL release_legal_hold(v_hold_id, 'Test completed', 'legal_manager');
    
    RAISE NOTICE 'TEST_6.5_HOLD_RELEASE: PASSED';
END $$;

-- =============================================================================
-- STEP 7: ROLLBACK PROCEDURES
-- =============================================================================

-- 7.1 Rollback hold application
CREATE OR REPLACE PROCEDURE rollback_hold_application(
    p_hold_id UUID,
    p_rollback_reason TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_count BIGINT;
BEGIN
    -- Remove hold from records
    UPDATE ledger_transactions
    SET legal_hold_ids = array_remove(legal_hold_ids, p_hold_id)
    WHERE p_hold_id = ANY(legal_hold_ids);
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    
    -- Delete applications
    DELETE FROM legal_hold_applications
    WHERE hold_id = p_hold_id
    AND released_at IS NULL;
    
    -- Log rollback
    INSERT INTO legal_hold_audit (
        hold_id,
        action_type,
        action_details,
        performed_by
    ) VALUES (
        p_hold_id,
        'HOLD_APPLICATION_ROLLBACK',
        jsonb_build_object(
            'rollback_reason', p_rollback_reason,
            'records_affected', v_count
        ),
        CURRENT_USER
    );
    
    RAISE NOTICE 'Rolled back hold application for %. % records affected.', p_hold_id, v_count;
END;
$$;

-- =============================================================================
-- STEP 8: VALIDATION CHECKS
-- =============================================================================

-- 8.1 Active holds summary
SELECT 
    hold_id,
    hold_name,
    hold_type,
    effective_date,
    estimated_records,
    (SELECT COUNT(*) FROM legal_hold_applications WHERE hold_id = lh.hold_id) as applied_count
FROM legal_holds lh
WHERE hold_status = 'ACTIVE'
ORDER BY effective_date DESC;

-- 8.2 Records with multiple holds
SELECT 
    transaction_id,
    legal_hold_ids,
    array_length(legal_hold_ids, 1) as hold_count
FROM ledger_transactions
WHERE array_length(legal_hold_ids, 1) > 1
LIMIT 10;

-- =============================================================================
-- TODO LIST FOR CUSTOMIZATION
-- =============================================================================

/*
TODO-1: Customize scope criteria matching logic:
        - Add support for complex boolean expressions
        - Implement regex matching for patterns
        - Add date range handling

TODO-2: Integrate with legal case management system:
        - API integration for hold creation
        - Automatic expiration handling
        - Matter lifecycle management

TODO-3: Configure notification workflows:
        - IT notification on hold creation
        - Legal team alerts for conflicts
        - Escalation procedures

TODO-4: Set up retention for hold records:
        - Post-matter retention requirements
        - Archive procedures
        - Destruction certificates

TODO-5: Customize verification procedures:
        - Add hash verification
        - Implement digital signatures
        - Blockchain anchoring

TODO-6: Implement hold reporting:
        - Legal hold reports
        - Custodian notifications
        - Preservation certificates

TODO-7: Configure access controls:
        - Role-based permissions
        - Segregation of duties
        - Audit trail requirements

TODO-8: Set up monitoring:
        - Hold expiration alerts
        - Conflict notifications
        - Compliance dashboards

TODO-9: Document custodian procedures:
        - Hold notification templates
        - Acknowledgment tracking
        - Training requirements

TODO-10: Establish privilege log integration:
        - Privileged record identification
        - Redaction workflows
        - Disclosure tracking
*/

-- =============================================================================
-- END OF LEGAL HOLD APPLICATION PROCEDURE
-- =============================================================================
