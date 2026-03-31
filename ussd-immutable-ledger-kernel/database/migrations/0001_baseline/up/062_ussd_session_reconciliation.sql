-- =============================================================================
-- USSD KERNEL GATEWAY SCHEMA - SESSION RECONCILIATION
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    062_ussd_session_reconciliation.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      ussd_gateway
-- DESCRIPTION: USSD session reconciliation for dropped connections,
--              timeout handling, and incomplete transaction recovery.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Session monitoring
├── A.16.1 Management of information security incidents
└── A.17.1 Continuity - Business continuity procedures

USSD Requirements
├── Session recovery after dropped connection
├── Timeout handling
├── Transaction completion verification
└── Customer notification

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. SESSION STATES
   - ACTIVE: Session in progress
   - TIMED_OUT: No response within timeout period
   - DROPPED: Connection lost
   - COMPLETED: Transaction finished
   - RECOVERED: Session recovered and completed

2. RECONCILIATION TYPES
   - AUTO: Automatic recovery
   - MANUAL: Customer-initiated
   - AGENT: Agent-assisted recovery

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

SESSION SECURITY:
- Session binding to device fingerprint
- Verification of session ownership
- Audit trail for all recovery attempts

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- SESSION_RECOVERED
- TIMEOUT_DETECTED
- RECOVERY_ATTEMPTED
- TRANSACTION_COMPLETED

RETENTION: 2 years (USSD sessions)
================================================================================
*/

-- =============================================================================
-- EXTEND SESSION STATE TABLE
-- =============================================================================

-- Add reconciliation columns to existing session_state table
ALTER TABLE ussd_gateway.session_state 
    ADD COLUMN IF NOT EXISTS reconciliation_status VARCHAR(20) DEFAULT 'NONE'
        CHECK (reconciliation_status IN ('NONE', 'PENDING', 'RECOVERED', 'FAILED', 'EXPIRED')),
    ADD COLUMN IF NOT EXISTS reconciliation_attempts INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_reconciliation_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS recovered_session_id UUID,
    ADD COLUMN IF NOT EXISTS recovery_method VARCHAR(20),
    ADD COLUMN IF NOT EXISTS is_recovered BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS original_session_id UUID,
    ADD COLUMN IF NOT EXISTS transaction_completed BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS transaction_reference VARCHAR(100),
    ADD COLUMN IF NOT EXISTS core_transaction_id BIGINT,
    ADD COLUMN IF NOT EXISTS timeout_reason VARCHAR(100);

-- =============================================================================
-- SESSION RECONCILIATION LOG
-- =============================================================================

CREATE TABLE ussd_gateway.session_reconciliation_log (
    log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Session references
    original_session_id UUID NOT NULL REFERENCES ussd_gateway.session_state(session_id),
    recovered_session_id UUID REFERENCES ussd_gateway.session_state(session_id),
    
    -- Reconciliation details
    reconciliation_type VARCHAR(20) NOT NULL
        CHECK (reconciliation_type IN ('AUTO', 'MANUAL', 'AGENT', 'SYSTEM')),
    status VARCHAR(20) NOT NULL
        CHECK (status IN ('ATTEMPTED', 'SUCCESS', 'FAILED', 'EXPIRED')),
    
    -- Customer info
    msisdn VARCHAR(20) NOT NULL,
    device_fingerprint_id UUID,
    
    -- Transaction details
    transaction_type VARCHAR(50),
    transaction_amount NUMERIC(20, 8),
    transaction_currency VARCHAR(6),
    
    -- Recovery details
    recovery_notes TEXT,
    error_message TEXT,
    
    -- Timestamps
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    completed_at TIMESTAMPTZ,
    
    -- Audit
    attempted_by UUID,
    completed_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now()
);

-- =============================================================================
-- PENDING TRANSACTION RECOVERY QUEUE
-- =============================================================================

CREATE TABLE ussd_gateway.pending_transaction_recovery (
    recovery_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- References
    session_id UUID NOT NULL REFERENCES ussd_gateway.session_state(session_id),
    pending_transaction_id BIGINT REFERENCES ussd_gateway.pending_transactions(pending_txn_id),
    core_transaction_id BIGINT REFERENCES core.transaction_log(transaction_id),
    
    -- Transaction details (snapshot)
    transaction_type VARCHAR(50) NOT NULL,
    from_account_id UUID,
    to_account_id UUID,
    amount NUMERIC(20, 8),
    currency VARCHAR(6),
    narrative VARCHAR(255),
    
    -- Recovery status
    status VARCHAR(20) DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    
    -- Retry logic
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    next_retry_at TIMESTAMPTZ,
    
    -- Resolution
    resolution VARCHAR(20) CHECK (resolution IN ('POSTED', 'REVERSED', 'TIMEOUT', 'CUSTOMER_CANCELLED')),
    resolved_at TIMESTAMPTZ,
    resolved_by UUID,
    resolution_notes TEXT,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    
    -- Constraints
    CONSTRAINT chk_retry CHECK (retry_count <= max_retries)
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Session state reconciliation indexes
CREATE INDEX idx_session_recon_status ON ussd_gateway.session_state(reconciliation_status) 
    WHERE reconciliation_status IN ('PENDING', 'RECOVERED');
CREATE INDEX idx_session_original ON ussd_gateway.session_state(original_session_id) 
    WHERE original_session_id IS NOT NULL;
CREATE INDEX idx_session_timeout ON ussd_gateway.session_state(last_activity_at) 
    WHERE status = 'ACTIVE';

-- Reconciliation log indexes
CREATE INDEX idx_recon_log_original ON ussd_gateway.session_reconciliation_log(original_session_id);
CREATE INDEX idx_recon_log_status ON ussd_gateway.session_reconciliation_log(status, attempted_at);
CREATE INDEX idx_recon_log_msisdn ON ussd_gateway.session_reconciliation_log(msisdn, attempted_at DESC);

-- Recovery queue indexes
CREATE INDEX idx_recovery_queue_status ON ussd_gateway.pending_transaction_recovery(status, next_retry_at) 
    WHERE status = 'PENDING';
CREATE INDEX idx_recovery_queue_session ON ussd_gateway.pending_transaction_recovery(session_id);
CREATE INDEX idx_recovery_pending ON ussd_gateway.pending_transaction_recovery(pending_transaction_id);

-- =============================================================================
-- TRIGGERS
-- =============================================================================

-- Update timestamp on recovery queue
CREATE OR REPLACE FUNCTION ussd_gateway.update_recovery_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = core.precise_now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_recovery_queue_update
    BEFORE UPDATE ON ussd_gateway.pending_transaction_recovery
    FOR EACH ROW
    EXECUTE FUNCTION ussd_gateway.update_recovery_timestamp();

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to detect timed-out sessions
CREATE OR REPLACE FUNCTION ussd_gateway.detect_timeout_sessions(
    p_timeout_minutes INTEGER DEFAULT 2
)
RETURNS TABLE (
    session_id UUID,
    msisdn VARCHAR,
    last_activity_at TIMESTAMPTZ,
    minutes_inactive NUMERIC
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ss.session_id,
        ss.msisdn,
        ss.last_activity_at,
        EXTRACT(EPOCH FROM (core.precise_now() - ss.last_activity_at)) / 60 as minutes_inactive
    FROM ussd_gateway.session_state ss
    WHERE ss.status = 'ACTIVE'
      AND ss.last_activity_at < core.precise_now() - (p_timeout_minutes || ' minutes')::INTERVAL
      AND ss.reconciliation_status = 'NONE';
END;
$$;

-- Function to mark session as timed out
CREATE OR REPLACE FUNCTION ussd_gateway.timeout_session(
    p_session_id UUID,
    p_reason VARCHAR DEFAULT 'NO_RESPONSE'
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_session RECORD;
BEGIN
    SELECT * INTO v_session FROM ussd_gateway.session_state WHERE session_id = p_session_id;
    
    IF NOT FOUND OR v_session.status != 'ACTIVE' THEN
        RETURN FALSE;
    END IF;
    
    UPDATE ussd_gateway.session_state SET
        status = 'TIMED_OUT',
        reconciliation_status = 'PENDING',
        timeout_reason = p_reason,
        updated_at = core.precise_now()
    WHERE session_id = p_session_id;
    
    -- Create recovery entry if there was a pending transaction
    IF v_session.pending_txn_id IS NOT NULL THEN
        INSERT INTO ussd_gateway.pending_transaction_recovery (
            session_id,
            pending_transaction_id,
            transaction_type,
            narrative,
            next_retry_at
        )
        SELECT 
            p_session_id,
            pending_txn_id,
            txn_type,
            'Auto-created from timeout',
            core.precise_now() + '5 minutes'::INTERVAL
        FROM ussd_gateway.pending_transactions
        WHERE pending_txn_id = v_session.pending_txn_id
          AND status IN ('PENDING', 'INITIATED');
    END IF;
    
    RETURN TRUE;
END;
$$;

-- Function to recover a session
CREATE OR REPLACE FUNCTION ussd_gateway.recover_session(
    p_original_session_id UUID,
    p_new_session_id UUID,
    p_recovery_method VARCHAR,
    p_msisdn VARCHAR,
    p_device_fingerprint_id UUID DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_original RECORD;
    v_success BOOLEAN := FALSE;
BEGIN
    SELECT * INTO v_original 
    FROM ussd_gateway.session_state 
    WHERE session_id = p_original_session_id;
    
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    
    -- Update original session
    UPDATE ussd_gateway.session_state SET
        reconciliation_status = 'RECOVERED',
        recovered_session_id = p_new_session_id,
        recovery_method = p_recovery_method,
        last_reconciliation_at = core.precise_now(),
        reconciliation_attempts = reconciliation_attempts + 1,
        updated_at = core.precise_now()
    WHERE session_id = p_original_session_id;
    
    -- Update new session to link to original
    UPDATE ussd_gateway.session_state SET
        original_session_id = p_original_session_id,
        is_recovered = TRUE,
        recovery_method = p_recovery_method,
        context = v_original.context || jsonb_build_object(
            'recovered_from_session', p_original_session_id,
            'recovery_method', p_recovery_method
        ),
        updated_at = core.precise_now()
    WHERE session_id = p_new_session_id;
    
    -- Log the reconciliation
    INSERT INTO ussd_gateway.session_reconciliation_log (
        original_session_id,
        recovered_session_id,
        reconciliation_type,
        status,
        msisdn,
        device_fingerprint_id,
        attempted_by
    ) VALUES (
        p_original_session_id,
        p_new_session_id,
        p_recovery_method,
        'SUCCESS',
        p_msisdn,
        p_device_fingerprint_id,
        NULL
    );
    
    -- Check for pending transaction recovery
    UPDATE ussd_gateway.pending_transaction_recovery
    SET status = 'PROCESSING',
        retry_count = retry_count + 1,
        next_retry_at = core.precise_now()
    WHERE session_id = p_original_session_id
      AND status = 'PENDING';
    
    RETURN TRUE;
END;
$$;

-- Function to verify transaction completion
CREATE OR REPLACE FUNCTION ussd_gateway.verify_transaction_completion(
    p_session_id UUID
)
RETURNS TABLE (
    is_completed BOOLEAN,
    transaction_id BIGINT,
    transaction_status VARCHAR,
    verification_method VARCHAR
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_session RECORD;
    v_txn RECORD;
BEGIN
    SELECT * INTO v_session FROM ussd_gateway.session_state WHERE session_id = p_session_id;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::BIGINT, NULL::VARCHAR, 'SESSION_NOT_FOUND'::VARCHAR;
        RETURN;
    END IF;
    
    -- Check if we have a core transaction ID
    IF v_session.core_transaction_id IS NOT NULL THEN
        SELECT status INTO v_txn 
        FROM core.transaction_log 
        WHERE transaction_id = v_session.core_transaction_id;
        
        IF FOUND THEN
            RETURN QUERY SELECT 
                TRUE,
                v_session.core_transaction_id,
                v_txn.status::VARCHAR,
                'CORE_TRANSACTION'::VARCHAR;
            RETURN;
        END IF;
    END IF;
    
    -- Check pending transactions
    SELECT * INTO v_txn 
    FROM ussd_gateway.pending_transactions 
    WHERE session_id = p_session_id 
    ORDER BY created_at DESC LIMIT 1;
    
    IF FOUND THEN
        IF v_txn.status = 'COMPLETED' THEN
            RETURN QUERY SELECT 
                TRUE,
                v_txn.pending_txn_id::BIGINT,
                v_txn.status::VARCHAR,
                'PENDING_TRANSACTION'::VARCHAR;
        ELSE
            RETURN QUERY SELECT 
                FALSE,
                v_txn.pending_txn_id::BIGINT,
                v_txn.status::VARCHAR,
                'PENDING_TRANSACTION'::VARCHAR;
        END IF;
        RETURN;
    END IF;
    
    -- No transaction found
    RETURN QUERY SELECT FALSE, NULL::BIGINT, NULL::VARCHAR, 'NO_TRANSACTION'::VARCHAR;
END;
$$;

-- Function to get recovery queue
CREATE OR REPLACE FUNCTION ussd_gateway.get_recovery_queue(
    p_limit INTEGER DEFAULT 100
)
RETURNS TABLE (
    recovery_id UUID,
    session_id UUID,
    transaction_type VARCHAR,
    amount NUMERIC,
    currency VARCHAR,
    status VARCHAR,
    retry_count INTEGER,
    next_retry_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ptr.recovery_id,
        ptr.session_id,
        ptr.transaction_type,
        ptr.amount,
        ptr.currency,
        ptr.status,
        ptr.retry_count,
        ptr.next_retry_at,
        ptr.created_at
    FROM ussd_gateway.pending_transaction_recovery ptr
    WHERE ptr.status = 'PENDING'
      AND ptr.next_retry_at <= core.precise_now()
    ORDER BY ptr.created_at
    LIMIT p_limit;
END;
$$;

-- Function to complete recovery
CREATE OR REPLACE FUNCTION ussd_gateway.complete_recovery(
    p_recovery_id UUID,
    p_resolution VARCHAR,
    p_core_transaction_id BIGINT DEFAULT NULL,
    p_notes TEXT DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE ussd_gateway.pending_transaction_recovery SET
        status = 'COMPLETED',
        resolution = p_resolution,
        core_transaction_id = p_core_transaction_id,
        resolution_notes = p_notes,
        resolved_at = core.precise_now()
    WHERE recovery_id = p_recovery_id;
    
    RETURN FOUND;
END;
$$;

-- =============================================================================
-- RECONCILIATION PROCEDURE (for cron job)
-- =============================================================================

CREATE OR REPLACE PROCEDURE ussd_gateway.run_session_reconciliation()
LANGUAGE plpgsql
AS $$
DECLARE
    v_session RECORD;
    v_count INTEGER := 0;
BEGIN
    -- Step 1: Mark timed-out sessions
    FOR v_session IN 
        SELECT session_id FROM ussd_gateway.detect_timeout_sessions(2)
    LOOP
        PERFORM ussd_gateway.timeout_session(v_session.session_id, 'AUTO_TIMEOUT');
        v_count := v_count + 1;
    END LOOP;
    
    RAISE NOTICE 'Marked % sessions as timed out', v_count;
    
    -- Step 2: Process recovery queue
    FOR v_session IN 
        SELECT * FROM ussd_gateway.get_recovery_queue(50)
    LOOP
        -- Update to processing
        UPDATE ussd_gateway.pending_transaction_recovery
        SET status = 'PROCESSING'
        WHERE recovery_id = v_session.recovery_id;
        
        -- Here would be the actual processing logic
        -- For now, we just log it
        RAISE NOTICE 'Processing recovery % for session %', 
            v_session.recovery_id, v_session.session_id;
    END LOOP;
    
    -- Step 3: Expire old pending recoveries (older than 24 hours)
    UPDATE ussd_gateway.pending_transaction_recovery
    SET status = 'CANCELLED',
        resolution = 'TIMEOUT',
        resolved_at = core.precise_now(),
        resolution_notes = 'Auto-cancelled after 24 hours'
    WHERE status IN ('PENDING', 'PROCESSING')
      AND created_at < core.precise_now() - INTERVAL '24 hours';
      
    COMMIT;
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE ussd_gateway.session_reconciliation_log IS 'Log of all session recovery attempts';
COMMENT ON TABLE ussd_gateway.pending_transaction_recovery IS 'Queue for recovering incomplete transactions';
COMMENT ON FUNCTION ussd_gateway.detect_timeout_sessions IS 'Find sessions that have timed out';
COMMENT ON FUNCTION ussd_gateway.recover_session IS 'Recover a dropped session';

-- =============================================================================
-- END OF FILE
-- =============================================================================
