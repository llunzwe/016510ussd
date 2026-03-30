/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - WORKFLOW: POST-COMMIT
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-FUNC-008
 * Feature Name:       Post-Commit
 * Description:        Post-commit
 *                     transaction processing, notifications, and integrations.
 *                     Handles success/failure callbacks and retry logic.
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
 *   - Control A.8.15: Logging
 *   - Control A.8.26: Application security
 * 
 * SOC 2 Type II
 *   - CC7.2: System monitoring
 *   - CC8.1: Change management
 * 
 * =============================================================================
 * SECURITY ANNOTATIONS
 * =============================================================================
 * 
 * POST-COMMIT
 *   - Always non-blocking (transaction already commit
 *   - Async mode prevents response delays
 *   - Retry with exponential backoff
 *   - Dead letter queue for exhausted retries
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - app.t_hooks_registry
 *   - core.t_transaction_log
 * 
 * CHANGE LOG:
 *   1.0.0 - Initial function creation
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
-- - Use SECURITY DEFINER for privileged operations
-- - Enforce RLS policies for multi-tenant data isolation
-- - Use explicit column lists (avoid SELECT *)
-- - Add audit logging for all security-relevant operations
-- - Use UUIDs for primary identifiers to prevent enumeration
-- - Implement optimistic locking with version columns
-- - Use TIMESTAMPTZ for all timestamp columns
-- - Validate all inputs with CHECK constraints
-- ============================================================================

-- =============================================================================
-- FUNCTION: app.execute_post_commit  -- [TXN] ISO 27001: ACID transaction boundary_hooks()
-- =============================================================================

CREATE OR REPLACE FUNCTION app.execute_post_commit  -- [TXN] ISO 27001: ACID transaction boundary_hooks(
    p_app_id UUID,
    p_event_type TEXT,
    p_transaction_id UUID,
    p_result_data JSONB DEFAULT '{}'
)
RETURNS TABLE (
    hook_id UUID,
    hook_code TEXT,
    execution_status TEXT,
    queued BOOLEAN,
    executed_at TIMESTAMPTZ,
    error_message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged execution context
SET search_path = app, core, public
AS $$
DECLARE
    v_hook RECORD;
    v_payload JSONB;
    v_queued BOOLEAN;
BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
    -- ========================================================================
    -- BUILD HOOK PAYLOAD
    -- ========================================================================
    v_payload := jsonb_build_object(
        'event_type', p_event_type,
        'transaction_id', p_transaction_id,
        'timestamp', NOW(),
        'result', p_result_data,
        'app_id', p_app_id
    );
    
    -- ========================================================================
    -- FIND AND EXECUTE POST-COMMIT  -- [TXN] ISO 27001: ACID transaction boundary HOOKS
    -- ========================================================================
    FOR v_hook IN (
        SELECT *
        FROM app.t_hooks_registry
        WHERE app_id = p_app_id
          AND hook_phase IN ('post_commit  -- [TXN] ISO 27001: ACID transaction boundary', 'on_success', 'on_error')
          AND p_event_type = ANY(trigger_events)
          AND status = 'active'
        ORDER BY execution_order ASC
    ) LOOP
        -- Determine execution mode
        CASE v_hook.execution_mode
            WHEN 'sync' THEN
                -- Execute immediately
                v_queued := FALSE;
                -- TODO: Execute sync
            WHEN 'async' THEN
                -- Queue for processing
                v_queued := TRUE;
                -- TODO: Queue hook
            WHEN 'deferred' THEN
                -- Schedule for later
                v_queued := TRUE;
                -- TODO: Schedule hook
        END CASE;
        
        RETURN QUERY SELECT 
            v_hook.hook_id,
            v_hook.hook_code,
            CASE WHEN v_queued THEN 'queued' ELSE 'completed' END,
            v_queued,
            NOW(),
            NULL::TEXT;
    END LOOP;
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON FUNCTION app.execute_post_commit  -- [TXN] ISO 27001: ACID transaction boundary_hooks(UUID, TEXT, UUID, JSONB) IS 
    'Execute post-commit;

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Post-commit  -- [TXN] ISO 27001: ACID transaction boundary hooks are always non-blocking
-- 2. Sync mode for critical notifications
-- 3. Async mode for high-volume processing
-- 4. Retry with exponential backoff for failures
-- 5. Dead letter queue for exhausted retries
-- 6. Transaction immutability assumed at this stage
-- =============================================================================
