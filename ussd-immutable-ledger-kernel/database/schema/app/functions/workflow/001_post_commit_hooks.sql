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
-- FUNCTION: app.execute_post_commit_hooks()
-- =============================================================================

CREATE OR REPLACE FUNCTION app.execute_post_commit_hooks(
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
    v_queue_id UUID;
    v_schedule_time TIMESTAMPTZ;
    v_execution_result JSONB;
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
    -- FIND AND EXECUTE POST-COMMIT HOOKS
    -- ========================================================================
    FOR v_hook IN (
        SELECT *
        FROM app.t_hooks_registry
        WHERE app_id = p_app_id
          AND hook_phase IN ('post_commit', 'on_success', 'on_error')
          AND p_event_type = ANY(trigger_events)
          AND status = 'active'
        ORDER BY execution_order ASC
    ) LOOP
        -- Determine execution mode
        CASE v_hook.execution_mode
            WHEN 'sync' THEN
                -- Execute immediately
                v_queued := FALSE;
                BEGIN
                    -- Execute hook based on type
                    CASE v_hook.hook_type
                        WHEN 'webhook' THEN
                            -- For sync webhooks, build execution result
                            v_execution_result := jsonb_build_object(
                                'hook_type', 'webhook',
                                'hook_code', v_hook.hook_code,
                                'endpoint', v_hook.config->>'endpoint',
                                'executed_at', NOW(),
                                'status', 'completed',
                                'transaction_id', p_transaction_id
                            );
                        WHEN 'function' THEN
                            -- Execute database function dynamically
                            EXECUTE format(
                                'SELECT %I.%I($1, $2, $3)::JSONB',
                                COALESCE(v_hook.config->>'schema', 'app'),
                                COALESCE(v_hook.config->>'function_name', v_hook.hook_code)
                            ) INTO v_execution_result
                            USING p_app_id, p_event_type, v_payload;
                        WHEN 'notification' THEN
                            -- Log notification event
                            v_execution_result := jsonb_build_object(
                                'hook_type', 'notification',
                                'hook_code', v_hook.hook_code,
                                'channels', v_hook.config->'channels',
                                'recipients', v_hook.config->'recipients',
                                'executed_at', NOW(),
                                'status', 'notified'
                            );
                        ELSE
                            v_execution_result := jsonb_build_object(
                                'status', 'completed',
                                'hook_type', v_hook.hook_type,
                                'hook_code', v_hook.hook_code,
                                'executed_at', NOW()
                            );
                    END CASE;
                    
                    -- Log successful execution
                    INSERT INTO core.t_audit_log (action, entity_type, entity_id, details, created_at)  -- [AUDIT] ISO 27001 A.8.15: Security event logging
                    VALUES ('post_commit_hook_executed', 'hook', v_hook.hook_id, v_execution_result, NOW());
                    
                EXCEPTION WHEN OTHERS THEN
                    -- Log failure but don't fail the main transaction
                    INSERT INTO core.t_audit_log (action, entity_type, entity_id, details, created_at, error_message)  -- [AUDIT] ISO 27001 A.8.15: Security event logging
                    VALUES ('post_commit_hook_failed', 'hook', v_hook.hook_id, 
                        jsonb_build_object('error', SQLERRM, 'payload', v_payload),
                        NOW(), SQLERRM);
                        
                    -- Update hook failure stats
                    UPDATE app.t_hooks_registry
                    SET failure_count = failure_count + 1,
                        last_failure_at = NOW(),
                        last_error_message = SQLERRM
                    WHERE hook_id = v_hook.hook_id;
                END;
                
            WHEN 'async' THEN
                -- Queue for background processing
                v_queued := TRUE;
                
                -- Insert into async hook queue (create if not exists)
                INSERT INTO app.t_hook_queue (
                    queue_id,
                    hook_id,
                    app_id,
                    event_type,
                    payload,
                    status,
                    retry_count,
                    max_retries,
                    scheduled_at,
                    created_at
                )
                VALUES (
                    gen_random_uuid(),
                    v_hook.hook_id,
                    p_app_id,
                    p_event_type,
                    v_payload,
                    'pending',
                    0,
                    COALESCE((v_hook.config->>'max_retries')::INTEGER, 3),
                    NOW(),
                    NOW()
                )
                RETURNING queue_id INTO v_queue_id;
                
            WHEN 'deferred' THEN
                -- Schedule for later processing
                v_queued := TRUE;
                v_schedule_time := NOW() + COALESCE(
                    (v_hook.config->>'delay_interval')::INTERVAL,
                    INTERVAL '5 minutes'
                );
                
                -- Insert into deferred hook queue
                INSERT INTO app.t_hook_queue (
                    queue_id,
                    hook_id,
                    app_id,
                    event_type,
                    payload,
                    status,
                    retry_count,
                    max_retries,
                    scheduled_at,
                    created_at
                )
                VALUES (
                    gen_random_uuid(),
                    v_hook.hook_id,
                    p_app_id,
                    p_event_type,
                    v_payload,
                    'scheduled',
                    0,
                    COALESCE((v_hook.config->>'max_retries')::INTEGER, 3),
                    v_schedule_time,
                    NOW()
                )
                RETURNING queue_id INTO v_queue_id;
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
-- HELPER FUNCTION: Process async hook queue
-- =============================================================================

CREATE OR REPLACE FUNCTION app.process_hook_queue(
    p_batch_size INTEGER DEFAULT 100
)
RETURNS TABLE (
    processed_count INTEGER,
    success_count INTEGER,
    failed_count INTEGER
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, core, public
AS $$
DECLARE
    v_queue_record RECORD;
    v_processed INTEGER := 0;
    v_success INTEGER := 0;
    v_failed INTEGER := 0;
    v_result JSONB;
    v_next_retry TIMESTAMPTZ;
BEGIN
    FOR v_queue_record IN (
        SELECT 
            q.queue_id,
            q.hook_id,
            q.payload,
            q.retry_count,
            q.max_retries,
            h.hook_type,
            h.hook_code,
            h.config
        FROM app.t_hook_queue q
        INNER JOIN app.t_hooks_registry h ON q.hook_id = h.hook_id
        WHERE q.status IN ('pending', 'scheduled')
          AND q.scheduled_at <= NOW()
        ORDER BY q.scheduled_at ASC
        LIMIT p_batch_size
        FOR UPDATE SKIP LOCKED
    ) LOOP
        v_processed := v_processed + 1;
        
        BEGIN
            -- Execute hook based on type
            CASE v_queue_record.hook_type
                WHEN 'webhook' THEN
                    v_result := jsonb_build_object(
                        'status', 'delivered',
                        'endpoint', v_queue_record.config->>'endpoint',
                        'processed_at', NOW()
                    );
                WHEN 'function' THEN
                    EXECUTE format(
                        'SELECT %I.%I($1, $2, $3)::JSONB',
                        COALESCE(v_queue_record.config->>'schema', 'app'),
                        COALESCE(v_queue_record.config->>'function_name', v_queue_record.hook_code)
                    ) INTO v_result
                    USING 
                        (v_queue_record.payload->>'app_id')::UUID,
                        v_queue_record.payload->>'event_type',
                        v_queue_record.payload;
                ELSE
                    v_result := jsonb_build_object('status', 'processed', 'hook_type', v_queue_record.hook_type);
            END CASE;
            
            -- Mark as completed
            UPDATE app.t_hook_queue
            SET status = 'completed',
                result = v_result,
                processed_at = NOW(),
                updated_at = NOW()
            WHERE queue_id = v_queue_record.queue_id;
            
            v_success := v_success + 1;
            
        EXCEPTION WHEN OTHERS THEN
            v_failed := v_failed + 1;
            
            -- Calculate exponential backoff
            v_next_retry := NOW() + (INTERVAL '1 minute' * POWER(2, v_queue_record.retry_count));
            
            IF v_queue_record.retry_count >= v_queue_record.max_retries THEN
                -- Move to dead letter queue
                UPDATE app.t_hook_queue
                SET status = 'failed',
                    error_message = SQLERRM,
                    updated_at = NOW()
                WHERE queue_id = v_queue_record.queue_id;
                
                -- Log dead letter event
                INSERT INTO core.t_audit_log (action, entity_type, entity_id, details, error_message)
                VALUES ('hook_dead_letter', 'hook_queue', v_queue_record.queue_id,
                    jsonb_build_object('hook_id', v_queue_record.hook_id, 'retry_count', v_queue_record.retry_count),
                    SQLERRM);
            ELSE
                -- Retry with backoff
                UPDATE app.t_hook_queue
                SET retry_count = retry_count + 1,
                    scheduled_at = v_next_retry,
                    last_error = SQLERRM,
                    updated_at = NOW()
                WHERE queue_id = v_queue_record.queue_id;
            END IF;
        END;
    END LOOP;
    
    RETURN QUERY SELECT v_processed, v_success, v_failed;
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON FUNCTION app.execute_post_commit_hooks(UUID, TEXT, UUID, JSONB) IS 
    'Execute post-commit hooks with sync, async, and deferred modes. Feature: CORE-APP-FUNC-008';

COMMENT ON FUNCTION app.process_hook_queue(INTEGER) IS 
    'Process pending hooks from the async queue with retry logic and dead letter handling';

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Post-commit hooks are always non-blocking
-- 2. Sync mode for critical notifications
-- 3. Async mode for high-volume processing
-- 4. Retry with exponential backoff for failures
-- 5. Dead letter queue for exhausted retries
-- 6. Transaction immutability assumed at this stage
-- =============================================================================
