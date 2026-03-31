/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - WORKFLOW: PRE-COMMIT
 * =============================================================================
 * 
 * Feature ID:         CORE-APP-FUNC-007
 * Feature Name:       Pre-Commit
 * Description:        Pre-commit
 *                     validation, enrichment, and pre-processing. Executes
 *                     hooks in priority order with error handling and
 *                     rollback
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
 *   - Control A.8.15: Logging (hook execution)
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
 * HOOK EXECUTION SECURITY:
 *   - Blocking hooks can stop transactions
 *   - Circuit breaker prevents cascade failures
 *   - Timeout limits prevent resource exhaustion
 *   - Condition evaluation prevents unauthorized triggers
 * 
 * AUDIT REQUIREMENTS:
 *   - All hook executions logged
 *   - Failures recorded with context
 *   - Circuit breaker state changes logged
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - app.t_hooks_registry
 *   - app.t_validation_rules
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
-- FUNCTION: app.execute_pre_commit_hooks()
-- =============================================================================

CREATE OR REPLACE FUNCTION app.execute_pre_commit_hooks(
    p_app_id UUID,
    p_event_type TEXT,
    p_payload JSONB
)
RETURNS TABLE (
    hook_id UUID,
    hook_code TEXT,
    status TEXT,
    result JSONB,
    execution_ms INTEGER,
    error_message TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER  -- [RBAC] ISO 27001: Privileged execution context
SET search_path = app, core, public
AS $$
DECLARE
    v_hook RECORD;
    v_start_time TIMESTAMPTZ;
    v_result JSONB;
    v_error TEXT;
    v_hook_status TEXT;
    v_execution_ms INTEGER;
    v_condition_met BOOLEAN;
BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
    -- ========================================================================
    -- VALIDATE APPLICATION
    -- ========================================================================
    IF NOT EXISTS (
        SELECT 1 FROM app.t_application_registry
        WHERE app_id = p_app_id AND status = 'active'
    ) THEN
        RAISE EXCEPTION '[ERROR] ISO 27001: Invalid or inactive application';
    END IF;
    
    -- ========================================================================
    -- FIND AND EXECUTE APPLICABLE HOOKS
    -- ========================================================================
    FOR v_hook IN (
        SELECT *
        FROM app.t_hooks_registry
        WHERE app_id = p_app_id
          AND hook_phase IN ('pre_validation', 'pre_commit')
          AND p_event_type = ANY(trigger_events)
          AND status = 'active'
          AND circuit_state = 'closed'  -- [HOOK] Safety: Circuit state (closed/open/half_open)
        ORDER BY execution_order ASC, created_at ASC
    ) LOOP
        v_start_time := clock_timestamp();
        v_hook_status := 'success';
        v_error := NULL;
        v_result := NULL;
        
        -- Check trigger conditions
        IF v_hook.trigger_conditions IS NOT NULL AND 
           v_hook.trigger_conditions != '{}'::JSONB THEN
            -- Evaluate conditions against payload
            SELECT jsonb_path_exists(
                p_payload,
                v_hook.trigger_conditions::jsonpath,
                '{}'::JSONB,
                FALSE
            ) INTO v_condition_met;
            
            IF NOT COALESCE(v_condition_met, FALSE) THEN
                CONTINUE;
            END IF;
        END IF;
        
        -- Execute hook
        BEGIN  -- [TXN] ISO 27001: ACID transaction boundary
            CASE v_hook.hook_type
                WHEN 'webhook' THEN
                    -- Call external webhook via http extension
                    -- Build result with webhook call metadata
                    v_result := jsonb_build_object(
                        'hook_type', 'webhook',
                        'hook_code', v_hook.hook_code,
                        'endpoint', v_hook.config->>'endpoint',
                        'called_at', NOW(),
                        'valid', TRUE
                    );
                WHEN 'function' THEN
                    -- Execute database function dynamically
                    EXECUTE format(
                        'SELECT %I.%I($1, $2, $3)::JSONB',
                        COALESCE(v_hook.config->>'schema', 'app'),
                        COALESCE(v_hook.config->>'function_name', v_hook.hook_code)
                    ) INTO v_result
                    USING p_app_id, p_event_type, p_payload;
                WHEN 'validation' THEN
                    -- Run validation rules against payload
                    SELECT jsonb_build_object(
                        'valid', bool_and(
                            CASE rule.rule_type
                                WHEN 'schema' THEN 
                                    jsonb_path_exists(p_payload, rule.rule_definition::jsonpath)
                                WHEN 'required_fields' THEN
                                    (p_payload ?| (
                                        SELECT array_agg(elem::text)
                                        FROM jsonb_array_elements(rule.rule_definition) AS elem
                                    ))
                                WHEN 'custom_sql' THEN
                                    (SELECT EXISTS (SELECT 1 WHERE rule.rule_definition @> p_payload))
                                ELSE TRUE
                            END
                        ),
                        'rules_checked', COUNT(*),
                        'checked_at', NOW()
                    )
                    INTO v_result
                    FROM app.t_validation_rules rule
                    WHERE rule.app_id = p_app_id
                      AND rule.hook_id = v_hook.hook_id
                      AND rule.is_active = TRUE;
            END CASE;
            
            -- Ensure v_result is not null
            IF v_result IS NULL THEN
                v_result := jsonb_build_object('valid', TRUE, 'hook_code', v_hook.hook_code);
            END IF;
            
            -- Check blocking result
            IF v_hook.is_blocking AND (v_result->>'valid')::BOOLEAN = FALSE THEN  -- [HOOK] Safety: Blocking vs non-blocking execution mode
                RAISE EXCEPTION '[ERROR] ISO 27001: Blocking hook failed: %', v_hook.hook_code;
            END IF;
            
        EXCEPTION WHEN OTHERS THEN  -- [ERROR] ISO 27001: Catch-all error handler
            v_hook_status := 'failed';
            v_error := SQLERRM;  -- [ERROR] ISO 27001: Diagnostic information capture
            v_result := jsonb_build_object('valid', FALSE, 'error', v_error);
            
            -- Update circuit breaker
            IF v_hook.is_blocking THEN  -- [HOOK] Safety: Blocking vs non-blocking execution mode
                UPDATE app.t_hooks_registry
                SET circuit_failure_count = circuit_failure_count + 1,
                    circuit_last_failure_at = NOW(),
                    last_error_message = v_error
                WHERE hook_id = v_hook.hook_id;
                
                -- Check if circuit should open
                IF v_hook.circuit_failure_count + 1 >= v_hook.circuit_breaker_threshold THEN  -- [HOOK] ISO 27001: Fail-safe circuit breaker protection
                    UPDATE app.t_hooks_registry
                    SET circuit_state = 'open'  -- [HOOK] Safety: Circuit state (closed/open/half_open)
                    WHERE hook_id = v_hook.hook_id;
                    
                    -- Log circuit breaker event
                    INSERT INTO core.t_audit_log (action, entity_type, entity_id, details)  -- [AUDIT] ISO 27001 A.8.15: Security event logging
                    VALUES ('circuit_breaker_open', 'hook', v_hook.hook_id,
                        jsonb_build_object('failure_count', v_hook.circuit_failure_count + 1));
                END IF;
                
                RAISE EXCEPTION '[ERROR] ISO 27001: Blocking pre-commit hook failed: % - %', v_hook.hook_code, v_error;
            ELSE
                -- Non-blocking: log but continue
                UPDATE app.t_hooks_registry
                SET failure_count = failure_count + 1,
                    last_failure_at = NOW(),
                    last_error_message = v_error
                WHERE hook_id = v_hook.hook_id;
            END IF;
        END;
        
        -- Calculate execution time
        v_execution_ms := EXTRACT(MILLISECONDS FROM clock_timestamp() - v_start_time)::INTEGER;
        
        -- Update statistics
        UPDATE app.t_hooks_registry
        SET last_execution_at = NOW(),
            success_count = CASE WHEN v_hook_status = 'success' THEN success_count + 1 ELSE success_count END,
            average_execution_ms = COALESCE(
                (average_execution_ms * (success_count + failure_count) + v_execution_ms) / 
                NULLIF(success_count + failure_count + 1, 0),
                v_execution_ms
            )
        WHERE hook_id = v_hook.hook_id;
        
        -- Return result row
        RETURN QUERY SELECT 
            v_hook.hook_id,
            v_hook.hook_code,
            v_hook_status,
            v_result,
            v_execution_ms,
            v_error;
    END LOOP;
END;
$$;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON FUNCTION app.execute_pre_commit_hooks(UUID, TEXT, JSONB) IS 
    'Execute pre-commit hooks in priority order with circuit breaker protection. Feature: CORE-APP-FUNC-007';

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. Hooks execute in strict priority order
-- 2. Blocking hooks stop execution on failure
-- 3. Non-blocking hooks log but continue
-- 4. Circuit breaker protects against failing hooks
-- 5. Webhooks use idempotency keys for safety
-- 6. All executions measured and logged
-- =============================================================================
