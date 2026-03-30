-- ============================================================================
-- USSD KERNEL APP SCHEMA - HOOKS SYSTEM
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Pluggable business logic hooks with pre/post commit execution,
--              retry policies, and dead-letter handling.
-- Immutability: Hook definitions are versioned, executions are logged
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. HOOK DEFINITIONS TABLE
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.hooks (
    hook_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Identification
    hook_name VARCHAR(100) NOT NULL,
    hook_code VARCHAR(50) NOT NULL UNIQUE,  -- Unique identifier
    
    -- Scope
    application_id UUID,  -- NULL = system-wide hook
    
    -- Hook type and timing
    hook_type ussd_app.hook_type NOT NULL,
    hook_mode ussd_app.hook_mode DEFAULT 'async',
    
    -- Execution configuration
    priority INTEGER DEFAULT 100,  -- Lower = earlier execution
    
    -- Implementation
    implementation_type VARCHAR(20) DEFAULT 'webhook' CHECK (implementation_type IN ('webhook', 'stored_procedure', 'queue', 'lambda')),
    
    -- Webhook configuration
    webhook_url TEXT,
    webhook_method VARCHAR(10) DEFAULT 'POST',
    webhook_headers JSONB DEFAULT '{}',
    webhook_timeout_ms INTEGER DEFAULT 30000,
    webhook_retry_count INTEGER DEFAULT 3,
    
    -- Stored procedure configuration
    procedure_name VARCHAR(100),
    procedure_schema VARCHAR(50) DEFAULT 'ussd_app',
    
    -- Queue configuration
    queue_name VARCHAR(100),
    queue_connection_string TEXT,  -- Encrypted
    
    -- Security
    auth_type VARCHAR(20) DEFAULT 'none' CHECK (auth_type IN ('none', 'api_key', 'oauth', 'mTLS')),
    auth_config JSONB DEFAULT '{}',  -- e.g., {"api_key_header": "X-API-Key"}
    
    -- Input/output schema
    input_schema JSONB,  -- Expected input structure
    output_schema JSONB,  -- Expected output structure
    
    -- Conditions for execution
    execution_conditions JSONB DEFAULT '{}',  -- e.g., {"transaction_types": ["TRANSFER"], "min_amount": 100}
    
    -- Error handling
    on_error_action VARCHAR(20) DEFAULT 'continue' CHECK (on_error_action IN ('continue', 'fail', 'retry', 'dead_letter')),
    error_notification_email VARCHAR(255),
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Versioning
    version INTEGER DEFAULT 1,
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    created_by UUID,
    superseded_by UUID REFERENCES ussd_app.hooks(hook_id),
    valid_from TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    valid_to TIMESTAMPTZ,
    
    record_hash VARCHAR(64) NOT NULL
);

-- ----------------------------------------------------------------------------
-- 2. HOOK EXECUTION LOG
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.hook_executions (
    execution_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    hook_id UUID NOT NULL REFERENCES ussd_app.hooks(hook_id),
    
    -- Context
    transaction_id BIGINT,
    block_id BIGINT,
    application_id UUID,
    
    -- Execution details
    triggered_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER,
    
    -- Input/output
    input_payload JSONB,
    output_payload JSONB,
    
    -- Result
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'success', 'failed', 'timeout', 'retrying')),
    http_status_code INTEGER,
    error_message TEXT,
    error_details JSONB,
    
    -- Retry tracking
    retry_count INTEGER DEFAULT 0,
    next_retry_at TIMESTAMPTZ,
    
    -- For async execution
    correlation_id UUID,  -- For tracking async responses
    
    -- Dead letter
    is_dead_letter BOOLEAN DEFAULT FALSE,
    dead_lettered_at TIMESTAMPTZ,
    dead_letter_reason TEXT
);

-- ----------------------------------------------------------------------------
-- 3. HOOK QUEUE (For retry management)
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.hook_retry_queue (
    queue_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    execution_id UUID NOT NULL REFERENCES ussd_app.hook_executions(execution_id),
    
    -- Retry configuration
    max_retries INTEGER DEFAULT 3,
    retry_count INTEGER DEFAULT 0,
    retry_delay_seconds INTEGER DEFAULT 60,
    backoff_multiplier NUMERIC DEFAULT 2.0,  -- Exponential backoff
    
    -- Scheduling
    scheduled_at TIMESTAMPTZ NOT NULL,
    processed_at TIMESTAMPTZ,
    
    -- Status
    status VARCHAR(20) DEFAULT 'scheduled' CHECK (status IN ('scheduled', 'processing', 'completed', 'failed')),
    
    -- Result
    result_message TEXT
);

-- ----------------------------------------------------------------------------
-- 4. APPLICATION HOOK ASSIGNMENTS
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.application_hook_assignments (
    assignment_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    application_id UUID NOT NULL,
    hook_id UUID NOT NULL REFERENCES ussd_app.hooks(hook_id),
    transaction_type_id UUID,  -- NULL = all types
    
    -- Override hook settings for this app
    priority_override INTEGER,
    is_enabled BOOLEAN DEFAULT TRUE,
    custom_config JSONB DEFAULT '{}',
    
    -- Execution order within app
    execution_order INTEGER DEFAULT 100,
    
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    created_by UUID
);

-- ----------------------------------------------------------------------------
-- 5. INDEXES
-- ----------------------------------------------------------------------------
CREATE INDEX idx_hooks_type ON ussd_app.hooks(hook_type);
CREATE INDEX idx_hooks_app ON ussd_app.hooks(application_id);
CREATE INDEX idx_hooks_active ON ussd_app.hooks(is_active) WHERE is_active = TRUE AND valid_to IS NULL;

CREATE INDEX idx_hook_exec_hook ON ussd_app.hook_executions(hook_id);
CREATE INDEX idx_hook_exec_tx ON ussd_app.hook_executions(transaction_id);
CREATE INDEX idx_hook_exec_status ON ussd_app.hook_executions(status);
CREATE INDEX idx_hook_exec_time ON ussd_app.hook_executions(triggered_at DESC);
CREATE INDEX idx_hook_exec_retry ON ussd_app.hook_executions(next_retry_at) 
    WHERE status = 'retrying';
CREATE INDEX idx_hook_exec_deadletter ON ussd_app.hook_executions(is_dead_letter) 
    WHERE is_dead_letter = TRUE;

CREATE INDEX idx_hook_retry_scheduled ON ussd_app.hook_retry_queue(scheduled_at) 
    WHERE status = 'scheduled';

CREATE INDEX idx_app_hooks_app ON ussd_app.application_hook_assignments(application_id);
CREATE INDEX idx_app_hooks_hook ON ussd_app.application_hook_assignments(hook_id);

-- ----------------------------------------------------------------------------
-- 6. IMMUTABILITY TRIGGERS
-- ----------------------------------------------------------------------------
CREATE TRIGGER trg_hooks_prevent_update
    BEFORE UPDATE ON ussd_app.hooks
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_update();

CREATE TRIGGER trg_hook_exec_prevent_update
    BEFORE UPDATE ON ussd_app.hook_executions
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_update();

CREATE TRIGGER trg_hook_exec_prevent_delete
    BEFORE DELETE ON ussd_app.hook_executions
    FOR EACH ROW
    EXECUTE FUNCTION ussd_core.prevent_delete();

-- ----------------------------------------------------------------------------
-- 7. HASH COMPUTATION
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd_app.compute_hook_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := ussd_core.generate_hash(
        NEW.hook_id::TEXT || NEW.hook_code || NEW.version::TEXT || NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_hooks_compute_hash
    BEFORE INSERT ON ussd_app.hooks
    FOR EACH ROW
    EXECUTE FUNCTION ussd_app.compute_hook_hash();

-- ----------------------------------------------------------------------------
-- 8. HOOK MANAGEMENT FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to register a new hook
CREATE OR REPLACE FUNCTION ussd_app.register_hook(
    p_hook_code VARCHAR,
    p_hook_name VARCHAR,
    p_hook_type ussd_app.hook_type,
    p_implementation_type VARCHAR,
    p_config JSONB,
    p_application_id UUID DEFAULT NULL,
    p_created_by UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_hook_id UUID;
BEGIN
    INSERT INTO ussd_app.hooks (
        hook_code,
        hook_name,
        hook_type,
        application_id,
        implementation_type,
        webhook_url,
        webhook_method,
        webhook_headers,
        webhook_timeout_ms,
        procedure_name,
        procedure_schema,
        queue_name,
        auth_type,
        auth_config,
        execution_conditions,
        on_error_action,
        created_by
    ) VALUES (
        p_hook_code,
        p_hook_name,
        p_hook_type,
        p_application_id,
        p_implementation_type,
        p_config->>'webhook_url',
        COALESCE(p_config->>'webhook_method', 'POST'),
        COALESCE(p_config->'webhook_headers', '{}'::JSONB),
        COALESCE((p_config->>'webhook_timeout_ms')::INTEGER, 30000),
        p_config->>'procedure_name',
        COALESCE(p_config->>'procedure_schema', 'ussd_app'),
        p_config->>'queue_name',
        COALESCE(p_config->>'auth_type', 'none'),
        COALESCE(p_config->'auth_config', '{}'::JSONB),
        COALESCE(p_config->'execution_conditions', '{}'::JSONB),
        COALESCE(p_config->>'on_error_action', 'continue'),
        p_created_by
    )
    RETURNING hook_id INTO v_hook_id;
    
    RETURN v_hook_id;
END;
$$;

-- Function to execute hooks for a transaction
CREATE OR REPLACE FUNCTION ussd_app.execute_hooks(
    p_transaction_id BIGINT,
    p_hook_type ussd_app.hook_type
)
RETURNS TABLE (
    hook_id UUID,
    execution_id UUID,
    status VARCHAR(20),
    error_message TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_transaction ussd_core.transactions%ROWTYPE;
    v_hook RECORD;
    v_execution_id UUID;
    v_result RECORD;
BEGIN
    -- Get transaction details
    SELECT * INTO v_transaction
    FROM ussd_core.transactions
    WHERE transaction_id = p_transaction_id;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction not found: %', p_transaction_id;
    END IF;
    
    -- Find applicable hooks
    FOR v_hook IN 
        SELECT 
            h.*,
            aha.priority_override,
            aha.custom_config
        FROM ussd_app.hooks h
        LEFT JOIN ussd_app.application_hook_assignments aha 
            ON h.hook_id = aha.hook_id 
            AND aha.application_id = v_transaction.application_id
        WHERE h.hook_type = p_hook_type
          AND h.is_active = TRUE
          AND h.valid_to IS NULL
          AND (h.application_id IS NULL OR h.application_id = v_transaction.application_id)
          AND (aha.is_enabled IS NULL OR aha.is_enabled = TRUE)
          AND (aha.transaction_type_id IS NULL OR aha.transaction_type_id = v_transaction.transaction_type_id)
        ORDER BY COALESCE(aha.priority_override, h.priority), h.hook_id
    LOOP
        -- Create execution record
        INSERT INTO ussd_app.hook_executions (
            hook_id,
            transaction_id,
            application_id,
            input_payload,
            status
        ) VALUES (
            v_hook.hook_id,
            p_transaction_id,
            v_transaction.application_id,
            jsonb_build_object(
                'transaction', to_jsonb(v_transaction),
                'hook_config', v_hook.custom_config
            ),
            CASE v_hook.hook_mode WHEN 'sync' THEN 'running' ELSE 'pending' END
        )
        RETURNING execution_id INTO v_execution_id;
        
        -- For webhook hooks, we would typically call an external service here
        -- For stored procedures, we can execute directly
        IF v_hook.implementation_type = 'stored_procedure' THEN
            BEGIN
                -- Execute stored procedure
                EXECUTE format('SELECT * FROM %I.%I($1)',
                    v_hook.procedure_schema, v_hook.procedure_name)
                USING to_jsonb(v_transaction);
                
                -- Update execution record
                UPDATE ussd_app.hook_executions
                SET status = 'success',
                    completed_at = ussd_core.precise_now(),
                    duration_ms = EXTRACT(EPOCH FROM (ussd_core.precise_now() - started_at)) * 1000
                WHERE execution_id = v_execution_id;
                
                hook_id := v_hook.hook_id;
                execution_id := v_execution_id;
                status := 'success'::VARCHAR;
                error_message := NULL::TEXT;
                RETURN NEXT;
                
            EXCEPTION WHEN OTHERS THEN
                -- Handle error based on configuration
                UPDATE ussd_app.hook_executions
                SET status = 'failed',
                    error_message = SQLERRM,
                    error_details = jsonb_build_object('sqlstate', SQLSTATE)
                WHERE execution_id = v_execution_id;
                
                -- Queue for retry if configured
                IF v_hook.on_error_action = 'retry' AND v_hook.webhook_retry_count > 0 THEN
                    INSERT INTO ussd_app.hook_retry_queue (
                        execution_id,
                        max_retries,
                        retry_delay_seconds,
                        scheduled_at
                    ) VALUES (
                        v_execution_id,
                        v_hook.webhook_retry_count,
                        60,
                        ussd_core.precise_now() + INTERVAL '1 minute'
                    );
                    
                    UPDATE ussd_app.hook_executions
                    SET status = 'retrying',
                        next_retry_at = ussd_core.precise_now() + INTERVAL '1 minute'
                    WHERE execution_id = v_execution_id;
                END IF;
                
                hook_id := v_hook.hook_id;
                execution_id := v_execution_id;
                status := 'failed'::VARCHAR;
                error_message := SQLERRM;
                RETURN NEXT;
                
                -- Fail fast if configured
                IF v_hook.on_error_action = 'fail' THEN
                    EXIT;
                END IF;
            END;
        ELSE
            -- For webhook/queue/lambda, mark as pending for external processing
            hook_id := v_hook.hook_id;
            execution_id := v_execution_id;
            status := 'pending'::VARCHAR;
            error_message := NULL::TEXT;
            RETURN NEXT;
        END IF;
    END LOOP;
END;
$$;

-- Function to process retry queue
CREATE OR REPLACE FUNCTION ussd_app.process_hook_retries(
    p_batch_size INTEGER DEFAULT 10
)
RETURNS TABLE (
    processed INTEGER,
    succeeded INTEGER,
    failed INTEGER
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_retry RECORD;
    v_processed INTEGER := 0;
    v_succeeded INTEGER := 0;
    v_failed INTEGER := 0;
BEGIN
    FOR v_retry IN 
        SELECT 
            qr.*,
            he.hook_id,
            h.implementation_type,
            h.procedure_schema,
            h.procedure_name
        FROM ussd_app.hook_retry_queue qr
        JOIN ussd_app.hook_executions he ON qr.execution_id = he.execution_id
        JOIN ussd_app.hooks h ON he.hook_id = h.hook_id
        WHERE qr.status = 'scheduled'
          AND qr.scheduled_at <= ussd_core.precise_now()
        LIMIT p_batch_size
    LOOP
        v_processed := v_processed + 1;
        
        UPDATE ussd_app.hook_retry_queue
        SET status = 'processing'
        WHERE queue_id = v_retry.queue_id;
        
        BEGIN
            -- Retry execution
            IF v_retry.implementation_type = 'stored_procedure' THEN
                EXECUTE format('SELECT * FROM %I.%I($1)',
                    v_retry.procedure_schema, v_retry.procedure_name)
                USING v_retry.execution_id;
            END IF;
            
            -- Mark success
            UPDATE ussd_app.hook_retry_queue
            SET status = 'completed',
                processed_at = ussd_core.precise_now(),
                result_message = 'Retry succeeded'
            WHERE queue_id = v_retry.queue_id;
            
            UPDATE ussd_app.hook_executions
            SET status = 'success',
                retry_count = retry_count + 1
            WHERE execution_id = v_retry.execution_id;
            
            v_succeeded := v_succeeded + 1;
            
        EXCEPTION WHEN OTHERS THEN
            -- Update retry count
            UPDATE ussd_app.hook_retry_queue
            SET retry_count = retry_count + 1
            WHERE queue_id = v_retry.queue_id;
            
            IF v_retry.retry_count + 1 >= v_retry.max_retries THEN
                -- Move to dead letter
                UPDATE ussd_app.hook_retry_queue
                SET status = 'failed',
                    processed_at = ussd_core.precise_now(),
                    result_message = 'Max retries exceeded: ' || SQLERRM
                WHERE queue_id = v_retry.queue_id;
                
                UPDATE ussd_app.hook_executions
                SET status = 'failed',
                    is_dead_letter = TRUE,
                    dead_lettered_at = ussd_core.precise_now(),
                    dead_letter_reason = 'Max retries exceeded',
                    retry_count = v_retry.max_retries
                WHERE execution_id = v_retry.execution_id;
                
                v_failed := v_failed + 1;
            ELSE
                -- Schedule next retry with exponential backoff
                UPDATE ussd_app.hook_retry_queue
                SET status = 'scheduled',
                    scheduled_at = ussd_core.precise_now() + 
                        (v_retry.retry_delay_seconds * power(v_retry.backoff_multiplier, v_retry.retry_count) || ' seconds')::INTERVAL
                WHERE queue_id = v_retry.queue_id;
                
                UPDATE ussd_app.hook_executions
                SET retry_count = retry_count + 1
                WHERE execution_id = v_retry.execution_id;
            END IF;
        END;
    END LOOP;
    
    RETURN QUERY SELECT v_processed, v_succeeded, v_failed;
END;
$$;

-- ----------------------------------------------------------------------------
-- 9. VIEWS
-- ----------------------------------------------------------------------------

-- Active hooks
CREATE VIEW ussd_app.active_hooks AS
SELECT *
FROM ussd_app.hooks
WHERE is_active = TRUE AND valid_to IS NULL;

-- Hook execution summary
CREATE VIEW ussd_app.hook_execution_summary AS
SELECT 
    he.hook_id,
    h.hook_name,
    h.hook_type,
    COUNT(*) as total_executions,
    COUNT(*) FILTER (WHERE he.status = 'success') as successful,
    COUNT(*) FILTER (WHERE he.status = 'failed') as failed,
    COUNT(*) FILTER (WHERE he.status = 'retrying') as retrying,
    COUNT(*) FILTER (WHERE he.is_dead_letter) as dead_letters,
    AVG(he.duration_ms) FILTER (WHERE he.duration_ms IS NOT NULL) as avg_duration_ms,
    MAX(he.triggered_at) as last_triggered
FROM ussd_app.hook_executions he
JOIN ussd_app.hooks h ON he.hook_id = h.hook_id
GROUP BY he.hook_id, h.hook_name, h.hook_type;

-- Pending retries
CREATE VIEW ussd_app.pending_hook_retries AS
SELECT 
    qr.*,
    he.hook_id,
    h.hook_name,
    he.transaction_id,
    he.error_message
FROM ussd_app.hook_retry_queue qr
JOIN ussd_app.hook_executions he ON qr.execution_id = he.execution_id
JOIN ussd_app.hooks h ON he.hook_id = h.hook_id
WHERE qr.status = 'scheduled'
ORDER BY qr.scheduled_at;

-- Dead letter queue
CREATE VIEW ussd_app.dead_letter_hooks AS
SELECT 
    he.*,
    h.hook_name,
    h.hook_type,
    h.implementation_type
FROM ussd_app.hook_executions he
JOIN ussd_app.hooks h ON he.hook_id = h.hook_id
WHERE he.is_dead_letter = TRUE
ORDER BY he.dead_lettered_at DESC;

-- ----------------------------------------------------------------------------
-- 10. INITIAL HOOKS (Kernel-Only)
-- ----------------------------------------------------------------------------
-- Note: Applications register their own business-specific hooks

INSERT INTO ussd_app.hooks (
    hook_code,
    hook_name,
    hook_type,
    implementation_type,
    procedure_name,
    on_error_action,
    description
) VALUES (
    'kernel_audit',
    'Kernel Audit Hook',
    'post_commit',
    'stored_procedure',
    'log_kernel_transaction',
    'continue',
    'Kernel-level transaction logging'
);

-- ----------------------------------------------------------------------------
-- 11. ROW LEVEL SECURITY
-- ----------------------------------------------------------------------------
ALTER TABLE ussd_app.hooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd_app.application_hook_assignments ENABLE ROW LEVEL SECURITY;

CREATE POLICY hooks_read ON ussd_app.hooks
    FOR SELECT USING (is_active = TRUE);

-- ----------------------------------------------------------------------------
-- 12. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_app.hooks IS 
    'Hook definitions for extensible business logic';
COMMENT ON TABLE ussd_app.hook_executions IS 
    'Immutable log of hook executions';
COMMENT ON TABLE ussd_app.hook_retry_queue IS 
    'Queue for failed hook retries with exponential backoff';
COMMENT ON FUNCTION ussd_app.execute_hooks IS 
    'Executes all applicable hooks for a transaction';
COMMENT ON FUNCTION ussd_app.process_hook_retries IS 
    'Processes pending hook retries with exponential backoff';
