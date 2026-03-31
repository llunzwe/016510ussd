-- ============================================================================
-- Saga Pattern Operations for Distributed Transactions
-- ============================================================================

-- Function: Start new saga
CREATE OR REPLACE FUNCTION core.start_saga(
    p_saga_type VARCHAR(32),
    p_payload JSONB,
    p_timeout_at TIMESTAMPTZ DEFAULT NULL,
    p_application_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_saga_id UUID;
BEGIN
    v_saga_id := gen_random_uuid();

    INSERT INTO core.transaction_sagas (
        saga_id,
        saga_type,
        status,
        payload,
        timeout_at,
        current_step,
        application_id,
        created_at,
        created_by
    ) VALUES (
        v_saga_id,
        p_saga_type,
        'PENDING',
        p_payload,
        COALESCE(p_timeout_at, now() + interval '5 minutes'),
        0,
        COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID),
        now(),
        current_user
    );

    RETURN v_saga_id;
END;
$$;

COMMENT ON FUNCTION core.start_saga IS 'Starts a new saga for distributed transaction';

-- Function: Add saga step
CREATE OR REPLACE FUNCTION core.add_saga_step(
    p_saga_id UUID,
    p_step_name VARCHAR(100),
    p_operation_type VARCHAR(32),
    p_payload JSONB,
    p_compensation_payload JSONB DEFAULT NULL,
    p_dependencies INTEGER[] DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_operation_id UUID;
    v_step_number INTEGER;
BEGIN
    -- Get next step number
    SELECT COALESCE(MAX(step_number), 0) + 1 INTO v_step_number
    FROM core.transaction_operations
    WHERE saga_id = p_saga_id;

    v_operation_id := gen_random_uuid();

    INSERT INTO core.transaction_operations (
        operation_id,
        saga_id,
        step_number,
        step_name,
        operation_type,
        status,
        payload,
        compensation_payload,
        dependencies,
        created_at
    ) VALUES (
        v_operation_id,
        p_saga_id,
        v_step_number,
        p_step_name,
        p_operation_type,
        'PENDING',
        p_payload,
        p_compensation_payload,
        p_dependencies,
        now()
    );

    RETURN v_operation_id;
END;
$$;

COMMENT ON FUNCTION core.add_saga_step IS 'Adds a step to an existing saga';

-- Function: Execute saga step
CREATE OR REPLACE FUNCTION core.execute_saga_step(
    p_operation_id UUID,
    p_result_status VARCHAR(16),
    p_result_payload JSONB DEFAULT NULL,
    p_error_message TEXT DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_saga_id UUID;
    v_step_number INTEGER;
BEGIN
    -- Update operation
    UPDATE core.transaction_operations
    SET status = p_result_status,
        result_payload = p_result_payload,
        error_message = p_error_message,
        executed_at = now()
    WHERE operation_id = p_operation_id
    RETURNING saga_id, step_number INTO v_saga_id, v_step_number;

    IF v_saga_id IS NULL THEN
        RAISE EXCEPTION 'Operation not found: %', p_operation_id;
    END IF;

    -- Update saga progress
    IF p_result_status = 'COMPLETED' THEN
        UPDATE core.transaction_sagas
        SET current_step = v_step_number,
            status = CASE 
                WHEN NOT EXISTS (
                    SELECT 1 FROM core.transaction_operations
                    WHERE saga_id = v_saga_id
                    AND status != 'COMPLETED'
                ) THEN 'COMPLETED'
                ELSE 'RUNNING'
            END,
            completed_at = CASE 
                WHEN NOT EXISTS (
                    SELECT 1 FROM core.transaction_operations
                    WHERE saga_id = v_saga_id
                    AND status != 'COMPLETED'
                ) THEN now()
                ELSE NULL
            END
        WHERE saga_id = v_saga_id;
    ELSIF p_result_status IN ('FAILED', 'TIMEOUT') THEN
        -- Trigger compensation
        PERFORM core.compensate_saga(v_saga_id);
    END IF;

    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION core.execute_saga_step IS 'Records step execution result and triggers compensation if needed';

-- Function: Compensate failed saga
CREATE OR REPLACE FUNCTION core.compensate_saga(
    p_saga_id UUID
)
RETURNS TABLE (
    operation_id UUID,
    step_name VARCHAR(100),
    compensation_status VARCHAR(16)
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_operation RECORD;
BEGIN
    -- Mark saga as compensating
    UPDATE core.transaction_sagas
    SET status = 'COMPENSATING'
    WHERE saga_id = p_saga_id;

    -- Return compensation operations in reverse order
    FOR v_operation IN
        SELECT * FROM core.transaction_operations
        WHERE saga_id = p_saga_id
        AND status = 'COMPLETED'
        ORDER BY step_number DESC
    LOOP
        operation_id := v_operation.operation_id;
        step_name := v_operation.step_name;
        
        -- Execute compensation logic here
        -- This would typically call external services or internal functions
        compensation_status := 'COMPLETED';
        
        UPDATE core.transaction_operations
        SET compensation_executed_at = now()
        WHERE operation_id = v_operation.operation_id;
        
        RETURN NEXT;
    END LOOP;

    -- Mark saga as compensated
    UPDATE core.transaction_sagas
    SET status = 'COMPENSATED',
        completed_at = now()
    WHERE saga_id = p_saga_id;
END;
$$;

COMMENT ON FUNCTION core.compensate_saga IS 'Executes compensation for failed saga';
