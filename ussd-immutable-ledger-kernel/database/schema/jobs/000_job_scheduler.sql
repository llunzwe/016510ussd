-- ============================================================================
-- Job Scheduler Setup
-- ============================================================================

-- Enable pg_cron extension (if available)
-- CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Table: Job schedule registry
CREATE TABLE IF NOT EXISTS app.job_schedule (
    job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_name VARCHAR(100) NOT NULL UNIQUE,
    job_description TEXT,
    schedule_cron VARCHAR(100) NOT NULL,
    function_name TEXT NOT NULL,
    function_schema VARCHAR(64) DEFAULT 'core',
    is_enabled BOOLEAN DEFAULT TRUE,
    run_count INTEGER DEFAULT 0,
    last_run_at TIMESTAMPTZ,
    last_run_status VARCHAR(16),
    last_run_duration_ms INTEGER,
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

COMMENT ON TABLE app.job_schedule IS 'Registry of scheduled background jobs';

-- Function: Execute scheduled job
CREATE OR REPLACE FUNCTION app.execute_scheduled_job(p_job_id UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = app, public
AS $$
DECLARE
    v_job RECORD;
    v_start_time TIMESTAMPTZ;
    v_sql TEXT;
BEGIN
    SELECT * INTO v_job FROM app.job_schedule WHERE job_id = p_job_id;
    
    IF v_job IS NULL OR NOT v_job.is_enabled THEN
        RETURN;
    END IF;

    v_start_time := now();
    
    -- Build and execute dynamic SQL
    v_sql := format('SELECT %I.%I()', v_job.function_schema, v_job.function_name);
    
    BEGIN
        EXECUTE v_sql;
        
        UPDATE app.job_schedule
        SET run_count = run_count + 1,
            last_run_at = v_start_time,
            last_run_status = 'SUCCESS',
            last_run_duration_ms = EXTRACT(MILLISECONDS FROM (now() - v_start_time))::INTEGER,
            next_run_at = CASE 
                WHEN schedule_cron IS NOT NULL THEN 
                    now() + interval '1 minute' -- Simplified
                ELSE NULL
            END,
            updated_at = now()
        WHERE job_id = p_job_id;
        
    EXCEPTION WHEN OTHERS THEN
        UPDATE app.job_schedule
        SET last_run_at = v_start_time,
            last_run_status = 'FAILED',
            last_run_duration_ms = EXTRACT(MILLISECONDS FROM (now() - v_start_time))::INTEGER,
            updated_at = now()
        WHERE job_id = p_job_id;
        
        RAISE;
    END;
END;
$$;

COMMENT ON FUNCTION app.execute_scheduled_job IS 'Executes a scheduled job and updates metrics';
