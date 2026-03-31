-- ============================================================================
-- Period-End Close Procedure
-- ============================================================================

CREATE OR REPLACE PROCEDURE core.period_end_close(
    p_fiscal_period_id UUID,
    p_application_id UUID DEFAULT NULL
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_closed_count INTEGER;
    v_app_id UUID;
BEGIN
    v_app_id := COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID);
    
    -- Close balances
    v_closed_count := core.close_fiscal_period(p_fiscal_period_id, v_app_id);
    RAISE NOTICE 'Closed balances for % accounts', v_closed_count;
    
    -- Mark period as closed
    UPDATE app.fiscal_periods
    SET is_closed = TRUE,
        closed_at = now(),
        closed_by = current_user
    WHERE fiscal_period_id = p_fiscal_period_id;
    
    -- Create next period
    INSERT INTO app.fiscal_periods (
        fiscal_period_id,
        application_id,
        period_name,
        period_start,
        period_end,
        is_current,
        is_closed,
        created_at
    )
    SELECT 
        gen_random_uuid(),
        application_id,
        'Next Period', -- Calculate actual name
        period_end + interval '1 day',
        period_end + interval '1 month',
        TRUE,
        FALSE,
        now()
    FROM app.fiscal_periods
    WHERE fiscal_period_id = p_fiscal_period_id;
    
    RAISE NOTICE 'Period-end close completed for %', p_fiscal_period_id;
END;
$$;

COMMENT ON PROCEDURE core.period_end_close IS 'Executes period-end closing process';
