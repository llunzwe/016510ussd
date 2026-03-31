-- ============================================================================
-- Reconciliation Job
-- ============================================================================

-- Function: Run daily reconciliation
CREATE OR REPLACE FUNCTION core.run_daily_reconciliation()
RETURNS TABLE (
    runs_started INTEGER,
    items_processed INTEGER,
    discrepancies_found INTEGER
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_runs INTEGER := 0;
    v_items INTEGER := 0;
    v_discrepancies INTEGER := 0;
    v_app RECORD;
    v_run_id UUID;
BEGIN
    FOR v_app IN
        SELECT application_id FROM app.application_registry
        WHERE status = 'ACTIVE'
    LOOP
        -- Start reconciliation
        v_run_id := core.start_reconciliation(
            'DAILY_BALANCE',
            'INTERNAL',
            (SELECT fiscal_period_id FROM core.fiscal_periods 
             WHERE is_current = TRUE AND application_id = v_app.application_id
             LIMIT 1),
            v_app.application_id
        );

        v_runs := v_runs + 1;

        -- Process accounts
        -- (Simplified - would process actual external data)
        v_items := v_items + 1;
    END LOOP;

    runs_started := v_runs;
    items_processed := v_items;
    discrepancies_found := v_discrepancies;
    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION core.run_daily_reconciliation IS 'Runs daily reconciliation for all applications';
