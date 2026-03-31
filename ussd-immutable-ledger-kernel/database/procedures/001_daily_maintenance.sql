-- ============================================================================
-- Daily Maintenance Procedure
-- ============================================================================

CREATE OR REPLACE PROCEDURE core.daily_maintenance()
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_result RECORD;
BEGIN
    -- Clean up expired sessions
    PERFORM ussd.cleanup_expired_sessions();
    
    -- Archive old audit records
    SELECT * INTO v_result FROM core.run_archival_process();
    RAISE NOTICE 'Archival: % manifests, % records', v_result.manifests_created, v_result.records_archived;
    
    -- Update statistics
    ANALYZE core.transactions;
    ANALYZE core.movements;
    ANALYZE core.movement_postings;
    
    -- Log completion
    RAISE NOTICE 'Daily maintenance completed at %', now();
END;
$$;

COMMENT ON PROCEDURE core.daily_maintenance IS 'Runs all daily maintenance tasks';
