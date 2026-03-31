-- ============================================================================
-- Archival Job
-- ============================================================================

-- Function: Run archival process
CREATE OR REPLACE FUNCTION core.run_archival_process()
RETURNS TABLE (
    manifests_created INTEGER,
    records_archived INTEGER,
    errors TEXT[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_manifests INTEGER := 0;
    v_records INTEGER := 0;
    v_errors TEXT[] := ARRAY[]::TEXT[];
    v_result RECORD;
BEGIN
    -- Archive old transactions
    FOR v_result IN
        SELECT * FROM core.archive_old_transactions(
            CURRENT_DATE - interval '2 years',
            100000
        )
    LOOP
        v_manifests := v_manifests + 1;
        v_records := v_records + v_result.archived_count;
    END LOOP;

    -- Clean up expired idempotency keys
    DELETE FROM core.idempotency_keys
    WHERE expires_at < now();

    manifests_created := v_manifests;
    records_archived := v_records;
    errors := v_errors;
    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION core.run_archival_process IS 'Archives old records and cleans up expired data';

-- Schedule the job (if pg_cron available)
-- SELECT cron.schedule('archival-job', '0 2 * * 0', 'SELECT core.run_archival_process()');
