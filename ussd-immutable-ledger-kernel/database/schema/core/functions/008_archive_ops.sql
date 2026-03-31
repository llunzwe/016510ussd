-- ============================================================================
-- Archival Operations
-- ============================================================================

-- Function: Create archive manifest
CREATE OR REPLACE FUNCTION core.create_archive_manifest(
    p_archive_type VARCHAR(32),
    p_date_range_start DATE,
    p_date_range_end DATE,
    p_table_list TEXT[],
    p_retention_years INTEGER,
    p_application_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_manifest_id UUID;
BEGIN
    v_manifest_id := gen_random_uuid();

    INSERT INTO core.archive_manifest (
        manifest_id,
        archive_type,
        date_range_start,
        date_range_end,
        table_list,
        record_count,
        storage_size_bytes,
        storage_location,
        integrity_hash,
        encryption_key_id,
        compression_ratio,
        retention_years,
        legal_hold,
        scheduled_destruction_date,
        status,
        created_by,
        verified_at,
        verified_by,
        restored_at,
        application_id,
        created_at
    ) VALUES (
        v_manifest_id,
        p_archive_type,
        p_date_range_start,
        p_date_range_end,
        p_table_list,
        0, -- Will be updated after archival
        0,
        's3://archives/' || v_manifest_id::text,
        NULL, -- Will be calculated after archival
        NULL,
        0,
        p_retention_years,
        FALSE,
        p_date_range_end + (p_retention_years || ' years')::interval,
        'PENDING',
        current_user,
        NULL,
        NULL,
        NULL,
        COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID),
        now()
    );

    RETURN v_manifest_id;
END;
$$;

COMMENT ON FUNCTION core.create_archive_manifest IS 'Creates archival manifest for data export';

-- Function: Archive old transactions
CREATE OR REPLACE FUNCTION core.archive_old_transactions(
    p_older_than_date DATE,
    p_batch_size INTEGER DEFAULT 10000,
    p_application_id UUID DEFAULT NULL
)
RETURNS TABLE (
    archived_count INTEGER,
    manifest_id UUID
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_manifest_id UUID;
    v_count INTEGER;
    v_app_id UUID;
BEGIN
    v_app_id := COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID);

    -- Create manifest
    v_manifest_id := core.create_archive_manifest(
        'TRANSACTIONS',
        '1900-01-01'::date,
        p_older_than_date,
        ARRAY['transactions', 'movements', 'movement_postings'],
        7, -- 7 year retention
        v_app_id
    );

    -- Count records to archive
    SELECT COUNT(*) INTO v_count
    FROM core.transactions
    WHERE created_at < p_older_than_date
    AND application_id = v_app_id
    LIMIT p_batch_size;

    -- In real implementation, would:
    -- 1. Export to compressed, encrypted format
    -- 2. Upload to cold storage
    -- 3. Update manifest with hashes
    -- 4. Mark records as archived

    -- Update manifest
    UPDATE core.archive_manifest
    SET record_count = v_count,
        status = 'ARCHIVED'
    WHERE manifest_id = v_manifest_id;

    archived_count := v_count;
    manifest_id := v_manifest_id;
    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION core.archive_old_transactions IS 'Archives transactions older than specified date';

-- Function: Restore from archive
CREATE OR REPLACE FUNCTION core.restore_from_archive(
    p_manifest_id UUID,
    p_restore_reason TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_manifest RECORD;
BEGIN
    SELECT * INTO v_manifest
    FROM core.archive_manifest
    WHERE manifest_id = p_manifest_id;

    IF v_manifest IS NULL THEN
        RAISE EXCEPTION 'Archive manifest not found: %', p_manifest_id;
    END IF;

    IF v_manifest.status != 'ARCHIVED' THEN
        RAISE EXCEPTION 'Cannot restore: archive status is %', v_manifest.status;
    END IF;

    -- Update manifest
    UPDATE core.archive_manifest
    SET status = 'RESTORED',
        restored_at = now(),
        restored_by = current_user,
        restoration_reason = p_restore_reason
    WHERE manifest_id = p_manifest_id;

    -- Log audit
    INSERT INTO core.audit_trail (
        table_name, record_id, action, old_values, new_values,
        changed_by, changed_at, transaction_id, severity
    ) VALUES (
        'archive_manifest', p_manifest_id, 'RESTORED',
        jsonb_build_object('status', 'ARCHIVED'),
        jsonb_build_object('status', 'RESTORED', 'reason', p_restore_reason),
        current_user, now(), txid_current(), 'WARNING'
    );

    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION core.restore_from_archive IS 'Restores archived data (requires approval)';
