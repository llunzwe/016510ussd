-- ============================================================================
-- Audit Trail Triggers
-- ============================================================================

-- Trigger: Prevent audit trail modification
CREATE OR REPLACE FUNCTION core.prevent_audit_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
BEGIN
    RAISE EXCEPTION 'Audit trail records are immutable';
END;
$$;

CREATE TRIGGER trg_audit_trail_immutable
    BEFORE UPDATE ON core.audit_trail
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_audit_modification();

CREATE TRIGGER trg_audit_trail_no_delete
    BEFORE DELETE ON core.audit_trail
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_audit_modification();

-- Trigger: Calculate audit record hash
CREATE OR REPLACE FUNCTION core.calculate_audit_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
DECLARE
    v_prev_hash VARCHAR(64);
BEGIN
    -- Get previous audit record hash
    SELECT record_hash INTO v_prev_hash
    FROM core.audit_trail
    ORDER BY changed_at DESC
    LIMIT 1;

    v_prev_hash := COALESCE(v_prev_hash, '0' || repeat('0', 63));

    NEW.previous_hash := v_prev_hash;
    NEW.record_hash := encode(
        digest(
            v_prev_hash || 
            NEW.table_name || 
            NEW.record_id::text || 
            NEW.action || 
            NEW.changed_at::text,
            'sha256'
        ),
        'hex'
    );

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_audit_trail_hash
    BEFORE INSERT ON core.audit_trail
    FOR EACH ROW
    EXECUTE FUNCTION core.calculate_audit_hash();
