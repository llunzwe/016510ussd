-- ============================================================================
-- Block Triggers
-- ============================================================================

-- Trigger: Calculate block hash
CREATE OR REPLACE FUNCTION core.calculate_block_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
BEGIN
    NEW.current_hash := encode(
        digest(
            NEW.previous_hash || 
            NEW.block_number::text || 
            NEW.merkle_root || 
            NEW.created_at::text,
            'sha256'
        ),
        'hex'
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_blocks_calculate_hash
    BEFORE INSERT ON core.blocks
    FOR EACH ROW
    EXECUTE FUNCTION core.calculate_block_hash();

-- Trigger: Prevent block modification
CREATE OR REPLACE FUNCTION core.prevent_block_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
BEGIN
    RAISE EXCEPTION 'Blocks are immutable once created';
END;
$$;

CREATE TRIGGER trg_blocks_immutable
    BEFORE UPDATE ON core.blocks
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_block_modification();

CREATE TRIGGER trg_blocks_no_delete
    BEFORE DELETE ON core.blocks
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_block_modification();

-- Trigger: Audit block creation
CREATE OR REPLACE FUNCTION core.audit_block_create()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
BEGIN
    INSERT INTO core.audit_trail (
        table_name, record_id, action, old_values, new_values,
        changed_by, changed_at, transaction_id, severity
    ) VALUES (
        'blocks', NEW.block_id, 'CREATE', '{}',
        jsonb_build_object(
            'block_number', NEW.block_number,
            'transaction_count', NEW.transaction_count,
            'hash', NEW.current_hash
        ),
        current_user, now(), txid_current(), 'INFO'
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_blocks_audit
    AFTER INSERT ON core.blocks
    FOR EACH ROW
    EXECUTE FUNCTION core.audit_block_create();
