-- ============================================================================
-- Transaction and Movement Triggers
-- ============================================================================

-- Trigger: Prevent transaction deletion
CREATE OR REPLACE FUNCTION core.prevent_transaction_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
BEGIN
    RAISE EXCEPTION 'Transactions are immutable and cannot be deleted';
END;
$$;

CREATE TRIGGER trg_transactions_no_delete
    BEFORE DELETE ON core.transactions
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_transaction_delete();

-- Trigger: Prevent transaction modification
CREATE OR REPLACE FUNCTION core.prevent_transaction_update()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
BEGIN
    RAISE EXCEPTION 'Transactions are immutable and cannot be modified';
END;
$$;

CREATE TRIGGER trg_transactions_immutable
    BEFORE UPDATE ON core.transactions
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_transaction_update();

-- Trigger: Prevent movement modification
CREATE OR REPLACE FUNCTION core.prevent_movement_update()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
BEGIN
    -- Only allow is_reversed to be updated
    IF OLD.is_reversed != NEW.is_reversed OR
       OLD.reversed_at IS DISTINCT FROM NEW.reversed_at OR
       OLD.reversal_reason IS DISTINCT FROM NEW.reversal_reason THEN
        RETURN NEW;
    END IF;
    
    RAISE EXCEPTION 'Movements are immutable except for reversal status';
END;
$$;

CREATE TRIGGER trg_movements_immutable
    BEFORE UPDATE ON core.movements
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_movement_update();

-- Trigger: Audit transaction creation
CREATE OR REPLACE FUNCTION core.audit_transaction_create()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
BEGIN
    INSERT INTO core.audit_trail (
        table_name, record_id, action, old_values, new_values,
        changed_by, changed_at, transaction_id, severity
    ) VALUES (
        'transactions', NEW.transaction_id, 'CREATE', '{}',
        jsonb_build_object(
            'transaction_type', NEW.transaction_type,
            'hash', NEW.current_hash
        ),
        current_user, now(), txid_current(), 'INFO'
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_transactions_audit
    AFTER INSERT ON core.transactions
    FOR EACH ROW
    EXECUTE FUNCTION core.audit_transaction_create();
