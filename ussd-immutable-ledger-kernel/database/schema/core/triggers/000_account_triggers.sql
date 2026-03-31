-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - A.8.2 (Data Integrity), A.12.4 (Logging)
-- ISO/IEC 27040:2024 - Storage Security
-- ============================================================================

-- Trigger: Prevent account record update (immutability)
CREATE OR REPLACE FUNCTION core.prevent_account_update()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
BEGIN
    -- Allow updates only to is_current, valid_to, superseded_by (versioning)
    -- and balance fields (operational)
    IF OLD.account_number != NEW.account_number OR
       OLD.account_type != NEW.account_type OR
       OLD.currency_code != NEW.currency_code OR
       OLD.created_at != NEW.created_at OR
       OLD.created_by != NEW.created_by THEN
        RAISE EXCEPTION 'Account record is immutable. Create new version instead.';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_account_registry_immutability
    BEFORE UPDATE ON core.account_registry
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_account_update();

COMMENT ON TRIGGER trg_account_registry_immutability ON core.account_registry IS 'Enforces immutability on core account fields';

-- Trigger: Calculate record hash on insert
CREATE OR REPLACE FUNCTION core.calculate_account_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
BEGIN
    NEW.record_hash := encode(
        digest(
            NEW.account_id::text || 
            NEW.account_number || 
            NEW.account_type || 
            NEW.currency_code || 
            NEW.created_at::text ||
            COALESCE(NEW.parent_account_id::text, ''),
            'sha256'
        ),
        'hex'
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_account_registry_hash
    BEFORE INSERT ON core.account_registry
    FOR EACH ROW
    EXECUTE FUNCTION core.calculate_account_hash();

-- Trigger: Audit account changes
CREATE OR REPLACE FUNCTION core.audit_account_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO core.audit_trail (
            table_name, record_id, action, old_values, new_values,
            changed_by, changed_at, transaction_id, severity
        ) VALUES (
            'account_registry', NEW.account_id, 'INSERT', '{}',
            jsonb_build_object(
                'account_number', NEW.account_number,
                'account_name', NEW.account_name,
                'account_type', NEW.account_type
            ),
            current_user, now(), txid_current(), 'INFO'
        );
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER trg_account_registry_audit
    AFTER INSERT ON core.account_registry
    FOR EACH ROW
    EXECUTE FUNCTION core.audit_account_change();
