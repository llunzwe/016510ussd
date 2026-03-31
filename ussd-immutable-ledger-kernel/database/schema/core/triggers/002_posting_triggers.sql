-- ============================================================================
-- Posting Triggers
-- ============================================================================

-- Trigger: Calculate running balance on posting insert
CREATE OR REPLACE FUNCTION core.calculate_running_balance()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
DECLARE
    v_last_balance DECIMAL(19,4);
BEGIN
    -- Get last running balance
    SELECT running_balance INTO v_last_balance
    FROM core.movement_postings
    WHERE account_id = NEW.account_id
    ORDER BY created_at DESC
    LIMIT 1;

    v_last_balance := COALESCE(v_last_balance, 0);

    -- Calculate new running balance
    IF NEW.side = 'CREDIT' THEN
        NEW.running_balance := v_last_balance + NEW.amount;
    ELSE
        NEW.running_balance := v_last_balance - NEW.amount;
    END IF;

    -- Calculate record hash
    NEW.record_hash := encode(
        digest(
            NEW.posting_id::text || 
            NEW.movement_id::text || 
            NEW.account_id::text || 
            NEW.side || 
            NEW.amount::text || 
            NEW.running_balance::text ||
            NEW.created_at::text,
            'sha256'
        ),
        'hex'
    );

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_postings_calculate_balance
    BEFORE INSERT ON core.movement_postings
    FOR EACH ROW
    EXECUTE FUNCTION core.calculate_running_balance();

-- Trigger: Prevent posting modification
CREATE OR REPLACE FUNCTION core.prevent_posting_update()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
BEGIN
    RAISE EXCEPTION 'Posting records are immutable';
END;
$$;

CREATE TRIGGER trg_postings_immutable
    BEFORE UPDATE ON core.movement_postings
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_posting_update();

CREATE TRIGGER trg_postings_no_delete
    BEFORE DELETE ON core.movement_postings
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_posting_update();
