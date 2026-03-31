-- ============================================================================
-- Compliance Triggers
-- ============================================================================

-- Trigger: Validate transaction limits
CREATE OR REPLACE FUNCTION core.validate_transaction_limit()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
DECLARE
    v_limit DECIMAL(19,4);
    v_daily_total DECIMAL(19,4);
BEGIN
    -- Get account limit (simplified - would check entitlement limits)
    v_limit := 1000000; -- Default limit

    -- Calculate daily total
    SELECT COALESCE(SUM(amount), 0) INTO v_daily_total
    FROM core.movements
    WHERE (debit_account_id = NEW.debit_account_id OR credit_account_id = NEW.credit_account_id)
    AND created_at >= CURRENT_DATE;

    IF (v_daily_total + NEW.amount) > v_limit THEN
        RAISE EXCEPTION 'Transaction would exceed daily limit: % > %', 
            (v_daily_total + NEW.amount), v_limit;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_movements_validate_limit
    BEFORE INSERT ON core.movements
    FOR EACH ROW
    EXECUTE FUNCTION core.validate_transaction_limit();

-- Trigger: Validate business hours
CREATE OR REPLACE FUNCTION core.validate_business_hours()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
DECLARE
    v_is_business_day BOOLEAN;
BEGIN
    -- Check if current date is business day
    SELECT is_business_day INTO v_is_business_day
    FROM core.business_calendar
    WHERE calendar_date = CURRENT_DATE;

    IF v_is_business_day = FALSE THEN
        -- Allow but flag
        NEW.metadata := COALESCE(NEW.metadata, '{}'::jsonb) || 
            jsonb_build_object('non_business_day', TRUE);
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_transactions_business_hours
    BEFORE INSERT ON core.transactions
    FOR EACH ROW
    EXECUTE FUNCTION core.validate_business_hours();

-- Trigger: Verify digital signature on document
CREATE OR REPLACE FUNCTION core.verify_document_signature()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = core, public
AS $$
BEGIN
    -- In production, would verify signature cryptographically
    -- For now, just ensure signature exists if required
    IF NEW.requires_signature AND NEW.signature_id IS NULL THEN
        RAISE EXCEPTION 'Document requires signature before approval';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_documents_verify_signature
    BEFORE UPDATE ON core.document_registry
    FOR EACH ROW
    WHEN (NEW.status = 'APPROVED')
    EXECUTE FUNCTION core.verify_document_signature();
