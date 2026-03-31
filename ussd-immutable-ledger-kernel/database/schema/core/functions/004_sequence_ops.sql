-- ============================================================================
-- Entity Sequence Operations
-- ============================================================================

-- Function: Get next sequence value
CREATE OR REPLACE FUNCTION core.next_sequence_value(
    p_sequence_name VARCHAR(50),
    p_application_id UUID DEFAULT NULL
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_next_value BIGINT;
    v_app_id UUID;
BEGIN
    v_app_id := COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID);

    -- Update sequence atomically
    UPDATE core.entity_sequences
    SET current_value = current_value + increment_by,
        last_used_at = now()
    WHERE sequence_name = p_sequence_name
    AND application_id = v_app_id
    RETURNING current_value INTO v_next_value;

    IF v_next_value IS NULL THEN
        RAISE EXCEPTION 'Sequence not found: % for application %', p_sequence_name, v_app_id;
    END IF;

    RETURN v_next_value;
END;
$$;

COMMENT ON FUNCTION core.next_sequence_value IS 'Gets next value from named sequence';

-- Function: Peek sequence value (without incrementing)
CREATE OR REPLACE FUNCTION core.peek_sequence_value(
    p_sequence_name VARCHAR(50),
    p_application_id UUID DEFAULT NULL
)
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
SET search_path = core, public
AS $$
DECLARE
    v_current_value BIGINT;
BEGIN
    SELECT current_value INTO v_current_value
    FROM core.entity_sequences
    WHERE sequence_name = p_sequence_name
    AND application_id = COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID);

    RETURN v_current_value;
END;
$$;

COMMENT ON FUNCTION core.peek_sequence_value IS 'Views current sequence value without incrementing';

-- Function: Reset sequence
CREATE OR REPLACE FUNCTION core.reset_sequence(
    p_sequence_name VARCHAR(50),
    p_new_value BIGINT,
    p_application_id UUID DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
BEGIN
    UPDATE core.entity_sequences
    SET current_value = p_new_value,
        last_used_at = now()
    WHERE sequence_name = p_sequence_name
    AND application_id = COALESCE(p_application_id, current_setting('app.current_account_id', true)::UUID);

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Sequence not found: %', p_sequence_name;
    END IF;
END;
$$;

COMMENT ON FUNCTION core.reset_sequence IS 'Resets sequence to specified value (admin only)';

-- Function: Generate formatted reference number
CREATE OR REPLACE FUNCTION core.generate_reference(
    p_sequence_name VARCHAR(50),
    p_prefix VARCHAR(10) DEFAULT '',
    p_suffix VARCHAR(10) DEFAULT '',
    p_padding INTEGER DEFAULT 10,
    p_application_id UUID DEFAULT NULL
)
RETURNS VARCHAR(64)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = core, public
AS $$
DECLARE
    v_seq_value BIGINT;
BEGIN
    v_seq_value := core.next_sequence_value(p_sequence_name, p_application_id);
    
    RETURN p_prefix || 
           LPAD(v_seq_value::text, p_padding, '0') || 
           p_suffix || 
           TO_CHAR(now(), 'YYYYMMDD');
END;
$$;

COMMENT ON FUNCTION core.generate_reference IS 'Generates formatted reference number from sequence';
