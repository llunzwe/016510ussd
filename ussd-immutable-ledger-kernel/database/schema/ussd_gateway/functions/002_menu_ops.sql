-- ============================================================================
-- USSD Menu Operations
-- ============================================================================

-- Function: Get menu display
CREATE OR REPLACE FUNCTION ussd.get_menu_display(
    p_menu_id UUID,
    p_language_code VARCHAR(5) DEFAULT 'en'
)
RETURNS TABLE (
    menu_text TEXT,
    options JSONB,
    timeout_seconds INTEGER,
    security_level VARCHAR(16)
)
LANGUAGE plpgsql
STABLE
SET search_path = ussd_gateway, public
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COALESCE(mt.translated_text, m.menu_text),
        m.options_config,
        m.timeout_seconds,
        m.security_level
    FROM ussd.menu_configurations m
    LEFT JOIN ussd.menu_translations mt 
        ON m.menu_id = mt.menu_id 
        AND mt.language_code = p_language_code
    WHERE m.menu_id = p_menu_id
    AND m.is_active = TRUE;
END;
$$;

COMMENT ON FUNCTION ussd.get_menu_display IS 'Gets localized menu display text';

-- Function: Process menu input
CREATE OR REPLACE FUNCTION ussd.process_menu_input(
    p_session_id UUID,
    p_user_input TEXT
)
RETURNS TABLE (
    next_menu_id UUID,
    menu_text TEXT,
    is_terminal BOOLEAN,
    action_payload JSONB
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ussd_gateway, public
AS $$
DECLARE
    v_session RECORD;
    v_current_menu RECORD;
    v_next_menu_id UUID;
BEGIN
    -- Get session
    SELECT * INTO v_session
    FROM ussd.session_state
    WHERE internal_session_id = p_session_id;

    IF v_session IS NULL THEN
        RETURN;
    END IF;

    -- Get current menu
    SELECT * INTO v_current_menu
    FROM ussd.menu_configurations
    WHERE menu_code = v_session.menu_state
    AND application_id = v_session.application_id
    AND is_active = TRUE;

    IF v_current_menu IS NULL THEN
        RETURN;
    END IF;

    -- Determine next menu based on input
    v_next_menu_id := v_current_menu.default_next_menu_id;

    -- Check for matching option
    SELECT target_menu_id INTO v_next_menu_id
    FROM jsonb_to_recordset(v_current_menu.options_config) 
        AS x(option_value TEXT, target_menu_id UUID)
    WHERE option_value = p_user_input;

    -- Update session
    UPDATE ussd.session_state
    SET menu_state = COALESCE(
        (SELECT menu_code FROM ussd.menu_configurations WHERE menu_id = v_next_menu_id),
        v_session.menu_state
    ),
        input_history = array_append(input_history, p_user_input)
    WHERE internal_session_id = p_session_id;

    -- Return next menu
    RETURN QUERY
    SELECT 
        m.menu_id,
        m.menu_text,
        m.is_terminal,
        m.action_payload
    FROM ussd.menu_configurations m
    WHERE m.menu_id = v_next_menu_id;
END;
$$;

COMMENT ON FUNCTION ussd.process_menu_input IS 'Processes user input and returns next menu';
