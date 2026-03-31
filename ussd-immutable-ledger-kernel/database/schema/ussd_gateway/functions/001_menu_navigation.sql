-- ============================================================================
-- USSD Gateway - Menu Navigation Functions
-- Implements hierarchical menu tree using LTREE for efficient traversal
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Function: ussd.build_menu_tree
-- Description: Builds complete menu tree from database using LTREE paths
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.build_menu_tree(
    p_root_path LTREE DEFAULT 'root'
) RETURNS TABLE (
    menu_id UUID,
    menu_code VARCHAR(50),
    parent_path LTREE,
    full_path LTREE,
    display_text TEXT,
    menu_type VARCHAR(20),
    service_endpoint VARCHAR(255),
    requires_auth BOOLEAN,
    children JSONB
) AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE menu_hierarchy AS (
        -- Base case: root level menus
        SELECT 
            m.id,
            m.menu_code,
            m.parent_path,
            m.full_path,
            m.display_text,
            m.menu_type,
            m.service_endpoint,
            m.requires_auth,
            m.sort_order,
            0 as depth,
            ARRAY[m.sort_order] as path_sort
        FROM ussd.menus m
        WHERE m.full_path ~ (p_root_path::TEXT || '.*{1}')::LQUERY
          AND m.is_active = TRUE
        
        UNION ALL
        
        -- Recursive case: child menus
        SELECT 
            m.id,
            m.menu_code,
            m.parent_path,
            m.full_path,
            m.display_text,
            m.menu_type,
            m.service_endpoint,
            m.requires_auth,
            m.sort_order,
            mh.depth + 1,
            mh.path_sort || m.sort_order
        FROM ussd.menus m
        INNER JOIN menu_hierarchy mh ON m.parent_path = mh.full_path
        WHERE m.is_active = TRUE
          AND mh.depth < 5  -- Limit recursion depth
    )
    SELECT 
        mh.id,
        mh.menu_code,
        mh.parent_path,
        mh.full_path,
        mh.display_text,
        mh.menu_type,
        mh.service_endpoint,
        mh.requires_auth,
        (
            SELECT jsonb_agg(
                jsonb_build_object(
                    'menu_id', child.id,
                    'menu_code', child.menu_code,
                    'display_text', child.display_text,
                    'menu_type', child.menu_type,
                    'sort_order', child.sort_order
                ) ORDER BY child.sort_order
            )
            FROM ussd.menus child
            WHERE child.parent_path = mh.full_path
              AND child.is_active = TRUE
        ) as children
    FROM menu_hierarchy mh
    ORDER BY mh.path_sort;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.build_menu_tree IS 'Builds hierarchical menu tree using LTREE paths';

-- ----------------------------------------------------------------------------
-- Function: ussd.get_menu_by_path
-- Description: Retrieves menu by LTREE path with validation
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.get_menu_by_path(
    p_path LTREE
) RETURNS TABLE (
    menu_id UUID,
    menu_code VARCHAR(50),
    display_text TEXT,
    menu_type VARCHAR(20),
    service_endpoint VARCHAR(255),
    requires_auth BOOLEAN,
    input_validation VARCHAR(100),
    validation_regex VARCHAR(255),
    error_message TEXT,
    next_menu_path LTREE,
    available_options JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        m.id,
        m.menu_code,
        m.display_text,
        m.menu_type,
        m.service_endpoint,
        m.requires_auth,
        m.input_validation,
        m.validation_regex,
        m.error_message,
        m.next_menu_path,
        (
            SELECT jsonb_agg(
                jsonb_build_object(
                    'option_number', child.sort_order,
                    'menu_code', child.menu_code,
                    'display_text', child.display_text
                ) ORDER BY child.sort_order
            )
            FROM ussd.menus child
            WHERE child.parent_path = m.full_path
              AND child.is_active = TRUE
        ) as available_options
    FROM ussd.menus m
    WHERE m.full_path = p_path
      AND m.is_active = TRUE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.get_menu_by_path IS 'Retrieves menu details by LTREE path';

-- ----------------------------------------------------------------------------
-- Function: ussd.navigate_menu
-- Description: Handles menu navigation based on user input
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.navigate_menu(
    p_session_id VARCHAR(100),
    p_user_input VARCHAR(50),
    p_current_path LTREE DEFAULT 'root'
) RETURNS TABLE (
    success BOOLEAN,
    new_path LTREE,
    display_text TEXT,
    menu_type VARCHAR(20),
    requires_input BOOLEAN,
    service_endpoint VARCHAR(255),
    error_message TEXT,
    session_data JSONB
) AS $$
DECLARE
    v_session RECORD;
    v_current_menu RECORD;
    v_next_menu RECORD;
    v_decrypted_msisdn VARCHAR(20);
BEGIN
    -- Get and validate session
    SELECT * INTO v_session
    FROM ussd.get_session(p_session_id);
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT 
            FALSE,
            p_current_path,
            'Session expired. Please dial again.'::TEXT,
            'END'::VARCHAR(20),
            FALSE,
            NULL::VARCHAR(255),
            'SESSION_EXPIRED'::TEXT,
            '{}'::JSONB;
        RETURN;
    END IF;
    
    -- Handle special inputs
    IF p_user_input IN ('0', '00') THEN
        -- Go back / Cancel
        RETURN QUERY SELECT * FROM ussd.handle_navigation_special(p_session_id, p_user_input, v_session.menu_path);
        RETURN;
    END IF;
    
    -- Get current menu
    SELECT * INTO v_current_menu
    FROM ussd.get_menu_by_path(COALESCE(v_session.menu_path, p_current_path));
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT 
            FALSE,
            p_current_path,
            'Invalid menu. Please try again.'::TEXT,
            'END'::VARCHAR(20),
            FALSE,
            NULL::VARCHAR(255),
            'INVALID_MENU'::TEXT,
            '{}'::JSONB;
        RETURN;
    END IF;
    
    -- Handle menu types
    CASE v_current_menu.menu_type
        WHEN 'INPUT' THEN
            -- Validate input
            IF v_current_menu.validation_regex IS NOT NULL 
               AND NOT (p_user_input ~ v_current_menu.validation_regex) THEN
                RETURN QUERY SELECT 
                    FALSE,
                    v_session.menu_path,
                    COALESCE(v_current_menu.error_message, 'Invalid input. Please try again.')::TEXT,
                    'INPUT'::VARCHAR(20),
                    TRUE,
                    v_current_menu.service_endpoint,
                    'VALIDATION_FAILED'::TEXT,
                    v_session.session_data;
                RETURN;
            END IF;
            
            -- Store input and proceed to next menu
            PERFORM ussd.update_session_state(
                p_session_id,
                'INPUT_RECEIVED',
                v_current_menu.next_menu_path,
                v_session.session_data || jsonb_build_object(v_current_menu.menu_code, p_user_input)
            );
            
            -- Get next menu
            SELECT * INTO v_next_menu
            FROM ussd.get_menu_by_path(v_current_menu.next_menu_path);
            
        WHEN 'MENU' THEN
            -- Navigate to selected option
            SELECT 
                m.id,
                m.menu_code,
                m.display_text,
                m.menu_type,
                m.service_endpoint,
                m.requires_auth,
                m.input_validation,
                m.validation_regex,
                m.error_message,
                m.next_menu_path,
                NULL::JSONB as available_options
            INTO v_next_menu
            FROM ussd.menus m
            WHERE m.parent_path = v_current_menu.full_path
              AND m.sort_order = p_user_input::INTEGER
              AND m.is_active = TRUE;
            
            IF NOT FOUND THEN
                RETURN QUERY SELECT 
                    FALSE,
                    v_session.menu_path,
                    'Invalid option. Please try again.'::TEXT,
                    'MENU'::VARCHAR(20),
                    FALSE,
                    NULL::VARCHAR(255),
                    'INVALID_OPTION'::TEXT,
                    v_session.session_data;
                RETURN;
            END IF;
            
            -- Update session with navigation
            PERFORM ussd.update_session_state(
                p_session_id,
                'NAVIGATING',
                v_next_menu.full_path,
                v_session.session_data || jsonb_build_object('last_selection', p_user_input)
            );
            
        WHEN 'SERVICE' THEN
            -- Service menu - call endpoint and return result
            RETURN QUERY SELECT * FROM ussd.execute_service_menu(
                p_session_id, 
                v_session, 
                v_current_menu
            );
            RETURN;
            
        WHEN 'CONFIRM' THEN
            -- Confirmation menu
            IF LOWER(p_user_input) IN ('1', 'yes', 'y') THEN
                RETURN QUERY SELECT * FROM ussd.handle_confirmation(p_session_id, TRUE, v_session);
            ELSE
                RETURN QUERY SELECT * FROM ussd.handle_confirmation(p_session_id, FALSE, v_session);
            END IF;
            RETURN;
            
        WHEN 'END' THEN
            -- End session
            PERFORM ussd.close_session(p_session_id, 'COMPLETED');
            RETURN QUERY SELECT 
                TRUE,
                v_session.menu_path,
                v_current_menu.display_text::TEXT,
                'END'::VARCHAR(20),
                FALSE,
                NULL::VARCHAR(255),
                NULL::TEXT,
                v_session.session_data;
            RETURN;
            
        ELSE
            RETURN QUERY SELECT 
                FALSE,
                v_session.menu_path,
                'Unknown menu type.'::TEXT,
                'END'::VARCHAR(20),
                FALSE,
                NULL::VARCHAR(255),
                'UNKNOWN_TYPE'::TEXT,
                v_session.session_data;
            RETURN;
    END CASE;
    
    -- Return next menu details
    IF FOUND THEN
        RETURN QUERY SELECT 
            TRUE,
            v_next_menu.full_path,
            v_next_menu.display_text::TEXT,
            v_next_menu.menu_type::VARCHAR(20),
            (v_next_menu.menu_type = 'INPUT')::BOOLEAN,
            v_next_menu.service_endpoint,
            NULL::TEXT,
            v_session.session_data;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.navigate_menu IS 'Handles USSD menu navigation based on user input';

-- ----------------------------------------------------------------------------
-- Function: ussd.handle_navigation_special
-- Description: Handles special navigation (back, cancel)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.handle_navigation_special(
    p_session_id VARCHAR(100),
    p_input VARCHAR(10),
    p_current_path LTREE
) RETURNS TABLE (
    success BOOLEAN,
    new_path LTREE,
    display_text TEXT,
    menu_type VARCHAR(20),
    requires_input BOOLEAN,
    service_endpoint VARCHAR(255),
    error_message TEXT,
    session_data JSONB
) AS $$
DECLARE
    v_parent_path LTREE;
    v_menu RECORD;
    v_session RECORD;
BEGIN
    -- Get current session
    SELECT * INTO v_session FROM ussd.get_session(p_session_id);
    
    IF p_input = '00' THEN
        -- Cancel - close session
        PERFORM ussd.close_session(p_session_id, 'CANCELLED');
        RETURN QUERY SELECT 
            TRUE,
            'root'::LTREE,
            'Session cancelled. Thank you.'::TEXT,
            'END'::VARCHAR(20),
            FALSE,
            NULL::VARCHAR(255),
            NULL::TEXT,
            v_session.session_data;
        RETURN;
    END IF;
    
    -- Go back - get parent path
    v_parent_path := subpath(p_current_path, 0, nlevel(p_current_path) - 1);
    
    IF v_parent_path IS NULL OR v_parent_path = ''::LTREE THEN
        v_parent_path := 'root'::LTREE;
    END IF;
    
    -- Get parent menu
    SELECT * INTO v_menu FROM ussd.get_menu_by_path(v_parent_path);
    
    IF FOUND THEN
        PERFORM ussd.update_session_state(
            p_session_id,
            'NAVIGATING',
            v_parent_path
        );
        
        RETURN QUERY SELECT 
            TRUE,
            v_parent_path,
            v_menu.display_text::TEXT,
            v_menu.menu_type::VARCHAR(20),
            (v_menu.menu_type = 'INPUT')::BOOLEAN,
            v_menu.service_endpoint,
            NULL::TEXT,
            v_session.session_data;
    ELSE
        RETURN QUERY SELECT 
            FALSE,
            p_current_path,
            'Cannot go back further.'::TEXT,
            'MENU'::VARCHAR(20),
            FALSE,
            NULL::VARCHAR(255),
            'AT_ROOT'::TEXT,
            v_session.session_data;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.handle_navigation_special IS 'Handles special navigation inputs (0=back, 00=cancel)';

-- ----------------------------------------------------------------------------
-- Function: ussd.execute_service_menu
-- Description: Executes service endpoint and returns result
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.execute_service_menu(
    p_session_id VARCHAR(100),
    p_session RECORD,
    p_menu RECORD
) RETURNS TABLE (
    success BOOLEAN,
    new_path LTREE,
    display_text TEXT,
    menu_type VARCHAR(20),
    requires_input BOOLEAN,
    service_endpoint VARCHAR(255),
    error_message TEXT,
    session_data JSONB
) AS $$
DECLARE
    v_result JSONB;
    v_next_path LTREE;
BEGIN
    -- Log service call attempt
    INSERT INTO ussd.service_calls (
        session_id,
        service_endpoint,
        request_data,
        created_at
    ) VALUES (
        p_session_id,
        p_menu.service_endpoint,
        p_session.session_data,
        NOW()
    );
    
    -- For now, return success - actual HTTP call would be done by application layer
    v_next_path := COALESCE(p_menu.next_menu_path, 'root.end'::LTREE);
    
    PERFORM ussd.update_session_state(
        p_session_id,
        'SERVICE_CALLED',
        v_next_path,
        p_session.session_data || jsonb_build_object('service_result', 'pending')
    );
    
    RETURN QUERY SELECT 
        TRUE,
        v_next_path,
        'Processing your request...'::TEXT,
        'END'::VARCHAR(20),
        FALSE,
        p_menu.service_endpoint,
        NULL::TEXT,
        p_session.session_data;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.execute_service_menu IS 'Executes service endpoint for service-type menus';

-- ----------------------------------------------------------------------------
-- Function: ussd.handle_confirmation
-- Description: Handles confirmation menu responses
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.handle_confirmation(
    p_session_id VARCHAR(100),
    p_confirmed BOOLEAN,
    p_session RECORD
) RETURNS TABLE (
    success BOOLEAN,
    new_path LTREE,
    display_text TEXT,
    menu_type VARCHAR(20),
    requires_input BOOLEAN,
    service_endpoint VARCHAR(255),
    error_message TEXT,
    session_data JSONB
) AS $$
DECLARE
    v_display_text TEXT;
    v_final_path LTREE := 'root.end'::LTREE;
BEGIN
    IF p_confirmed THEN
        v_display_text := 'Transaction confirmed successfully.';
        PERFORM ussd.close_session(p_session_id, 'CONFIRMED', 
            p_session.session_data || jsonb_build_object('confirmed', TRUE));
    ELSE
        v_display_text := 'Transaction cancelled.';
        PERFORM ussd.close_session(p_session_id, 'CANCELLED',
            p_session.session_data || jsonb_build_object('confirmed', FALSE));
    END IF;
    
    RETURN QUERY SELECT 
        TRUE,
        v_final_path,
        v_display_text::TEXT,
        'END'::VARCHAR(20),
        FALSE,
        NULL::VARCHAR(255),
        NULL::TEXT,
        p_session.session_data || jsonb_build_object('confirmed', p_confirmed);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.handle_confirmation IS 'Handles confirmation menu yes/no responses';
