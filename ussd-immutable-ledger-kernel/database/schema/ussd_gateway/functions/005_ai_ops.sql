-- ============================================================================
-- USSD AI Operations
-- ============================================================================

-- Function: Get AI menu recommendation
CREATE OR REPLACE FUNCTION ussd.get_menu_recommendation(
    p_session_id UUID,
    p_user_input TEXT
)
RETURNS TABLE (
    recommended_menu_id UUID,
    confidence DECIMAL(5,4),
    reason TEXT
)
LANGUAGE plpgsql
STABLE
SET search_path = ussd_gateway, public
AS $$
DECLARE
    v_session RECORD;
    v_history TEXT;
BEGIN
    SELECT * INTO v_session
    FROM ussd.session_state
    WHERE internal_session_id = p_session_id;

    IF v_session IS NULL THEN
        RETURN;
    END IF;

    -- Build input history context
    v_history := array_to_string(v_session.input_history, ' ');

    -- Query vector store for similar patterns
    RETURN QUERY
    SELECT 
        vs.metadata->>'menu_id' AS recommended_menu_id,
        1 - (vs.embedding <=> query_embedding) AS confidence,
        'Pattern match: ' || vs.content AS reason
    FROM app.vector_store vs,
        (SELECT embedding FROM app.vector_store 
         WHERE content LIKE '%' || p_user_input || '%' 
         LIMIT 1) AS query_embedding
    WHERE vs.category = 'menu_navigation'
    AND vs.application_id = v_session.application_id
    ORDER BY vs.embedding <=> query_embedding.embedding
    LIMIT 1;
END;
$$;

COMMENT ON FUNCTION ussd.get_menu_recommendation IS 'Gets AI-powered menu recommendation';

-- Function: Analyze session sentiment
CREATE OR REPLACE FUNCTION ussd.analyze_sentiment(
    p_session_id UUID
)
RETURNS TABLE (
    sentiment VARCHAR(16),
    confidence DECIMAL(5,4),
    suggestions TEXT[]
)
LANGUAGE plpgsql
STABLE
SET search_path = ussd_gateway, public
AS $$
DECLARE
    v_session RECORD;
    v_input_text TEXT;
BEGIN
    SELECT * INTO v_session
    FROM ussd.session_state
    WHERE internal_session_id = p_session_id;

    IF v_session IS NULL OR array_length(v_session.input_history, 1) IS NULL THEN
        sentiment := 'NEUTRAL';
        confidence := 1.0;
        suggestions := ARRAY[]::TEXT[];
        RETURN NEXT;
        RETURN;
    END IF;

    v_input_text := array_to_string(v_session.input_history, ' ');

    -- Simple heuristic sentiment (would use ML model in production)
    sentiment := CASE 
        WHEN v_input_text ~* '(error|wrong|fail|bad|problem)' THEN 'NEGATIVE'
        WHEN v_input_text ~* '(good|great|thanks|ok|yes)' THEN 'POSITIVE'
        ELSE 'NEUTRAL'
    END;

    confidence := 0.7;
    suggestions := CASE sentiment
        WHEN 'NEGATIVE' THEN ARRAY['Offer support option', 'Simplify menu']
        ELSE ARRAY[]::TEXT[]
    END;

    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION ussd.analyze_sentiment IS 'Analyzes user sentiment from session history';
