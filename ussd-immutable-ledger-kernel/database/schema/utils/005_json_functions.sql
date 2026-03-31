-- ============================================================================
-- JSON Utility Functions
-- ============================================================================

-- Function: Safe JSONB extract
CREATE OR REPLACE FUNCTION utils.jsonb_safe_extract(
    p_jsonb JSONB,
    p_key TEXT,
    p_default JSONB DEFAULT 'null'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
IMMUTABLE
SET search_path = utils, public
AS $$
BEGIN
    RETURN COALESCE(p_jsonb->p_key, p_default);
END;
$$;

COMMENT ON FUNCTION utils.jsonb_safe_extract IS 'Safely extracts JSONB value with default';

-- Function: Merge JSONB arrays
CREATE OR REPLACE FUNCTION utils.jsonb_merge_arrays(
    p_array1 JSONB,
    p_array2 JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
IMMUTABLE
SET search_path = utils, public
AS $$
BEGIN
    IF jsonb_typeof(p_array1) != 'array' OR jsonb_typeof(p_array2) != 'array' THEN
        RETURN '[]'::jsonb;
    END IF;
    
    RETURN p_array1 || p_array2;
END;
$$;

COMMENT ON FUNCTION utils.jsonb_merge_arrays IS 'Merges two JSONB arrays';

-- Function: Flatten JSONB object
CREATE OR REPLACE FUNCTION utils.jsonb_flatten(
    p_jsonb JSONB,
    p_separator TEXT DEFAULT '.'
)
RETURNS TABLE (key TEXT, value JSONB)
LANGUAGE plpgsql
STABLE
SET search_path = utils, public
AS $$
DECLARE
    v_key TEXT;
    v_value JSONB;
BEGIN
    FOR v_key, v_value IN SELECT * FROM jsonb_each(p_jsonb)
    LOOP
        IF jsonb_typeof(v_value) = 'object' THEN
            RETURN QUERY
            SELECT 
                v_key || p_separator || f.key,
                f.value
            FROM utils.jsonb_flatten(v_value, p_separator) f;
        ELSE
            key := v_key;
            value := v_value;
            RETURN NEXT;
        END IF;
    END LOOP;
END;
$$;

COMMENT ON FUNCTION utils.jsonb_flatten IS 'Flattens nested JSONB object';
