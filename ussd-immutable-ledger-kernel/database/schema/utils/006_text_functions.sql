-- ============================================================================
-- Text Utility Functions
-- ============================================================================

-- Function: Slugify text
CREATE OR REPLACE FUNCTION utils.slugify(p_text TEXT)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
SET search_path = utils, public
AS $$
BEGIN
    RETURN lower(
        regexp_replace(
            regexp_replace(p_text, '[^a-zA-Z0-9]+', '-', 'g'),
            '^-+|-+$', '', 'g'
        )
    );
END;
$$;

COMMENT ON FUNCTION utils.slugify IS 'Converts text to URL-friendly slug';

-- Function: Truncate with ellipsis
CREATE OR REPLACE FUNCTION utils.truncate_text(
    p_text TEXT,
    p_max_length INTEGER,
    p_ellipsis TEXT DEFAULT '...'
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
SET search_path = utils, public
AS $$
BEGIN
    IF length(p_text) <= p_max_length THEN
        RETURN p_text;
    END IF;
    
    RETURN left(p_text, p_max_length - length(p_ellipsis)) || p_ellipsis;
END;
$$;

COMMENT ON FUNCTION utils.truncate_text IS 'Truncates text with ellipsis';

-- Function: Normalize phone number
CREATE OR REPLACE FUNCTION utils.normalize_phone(p_phone TEXT)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
SET search_path = utils, public
AS $$
DECLARE
    v_digits TEXT;
BEGIN
    v_digits := regexp_replace(p_phone, '\D', '', 'g');
    
    -- Add + if missing and starts with country code
    IF length(v_digits) > 10 AND left(v_digits, 1) != '+' THEN
        v_digits := '+' || v_digits;
    END IF;
    
    RETURN v_digits;
END;
$$;

COMMENT ON FUNCTION utils.normalize_phone IS 'Normalizes phone number to E.164 format';
