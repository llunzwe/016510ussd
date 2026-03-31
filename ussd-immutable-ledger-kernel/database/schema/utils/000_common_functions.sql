-- ============================================================================
-- Common Utility Functions
-- ============================================================================

-- Function: Generate secure random string
CREATE OR REPLACE FUNCTION utils.generate_random_string(
    p_length INTEGER DEFAULT 32,
    p_charset TEXT DEFAULT 'alphanumeric'
)
RETURNS TEXT
LANGUAGE plpgsql
SET search_path = utils, public
AS $$
DECLARE
    v_chars TEXT;
    v_result TEXT := '';
    v_i INTEGER;
BEGIN
    v_chars := CASE p_charset
        WHEN 'alphanumeric' THEN 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        WHEN 'numeric' THEN '0123456789'
        WHEN 'hex' THEN '0123456789abcdef'
        WHEN 'safe' THEN 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
        ELSE 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    END;

    FOR v_i IN 1..p_length LOOP
        v_result := v_result || substr(v_chars, floor(random() * length(v_chars) + 1)::integer, 1);
    END LOOP;

    RETURN v_result;
END;
$$;

COMMENT ON FUNCTION utils.generate_random_string IS 'Generates cryptographically secure random string';

-- Function: Format currency
CREATE OR REPLACE FUNCTION utils.format_currency(
    p_amount DECIMAL(19,4),
    p_currency_code CHAR(3) DEFAULT 'USD',
    p_locale VARCHAR(10) DEFAULT 'en_US'
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
SET search_path = utils, public
AS $$
DECLARE
    v_symbol TEXT;
BEGIN
    v_symbol := CASE p_currency_code
        WHEN 'USD' THEN '$'
        WHEN 'EUR' THEN '€'
        WHEN 'GBP' THEN '£'
        WHEN 'JPY' THEN '¥'
        WHEN 'ZAR' THEN 'R'
        WHEN 'ZWL' THEN '$'
        ELSE p_currency_code || ' '
    END;

    RETURN v_symbol || to_char(p_amount, 'FM999,999,999,999.00');
END;
$$;

COMMENT ON FUNCTION utils.format_currency IS 'Formats amount with currency symbol';

-- Function: Mask sensitive data
CREATE OR REPLACE FUNCTION utils.mask_sensitive(
    p_data TEXT,
    p_mask_type VARCHAR(20) DEFAULT 'partial'
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
SET search_path = utils, public
AS $$
DECLARE
    v_length INTEGER;
BEGIN
    IF p_data IS NULL OR length(p_data) < 4 THEN
        RETURN '****';
    END IF;

    v_length := length(p_data);

    RETURN CASE p_mask_type
        WHEN 'full' THEN repeat('*', v_length)
        WHEN 'partial' THEN left(p_data, 2) || repeat('*', v_length - 4) || right(p_data, 2)
        WHEN 'email' THEN left(split_part(p_data, '@', 1), 1) || '***@' || split_part(p_data, '@', 2)
        WHEN 'phone' THEN repeat('*', v_length - 4) || right(p_data, 4)
        ELSE repeat('*', v_length)
    END;
END;
$$;

COMMENT ON FUNCTION utils.mask_sensitive IS 'Masks sensitive data for display';
