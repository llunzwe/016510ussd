-- ============================================================================
-- Math Utility Functions
-- ============================================================================

-- Function: Round to nearest
CREATE OR REPLACE FUNCTION utils.round_to(
    p_value DECIMAL,
    p_precision INTEGER,
    p_direction VARCHAR(10) DEFAULT 'NEAREST'
)
RETURNS DECIMAL
LANGUAGE plpgsql
IMMUTABLE
SET search_path = utils, public
AS $$
DECLARE
    v_factor DECIMAL;
BEGIN
    v_factor := power(10, p_precision);
    
    RETURN CASE p_direction
        WHEN 'UP' THEN ceil(p_value * v_factor) / v_factor
        WHEN 'DOWN' THEN floor(p_value * v_factor) / v_factor
        ELSE round(p_value, p_precision)
    END;
END;
$$;

COMMENT ON FUNCTION utils.round_to IS 'Rounds value with direction control';

-- Function: Calculate percentage
CREATE OR REPLACE FUNCTION utils.percentage(
    p_part DECIMAL,
    p_whole DECIMAL
)
RETURNS DECIMAL(5,2)
LANGUAGE plpgsql
IMMUTABLE
SET search_path = utils, public
AS $$
BEGIN
    IF p_whole = 0 THEN
        RETURN 0;
    END IF;
    
    RETURN ROUND((p_part / p_whole) * 100, 2);
END;
$$;

COMMENT ON FUNCTION utils.percentage IS 'Calculates percentage safely';

-- Function: Generate check digit (Luhn mod 10)
CREATE OR REPLACE FUNCTION utils.luhn_check_digit(p_digits TEXT)
RETURNS INTEGER
LANGUAGE plpgsql
IMMUTABLE
SET search_path = utils, public
AS $$
DECLARE
    v_sum INTEGER := 0;
    v_is_even BOOLEAN := FALSE;
    v_digit INTEGER;
    v_i INTEGER;
BEGIN
    FOR v_i IN REVERSE length(p_digits)..1 LOOP
        v_digit := substring(p_digits, v_i, 1)::INTEGER;
        
        IF v_is_even THEN
            v_digit := v_digit * 2;
            IF v_digit > 9 THEN
                v_digit := v_digit - 9;
            END IF;
        END IF;
        
        v_sum := v_sum + v_digit;
        v_is_even := NOT v_is_even;
    END LOOP;
    
    RETURN (10 - (v_sum % 10)) % 10;
END;
$$;

COMMENT ON FUNCTION utils.luhn_check_digit IS 'Calculates Luhn mod 10 check digit';
