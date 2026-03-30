-- ============================================================================
-- USSD KERNEL APP SCHEMA - ENTITY SEQUENCES
-- Enterprise-Grade Immutable Ledger System
-- ============================================================================
-- Description: Human-readable sequential code generators for transactions.
--              This is a kernel configuration primitive - applications define
--              their own sequence codes and formats.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. SEQUENCE REGISTRY
-- ----------------------------------------------------------------------------
CREATE TABLE ussd_app.entity_sequences (
    sequence_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Identification
    sequence_code VARCHAR(50) NOT NULL,  -- Unique code for the sequence type
    sequence_name VARCHAR(100) NOT NULL,
    
    -- Scope
    application_id UUID,  -- NULL = global/kernel
    
    -- Formatting (configurable by applications)
    prefix VARCHAR(20) DEFAULT '',
    year_format VARCHAR(10) DEFAULT 'YYYY', -- 'YYYY', 'YY', or ''
    separator VARCHAR(5) DEFAULT '-',
    padding_length INTEGER DEFAULT 6,
    
    -- Current value
    current_value BIGINT DEFAULT 0,
    last_year INTEGER,
    
    -- Constraints
    min_value BIGINT DEFAULT 1,
    max_value BIGINT DEFAULT 999999999,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Audit
    created_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    created_by UUID,
    
    UNIQUE(sequence_code, application_id)
);

-- Sequence history (for audit)
CREATE TABLE ussd_app.sequence_usage_log (
    log_id BIGSERIAL PRIMARY KEY,
    sequence_id UUID NOT NULL,
    generated_code VARCHAR(100) NOT NULL,
    reference_type VARCHAR(50),  -- What this code refers to
    reference_id UUID,
    generated_at TIMESTAMPTZ DEFAULT ussd_core.precise_now(),
    generated_by UUID
);

-- ----------------------------------------------------------------------------
-- 2. INDEXES
-- ----------------------------------------------------------------------------
CREATE INDEX idx_entity_sequences_app ON ussd_app.entity_sequences(application_id);
CREATE INDEX idx_entity_sequences_active ON ussd_app.entity_sequences(is_active) WHERE is_active = TRUE;

CREATE INDEX idx_seq_usage_log_sequence ON ussd_app.sequence_usage_log(sequence_id);
CREATE INDEX idx_seq_usage_log_code ON ussd_app.sequence_usage_log(generated_code);

-- ----------------------------------------------------------------------------
-- 3. SEQUENCE GENERATION FUNCTION
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd_app.generate_entity_code(
    p_sequence_code VARCHAR,
    p_application_id UUID DEFAULT NULL,
    p_reference_type VARCHAR DEFAULT NULL,
    p_reference_id UUID DEFAULT NULL
)
RETURNS VARCHAR
LANGUAGE plpgsql
AS $$
DECLARE
    v_sequence ussd_app.entity_sequences%ROWTYPE;
    v_next_value BIGINT;
    v_current_year INTEGER;
    v_year_str VARCHAR(10);
    v_generated_code VARCHAR(100);
BEGIN
    -- Lock the sequence row
    SELECT * INTO v_sequence
    FROM ussd_app.entity_sequences
    WHERE sequence_code = p_sequence_code
      AND (application_id IS NOT DISTINCT FROM p_application_id)
      AND is_active = TRUE
    FOR UPDATE;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Sequence not found: %', p_sequence_code;
    END IF;
    
    v_current_year := EXTRACT(YEAR FROM CURRENT_DATE);
    
    -- Check year change
    IF v_sequence.last_year IS NOT NULL AND v_sequence.last_year != v_current_year THEN
        v_sequence.current_value := 0;
    END IF;
    
    v_next_value := v_sequence.current_value + 1;
    
    IF v_next_value > v_sequence.max_value THEN
        RAISE EXCEPTION 'Sequence % has reached maximum value', p_sequence_code;
    END IF;
    
    -- Build year string
    IF v_sequence.year_format = 'YYYY' THEN
        v_year_str := v_current_year::TEXT;
    ELSIF v_sequence.year_format = 'YY' THEN
        v_year_str := RIGHT(v_current_year::TEXT, 2);
    ELSE
        v_year_str := '';
    END IF;
    
    -- Build code
    v_generated_code := v_sequence.prefix;
    
    IF v_year_str != '' THEN
        v_generated_code := v_generated_code || v_sequence.separator || v_year_str;
    END IF;
    
    v_generated_code := v_generated_code || v_sequence.separator || 
                        LPAD(v_next_value::TEXT, v_sequence.padding_length, '0');
    
    -- Update sequence
    UPDATE ussd_app.entity_sequences
    SET current_value = v_next_value,
        last_year = v_current_year
    WHERE sequence_id = v_sequence.sequence_id;
    
    -- Log usage
    INSERT INTO ussd_app.sequence_usage_log (
        sequence_id, generated_code, reference_type, reference_id, generated_by
    ) VALUES (
        v_sequence.sequence_id, v_generated_code, p_reference_type, p_reference_id,
        NULLIF(current_setting('app.current_account_id', TRUE), '')::UUID
    );
    
    RETURN v_generated_code;
END;
$$;

-- ----------------------------------------------------------------------------
-- 4. COMMENTS
-- ----------------------------------------------------------------------------
COMMENT ON TABLE ussd_app.entity_sequences IS 
    'Application-configurable sequential code generators (business-agnostic)';
COMMENT ON FUNCTION ussd_app.generate_entity_code IS 
    'Generates next sequential code with configurable formatting';
