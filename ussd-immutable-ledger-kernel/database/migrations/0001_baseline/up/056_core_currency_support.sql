-- =============================================================================
-- USSD KERNEL CORE SCHEMA - CURRENCY SUPPORT & FX HANDLING
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    056_core_currency_support.sql
-- MIGRATION:   0001_baseline/up
-- SCHEMA:      core
-- DESCRIPTION: Multi-currency support with FX rate management for international
--              USSD applications handling multiple currencies.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - FX rate change monitoring
├── A.18.1 Compliance - Regulatory FX reporting
└── A.18.2 Compliance - Audit trail for currency conversions

Financial Regulations
├── IFRS: Multi-currency transaction reporting
├── Central Bank: FX rate reporting requirements
├── AML: Cross-border transaction monitoring
└── Tax: Currency conversion for tax calculations

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. CURRENCY CODES
   - ISO 4217 standard currency codes (3 characters)
   - Cryptocurrency support (4-6 characters)
   - Token/internal currency support

2. FX RATE MANAGEMENT
   - Append-only rate history (immutable)
   - Multiple rate sources (central bank, market, internal)
   - Rate validity periods
   - Cross-rate calculation support

3. PRECISION
   - Amounts: NUMERIC(20, 8) for high precision
   - Rates: NUMERIC(20, 10) for FX rates
   - All calculations use exact decimal arithmetic

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

FX SECURITY:
- Immutable rate history prevents manipulation
- Source attribution for audit
- Rate validation ranges
- Multi-signature for rate updates (in application layer)

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: currency_code
- FX RATES: from_currency + to_currency + effective_at
- SOURCE: source + effective_at
- PARTITION: effective_at for time-series queries

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- CURRENCY_REGISTERED
- FX_RATE_RECORDED
- CURRENCY_DEPRECATED
- RATE_SOURCE_CHANGED

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- CREATE TABLE: currency_registry
-- =============================================================================
CREATE TABLE core.currency_registry (
    -- ISO 4217 currency code (primary key)
    currency_code VARCHAR(6) PRIMARY KEY,
    
    -- Currency details
    currency_name VARCHAR(100) NOT NULL,
    currency_symbol VARCHAR(10),
    
    -- Precision configuration
    decimal_places INTEGER DEFAULT 2 CHECK (decimal_places BETWEEN 0 AND 18),
    minor_unit_name VARCHAR(50),  -- e.g., "cents", "paisa", "satoshis"
    
    -- Classification
    currency_type VARCHAR(20) NOT NULL DEFAULT 'FIAT'
        CHECK (currency_type IN ('FIAT', 'CRYPTO', 'TOKEN', 'COMMODITY', 'INTERNAL')),
    
    -- Issuer information
    issuing_country VARCHAR(2),  -- ISO 3166-1 alpha-2
    issuing_authority VARCHAR(100),
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_tradeable BOOLEAN DEFAULT TRUE,
    is_settlement_currency BOOLEAN DEFAULT FALSE,
    
    -- FX configuration
    fx_rate_decimals INTEGER DEFAULT 6,
    requires_fx_approval BOOLEAN DEFAULT FALSE,
    
    -- Compliance
    regulatory_category VARCHAR(50),
    reporting_required BOOLEAN DEFAULT FALSE,
    
    -- Validity period
    valid_from DATE NOT NULL DEFAULT CURRENT_DATE,
    valid_to DATE,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING'
);

-- =============================================================================
-- CREATE TABLE: fx_rates (partitioned for time-series)
-- =============================================================================
CREATE TABLE core.fx_rates (
    -- Primary identifier
    rate_id BIGSERIAL,
    rate_reference VARCHAR(100) UNIQUE NOT NULL,
    
    -- Currency pair
    from_currency VARCHAR(6) NOT NULL REFERENCES core.currency_registry(currency_code),
    to_currency VARCHAR(6) NOT NULL REFERENCES core.currency_registry(currency_code),
    
    -- Rate details
    mid_rate NUMERIC(20, 10) NOT NULL CHECK (mid_rate > 0),
    bid_rate NUMERIC(20, 10) CHECK (bid_rate > 0),
    ask_rate NUMERIC(20, 10) CHECK (ask_rate > 0),
    spread_percentage NUMERIC(10, 6) GENERATED ALWAYS AS (
        CASE 
            WHEN bid_rate IS NOT NULL AND ask_rate IS NOT NULL AND bid_rate > 0 
            THEN ((ask_rate - bid_rate) / bid_rate) * 100
            ELSE NULL
        END
    ) STORED,
    
    -- Inverse rate for efficiency
    inverse_rate NUMERIC(20, 10) GENERATED ALWAYS AS (1 / mid_rate) STORED,
    
    -- Rate source and validity
    rate_source VARCHAR(50) NOT NULL 
        CHECK (rate_source IN ('CENTRAL_BANK', 'MARKET', 'INTERBANK', 'INTERNAL', 'CALCULATED', 'MANUAL')),
    source_reference VARCHAR(255),
    effective_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    
    -- Rate type
    rate_type VARCHAR(20) DEFAULT 'SPOT'
        CHECK (rate_type IN ('SPOT', 'FORWARD', 'FIXING', 'HISTORICAL', 'INTERNAL')),
    
    -- Forward rate specifics
    settlement_date DATE,
    
    -- Metadata
    is_cross_rate BOOLEAN DEFAULT FALSE,
    via_currency VARCHAR(6),  -- For cross-rates (e.g., USD)
    
    -- Usage tracking
    access_count INTEGER DEFAULT 0,
    last_accessed_at TIMESTAMPTZ,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL DEFAULT 'PENDING',
    
    -- Constraints
    CONSTRAINT chk_different_currencies CHECK (from_currency != to_currency),
    CONSTRAINT chk_valid_until CHECK (valid_until IS NULL OR valid_until > effective_at),
    CONSTRAINT chk_settlement_date CHECK (settlement_date IS NULL OR settlement_date >= effective_at::DATE)
) PARTITION BY RANGE (effective_at);

-- Create initial partitions for FX rates
CREATE TABLE core.fx_rates_current 
    PARTITION OF core.fx_rates
    FOR VALUES FROM ('2026-01-01') TO ('2026-07-01');

CREATE TABLE core.fx_rates_2026_h2 
    PARTITION OF core.fx_rates
    FOR VALUES FROM ('2026-07-01') TO ('2027-01-01');

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Currency registry indexes
CREATE INDEX idx_currency_type ON core.currency_registry(currency_type, is_active);
CREATE INDEX idx_currency_country ON core.currency_registry(issuing_country, is_active);
CREATE INDEX idx_currency_active ON core.currency_registry(currency_code) WHERE is_active = TRUE;

-- FX rate indexes
CREATE INDEX idx_fx_rates_pair ON core.fx_rates(from_currency, to_currency, effective_at DESC);
CREATE INDEX idx_fx_rates_current ON core.fx_rates(from_currency, to_currency) 
    WHERE valid_until IS NULL;
CREATE INDEX idx_fx_rates_source ON core.fx_rates(rate_source, effective_at);
CREATE INDEX idx_fx_rates_type ON core.fx_rates(rate_type, effective_at);
CREATE INDEX idx_fx_rates_settlement ON core.fx_rates(settlement_date, from_currency, to_currency) 
    WHERE rate_type = 'FORWARD';

-- =============================================================================
-- IMMUTABILITY TRIGGERS
-- =============================================================================

CREATE TRIGGER trg_currency_registry_prevent_update
    BEFORE UPDATE ON core.currency_registry
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_currency_registry_prevent_delete
    BEFORE DELETE ON core.currency_registry
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

CREATE TRIGGER trg_fx_rates_prevent_update
    BEFORE UPDATE ON core.fx_rates
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

CREATE TRIGGER trg_fx_rates_prevent_delete
    BEFORE DELETE ON core.fx_rates
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- =============================================================================
-- HASH COMPUTATION TRIGGERS
-- =============================================================================

CREATE OR REPLACE FUNCTION core.compute_currency_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.currency_code || 
        NEW.currency_name || 
        NEW.currency_type ||
        NEW.decimal_places::TEXT ||
        NEW.valid_from::TEXT ||
        NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_currency_registry_compute_hash
    BEFORE INSERT ON core.currency_registry
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_currency_hash();

CREATE OR REPLACE FUNCTION core.compute_fx_rate_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.rate_id::TEXT || 
        NEW.rate_reference || 
        NEW.from_currency ||
        NEW.to_currency ||
        NEW.mid_rate::TEXT ||
        NEW.rate_source ||
        NEW.effective_at::TEXT ||
        NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_fx_rates_compute_hash
    BEFORE INSERT ON core.fx_rates
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_fx_rate_hash();

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

ALTER TABLE core.currency_registry ENABLE ROW LEVEL SECURITY;

CREATE POLICY currency_registry_read_all ON core.currency_registry
    FOR SELECT
    TO ussd_app_user
    USING (is_active = TRUE);

CREATE POLICY currency_registry_kernel_access ON core.currency_registry
    FOR ALL
    TO ussd_kernel_role
    USING (true);

ALTER TABLE core.fx_rates ENABLE ROW LEVEL SECURITY;

CREATE POLICY fx_rates_read_all ON core.fx_rates
    FOR SELECT
    TO ussd_app_user
    USING (true);

CREATE POLICY fx_rates_kernel_access ON core.fx_rates
    FOR ALL
    TO ussd_kernel_role
    USING (true);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to register a currency
CREATE OR REPLACE FUNCTION core.register_currency(
    p_currency_code VARCHAR,
    p_currency_name VARCHAR,
    p_symbol VARCHAR DEFAULT NULL,
    p_decimal_places INTEGER DEFAULT 2,
    p_currency_type VARCHAR DEFAULT 'FIAT',
    p_country VARCHAR DEFAULT NULL,
    p_created_by UUID DEFAULT NULL
)
RETURNS VARCHAR
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO core.currency_registry (
        currency_code,
        currency_name,
        currency_symbol,
        decimal_places,
        currency_type,
        issuing_country,
        created_by
    ) VALUES (
        p_currency_code,
        p_currency_name,
        p_symbol,
        p_decimal_places,
        p_currency_type,
        p_country,
        p_created_by
    );
    
    RETURN p_currency_code;
EXCEPTION
    WHEN unique_violation THEN
        RAISE EXCEPTION 'Currency % already exists', p_currency_code;
END;
$$;

-- Function to record FX rate
CREATE OR REPLACE FUNCTION core.record_fx_rate(
    p_from_currency VARCHAR,
    p_to_currency VARCHAR,
    p_mid_rate NUMERIC,
    p_rate_source VARCHAR,
    p_effective_at TIMESTAMPTZ DEFAULT NULL,
    p_bid_rate NUMERIC DEFAULT NULL,
    p_ask_rate NUMERIC DEFAULT NULL,
    p_created_by UUID DEFAULT NULL
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_rate_id BIGINT;
    v_reference VARCHAR(100);
    v_effective TIMESTAMPTZ;
BEGIN
    v_effective := COALESCE(p_effective_at, core.precise_now());
    v_reference := 'FX-' || p_from_currency || '-' || p_to_currency || '-' || 
                   TO_CHAR(v_effective, 'YYYYMMDD-HH24MISS') || '-' || 
                   SUBSTRING(MD5(RANDOM()::TEXT), 1, 4);
    
    INSERT INTO core.fx_rates (
        rate_reference,
        from_currency,
        to_currency,
        mid_rate,
        bid_rate,
        ask_rate,
        rate_source,
        effective_at,
        created_by
    ) VALUES (
        v_reference,
        p_from_currency,
        p_to_currency,
        p_mid_rate,
        p_bid_rate,
        p_ask_rate,
        p_rate_source,
        v_effective,
        p_created_by
    )
    RETURNING rate_id INTO v_rate_id;
    
    RETURN v_rate_id;
END;
$$;

-- Function to get current FX rate
CREATE OR REPLACE FUNCTION core.get_fx_rate(
    p_from_currency VARCHAR,
    p_to_currency VARCHAR,
    p_as_of TIMESTAMPTZ DEFAULT NULL
)
RETURNS TABLE (
    mid_rate NUMERIC,
    bid_rate NUMERIC,
    ask_rate NUMERIC,
    spread_percentage NUMERIC,
    rate_source VARCHAR,
    effective_at TIMESTAMPTZ,
    is_cross_rate BOOLEAN
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_as_of TIMESTAMPTZ;
BEGIN
    v_as_of := COALESCE(p_as_of, core.precise_now());
    
    -- Update access count
    UPDATE core.fx_rates
    SET access_count = access_count + 1,
        last_accessed_at = core.precise_now()
    WHERE from_currency = p_from_currency
      AND to_currency = p_to_currency
      AND effective_at <= v_as_of
      AND (valid_until IS NULL OR valid_until > v_as_of);
    
    -- Return direct rate
    RETURN QUERY
    SELECT 
        fr.mid_rate,
        fr.bid_rate,
        fr.ask_rate,
        fr.spread_percentage,
        fr.rate_source,
        fr.effective_at,
        fr.is_cross_rate
    FROM core.fx_rates fr
    WHERE fr.from_currency = p_from_currency
      AND fr.to_currency = p_to_currency
      AND fr.effective_at <= v_as_of
      AND (fr.valid_until IS NULL OR fr.valid_until > v_as_of)
    ORDER BY fr.effective_at DESC
    LIMIT 1;
    
    -- If no direct rate, try inverse
    IF NOT FOUND THEN
        RETURN QUERY
        SELECT 
            (1 / fr.mid_rate) as mid_rate,
            (1 / fr.ask_rate) as bid_rate,
            (1 / fr.bid_rate) as ask_rate,
            fr.spread_percentage,
            fr.rate_source,
            fr.effective_at,
            TRUE as is_cross_rate
        FROM core.fx_rates fr
        WHERE fr.from_currency = p_to_currency
          AND fr.to_currency = p_from_currency
          AND fr.effective_at <= v_as_of
          AND (fr.valid_until IS NULL OR fr.valid_until > v_as_of)
        ORDER BY fr.effective_at DESC
        LIMIT 1;
    END IF;
END;
$$;

-- Function to convert currency amount
CREATE OR REPLACE FUNCTION core.convert_currency(
    p_amount NUMERIC,
    p_from_currency VARCHAR,
    p_to_currency VARCHAR,
    p_as_of TIMESTAMPTZ DEFAULT NULL,
    p_use_bid_ask BOOLEAN DEFAULT FALSE,
    p_is_buying BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (
    converted_amount NUMERIC,
    rate_used NUMERIC,
    rate_source VARCHAR,
    rate_timestamp TIMESTAMPTZ,
    is_cross_rate BOOLEAN
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_rate RECORD;
    v_final_rate NUMERIC;
BEGIN
    -- Same currency, no conversion needed
    IF p_from_currency = p_to_currency THEN
        RETURN QUERY SELECT p_amount, 1::NUMERIC, 'DIRECT'::VARCHAR, core.precise_now(), FALSE;
        RETURN;
    END IF;
    
    SELECT * INTO v_rate FROM core.get_fx_rate(p_from_currency, p_to_currency, p_as_of);
    
    IF NOT FOUND THEN
        -- Try cross-rate via USD
        RETURN QUERY
        WITH 
        from_usd AS (
            SELECT * FROM core.get_fx_rate(p_from_currency, 'USD', p_as_of)
        ),
        to_usd AS (
            SELECT * FROM core.get_fx_rate(p_to_currency, 'USD', p_as_of)
        )
        SELECT 
            ROUND(p_amount * (to_usd.mid_rate / from_usd.mid_rate), 8),
            (to_usd.mid_rate / from_usd.mid_rate),
            'CROSS_RATE'::VARCHAR,
            GREATEST(from_usd.effective_at, to_usd.effective_at),
            TRUE
        FROM from_usd, to_usd;
        RETURN;
    END IF;
    
    -- Determine which rate to use
    IF p_use_bid_ask THEN
        v_final_rate := CASE 
            WHEN p_is_buying THEN v_rate.ask_rate  -- Buying = we pay more
            ELSE v_rate.bid_rate                   -- Selling = we receive less
        END;
    ELSE
        v_final_rate := v_rate.mid_rate;
    END IF;
    
    RETURN QUERY SELECT 
        ROUND(p_amount * v_final_rate, 8),
        v_final_rate,
        v_rate.rate_source,
        v_rate.effective_at,
        v_rate.is_cross_rate;
END;
$$;

-- Function to calculate cross rate
CREATE OR REPLACE FUNCTION core.calculate_cross_rate(
    p_from_currency VARCHAR,
    p_to_currency VARCHAR,
    p_via_currency VARCHAR DEFAULT 'USD'
)
RETURNS TABLE (
    cross_rate NUMERIC,
    via_currency VARCHAR,
    from_rate NUMERIC,
    to_rate NUMERIC
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_from_rate NUMERIC;
    v_to_rate NUMERIC;
BEGIN
    SELECT mid_rate INTO v_from_rate
    FROM core.get_fx_rate(p_from_currency, p_via_currency);
    
    SELECT mid_rate INTO v_to_rate
    FROM core.get_fx_rate(p_to_currency, p_via_currency);
    
    IF v_from_rate IS NULL OR v_to_rate IS NULL THEN
        RAISE EXCEPTION 'Cannot calculate cross rate: missing rates for % or % via %', 
            p_from_currency, p_to_currency, p_via_currency;
    END IF;
    
    RETURN QUERY SELECT (v_to_rate / v_from_rate), p_via_currency, v_from_rate, v_to_rate;
END;
$$;

-- Function to get FX rate history
CREATE OR REPLACE FUNCTION core.get_fx_rate_history(
    p_from_currency VARCHAR,
    p_to_currency VARCHAR,
    p_start_date DATE,
    p_end_date DATE
)
RETURNS TABLE (
    rate_date DATE,
    open_rate NUMERIC,
    high_rate NUMERIC,
    low_rate NUMERIC,
    close_rate NUMERIC,
    avg_rate NUMERIC,
    rate_count BIGINT
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        fr.effective_at::DATE as rate_date,
        (ARRAY_AGG(fr.mid_rate ORDER BY fr.effective_at ASC))[1] as open_rate,
        MAX(fr.mid_rate) as high_rate,
        MIN(fr.mid_rate) as low_rate,
        (ARRAY_AGG(fr.mid_rate ORDER BY fr.effective_at DESC))[1] as close_rate,
        AVG(fr.mid_rate)::NUMERIC as avg_rate,
        COUNT(*) as rate_count
    FROM core.fx_rates fr
    WHERE fr.from_currency = p_from_currency
      AND fr.to_currency = p_to_currency
      AND fr.effective_at::DATE BETWEEN p_start_date AND p_end_date
    GROUP BY fr.effective_at::DATE
    ORDER BY rate_date;
END;
$$;

-- =============================================================================
-- INITIAL DATA: Standard currencies
-- =============================================================================

INSERT INTO core.currency_registry (
    currency_code, currency_name, currency_symbol, decimal_places, 
    currency_type, issuing_country, is_settlement_currency
) VALUES 
('USD', 'United States Dollar', '$', 2, 'FIAT', 'US', TRUE),
('EUR', 'Euro', '€', 2, 'FIAT', 'EU', TRUE),
('GBP', 'British Pound Sterling', '£', 2, 'FIAT', 'GB', TRUE),
('JPY', 'Japanese Yen', '¥', 0, 'FIAT', 'JP', FALSE),
('ZAR', 'South African Rand', 'R', 2, 'FIAT', 'ZA', FALSE),
('NGN', 'Nigerian Naira', '₦', 2, 'FIAT', 'NG', FALSE),
('KES', 'Kenyan Shilling', 'KSh', 2, 'FIAT', 'KE', FALSE),
('GHS', 'Ghanaian Cedi', 'GH₵', 2, 'FIAT', 'GH', FALSE),
('TZS', 'Tanzanian Shilling', 'TSh', 2, 'FIAT', 'TZ', FALSE),
('UGX', 'Ugandan Shilling', 'USh', 0, 'FIAT', 'UG', FALSE),
('ZMW', 'Zambian Kwacha', 'K', 2, 'FIAT', 'ZM', FALSE),
('BWP', 'Botswana Pula', 'P', 2, 'FIAT', 'BW', FALSE),
('MZN', 'Mozambican Metical', 'MT', 2, 'FIAT', 'MZ', FALSE),
('ZWL', 'Zimbabwean Dollar', 'Z$', 2, 'FIAT', 'ZW', FALSE),
('XOF', 'West African CFA Franc', 'CFA', 0, 'FIAT', NULL, FALSE),
('XAF', 'Central African CFA Franc', 'CFA', 0, 'FIAT', NULL, FALSE),
('BTC', 'Bitcoin', '₿', 8, 'CRYPTO', NULL, FALSE),
('ETH', 'Ethereum', 'Ξ', 18, 'CRYPTO', NULL, FALSE),
('USDT', 'Tether', '₮', 6, 'TOKEN', NULL, FALSE),
('USDC', 'USD Coin', 'USDC', 6, 'TOKEN', NULL, FALSE)
ON CONFLICT (currency_code) DO NOTHING;

-- Insert sample FX rates (placeholders for initialization)
INSERT INTO core.fx_rates (
    rate_reference, from_currency, to_currency, mid_rate, 
    bid_rate, ask_rate, rate_source, effective_at
) VALUES 
('FX-INIT-USD-EUR-001', 'USD', 'EUR', 0.8500000000, 0.8495000000, 0.8505000000, 'INIT', '2026-01-01'),
('FX-INIT-EUR-USD-001', 'EUR', 'USD', 1.1764705882, 1.1758000000, 1.1771000000, 'INIT', '2026-01-01'),
('FX-INIT-USD-ZAR-001', 'USD', 'ZAR', 18.5000000000, 18.4500000000, 18.5500000000, 'INIT', '2026-01-01'),
('FX-INIT-USD-NGN-001', 'USD', 'NGN', 1500.0000000000, 1495.0000000000, 1505.0000000000, 'INIT', '2026-01-01'),
('FX-INIT-USD-KES-001', 'USD', 'KES', 130.0000000000, 129.5000000000, 130.5000000000, 'INIT', '2026-01-01'),
('FX-INIT-USD-GHS-001', 'USD', 'GHS', 15.0000000000, 14.9500000000, 15.0500000000, 'INIT', '2026-01-01')
ON CONFLICT (rate_reference) DO NOTHING;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE core.currency_registry IS 'Registry of all supported currencies with ISO 4217 compliance';
COMMENT ON TABLE core.fx_rates IS 'Immutable FX rate history with bid/ask/mid rates';
COMMENT ON FUNCTION core.get_fx_rate IS 'Get the most recent FX rate for a currency pair';
COMMENT ON FUNCTION core.convert_currency IS 'Convert amount between currencies with optional bid/ask spread';

-- =============================================================================
-- END OF FILE
-- =============================================================================
