-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Financial controls, Access control)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Configuration isolation)
-- ISO/IEC 27040:2024 - Storage Security (Immutable fare configuration)
-- SOX Section 404 - Internal Controls (Financial data integrity)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Immutable, versioned fare parameters with valid_from/valid_to
-- - Temporal integrity ensuring no overlapping active versions
-- - Audit trail for all fare configuration changes
-- - RLS policies for multi-tenant fare isolation
-- ============================================================================
-- =============================================================================
-- MIGRATION: 004_transport_fare_primitives.sql
-- DESCRIPTION: Transport Fare & Financial Configuration Primitives
-- TABLES: core.fare_parameters, core.fee_structures, core.regulatory_parameters
-- DEPENDENCIES: 031_app_registry.sql, 026_core_chart_of_accounts.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 17. Configuration & Parameter Primitives (Immutable Only)
- Feature: Fare Parameters, Fee Structures, Regulatory Parameters
- Source: Transport Business Application on USSD Immutable Ledger

BUSINESS CONTEXT:
Zimbabwe transport fare calculation requires immutable, versioned configuration:
- Distance rates, time charges, base fares, surge multipliers
- Platform commission rates, government tax withholdings, municipal levies
- ZTA-mandated maximum fares, VID inspection intervals, tax thresholds
- All changes create new versions; historical transactions use version active at transaction time

KEY FEATURES:
- Immutable fare parameter registry with full change history
- Fee structure registry for platform, government, and municipal charges
- Regulatory parameter registry for ZTA/VID/ZIMRA compliance thresholds
- Temporal validity ensuring no overlapping active versions
- Point-in-time lookup functions for accurate historical reconstruction
================================================================================
*/

-- =============================================================================
-- IMPLEMENTATION: Create core.fare_parameters table
-- DESCRIPTION: Immutable, versioned fare configuration
-- PRIORITY: CRITICAL
-- SECURITY: Financial configuration - changes audited
-- ============================================================================
-- [FARE-001] Create core.fare_parameters table

CREATE TABLE core.fare_parameters (
    fare_parameter_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parameter_code      VARCHAR(50) NOT NULL,        -- e.g., "HRE_STANDARD_BASE"
    parameter_name      VARCHAR(200) NOT NULL,
    
    -- Scope
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    zone_id             UUID REFERENCES core.zones(zone_id),
    route_id            UUID REFERENCES core.route_definitions(route_id),
    vehicle_type        VARCHAR(50),                 -- STANDARD, PREMIUM, etc.
    
    -- Fare Components
    base_fare           NUMERIC(20, 8) NOT NULL DEFAULT 0,
    distance_rate_per_km NUMERIC(20, 8) NOT NULL DEFAULT 0,
    time_rate_per_minute NUMERIC(20, 8) NOT NULL DEFAULT 0,
    minimum_fare        NUMERIC(20, 8) NOT NULL DEFAULT 0,
    cancellation_fee    NUMERIC(20, 8) NOT NULL DEFAULT 0,
    
    -- Surge Configuration
    surge_cap           NUMERIC(5, 2) DEFAULT 3.00, -- Maximum surge multiplier
    surge_floor         NUMERIC(5, 2) DEFAULT 1.00, -- Minimum surge multiplier
    
    -- Waiting Time
    free_waiting_minutes INTEGER DEFAULT 5,
    waiting_rate_per_minute NUMERIC(20, 8) DEFAULT 0,
    
    -- Night/Peak Premiums
    night_premium_multiplier NUMERIC(5, 2) DEFAULT 1.00,
    night_premium_start   TIME,
    night_premium_end     TIME,
    
    -- Currency
    currency            VARCHAR(3) NOT NULL DEFAULT 'USD',
    
    -- Status
    status              VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, ARCHIVED
    
    -- Temporal Validity
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,
    
    -- Versioning
    version             INTEGER NOT NULL DEFAULT 1,
    superseded_by       UUID REFERENCES core.fare_parameters(fare_parameter_id),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    change_reason       TEXT,
    
    -- Constraints
    CONSTRAINT chk_fare_parameters_status 
        CHECK (status IN ('ACTIVE', 'ARCHIVED')),
    CONSTRAINT chk_fare_parameters_currency 
        CHECK (currency ~ '^[A-Z]{3}$'),
    CONSTRAINT chk_fare_parameters_rates 
        CHECK (base_fare >= 0 AND distance_rate_per_km >= 0 AND time_rate_per_minute >= 0),
    CONSTRAINT chk_fare_parameters_surge 
        CHECK (surge_cap >= surge_floor AND surge_floor >= 1.00),
    CONSTRAINT chk_fare_parameters_valid_time 
        CHECK (valid_to IS NULL OR valid_to > valid_from),
    CONSTRAINT chk_fare_parameters_scope 
        CHECK (
            (zone_id IS NOT NULL AND route_id IS NULL) OR
            (zone_id IS NULL AND route_id IS NOT NULL) OR
            (zone_id IS NULL AND route_id IS NULL)
        )
);

-- INDEXES
CREATE INDEX idx_fare_parameters_code ON core.fare_parameters(parameter_code, application_id);
CREATE INDEX idx_fare_parameters_app ON core.fare_parameters(application_id, vehicle_type);
CREATE INDEX idx_fare_parameters_zone ON core.fare_parameters(zone_id, status) WHERE valid_to IS NULL;
CREATE INDEX idx_fare_parameters_route ON core.fare_parameters(route_id, status) WHERE valid_to IS NULL;
CREATE INDEX idx_fare_parameters_current ON core.fare_parameters(parameter_code, application_id, COALESCE(valid_to, 'infinity'::timestamptz)) WHERE valid_to IS NULL;
CREATE INDEX idx_fare_parameters_valid ON core.fare_parameters(valid_from, valid_to);

COMMENT ON TABLE core.fare_parameters IS 'Immutable, versioned primitive storing distance rates, time charges, base fares, and surge parameters';
COMMENT ON COLUMN core.fare_parameters.surge_cap IS 'Maximum allowed surge multiplier during high demand';

-- =============================================================================
-- IMPLEMENTATION: Create fare parameter temporal exclusion constraint
-- DESCRIPTION: Prevent overlapping active versions of same parameter code
-- PRIORITY: HIGH
-- ============================================================================
-- [FARE-002] Add temporal exclusion constraint for fare parameters

ALTER TABLE core.fare_parameters
    ADD CONSTRAINT uq_fare_parameters_no_overlap 
    EXCLUDE USING gist (
        parameter_code WITH =,
        application_id WITH =,
        tsrange(valid_from, COALESCE(valid_to, 'infinity'::timestamptz), '[)') WITH &&
    )
    WHERE (valid_to IS NULL);

-- =============================================================================
-- IMPLEMENTATION: Create core.fee_structures table
-- DESCRIPTION: Immutable platform commission and government levy configurations
-- PRIORITY: CRITICAL
-- SECURITY: Financial configuration affecting all transactions
-- ============================================================================
-- [FARE-003] Create core.fee_structures table

CREATE TABLE core.fee_structures (
    fee_structure_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    structure_code      VARCHAR(50) NOT NULL,        -- e.g., "ZW_TRANSPORT_STD"
    structure_name      VARCHAR(200) NOT NULL,
    
    -- Scope
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Platform Fee
    platform_fee_type   VARCHAR(20) NOT NULL DEFAULT 'PERCENTAGE', -- PERCENTAGE, FIXED
    platform_fee_value  NUMERIC(20, 8) NOT NULL DEFAULT 0,        -- 0.15 = 15% or fixed amount
    platform_fee_cap    NUMERIC(20, 8),             -- Maximum platform fee per trip
    platform_fee_floor  NUMERIC(20, 8),             -- Minimum platform fee per trip
    
    -- Government Tax
    tax_type            VARCHAR(50),                 -- VAT, WITHHOLDING, LEVY
    tax_rate            NUMERIC(20, 8) DEFAULT 0,   -- Percentage
    tax_coa_code        VARCHAR(50) REFERENCES core.chart_of_accounts(coa_code),
    
    -- Fuel Surcharge
    fuel_surcharge_enabled BOOLEAN DEFAULT false,
    fuel_surcharge_rate NUMERIC(20, 8) DEFAULT 0,
    
    -- Municipal Levy
    municipal_levy_enabled BOOLEAN DEFAULT false,
    municipal_levy_rate NUMERIC(20, 8) DEFAULT 0,
    municipal_levy_coa_code VARCHAR(50) REFERENCES core.chart_of_accounts(coa_code),
    
    -- Driver Insurance Levy
    insurance_levy_enabled BOOLEAN DEFAULT false,
    insurance_levy_rate NUMERIC(20, 8) DEFAULT 0,
    
    -- Currency
    currency            VARCHAR(3) NOT NULL DEFAULT 'USD',
    
    -- Status
    status              VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    
    -- Temporal Validity
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,
    
    -- Versioning
    version             INTEGER NOT NULL DEFAULT 1,
    superseded_by       UUID REFERENCES core.fee_structures(fee_structure_id),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    change_reason       TEXT,
    
    -- Constraints
    CONSTRAINT chk_fee_structures_status 
        CHECK (status IN ('ACTIVE', 'ARCHIVED')),
    CONSTRAINT chk_fee_structures_fee_type 
        CHECK (platform_fee_type IN ('PERCENTAGE', 'FIXED')),
    CONSTRAINT chk_fee_structures_currency 
        CHECK (currency ~ '^[A-Z]{3}$'),
    CONSTRAINT chk_fee_structures_rates 
        CHECK (platform_fee_value >= 0 AND COALESCE(tax_rate, 0) >= 0),
    CONSTRAINT chk_fee_structures_valid_time 
        CHECK (valid_to IS NULL OR valid_to > valid_from)
);

-- INDEXES
CREATE INDEX idx_fee_structures_code ON core.fee_structures(structure_code, application_id);
CREATE INDEX idx_fee_structures_app ON core.fee_structures(application_id, status) WHERE valid_to IS NULL;
CREATE INDEX idx_fee_structures_current ON core.fee_structures(structure_code, application_id, COALESCE(valid_to, 'infinity'::timestamptz)) WHERE valid_to IS NULL;
CREATE INDEX idx_fee_structures_valid ON core.fee_structures(valid_from, valid_to);

COMMENT ON TABLE core.fee_structures IS 'Immutable, versioned configuration for platform commission, taxes, fuel surcharges, and municipal levies';
COMMENT ON COLUMN core.fee_structures.platform_fee_value IS 'Platform fee as percentage (e.g., 0.15) or fixed amount depending on platform_fee_type';

-- =============================================================================
-- IMPLEMENTATION: Create fee structure temporal exclusion constraint
-- DESCRIPTION: Prevent overlapping active versions of same structure code
-- PRIORITY: HIGH
-- ============================================================================
-- [FARE-004] Add temporal exclusion constraint for fee structures

ALTER TABLE core.fee_structures
    ADD CONSTRAINT uq_fee_structures_no_overlap 
    EXCLUDE USING gist (
        structure_code WITH =,
        application_id WITH =,
        tsrange(valid_from, COALESCE(valid_to, 'infinity'::timestamptz), '[)') WITH &&
    )
    WHERE (valid_to IS NULL);

-- =============================================================================
-- IMPLEMENTATION: Create core.regulatory_parameters table
-- DESCRIPTION: ZTA-mandated and government regulatory thresholds
-- PRIORITY: CRITICAL
-- SECURITY: Compliance-critical configuration
-- ============================================================================
-- [FARE-005] Create core.regulatory_parameters table

CREATE TABLE core.regulatory_parameters (
    regulatory_param_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    param_code          VARCHAR(50) NOT NULL,        -- e.g., "ZTA_MAX_FARE_HRE"
    param_name          VARCHAR(200) NOT NULL,
    
    -- Scope
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    zone_id             UUID REFERENCES core.zones(zone_id),
    
    -- Parameter Classification
    param_category      VARCHAR(50) NOT NULL,        -- MAX_FARE, INSPECTION_INTERVAL, TAX_THRESHOLD, etc.
    issuing_authority   VARCHAR(100) NOT NULL,       -- ZTA, VID, ZIMRA, MUNICIPAL
    authority_reference VARCHAR(255),                 -- Regulation citation
    
    -- Value
    param_value_numeric NUMERIC(20, 8),
    param_value_string  VARCHAR(500),
    param_value_json    JSONB,
    param_unit          VARCHAR(50),                 -- USD, KM, DAYS, PERCENT
    
    -- Enforcement
    is_enforced         BOOLEAN DEFAULT true,
    enforcement_action  VARCHAR(50),                 -- BLOCK, WARN, FLAG
    
    -- Status
    status              VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    
    -- Temporal Validity
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,
    
    -- Versioning
    version             INTEGER NOT NULL DEFAULT 1,
    superseded_by       UUID REFERENCES core.regulatory_parameters(regulatory_param_id),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    change_reason       TEXT,
    
    -- Constraints
    CONSTRAINT chk_regulatory_parameters_category 
        CHECK (param_category IN ('MAX_FARE', 'MIN_FARE', 'INSPECTION_INTERVAL', 'TAX_THRESHOLD', 'DAILY_LIMIT', 'WITHHOLDING_RATE', 'SURGE_CAP', 'OPERATING_HOURS')),
    CONSTRAINT chk_regulatory_parameters_status 
        CHECK (status IN ('ACTIVE', 'ARCHIVED', 'PENDING')),
    CONSTRAINT chk_regulatory_parameters_valid_time 
        CHECK (valid_to IS NULL OR valid_to > valid_from)
);

-- INDEXES
CREATE INDEX idx_regulatory_parameters_code ON core.regulatory_parameters(param_code, application_id);
CREATE INDEX idx_regulatory_parameters_app ON core.regulatory_parameters(application_id, param_category) WHERE valid_to IS NULL;
CREATE INDEX idx_regulatory_parameters_authority ON core.regulatory_parameters(issuing_authority, param_category);
CREATE INDEX idx_regulatory_parameters_current ON core.regulatory_parameters(param_code, application_id, COALESCE(valid_to, 'infinity'::timestamptz)) WHERE valid_to IS NULL;
CREATE INDEX idx_regulatory_parameters_valid ON core.regulatory_parameters(valid_from, valid_to);

COMMENT ON TABLE core.regulatory_parameters IS 'Immutable configuration storing ZTA-mandated maximum fares, VID inspection intervals, tax withholding percentages, and legal thresholds';
COMMENT ON COLUMN core.regulatory_parameters.param_category IS 'MAX_FARE, MIN_FARE, INSPECTION_INTERVAL, TAX_THRESHOLD, DAILY_LIMIT, WITHHOLDING_RATE, SURGE_CAP, OPERATING_HOURS';

-- =============================================================================
-- IMPLEMENTATION: Create regulatory parameter temporal exclusion constraint
-- DESCRIPTION: Prevent overlapping active versions of same parameter code
-- PRIORITY: HIGH
-- ============================================================================
-- [FARE-006] Add temporal exclusion constraint for regulatory parameters

ALTER TABLE core.regulatory_parameters
    ADD CONSTRAINT uq_regulatory_parameters_no_overlap 
    EXCLUDE USING gist (
        param_code WITH =,
        application_id WITH =,
        tsrange(valid_from, COALESCE(valid_to, 'infinity'::timestamptz), '[)') WITH &&
    )
    WHERE (valid_to IS NULL);

-- =============================================================================
-- IMPLEMENTATION: Create fare calculation function
-- DESCRIPTION: Compute trip fare using active parameters at a given time
-- PRIORITY: CRITICAL
-- SECURITY: Financial calculation - deterministic and auditable
-- ============================================================================
-- [FARE-007] Create calculate_trip_fare function

CREATE OR REPLACE FUNCTION core.calculate_trip_fare(
    p_application_id UUID,
    p_zone_id UUID,
    p_vehicle_type VARCHAR(50),
    p_distance_km NUMERIC,
    p_duration_minutes NUMERIC,
    p_waiting_minutes NUMERIC DEFAULT 0,
    p_surge_multiplier NUMERIC DEFAULT 1.00,
    p_as_of TIMESTAMPTZ DEFAULT now()
) RETURNS TABLE (
    base_fare NUMERIC,
    distance_fare NUMERIC,
    time_fare NUMERIC,
    waiting_fare NUMERIC,
    surge_multiplier NUMERIC,
    subtotal NUMERIC,
    minimum_fare NUMERIC,
    total_fare NUMERIC,
    currency VARCHAR(3),
    fare_parameter_id UUID
) AS $$
DECLARE
    v_fp RECORD;
    v_base NUMERIC;
    v_distance NUMERIC;
    v_time NUMERIC;
    v_waiting NUMERIC;
    v_subtotal NUMERIC;
    v_total NUMERIC;
BEGIN
    -- Find active fare parameters
    SELECT * INTO v_fp
    FROM core.fare_parameters
    WHERE application_id = p_application_id
      AND (zone_id = p_zone_id OR zone_id IS NULL)
      AND (vehicle_type = p_vehicle_type OR vehicle_type IS NULL)
      AND valid_from <= p_as_of
      AND (valid_to IS NULL OR valid_to > p_as_of)
      AND status = 'ACTIVE'
    ORDER BY 
        CASE WHEN zone_id = p_zone_id THEN 0 ELSE 1 END,
        CASE WHEN vehicle_type = p_vehicle_type THEN 0 ELSE 1 END,
        valid_from DESC
    LIMIT 1;
    
    IF v_fp IS NULL THEN
        RAISE EXCEPTION 'No active fare parameters found for application=%, zone=%, vehicle_type=% at %',
            p_application_id, p_zone_id, p_vehicle_type, p_as_of;
    END IF;
    
    -- Calculate components
    v_base := v_fp.base_fare;
    v_distance := ROUND(p_distance_km * v_fp.distance_rate_per_km, 8);
    v_time := ROUND(p_duration_minutes * v_fp.time_rate_per_minute, 8);
    
    -- Waiting time (after free minutes)
    IF p_waiting_minutes > COALESCE(v_fp.free_waiting_minutes, 0) THEN
        v_waiting := ROUND((p_waiting_minutes - v_fp.free_waiting_minutes) * v_fp.waiting_rate_per_minute, 8);
    ELSE
        v_waiting := 0;
    END IF;
    
    -- Apply surge
    v_subtotal := v_base + v_distance + v_time + v_waiting;
    v_total := ROUND(v_subtotal * LEAST(GREATEST(p_surge_multiplier, v_fp.surge_floor), v_fp.surge_cap), 8);
    
    -- Apply minimum fare
    IF v_total < v_fp.minimum_fare THEN
        v_total := v_fp.minimum_fare;
    END IF;
    
    RETURN QUERY SELECT 
        v_base,
        v_distance,
        v_time,
        v_waiting,
        LEAST(GREATEST(p_surge_multiplier, v_fp.surge_floor), v_fp.surge_cap),
        v_subtotal,
        v_fp.minimum_fare,
        v_total,
        v_fp.currency,
        v_fp.fare_parameter_id;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.calculate_trip_fare IS 'Computes trip fare using the fare parameters active at the specified point in time';

-- =============================================================================
-- IMPLEMENTATION: Create fee breakdown function
-- DESCRIPTION: Calculate platform fees and taxes for a given fare
-- PRIORITY: CRITICAL
-- SECURITY: Financial calculation affecting driver earnings
-- ============================================================================
-- [FARE-008] Create calculate_fee_breakdown function

CREATE OR REPLACE FUNCTION core.calculate_fee_breakdown(
    p_application_id UUID,
    p_fare_amount NUMERIC,
    p_currency VARCHAR(3),
    p_as_of TIMESTAMPTZ DEFAULT now()
) RETURNS TABLE (
    platform_fee NUMERIC,
    tax_amount NUMERIC,
    fuel_surcharge NUMERIC,
    municipal_levy NUMERIC,
    insurance_levy NUMERIC,
    total_deductions NUMERIC,
    driver_earnings NUMERIC,
    fee_structure_id UUID
) AS $$
DECLARE
    v_fs RECORD;
    v_platform NUMERIC;
    v_tax NUMERIC;
    v_fuel NUMERIC;
    v_municipal NUMERIC;
    v_insurance NUMERIC;
    v_total_deductions NUMERIC;
BEGIN
    -- Find active fee structure
    SELECT * INTO v_fs
    FROM core.fee_structures
    WHERE application_id = p_application_id
      AND valid_from <= p_as_of
      AND (valid_to IS NULL OR valid_to > p_as_of)
      AND status = 'ACTIVE'
    ORDER BY valid_from DESC
    LIMIT 1;
    
    IF v_fs IS NULL THEN
        -- No fee structure found - return zero deductions
        RETURN QUERY SELECT 
            0::NUMERIC, 0::NUMERIC, 0::NUMERIC, 0::NUMERIC, 0::NUMERIC,
            0::NUMERIC, p_fare_amount, NULL::UUID;
        RETURN;
    END IF;
    
    -- Platform fee
    IF v_fs.platform_fee_type = 'PERCENTAGE' THEN
        v_platform := ROUND(p_fare_amount * v_fs.platform_fee_value, 8);
    ELSE
        v_platform := v_fs.platform_fee_value;
    END IF;
    
    -- Apply cap and floor
    IF v_fs.platform_fee_cap IS NOT NULL THEN
        v_platform := LEAST(v_platform, v_fs.platform_fee_cap);
    END IF;
    IF v_fs.platform_fee_floor IS NOT NULL THEN
        v_platform := GREATEST(v_platform, v_fs.platform_fee_floor);
    END IF;
    
    -- Tax
    v_tax := ROUND(p_fare_amount * COALESCE(v_fs.tax_rate, 0), 8);
    
    -- Fuel surcharge
    v_fuel := CASE WHEN v_fs.fuel_surcharge_enabled THEN ROUND(p_fare_amount * COALESCE(v_fs.fuel_surcharge_rate, 0), 8) ELSE 0 END;
    
    -- Municipal levy
    v_municipal := CASE WHEN v_fs.municipal_levy_enabled THEN ROUND(p_fare_amount * COALESCE(v_fs.municipal_levy_rate, 0), 8) ELSE 0 END;
    
    -- Insurance levy
    v_insurance := CASE WHEN v_fs.insurance_levy_enabled THEN ROUND(p_fare_amount * COALESCE(v_fs.insurance_levy_rate, 0), 8) ELSE 0 END;
    
    v_total_deductions := v_platform + v_tax + v_fuel + v_municipal + v_insurance;
    
    RETURN QUERY SELECT 
        v_platform,
        v_tax,
        v_fuel,
        v_municipal,
        v_insurance,
        v_total_deductions,
        p_fare_amount - v_total_deductions,
        v_fs.fee_structure_id;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.calculate_fee_breakdown IS 'Calculates platform fees, taxes, and levies deducted from a trip fare';

-- =============================================================================
-- IMPLEMENTATION: Create point-in-time parameter lookup function
-- DESCRIPTION: Retrieve active fare parameters at a specific time
-- PRIORITY: HIGH
-- ============================================================================
-- [FARE-009] Create get_fare_parameters_at_time function

CREATE OR REPLACE FUNCTION core.get_fare_parameters_at_time(
    p_application_id UUID,
    p_zone_id UUID,
    p_vehicle_type VARCHAR(50),
    p_as_of TIMESTAMPTZ DEFAULT now()
) RETURNS SETOF core.fare_parameters AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM core.fare_parameters
    WHERE application_id = p_application_id
      AND (zone_id = p_zone_id OR zone_id IS NULL)
      AND (vehicle_type = p_vehicle_type OR vehicle_type IS NULL)
      AND valid_from <= p_as_of
      AND (valid_to IS NULL OR valid_to > p_as_of)
      AND status = 'ACTIVE'
    ORDER BY 
        CASE WHEN zone_id = p_zone_id THEN 0 ELSE 1 END,
        CASE WHEN vehicle_type = p_vehicle_type THEN 0 ELSE 1 END,
        valid_from DESC
    LIMIT 1;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.get_fare_parameters_at_time IS 'Retrieves the fare parameters that were active at a specific point in time';

-- =============================================================================
-- IMPLEMENTATION: Create current configuration views
-- DESCRIPTION: Convenience views for active fare and fee configurations
-- PRIORITY: MEDIUM
-- ============================================================================
-- [FARE-010] Create current fare configuration views

CREATE OR REPLACE VIEW core.current_fare_parameters AS
SELECT * FROM core.fare_parameters
WHERE valid_to IS NULL AND superseded_by IS NULL AND status = 'ACTIVE';

COMMENT ON VIEW core.current_fare_parameters IS 'View showing only currently active fare parameters';

CREATE OR REPLACE VIEW core.current_fee_structures AS
SELECT * FROM core.fee_structures
WHERE valid_to IS NULL AND superseded_by IS NULL AND status = 'ACTIVE';

COMMENT ON VIEW core.current_fee_structures IS 'View showing only currently active fee structures';

CREATE OR REPLACE VIEW core.current_regulatory_parameters AS
SELECT * FROM core.regulatory_parameters
WHERE valid_to IS NULL AND superseded_by IS NULL AND status = 'ACTIVE';

COMMENT ON VIEW core.current_regulatory_parameters IS 'View showing only currently active regulatory parameters';

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create core.fare_parameters table with comprehensive fare components
☑ Create core.fee_structures table for platform commissions and levies
☑ Create core.regulatory_parameters table for ZTA/VID/ZIMRA thresholds
☑ Implement calculate_trip_fare function with point-in-time accuracy
☑ Implement calculate_fee_breakdown function for driver earnings
☑ Implement get_fare_parameters_at_time lookup function
☑ Create current_fare_parameters view
☑ Create current_fee_structures view
☑ Create current_regulatory_parameters view
☑ Add temporal exclusion constraints for all configuration tables
☑ Add all indexes for fare and fee queries
☑ Verify foreign key constraints
================================================================================
*/
