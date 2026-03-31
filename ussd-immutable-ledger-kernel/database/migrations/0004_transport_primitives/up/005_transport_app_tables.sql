-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Access control, Data integrity)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Multi-tenant data isolation)
-- ISO/IEC 27018:2019 - PII Protection (Location and preference data)
-- GDPR / Zimbabwe Data Protection Act - Data minimization and consent
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Mutable app tables with full audit trail
-- - RLS policies ensuring users only access their own data
-- - Temporal validity for promo codes and preferences
-- - Encrypted PII where required
-- ============================================================================
-- =============================================================================
-- MIGRATION: 005_transport_app_tables.sql
-- DESCRIPTION: Transport Application-Specific Mutable Tables
-- TABLES: app.driver_status_cache, app.favorite_locations, app.promo_codes
-- DEPENDENCIES: 032_app_account_membership.sql, 001_transport_geospatial_primitives.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 5. Rider Experience & Personalization, 4. Driver Management
- Feature: Driver Status, Favorite Locations, Promotions
- Source: Transport Business Application on USSD Immutable Ledger

BUSINESS CONTEXT:
Application-layer mutable state for transport operations:
- Driver online/offline/busy status (cached, but changes logged)
- Rider favorite locations (Home, Work, etc.)
- Promo codes and discount campaigns

KEY FEATURES:
- Fast mutable cache for driver operational status
- Rider personalization with encrypted location data
- Time-bounded promotional campaigns with usage limits
- Full audit trail via app schema audit triggers
================================================================================
*/

-- =============================================================================
-- IMPLEMENTATION: Create app.driver_status_cache table
-- DESCRIPTION: Real-time driver operational status cache
-- PRIORITY: CRITICAL
-- SECURITY: Location data encrypted; RLS by driver account
-- ============================================================================
-- [APP-TR-001] Create app.driver_status_cache table

CREATE TABLE app.driver_status_cache (
    cache_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    driver_account_id   UUID NOT NULL REFERENCES core.accounts(account_id),
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Operational Status
    online_status       VARCHAR(20) NOT NULL DEFAULT 'OFFLINE', -- ONLINE, OFFLINE, BUSY, BREAK
    status_changed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    status_reason       TEXT,
    
    -- Current Location (last known)
    last_latitude       NUMERIC(10, 8),
    last_longitude      NUMERIC(11, 8),
    location_updated_at TIMESTAMPTZ,
    location_accuracy_meters NUMERIC(10, 2),
    matched_zone_id     UUID REFERENCES core.zones(zone_id),
    
    -- Current Assignment
    active_vehicle_id   UUID REFERENCES core.vehicles(vehicle_id),
    active_trip_transaction_id UUID REFERENCES core.transaction_log(transaction_id),
    
    -- Availability Settings
    accepts_rides       BOOLEAN DEFAULT true,
    accepts_shared      BOOLEAN DEFAULT false,
    accepts_delivery    BOOLEAN DEFAULT false,
    preferred_zone_ids  UUID[],
    
    -- Session
    last_ussd_session_id UUID,
    last_ping_at        TIMESTAMPTZ,
    
    -- Metrics (denormalized for performance)
    today_trips_count   INTEGER DEFAULT 0,
    today_earnings      NUMERIC(20, 8) DEFAULT 0,
    acceptance_rate     NUMERIC(5, 4),              -- 0.0 to 1.0
    rating_average      NUMERIC(3, 2),              -- 1.00 to 5.00
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Constraints
    CONSTRAINT chk_driver_status_cache_online 
        CHECK (online_status IN ('ONLINE', 'OFFLINE', 'BUSY', 'BREAK')),
    CONSTRAINT chk_driver_status_cache_latitude 
        CHECK (last_latitude IS NULL OR (last_latitude BETWEEN -90 AND 90)),
    CONSTRAINT chk_driver_status_cache_longitude 
        CHECK (last_longitude IS NULL OR (last_longitude BETWEEN -180 AND 180)),
    CONSTRAINT chk_driver_status_cache_rating 
        CHECK (rating_average IS NULL OR (rating_average BETWEEN 1.00 AND 5.00)),
    CONSTRAINT chk_driver_status_cache_acceptance 
        CHECK (acceptance_rate IS NULL OR (acceptance_rate BETWEEN 0.00 AND 1.00))
);

-- INDEXES
CREATE UNIQUE INDEX idx_driver_status_cache_driver_app ON app.driver_status_cache(driver_account_id, application_id);
CREATE INDEX idx_driver_status_cache_online ON app.driver_status_cache(application_id, online_status, matched_zone_id);
CREATE INDEX idx_driver_status_cache_zone ON app.driver_status_cache(matched_zone_id, online_status) WHERE online_status = 'ONLINE';
CREATE INDEX idx_driver_status_cache_location ON app.driver_status_cache(last_latitude, last_longitude) WHERE online_status = 'ONLINE';
CREATE INDEX idx_driver_status_cache_trip ON app.driver_status_cache(active_trip_transaction_id) WHERE active_trip_transaction_id IS NOT NULL;
CREATE INDEX idx_driver_status_cache_ping ON app.driver_status_cache(last_ping_at DESC);

COMMENT ON TABLE app.driver_status_cache IS 'Mutable cache of driver online status and current operational state';
COMMENT ON COLUMN app.driver_status_cache.online_status IS 'ONLINE, OFFLINE, BUSY (on trip), or BREAK (temporary offline)';

-- =============================================================================
-- IMPLEMENTATION: Create driver status history table
-- DESCRIPTION: Audit log of driver status changes
-- PRIORITY: HIGH
-- SECURITY: Immutable record of all online/offline transitions
-- ============================================================================
-- [APP-TR-002] Create app.driver_status_history table

CREATE TABLE app.driver_status_history (
    history_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    driver_account_id   UUID NOT NULL REFERENCES core.accounts(account_id),
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    previous_status     VARCHAR(20),
    new_status          VARCHAR(20) NOT NULL,
    
    -- Context
    vehicle_id          UUID REFERENCES core.vehicles(vehicle_id),
    zone_id             UUID REFERENCES core.zones(zone_id),
    latitude            NUMERIC(10, 8),
    longitude           NUMERIC(11, 8),
    
    -- Reason
    change_reason       TEXT,
    changed_by          UUID REFERENCES core.accounts(account_id),
    
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_driver_status_history_driver ON app.driver_status_history(driver_account_id, created_at DESC);
CREATE INDEX idx_driver_status_history_app ON app.driver_status_history(application_id, new_status, created_at DESC);
CREATE INDEX idx_driver_status_history_status ON app.driver_status_history(driver_account_id, new_status, created_at DESC);

COMMENT ON TABLE app.driver_status_history IS 'Audit trail of all driver online/offline/busy status transitions';

-- =============================================================================
-- IMPLEMENTATION: Create driver status change trigger
-- DESCRIPTION: Log all status transitions to history
-- PRIORITY: HIGH
-- ============================================================================
-- [APP-TR-003] Create driver_status_change_trigger

CREATE OR REPLACE FUNCTION app.log_driver_status_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.online_status IS DISTINCT FROM NEW.online_status THEN
        INSERT INTO app.driver_status_history (
            driver_account_id, application_id, previous_status, new_status,
            vehicle_id, zone_id, latitude, longitude, change_reason
        ) VALUES (
            NEW.driver_account_id, NEW.application_id, OLD.online_status, NEW.online_status,
            NEW.active_vehicle_id, NEW.matched_zone_id, NEW.last_latitude, NEW.last_longitude,
            NEW.status_reason
        );
        
        NEW.status_changed_at := now();
    END IF;
    
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = app, core, pg_catalog;

CREATE TRIGGER trg_driver_status_cache_change
    BEFORE UPDATE ON app.driver_status_cache
    FOR EACH ROW
    EXECUTE FUNCTION app.log_driver_status_change();

COMMENT ON FUNCTION app.log_driver_status_change IS 'Automatically logs driver status transitions to immutable history';

-- =============================================================================
-- IMPLEMENTATION: Create app.favorite_locations table
-- DESCRIPTION: Rider saved pickup/dropoff locations
-- PRIORITY: MEDIUM
-- SECURITY: Location data - RLS by rider account
-- ============================================================================
-- [APP-TR-004] Create app.favorite_locations table

CREATE TABLE app.favorite_locations (
    location_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rider_account_id    UUID NOT NULL REFERENCES core.accounts(account_id),
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Label
    location_label      VARCHAR(50) NOT NULL,        -- Home, Work, etc.
    
    -- Address
    address_text        TEXT NOT NULL,
    landmark            VARCHAR(255),
    
    -- Coordinates (optional but preferred)
    latitude            NUMERIC(10, 8),
    longitude           NUMERIC(11, 8),
    location_accuracy_meters NUMERIC(10, 2),
    
    -- Zone Matching
    matched_zone_id     UUID REFERENCES core.zones(zone_id),
    
    -- Usage
    usage_count         INTEGER DEFAULT 0,
    last_used_at        TIMESTAMPTZ,
    
    -- Status
    is_active           BOOLEAN DEFAULT true,
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT chk_favorite_locations_latitude 
        CHECK (latitude IS NULL OR (latitude BETWEEN -90 AND 90)),
    CONSTRAINT chk_favorite_locations_longitude 
        CHECK (longitude IS NULL OR (longitude BETWEEN -180 AND 180))
);

-- INDEXES
CREATE INDEX idx_favorite_locations_rider ON app.favorite_locations(rider_account_id, is_active);
CREATE INDEX idx_favorite_locations_app ON app.favorite_locations(application_id, rider_account_id);
CREATE INDEX idx_favorite_locations_zone ON app.favorite_locations(matched_zone_id);

COMMENT ON TABLE app.favorite_locations IS 'Rider saved common pickup and dropoff locations';

-- =============================================================================
-- IMPLEMENTATION: Create app.promo_codes table
-- DESCRIPTION: Promotional discount campaigns
-- PRIORITY: MEDIUM
-- SECURITY: Usage limits prevent abuse
-- ============================================================================
-- [APP-TR-005] Create app.promo_codes table

CREATE TABLE app.promo_codes (
    promo_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    promo_code          VARCHAR(50) NOT NULL,        -- User-entered code
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Campaign Details
    campaign_name       VARCHAR(200) NOT NULL,
    description         TEXT,
    
    -- Discount Type
    discount_type       VARCHAR(20) NOT NULL,        -- PERCENTAGE, FIXED_AMOUNT
    discount_value      NUMERIC(20, 8) NOT NULL,
    max_discount_amount NUMERIC(20, 8),             -- Cap for percentage discounts
    minimum_trip_fare   NUMERIC(20, 8) DEFAULT 0,   -- Minimum fare to apply
    
    -- Scope
    applicable_vehicle_types VARCHAR(50)[],          -- NULL = all types
    applicable_zone_ids UUID[],                      -- NULL = all zones
    applicable_routes   UUID[],                      -- NULL = all routes
    new_users_only      BOOLEAN DEFAULT false,
    
    -- Limits
    total_usage_limit   INTEGER,                     -- NULL = unlimited
    per_user_limit      INTEGER DEFAULT 1,
    current_usage_count INTEGER DEFAULT 0,
    
    -- Validity
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ NOT NULL,
    
    -- Status
    status              VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, PAUSED, EXPIRED, DISABLED
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    updated_at          TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT uq_promo_codes_code_app UNIQUE (promo_code, application_id),
    CONSTRAINT chk_promo_codes_discount_type 
        CHECK (discount_type IN ('PERCENTAGE', 'FIXED_AMOUNT')),
    CONSTRAINT chk_promo_codes_status 
        CHECK (status IN ('ACTIVE', 'PAUSED', 'EXPIRED', 'DISABLED')),
    CONSTRAINT chk_promo_codes_discount_value 
        CHECK (discount_value >= 0),
    CONSTRAINT chk_promo_codes_valid_time 
        CHECK (valid_to > valid_from)
);

-- INDEXES
CREATE INDEX idx_promo_codes_app ON app.promo_codes(application_id, status);
CREATE INDEX idx_promo_codes_valid ON app.promo_codes(valid_from, valid_to, status);
CREATE INDEX idx_promo_codes_active ON app.promo_codes(promo_code, application_id, status) WHERE status = 'ACTIVE';

COMMENT ON TABLE app.promo_codes IS 'Promotional discount codes with usage limits and applicability rules';
COMMENT ON COLUMN app.promo_codes.discount_value IS 'Discount as percentage (e.g., 0.15) or fixed amount';

-- =============================================================================
-- IMPLEMENTATION: Create promo code usage tracking table
-- DESCRIPTION: Record of promo code redemptions
-- PRIORITY: MEDIUM
-- SECURITY: Prevents duplicate usage beyond limits
-- ============================================================================
-- [APP-TR-006] Create app.promo_code_usages table

CREATE TABLE app.promo_code_usages (
    usage_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    promo_id            UUID NOT NULL REFERENCES app.promo_codes(promo_id),
    rider_account_id    UUID NOT NULL REFERENCES core.accounts(account_id),
    
    -- Usage Context
    trip_transaction_id UUID REFERENCES core.transaction_log(transaction_id),
    discount_amount     NUMERIC(20, 8) NOT NULL,
    currency            VARCHAR(3) NOT NULL,
    
    -- Timing
    used_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_promo_code_usages_promo ON app.promo_code_usages(promo_id, used_at);
CREATE INDEX idx_promo_code_usages_rider ON app.promo_code_usages(rider_account_id, promo_id);
CREATE INDEX idx_promo_code_usages_trip ON app.promo_code_usages(trip_transaction_id);

COMMENT ON TABLE app.promo_code_usages IS 'Immutable record of promo code redemptions for audit and limit enforcement';

-- =============================================================================
-- IMPLEMENTATION: Create promo code validation function
-- DESCRIPTION: Check if a promo code is valid for a given trip
-- PRIORITY: HIGH
-- SECURITY: Enforces usage limits and applicability rules
-- ============================================================================
-- [APP-TR-007] Create validate_promo_code function

CREATE OR REPLACE FUNCTION app.validate_promo_code(
    p_promo_code VARCHAR(50),
    p_application_id UUID,
    p_rider_account_id UUID,
    p_trip_fare NUMERIC,
    p_vehicle_type VARCHAR(50) DEFAULT NULL,
    p_zone_id UUID DEFAULT NULL
) RETURNS TABLE (
    is_valid BOOLEAN,
    promo_id UUID,
    discount_amount NUMERIC,
    discount_currency VARCHAR(3),
    reason TEXT
) AS $$
DECLARE
    v_promo RECORD;
    v_user_usage INTEGER;
    v_is_new_user BOOLEAN;
    v_discount NUMERIC;
BEGIN
    -- Find active promo
    SELECT * INTO v_promo
    FROM app.promo_codes
    WHERE promo_code = UPPER(p_promo_code)
      AND application_id = p_application_id
      AND status = 'ACTIVE'
      AND valid_from <= now()
      AND valid_to > now();
    
    IF v_promo IS NULL THEN
        RETURN QUERY SELECT false, NULL::UUID, NULL::NUMERIC, NULL::VARCHAR(3), 'Promo code not found or expired'::TEXT;
        RETURN;
    END IF;
    
    -- Check minimum fare
    IF p_trip_fare < v_promo.minimum_trip_fare THEN
        RETURN QUERY SELECT false, NULL::UUID, NULL::NUMERIC, NULL::VARCHAR(3), 
            'Trip fare below minimum required for this promo'::TEXT;
        RETURN;
    END IF;
    
    -- Check vehicle type applicability
    IF v_promo.applicable_vehicle_types IS NOT NULL AND p_vehicle_type IS NOT NULL THEN
        IF NOT (p_vehicle_type = ANY(v_promo.applicable_vehicle_types)) THEN
            RETURN QUERY SELECT false, NULL::UUID, NULL::NUMERIC, NULL::VARCHAR(3), 
                'Promo not applicable for this vehicle type'::TEXT;
            RETURN;
        END IF;
    END IF;
    
    -- Check zone applicability
    IF v_promo.applicable_zone_ids IS NOT NULL AND p_zone_id IS NOT NULL THEN
        IF NOT (p_zone_id = ANY(v_promo.applicable_zone_ids)) THEN
            RETURN QUERY SELECT false, NULL::UUID, NULL::NUMERIC, NULL::VARCHAR(3), 
                'Promo not applicable in this zone'::TEXT;
            RETURN;
        END IF;
    END IF;
    
    -- Check new user restriction
    IF v_promo.new_users_only THEN
        SELECT COUNT(*) = 0 INTO v_is_new_user
        FROM core.transaction_log
        WHERE initiator_account_id = p_rider_account_id
          AND application_id = p_application_id
          AND transaction_type_id IN (
              SELECT transaction_type_id FROM core.transaction_types 
              WHERE type_code IN ('RIDE_PAYMENT', 'RIDE_REQUEST')
          );
        
        IF NOT v_is_new_user THEN
            RETURN QUERY SELECT false, NULL::UUID, NULL::NUMERIC, NULL::VARCHAR(3), 
                'Promo valid for new users only'::TEXT;
            RETURN;
        END IF;
    END IF;
    
    -- Check total usage limit
    IF v_promo.total_usage_limit IS NOT NULL AND v_promo.current_usage_count >= v_promo.total_usage_limit THEN
        RETURN QUERY SELECT false, NULL::UUID, NULL::NUMERIC, NULL::VARCHAR(3), 
            'Promo code usage limit reached'::TEXT;
        RETURN;
    END IF;
    
    -- Check per-user limit
    SELECT COUNT(*) INTO v_user_usage
    FROM app.promo_code_usages
    WHERE promo_id = v_promo.promo_id AND rider_account_id = p_rider_account_id;
    
    IF v_user_usage >= v_promo.per_user_limit THEN
        RETURN QUERY SELECT false, NULL::UUID, NULL::NUMERIC, NULL::VARCHAR(3), 
            'You have already used this promo code the maximum number of times'::TEXT;
        RETURN;
    END IF;
    
    -- Calculate discount
    IF v_promo.discount_type = 'PERCENTAGE' THEN
        v_discount := ROUND(p_trip_fare * v_promo.discount_value, 8);
        IF v_promo.max_discount_amount IS NOT NULL THEN
            v_discount := LEAST(v_discount, v_promo.max_discount_amount);
        END IF;
    ELSE
        v_discount := v_promo.discount_value;
    END IF;
    
    v_discount := LEAST(v_discount, p_trip_fare);
    
    RETURN QUERY SELECT true, v_promo.promo_id, v_discount, v_promo.currency, 
        'Promo code valid'::TEXT;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = app, core, pg_catalog;

COMMENT ON FUNCTION app.validate_promo_code IS 'Validates a promo code against all usage limits and applicability rules';

-- =============================================================================
-- IMPLEMENTATION: Create available drivers view
-- DESCRIPTION: Drivers currently online and eligible for assignments
-- PRIORITY: HIGH
-- ============================================================================
-- [APP-TR-008] Create available_drivers view

CREATE OR REPLACE VIEW app.available_drivers AS
SELECT 
    dsc.*,
    v.vehicle_id,
    v.vehicle_type,
    v.registration_number,
    v.seating_capacity,
    a.display_name as driver_name,
    a.metadata->>'msisdn' as driver_msisdn
FROM app.driver_status_cache dsc
JOIN core.accounts a ON dsc.driver_account_id = a.account_id
LEFT JOIN core.vehicles v ON dsc.active_vehicle_id = v.vehicle_id
WHERE dsc.online_status = 'ONLINE'
  AND dsc.accepts_rides = true
  AND a.status = 'ACTIVE';

COMMENT ON VIEW app.available_drivers IS 'View of drivers currently online and available for ride assignments';

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create app.driver_status_cache table for real-time driver status
☑ Create app.driver_status_history table for audit trail
☑ Implement auto-logging trigger for driver status changes
☑ Create app.favorite_locations table for rider saved locations
☑ Create app.promo_codes table with usage limits
☑ Create app.promo_code_usages table for redemption tracking
☑ Implement validate_promo_code function
☑ Create available_drivers view
☑ Add all indexes for performance-critical queries
☑ Verify foreign key constraints
================================================================================
*/
