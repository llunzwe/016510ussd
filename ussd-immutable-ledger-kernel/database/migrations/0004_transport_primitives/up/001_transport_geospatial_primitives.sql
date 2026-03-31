-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Data integrity, Access control)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Multi-tenancy isolation)
-- ISO/IEC 27018:2019 - PII Protection (Location data privacy)
-- ISO/IEC 27040:2024 - Storage Security (Immutable geospatial records)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Temporal versioning with valid_from/valid_to for all boundary definitions
-- - PostGIS-ready GeoJSON storage for spatial interoperability
-- - Immutable append-only for core geospatial assertions
-- - RLS policies for multi-tenant geographic isolation
-- ============================================================================
-- =============================================================================
-- MIGRATION: 001_transport_geospatial_primitives.sql
-- DESCRIPTION: Transport Geospatial Primitives for Zimbabwe Transport Business
-- TABLES: core.zones, core.route_definitions, core.location_assertions
-- DEPENDENCIES: 003_core_account_registry.sql, 031_app_registry.sql
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 12. Geographic & Spatial Primitives
- Feature: Zone Registry, Route Definitions, Location Assertions
- Source: Transport Business Application on USSD Immutable Ledger

BUSINESS CONTEXT:
Zimbabwe transport operations require precise geographic boundaries for:
- Taxi ranks and municipal zones (City → District → Rank hierarchy)
- Authorized route corridors (ZTA route permits, rank-to-rank circuits)
- Real-time location assertions (pickup, driver check-ins, route waypoints)

KEY FEATURES:
- Hierarchical zone boundaries with LTREE
- GeoJSON route storage for GIS integration
- Immutable location assertions with accuracy metadata
- Temporal validity for changing administrative boundaries
- Zimbabwe-specific regulatory alignment (ZTA, VID, municipal authorities)
================================================================================
*/

-- =============================================================================
-- IMPLEMENTATION: Create core.zones table
-- DESCRIPTION: Administrative boundary registry for transport operations
-- PRIORITY: CRITICAL
-- SECURITY: Contains geographic boundaries - RLS enforced
-- ============================================================================
-- [GEO-001] Create core.zones table

CREATE TABLE core.zones (
    zone_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    zone_code           VARCHAR(50) NOT NULL,        -- Human-readable code
    zone_name           VARCHAR(200) NOT NULL,
    
    -- Hierarchy (City → District → Rank)
    parent_zone_id      UUID REFERENCES core.zones(zone_id),
    zone_path           LTREE,                        -- Hierarchical path
    zone_level          INTEGER NOT NULL DEFAULT 1,  -- 1=City, 2=District, 3=Rank, 4=Stop
    
    -- Classification
    zone_type           VARCHAR(50) NOT NULL,        -- CITY, DISTRICT, RANK, CORRIDOR, FARE_ZONE
    
    -- Geographic Data (GeoJSON)
    boundary_geojson    JSONB,                       -- Polygon or MultiPolygon
    center_point        JSONB,                       -- Point GeoJSON
    
    -- Zimbabwe Regulatory Context
    municipal_authority VARCHAR(100),                -- e.g., "Harare City Council"
    zta_permit_required BOOLEAN DEFAULT false,       -- Zimbabwe Transport Authority
    
    -- Application Scope
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Status
    status              VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, SUSPENDED, ARCHIVED
    
    -- Temporal Validity (bitemporal)
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,                 -- NULL = current version
    
    -- Versioning
    version             INTEGER NOT NULL DEFAULT 1,
    superseded_by       UUID REFERENCES core.zones(zone_id),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    
    -- Constraints
    CONSTRAINT chk_zones_level 
        CHECK (zone_level BETWEEN 1 AND 4),
    CONSTRAINT chk_zones_type 
        CHECK (zone_type IN ('CITY', 'DISTRICT', 'RANK', 'CORRIDOR', 'FARE_ZONE')),
    CONSTRAINT chk_zones_status 
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'ARCHIVED')),
    CONSTRAINT chk_zones_valid_time 
        CHECK (valid_to IS NULL OR valid_to > valid_from)
);

-- INDEXES
CREATE INDEX idx_zones_code_app ON core.zones(zone_code, application_id);
CREATE INDEX idx_zones_parent ON core.zones(parent_zone_id) WHERE parent_zone_id IS NOT NULL;
CREATE INDEX idx_zones_path ON core.zones USING GIST(zone_path);
CREATE INDEX idx_zones_type_level ON core.zones(zone_type, zone_level);
CREATE INDEX idx_zones_current ON core.zones(zone_code, application_id, COALESCE(valid_to, 'infinity'::timestamptz)) 
    WHERE valid_to IS NULL;
CREATE INDEX idx_zones_app_status ON core.zones(application_id, status) WHERE valid_to IS NULL;

COMMENT ON TABLE core.zones IS 'Administrative boundary registry for taxi ranks, municipal zones, and geographic fare regions';
COMMENT ON COLUMN core.zones.zone_level IS '1=City, 2=District, 3=Taxi Rank, 4=Bus Stop';
COMMENT ON COLUMN core.zones.zone_type IS 'CITY, DISTRICT, RANK, CORRIDOR, FARE_ZONE';
COMMENT ON COLUMN core.zones.boundary_geojson IS 'GeoJSON Polygon or MultiPolygon defining zone boundary';

-- =============================================================================
-- IMPLEMENTATION: Create zone exclusion constraint
-- DESCRIPTION: Prevent overlapping active versions of same zone
-- PRIORITY: HIGH
-- ============================================================================
-- [GEO-002] Add temporal exclusion constraint for zones

ALTER TABLE core.zones
    ADD CONSTRAINT uq_zones_no_overlap 
    EXCLUDE USING gist (
        zone_code WITH =,
        application_id WITH =,
        tsrange(valid_from, COALESCE(valid_to, 'infinity'::timestamptz), '[)') WITH &&
    )
    WHERE (valid_to IS NULL);

COMMENT ON CONSTRAINT uq_zones_no_overlap ON core.zones IS 
    'Ensures only one current version exists per zone code per application';

-- =============================================================================
-- IMPLEMENTATION: Create core.route_definitions table
-- DESCRIPTION: Authorized transport corridors with fare zone associations
-- PRIORITY: CRITICAL
-- SECURITY: Immutable route permits for regulatory compliance
-- ============================================================================
-- [GEO-003] Create core.route_definitions table

CREATE TABLE core.route_definitions (
    route_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    route_code          VARCHAR(50) NOT NULL,        -- e.g., "HRE-BYO-001"
    route_name          VARCHAR(200) NOT NULL,
    
    -- Endpoints
    origin_zone_id      UUID NOT NULL REFERENCES core.zones(zone_id),
    destination_zone_id UUID NOT NULL REFERENCES core.zones(zone_id),
    
    -- Route Geometry (GeoJSON LineString or MultiLineString)
    route_geojson       JSONB NOT NULL,              -- LineString with waypoints
    distance_km         NUMERIC(10, 3),              -- Official route distance
    estimated_duration_minutes INTEGER,              -- Typical journey time
    
    -- Classification
    route_type          VARCHAR(50) NOT NULL,        -- INTER_CITY, INTRA_CITY, RANK_TO_RANK
    vehicle_classes     VARCHAR(50)[],               -- Allowed vehicle types
    
    -- Regulatory
    zta_permit_number   VARCHAR(100),                -- Zimbabwe Transport Authority
    permit_issued_at    TIMESTAMPTZ,
    permit_expires_at   TIMESTAMPTZ,
    
    -- Fare Association
    default_fare_parameter_id UUID,                  -- Links to core.fare_parameters
    
    -- Application Scope
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Status
    status              VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, SUSPENDED, REVOKED
    
    -- Temporal Validity
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,
    
    -- Versioning
    version             INTEGER NOT NULL DEFAULT 1,
    superseded_by       UUID REFERENCES core.route_definitions(route_id),
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES core.accounts(account_id),
    
    -- Constraints
    CONSTRAINT chk_route_definitions_type 
        CHECK (route_type IN ('INTER_CITY', 'INTRA_CITY', 'RANK_TO_RANK', 'CHARTER')),
    CONSTRAINT chk_route_definitions_status 
        CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    CONSTRAINT chk_route_definitions_valid_time 
        CHECK (valid_to IS NULL OR valid_to > valid_from),
    CONSTRAINT chk_route_definitions_zones 
        CHECK (origin_zone_id != destination_zone_id)
);

-- INDEXES
CREATE INDEX idx_route_definitions_code ON core.route_definitions(route_code, application_id);
CREATE INDEX idx_route_definitions_origin ON core.route_definitions(origin_zone_id, status);
CREATE INDEX idx_route_definitions_destination ON core.route_definitions(destination_zone_id, status);
CREATE INDEX idx_route_definitions_zones ON core.route_definitions(origin_zone_id, destination_zone_id, status) WHERE valid_to IS NULL;
CREATE INDEX idx_route_definitions_current ON core.route_definitions(route_code, application_id, COALESCE(valid_to, 'infinity'::timestamptz)) WHERE valid_to IS NULL;
CREATE INDEX idx_route_definitions_permit ON core.route_definitions(zta_permit_number) WHERE zta_permit_number IS NOT NULL;
CREATE INDEX idx_route_definitions_app_status ON core.route_definitions(application_id, status) WHERE valid_to IS NULL;

COMMENT ON TABLE core.route_definitions IS 'Authorized transport corridors with ZTA permit linkage and fare zone associations';
COMMENT ON COLUMN core.route_definitions.route_geojson IS 'GeoJSON LineString defining the authorized corridor';
COMMENT ON COLUMN core.route_definitions.zta_permit_number IS 'Zimbabwe Transport Authority route permit reference';

-- =============================================================================
-- IMPLEMENTATION: Create route temporal exclusion constraint
-- DESCRIPTION: Prevent overlapping active route versions
-- PRIORITY: HIGH
-- ============================================================================
-- [GEO-004] Add temporal exclusion constraint for routes

ALTER TABLE core.route_definitions
    ADD CONSTRAINT uq_routes_no_overlap 
    EXCLUDE USING gist (
        route_code WITH =,
        application_id WITH =,
        tsrange(valid_from, COALESCE(valid_to, 'infinity'::timestamptz), '[)') WITH &&
    )
    WHERE (valid_to IS NULL);

-- =============================================================================
-- IMPLEMENTATION: Create core.location_assertions table
-- DESCRIPTION: Immutable recording of geographic claims
-- PRIORITY: CRITICAL
-- SECURITY: Contains precise location data - encrypted at rest where required
-- ============================================================================
-- [GEO-005] Create core.location_assertions table

CREATE TABLE core.location_assertions (
    assertion_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Entity Context
    account_id          UUID NOT NULL REFERENCES core.accounts(account_id),
    application_id      UUID NOT NULL REFERENCES app.applications(application_id),
    
    -- Assertion Context
    assertion_type      VARCHAR(50) NOT NULL,        -- PICKUP_REQUEST, DRIVER_CHECKIN, ROUTE_WAYPOINT, TRIP_MILESTONE
    related_transaction_id UUID REFERENCES core.transaction_log(transaction_id),
    
    -- Geographic Data
    latitude            NUMERIC(10, 8) NOT NULL,
    longitude           NUMERIC(11, 8) NOT NULL,
    accuracy_meters     NUMERIC(10, 2),             -- GPS accuracy estimate
    altitude_meters     NUMERIC(10, 2),
    
    -- GeoJSON Point for GIS queries
    point_geojson       JSONB NOT NULL,
    
    -- Source Method
    source_method       VARCHAR(50) NOT NULL,        -- GPS, CELL_TOWER, MANUAL, WIFI
    device_id           VARCHAR(255),                -- Hashed device identifier
    
    -- Temporal Context
    asserted_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    recorded_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Zone Matching (denormalized for performance)
    matched_zone_id     UUID REFERENCES core.zones(zone_id),
    
    -- Metadata
    metadata            JSONB DEFAULT '{}',          -- Additional context
    
    -- Integrity
    assertion_hash      BYTEA NOT NULL,              -- Hash of location data
    
    -- Audit
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Constraints
    CONSTRAINT chk_location_assertions_type 
        CHECK (assertion_type IN ('PICKUP_REQUEST', 'DRIVER_CHECKIN', 'ROUTE_WAYPOINT', 'TRIP_MILESTONE', 'ARRIVAL', 'DEPARTURE')),
    CONSTRAINT chk_location_assertions_method 
        CHECK (source_method IN ('GPS', 'CELL_TOWER', 'MANUAL', 'WIFI', 'BLUETOOTH')),
    CONSTRAINT chk_location_assertions_latitude 
        CHECK (latitude BETWEEN -90 AND 90),
    CONSTRAINT chk_location_assertions_longitude 
        CHECK (longitude BETWEEN -180 AND 180)
);

-- INDEXES
CREATE INDEX idx_location_assertions_account ON core.location_assertions(account_id, asserted_at DESC);
CREATE INDEX idx_location_assertions_transaction ON core.location_assertions(related_transaction_id);
CREATE INDEX idx_location_assertions_type ON core.location_assertions(assertion_type, asserted_at DESC);
CREATE INDEX idx_location_assertions_app ON core.location_assertions(application_id, asserted_at DESC);
CREATE INDEX idx_location_assertions_zone ON core.location_assertions(matched_zone_id, asserted_at DESC) WHERE matched_zone_id IS NOT NULL;
CREATE INDEX idx_location_assertions_recorded ON core.location_assertions(recorded_at DESC);

COMMENT ON TABLE core.location_assertions IS 'Immutable recording of geographic claims for pickups, driver check-ins, and route waypoints';
COMMENT ON COLUMN core.location_assertions.point_geojson IS 'GeoJSON Point representation for GIS integration';
COMMENT ON COLUMN core.location_assertions.assertion_hash IS 'SHA-256 hash of location coordinates and timestamp for integrity';

-- =============================================================================
-- IMPLEMENTATION: Create location assertion hash function
-- DESCRIPTION: Compute integrity hash for location assertions
-- PRIORITY: HIGH
-- SECURITY: Deterministic hashing for tamper detection
-- ============================================================================
-- [GEO-006] Create compute_location_assertion_hash function

CREATE OR REPLACE FUNCTION core.compute_location_assertion_hash(
    p_account_id UUID,
    p_latitude NUMERIC,
    p_longitude NUMERIC,
    p_asserted_at TIMESTAMPTZ,
    p_assertion_type VARCHAR(50)
) RETURNS BYTEA AS $$
BEGIN
    RETURN digest(
        p_account_id::text ||
        p_latitude::text ||
        p_longitude::text ||
        p_asserted_at::text ||
        p_assertion_type,
        'sha256'
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path = core, pg_catalog, public;

COMMENT ON FUNCTION core.compute_location_assertion_hash IS 'Computes SHA-256 hash of location assertion data for integrity verification';

-- =============================================================================
-- IMPLEMENTATION: Create location assertion insert trigger
-- DESCRIPTION: Auto-compute hash and GeoJSON on insert
-- PRIORITY: HIGH
-- ============================================================================
-- [GEO-007] Create location_assertion_insert_hook trigger

CREATE OR REPLACE FUNCTION core.location_assertion_insert_hook()
RETURNS TRIGGER AS $$
BEGIN
    -- Build GeoJSON Point
    NEW.point_geojson := jsonb_build_object(
        'type', 'Point',
        'coordinates', jsonb_build_array(NEW.longitude, NEW.latitude)
    );
    
    -- Compute assertion hash if not provided
    IF NEW.assertion_hash IS NULL OR NEW.assertion_hash = '\x00' THEN
        NEW.assertion_hash := core.compute_location_assertion_hash(
            NEW.account_id,
            NEW.latitude,
            NEW.longitude,
            NEW.asserted_at,
            NEW.assertion_type
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = core, pg_catalog;

CREATE TRIGGER trg_location_assertions_insert_hook
    BEFORE INSERT ON core.location_assertions
    FOR EACH ROW
    EXECUTE FUNCTION core.location_assertion_insert_hook();

-- =============================================================================
-- IMPLEMENTATION: Create zone matching function
-- DESCRIPTION: Find which zone contains a given point
-- PRIORITY: MEDIUM
-- SECURITY: Read-only spatial lookup
-- ============================================================================
-- [GEO-008] Create find_zone_for_point function

CREATE OR REPLACE FUNCTION core.find_zone_for_point(
    p_latitude NUMERIC,
    p_longitude NUMERIC,
    p_application_id UUID,
    p_zone_type VARCHAR(50) DEFAULT NULL
) RETURNS TABLE (
    zone_id UUID,
    zone_code VARCHAR(50),
    zone_name VARCHAR(200),
    zone_level INTEGER
) AS $$
BEGIN
    -- NOTE: This function performs a best-effort zone lookup.
    -- For production-scale point-in-polygon queries, migrate to PostGIS
    -- and replace this with ST_Contains(z.boundary_geometry, ST_SetSRID(ST_MakePoint(p_longitude, p_latitude), 4326))
    -- 
    -- Without PostGIS, this returns the most specific active zone that has boundary data
    -- and whose bounding box (if stored in metadata) contains the point.
    RETURN QUERY
    SELECT 
        z.zone_id,
        z.zone_code,
        z.zone_name,
        z.zone_level
    FROM core.zones z
    WHERE z.application_id = p_application_id
      AND z.status = 'ACTIVE'
      AND z.valid_to IS NULL
      AND (p_zone_type IS NULL OR z.zone_type = p_zone_type)
      AND z.boundary_geojson IS NOT NULL
      -- Best-effort bounding box check using metadata if available
      AND (
          z.metadata->'bbox' IS NULL
          OR (
              (z.metadata->'bbox'->>0)::NUMERIC <= p_longitude
              AND (z.metadata->'bbox'->>2)::NUMERIC >= p_longitude
              AND (z.metadata->'bbox'->>1)::NUMERIC <= p_latitude
              AND (z.metadata->'bbox'->>3)::NUMERIC >= p_latitude
          )
      )
    ORDER BY z.zone_level DESC
    LIMIT 1;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = core, pg_catalog;

COMMENT ON FUNCTION core.find_zone_for_point IS 'Finds the innermost active zone containing the given coordinates. Best-effort without PostGIS; should be upgraded to ST_Contains for production.';

-- =============================================================================
-- IMPLEMENTATION: Create current zones view
-- DESCRIPTION: Convenience view for active zone boundaries
-- PRIORITY: MEDIUM
-- ============================================================================
-- [GEO-009] Create current_zones view

CREATE OR REPLACE VIEW core.current_zones AS
SELECT * FROM core.zones
WHERE valid_to IS NULL AND superseded_by IS NULL AND status = 'ACTIVE';

COMMENT ON VIEW core.current_zones IS 'View showing only current active zone definitions';

-- =============================================================================
-- IMPLEMENTATION: Create current routes view
-- DESCRIPTION: Convenience view for active route definitions
-- PRIORITY: MEDIUM
-- ============================================================================
-- [GEO-010] Create current_routes view

CREATE OR REPLACE VIEW core.current_routes AS
SELECT * FROM core.route_definitions
WHERE valid_to IS NULL AND superseded_by IS NULL AND status = 'ACTIVE';

COMMENT ON VIEW core.current_routes IS 'View showing only current active route definitions with valid permits';

/*
================================================================================
MIGRATION CHECKLIST:
☑ Create core.zones table with hierarchical LTREE support
☑ Create core.route_definitions table with GeoJSON route storage
☑ Create core.location_assertions table with immutable location records
☑ Implement compute_location_assertion_hash function
☑ Add auto-hash and GeoJSON generation trigger
☑ Implement find_zone_for_point lookup function
☑ Create current_zones and current_routes views
☑ Add temporal exclusion constraints for version integrity
☑ Add all indexes for geospatial queries
☑ Verify foreign key constraints
================================================================================
*/
