# Transport Business Primitives – USSD Immutable Ledger Kernel

## Executive Summary

This document provides a comprehensive, enterprise-grade specification of all transport business primitives added to the USSD Immutable Ledger Kernel. These primitives align the core kernel specifically to the Zimbabwe transport business context, covering ride-hailing, fleet management, fare calculation, regulatory compliance, and dispute resolution.

Every primitive follows the kernel's architectural separation:
- **Core Schema (`core.*`)**: Immutable, append-only, cryptographically verifiable records
- **App Schema (`app.*`)**: Mutable, audited application configuration and operational cache
- **USSD Gateway (`ussd.*`)**: Session management and menu routing (existing, extended via context)

---

## 1. Migration Overview

| Migration | Files | Description |
|-----------|-------|-------------|
| `0004_transport_primitives` | 6 up + 1 down | Complete transport business layer |
| `001_transport_geospatial_primitives.sql` | 1 | Zones, routes, location assertions |
| `002_transport_vehicle_primitives.sql` | 1 | Vehicles, assignments, compliance, document verification |
| `003_transport_service_primitives.sql` | 1 | Disputes, regulatory flags |
| `004_transport_fare_primitives.sql` | 1 | Fare parameters, fee structures, regulatory parameters |
| `005_transport_app_tables.sql` | 1 | Driver status cache, favorite locations, promo codes |
| `006_transport_seed_data.sql` | 1 | Transport-specific seed data |

---

## 2. Geospatial Primitives

### 2.1 `core.zones`
**Purpose**: Administrative boundary registry for taxi ranks, municipal zones, and fare regions.

| Column | Type | Description |
|--------|------|-------------|
| `zone_id` | UUID | Primary key |
| `zone_code` | VARCHAR(50) | Human-readable code (e.g., `ZW_HRE_CBD`) |
| `zone_name` | VARCHAR(200) | Display name |
| `parent_zone_id` | UUID | Self-referential hierarchy |
| `zone_path` | LTREE | Hierarchical path for tree queries |
| `zone_level` | INTEGER | 1=City, 2=District, 3=Rank, 4=Stop |
| `zone_type` | VARCHAR(50) | CITY, DISTRICT, RANK, CORRIDOR, FARE_ZONE |
| `boundary_geojson` | JSONB | GeoJSON Polygon/MultiPolygon |
| `center_point` | JSONB | GeoJSON Point |
| `municipal_authority` | VARCHAR(100) | e.g., "Harare City Council" |
| `zta_permit_required` | BOOLEAN | Zimbabwe Transport Authority requirement |
| `valid_from` / `valid_to` | TIMESTAMPTZ | Temporal versioning |
| `version` | INTEGER | Version number |

**Constraints**:
- Temporal exclusion constraint prevents overlapping active versions per `zone_code + application_id`
- `zone_level` CHECK: 1–4
- `zone_type` CHECK: valid enumeration

**Indexes**:
- `idx_zones_path` (GIST on LTREE)
- `idx_zones_current` (partial, current versions only)

---

### 2.2 `core.route_definitions`
**Purpose**: Authorized transport corridors with ZTA permit linkage.

| Column | Type | Description |
|--------|------|-------------|
| `route_id` | UUID | Primary key |
| `route_code` | VARCHAR(50) | e.g., `HRE-BYO-001` |
| `origin_zone_id` | UUID | FK to `core.zones` |
| `destination_zone_id` | UUID | FK to `core.zones` |
| `route_geojson` | JSONB | GeoJSON LineString |
| `distance_km` | NUMERIC(10,3) | Official distance |
| `estimated_duration_minutes` | INTEGER | Typical journey time |
| `route_type` | VARCHAR(50) | INTER_CITY, INTRA_CITY, RANK_TO_RANK, CHARTER |
| `vehicle_classes` | VARCHAR(50)[] | Allowed vehicle types |
| `zta_permit_number` | VARCHAR(100) | Permit reference |
| `permit_issued_at` / `permit_expires_at` | TIMESTAMPTZ | Permit validity |
| `default_fare_parameter_id` | UUID | Links to `core.fare_parameters` |

**Constraints**:
- Temporal exclusion constraint for active versions
- `origin_zone_id != destination_zone_id`

---

### 2.3 `core.location_assertions`
**Purpose**: Immutable recording of geographic claims (pickups, driver check-ins, waypoints).

| Column | Type | Description |
|--------|------|-------------|
| `assertion_id` | UUID | Primary key |
| `account_id` | UUID | Entity making the assertion |
| `assertion_type` | VARCHAR(50) | PICKUP_REQUEST, DRIVER_CHECKIN, ROUTE_WAYPOINT, TRIP_MILESTONE, ARRIVAL, DEPARTURE |
| `related_transaction_id` | UUID | Links to `core.transaction_log` |
| `latitude` / `longitude` | NUMERIC | Coordinates with bounds checks |
| `accuracy_meters` | NUMERIC(10,2) | GPS accuracy |
| `point_geojson` | JSONB | Auto-generated GeoJSON Point |
| `source_method` | VARCHAR(50) | GPS, CELL_TOWER, MANUAL, WIFI, BLUETOOTH |
| `asserted_at` | TIMESTAMPTZ | When the location was reported |
| `assertion_hash` | BYTEA | SHA-256 hash for integrity |

**Automation**:
- `BEFORE INSERT` trigger auto-generates `point_geojson` and `assertion_hash`

**Functions**:
- `core.compute_location_assertion_hash(...)` – deterministic hash
- `core.find_zone_for_point(lat, lon, app_id, zone_type)` – point-in-polygon lookup

---

## 3. Vehicle & Asset Primitives

### 3.1 `core.vehicles`
**Purpose**: Asset identity master record for all registered vehicles.

| Column | Type | Description |
|--------|------|-------------|
| `vehicle_id` | UUID | Primary key |
| `vehicle_reference` | VARCHAR(100) | Internal reference |
| `registration_number` | VARCHAR(50) | Number plate |
| `registration_country` | VARCHAR(3) | Default `ZW` |
| `vehicle_type` | VARCHAR(50) | STANDARD, PREMIUM, LUXURY, BUS, BIKE, TRUCK |
| `vehicle_class` | VARCHAR(50) | SEDAN, SUV, MINIBUS, etc. |
| `seating_capacity` | INTEGER | Default 4 |
| `make` / `model` / `color` | VARCHAR | Vehicle specs |
| `year_of_manufacture` | INTEGER | 1900–2100 |
| `fuel_type` | VARCHAR(20) | PETROL, DIESEL, ELECTRIC, HYBRID, LPG |
| `owner_account_id` | UUID | FK to `core.accounts` |
| `registration_doc_id` | UUID | FK to `core.document_registry` |
| `insurance_doc_id` | UUID | FK to `core.document_registry` |
| `crw_doc_id` | UUID | FK to `core.document_registry` |

**Constraints**:
- Temporal exclusion constraint on `registration_number + application_id`

---

### 3.2 `core.vehicle_assignments`
**Purpose**: Temporal tracking of driver-vehicle relationships.

| Column | Type | Description |
|--------|------|-------------|
| `assignment_id` | UUID | Primary key |
| `vehicle_id` | UUID | FK to `core.vehicles` |
| `driver_account_id` | UUID | FK to `core.accounts` |
| `assignment_type` | VARCHAR(50) | PRIMARY, SECONDARY, TEMPORARY, POOL |
| `valid_from` / `valid_to` | TIMESTAMPTZ | Assignment period |
| `status` | VARCHAR(20) | ACTIVE, ENDED, SUSPENDED |

**Constraints**:
- Exclusion constraint: only one `PRIMARY` assignment per vehicle at any time

**View**:
- `core.current_vehicle_assignments` – active assignments only

---

### 3.3 `core.vehicle_compliance`
**Purpose**: Regulatory state tracking (CRW, insurance, VID inspection, route authority).

| Column | Type | Description |
|--------|------|-------------|
| `compliance_id` | UUID | Primary key |
| `vehicle_id` | UUID | FK to `core.vehicles` |
| `compliance_type` | VARCHAR(50) | CRW, INSURANCE, VID_INSPECTION, ROUTE_AUTHORITY, TAX_CLEARANCE, OPERATING_LICENSE |
| `compliance_status` | VARCHAR(50) | VALID, EXPIRED, PENDING, REVOKED, SUSPENDED |
| `document_id` | UUID | FK to `core.document_registry` |
| `valid_from` / `valid_to` | TIMESTAMPTZ | Compliance validity period |
| `issuing_authority` | VARCHAR(200) | e.g., "VID Harare", "ZTA" |
| `renewal_reminder_sent` | BOOLEAN | Alert tracking |

**Functions**:
- `core.check_vehicle_compliance(vehicle_id, as_of)` – returns all compliance statuses
- `core.is_vehicle_serviceable(vehicle_id, as_of)` – eligibility gatekeeper

**View**:
- `core.vehicle_compliance_summary` – latest status per vehicle and compliance type

---

### 3.4 `core.document_verifications`
**Purpose**: Immutable audit trail of document approvals/rejections.

| Column | Type | Description |
|--------|------|-------------|
| `verification_id` | UUID | Primary key |
| `document_id` | UUID | FK to `core.document_registry` |
| `verification_status` | VARCHAR(50) | PENDING, APPROVED, REJECTED, EXPIRED, UNDER_REVIEW |
| `verifier_account_id` | UUID | Approver identity |
| `verifier_role` | VARCHAR(50) | ADMIN, FLEET_MANAGER, SYSTEM |
| `related_entity_type` | VARCHAR(50) | VEHICLE, DRIVER, ACCOUNT |
| `verification_method` | VARCHAR(50) | MANUAL, OCR, API, BIOMETRIC, THIRD_PARTY |
| `verified_at` | TIMESTAMPTZ | Verification timestamp |

---

## 4. Service & Dispute Primitives

### 4.1 `core.disputes`
**Purpose**: Conflict resolution for fare and service quality disputes.

| Column | Type | Description |
|--------|------|-------------|
| `dispute_id` | UUID | Primary key |
| `dispute_reference` | VARCHAR(100) | e.g., `DISP-20240331-001` |
| `trip_transaction_id` | UUID | FK to `core.transaction_log` |
| `rider_account_id` | UUID | Complainant |
| `driver_account_id` | UUID | Respondent |
| `dispute_category` | VARCHAR(50) | FARE_DISPUTE, SERVICE_QUALITY, SAFETY, ROUTE_DEVIATION, PAYMENT_ISSUE, DRIVER_CONDUCT, VEHICLE_CONDITION |
| `dispute_priority` | VARCHAR(20) | LOW, MEDIUM, HIGH, CRITICAL |
| `status` | VARCHAR(50) | OPEN, UNDER_REVIEW, EVIDENCE_REQUESTED, MEDIATION, RESOLVED_RIDER_FAVOUR, RESOLVED_DRIVER_FAVOUR, RESOLVED_SPLIT, REJECTED, ESCALATED, CLOSED |
| `resolution_type` | VARCHAR(50) | REFUND, PARTIAL_REFUND, NO_ACTION, PENALTY, ADJUSTMENT, BANNED, WARNING |
| `resolution_amount` | NUMERIC(20,8) | Adjusted amount |
| `compensation_movement_id` | UUID | FK to `core.movement_headers` |
| `evidence_document_ids` | UUID[] | Supporting documents |

**Automation**:
- `BEFORE UPDATE` trigger logs all status transitions to `core.dispute_status_history`
- Auto-sets `closed_at` on terminal states

**View**:
- `core.open_disputes` – unresolved disputes

---

### 4.2 `core.regulatory_flags`
**Purpose**: Compliance enforcement state for accounts and vehicles.

| Column | Type | Description |
|--------|------|-------------|
| `flag_id` | UUID | Primary key |
| `flag_reference` | VARCHAR(100) | e.g., `REG-ZTA-001` |
| `target_type` | VARCHAR(50) | ACCOUNT or VEHICLE |
| `target_id` | UUID | Account or vehicle ID |
| `flag_type` | VARCHAR(50) | SUSPENSION, CRW_EXPIRY, TAX_DELINQUENCY, SAFETY_VIOLATION, FRAUD, LICENSE_EXPIRY, INSURANCE_LAPSE, COMPLIANCE_FAILURE |
| `flag_severity` | VARCHAR(20) | LOW, MEDIUM, HIGH, CRITICAL |
| `issuing_authority` | VARCHAR(100) | ZTA, VID, ZIMRA, PLATFORM |
| `blocks_online_status` | BOOLEAN | Prevents going online |
| `blocks_booking` | BOOLEAN | Prevents accepting bookings |
| `blocks_payout` | BOOLEAN | Prevents withdrawals |
| `valid_from` / `valid_to` | TIMESTAMPTZ | Enforcement period |
| `cleared_by` / `cleared_at` | UUID / TIMESTAMPTZ | Resolution tracking |

**View**:
- `core.active_regulatory_flags` – currently enforceable flags

**Functions**:
- `core.check_account_eligibility(account_id, app_id, check_type)` – returns blocking flags
- `core.check_vehicle_regulatory_status(vehicle_id, app_id)` – returns blocking flags

---

## 5. Fare & Financial Configuration Primitives

### 5.1 `core.fare_parameters`
**Purpose**: Immutable, versioned fare configuration.

| Column | Type | Description |
|--------|------|-------------|
| `fare_parameter_id` | UUID | Primary key |
| `parameter_code` | VARCHAR(50) | e.g., `ZW_HRE_STANDARD` |
| `application_id` | UUID | Tenant |
| `zone_id` | UUID | Optional zone scope |
| `route_id` | UUID | Optional route scope |
| `vehicle_type` | VARCHAR(50) | STANDARD, PREMIUM, etc. |
| `base_fare` | NUMERIC(20,8) | Flat starting fare |
| `distance_rate_per_km` | NUMERIC(20,8) | Per-kilometer rate |
| `time_rate_per_minute` | NUMERIC(20,8) | Per-minute rate |
| `minimum_fare` | NUMERIC(20,8) | Floor price |
| `cancellation_fee` | NUMERIC(20,8) | Cancellation charge |
| `surge_cap` / `surge_floor` | NUMERIC(5,2) | Surge bounds |
| `free_waiting_minutes` | INTEGER | Grace period |
| `waiting_rate_per_minute` | NUMERIC(20,8) | Waiting charge |
| `night_premium_multiplier` | NUMERIC(5,2) | Night rate multiplier |
| `currency` | VARCHAR(3) | Default `USD` |

**Functions**:
- `core.calculate_trip_fare(...)` – point-in-time fare calculation
- `core.get_fare_parameters_at_time(...)` – historical parameter lookup

**View**:
- `core.current_fare_parameters` – active configurations only

---

### 5.2 `core.fee_structures`
**Purpose**: Platform commission, tax, and levy configurations.

| Column | Type | Description |
|--------|------|-------------|
| `fee_structure_id` | UUID | Primary key |
| `structure_code` | VARCHAR(50) | e.g., `ZW_TRANSPORT_STD` |
| `platform_fee_type` | VARCHAR(20) | PERCENTAGE or FIXED |
| `platform_fee_value` | NUMERIC(20,8) | 0.15 = 15% or fixed amount |
| `platform_fee_cap` / `platform_fee_floor` | NUMERIC(20,8) | Bounds |
| `tax_rate` | NUMERIC(20,8) | Government tax percentage |
| `tax_coa_code` | VARCHAR(50) | Chart of accounts mapping |
| `fuel_surcharge_enabled` / `fuel_surcharge_rate` | BOOLEAN / NUMERIC | Fuel adjustment |
| `municipal_levy_enabled` / `municipal_levy_rate` | BOOLEAN / NUMERIC | Municipal charge |
| `insurance_levy_enabled` / `insurance_levy_rate` | BOOLEAN / NUMERIC | Insurance charge |

**Functions**:
- `core.calculate_fee_breakdown(app_id, fare_amount, currency, as_of)` – returns driver earnings

**View**:
- `core.current_fee_structures` – active configurations only

---

### 5.3 `core.regulatory_parameters`
**Purpose**: ZTA-mandated and government regulatory thresholds.

| Column | Type | Description |
|--------|------|-------------|
| `regulatory_param_id` | UUID | Primary key |
| `param_code` | VARCHAR(50) | e.g., `ZTA_SURGE_CAP` |
| `param_category` | VARCHAR(50) | MAX_FARE, MIN_FARE, INSPECTION_INTERVAL, TAX_THRESHOLD, DAILY_LIMIT, WITHHOLDING_RATE, SURGE_CAP, OPERATING_HOURS |
| `issuing_authority` | VARCHAR(100) | ZTA, VID, ZIMRA, MUNICIPAL |
| `param_value_numeric` | NUMERIC(20,8) | Numeric threshold |
| `param_value_string` | VARCHAR(500) | Text threshold |
| `param_value_json` | JSONB | Complex threshold |
| `param_unit` | VARCHAR(50) | USD, KM, DAYS, PERCENT, MULTIPLIER |
| `is_enforced` | BOOLEAN | Active enforcement |
| `enforcement_action` | VARCHAR(50) | BLOCK, WARN, FLAG |

**View**:
- `core.current_regulatory_parameters` – active configurations only

---

## 6. Application-Layer Transport Tables

### 6.1 `app.driver_status_cache`
**Purpose**: Real-time driver operational status cache.

| Column | Type | Description |
|--------|------|-------------|
| `cache_id` | UUID | Primary key |
| `driver_account_id` | UUID | Unique per driver+app |
| `online_status` | VARCHAR(20) | ONLINE, OFFLINE, BUSY, BREAK |
| `last_latitude` / `last_longitude` | NUMERIC | Last known location |
| `matched_zone_id` | UUID | Current zone |
| `active_vehicle_id` | UUID | Currently assigned vehicle |
| `active_trip_transaction_id` | UUID | Current trip (if BUSY) |
| `accepts_rides` / `accepts_shared` / `accepts_delivery` | BOOLEAN | Service preferences |
| `today_trips_count` / `today_earnings` | INTEGER / NUMERIC | Daily metrics |
| `acceptance_rate` / `rating_average` | NUMERIC | Performance metrics |

**Automation**:
- `BEFORE UPDATE` trigger logs status changes to `app.driver_status_history`

**View**:
- `app.available_drivers` – drivers currently online and eligible for assignment

---

### 6.2 `app.favorite_locations`
**Purpose**: Rider saved pickup/dropoff locations.

| Column | Type | Description |
|--------|------|-------------|
| `location_id` | UUID | Primary key |
| `rider_account_id` | UUID | Owner |
| `location_label` | VARCHAR(50) | Home, Work, etc. |
| `address_text` | TEXT | Human-readable address |
| `landmark` | VARCHAR(255) | Nearby landmark |
| `latitude` / `longitude` | NUMERIC | Optional coordinates |
| `matched_zone_id` | UUID | Zone for fare calculation |
| `usage_count` | INTEGER | Frequency of use |

---

### 6.3 `app.promo_codes`
**Purpose**: Promotional discount campaigns.

| Column | Type | Description |
|--------|------|-------------|
| `promo_id` | UUID | Primary key |
| `promo_code` | VARCHAR(50) | User-entered code |
| `discount_type` | VARCHAR(20) | PERCENTAGE or FIXED_AMOUNT |
| `discount_value` | NUMERIC(20,8) | Discount amount |
| `max_discount_amount` | NUMERIC(20,8) | Cap for percentage discounts |
| `minimum_trip_fare` | NUMERIC(20,8) | Eligibility floor |
| `new_users_only` | BOOLEAN | First-time rider restriction |
| `total_usage_limit` / `per_user_limit` | INTEGER | Usage caps |
| `current_usage_count` | INTEGER | Redemptions so far |
| `valid_from` / `valid_to` | TIMESTAMPTZ | Campaign period |

**Related Table**:
- `app.promo_code_usages` – immutable redemption log

**Functions**:
- `app.validate_promo_code(...)` – comprehensive validation including user limits, zone applicability, and new-user checks

---

## 7. Seed Data Summary

### 7.1 Transaction Types Added
| Type Code | Description | Approvals |
|-----------|-------------|-----------|
| `RIDE_REQUEST` | Passenger requests a ride | 0 |
| `DRIVER_ASSIGNMENT` | System assigns driver | 0 |
| `TRIP_START` | Driver marks trip started | 0 |
| `TRIP_COMPLETE` | Driver marks trip completed | 0 |
| `RATING` | Mutual rider/driver rating | 0 |
| `CANCELLATION_FEE` | Fee for cancelled ride | 0 |
| `PAYOUT_REQUEST` | Driver earnings payout | 1 |
| `PROMO_APPLIED` | Discount applied to fare | 0 |

### 7.2 Roles Added
| Role Code | Description |
|-----------|-------------|
| `RIDER` | Passenger requesting rides |
| `DRIVER` | Transport service provider |
| `FLEET_MANAGER` | Oversees multiple drivers |
| `TRANSPORT_ADMIN` | Platform operator |

### 7.3 Default Configuration
- **Fare Parameters**: `ZW_HRE_STANDARD` (base $2.00, $0.80/km) and `ZW_HRE_PREMIUM` (base $4.00, $1.50/km)
- **Fee Structure**: `ZW_TRANSPORT_STD` (15% platform fee, $10 cap)
- **Regulatory Parameters**: ZTA surge cap (3.0x), VID inspection interval (180 days), driver daily payout limit ($500)
- **Zones**: Harare (city) and Harare CBD (district)
- **Promo Code**: `WELCOMEZW` (25% off first ride, new users only)

### 7.4 Chart of Accounts Additions
- **Income**: `4.1.1` Ride Fare Income, `4.1.2` Cancellation Fee Income, `4.3.1` Driver Commission
- **Expense**: `5.1.1` Driver Payouts, `5.1.2` Settlement Fees, `5.1.3` Mobile Money Charges, `5.3.1` Promo Code Redemptions
- **Liability**: `2.3.1` Driver Earnings Payable, `2.3.2` Pending Settlements, `2.4.1` Rider Wallet Balances

---

## 8. Integration with Existing Kernel Components

| Transport Feature | Kernel Component Used |
|-------------------|----------------------|
| Account creation | `core.accounts` + `app.account_memberships` |
| Ride request | `core.transaction_log` (type `RIDE_REQUEST`) |
| Driver assignment | `core.transaction_log` (type `DRIVER_ASSIGNMENT`) |
| Trip execution | `core.transaction_log` (types `TRIP_START`, `TRIP_COMPLETE`) |
| Fare calculation | `core.calculate_trip_fare()` reads `core.fare_parameters` |
| Payment (wallet) | `core.movement_headers` + `core.movement_legs` |
| Mobile money payout | `core.settlement_instructions` |
| Rating | `core.transaction_log` (type `RATING`) |
| Promo codes | `app.promo_codes` + `app.promo_code_usages` |
| Region fares | `core.fare_parameters` (zone-scoped) |
| Vehicle info | `core.vehicles` + `core.document_registry` |
| Driver online status | `app.driver_status_cache` (changes logged to `app.driver_status_history`) |
| Surge pricing | Real-time calculation stored in transaction payload |
| Dispute resolution | `core.disputes` + `core.dispute_status_history` |
| Regulatory compliance | `core.vehicle_compliance` + `core.regulatory_flags` |

---

## 9. Security & Compliance

### 9.1 Row-Level Security
All new core and app tables are designed for RLS enforcement:
- `core.zones`, `core.route_definitions`, `core.location_assertions` – isolated by `application_id`
- `core.vehicles`, `core.vehicle_assignments`, `core.vehicle_compliance` – driver sees own, fleet manager sees fleet, admin sees all
- `core.disputes` – participants see own disputes, admins see all
- `app.driver_status_cache` – driver sees own status only
- `app.favorite_locations` – rider sees own locations only

### 9.2 Immutability
- All `core.*` tables in this migration are append-only with `valid_from/valid_to` versioning
- `core.location_assertions` and `core.dispute_status_history` are strictly immutable (no updates/deletes)
- `core.vehicles`, `core.route_definitions`, `core.zones` use temporal exclusion constraints to prevent overlapping versions

### 9.3 Encryption
- Location coordinates in `app.driver_status_cache` and `app.favorite_locations` should be encrypted at rest in high-security deployments
- Document references in `core.vehicles` link to `core.document_registry` which already enforces encryption

---

## 10. Performance Considerations

### 10.1 Indexes
- All foreign keys are indexed
- Partial indexes on active/current records reduce query overhead
- GIST indexes on LTREE (`zone_path`) and GeoJSON boundaries
- BRIN indexes can be added to `core.location_assertions` for time-series optimization

### 10.2 Partitioning
- `core.location_assertions` is a high-volume time-series table and should be partitioned by `asserted_at` in production
- Recommended: monthly range partitions per `application_id`

### 10.3 Caching
- `app.driver_status_cache` serves as the operational cache for driver availability
- `app.available_drivers` view can be materialized for high-frequency assignment queries

---

## 11. Zimbabwe-Specific Alignment

| Requirement | Primitive | Implementation |
|-------------|-----------|----------------|
| ZTA route permits | `core.route_definitions` | `zta_permit_number`, `permit_expires_at` |
| VID inspections | `core.vehicle_compliance` | `VID_INSPECTION` type with expiry tracking |
| CRW validity | `core.vehicle_compliance` | `CRW` type linked to `core.document_registry` |
| Municipal levies | `core.fee_structures` | `municipal_levy_enabled/rate` |
| Taxi ranks/zones | `core.zones` | `zone_type = 'RANK'`, municipal authority linkage |
| Driver earnings payout | `core.settlement_instructions` | Mobile money and bank transfer methods |
| Fare disputes | `core.disputes` | `FARE_DISPUTE` category with compensation tracking |
| Surge pricing caps | `core.regulatory_parameters` | `ZTA_SURGE_CAP` parameter |

---

## 12. Migration Execution Order

```sql
-- 1. Baseline (must already be applied)
-- 2. Partitioning setup
-- 3. Archival policies
-- 4. Transport primitives (this migration)
\i database/migrations/0004_transport_primitives/up/001_transport_geospatial_primitives.sql
\i database/migrations/0004_transport_primitives/up/002_transport_vehicle_primitives.sql
\i database/migrations/0004_transport_primitives/up/003_transport_service_primitives.sql
\i database/migrations/0004_transport_primitives/up/004_transport_fare_primitives.sql
\i database/migrations/0004_transport_primitives/up/005_transport_app_tables.sql
\i database/migrations/0004_transport_primitives/up/006_transport_seed_data.sql
```

---

*Document Version: 1.0*  
*Last Updated: 2026-03-31*  
*Author: USSD Immutable Ledger Kernel Team*
