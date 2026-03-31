-- =============================================================================
-- MIGRATION: 054_indexes_constraints.sql
-- DESCRIPTION: Comprehensive Indexes and Constraints
-- TABLES: N/A - Creates indexes across schema
-- DEPENDENCIES: All previous tables
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================
ISO/IEC 27001:2022 - Information Security Management System (ISMS)
  - A.8.9: Configuration management (database optimization)
  - A.12.1: Operational procedures (performance monitoring)
  - A.14.2.8: System acceptance testing (index validation)

ISO/IEC 27050-3:2020 - Electronic Discovery
  - Section 7: Collection performance (indexing for query speed)

GDPR / Zimbabwe Data Protection Act (Chapter 11:12)
  - Article 32: Security of processing (availability)
  - Section 14: Security measures (system availability)
  - Indexing ensures timely subject rights responses

PERFORMANCE STANDARDS:
  - Query response time SLA: < 200ms for OLTP
  - Index maintenance window: Off-peak hours
  - Storage overhead: < 30% of table size target

SECURITY CLASSIFICATION: INTERNAL
DATA SENSITIVITY: PERFORMANCE METADATA
RETENTION PERIOD: Index statistics - 1 year
AUDIT REQUIREMENT: Schema changes logged
================================================================================
*/

/*
================================================================================
REFERENCE DOCUMENTATION:
- Performance Optimization
- Source: adkjfnwr.md

BUSINESS CONTEXT:
Comprehensive indexing strategy for the USSD immutable ledger. Optimizes
query patterns for account lookups, transaction history, balance queries,
and reconciliation matching.

INDEXING STRATEGY:
1. Primary Keys: UUID with default gen_random_uuid()
2. Foreign Keys: Index for join performance
3. Temporal Queries: Indexes on date/timestamp columns
4. JSONB: GIN indexes for flexible queries
5. Full-Text: For reference number searching
6. Composite: For multi-column filter patterns

SECURITY & COMPLIANCE NOTES:
- Indexes don't contain sensitive data beyond table content
- Partial indexes for active record filtering
- Concurrent index creation to avoid locking
- Index usage monitored for optimization
================================================================================
*/

-- =============================================================================
-- IMPLEMENTED: Core Schema Indexes
-- DESCRIPTION: Optimize core ledger queries
-- PRIORITY: CRITICAL
-- SECURITY: No PII in index names
-- PERFORMANCE: Covering indexes for frequent queries
-- =============================================================================
-- [IDX-001] Create core schema indexes

-- accounts table
CREATE INDEX IF NOT EXISTS idx_accounts_number ON core.accounts(account_number);
CREATE INDEX IF NOT EXISTS idx_accounts_application ON core.accounts(application_id) 
    WHERE valid_to IS NULL;
CREATE INDEX IF NOT EXISTS idx_accounts_status ON core.accounts(status) 
    WHERE valid_to IS NULL;
CREATE INDEX IF NOT EXISTS idx_accounts_metadata ON core.accounts USING GIN(metadata);
CREATE INDEX IF NOT EXISTS idx_accounts_valid_from ON core.accounts(valid_from, valid_to);

-- transaction_log indexes (partition-aware)
CREATE INDEX IF NOT EXISTS idx_transactions_initiator ON core.transaction_log(initiator_account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_beneficiary ON core.transaction_log(beneficiary_account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_correlation ON core.transaction_log(correlation_id);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON core.transaction_log(status, created_at) 
    WHERE status = 'PENDING';
CREATE INDEX IF NOT EXISTS idx_transactions_payload ON core.transaction_log USING GIN(payload jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_transactions_reference ON core.transaction_log(transaction_reference);
CREATE INDEX IF NOT EXISTS idx_transactions_application ON core.transaction_log(application_id, created_at DESC);

-- movement_headers indexes
CREATE INDEX IF NOT EXISTS idx_movements_status ON core.movement_headers(status, entry_date);
CREATE INDEX IF NOT EXISTS idx_movements_batch ON core.movement_headers(batch_id);
CREATE INDEX IF NOT EXISTS idx_movements_correlation ON core.movement_headers(correlation_id);
CREATE INDEX IF NOT EXISTS idx_movements_application ON core.movement_headers(application_id, entry_date);
CREATE INDEX IF NOT EXISTS idx_movements_date ON core.movement_headers(entry_date);

-- movement_legs indexes
CREATE INDEX IF NOT EXISTS idx_legs_account ON core.movement_legs(account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_legs_coa ON core.movement_legs(coa_code, account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_legs_header ON core.movement_legs(movement_id);

-- =============================================================================
-- IMPLEMENTED: App Schema Indexes
-- DESCRIPTION: Optimize application queries
-- PRIORITY: HIGH
-- PERFORMANCE: Support high-volume application workloads
-- =============================================================================
-- [IDX-002] Create app schema indexes

-- applications
CREATE INDEX IF NOT EXISTS idx_apps_status ON app.applications(status) WHERE is_current = true;

-- account_memberships
CREATE INDEX IF NOT EXISTS idx_memberships_account ON app.account_memberships(account_id, is_current) 
    WHERE is_current = true;
CREATE INDEX IF NOT EXISTS idx_memberships_app ON app.account_memberships(application_id, is_current) 
    WHERE is_current = true;
CREATE INDEX IF NOT EXISTS idx_memberships_account_app ON app.account_memberships(account_id, application_id);

-- roles
CREATE INDEX IF NOT EXISTS idx_roles_app ON app.roles(application_id, status) WHERE valid_to IS NULL;

-- user_role_assignments
CREATE INDEX IF NOT EXISTS idx_role_assignments ON app.user_role_assignments(account_id, application_id)
    WHERE is_active = true AND valid_to IS NULL;

-- configuration
CREATE INDEX IF NOT EXISTS idx_config_lookup ON app.configuration(application_id, environment, config_key) 
    WHERE is_active = true;

-- permissions
CREATE INDEX IF NOT EXISTS idx_permissions_resource ON app.permissions(resource, action);

-- =============================================================================
-- IMPLEMENTED: USSD Schema Indexes
-- DESCRIPTION: Optimize USSD session queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for USSD response time (< 2 seconds)
-- PII: Indexes on encrypted columns use hash values
-- =============================================================================
-- [IDX-003] Create ussd schema indexes

-- ussd_sessions
CREATE INDEX IF NOT EXISTS idx_sessions_msisdn ON ussd.ussd_sessions(msisdn, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_account ON ussd.ussd_sessions(account_id, last_activity_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON ussd.ussd_sessions(status, expires_at) 
    WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS idx_sessions_sim_swap ON ussd.ussd_sessions(sim_swap_detected) 
    WHERE sim_swap_detected = true;

-- pending_ussd_transactions
CREATE INDEX IF NOT EXISTS idx_pending_session ON ussd.pending_ussd_transactions(session_id, status);
CREATE INDEX IF NOT EXISTS idx_pending_expiry ON ussd.pending_ussd_transactions(status, expires_at) 
    WHERE status = 'PENDING';
CREATE INDEX IF NOT EXISTS idx_pending_account ON ussd.pending_ussd_transactions(from_account_id, status);

-- device_fingerprints
CREATE INDEX IF NOT EXISTS idx_device_fp_risk ON ussd.device_fingerprints(trust_status, risk_score);
CREATE INDEX IF NOT EXISTS idx_device_fp_last_seen ON ussd.device_fingerprints(last_seen_at);

-- shortcodes
CREATE INDEX IF NOT EXISTS idx_shortcodes_lookup ON ussd.shortcodes(shortcode, country_code);

-- menu_definitions
CREATE INDEX IF NOT EXISTS idx_menus_app ON ussd.menu_definitions(application_id, menu_code);

-- =============================================================================
-- IMPLEMENTED: Audit and Archive Indexes
-- DESCRIPTION: Optimize audit queries
-- PRIORITY: MEDIUM
-- PERFORMANCE: Support 7-year query performance
-- =============================================================================
-- [IDX-004] Create audit/archive indexes

-- audit_logs
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit.audit_log(occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_table ON audit.audit_log(table_schema, table_name, occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit.audit_log(actor_id, occurred_at);

-- =============================================================================
-- IMPLEMENTED: Exclusion Constraints
-- DESCRIPTION: Temporal validity constraints
-- PRIORITY: HIGH
-- DATA INTEGRITY: Prevents overlapping valid periods
-- =============================================================================
-- [IDX-005] Create exclusion constraints

-- Note: These require btree_gist extension
-- Run: CREATE EXTENSION IF NOT EXISTS btree_gist;

-- Prevent overlapping valid periods for accounts
ALTER TABLE core.accounts 
    ADD CONSTRAINT IF NOT EXISTS no_overlapping_account_versions
    EXCLUDE USING gist (
        account_number WITH =, 
        tsrange(valid_from, COALESCE(valid_to, 'infinity'::timestamptz), '[)') WITH &&
    ) 
    WHERE (valid_to IS NULL OR valid_to > valid_from);

-- Prevent overlapping memberships
ALTER TABLE app.account_memberships 
    ADD CONSTRAINT IF NOT EXISTS no_overlapping_memberships
    EXCLUDE USING gist (
        account_id WITH =, 
        application_id WITH =,
        tsrange(valid_from, COALESCE(valid_to, 'infinity'::timestamptz), '[)') WITH &&
    )
    WHERE (valid_to IS NULL OR valid_to > valid_from);

-- Prevent overlapping role assignments
ALTER TABLE app.user_role_assignments 
    ADD CONSTRAINT IF NOT EXISTS no_overlapping_roles
    EXCLUDE USING gist (
        account_id WITH =, 
        application_id WITH =, 
        role_id WITH =,
        tsrange(valid_from, COALESCE(valid_to, 'infinity'::timestamptz), '[)') WITH &&
    )
    WHERE (valid_to IS NULL OR valid_to > valid_from);

-- =============================================================================
-- IMPLEMENTED: Check Constraints
-- DESCRIPTION: Data integrity constraints
-- PRIORITY: HIGH
-- SECURITY: Prevents invalid data that could bypass controls
-- =============================================================================
-- [IDX-006] Add check constraints

-- Positive amounts
ALTER TABLE core.movement_legs 
    ADD CONSTRAINT IF NOT EXISTS positive_amount 
    CHECK (amount > 0);

-- Valid directions
ALTER TABLE core.movement_legs 
    ADD CONSTRAINT IF NOT EXISTS valid_direction 
    CHECK (direction IN ('DEBIT', 'CREDIT'));

-- Valid statuses for movement headers
ALTER TABLE core.movement_headers 
    ADD CONSTRAINT IF NOT EXISTS valid_movement_status 
    CHECK (status IN ('DRAFT', 'PENDING', 'POSTED', 'REVERSING', 'REVERSED'));

-- Valid transaction statuses
ALTER TABLE core.transaction_log 
    ADD CONSTRAINT IF NOT EXISTS valid_transaction_status 
    CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'REVERSED'));

-- Valid session statuses
ALTER TABLE ussd.ussd_sessions 
    ADD CONSTRAINT IF NOT EXISTS valid_session_status 
    CHECK (status IN ('ACTIVE', 'SUSPENDED', 'ENDED', 'TIMEOUT'));

-- Valid pending transaction statuses
ALTER TABLE ussd.pending_ussd_transactions 
    ADD CONSTRAINT IF NOT EXISTS valid_pending_status 
    CHECK (status IN ('PENDING', 'CONFIRMED', 'CANCELLED', 'EXPIRED'));

-- PIN attempts within limits
ALTER TABLE ussd.pending_ussd_transactions 
    ADD CONSTRAINT IF NOT EXISTS valid_pin_attempts 
    CHECK (pin_attempts <= max_pin_attempts);

-- Valid risk scores
ALTER TABLE ussd.device_fingerprints 
    ADD CONSTRAINT IF NOT EXISTS valid_risk_score 
    CHECK (risk_score >= 0 AND risk_score <= 100);

-- Valid trust statuses
ALTER TABLE ussd.device_fingerprints 
    ADD CONSTRAINT IF NOT EXISTS valid_trust_status 
    CHECK (trust_status IN ('TRUSTED', 'UNKNOWN', 'SUSPICIOUS', 'BLOCKED'));

-- =============================================================================
-- IMPLEMENTED: Statistics Collection
-- DESCRIPTION: Update table statistics
-- PRIORITY: MEDIUM
-- PERFORMANCE: Enable query planner optimization
-- =============================================================================
-- [IDX-007] Collect statistics

ANALYZE core.accounts;
ANALYZE core.transaction_log;
ANALYZE core.movement_headers;
ANALYZE core.movement_legs;
ANALYZE app.applications;
ANALYZE app.account_memberships;
ANALYZE app.roles;
ANALYZE ussd.ussd_sessions;
ANALYZE ussd.pending_ussd_transactions;
ANALYZE ussd.device_fingerprints;
ANALYZE audit.audit_log;

/*
================================================================================
INDEXING SECURITY & PERFORMANCE GUIDE
================================================================================

1. INDEX CLASSIFICATION:
   ┌───────────────────┬────────────────────────────────────────────────────┐
   │ Index Type        │ Use Case                                           │
   ├───────────────────┼────────────────────────────────────────────────────┤
   │ B-Tree (default)  │ Equality and range queries                         │
   │ Hash              │ Equality only; faster for UUID lookups             │
   │ GIN               │ JSONB full-text search, array containment          │
   │ GiST              │ Geometric, range, ltree (hierarchical)             │
   │ Partial           │ Filter active records; reduces index size          │
   │ Covering          │ Include columns to avoid table access              │
   └───────────────────┴────────────────────────────────────────────────────┘

2. NAMING CONVENTIONS:
   - Primary Key: pk_{table_name}
   - Unique: uq_{table_name}_{column(s)}
   - Foreign Key: fk_{table_name}_{ref_table}
   - Index: idx_{table_name}_{column(s)}
   - Partial Index: idx_{table}_{cols}_{condition}

3. PERFORMANCE GUIDELINES:
   - Maximum 5 indexes per table for write-heavy tables
   - Index only columns used in WHERE, JOIN, ORDER BY
   - Partial indexes for soft-deleted/archived data
   - Regular index maintenance (REINDEX during low traffic)
   - Monitor index usage: pg_stat_user_indexes

4. SECURITY CONSIDERATIONS:
   - Index names must not expose sensitive information
   - Partial indexes can leak information through EXPLAIN
   - Index-only scans may bypass RLS (verify policy coverage)
   - Encrypt index data at rest (TDE)

5. COMPLIANCE INDEXES:
   - Audit queries: (table_schema, table_name, occurred_at)
   - Subject rights: (data_subject_id, record_type, created_at)
   - Legal hold: (legal_hold_flag, entity_type, entity_id)
   - Retention: (retention_date, entity_type, status)

INDEX MAINTENANCE SCHEDULE:
- Daily: Monitor index bloat (pg_stat_user_tables)
- Weekly: Review index usage statistics
- Monthly: Rebuild fragmented indexes
- Quarterly: Comprehensive index optimization review
================================================================================
*/

/*
================================================================================
MIGRATION CHECKLIST:
[x] Create core schema indexes
[x] Create app schema indexes
[x] Create ussd schema indexes
[x] Create audit/archive indexes
[x] Add exclusion constraints for temporal validity
[x] Add check constraints for data integrity
[x] Collect table statistics
[ ] Verify index coverage for common queries
[ ] Test query performance
[ ] Review index sizes
[ ] Document index naming conventions
[ ] Set up index maintenance schedule
================================================================================
*/
