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
-- TODO: Core Schema Indexes
-- DESCRIPTION: Optimize core ledger queries
-- PRIORITY: CRITICAL
-- SECURITY: No PII in index names
-- PERFORMANCE: Covering indexes for frequent queries
-- =============================================================================
-- TODO: [IDX-001] Create core schema indexes
-- INSTRUCTIONS:
--   -- accounts table
--   CREATE INDEX idx_accounts_number ON core.accounts(account_number);
--   CREATE INDEX idx_accounts_application ON core.accounts(application_id) 
--       WHERE valid_to IS NULL;
--   CREATE INDEX idx_accounts_status ON core.accounts(status) 
--       WHERE valid_to IS NULL;
--   CREATE INDEX idx_accounts_path ON core.accounts USING GIST(account_path);
--   CREATE INDEX idx_accounts_metadata ON core.accounts USING GIN(metadata);
--   
--   -- transaction_log indexes (partition-aware)
--   CREATE INDEX idx_transactions_initiator ON core.transaction_log(initiator_account_id, created_at DESC);
--   CREATE INDEX idx_transactions_beneficiary ON core.transaction_log(beneficiary_account_id, created_at DESC);
--   CREATE INDEX idx_transactions_correlation ON core.transaction_log(correlation_id);
--   CREATE INDEX idx_transactions_status ON core.transaction_log(status, created_at) 
--       WHERE status = 'PENDING';
--   CREATE INDEX idx_transactions_payload ON core.transaction_log USING GIN(payload jsonb_path_ops);
--   CREATE INDEX idx_transactions_reference ON core.transaction_log(transaction_reference);
--   
--   -- movement_headers indexes
--   CREATE INDEX idx_movements_status ON core.movement_headers(status, entry_date);
--   CREATE INDEX idx_movements_batch ON core.movement_headers(batch_id);
--   CREATE INDEX idx_movements_correlation ON core.movement_headers(correlation_id);
--   CREATE INDEX idx_movements_application ON core.movement_headers(application_id, entry_date);
--   
--   -- movement_legs indexes
--   CREATE INDEX idx_legs_account ON core.movement_legs(account_id, created_at DESC);
--   CREATE INDEX idx_legs_coa ON core.movement_legs(coa_code, account_id, created_at DESC);
--   
--   -- movement_postings indexes (TimescaleDB hypertable)
--   CREATE INDEX idx_postings_account ON core.movement_postings(account_id, posted_at DESC);
--   CREATE INDEX idx_postings_period ON core.movement_postings(accounting_period, account_id);

-- =============================================================================
-- TODO: App Schema Indexes
-- DESCRIPTION: Optimize application queries
-- PRIORITY: HIGH
-- PERFORMANCE: Support high-volume application workloads
-- =============================================================================
-- TODO: [IDX-002] Create app schema indexes
-- INSTRUCTIONS:
--   -- applications
--   CREATE INDEX idx_apps_status ON app.applications(status) WHERE is_current = true;
--   
--   -- account_memberships
--   CREATE INDEX idx_memberships_account ON app.account_memberships(account_id, is_current) 
--       WHERE is_current = true;
--   CREATE INDEX idx_memberships_app ON app.account_memberships(application_id, is_current) 
--       WHERE is_current = true;
--   
--   -- roles
--   CREATE INDEX idx_roles_app ON app.roles(application_id, status) WHERE valid_to IS NULL;
--   
--   -- user_role_assignments
--   CREATE INDEX idx_role_assignments ON app.user_role_assignments(account_id, application_id)
--       WHERE is_active = true AND valid_to IS NULL;
--   
--   -- configuration
--   CREATE INDEX idx_config_lookup ON app.configuration(application_id, environment, config_key) 
--       WHERE is_active = true;

-- =============================================================================
-- TODO: USSD Schema Indexes
-- DESCRIPTION: Optimize USSD session queries
-- PRIORITY: HIGH
-- PERFORMANCE: Critical for USSD response time (< 2 seconds)
-- PII: Indexes on encrypted columns use hash values
-- =============================================================================
-- TODO: [IDX-003] Create ussd schema indexes
-- INSTRUCTIONS:
--   -- ussd_sessions
--   CREATE INDEX idx_sessions_msisdn ON ussd.ussd_sessions(msisdn, status, expires_at);
--   CREATE INDEX idx_sessions_account ON ussd.ussd_sessions(account_id, last_activity_at DESC);
--   
--   -- pending_ussd_transactions
--   CREATE INDEX idx_pending_session ON ussd.pending_ussd_transactions(session_id, status);
--   CREATE INDEX idx_pending_expiry ON ussd.pending_ussd_transactions(status, expires_at) 
--       WHERE status = 'PENDING';

-- =============================================================================
-- TODO: Audit and Archive Indexes
-- DESCRIPTION: Optimize audit queries
-- PRIORITY: MEDIUM
-- PERFORMANCE: Support 7-year query performance
-- =============================================================================
-- TODO: [IDX-004] Create audit/archive indexes
-- INSTRUCTIONS:
--   -- audit_logs
--   CREATE INDEX idx_audit_table ON audit.audit_log(table_schema, table_name, occurred_at);
--   CREATE INDEX idx_audit_actor ON audit.audit_log(actor_id, occurred_at);
--   
--   -- archive_manifest
--   CREATE INDEX idx_archive_lookup ON archive.archive_manifest(source_schema, source_table, source_record_id);

-- =============================================================================
-- TODO: Exclusion Constraints
-- DESCRIPTION: Temporal validity constraints
-- PRIORITY: HIGH
-- DATA INTEGRITY: Prevents overlapping valid periods
-- =============================================================================
-- TODO: [IDX-005] Create exclusion constraints
-- INSTRUCTIONS:
--   -- Prevent overlapping valid periods
--   ALTER TABLE core.accounts ADD CONSTRAINT no_overlapping_account_versions
--       EXCLUDE USING gist (account_number WITH =, valid_during WITH &&) 
--       WHERE (valid_to IS NULL);
--   
--   ALTER TABLE app.account_memberships ADD CONSTRAINT no_overlapping_memberships
--       EXCLUDE USING gist (account_id WITH =, application_id WITH =, valid_during WITH &&)
--       WHERE (valid_to IS NULL);
--   
--   ALTER TABLE app.user_role_assignments ADD CONSTRAINT no_overlapping_roles
--       EXCLUDE USING gist (account_id WITH =, application_id WITH =, role_id WITH =, valid_during WITH &&)
--       WHERE (valid_to IS NULL);

-- =============================================================================
-- TODO: Check Constraints
-- DESCRIPTION: Data integrity constraints
-- PRIORITY: HIGH
-- SECURITY: Prevents invalid data that could bypass controls
-- =============================================================================
-- TODO: [IDX-006] Add check constraints
-- INSTRUCTIONS:
--   -- Positive amounts
--   ALTER TABLE core.movement_legs ADD CONSTRAINT positive_amount 
--       CHECK (amount > 0);
--   
--   -- Valid directions
--   ALTER TABLE core.movement_legs ADD CONSTRAINT valid_direction 
--       CHECK (direction IN ('DEBIT', 'CREDIT'));
--   
--   -- Valid statuses
--   ALTER TABLE core.movement_headers ADD CONSTRAINT valid_status 
--       CHECK (status IN ('DRAFT', 'PENDING', 'POSTED', 'REVERSING', 'REVERSED'));

-- =============================================================================
-- TODO: Statistics Collection
-- DESCRIPTION: Update table statistics
-- PRIORITY: MEDIUM
-- PERFORMANCE: Enable query planner optimization
-- =============================================================================
-- TODO: [IDX-007] Collect statistics
-- INSTRUCTIONS:
--   ANALYZE core.accounts;
--   ANALYZE core.transaction_log;
--   ANALYZE core.movement_headers;
--   ANALYZE core.movement_legs;

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
□ Create core schema indexes
□ Create app schema indexes
□ Create ussd schema indexes
□ Create audit/archive indexes
□ Add exclusion constraints for temporal validity
□ Add check constraints for data integrity
□ Collect table statistics
□ Verify index coverage for common queries
□ Test query performance
□ Review index sizes
□ Document index naming conventions
□ Set up index maintenance schedule
================================================================================
*/
