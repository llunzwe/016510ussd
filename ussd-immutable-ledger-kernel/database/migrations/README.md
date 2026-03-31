# USSD Immutable Ledger Database Migration Guide

## Overview

This directory contains database migration scripts for the USSD Immutable Ledger system. Migrations follow a semantic versioning approach with up/down scripts organized by migration number.

---

## Compliance

### ISO Standards Mapping

| ISO Standard | Requirement | Implementation |
|--------------|-------------|----------------|
| **ISO 27001:2022** | A.5.29 - Information security during disruption | Migration procedures ensure system availability during changes |
| **ISO 27001:2022** | A.5.30 - ICT readiness for business continuity | Rollback procedures for migration failures |
| **ISO 27001:2022** | A.5.37 - Documented operating procedures | This guide documents all migration procedures |
| **ISO 27031** | ICT readiness for business continuity | Change management and rollback compliance |
| **ISO 20000** | IT service management | Migration change management processes |
| **ISO 22301** | Business continuity management | Migration impact assessment and recovery |

### Regulatory Compliance

| Regulation | Compliance Requirement |
|------------|------------------------|
| **SOX Section 404** | Change management controls for financial systems |
| **GDPR Article 5(1)(f)** | Integrity protection during schema changes |
| **PCI DSS 4.0 Req 6.5.1** | Secure change control for cardholder data environment |
| **Basel III** | Operational risk management for database changes |

---

## Security Considerations

### Migration Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    MIGRATION SECURITY CONTROLS                   │
├─────────────────────────────────────────────────────────────────┤
│ 1. Access Control                                                │
│    - Migration execution: DB_ADMIN role only                     │
│    - Production changes: Two-person rule                         │
│    - Emergency changes: CDBA approval required                   │
├─────────────────────────────────────────────────────────────────┤
│ 2. Change Management                                             │
│    - All migrations require Change Advisory Board (CAB) approval │
│    - Emergency changes require post-hoc review within 24 hours   │
│    - Migration windows scheduled during low-traffic periods      │
├─────────────────────────────────────────────────────────────────┤
│ 3. Code Review                                                   │
│    - All migrations reviewed by Database Architect               │
│    - Security review for migrations touching auth/payment tables │
│    - Performance review for large table operations               │
├─────────────────────────────────────────────────────────────────┤
│ 4. Audit Trail                                                   │
│    - All migration executions logged to migration_audit_log      │
│    - DDL operations captured in database audit log               │
│    - Migration artifacts (backups) retained per policy           │
├─────────────────────────────────────────────────────────────────┤
│ 5. Rollback Capability                                           │
│    - Every migration must have tested rollback script            │
│    - Rollback procedures tested in staging before production     │
│    - Emergency rollback capability documented and tested         │
└─────────────────────────────────────────────────────────────────┘
```

### Migration Security Checklist

| Phase | Security Control | Verification |
|-------|-----------------|--------------|
| Development | No hardcoded credentials | Code review |
| Review | SQL injection prevention | Static analysis |
| Testing | Data masking in non-prod | Environment check |
| Deployment | Least privilege execution | Role verification |
| Post-deploy | Audit log verification | Log review |

---

## Audit Requirements

### Migration Audit Trail

All migrations are automatically logged to `migration_audit_log`:

| Field | Description | Retention |
|-------|-------------|-----------|
| migration_id | Unique migration identifier (e.g., 0001_baseline) | 10 years |
| operation | UP, DOWN, or VERIFY | 10 years |
| executed_at | Timestamp of execution | 10 years |
| executed_by | Database user who executed | 10 years |
| approver_reference | Change ticket or CAB reference | 10 years |
| checksum | SHA-256 of migration script | 10 years |
| status | IN_PROGRESS, COMPLETED, FAILED, ROLLED_BACK | 10 years |
| verification_result | Boolean result of post-migration verification | 10 years |

### Audit Query Examples

```sql
-- Migration history
SELECT 
    migration_id,
    operation,
    executed_at,
    executed_by,
    status,
    verification_result
FROM migration_audit_log
ORDER BY executed_at DESC;

-- Failed migrations requiring attention
SELECT 
    migration_id,
    executed_at,
    executed_by,
    approver_reference
FROM migration_audit_log
WHERE status = 'FAILED'
  AND executed_at > NOW() - INTERVAL '90 days';

-- Migration duration trends
SELECT 
    migration_id,
    EXTRACT(EPOCH FROM (executed_at - LAG(executed_at) OVER (ORDER BY executed_at)))/60 as minutes_since_previous
FROM migration_audit_log
WHERE status = 'COMPLETED'
ORDER BY executed_at DESC;
```

### Compliance Reporting

```sql
-- Monthly migration compliance report
SELECT 
    DATE_TRUNC('month', executed_at) as month,
    COUNT(*) FILTER (WHERE operation = 'UP') as upgrades,
    COUNT(*) FILTER (WHERE operation = 'DOWN') as rollbacks,
    COUNT(*) FILTER (WHERE status = 'FAILED') as failures,
    AVG(duration_ms) FILTER (WHERE status = 'COMPLETED') as avg_duration_ms
FROM migration_audit_log
WHERE executed_at > NOW() - INTERVAL '12 months'
GROUP BY DATE_TRUNC('month', executed_at)
ORDER BY month DESC;
```

---

## Data Protection Notes

### Migration Data Handling

| Data Type | Handling | Justification |
|-----------|----------|---------------|
| Production data | Never used in development | Data minimization (GDPR Article 5) |
| Test data | Synthetic or anonymized | Privacy by design |
| Migration logs | Retained 10 years | Audit requirements |
| Backup data | Encrypted, access controlled | Security and compliance |

### Cross-Border Considerations

- **Schema changes**: Synchronized across regions after validation
- **Data residency**: Migrations respect regional data boundaries
- **Audit logs**: Stored in same region as affected database

### Retention Policy

| Migration Artifact | Retention | Storage |
|-------------------|-----------|---------|
| Migration scripts | Indefinite | Version control (Git) |
| Audit logs | 10 years | Database + cold storage |
| Pre-migration backups | 90 days | Encrypted object storage |
| Post-migration verification | 7 years | Database |

---

## Directory Structure

```
migrations/
├── README.md                          # This file
├── 0001_baseline/                     # Initial schema deployment
│   ├── up/
│   │   └── 0001_baseline.sql
│   └── down/
│       └── 0001_baseline_rollback.sql
├── 0002_partitioning_setup/           # Table partitioning
│   ├── up/
│   │   └── 0002_partitioning_setup.sql
│   └── down/
│       └── .gitkeep                   # See note below
├── 0003_archival_policies/            # Data lifecycle management
│   ├── up/
│   │   └── 0003_archival_policies.sql
│   └── down/
│       └── .gitkeep                   # See note below
├── 0004_transport_primitives/         # Transport business primitives
│   ├── up/
│   │   ├── 001_transport_geospatial_primitives.sql
│   │   ├── 002_transport_vehicle_primitives.sql
│   │   ├── 003_transport_service_primitives.sql
│   │   ├── 004_transport_fare_primitives.sql
│   │   ├── 005_transport_app_tables.sql
│   │   ├── 006_transport_seed_data.sql
│   │   └── 007_transport_rls_policies.sql
│   └── down/
│       └── 0004_transport_primitives_rollback.sql
└── [future_migrations]/
```

## Migration Naming Convention

| Component | Format | Example |
|-----------|--------|---------|
| Migration ID | `NNNN_description` | `0001_baseline` |
| Up script | `{NNNN}_{description}.sql` | `0001_baseline.sql` |
| Down script | `{NNNN}_{description}_rollback.sql` | `0001_baseline_rollback.sql` |

## Migration List

| Version | Name | Description | Status | Date | Approver |
|---------|------|-------------|--------|------|----------|
| 0001 | baseline | Core schema, tables, enums, functions | Draft | TBD | Pending |
| 0002 | partitioning_setup | Range partitioning for ledger_entries | Draft | TBD | Pending |
| 0003 | archival_policies | Automated archival and compression | Draft | TBD | Pending |
| 0004 | transport_primitives | Zimbabwe transport business primitives | Draft | TBD | Pending |

## Migration Status Key

- **Draft** - Initial creation, not yet reviewed
- **Pending** - Reviewed, awaiting deployment
- **Applied** - Successfully deployed to environment
- **Rolled Back** - Previously applied, then reverted
- **Deprecated** - No longer supported

---

## Running Migrations

### Prerequisites

```bash
# Required environment variables
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=ussd_ledger
export DB_USER=ledger_admin
export DB_PASSWORD=********

# Optional: SSL settings
export DB_SSLMODE=require
export DB_SSLROOTCERT=/path/to/ca.crt

# Change ticket reference (required for production)
export CHANGE_TICKET="CHG-2025-001"
export APPROVER_REF="CDBA-20250330"
```

### Using psql (Manual)

```bash
# Run up migration
psql -h $DB_HOST -U $DB_USER -d $DB_NAME \
  -v approver="$APPROVER_REF" \
  -v ticket="$CHANGE_TICKET" \
  -f migrations/0001_baseline/up/0001_baseline.sql

# Run down migration
psql -h $DB_HOST -U $DB_USER -d $DB_NAME \
  -v approver="$APPROVER_REF" \
  -v ticket="$CHANGE_TICKET" \
  -f migrations/0001_baseline/down/0001_baseline_rollback.sql
```

### Using Migration Tool (Recommended)

```bash
# Install golang-migrate
# https://github.com/golang-migrate/migrate

# Run pending migrations
migrate -database "postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME?sslmode=require" \
  -path migrations up

# Rollback last migration
migrate -database "postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME?sslmode=require" \
  -path migrations down 1

# Check current version
migrate -database "postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME?sslmode=require" \
  -path migrations version
```

---

## Migration Safety Guidelines

### Pre-Migration Checklist

- [ ] Backup database before running migrations
- [ ] Test migration in non-production environment first
- [ ] Review migration script for:
  - [ ] Transaction safety (BEGIN/COMMIT/ROLLBACK)
  - [ ] Idempotency (can run multiple times safely)
  - [ ] Data preservation (no unintended data loss)
  - [ ] Performance impact (large table operations)
- [ ] Verify rollback script exists and is tested
- [ ] Schedule maintenance window if downtime expected
- [ ] Notify stakeholders of pending changes
- [ ] CAB approval obtained (production only)
- [ ] Change ticket reference documented

### Post-Migration Verification

```sql
-- Verify migration tracking table
SELECT * FROM schema_migrations ORDER BY version DESC LIMIT 5;

-- Verify core tables exist
SELECT table_name, table_type 
FROM information_schema.tables 
WHERE table_schema = 'public'
ORDER BY table_name;

-- Verify row counts (should not decrease unexpectedly)
SELECT 'ledger_entries' as table_name, COUNT(*) as row_count FROM ledger_entries
UNION ALL
SELECT 'accounts', COUNT(*) FROM accounts
UNION ALL
SELECT 'ussd_sessions', COUNT(*) FROM ussd_sessions;

-- Verify critical indexes
SELECT indexname, indexdef 
FROM pg_indexes 
WHERE schemaname = 'public'
  AND indexname LIKE 'idx_%';

-- Verify migration audit log
SELECT * FROM migration_audit_log 
WHERE migration_id = '0001_baseline' 
ORDER BY executed_at DESC LIMIT 1;
```

---

## Partitioning Strategy

The `ledger_entries` table is partitioned by `created_at` using monthly ranges:

```
ledger_entries_2024_01  - January 2024
ledger_entries_2024_02  - February 2024
...
ledger_entries_default  - Catch-all for unpartitioned data
```

### Partition Management

```sql
-- View current partitions
SELECT 
    parent.relname AS parent,
    child.relname AS partition,
    pg_get_expr(child.relpartbound, child.oid) AS constraint
FROM pg_inherits
JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
JOIN pg_class child ON pg_inherits.inhrelid = child.oid
WHERE parent.relname = 'ledger_entries';

-- Create new monthly partition (automated via cron)
SELECT create_monthly_partition(DATE_TRUNC('month', NOW() + INTERVAL '1 month'));

-- Archive old partition
SELECT detach_and_archive_partition('ledger_entries_2023_01');
```

---

## Archival Policies

### Default Retention

| Data Type | Hot Storage | Warm Storage | Cold Storage |
|-----------|-------------|--------------|--------------|
| Ledger Entries | 90 days | 1 year | Indefinite |
| Session Data | 30 days | 90 days | 1 year |
| Audit Logs | 1 year | 2 years | 7 years |

### Policy Configuration

```sql
-- View active policies
SELECT * FROM archival_policies WHERE is_active = true;

-- Temporarily disable archival
UPDATE archival_policies 
SET is_active = false 
WHERE policy_name = 'ledger_entries_monthly';

-- Force immediate archival (maintenance)
SELECT archive_partitions_older_than(NOW() - INTERVAL '90 days');
```

---

## Rollback Procedures

### Emergency Rollback

```bash
#!/bin/bash
# emergency_rollback.sh

TARGET_VERSION="0001"
BACKUP_PATH="/backups/ledger_$(date +%Y%m%d_%H%M%S).sql"
INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"

echo "Emergency Rollback - Incident: $INCIDENT_ID"
echo "Target Version: $TARGET_VERSION"

# Log rollback initiation
psql -c "
    INSERT INTO migration_audit_log (
        migration_id, operation, status, approver_reference, rollback_reason
    ) VALUES (
        '$TARGET_VERSION', 'DOWN', 'IN_PROGRESS', 
        'EMERGENCY-$INCIDENT_ID', 'Emergency rollback'
    );
"

echo "Creating emergency backup..."
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME > $BACKUP_PATH

echo "Rolling back to version $TARGET_VERSION..."
migrate -database "$DATABASE_URL" -path migrations goto $TARGET_VERSION

echo "Rollback complete. Backup saved to: $BACKUP_PATH"
```

### Selective Rollback

For partial rollback (specific tables only):

```sql
-- Example: Rollback only archival policies, keep baseline schema
BEGIN;
UPDATE archival_policies SET is_active = false;
SELECT cron.unschedule(jobid) FROM cron.job WHERE jobname LIKE 'ledger_%';
COMMIT;
```

---

## Troubleshooting

### Common Issues

#### Migration Locked

```sql
-- Check for blocking queries
SELECT * FROM pg_stat_activity WHERE wait_event_type = 'Lock';

-- Terminate blocking query (use with caution)
SELECT pg_terminate_backend(pid) FROM pg_stat_activity 
WHERE query LIKE '%CREATE INDEX%' AND state = 'active';
```

#### Dirty Migration State

```bash
# Force clean migration state
migrate -database "$DATABASE_URL" -path migrations force VERSION

# Example: Force to version 0001
migrate -database "$DATABASE_URL" -path migrations force 1
```

#### Partition Creation Failure

```sql
-- Check for data in default partition blocking creation
SELECT COUNT(*) FROM ledger_entries_default;

-- Move data to correct partition
SELECT move_data_from_default_partition();
```

---

## Environment-Specific Notes

### Production

- All migrations require CAB approval
- Rollback scripts must be tested in staging first
- Maintenance windows required for locking operations
- Data exports required before destructive changes
- Two-person rule for production changes

### Staging

- Auto-migration on deployment
- Nightly refresh from production (sanitized)
- Full rollback testing required before production promotion
- Migration performance testing

### Development

- Migrations can be reset freely
- Use `migrate drop` to clean and restart
- Seed data loaded after migrations
- Local migration testing encouraged

---

## Contributing

### Adding a New Migration

1. Create migration directory: `NNNN_descriptive_name/`
2. Create `up/` and `down/` subdirectories
3. Write up migration script with:
   - Transaction safety
   - Idempotency checks
   - Performance considerations
   - Rollback verification
4. Write down migration script
5. Update this README migration list
6. Submit for review with:
   - Migration purpose
   - Testing evidence
   - Rollback procedure tested
   - Performance impact assessment
   - CAB approval (if production)

### Migration Review Checklist

- [ ] Script follows naming convention
- [ ] Up script is idempotent
- [ ] Down script is complete
- [ ] Transaction boundaries are correct
- [ ] No hardcoded values (use parameters/config)
- [ ] Index creation uses CONCURRENTLY where possible
- [ ] Large table operations are batched
- [ ] Rollback has been tested
- [ ] Documentation is updated
- [ ] Security review completed (if applicable)
- [ ] Performance impact assessed

---

## Version Control Standards

### Git Workflow

```
feature/migration-NNNN-description
    |
    v
develop (integration testing)
    |
    v
staging (pre-production validation)
    |
    v
main (production)
```

### Commit Message Convention

```
migration(0001): add baseline schema

- Create core ledger tables with immutable design
- Implement hash chain for integrity verification
- Add partition support for ledger_entries

Relates-to: CHG-2025-001
Approved-by: Database Architect
```

### Tagging

Production releases are tagged:
```
git tag -a migration-0001-v1.0.0 -m "Baseline schema deployment"
git push origin migration-0001-v1.0.0
```

---

## Support

For migration issues contact:
- **Slack**: #database-ops
- **Email**: db-team@company.com
- **On-Call**: +1-xxx-xxx-xxxx

---

## License

Internal use only - USSD Immutable Ledger Kernel Project

---

## TODOs

- [ ] Implement migration CI/CD pipeline
- [ ] Add migration performance benchmarking
- [ ] Create migration dry-run mode
- [ ] Implement cross-region migration coordination
- [ ] Add migration rollback simulation
- [ ] Create migration dependency graph visualization
- [ ] Implement automatic migration testing framework
- [ ] Add migration security scanning
- [ ] Create migration documentation auto-generation
- [ ] Implement blue-green migration deployment
