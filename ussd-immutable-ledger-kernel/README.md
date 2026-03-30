# USSD Immutable Ledger Kernel

## Directory Structure

This directory contains the complete directory structure for the USSD Immutable Ledger Kernel.

```
ussd-immutable-ledger-kernel/
├── database/                    # All database-related files
│   ├── migrations/              # Versioned database migrations
│   │   ├── 0001_baseline/       # Initial schema creation
│   │   ├── 0002_partitioning_setup/
│   │   └── 0003_archival_policies/
│   ├── schema/                  # Schema definitions by component
│   │   ├── core/                # Core immutable ledger schema
│   │   ├── app/                 # Application layer schema
│   │   └── ussd_gateway/        # USSD-specific session handling
│   ├── partitions/              # Partitioning configuration
│   ├── replication/             # Logical and physical replication
│   ├── security/                # RLS, encryption, audit
│   ├── jobs/                    # Background workers and cron jobs
│   └── utils/                   # Extensions, helpers, seed data
├── config/                      # Configuration files
│   ├── postgresql/              # PostgreSQL configuration
│   ├── partitioning/            # Partition strategy YAML
│   └── monitoring/              # Prometheus/Grafana config
├── procedures/                  # Operational procedures
│   ├── disaster_recovery/       # PITR, rebuild, restore
│   ├── compliance/              # GDPR, legal hold, reporting
│   └── maintenance/             # Vacuum, reindex, tuning
├── tests/                       # Test suites
│   ├── integrity/               # Hash chain, Merkle tests
│   ├── performance/             # Load tests, benchmarks
│   └── security/                # RLS, encryption, fraud tests
└── docs/                        # Documentation
    ├── schema_documentation/    # ERDs and schema docs
    ├── runbooks/                # Operational runbooks
    └── api/                     # API specifications
```

## File Count

- **Total Files**: 227
- **Migrations**: 55 up + 3 down + 1 README
- **Schema Files**: 30 tables + 15 functions + 3 triggers + 1 policies + 3 views + 3 indexes
- **App Schema**: 16 tables + 6 functions + 3 views + 1 indexes
- **USSD Gateway**: 5 tables + 9 functions + 1 indexes
- **Config**: 8 files
- **Procedures**: 9 files
- **Tests**: 9 files
- **Docs**: 8 files

## Migration Order

Execute migrations in numerical order:

1. `0001_baseline/up/` - Creates core and app schemas
2. `0002_partitioning_setup/up/` - Sets up hypertables
3. `0003_archival_policies/up/` - Configures data lifecycle

## Original SQL Folder

The original working SQL files remain in the parent directory's `sql/` folder:
- `sql/core/` - Core schema files
- `sql/app/` - App schema files

This directory structure provides the full enterprise-grade organization template.
