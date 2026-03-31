# USSD Immutable Ledger Kernel

## Directory Structure

This directory contains the complete directory structure for the USSD Immutable Ledger Kernel.

```
ussd-immutable-ledger-kernel/
├── database/                    # All database-related files
│   ├── migrations/              # Versioned database migrations
│   │   ├── 0001_baseline/       # Initial schema creation
│   │   ├── 0002_partitioning_setup/
│   │   ├── 0003_archival_policies/
│   │   └── 0004_transport_primitives/  # Zimbabwe transport business
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

- **Total Files**: 250+
- **Migrations**: 63 up + 5 down + 1 README
- **Schema Files**: 55+ tables + 30+ functions + 8 triggers + 1 policies + 12 views + 3 indexes
- **App Schema**: 19 tables + 7 functions + 4 views + 1 indexes
- **USSD Gateway**: 5 tables + 9 functions + 1 indexes
- **Config**: 8 files
- **Procedures**: 9 files
- **Tests**: 9 files
- **Docs**: 9 files

## Migration Order

Execute migrations in numerical order:

1. `0001_baseline/up/` - Creates core and app schemas
2. `0002_partitioning_setup/up/` - Sets up hypertables
3. `0003_archival_policies/up/` - Configures data lifecycle
4. `0004_transport_primitives/up/` - Adds Zimbabwe transport business primitives

## Original SQL Folder

The original working SQL files remain in the parent directory's `sql/` folder:
- `sql/core/` - Core schema files
- `sql/app/` - App schema files

This directory structure provides the full enterprise-grade organization template.
