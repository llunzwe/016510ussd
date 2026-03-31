# Enterprise Deployment Guide
## USSD Immutable Ledger Kernel

This guide provides step-by-step instructions for deploying the USSD Immutable Ledger Kernel with all enterprise-grade enhancements.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Database Installation](#database-installation)
4. [Migration Execution](#migration-execution)
5. [Post-Deployment Verification](#post-deployment-verification)
6. [Application Integration](#application-integration)
7. [Monitoring Setup](#monitoring-setup)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| PostgreSQL | 14.x | 15.x or 16.x |
| CPU | 4 cores | 8+ cores |
| RAM | 16 GB | 32+ GB |
| Storage | 500 GB SSD | 1+ TB NVMe SSD |
| Network | 1 Gbps | 10 Gbps |

### Required PostgreSQL Extensions

```sql
-- Install required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "ltree";
CREATE EXTENSION IF NOT EXISTS "btree_gist";  -- For exclusion constraints
```

### Required Privileges

```sql
-- Create application role
CREATE ROLE ussd_app WITH LOGIN PASSWORD 'secure_password';

-- Grant schema privileges
GRANT USAGE ON SCHEMA core, app, ussd, security, audit TO ussd_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA core, app, ussd TO ussd_app;
```

---

## Environment Setup

### 1. Database Configuration

```bash
# postgresql.conf settings for immutable ledger
shared_preload_libraries = 'pgcrypto'
max_connections = 200
shared_buffers = 8GB
effective_cache_size = 24GB
work_mem = 32MB
maintenance_work_mem = 2GB
wal_buffers = 16MB
default_transaction_isolation = 'read committed'
```

### 2. Environment Variables

```bash
# .env file for application
DATABASE_URL=postgresql://ussd_app:secure_password@localhost:5432/ussd_ledger
APP_ENCRYPTION_KEY=your-256-bit-encryption-key
AUDIT_LOG_LEVEL=INFO
RLS_ENABLED=true
IMMUTABILITY_ENFORCED=true
```

### 3. Application Context Settings

```sql
-- Set these for each database connection
SET app.current_application_id = 'your-app-uuid';
SET app.current_account_id = 'user-account-uuid';
SET app.is_admin = 'false';
SET app.encryption_key = 'your-encryption-key';
```

---

## Database Installation

### Step 1: Create Database

```bash
# Create database
createdb -U postgres -E UTF8 -T template0 ussd_ledger

# Enable required extensions
psql -U postgres -d ussd_ledger -c "CREATE EXTENSION IF NOT EXISTS uuid-ossp;"
psql -U postgres -d ussd_ledger -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
psql -U postgres -d ussd_ledger -c "CREATE EXTENSION IF NOT EXISTS ltree;"
psql -U postgres -d ussd_ledger -c "CREATE EXTENSION IF NOT EXISTS btree_gist;"
```

### Step 2: Execute Migrations in Order

```bash
#!/bin/bash
# deploy.sh - Migration execution script

DB_NAME="ussd_ledger"
DB_USER="postgres"
MIGRATIONS_DIR="database/migrations/0001_baseline/up"

echo "Starting migration deployment..."

# Standard migrations (001-055)
for file in $(ls $MIGRATIONS_DIR/*.sql | sort); do
    echo "Applying: $file"
    psql -U $DB_USER -d $DB_NAME -f "$file"
    if [ $? -ne 0 ]; then
        echo "ERROR: Migration failed: $file"
        exit 1
    fi
done

# Enterprise fix migrations (997-999)
echo "Applying enterprise enhancements..."
psql -U $DB_USER -d $DB_NAME -f "$MIGRATIONS_DIR/997_integrity_and_archive_enhancements.sql"
psql -U $DB_USER -d $DB_NAME -f "$MIGRATIONS_DIR/998_app_schema_enhancements.sql"
psql -U $DB_USER -d $DB_NAME -f "$MIGRATIONS_DIR/999_enterprise_fk_and_immutability_fixes.sql"

echo "Migration deployment complete!"
```

### Step 3: Verify Installation

```sql
-- Check schema objects
SELECT schemaname, tablename, tableowner 
FROM pg_tables 
WHERE schemaname IN ('core', 'app', 'ussd');

-- Check extensions
SELECT extname, extversion FROM pg_extension;

-- Check constraints
SELECT conname, contype, conrelid::regclass 
FROM pg_constraint 
WHERE connamespace IN ('core'::regnamespace, 'app'::regnamespace);
```

---

## Migration Execution

### Migration Order

| Order | File | Description |
|-------|------|-------------|
| 001 | create_schemas.sql | Schema creation |
| 002 | core_extensions.sql | Extensions setup |
| 003 | core_account_registry.sql | Account tables |
| 004 | core_transaction_log.sql | Transaction log |
| 005 | core_movement_legs.sql | Double-entry |
| 006 | core_movement_postings.sql | Postings |
| 007 | core_blocks_merkle.sql | Blocks, Merkle |
| ... | ... | ... |
| 031 | app_registry.sql | Applications |
| 032 | app_account_membership.sql | Memberships |
| 054 | indexes_constraints.sql | Indexes |
| 055 | seed_data.sql | Seed data |
| **997** | **integrity_and_archive_enhancements.sql** | **DLQ, integrity, archive** |
| **998** | **app_schema_enhancements.sql** | **App constraints, RLS** |
| **999** | **enterprise_fk_and_immutability_fixes.sql** | **FKs, triggers, RLS** |

### Critical Migration Notes

1. **Migration 997-999 must run after 055** - They depend on all baseline objects
2. **999 uses DEFERRABLE constraints** - Required for circular dependency between accounts/applications
3. **Triggers in 999 are active immediately** - No data modifications allowed after deployment

---

## Post-Deployment Verification

### 1. Foreign Key Verification

```sql
-- List all FK constraints
SELECT 
    tc.constraint_name,
    tc.table_schema,
    tc.table_name,
    kcu.column_name,
    ccu.table_schema AS foreign_table_schema,
    ccu.table_name AS foreign_table_name,
    ccu.column_name AS foreign_column_name
FROM information_schema.table_constraints AS tc
JOIN information_schema.key_column_usage AS kcu
    ON tc.constraint_name = kcu.constraint_name
JOIN information_schema.constraint_column_usage AS ccu
    ON ccu.constraint_name = tc.constraint_name
WHERE tc.constraint_type = 'FOREIGN KEY'
AND tc.table_schema IN ('core', 'app', 'ussd');
```

### 2. Trigger Verification

```sql
-- List immutability triggers
SELECT 
    tgname AS trigger_name,
    relname AS table_name,
    CASE tgtype & 2 WHEN 2 THEN 'BEFORE' ELSE 'AFTER' END AS timing,
    CASE 
        WHEN tgtype & 4 = 4 THEN 'INSERT'
        WHEN tgtype & 8 = 8 THEN 'DELETE'
        WHEN tgtype & 16 = 16 THEN 'UPDATE'
    END AS event
FROM pg_trigger t
JOIN pg_class c ON t.tgrelid = c.oid
WHERE tgname LIKE 'trg_%_no_%'
ORDER BY relname, tgname;
```

### 3. RLS Verification

```sql
-- Verify RLS is enabled
SELECT 
    schemaname,
    tablename,
    rowsecurity AS rls_enabled,
    forcerowsecurity AS force_rls
FROM pg_tables
WHERE schemaname IN ('core', 'app', 'ussd')
AND rowsecurity = true;

-- List RLS policies
SELECT 
    schemaname,
    tablename,
    policyname,
    permissive,
    roles,
    cmd,
    qual AS using_expression,
    with_check AS with_check_expression
FROM pg_policies
WHERE schemaname IN ('core', 'app', 'ussd');
```

### 4. Index Verification

```sql
-- List indexes on core tables
SELECT 
    schemaname,
    tablename,
    indexname,
    indexdef
FROM pg_indexes
WHERE schemaname IN ('core', 'app', 'ussd')
ORDER BY schemaname, tablename, indexname;
```

### 5. Run Integrity Checks

```sql
-- Test hash chain verification
SELECT * FROM core.verify_hash_chain_enhanced();

-- Test balance verification
SELECT * FROM core.verify_account_balances();

-- Run comprehensive integrity check
SELECT * FROM core.run_integrity_check_comprehensive(
    'HASH_CHAIN',
    '{}'::JSONB
);
```

---

## Application Integration

### 1. Connection Setup

```python
# Python example with RLS context
import psycopg2

def get_db_connection(application_id, account_id, is_admin=False):
    conn = psycopg2.connect(
        host="localhost",
        database="ussd_ledger",
        user="ussd_app",
        password="secure_password"
    )
    
    # Set RLS context
    with conn.cursor() as cur:
        cur.execute("SET app.current_application_id = %s", (application_id,))
        cur.execute("SET app.current_account_id = %s", (account_id,))
        cur.execute("SET app.is_admin = %s", (str(is_admin).lower(),))
    
    return conn
```

### 2. Transaction Submission

```python
def submit_transaction(conn, transaction_type_id, initiator_id, payload, amount, currency):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO core.transaction_log (
                transaction_type_id,
                initiator_account_id,
                payload,
                amount,
                currency,
                status
            ) VALUES (%s, %s, %s, %s, %s, 'PENDING')
            RETURNING transaction_id
        """, (transaction_type_id, initiator_id, payload, amount, currency))
        
        return cur.fetchone()[0]
```

### 3. Error Handling

```python
def handle_transaction_failure(conn, error, context):
    """Add failed transaction to DLQ"""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT core.add_to_dlq(
                %s, %s, %s, %s, %s, %s, %s, %s
            )
        """, (
            context['application_id'],
            context['initiator_account_id'],
            context['transaction_type_id'],
            context['payload'],
            error.stage,
            error.message,
            error.code,
            json.dumps(error.details)
        ))
```

---

## Monitoring Setup

### 1. Key Metrics to Monitor

| Metric | Query | Alert Threshold |
|--------|-------|-----------------|
| Integrity Violations | `SELECT COUNT(*) FROM core.integrity_violations WHERE attempted_at > now() - interval '1 hour'` | > 0 |
| DLQ Size | `SELECT COUNT(*) FROM core.transactions_dlq WHERE status = 'PENDING'` | > 100 |
| Failed Transactions | `SELECT COUNT(*) FROM core.transaction_log WHERE status = 'FAILED' AND created_at > now() - interval '1 hour'` | > 10 |
| RLS Bypass Attempts | Check PostgreSQL logs for policy violations | Any occurrence |

### 2. Health Check Function

```sql
-- Create health check function
CREATE OR REPLACE FUNCTION core.health_check()
RETURNS TABLE (
    check_name VARCHAR(50),
    status VARCHAR(10),
    details JSONB
) AS $$
BEGIN
    -- Check integrity violations
    RETURN QUERY
    SELECT 
        'integrity_violations'::VARCHAR(50),
        CASE WHEN COUNT(*) = 0 THEN 'OK'::VARCHAR(10) ELSE 'WARNING'::VARCHAR(10) END,
        jsonb_build_object('count', COUNT(*), 'latest', MAX(attempted_at))
    FROM core.integrity_violations
    WHERE attempted_at > now() - interval '24 hours';
    
    -- Check DLQ
    RETURN QUERY
    SELECT 
        'dlq_pending'::VARCHAR(50),
        CASE WHEN COUNT(*) < 100 THEN 'OK'::VARCHAR(10) ELSE 'WARNING'::VARCHAR(10) END,
        jsonb_build_object('count', COUNT(*))
    FROM core.transactions_dlq
    WHERE status IN ('PENDING', 'RETRYING');
    
    -- Check failed transactions
    RETURN QUERY
    SELECT 
        'failed_transactions'::VARCHAR(50),
        CASE WHEN COUNT(*) < 10 THEN 'OK'::VARCHAR(10) ELSE 'WARNING'::VARCHAR(10) END,
        jsonb_build_object('count', COUNT(*))
    FROM core.transaction_log
    WHERE status = 'FAILED'
    AND created_at > now() - interval '1 hour';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

### 3. Scheduled Jobs

```sql
-- Schedule integrity checks
INSERT INTO core.integrity_check_schedule (
    check_name, check_type, frequency, is_active, parameters
) VALUES 
    ('Daily Hash Chain Check', 'HASH_CHAIN', 'DAILY', true, '{}'),
    ('Daily Balance Check', 'BALANCE', 'DAILY', true, '{}');

-- Schedule using pg_cron (if installed)
SELECT cron.schedule('integrity-checks', '0 2 * * *', 
    'SELECT core.schedule_integrity_checks()');
```

---

## Troubleshooting

### Common Issues

#### 1. Foreign Key Violation on Insert

**Error:** `foreign_key_violation on core.accounts.application_id`

**Cause:** Application doesn't exist or migration order issue

**Solution:**
```sql
-- Verify application exists
SELECT application_id FROM app.applications WHERE is_current = true;

-- Or defer constraints during batch insert
BEGIN;
SET CONSTRAINTS ALL DEFERRED;
-- ... inserts ...
COMMIT;
```

#### 2. Immutability Trigger Blocking Updates

**Error:** `IMMUTABILITY_VIOLATION: UPDATE blocked on core.transaction_log`

**Cause:** Attempting to update immutable record

**Solution:** Use compensating transaction instead:
```sql
-- Create reversal transaction
INSERT INTO core.transaction_log (
    transaction_type_id,
    initiator_account_id,
    payload,
    amount,
    currency,
    status
) VALUES (
    'reversal-type-uuid',
    original_initiator_id,
    jsonb_build_object('reverses_transaction_id', original_tx_id),
    -original_amount,  -- Negative for reversal
    original_currency,
    'PENDING'
);
```

#### 3. RLS Policy Blocking Access

**Error:** `query returned no rows` (when data exists)

**Cause:** RLS context not set correctly

**Solution:**
```sql
-- Set context before query
SET app.current_application_id = 'your-app-uuid';
SET app.current_account_id = 'user-uuid';

-- Verify context
SHOW app.current_application_id;
```

#### 4. Hash Verification Failure

**Error:** `Hash mismatch in verify_hash_chain`

**Cause:** Data corruption or manual modification

**Solution:**
```sql
-- Identify affected records
SELECT * FROM core.verify_hash_chain_enhanced();

-- Check for violations
SELECT * FROM core.integrity_violations ORDER BY attempted_at DESC;

-- If corruption confirmed, restore from backup
```

---

## Rollback Procedures

### Rollback Enterprise Migrations

```sql
-- Disable immutability triggers first
DROP TRIGGER IF EXISTS trg_accounts_no_update ON core.accounts;
DROP TRIGGER IF EXISTS trg_accounts_no_delete ON core.accounts;
DROP TRIGGER IF EXISTS trg_transaction_log_no_update ON core.transaction_log;
DROP TRIGGER IF EXISTS trg_transaction_log_no_delete ON core.transaction_log;
-- ... etc for all triggers

-- Drop deferred FK constraints
ALTER TABLE core.accounts DROP CONSTRAINT IF EXISTS fk_accounts_application;
-- ... etc for all enterprise FKs

-- Disable RLS (if needed)
ALTER TABLE core.transaction_log NO FORCE ROW LEVEL SECURITY;
-- ... etc for all tables
```

### Full Rollback to Baseline

```bash
# Use down migrations
psql -U postgres -d ussd_ledger -f database/migrations/0001_baseline/down/0001_baseline_rollback.sql
```

---

## Support and Maintenance

### Regular Maintenance Tasks

| Task | Frequency | Command/Query |
|------|-----------|---------------|
| Analyze tables | Daily | `ANALYZE core.transaction_log;` |
| Reindex | Weekly | `REINDEX INDEX CONCURRENTLY idx_transactions_initiator;` |
| Integrity check | Daily | `SELECT * FROM core.run_integrity_check_comprehensive('HASH_CHAIN', '{}');` |
| Archive old data | Monthly | Run archive policy execution |
| DLQ review | Daily | `SELECT * FROM core.transactions_dlq WHERE status = 'PENDING';` |

### Emergency Contacts

| Issue | Contact | Escalation |
|-------|---------|------------|
| Data corruption | DBA Team | CTO |
| Security breach | Security Team | CISO |
| Performance degradation | DevOps Team | CTO |
| Compliance audit | Compliance Team | Legal |

---

*Document Version: 1.0*  
*Last Updated: 2026-03-31*
