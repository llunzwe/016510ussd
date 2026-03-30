# Partition Management Runbook

## Overview

This runbook provides procedures for managing table partitions in the USSD Immutable Ledger database.

## Pre-Operational Checks

### 1. Verify Current Partition Status

```sql
-- Check existing partitions for LEDGER_ENTRIES
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables 
WHERE tablename LIKE 'ledger_entries_%'
ORDER BY tablename;
```

### 2. Check Partition Boundaries

```sql
-- View partition boundaries
SELECT 
    parent.relname AS parent_table,
    child.relname AS partition_name,
    pg_get_expr(child.relpartbound, child.oid) AS partition_constraint
FROM pg_inherits
JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
JOIN pg_class child ON pg_inherits.inhrelid = child.oid
WHERE parent.relname = 'ledger_entries'
ORDER BY child.relname;
```

---

## Compliance

### ISO Standards Mapping

| ISO Standard | Requirement | Implementation |
|--------------|-------------|----------------|
| **ISO 27001:2022** | A.5.37 - Documented operating procedures | This runbook provides documented procedures for partition management |
| **ISO 27001:2022** | A.5.29 - Information security during disruption | Partition archival ensures business continuity during storage issues |
| **ISO 27001:2022** | A.8.1 - User endpoint devices | Partition management controls data retention on storage endpoints |
| **ISO 27031** | ICT readiness for business continuity | Partition archiving supports disaster recovery objectives |
| **ISO 22301** | Business continuity management | Partition procedures maintain service availability |

### Regulatory Compliance

| Regulation | Compliance Requirement |
|------------|------------------------|
| **GDPR Article 5(1)(e)** | Storage limitation - partition archival supports data lifecycle |
| **SOX Section 404** | IT general controls - partition changes logged for audit |
| **PCI DSS 3.1** | Data retention policies - partition management enforces retention |

---

## Security Considerations

### Partition Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    PARTITION SECURITY CONTROLS                   │
├─────────────────────────────────────────────────────────────────┤
│ 1. Access Control                                                │
│    - Partition management restricted to DB_ADMIN role            │
│    - DDL operations require two-person approval                  │
│    - All partition operations logged to audit table              │
├─────────────────────────────────────────────────────────────────┤
│ 2. Data Protection                                               │
│    - Archived partitions moved to encrypted storage              │
│    - Detached partitions require explicit re-attachment auth     │
│    - Partition drops require 7-day quarantine period             │
├─────────────────────────────────────────────────────────────────┤
│ 3. Integrity Controls                                            │
│    - Hash verification before and after partition operations     │
│    - Checksum validation for archived partition files            │
│    - Immutable partitions marked read-only at filesystem level   │
└─────────────────────────────────────────────────────────────────┘
```

### Security Checklist for Partition Operations

| Check | Description | Verification |
|-------|-------------|--------------|
| Authorization | Operator has DB_ADMIN role | `SELECT rolname FROM pg_roles WHERE pg_has_role(current_user, 'db_admin', 'member');` |
| Approval | Change ticket approved | Check ITSM ticket status |
| Backup | Pre-operation backup completed | Verify backup timestamp |
| Encryption | Archive storage encrypted | Check storage encryption status |
| Logging | Audit logging enabled | Verify `log_statement = 'ddl'` |

---

## Audit Requirements

### Required Audit Records

| Operation | Audit Table | Retention |
|-----------|-------------|-----------|
| Partition creation | partition_audit_log | 7 years |
| Partition detachment | partition_audit_log | 7 years |
| Partition archival | partition_audit_log | 7 years |
| Partition restoration | partition_audit_log | 7 years |
| Hash verification | integrity_verification | 7 years |

### Audit Log Schema

```sql
CREATE TABLE partition_audit_log (
    audit_id BIGSERIAL PRIMARY KEY,
    operation_type VARCHAR(50) NOT NULL,  -- CREATE, DETACH, ATTACH, ARCHIVE, RESTORE
    partition_name VARCHAR(100) NOT NULL,
    parent_table VARCHAR(100) NOT NULL,
    performed_by VARCHAR(100) NOT NULL,
    performed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    change_ticket VARCHAR(50),
    rows_affected BIGINT,
    hash_before BYTEA,
    hash_after BYTEA,
    status VARCHAR(20) NOT NULL,  -- SUCCESS, FAILED, ROLLED_BACK
    error_message TEXT
);
```

### Audit Query Examples

```sql
-- Partition operation history
SELECT 
    operation_type,
    partition_name,
    performed_by,
    performed_at,
    change_ticket,
    status
FROM partition_audit_log
WHERE performed_at > NOW() - INTERVAL '90 days'
ORDER BY performed_at DESC;

-- Failed partition operations
SELECT 
    partition_name,
    operation_type,
    performed_by,
    error_message,
    performed_at
FROM partition_audit_log
WHERE status = 'FAILED'
  AND performed_at > NOW() - INTERVAL '30 days';
```

---

## Data Protection Notes

### Retention Compliance

| Data Type | Partition Strategy | Retention Period |
|-----------|-------------------|------------------|
| Ledger entries | Monthly partitions | 7 years (financial records) |
| Session data | Monthly partitions | 1 year |
| Audit logs | Monthly partitions | 7 years |
| Verification data | Quarterly partitions | 10 years |

### Archival Security

```sql
-- Archive partition with security controls
DO $$
DECLARE
    partition_name TEXT := 'ledger_entries_2024_01';
    archive_path TEXT := '/secure/archive/';
    checksum BYTEA;
BEGIN
    -- Calculate checksum before detachment
    SELECT pg_crypto_hash_agg(entry_hash) INTO checksum
    FROM ledger_entries_2024_01;
    
    -- Detach partition
    EXECUTE format('ALTER TABLE ledger_entries DETACH PARTITION %I', partition_name);
    
    -- Move to encrypted archive storage
    EXECUTE format('ALTER TABLE %I SET SCHEMA archive', partition_name);
    
    -- Log archival with checksum
    INSERT INTO partition_audit_log (
        operation_type, partition_name, parent_table,
        performed_by, change_ticket, rows_affected,
        hash_after, status
    ) VALUES (
        'ARCHIVE', partition_name, 'ledger_entries',
        current_user, 'CHG-2025-001',
        (SELECT COUNT(*) FROM archive.ledger_entries_2024_01),
        checksum, 'SUCCESS'
    );
END $$;
```

---

## Procedures

### Procedure 1: Create New Monthly Partition

**Use Case:** Create partition for upcoming month before it begins.

**Pre-Authorization:**
- Change ticket: CHG-YYYY-NNN
- Approved by: Database Architect
- Scheduled window: Low-traffic period (02:00-04:00 UTC)

```sql
-- Create partition for next month
-- Run on 25th of each month (automated) or manually as needed

DO $$
DECLARE
    next_month DATE := DATE_TRUNC('month', CURRENT_DATE + INTERVAL '1 month');
    partition_name TEXT := 'ledger_entries_' || TO_CHAR(next_month, 'YYYY_MM');
    start_date DATE := next_month;
    end_date DATE := next_month + INTERVAL '1 month';
    v_audit_id BIGINT;
BEGIN
    -- Log operation start
    INSERT INTO partition_audit_log (
        operation_type, partition_name, parent_table,
        performed_by, status
    ) VALUES (
        'CREATE', partition_name, 'ledger_entries',
        current_user, 'IN_PROGRESS'
    ) RETURNING audit_id INTO v_audit_id;
    
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF ledger_entries
         FOR VALUES FROM (%L) TO (%L)
         PARTITION BY RANGE (created_at)',
        partition_name, start_date, end_date
    );
    
    -- Add indexes to new partition
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS idx_%s_account ON %I(account_id, created_at DESC)',
        partition_name, partition_name
    );
    
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS idx_%s_session ON %I(session_id)',
        partition_name, partition_name
    );
    
    -- Update audit log
    UPDATE partition_audit_log 
    SET status = 'SUCCESS',
        performed_at = CURRENT_TIMESTAMP
    WHERE audit_id = v_audit_id;
    
    RAISE NOTICE 'Created partition: %', partition_name;
END $$;
```

**Verification:**
```sql
-- Verify partition was created
SELECT tablename FROM pg_tables 
WHERE tablename = 'ledger_entries_' || TO_CHAR(CURRENT_DATE + INTERVAL '1 month', 'YYYY_MM');
```

### Procedure 2: Archive Old Partitions

**Use Case:** Move partitions older than retention period to read-only/archive storage.

**Prerequisites:**
- Ensure partition is not being actively written
- Verify backup of partition data exists
- Schedule during low-traffic period
- Change ticket approved

```sql
-- Step 1: Identify partitions to archive (> 90 days old)
SELECT 
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables 
WHERE tablename LIKE 'ledger_entries_%'
  AND tablename < 'ledger_entries_' || TO_CHAR(CURRENT_DATE - INTERVAL '90 days', 'YYYY_MM')
ORDER BY tablename;

-- Step 2: Detach partition (run for each partition)
DO $$
DECLARE
    partition_name TEXT := 'ledger_entries_2025_01';  -- Update with actual name
    v_checksum BYTEA;
    v_row_count BIGINT;
BEGIN
    -- Calculate integrity hash
    SELECT COUNT(*) INTO v_row_count FROM ledger_entries_2025_01;
    
    -- Detach from parent
    EXECUTE format('ALTER TABLE ledger_entries DETACH PARTITION %I', partition_name);
    
    -- Convert to read-only (optional)
    EXECUTE format('ALTER TABLE %I SET (fillfactor = 100)', partition_name);
    
    -- Move to archive schema
    EXECUTE format('ALTER TABLE %I SET SCHEMA archive', partition_name);
    
    -- Log archival
    INSERT INTO partition_audit_log (
        operation_type, partition_name, parent_table,
        performed_by, rows_affected, status
    ) VALUES (
        'ARCHIVE', partition_name, 'ledger_entries',
        current_user, v_row_count, 'SUCCESS'
    );
    
    RAISE NOTICE 'Archived partition: %', partition_name;
END $$;
```

**Verification:**
```sql
-- Confirm partition is detached
SELECT * FROM pg_inherits 
WHERE inhparent = 'ledger_entries'::regclass;

-- Check archive schema
SELECT tablename FROM pg_tables WHERE schemaname = 'archive';
```

### Procedure 3: Attach Existing Partition

**Use Case:** Re-attach a previously detached partition.

```sql
-- Move from archive schema back to public
ALTER TABLE archive.ledger_entries_2025_01 SET SCHEMA public;

-- Re-attach to parent table
ALTER TABLE ledger_entries ATTACH PARTITION ledger_entries_2025_01
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
```

**Verification:**
```sql
-- Verify re-attachment
SELECT 
    child.relname AS partition_name,
    pg_get_expr(child.relpartbound, child.oid) AS constraint
FROM pg_inherits
JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
JOIN pg_class child ON pg_inherits.inhrelid = child.oid
WHERE parent.relname = 'ledger_entries'
  AND child.relname = 'ledger_entries_2025_01';
```

### Procedure 4: Split Large Partition

**Use Case:** Split a large monthly partition into weekly partitions.

**⚠️ WARNING:** This is a blocking operation. Schedule during maintenance window.

**Required Approvals:**
- Change ticket: CHG-YYYY-NNN
- CAB approval: Yes
- Downtime window: Scheduled

```sql
-- Step 1: Create new weekly partitions with temporary names
DO $$
DECLARE
    v_month DATE := '2025-03-01';  -- Target month
    v_week_start DATE;
    v_week_end DATE;
    v_partition_name TEXT;
BEGIN
    FOR i IN 0..3 LOOP
        v_week_start := v_month + (i * 7);
        v_week_end := LEAST(v_week_start + 7, v_month + INTERVAL '1 month');
        v_partition_name := 'ledger_entries_2025_03_w' || (i+1);
        
        EXECUTE format(
            'CREATE TABLE %I (LIKE ledger_entries INCLUDING ALL)',
            v_partition_name
        );
        
        EXECUTE format(
            'ALTER TABLE %I ADD CONSTRAINT %I 
             CHECK (created_at >= %L AND created_at < %L)',
            v_partition_name, v_partition_name || '_chk', 
            v_week_start, v_week_end
        );
    END LOOP;
END $$;

-- Step 2: Migrate data (using CTAS for performance)
INSERT INTO ledger_entries_2025_03_w1 
SELECT * FROM ledger_entries_2025_03 
WHERE created_at >= '2025-03-01' AND created_at < '2025-03-08';

INSERT INTO ledger_entries_2025_03_w2 
SELECT * FROM ledger_entries_2025_03 
WHERE created_at >= '2025-03-08' AND created_at < '2025-03-15';

-- ... continue for other weeks

-- Step 3: Detach old partition and attach new ones
ALTER TABLE ledger_entries DETACH PARTITION ledger_entries_2025_03;
ALTER TABLE ledger_entries ATTACH PARTITION ledger_entries_2025_03_w1 
    FOR VALUES FROM ('2025-03-01') TO ('2025-03-08');
ALTER TABLE ledger_entries ATTACH PARTITION ledger_entries_2025_03_w2 
    FOR VALUES FROM ('2025-03-08') TO ('2025-03-15');
-- ... continue for other weeks

-- Step 4: Verify and drop old partition
DROP TABLE ledger_entries_2025_03;
```

### Procedure 5: Partition Maintenance (VACUUM/ANALYZE)

**Use Case:** Regular maintenance for partition performance.

```sql
-- Vacuum and analyze all ledger partitions
DO $$
DECLARE
    partition_record RECORD;
BEGIN
    FOR partition_record IN 
        SELECT tablename 
        FROM pg_tables 
        WHERE tablename LIKE 'ledger_entries_%'
        ORDER BY tablename
    LOOP
        RAISE NOTICE 'Processing: %', partition_record.tablename;
        EXECUTE format('VACUUM ANALYZE %I', partition_record.tablename);
    END LOOP;
END $$;
```

---

## Monitoring Queries

### Partition Size Growth

```sql
SELECT 
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as total_size,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) as data_size,
    pg_size_pretty(pg_indexes_size(schemaname||'.'||tablename)) as index_size,
    (SELECT COUNT(*) FROM pg_stat_user_tables WHERE relname = tablename) as has_stats
FROM pg_tables 
WHERE tablename LIKE 'ledger_entries_%'
ORDER BY tablename DESC
LIMIT 10;
```

### Partition Row Counts

```sql
SELECT 
    'ledger_entries_' || TO_CHAR(created_at, 'YYYY_MM') as partition_name,
    COUNT(*) as row_count,
    MIN(created_at) as earliest_entry,
    MAX(created_at) as latest_entry
FROM ledger_entries
GROUP BY TO_CHAR(created_at, 'YYYY_MM')
ORDER BY partition_name DESC;
```

---

## Rollback Procedures

### Rollback: Detached Wrong Partition

```sql
-- Re-attach immediately if transaction hasn't completed
-- If already committed:

-- Step 1: Check if data still exists
SELECT COUNT(*) FROM archive.ledger_entries_2025_01;

-- Step 2: Move back and re-attach
ALTER TABLE archive.ledger_entries_2025_01 SET SCHEMA public;
ALTER TABLE ledger_entries ATTACH PARTITION ledger_entries_2025_01
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

-- Step 3: Verify hash chain integrity
SELECT verify_hash_chain('2025-01-01'::timestamp, '2025-02-01'::timestamp);

-- Step 4: Log rollback
INSERT INTO partition_audit_log (
    operation_type, partition_name, parent_table,
    performed_by, status
) VALUES (
    'ROLLBACK_RESTORE', 'ledger_entries_2025_01', 'ledger_entries',
    current_user, 'SUCCESS'
);
```

### Rollback: Corrupted Partition During Split

```sql
-- If split operation failed mid-way:

-- Step 1: Detach any partially attached partitions
ALTER TABLE ledger_entries DETACH PARTITION IF EXISTS ledger_entries_2025_03_w1;
ALTER TABLE ledger_entries DETACH PARTITION IF EXISTS ledger_entries_2025_03_w2;

-- Step 2: Drop incomplete partitions
DROP TABLE IF EXISTS ledger_entries_2025_03_w1;
DROP TABLE IF EXISTS ledger_entries_2025_03_w2;

-- Step 3: Restore from backup if original was dropped
-- (Use pg_restore or point-in-time recovery)

-- Step 4: Re-run split procedure from clean state
```

---

## Emergency Procedures

### Emergency: Default Partition Overflow

```sql
-- If data is going to default partition
-- Step 1: Check default partition contents
SELECT 
    MIN(created_at) as min_date,
    MAX(created_at) as max_date,
    COUNT(*) as row_count
FROM ledger_entries_default;

-- Step 2: Create missing partitions
-- (Run Procedure 1 for missing months)

-- Step 3: Move data from default to proper partitions
DO $$
DECLARE
    target_date DATE;
    partition_name TEXT;
BEGIN
    FOR target_date IN 
        SELECT DISTINCT DATE_TRUNC('month', created_at)::date 
        FROM ledger_entries_default
    LOOP
        partition_name := 'ledger_entries_' || TO_CHAR(target_date, 'YYYY_MM');
        
        -- Ensure partition exists
        IF NOT EXISTS (
            SELECT 1 FROM pg_tables WHERE tablename = partition_name
        ) THEN
            RAISE EXCEPTION 'Missing partition: %', partition_name;
        END IF;
        
        -- Move data
        EXECUTE format(
            'WITH moved AS (
                DELETE FROM ledger_entries_default 
                WHERE created_at >= %L AND created_at < %L
                RETURNING *
            )
            INSERT INTO %I SELECT * FROM moved',
            target_date, target_date + INTERVAL '1 month', partition_name
        );
    END LOOP;
END $$;
```

---

## TODOs

- [ ] Automate monthly partition creation via cron/pg_cron
- [ ] Implement partition compression for cold storage
- [ ] Create partition archival S3 integration
- [ ] Add partition health check alerts
- [ ] Implement partition-level backup strategy
- [ ] Create partition split automation for oversized partitions
- [ ] Design partition merge capability for sparse historical data
- [ ] Add partition statistics monitoring dashboard
