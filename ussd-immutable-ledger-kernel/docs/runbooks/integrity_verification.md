# Integrity Verification Runbook

## Overview

This runbook provides procedures for verifying the cryptographic integrity of the immutable ledger hash chain.

## Hash Chain Architecture

```mermaid
graph LR
    G[Genesis Block<br/>Hash: 0x00...00] --> E1[Entry 1<br/>Hash: SHA256(...)]
    E1 --> E2[Entry 2<br/>Hash: SHA256(E1+Data)]
    E2 --> E3[Entry 3<br/>Hash: SHA256(E2+Data)]
    E3 --> E4[Entry 4<br/>Hash: SHA256(E3+Data)]
    E4 --> D[...]
    style G fill:#90EE90
    style E1 fill:#87CEEB
    style E2 fill:#87CEEB
    style E3 fill:#87CEEB
    style E4 fill:#87CEEB
```

## Verification Types

| Type | Scope | Frequency | Duration |
|------|-------|-----------|----------|
| Full | All entries | Monthly | Hours |
| Incremental | Since last verify | Daily | Minutes |
| Spot | Random sampling | Hourly | Seconds |
| Targeted | Specific range | On-demand | Variable |

---

## Compliance

### ISO Standards Mapping

| ISO Standard | Requirement | Implementation |
|--------------|-------------|----------------|
| **ISO 27001:2022** | A.5.33 - Protection of records | Hash chain provides tamper-evident record protection |
| **ISO 27001:2022** | A.5.35 - Independent review of information security | Third-party verification of hash chain integrity |
| **ISO 27001:2022** | A.8.10 - Information deletion | Verification ensures no unauthorized deletions occurred |
| **ISO 27001:2022** | A.8.11 - Data masking | Verification masks sensitive data in output reports |
| **ISO 19011** | Auditing management systems | Verification procedures follow audit principles |
| **ISO 27037** - Digital evidence collection | Hash chain provides court-admissible integrity evidence |

### Regulatory Compliance

| Regulation | Compliance Requirement |
|------------|------------------------|
| **SOX Section 302/404** | CEO/CFO certification of financial controls - hash verification provides attestation evidence |
| **GDPR Article 5(1)(f)** | Integrity and confidentiality - verification ensures data integrity |
| **PCI DSS 4.0 Req 10.3** | Audit trail coverage - verification ensures audit log integrity |
| **Basel II/III** | Data integrity for risk calculations - verification supports regulatory capital calculations |
| **MiFID II** | Transaction recording - hash chain provides immutable record |

---

## Security Considerations

### Verification Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│                  VERIFICATION SECURITY CONTROLS                  │
├─────────────────────────────────────────────────────────────────┤
│ 1. Access Control                                                │
│    - Verification execution: LEDGER_AUDITOR role                 │
│    - Verification configuration: LEDGER_ADMIN role               │
│    - Results access: LEDGER_READER role                          │
├─────────────────────────────────────────────────────────────────┤
│ 2. Cryptographic Controls                                        │
│    - SHA-256 for all hash calculations                           │
│    - HMAC-SHA256 for verification result signing                 │
│    - Verification reports digitally signed                       │
├─────────────────────────────────────────────────────────────────┤
│ 3. Operational Security                                          │
│    - Verification runs during low-traffic periods                │
│    - Resource limits prevent DoS during verification             │
│    - Verification results encrypted at rest                      │
├─────────────────────────────────────────────────────────────────┤
│ 4. Audit Trail                                                   │
│    - All verification attempts logged                            │
│    - Failed verifications trigger immediate alerts               │
│    - Verification history retained for 7 years                   │
└─────────────────────────────────────────────────────────────────┘
```

### Security Checklist

| Check | Description | Verification Command |
|-------|-------------|---------------------|
| Role verification | User has LEDGER_AUDITOR role | `SELECT pg_has_role(current_user, 'ledger_auditor', 'member');` |
| Resource availability | Sufficient disk space for temp tables | `SELECT pg_size_pretty(pg_database_size(current_database()));` |
| Network isolation | Verification runs on isolated network segment | Check network configuration |
| Log integrity | Audit logging enabled | `SHOW log_statement;` |
| Backup verified | Recent backup available before full verification | Check backup timestamps |

### Threat Mitigation

| Threat | Mitigation Strategy |
|--------|---------------------|
| Verification tampering | HMAC-signed verification results |
| Resource exhaustion | Resource limits and scheduled low-traffic execution |
| Side-channel attacks | Constant-time hash comparison |
| Verification bypass | Mandatory verification before settlement batches |

---

## Audit Requirements

### Required Audit Records

| Event | Table | Retention | Standard |
|-------|-------|-----------|----------|
| Full verification | verification_runs | 7 years | SOX, Basel |
| Incremental verification | verification_runs | 7 years | SOX, Basel |
| Integrity violations | integrity_violations | 10 years | Legal hold |
| Verification queries | transaction_audit | 3 years | PCI DSS |

### Audit Evidence Package

For regulatory examinations, the following evidence is available:

```sql
-- Complete audit trail for verification
SELECT 
    vr.run_id,
    vr.run_type,
    vr.status,
    vr.entries_checked,
    vr.violations_found,
    vr.started_at,
    vr.completed_at,
    vr.performed_by,
    vr.digital_signature,
    iv.violation_id,
    iv.entry_id,
    iv.violation_type,
    iv.detected_at
FROM verification_runs vr
LEFT JOIN integrity_violations iv ON iv.detected_at BETWEEN vr.started_at AND vr.completed_at
WHERE vr.started_at > NOW() - INTERVAL '1 year'
ORDER BY vr.started_at DESC;
```

### Compliance Reporting

```sql
-- Monthly compliance report
SELECT 
    DATE_TRUNC('month', started_at) as month,
    COUNT(*) FILTER (WHERE run_type = 'FULL') as full_verifications,
    COUNT(*) FILTER (WHERE run_type = 'INCREMENTAL') as incremental_verifications,
    SUM(violations_found) as total_violations,
    AVG(entries_checked) as avg_entries_checked,
    CASE 
        WHEN SUM(violations_found) = 0 THEN 'COMPLIANT'
        ELSE 'VIOLATIONS_DETECTED'
    END as compliance_status
FROM verification_runs
WHERE status = 'COMPLETED'
  AND started_at > NOW() - INTERVAL '12 months'
GROUP BY DATE_TRUNC('month', started_at)
ORDER BY month DESC;
```

---

## Data Protection Notes

### Sensitive Data Handling

During verification, the following data protection measures apply:

| Data Element | Handling | Justification |
|--------------|----------|---------------|
| MSISDN | Masked in verification output | PII protection (GDPR) |
| Account ID | Tokenized in reports | Account confidentiality |
| Amount | Full precision retained | Financial accuracy required |
| Entry hash | Full value retained | Cryptographic integrity |
| Client IP | Excluded from reports | Privacy protection |

### Verification Output Security

```sql
-- Secure verification result storage
CREATE TABLE verification_runs_secure (
    run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,
    entries_checked BIGINT,
    violations_found INTEGER,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    performed_by VARCHAR(100) NOT NULL,
    result_hash BYTEA,  -- HMAC of verification results
    encrypted_details BYTEA,  -- AES-256 encrypted detailed results
    digital_signature BYTEA  -- RSA signature for non-repudiation
);
```

### Retention Policy

| Verification Type | Retention Period | Storage Class |
|-------------------|------------------|---------------|
| Full verification | 7 years | Write-once media |
| Incremental verification | 1 year | Standard storage |
| Spot verification | 90 days | Standard storage |
| Violations | 10 years | Legal hold storage |

---

## Pre-Verification Checks

### 1. Verify Database Connectivity

```bash
# Test connection
psql -h $DB_HOST -U $DB_USER -d ledger_db -c "SELECT COUNT(*) FROM ledger_entries;"

# Check replication lag (if applicable)
psql -c "SELECT 
    client_addr, 
    state, 
    pg_size_pretty(pg_wal_lsn_diff(sent_lsn, flush_lsn)) as lag
FROM pg_stat_replication;"
```

### 2. Check System Resources

```sql
-- Verify adequate resources for verification
SELECT 
    (SELECT COUNT(*) FROM ledger_entries) as total_entries,
    pg_size_pretty(pg_total_relation_size('ledger_entries')) as total_size,
    (SELECT setting::int FROM pg_settings WHERE name = 'max_parallel_workers') as max_workers,
    (SELECT setting::int FROM pg_settings WHERE name = 'shared_buffers') as shared_buffers;
```

---

## Procedures

### Procedure 1: Full Hash Chain Verification

**Use Case:** Comprehensive verification of entire ledger (run monthly).

**Pre-Authorization:**
- Scheduled: First Sunday of month, 02:00 UTC
- Approved by: Chief Information Security Officer
- Notification: Stakeholders notified 48 hours in advance

```sql
-- Full verification stored procedure
CREATE OR REPLACE PROCEDURE verify_full_hash_chain()
LANGUAGE plpgsql
AS $$
DECLARE
    v_entry RECORD;
    v_previous_hash BYTEA := '\x0000000000000000000000000000000000000000000000000000000000000000';
    v_computed_hash BYTEA;
    v_cumulative_hash BYTEA;
    v_error_count INT := 0;
    v_total_checked INT := 0;
    v_start_time TIMESTAMP := clock_timestamp();
    v_run_id UUID := gen_random_uuid();
BEGIN
    RAISE NOTICE 'Starting full hash chain verification at %', v_start_time;
    
    -- Log verification start
    INSERT INTO verification_runs (
        run_id, run_type, started_at, status, performed_by
    ) VALUES (
        v_run_id, 'FULL', v_start_time, 'IN_PROGRESS', current_user
    );
    
    FOR v_entry IN 
        SELECT entry_id, entry_uuid, entry_hash, previous_entry_id, 
               created_at, amount, account_id, chain_hash
        FROM ledger_entries
        ORDER BY entry_id
    LOOP
        -- Compute expected hash
        v_computed_hash := digest(
            v_entry.entry_uuid::text || 
            v_entry.amount::text || 
            v_entry.account_id ||
            v_entry.created_at::text ||
            encode(v_previous_hash, 'hex'),
            'sha256'
        );
        
        -- Verify entry hash
        IF v_entry.entry_hash != v_computed_hash THEN
            RAISE WARNING 'Hash mismatch at entry_id: %', v_entry.entry_id;
            
            -- Log integrity violation
            INSERT INTO integrity_violations (
                entry_id, detected_at, violation_type,
                expected_hash, actual_hash, run_id
            ) VALUES (
                v_entry.entry_id, NOW(), 'ENTRY_HASH_MISMATCH',
                v_computed_hash, v_entry.entry_hash, v_run_id
            );
            
            v_error_count := v_error_count + 1;
        END IF;
        
        v_previous_hash := v_entry.entry_hash;
        v_total_checked := v_total_checked + 1;
        
        -- Progress report every 100k entries
        IF v_total_checked % 100000 = 0 THEN
            RAISE NOTICE 'Verified % entries, % errors found', v_total_checked, v_error_count;
            COMMIT;  -- Prevent long transaction
        END IF;
    END LOOP;
    
    -- Record verification result
    UPDATE verification_runs 
    SET 
        status = CASE WHEN v_error_count = 0 THEN 'PASSED' ELSE 'FAILED' END,
        completed_at = clock_timestamp(),
        entries_checked = v_total_checked,
        violations_found = v_error_count
    WHERE run_id = v_run_id;
    
    RAISE NOTICE 'Full verification complete. Total: %, Errors: %, Duration: %',
        v_total_checked, v_error_count, clock_timestamp() - v_start_time;
END;
$$;

-- Execute full verification
CALL verify_full_hash_chain();
```

**Command Line Execution:**
```bash
# Run via psql with timing
\timing on
psql -U ledger_admin -d ledger_db -c "CALL verify_full_hash_chain();"
```

### Procedure 2: Incremental Verification

**Use Case:** Verify only new entries since last verification (run daily).

```sql
-- Get last verified entry
CREATE OR REPLACE FUNCTION get_last_verified_entry_id()
RETURNS BIGINT AS $$
    SELECT COALESCE(MAX(last_entry_id), 0)
    FROM verification_runs
    WHERE status = 'PASSED' AND run_type IN ('FULL', 'INCREMENTAL');
$$ LANGUAGE SQL STABLE;

-- Incremental verification
CREATE OR REPLACE PROCEDURE verify_incremental_hash_chain()
LANGUAGE plpgsql
AS $$
DECLARE
    v_last_verified BIGINT := get_last_verified_entry_id();
    v_entry RECORD;
    v_previous_hash BYTEA;
    v_error_count INT := 0;
    v_total_checked INT := 0;
    v_run_id UUID := gen_random_uuid();
BEGIN
    RAISE NOTICE 'Starting incremental verification from entry_id: %', v_last_verified;
    
    INSERT INTO verification_runs (
        run_id, run_type, started_at, status, first_entry_id, performed_by
    ) VALUES (
        v_run_id, 'INCREMENTAL', NOW(), 'IN_PROGRESS', v_last_verified + 1, current_user
    );
    
    -- Get hash of last verified entry
    SELECT entry_hash INTO v_previous_hash
    FROM ledger_entries
    WHERE entry_id = v_last_verified;
    
    IF v_previous_hash IS NULL THEN
        v_previous_hash := '\x0000000000000000000000000000000000000000000000000000000000000000';
    END IF;
    
    FOR v_entry IN 
        SELECT entry_id, entry_uuid, entry_hash, created_at, amount, account_id
        FROM ledger_entries
        WHERE entry_id > v_last_verified
        ORDER BY entry_id
    LOOP
        -- Verify hash linkage
        IF NOT verify_entry_hash(v_entry.entry_id, v_previous_hash) THEN
            v_error_count := v_error_count + 1;
        END IF;
        
        v_previous_hash := v_entry.entry_hash;
        v_total_checked := v_total_checked + 1;
    END LOOP;
    
    -- Record results
    UPDATE verification_runs
    SET 
        status = CASE WHEN v_error_count = 0 THEN 'PASSED' ELSE 'FAILED' END,
        completed_at = NOW(),
        entries_checked = v_total_checked,
        violations_found = v_error_count,
        last_entry_id = (SELECT MAX(entry_id) FROM ledger_entries)
    WHERE run_id = v_run_id;
    
    RAISE NOTICE 'Incremental verification complete. New entries: %, Errors: %',
        v_total_checked, v_error_count;
END;
$$;
```

### Procedure 3: Spot Verification (Sampling)

**Use Case:** Random sampling for continuous monitoring (run hourly).

```sql
-- Spot verification with random sampling
CREATE OR REPLACE PROCEDURE verify_spot_hash_chain(
    p_sample_size INT DEFAULT 1000
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_entry RECORD;
    v_previous_hash BYTEA;
    v_error_count INT := 0;
    v_run_id UUID := gen_random_uuid();
BEGIN
    RAISE NOTICE 'Starting spot verification with sample size: %', p_sample_size;
    
    INSERT INTO verification_runs (
        run_id, run_type, started_at, status, performed_by
    ) VALUES (
        v_run_id, 'SPOT', NOW(), 'IN_PROGRESS', current_user
    );
    
    FOR v_entry IN 
        SELECT entry_id, entry_hash, previous_entry_id
        FROM ledger_entries
        TABLESAMPLE SYSTEM (0.01)  -- 0.01% sample
        WHERE entry_id > 0
        LIMIT p_sample_size
    LOOP
        -- Get previous entry hash
        SELECT entry_hash INTO v_previous_hash
        FROM ledger_entries
        WHERE entry_id = v_entry.previous_entry_id;
        
        IF v_previous_hash IS NULL AND v_entry.previous_entry_id IS NOT NULL THEN
            RAISE WARNING 'Missing previous entry for entry_id: %', v_entry.entry_id;
            v_error_count := v_error_count + 1;
            CONTINUE;
        END IF;
        
        -- Verify chain link
        IF NOT EXISTS (
            SELECT 1 FROM ledger_hash_chain
            WHERE entry_id = v_entry.entry_id
              AND entry_hash = v_entry.entry_hash
        ) THEN
            v_error_count := v_error_count + 1;
        END IF;
    END LOOP;
    
    UPDATE verification_runs
    SET 
        status = CASE WHEN v_error_count = 0 THEN 'PASSED' ELSE 'FAILED' END,
        completed_at = NOW(),
        entries_checked = p_sample_size,
        violations_found = v_error_count
    WHERE run_id = v_run_id;
    
    RAISE NOTICE 'Spot verification complete. Sampled: %, Errors: %',
        p_sample_size, v_error_count;
END;
$$;
```

### Procedure 4: Targeted Range Verification

**Use Case:** Verify specific date range after incident or data migration.

```sql
-- Verify specific date range
CREATE OR REPLACE PROCEDURE verify_range_hash_chain(
    p_start_date TIMESTAMP,
    p_end_date TIMESTAMP
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_entry RECORD;
    v_previous_hash BYTEA;
    v_error_count INT := 0;
    v_total_checked INT := 0;
    v_run_id UUID := gen_random_uuid();
BEGIN
    RAISE NOTICE 'Starting range verification from % to %', p_start_date, p_end_date;
    
    INSERT INTO verification_runs (
        run_id, run_type, started_at, status, range_start, range_end, performed_by
    ) VALUES (
        v_run_id, 'TARGETED', NOW(), 'IN_PROGRESS', p_start_date, p_end_date, current_user
    );
    
    -- Get starting hash
    SELECT entry_hash INTO v_previous_hash
    FROM ledger_entries
    WHERE created_at < p_start_date
    ORDER BY entry_id DESC
    LIMIT 1;
    
    IF v_previous_hash IS NULL THEN
        v_previous_hash := '\x0000000000000000000000000000000000000000000000000000000000000000';
    END IF;
    
    FOR v_entry IN 
        SELECT entry_id, entry_hash, entry_uuid, amount, account_id, created_at
        FROM ledger_entries
        WHERE created_at >= p_start_date AND created_at < p_end_date
        ORDER BY entry_id
    LOOP
        IF NOT verify_entry_integrity(v_entry, v_previous_hash) THEN
            v_error_count := v_error_count + 1;
        END IF;
        
        v_previous_hash := v_entry.entry_hash;
        v_total_checked := v_total_checked + 1;
    END LOOP;
    
    UPDATE verification_runs
    SET 
        status = CASE WHEN v_error_count = 0 THEN 'PASSED' ELSE 'FAILED' END,
        completed_at = NOW(),
        entries_checked = v_total_checked,
        violations_found = v_error_count
    WHERE run_id = v_run_id;
    
    RAISE NOTICE 'Range verification complete. Checked: %, Errors: %',
        v_total_checked, v_error_count;
END;
$$;

-- Example: Verify last 24 hours
CALL verify_range_hash_chain(NOW() - INTERVAL '24 hours', NOW());
```

---

## Monitoring Queries

### Verification Status Dashboard

```sql
-- Latest verification results
SELECT 
    run_type,
    status,
    entries_checked,
    violations_found,
    started_at,
    completed_at,
    EXTRACT(EPOCH FROM (completed_at - started_at))/60 as duration_minutes
FROM verification_runs
ORDER BY started_at DESC
LIMIT 10;
```

### Integrity Violations Report

```sql
-- Pending violations requiring investigation
SELECT 
    iv.violation_id,
    iv.entry_id,
    iv.detected_at,
    iv.violation_type,
    iv.investigation_status,
    le.transaction_ref,
    le.amount,
    le.created_at as entry_created_at
FROM integrity_violations iv
JOIN ledger_entries le ON iv.entry_id = le.entry_id
WHERE iv.resolved_at IS NULL
ORDER BY iv.detected_at DESC;
```

### Hash Chain Statistics

```sql
-- Chain health metrics
SELECT 
    COUNT(*) as total_entries,
    COUNT(DISTINCT chain_hash) as unique_chains,
    MIN(entry_id) as first_entry,
    MAX(entry_id) as last_entry,
    MAX(entry_id) - MIN(entry_id) + 1 as expected_entries,
    COUNT(*) - (MAX(entry_id) - MIN(entry_id) + 1) as gap_count
FROM ledger_entries;
```

---

## Alert Configuration

### Automated Alert Trigger

```sql
-- Create alert trigger for new violations
CREATE OR REPLACE FUNCTION alert_on_integrity_failure()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.violations_found > 0 THEN
        -- Send notification (requires pg_notify or external integration)
        PERFORM pg_notify('integrity_alert', json_build_object(
            'run_type', NEW.run_type,
            'violations', NEW.violations_found,
            'time', NEW.completed_at,
            'run_id', NEW.run_id
        )::text);
        
        -- Insert into incident queue
        INSERT INTO incident_queue (
            incident_type, severity, description, created_at, reference_id
        ) VALUES (
            'INTEGRITY_FAILURE',
            'CRITICAL',
            format('%s verification found %s violations', 
                   NEW.run_type, NEW.violations_found),
            NOW(),
            NEW.run_id
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER integrity_failure_alert
    AFTER INSERT ON verification_runs
    FOR EACH ROW
    EXECUTE FUNCTION alert_on_integrity_failure();
```

---

## Rollback Procedures

### Rollback: Verification Corrupted State

```sql
-- If verification run itself has issues
-- Step 1: Identify problematic verification run
SELECT * FROM verification_runs 
WHERE status = 'FAILED' 
ORDER BY started_at DESC;

-- Step 2: Delete problematic run record (admin only)
DELETE FROM verification_runs 
WHERE run_id = 'specific_run_id';

-- Step 3: Re-run verification for affected range
CALL verify_range_hash_chain('2025-01-01', '2025-01-31');
```

### Rollback: False Positive Violations

```sql
-- If violations were incorrectly flagged
-- Step 1: Review violations
SELECT * FROM integrity_violations 
WHERE investigation_status = 'PENDING';

-- Step 2: Mark as false positive
UPDATE integrity_violations 
SET 
    investigation_status = 'FALSE_POSITIVE',
    resolved_at = NOW(),
    resolution_notes = 'Re-verified - hash calculation timing issue'
WHERE violation_id IN (1, 2, 3);
```

---

## TODOs

- [ ] Implement parallel verification using multiple workers
- [ ] Add Merkle tree root hash for efficient batch verification
- [ ] Create verification performance benchmarking
- [ ] Implement cross-region hash replication verification
- [ ] Add cryptographic signature verification for entries
- [ ] Create real-time verification streaming service
- [ ] Design verification result blockchain anchoring
- [ ] Implement GPU-accelerated hash verification
- [ ] Add verification SLA monitoring and alerting
- [ ] Create verification report generation automation
