# Application Schema ERD Documentation

## Overview

The Application Schema provides operational data structures supporting the USSD Immutable Ledger. These tables support session management, account operations, and settlement workflows.

## Entity Relationship Diagram

```mermaid
erDiagram
    ACCOUNTS ||--o{ ACCOUNT_BALANCES : maintains
    ACCOUNTS ||--o{ USSD_SESSIONS : initiates
    ACCOUNTS ||--o{ SETTLEMENT_BATCHES : settles
    USSD_SESSIONS ||--o{ SESSION_TRANSACTIONS : contains
    USSD_SESSIONS ||--o{ SESSION_STATES : tracks
    SETTLEMENT_BATCHES ||--o{ SETTLEMENT_ENTRIES : aggregates
    SETTLEMENT_ENTRIES ||--|| LEDGER_ENTRIES : references
    SERVICE_PROVIDERS ||--o{ ACCOUNTS : owns
    SERVICE_PROVIDERS ||--o{ SETTLEMENT_BATCHES : generates
    
    ACCOUNTS {
        varchar account_id PK
        varchar account_type "WALLET|BANK|MOBILE_MONEY"
        varchar status "ACTIVE|FROZEN|CLOSED"
        varchar msisdn UK
        varchar service_provider_id FK
        jsonb kyc_data
        timestamp opened_at
        timestamp closed_at
        varchar opened_by
    }
    
    ACCOUNT_BALANCES {
        varchar balance_id PK
        varchar account_id FK UK
        decimal available_balance
        decimal pending_balance
        decimal hold_balance
        varchar currency_code
        timestamp last_updated
        bigint last_entry_id FK
    }
    
    USSD_SESSIONS {
        varchar session_id PK
        varchar msisdn
        varchar account_id FK
        varchar ussd_code
        varchar session_status "ACTIVE|COMPLETED|TIMEOUT|ERROR"
        timestamp started_at
        timestamp ended_at
        varchar network_operator
        inet client_ip
        jsonb session_context
    }
    
    SESSION_STATES {
        bigint state_id PK
        varchar session_id FK
        varchar state_name
        jsonb state_data
        timestamp entered_at
        timestamp exited_at
    }
    
    SESSION_TRANSACTIONS {
        bigint tx_id PK
        varchar session_id FK
        varchar transaction_type
        varchar transaction_ref UK
        varchar status "PENDING|COMPLETED|FAILED"
        decimal amount
        timestamp created_at
        timestamp completed_at
        varchar ledger_entry_uuid FK
    }
    
    SETTLEMENT_BATCHES {
        varchar batch_id PK
        varchar service_provider_id FK
        varchar batch_type "DAILY|WEEKLY|MANUAL"
        varchar status "OPEN|CLOSED|SETTLED"
        timestamp batch_date
        timestamp opened_at
        timestamp closed_at
        decimal total_amount
        int entry_count
    }
    
    SETTLEMENT_ENTRIES {
        bigint settlement_entry_id PK
        varchar batch_id FK
        varchar ledger_entry_uuid FK
        decimal amount
        varchar entry_type
        timestamp included_at
    }
    
    SERVICE_PROVIDERS {
        varchar provider_id PK
        varchar provider_name
        varchar provider_code UK
        varchar settlement_schedule
        varchar status "ACTIVE|SUSPENDED"
        jsonb settlement_accounts
        timestamp created_at
    }
```

## Table Descriptions

### ACCOUNTS

Primary account registry for all financial entities.

**Account Types:**
- `WALLET` - Internal digital wallet
- `BANK` - Linked bank account
- `MOBILE_MONEY` - Mobile money integration

**Status Transitions:**
```
ACTIVE → FROZEN → ACTIVE
ACTIVE → CLOSED (irreversible)
FROZEN → CLOSED
```

### ACCOUNT_BALANCES

Real-time balance cache synchronized with ledger.

**Balance Consistency:**
```
available_balance = SUM(ledger_credits) - SUM(ledger_debits) - hold_balance
pending_balance = SUM(pending_credits) - SUM(pending_debits)
```

**Update Strategy:**
- Async updates via event streaming
- Reconciliation job runs every 5 minutes
- Conflict resolution: ledger always wins

### USSD_SESSIONS

USSD session tracking for audit and reconciliation.

**Session Lifecycle:**
1. `INIT` - Session created
2. `ACTIVE` - User interacting
3. `COMPLETED` - Normal termination
4. `TIMEOUT` - No response (30s default)
5. `ERROR` - System failure

**Retention:** 90 days active, archive to cold storage after

### SESSION_STATES

Finite state machine tracking for complex USSD flows.

**Common States:**
- `MENU_MAIN`
- `MENU_BALANCE`
- `TRANSFER_INPUT_AMOUNT`
- `TRANSFER_CONFIRM`
- `PIN_ENTRY`
- `RECEIPT_DISPLAY`

### SESSION_TRANSACTIONS

Bridge table linking USSD sessions to ledger entries.

**Status Flow:**
```
PENDING → COMPLETED (async confirmation)
PENDING → FAILED (error or timeout)
```

### SETTLEMENT_BATCHES

Aggregates transactions for service provider settlement.

**Batch Windows:**
- Daily: Close at 23:59 UTC
- Weekly: Close Sunday 23:59 UTC
- Manual: Operator initiated

### SETTLEMENT_ENTRIES

Individual entries within a settlement batch.

**Immutability Note:**
- Entries added while batch is `OPEN`
- Batch close creates snapshot
- No modifications after close

### SERVICE_PROVIDERS

Third-party service integration registry.

**Settlement Schedule Options:**
- `T+0` - Same day
- `T+1` - Next day
- `T+7` - Weekly
- `MANUAL` - On request

## Indexes

```sql
-- Account indexes
CREATE INDEX idx_accounts_msisdn ON ACCOUNTS(msisdn) WHERE status = 'ACTIVE';
CREATE INDEX idx_accounts_provider ON ACCOUNTS(service_provider_id);

-- Balance indexes
CREATE INDEX idx_balance_updated ON ACCOUNT_BALANCES(last_updated);

-- Session indexes
CREATE INDEX idx_sessions_msisdn ON USSD_SESSIONS(msisdn, started_at DESC);
CREATE INDEX idx_sessions_account ON USSD_SESSIONS(account_id, started_at DESC);
CREATE INDEX idx_sessions_status ON USSD_SESSIONS(session_status) WHERE session_status = 'ACTIVE';

-- Settlement indexes
CREATE INDEX idx_settlement_provider ON SETTLEMENT_BATCHES(service_provider_id, batch_date);
CREATE INDEX idx_settlement_status ON SETTLEMENT_BATCHES(status);
CREATE INDEX idx_settlement_entry_batch ON SETTLEMENT_ENTRIES(batch_id);
```

## Foreign Key Relationships

| Child Table | Column | Parent Table | On Delete |
|-------------|--------|--------------|-----------|
| ACCOUNT_BALANCES | account_id | ACCOUNTS | CASCADE |
| USSD_SESSIONS | account_id | ACCOUNTS | SET NULL |
| SESSION_TRANSACTIONS | session_id | USSD_SESSIONS | CASCADE |
| SESSION_STATES | session_id | USSD_SESSIONS | CASCADE |
| SETTLEMENT_BATCHES | service_provider_id | SERVICE_PROVIDERS | RESTRICT |
| SETTLEMENT_ENTRIES | batch_id | SETTLEMENT_BATCHES | RESTRICT |

---

## Compliance

### ISO Standards Mapping

| ISO Standard | Requirement | Implementation |
|--------------|-------------|----------------|
| **ISO 27001:2022** | A.5.18 - Access rights | Account status (ACTIVE/FROZEN/CLOSED) enforces access control |
| **ISO 27001:2022** | A.5.24 - Information security incident management | SESSION_STATES tracks error conditions for incident analysis |
| **ISO 27001:2022** | A.8.2 - Privileged access rights | Service provider segregation via SERVICE_PROVIDERS table |
| **ISO 20022** | Cash management | SETTLEMENT_BATCHES structure aligned with camt.053 messages |
| **ISO 8583** | Reconciliation | Settlement batch totals support 8583 reconciliation fields |
| **ISO 27017** | Cloud security | Multi-tenant isolation via service_provider_id |

### Regulatory Compliance

| Regulation | Schema Compliance |
|------------|-------------------|
| **PCI DSS 4.0** | No cardholder data stored; account tokens only |
| **GDPR Article 25** | Data minimization in kyc_data (JSONB allows selective collection) |
| **AML/CFT** | Account status tracking supports suspicious activity monitoring |
| **PSD2** | Settlement batch structure supports SEPA Instant requirements |

---

## Security Considerations

### Account Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    ACCOUNT SECURITY LAYERS                       │
├─────────────────────────────────────────────────────────────────┤
│ 1. Account Status Controls                                       │
│    - ACTIVE: Full transaction capability                         │
│    - FROZEN: No debits, credits allowed (investigation mode)     │
│    - CLOSED: No transactions, read-only history                  │
├─────────────────────────────────────────────────────────────────┤
│ 2. Balance Protection                                            │
│    - hold_balance: Reserved funds (escrow, pending disputes)     │
│    - pending_balance: Uncleared funds (check deposits, etc.)     │
│    - available_balance: Immediately usable funds                 │
├─────────────────────────────────────────────────────────────────┤
│ 3. Session Security                                              │
│    - 30-second timeout prevents session hijacking                │
│    - client_ip tracking for anomaly detection                    │
│    - session_context stores device fingerprinting                │
├─────────────────────────────────────────────────────────────────┤
│ 4. Settlement Controls                                           │
│    - RESTRICT on delete prevents orphaned batches                │
│    - Batch close creates immutable snapshot                      │
│    - Settlement schedules enforce T+n controls                   │
└─────────────────────────────────────────────────────────────────┘
```

### Data Protection Controls

| Control | Implementation |
|---------|---------------|
| KYC Data Encryption | kyc_data JSONB field encrypted at application layer |
| MSISDN Tokenization | Phone numbers tokenized before storage |
| Settlement Account Masking | Account numbers masked (****1234) in database |
| Session Context Isolation | Session data purged after 90 days |

### Threat Mitigation

| Threat | Mitigation Strategy |
|--------|---------------------|
| Account takeover | Status FROZEN prevents transactions during investigation |
| Balance manipulation | Async reconciliation with ledger ensures consistency |
| Settlement fraud | RESTRICT constraints prevent batch manipulation |
| Session replay | Session timeout and UUID uniqueness prevent replay |

---

## Audit Requirements

### Required Audit Events

| Event Type | Table | Retention | Justification |
|------------|-------|-----------|---------------|
| Account status change | ACCOUNTS (history table) | 7 years | Regulatory requirement for frozen/closed accounts |
| Settlement batch close | SETTLEMENT_BATCHES | 7 years | Financial audit trail |
| Session creation | USSD_SESSIONS | 90 days | Fraud investigation support |
| Balance reconciliation | ACCOUNT_BALANCES (history) | 1 year | Dispute resolution |
| Provider status change | SERVICE_PROVIDERS (history) | 7 years | Contract compliance |

### Audit Query Examples

```sql
-- Account status change audit trail
SELECT 
    account_id,
    status,
    changed_at,
    changed_by,
    reason_code,
    LAG(status) OVER (PARTITION BY account_id ORDER BY changed_at) as previous_status
FROM account_status_history
WHERE account_id = 'ACC-123456789'
ORDER BY changed_at DESC;

-- Settlement batch audit
SELECT 
    sb.batch_id,
    sb.service_provider_id,
    sb.status,
    sb.total_amount,
    sb.closed_at,
    COUNT(se.settlement_entry_id) as actual_entry_count,
    SUM(se.amount) as actual_total
FROM settlement_batches sb
LEFT JOIN settlement_entries se ON sb.batch_id = se.batch_id
WHERE sb.batch_date BETWEEN '2025-03-01' AND '2025-03-31'
GROUP BY sb.batch_id
HAVING sb.total_amount != SUM(se.amount) OR sb.entry_count != COUNT(se.settlement_entry_id);

-- High-risk account activity
SELECT 
    a.account_id,
    a.status,
    COUNT(DISTINCT s.session_id) as session_count,
    COUNT(DISTINCT st.tx_id) as transaction_count,
    SUM(CASE WHEN st.status = 'FAILED' THEN 1 ELSE 0 END) as failed_count
FROM accounts a
LEFT JOIN ussd_sessions s ON a.account_id = s.account_id
LEFT JOIN session_transactions st ON s.session_id = st.session_id
WHERE s.started_at > NOW() - INTERVAL '24 hours'
GROUP BY a.account_id
HAVING COUNT(DISTINCT st.tx_id) > 100  -- Unusual volume
   OR SUM(CASE WHEN st.status = 'FAILED' THEN 1 ELSE 0 END) > 10;  -- High failure rate
```

### Audit Evidence Package

For regulatory examinations:
1. **Account Lifecycle Report** - All status changes with justification
2. **Settlement Reconciliation** - Batch totals vs. ledger entries
3. **Session Forensics** - Complete session flow for disputed transactions
4. **Provider Performance** - SLA metrics and settlement timeliness

---

## Data Protection Notes

### Data Classification

| Field | Classification | Protection Level |
|-------|---------------|------------------|
| account_id | Internal | Standard access controls |
| msisdn | Sensitive (PII) | Tokenized + encrypted |
| kyc_data | Sensitive (PII) | Application-level AES-256 encryption |
| settlement_accounts | Sensitive | Masked display, encrypted storage |
| session_context | Internal | Purged after retention period |
| client_ip | Internal | Used for fraud detection only |

### Retention Policy

| Data Type | Hot Storage | Warm Storage | Cold Storage | Deletion |
|-----------|-------------|--------------|--------------|----------|
| Accounts | Indefinite | - | - | Soft delete only (anonymize) |
| Account balances | 90 days | 1 year | 7 years | After 7 years |
| USSD sessions | 30 days | 90 days | 1 year | After 1 year |
| Session states | 30 days | 90 days | 1 year | After 1 year |
| Settlement batches | 7 years | 10 years | Indefinite | Never |
| Service providers | Indefinite | - | - | Soft delete only |

### Data Subject Rights Implementation

| Right | Technical Implementation |
|-------|-------------------------|
| Right to Access | Export account data, sessions, and settlements |
| Right to Rectification | Update kyc_data with audit trail |
| Right to Erasure | Close account (soft delete, preserve settlements) |
| Right to Restrict Processing | Freeze account status |
| Right to Data Portability | Export in ISO 20022 format |

---

## TODOs

- [ ] Implement account status change audit logging
- [ ] Add soft-delete pattern for closed accounts
- [ ] Create materialized view for high-velocity balance queries
- [ ] Implement session timeout auto-cleanup job
- [ ] Add settlement batch auto-close scheduler
- [ ] Design multi-currency balance handling
- [ ] Create provider settlement forecasting model
- [ ] Implement account merge/split procedures
