# USSD Immutable Ledger Kernel

## Clean 2-Schema Architecture

**Total Files:** 16 SQL files  
**Total Lines:** ~8,700 lines  
**Schemas:** 2 (ussd_core, ussd_app)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ussd_core SCHEMA                             │
│              (Immutable Foundation - Business Agnostic)              │
├─────────────────────────────────────────────────────────────────────┤
│  account_registry         - Participant registry (users, groups,     │
│                             merchants, system accounts)              │
│  transaction_types        - Generic transaction type catalog         │
│  transactions             - IMMUTABLE transaction log                │
│  blocks                   - Cryptographic batching with Merkle trees │
│  merkle_trees             - Tree structure for inclusion proofs      │
│  state_snapshots          - Derived state (rebuildable from log)     │
│  agent_relationships      - Generic graph links between accounts     │
│  security/encryption      - Keys, signatures, field encryption       │
│  integrity_verification   - Hash chain verification service          │
└─────────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────┐
│                          ussd_app SCHEMA                             │
│            (Application Layer - Multi-Tenancy & Config)              │
├─────────────────────────────────────────────────────────────────────┤
│  applications             - App registry & versioning                │
│  account_memberships      - Account-to-app enrollment                │
│  roles/permissions        - RBAC system                              │
│  configuration_store      - Mutable config with audit trail          │
│  feature_flags            - Hierarchical feature toggles             │
│  hooks                    - Extensibility points                     │
│  entity_sequences         - Sequential code generators               │
│  audit_infrastructure     - App-level audit logging                  │
│  multi_tenancy_utils      - Tenant isolation & quotas                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Core Principles

### 1. Kernel is Business-Agnostic
- NO business logic (loans, payments, transfers)
- NO accounting rules (debit/credit, COA)
- NO settlement logic
- ONLY generic primitives for building any USSD application

### 2. Applications Define Business Logic
- Register their own transaction types
- Define their own relationship types
- Configure their own hooks
- Set up their own feature flags

### 3. Immutable Core
- Transaction log is append-only
- Hash chaining for tamper evidence
- Merkle trees for batch verification
- No updates or deletes allowed

---

## File Structure

### Core Schema (`sql/core/`)

| File | Description |
|------|-------------|
| `000_setup.sql` | Foundation, extensions, enums |
| `001_account_registry.sql` | Account registry with hierarchy |
| `002_transaction_types.sql` | Transaction type catalog (generic) |
| `003_transaction_log.sql` | **Immutable transaction log** |
| `004_blocks_merkle.sql` | Block batching & Merkle trees |
| `005_state_snapshots.sql` | Derived state snapshots |
| `006_security_layer.sql` | Encryption, keys, RLS |
| `007_integrity_verification.sql` | Hash verification service |
| `008_agent_relationships.sql` | Generic account relationships |
| `099_core_utils.sql` | Utilities & maintenance |

### App Schema (`sql/app/`)

| File | Description |
|------|-------------|
| `100_application_registry.sql` | App registry & lifecycle |
| `101_account_memberships.sql` | Account-app linking |
| `102_rbac_permissions.sql` | Roles & permissions |
| `103_configuration_store.sql` | Config & feature flags |
| `104_hooks_system.sql` | Extensible hooks |
| `105_entity_sequences.sql` | Sequential code generators |
| `150_audit_infrastructure.sql` | App-level audit logging |
| `199_app_utils.sql` | Multi-tenancy utilities |

---

## Deployment

```bash
# 1. Create database
createdb ussd_kernel

# 2. Deploy core schema
for f in sql/core/*.sql; do
  psql ussd_kernel -f "$f"
done

# 3. Deploy app schema
for f in sql/app/*.sql; do
  psql ussd_kernel -f "$f"
done
```

---

## Usage Example

### 1. Register an Application
```sql
-- Applications register themselves
SELECT ussd_app.register_application(
    'my_transport_app',
    'Transport Services',
    'owner_account_uuid'::UUID,
    'logistics'
);
```

### 2. Define Transaction Types
```sql
-- Applications define their own transaction types
SELECT ussd_app.enable_transaction_type(
    'my_transport_app'::UUID,
    'TRANSFER',  -- Generic kernel type
    '{"custom_name": "Ride Payment"}'::JSONB
);
```

### 3. Submit Transaction
```sql
-- Submit to immutable core log
SELECT * FROM ussd_core.submit_transaction(
    'unique-idempotency-key',
    'TRANSFER',
    'account_uuid'::UUID,
    '{"amount": 100, "to": "other_account"}'::JSONB,
    'my_transport_app'::UUID
);
```

---

## Key Features

### Immutability
- Database-level triggers prevent UPDATE/DELETE on core tables
- Compensating transactions only (new records)
- Hash chaining links every transaction

### Multi-Tenancy
- Row-Level Security (RLS) policies
- Tenant context via `ussd_app.set_tenant_context()`
- Per-application resource quotas

### Extensibility
- Hook system for pre/post commit actions
- Feature flags with rollout strategies
- Configurable relationship types

### Security
- Field-level encryption
- API key management
- Session handling
- Audit trails

---

## No Business Logic

This kernel does **NOT** include:
- ❌ Double-entry accounting
- ❌ Loan management
- ❌ Payment processing
- ❌ Settlement logic
- ❌ Chart of accounts
- ❌ Tax calculation
- ❌ IFRS 9 provisions

These belong in **business applications** that use this kernel.

---

## License

Enterprise Grade - See LICENSE file
