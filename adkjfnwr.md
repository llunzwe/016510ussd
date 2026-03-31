## Kernel Core Schema – Enterprise‑Grade Features & Components (Fully Immutable)
The **Core Schema** is the append‑only, cryptographically verifiable foundation of the kernel. Every fact recorded here is permanent and tamper‑evident. It stores all transactions across all USSD applications (transport, health, e‑commerce, etc.) and the essential low‑level state needed to validate and audit them.
---
### 1. Immutable Data Structures
| Component | Description |
|-----------|-------------|
| **Account Registry** | Stores every participant (user, group, merchant, system account) with a unique identifier, account type, metadata, and optional public key for cryptographic signing. Supports hierarchical relationships (e.g., group members). Accounts are tagged with a primary `application_id` but can be shared across applications via the App Schema mapping. |
| **Transaction Types Registry** | A global catalogue of allowed transaction types (e.g., `TRANSFER`, `RIDE_BOOKING`, `LOAN_DISBURSEMENT`). Each type defines a JSON schema for payload validation, required approvals, and references to validation hooks. Types can be global (all applications) or scoped to a specific `application_id`. |
| **Append‑Only Transaction Log** | The central immutable table where every state change is recorded as a row. Fields include: unique ID, previous hash, current hash, transaction type, JSON payload, timestamp, idempotency key, digital signature, initiator, status, and block reference. No row can ever be updated or deleted. |
| **Block / Batch Table** | Aggregates transactions into cryptographic blocks (time‑based or size‑based). Stores block height, time range, list of transaction IDs, Merkle root, kernel signature, and optional external anchor (e.g., blockchain transaction ID). Blocks are also immutable once sealed. |
| **State Snapshots (Core)** | Materialized views derived from the transaction log, providing fast access to current account balances, sequence numbers, and last hash values. These are refreshed periodically or on‑demand and can be rebuilt entirely from the log. |
---
### 2. Immutability & Integrity Enforcement
| Component | Description |
|-----------|-------------|
| **Cryptographic Hash Chaining** | Each transaction stores the hash of the previous transaction (per‑account or global chain). This creates a tamper‑evident chain; altering any historical transaction breaks the link. |
| **Merkle Tree Batching** | Transactions are grouped into blocks, and a Merkle tree is built over their hashes. The root hash is stored and signed, enabling efficient inclusion proofs and external anchoring. |
| **Database-Level Immutability** | `BEFORE UPDATE` and `BEFORE DELETE` triggers on all core tables raise exceptions. Permissions are set to allow only `INSERT`. All corrections must be made via compensating transactions (new entries). |
| **Integrity Verification Service** | A background process that continuously verifies hash chains and Merkle trees, alerting on any mismatch. Exposes APIs for external auditors to request proofs of inclusion and consistency. |
| **Write‑Once Storage Semantics** | The storage layer (PostgreSQL with WAL archiving) and backup strategies are configured to prevent any circumvention of immutability (e.g., no direct file edits). Replicas follow the same rules. |
---
### 3. Transaction Processing (Core Level)
| Component | Description |
|-----------|-------------|
| **Idempotency Management** | A global table stores idempotency keys. Before accepting a transaction, the kernel checks if the key already exists; if so, returns the prior result. Prevents duplicate processing across all applications. |
| **Basic Validation Engine** | Verifies account existence, transaction type validity, payload conformance to JSON schema, and signature (if provided). This is the core’s minimal, schema‑only validation – no business logic. |
| **ACID Transactions** | All core writes (insert transaction, update materialized views, record idempotency) are wrapped in a database transaction with `SERIALIZABLE` isolation level for full atomicity and consistency. |
| **Concurrency Control** | Uses optimistic locking (based on hash chain verification) and, where necessary, PostgreSQL advisory locks to prevent race conditions when updating account sequence numbers. |
| **Rejection Handling** | Transactions that fail validation are not stored in the immutable log. A separate rejection log (outside the core) records the attempt, reason, and idempotency key for troubleshooting. |
| **Lifecycle Hooks (Core Exit Points)** | Pre‑commit and post‑commit hooks allow external modules (e.g., application layer, blockchain anchor) to react to transaction events without modifying core code. Core itself is stateless regarding business logic. |
---
### 4. Query & Retrieval (Core-Facing)
| Component | Description |
|-----------|-------------|
| **Account State Queries** | Real‑time retrieval of account balances and metadata from materialized views, with sub‑second latency. Supports point‑in‑time queries by replaying the log from a snapshot. |
| **Transaction History** | Paginated, filterable queries by account, date range, transaction type, amount range, and `application_id`. Optimised for high throughput and USSD screen constraints (short lists). |
| **Full‑Text Search** | Indexed search over transaction payloads (JSON) for auditing and support. Enables finding specific references (e.g., order IDs, ride IDs). |
| **Materialized View Refresh** | Automated refresh strategies (time‑based, commit‑based, or on‑demand) to keep core state snapshots consistent with the immutable log while minimising performance impact. |
| **Audit Trail Queries** | Dedicated APIs to retrieve the full, immutable history of changes to any core entity, including account creation, type registration, and administrative actions. |
---
### 5. Security & Access Control (Core)
| Component | Description |
|-----------|-------------|
| **API Authentication** | All core APIs are protected via mutual TLS (mTLS), API keys, or OAuth2 tokens with scope‑based permissions. The core does not handle user authentication directly; it trusts the application layer. |
| **Role‑Based Access Control (RBAC)** | Fine‑grained authorisation for core operations: `read_transaction`, `submit_transaction`, `verify_integrity`, `admin_config`. Roles are assigned in the App Schema but enforced in Core via RLS. |
| **Row‑Level Security (RLS)** | PostgreSQL RLS policies ensure that users can only access transactions and accounts for which they have explicit permission (based on `application_id` and account membership). |
| **Data Encryption at Rest** | Full‑database encryption (TDE) plus per‑field encryption for sensitive data (e.g., PII in account metadata) using AEAD (AES‑256‑GCM) with keys managed by a KMS (Hashicorp Vault, AWS KMS). |
| **Key Management** | Secure storage of the kernel’s signing keys (for block roots) and user public keys. Integrated with hardware security module (HSM) or cloud KMS. Keys never appear in logs or backups. |
| **Audit Logging** | All access attempts, configuration changes, and administrative actions on core tables are logged in a separate, append‑only audit table (outside core) for compliance and forensic analysis. |
---
### 6. Extensibility & Modularity (Core)
| Component | Description |
|-----------|-------------|
| **Pluggable Storage Backends** | Abstraction layer (via database connectors) allows the core logic to run on PostgreSQL, CockroachDB, or cloud‑native databases. The SQL schema remains portable. |
| **Transaction Type Plugins** | New transaction types can be added by inserting metadata and providing a JSON schema. No code changes to core are required. Advanced validation can be delegated to external services via hooks. |
| **Extension Hooks** | Event‑driven hooks (pre‑commit, post‑commit, block‑creation) allow custom modules (e.g., blockchain anchoring, real‑time analytics) to integrate without modifying core code. Hooks are registered in the App Schema. |
| **Blockchain Anchor Extension** | A separate, optional module that listens for new blocks, submits Merkle roots to a public blockchain (Ethereum, Stellar, etc.), and records the anchor transaction hash back into the core. Not part of core itself. |
| **Admin Console (Core View)** | A web‑based interface for kernel administrators to monitor core integrity, view transaction logs, manage transaction types, and configure hooks – with read‑only access to immutable data. |
---
### 7. Operational & Observability (Core)
| Component | Description |
|-----------|-------------|
| **High Availability** | Active‑passive or active‑active PostgreSQL clustering with automatic failover. Synchronous replication for critical regions to ensure zero data loss. |
| **Disaster Recovery** | Point‑in‑time recovery (PITR) and off‑site encrypted backups. The immutable log allows recovery to any transaction ID or timestamp by restoring a snapshot and replaying subsequent transactions. |
| **Monitoring & Metrics** | Prometheus metrics for transaction throughput, latency, error rates, chain integrity status, hash verification failures, and resource usage (CPU, memory, disk). Dashboards in Grafana. |
| **Alerting** | Proactive alerts for integrity failures (hash chain mismatch), performance degradation (high commit latency), unusual activity (massive idempotency key collisions), or certificate expiry. |
| **Backup & Restore** | Automated, encrypted full and incremental backups. Ability to restore to a specific transaction ID or timestamp. Backups include all core tables and their immutability constraints. |
| **Capacity Planning** | Tools to estimate storage growth based on transaction volume, partition sizes, index bloat, and replication lag. Reports on per‑application consumption. |
---
### 8. Integration Interfaces (Core)
| Component | Description |
|-----------|-------------|
| **REST API** | JSON over HTTPS for all core operations. Well‑documented with OpenAPI. Used by the App Schema (internal) and by external application services for direct submission when no business logic is needed. |
| **gRPC** | High‑performance, strongly‑typed interface for internal services (e.g., App Schema, integrity verifier) that require low latency and bidirectional streaming. |
| **Event Stream** | Real‑time transaction events published to Kafka or NATS. Allows downstream systems (fraud detection, analytics, USSD session manager) to react instantly without polling. |
| **Webhook Callbacks** | Configurable endpoints (per application) to receive notifications on specific transaction completions. Managed by the App Schema, triggered by core post‑commit hooks. |
| **Client SDKs** | Official SDKs in Python, Node.js, Go, and Java to simplify integration for application services and third‑party developers. |
---
### 9. Governance & Compliance (Core)
| Component | Description |
|-----------|-------------|
| **Data Retention Policies** | Configurable retention periods per transaction type and application. Deletion (if legally required) is handled by moving partitions to cold storage while preserving cryptographic proofs. No in‑place deletion. |
| **Regulatory Reporting** | Pre‑built queries and exports for central bank, tax, or AML reporting. Reports are generated from the immutable log, ensuring they are reproducible and auditable. |
| **Privacy by Design** | Personal data (e.g., MSISDN, name) is stored in a separate, encrypted table with minimal retention. Aggregated views and hashed identifiers are used for analytics. |
| **Legal Hold** | Ability to mark specific records or entire partitions for indefinite retention during litigation. The hold prevents any automated purging or archiving. |
| **Proof of Existence / Non‑Repudiation** | For any transaction, the kernel can provide a cryptographic proof (Merkle proof and hash chain) that the transaction existed at a specific time and that the chain has not been altered. |
---
### 10. Performance & Scalability (Core)
| Component | Description |
|-----------|-------------|
| **Horizontal Partitioning** | `transactions` table partitioned by `application_id` (list partition) then by time (range partition, e.g., monthly). Keeps indexes small and manageable. Allows efficient per‑app data purging by dropping old partitions. |
| **Read Replicas** | Multiple read replicas to offload query traffic. Replicas can be configured with slight lag to reduce load on the primary. Some replicas may exclude materialised views for faster replay. |
| **Caching Layer** | Redis cluster for frequently accessed data (account balances, last transaction hashes, idempotency keys) with invalidation on new commits. Partitioned by `application_id` to avoid cross‑tenant leakage. |
| **Connection Pooling** | PgBouncer or built‑in connection pools to handle thousands of concurrent USSD sessions efficiently. Separate pools for read and write operations. |
| **Async Commit** | For non‑critical operations (e.g., analytics logging), the core can accept requests asynchronously and return a tracking ID. Critical transactions always commit synchronously. |
| **Bulk Operations** | APIs for importing large transaction sets (e.g., initial migration from legacy systems) while maintaining integrity, idempotency, and hash chaining. Bulk loads are atomic and verified after completion. |
---
## Kernel App Schema – Enterprise‑Grade Features & Components (Hybrid: Immutable + Mutable)
The **App Schema** is part of the kernel and provides multi‑tenancy, per‑application configuration, role management, and application‑specific business logic hooks. It is **not** a dumping ground for domain data (routes, products, etc.). It stores data that is either **immutable** (auditable events, versioned configurations) or **mutable with full audit** (feature flags, runtime settings). All changes that affect business rules are logged immutably.
---
### 1. Application Registry (Immutable Core of App Schema)
| Component | Description |
|-----------|-------------|
| **Application Definition** | Stores metadata for each application: unique ID, name, description, owner, status (active, suspended, archived), creation timestamp. This table is **append‑only**; status changes create a new row with `superseded_by` pointer. |
| **Application Versioning** | Supports versioned configurations. Each application can have multiple versions; transactions reference a specific `application_version_id` at creation. Versions are also immutable once published. |
| **Application Lifecycle Management** | APIs to create, update (→ new version), suspend, or archive applications. Every change is recorded as a new immutable record in the application registry and audited in the global audit log. |
---
### 2. Account‑Application Membership (Immutable / Versioned)
| Component | Description |
|-----------|-------------|
| **Account to Application Mapping** | A many‑to‑many table linking core accounts to applications. Includes `valid_from` and `valid_to` timestamps (immutable versioning). An account can be enrolled in multiple applications over time. |
| **Application‑Specific Metadata** | For each membership, stores application‑specific information (e.g., role, nickname, settings). Changes create a new membership version (append‑only). |
| **Enrolment Workflow** | APIs to enrol, update, or terminate an account’s participation in an application. All changes are immutable and auditable. Current active membership is a view filtering `valid_to IS NULL`. |
---
### 3. Role & Permission Management (Immutable / Versioned)
| Component | Description |
|-----------|-------------|
| **Application Roles** | Predefined roles per application (e.g., `passenger`, `driver`, `admin`). Stored in an append‑only table with versioning. Roles can be added or deprecated (new version with `deprecated_at`). |
| **Permission Definitions** | A catalogue of permissions (e.g., `can_submit_ride`, `can_approve_loan`). Permissions are global or application‑scoped. Stored immutably. |
| **Role‑Permission Grants** | Many‑to‑many mapping between roles and permissions, versioned. Changes (e.g., adding a permission to a role) create new rows. |
| **User Role Assignments** | Assigns a role to an account within an application. Versioned (valid_from/to). Current effective roles are derived from the latest assignment. All changes are audited. |
| **RBAC Enforcement** | The App Schema evaluates permissions before forwarding transactions to Core. The evaluation uses the current (mutable) effective role assignments but the history is fully immutable. |
---
### 4. Transaction Type Scoping (Immutable / Versioned)
| Component | Description |
|-----------|-------------|
| **Per‑Application Transaction Types** | Links core transaction types to applications. Allows an application to enable/disable a global type or define its own application‑specific type. Stored in an append‑only table. |
| **Application‑Specific Validation Rules** | JSON definitions of additional validation logic (e.g., balance checks, external API calls) per transaction type and application. Rules are versioned – changes create new rows. |
| **Payload Schema Extensions** | An application can extend the core JSON schema for a transaction type (e.g., adding `route_id` for ride bookings). The merged schema is validated by Core. Stored immutably. |
| **Rule Execution Order** | Defines the sequence in which validation rules are executed (e.g., local balance check first, then external fraud service). Stored as part of the versioned configuration. |
---
### 5. Application Configuration Store (Mutable with Immutable Audit)
| Component | Description |
|-----------|-------------|
| **Configuration Store** | A mutable table holding current JSON configuration per application (e.g., `default_currency`, `fee_percentage`, `settlement_account_id`). Direct updates are allowed but **every change is logged** in an immutable audit table. |
| **Audit Log for Config Changes** | Append‑only table recording old value, new value, changed by user, timestamp, and reason. This audit log is part of the kernel and cannot be altered. |
| **Configuration Versioning (Optional)** | For critical parameters, the kernel can be configured to require versioned configs (immutable rows) instead of mutable updates. The choice is enterprise policy. |
| **Feature Flags** | Mutable table for runtime toggles (e.g., `allow_credit`, `require_approval`). Each flag change is audited. Feature flags can be applied per application, per account, or globally. |
| **Configuration Validation** | Before accepting a config change, the kernel validates against a schema and may run impact analysis (e.g., ensure settlement account exists). Rejected changes are not applied and are logged. |
---
### 6. Application‑Specific Business Logic Hooks (Mutable with Audit)
| Component | Description |
|-----------|-------------|
| **Pluggable Rule Engines** | Each application can register pre‑commit and post‑commit hooks (URLs or stored procedures). Hooks are stored in a mutable table with audit logging. |
| **Hook Execution Order** | Defines priority and error‑handling behaviour (e.g., fail‑fast or continue on error). Stored in configuration, audited. |
| **Retry & Dead‑Letter Policies** | For asynchronous hooks (e.g., Kafka, webhooks), the kernel supports retry queues, exponential backoff, and dead‑letter topics. Policies are per‑application and auditable. |
| **Hook Metrics** | Tracks hook invocation count, latency, success/failure rates. Used for monitoring and billing. |
---
### 7. Application‑Specific State Snapshots (Derived, Rebuildable)
| Component | Description |
|-----------|-------------|
| **Materialized Views per Application** | The App Schema can maintain its own materialised views (e.g., driver earnings, patient appointment count) derived from core transactions filtered by `application_id`. These are **not** sources of truth – they can be rebuilt at any time. |
| **Refresh Strategies** | Configurable refresh: on‑commit (synchronous), time‑based (every N seconds), or on‑demand (API call). Refresh is atomic and isolated from core writes. |
| **Snapshot Versioning** | The App Schema can store historical snapshots (e.g., end‑of‑day balances) as immutable rows for fast reporting without replaying the entire log. |
| **Consistency Guarantees** | Snapshots are eventually consistent with the core log. Applications that require strong consistency query core directly or use synchronous refresh. |
---
### 8. Multi‑Tenancy & Isolation (Enforced by App Schema)
| Component | Description |
|-----------|-------------|
| **Resource Quotas** | Per‑application limits on transaction rate (TPS), storage (total log size), API calls, and hook executions. Quotas are stored in mutable config (audited). Enforced by API gateway and core. |
| **Tenant‑Aware Caching** | Redis cache is partitioned by `application_id`. Cache keys include the application ID to prevent cross‑tenant data leakage. |
| **Isolated Background Processes** | Merkle tree batching, integrity verification, and snapshot refresh can be configured per application (e.g., different block intervals). Processes are scheduled globally but filter by `application_id`. |
| **Cross‑Application Visibility** | By default, accounts see only their own application data. Administrators with special roles (e.g., `system_auditor`) can query across applications, but all such accesses are logged. |
---
### 9. Integration with USSD Kernel & External Services
| Component | Description |
|-----------|-------------|
| **Application Code Routing** | The USSD kernel’s service router maps a USSD short code or menu option to an `application_id`. The App Schema provides the lookup table (mutable, audited). |
| **Application‑Aware Session** | The USSD session manager stores the current `application_id` and role. The App Schema provides APIs to validate session context. |
| **Application‑Specific Menus** | The USSD menu engine can load application‑specific menu trees (JSON) from the App Schema’s configuration store. Menus are mutable but changes are audited. |
| **External Application Service Integration** | The App Schema stores endpoint URLs and authentication secrets for external application services (e.g., route service, product catalogue). Secrets are encrypted. Changes are audited. |
| **API Rate Limiting** | Per‑application rate limiting (e.g., 1000 requests/minute) configured in App Schema and enforced by the API gateway. |
---
### 10. Observability & Monitoring (Application‑Aware)
| Component | Description |
|-----------|-------------|
| **Per‑Application Metrics** | Prometheus metrics tagged with `application_id`: transaction throughput, latency, error rates, quota utilisation, hook success/failure. |
| **Application‑Level Logging** | All logs (including core audit logs) include `application_id`. Log aggregation tools (Loki, ELK) enable filtering and correlation by application. |
| **Application Health Dashboard** | Dedicated Grafana dashboard for each application showing status, recent transaction volumes, integrity alerts, and resource consumption. |
| **Billing & Usage Tracking** | The App Schema records usage metrics (transaction count, storage, hook calls) per application. These are stored in immutable usage tables for invoicing and chargeback. |
| **Audit Trail for App Changes** | All changes to application configuration, role assignments, hooks, and quotas are stored in an immutable audit table (separate from core audit). This ensures full traceability of administrative actions. |
---
### 11. Governance & Compliance (App Schema)
| Component | Description |
|-----------|-------------|
| **Data Retention per Application** | Each application can have its own retention policy for core transactions (e.g., transport: 5 years, health: 10 years). The App Schema stores the policy (audited) and the kernel enforces it during partition management. |
| **Privacy Controls** | The App Schema can tag fields in core transaction payloads as “PII”. The core will then encrypt those fields. The App Schema manages the tagging schema (immutable). |
| **Legal Hold per Application** | Legal hold flags can be applied to specific applications or accounts. The App Schema stores the hold status (mutable but audited) and the kernel enforces retention. |
| **Regulatory Reporting Hooks** | The App Schema can register reporting endpoints (e.g., for central bank). When a report is requested, the kernel invokes these hooks with the appropriate data scope. |
| **Proof of Non‑Repudiation** | The App Schema can request cryptographic proofs from the core for any transaction within its application. The proof includes Merkle path and hash chain, verifiable independently. |
---
### 12. Extensibility & Future Proofing (App Schema)
| Component | Description |
|-----------|-------------|
| **Application‑Specific Extensions** | The kernel’s extension hooks (e.g., blockchain anchoring, real‑time notifications) can be configured per application via the App Schema. Each application decides whether to anchor its Merkle roots. |
| **Custom Application Modules** | Application owners can deploy microservices that integrate with the kernel via its standard APIs. The App Schema stores the endpoints and authentication for these modules (audited). |
| **Application Marketplace** | A future extension where third‑party developers can build and deploy new applications on the kernel. The App Schema will support marketplace metadata, billing, and usage tracking. |
| **Self‑Service Onboarding** | APIs and workflows for application owners to create new applications, define transaction types, and configure hooks – all subject to approval workflows managed by the App Schema. |
| **Schema Evolution** | The App Schema supports non‑breaking changes (e.g., adding a new optional field to a payload schema) via versioning. Breaking changes require a new application version or a new transaction type. |
---
## Summary – Kernel as Single Source of Truth
| Schema | Role | Immutability | Mutability |
|--------|------|--------------|------------|
| **Core** | Immutable transaction log, account registry, cryptographic proofs | **100%** – no updates or deletes | None |
| **App** | Application registry, roles, config, hooks, audit logs | **Immutable events and versioned data** | Mutable config (fully audited), ephemeral session state |
**Key enterprise guarantees:**
- Every transaction that affects business state is permanently recorded in Core.
- Every change to application configuration or roles is either versioned (immutable) or fully audited.
- The kernel (Core + App) is the **only source of truth** for all auditable events and critical configurations.
- Domain‑specific data (routes, products, patient records) lives **outside** the kernel, keeping the kernel lean, fast, and focused on its integrity mission.
---
# Comprehensive List of Applicable Features for the USSD Immutable Ledger Kernel
This document combines and filters features from the **FinOS Core Kernel** and the **InsureLedger Kernel** to produce a definitive set of components for a **USSD‑focused immutable ledger** (Core + App schemas). Only features that directly support savings groups, micro‑loans, marketplaces, transport, health, and e‑commerce are included. The list is organised by functional domain, with clear justifications for each component.
---
## 1. Identity & Multi‑Tenancy (Application Registry)
| Component | Description | USSD Justification |
|-----------|-------------|---------------------|
| **Application (Tenant) Registry** | Stores each USSD application (transport, health, e‑commerce, savings group, micro‑loan) with unique ID, name, owner, status (active/suspended), base currency, timezone, and configuration JSON. Supports soft delete and bitemporal validity. | Each USSD service is isolated as a tenant. Enables per‑app settings (e.g., default fees, allowed transaction types, feature flags). |
| **Account Registry (Participants)** | Stores all actors: individual users, groups (savings groups), merchants, system accounts. Includes account type (user/group/merchant/system), metadata, optional public key for signing, and KYC/AML fields (risk score, sanctions status). | Single source of truth for all ecosystem participants. Groups are first‑class accounts. KYC fields for micro‑finance compliance. |
| **Account‑Application Membership** | Many‑to‑many mapping linking accounts to applications, with per‑application metadata (e.g., role within that app). Supports valid_from/valid_to for versioned membership. | A user can be a “driver” in transport app, a “patient” in health app, and a “member” in a savings group – each with different permissions. |
| **Entity Sequences (Human‑readable codes)** | Generates tenant‑scoped sequential codes (e.g., `CONT-2025-000123` for contribution, `LOAN-2025-000045` for loan). | USSD users see short, memorable references. Helps with customer support and reconciliation. |
| **Agent Relationships (Graph)** | Directed edges between accounts: ownership, group membership, employment, representation, agency, guarantee, beneficiary. Supports percentages, temporal validity, and circular detection. | Models group‑member relationships, loan guarantors, merchant‑agent hierarchies. Enables complex queries (e.g., “find all members of group X”). |
## 2. Core Immutable Ledger (Value Storage & Movements)
| Component | Description | USSD Justification |
|-----------|-------------|---------------------|
| **Value Containers (Accounts)** | Universal accounts with account class (asset/liability/equity/income/expense), currency, balance, held balance, state (active/frozen/closed). Supports hierarchy (LTREE) for sub‑ledgers and virtual accounts. | Each user, group, merchant, and system (e.g., fee account) has a container. Balances are derived from immutable movements. |
| **Virtual Accounts & Master Account Segregation** | Virtual accounts linked to a master container; auto‑sweep rules; support for IBAN generation/validation. | Enables virtual wallets for USSD users without creating separate physical bank accounts. Sweep rules consolidate funds into a master account. |
| **Double‑Entry Value Movements** | Immutable movement headers with total_debits = total_credits (conservation enforced). Status: draft → pending → posted → reversed. Fields: reference, entry_date, value_date, currency, exchange_rate, batch_id, correlation_id, idempotency_key. | Every financial event (contribution, loan disbursement, repayment, ride payment, product purchase) is a movement. Double‑entry guarantees integrity. |
| **Movement Legs** | Debit/credit legs linking to containers. Each leg has sequence number, amount, direction, and optional account code (COA). Leg hash for integrity. | A contribution movement has one leg debiting the member’s wallet and one leg crediting the group savings container. |
| **Movement Postings (Balance History)** | Time‑series table recording running balance per container after each movement. Supports TimescaleDB hypertable for efficient historical queries. | Answer “What was my balance on 1st March?” without replaying all transactions. Essential for USSD balance checks. |
| **Movement Types Registry** | Catalog of allowed movement types (e.g., `CONTRIBUTION`, `LOAN_DISBURSEMENT`, `LOAN_REPAYMENT`, `RIDE_PAYMENT`, `PRODUCT_PURCHASE`, `FEE`, `INTEREST`, `REVERSAL`). Each type defines JSON schema for payload, flags for approval, and custom validation hooks. | Enforces business rules per transaction type. Allows adding new types without core changes. |
| **Idempotency Management** | Global table storing idempotency keys. Before processing a request, kernel checks if key exists; if so, returns previous result. Keys are scoped per application to avoid collisions. | USSD network glitches may resend the same request. Prevents double‑processing (e.g., duplicate loan repayment). |
## 3. Immutability & Cryptographic Integrity
| Component | Description | USSD Justification |
|-----------|-------------|---------------------|
| **Cryptographic Hash Chaining** | Each transaction stores the hash of the previous transaction (per‑account or global chain). Computed as SHA‑256(prev_hash + transaction_data). | Tamper‑evident ledger. Altering any historical transaction breaks the chain – detectable by integrity service. |
| **Merkle Tree Batching** | Periodically (e.g., hourly) group transactions into blocks, build Merkle tree, store root hash. Optional anchoring to a public blockchain (e.g., Stellar, Ethereum). | Enables efficient inclusion proofs. Regulators or auditors can verify that a transaction existed in a batch without accessing the full database. |
| **Database‑Level Immutability** | `BEFORE UPDATE` and `BEFORE DELETE` triggers on all core tables raise exceptions. All corrections are made via compensating transactions (new entries). | Guarantees append‑only nature. No accidental or malicious data alteration. |
| **Integrity Verification Service** | Background process (e.g., cron job) that continuously recomputes hash chains and Merkle roots, alerting on any discrepancy. Exposes API for external auditors to request proofs. | Proactive monitoring. If a hash mismatch occurs, the system alerts immediately. |
| **Entity Streams (Per‑Account Hash Chains)** | Tracks a separate hash chain for each entity (account, group, etc.) with genesis hash, current hash, record count. | Efficient verification of a single account’s history without scanning global chain. |
## 4. Transaction Processing & Lifecycle
| Component | Description | USSD Justification |
|-----------|-------------|---------------------|
| **Transaction Entity (Saga)** | First‑class transaction with status workflow: pending → validating → executing → committed / failed / compensating. Supports participants (initiator, beneficiary, approver) and correlation IDs. | Multi‑step operations (e.g., hold payment, wait for service, then capture). If any step fails, compensation reverses previous steps (e.g., refund). |
| **Transaction Operations** | Individual steps within a transaction, each with its own status, target entity, and compensation operation. | Loan approval workflow: 1) check balance, 2) debit from group, 3) credit to member, 4) update loan status. Step 2 fails → compensation reverses step 1. |
| **Validation Rules Engine** | Pluggable validation logic per transaction type (e.g., balance sufficiency, daily limits, allowed counterparties). Rules can be SQL functions or external microservice calls. | Prevent overdrawing a savings group account or exceeding a member’s contribution limit. |
| **ACID Transactions (SERIALIZABLE)** | All ledger operations (insert movement, update snapshots, record idempotency) wrapped in a database transaction with `SERIALIZABLE` isolation. | Guarantees atomicity: either the entire movement is committed or none of it. Prevents race conditions on balances. |
| **Rejection Handling** | Failed validations are not stored in the immutable log; instead, a rejection record is written to a separate table (outside the ledger) with reason and idempotency key. | Troubleshooting and monitoring. Support can see why a user’s contribution was rejected. |
## 5. Query & Retrieval (Materialised Views)
| Component | Description | USSD Justification |
|-----------|-------------|---------------------|
| **Account State Snapshot** | Materialised view of current balances, last transaction hash, and sequence number per container. Refreshed periodically (e.g., every 5 seconds) or on‑demand. | USSD menus need sub‑second balance retrieval. Avoids replaying transaction log for every request. |
| **Transaction History Queries** | Paginated, filterable queries by account, date range, transaction type, amount range, and application ID. Optimised for USSD screen constraints (short lists). | Show last 5 contributions to a group or last 3 loan repayments. |
| **As‑of (Point‑in‑Time) Queries** | Functions to retrieve state of any entity as of a given system time (audit) or valid time (business). | Dispute resolution: “What was the group balance on 15th March?” |
| **Full‑Text Search over Payloads** | Indexed search on transaction payload JSONB (e.g., searching for a specific reference number). | Customer support can find a transaction by external reference. |
## 6. Entitlements & Access Control (Per‑Application RBAC)
| Component | Description | USSD Justification |
|-----------|-------------|---------------------|
| **Per‑Application Roles** | Predefined roles per application (e.g., `group_admin`, `loan_officer`, `passenger`, `driver`, `patient`, `merchant`). Each role has a set of permissions (e.g., `contribution:create`, `loan:approve`). | Granular control: group members can contribute but only admins can approve loans. |
| **User Role Assignments** | Assigns a role to an account within a specific application, with temporal validity (valid_from/valid_to). | A user may be a driver in transport app and a patient in health app concurrently. Roles can expire (e.g., seasonal driver). |
| **Entitlement Limits** | Per‑entitlement limits: max amount per transaction, daily/monthly limits, allowed counterparties, allowed payment schemes (e.g., SCT, SWIFT, mobile money). | Prevent fraud: group admin can approve loans up to $1000; daily withdrawal limit for members. |
| **Row‑Level Security (RLS)** | PostgreSQL RLS policies enforce that users can only access transactions and accounts for applications they are authorised for. | A transport app user cannot see health app transactions. Group members see only their own group’s data. |
| **API Authentication & Authorisation** | Mutual TLS, API keys (hashed), or OAuth2 tokens. API gateway enforces rate limiting per application. | Secure USSD gateway. Each application (transport, health) gets its own API key. |
## 7. Settlement & External Integration
| Component | Description | USSD Justification |
|-----------|-------------|---------------------|
| **Settlement Instructions** | Tracks settlement of movements to external systems (mobile money, bank). Fields: settlement_method (RTGS, mobile_money, wallet), settlement_date, finality timestamp, external reference (e.g., mobile money transaction ID). | When a user withdraws from a savings group to mobile money, a settlement instruction records the external payout status. |
| **Settlement Failures** | Records failed settlement attempts (insufficient funds, timeout, network error) with retry policies and manual intervention queue. | Handle failed mobile money payouts – retry or flag for manual resolution. |
| **Liquidity Positions (Simplified)** | Real‑time tracking of available liquidity per agent/currency across multiple mobile money wallets or bank accounts. | Prevent over‑spending: if the group’s mobile money wallet has insufficient float, decline withdrawal requests. |
## 8. Reconciliation & Exception Management
| Component | Description | USSD Justification |
|-----------|-------------|---------------------|
| **Reconciliation Runs** | Matches internal ledger movements against external statements (mobile money provider, bank). Period: daily or weekly. | Automatically detect discrepancies between USSD ledger and mobile money settlement reports. |
| **Internal & External Items** | Stores internal movements and external statement lines. Supports matching by reference, amount, date, with tolerance. | Identify missing or duplicate transactions. |
| **Matching Rules** | Rule‑based auto‑matching (exact, fuzzy, tolerance) with confidence scoring. | Auto‑pair a withdrawal movement with a mobile money debit notification. |
| **Suspense Items (Breaks)** | Unmatched items go into suspense queue with aging analysis (0‑1 days, 2‑7 days, 8‑30 days, 90+ days). | Manual review of unresolved discrepancies. Aging helps prioritise older issues. |
| **Suspense Resolution** | Supports resolution actions: match to movement, adjustment, write‑off, refund. Full audit trail of resolution. | Write off a small unmatched amount after investigation. |
## 9. Control & Batch Processing
| Component | Description | USSD Justification |
|-----------|-------------|---------------------|
| **Control Batches** | Groups a set of entries (e.g., from a file or bulk operation) with hash total, amount total, record count. Validates before posting. | Bulk loan disbursement to 500 members – ensure the batch is balanced and complete before committing. |
| **Batch Jobs** | Scheduled or one‑off batch jobs (e.g., daily interest accrual, monthly fee calculation) with progress tracking, retries, and result summary. | Automate end‑of‑day interest on savings group accounts. |
| **End‑of‑Day (EOD) Processing** | Manages daily closing: pre‑validation, cut‑off, balance snapshots, statement generation, control execution, opening next day. Supports rollback. | Close the business day, compute daily balances, generate statements for groups, and prepare for next day’s transactions. |
| **Business Calendar** | Defines business days, holidays, and next/previous business day. | Determine value dates for transactions (e.g., if a holiday, settlement moves to next business day). |
| **Cut‑off Times** | Configurable cut‑off times per transaction type (e.g., contributions after 4 PM processed next day). | USSD users see real‑time cut‑off rules. |
## 10. Document & Evidence Management
| Component | Description | USSD Justification |
|-----------|-------------|---------------------|
| **Document Registry** | Stores references to external documents (PDF, images) with content hash (SHA‑256), encryption, retention period, legal hold flag. Linked to any entity (user, group, transaction). | Attach KYC documents (ID photo, proof of address) to a user account. Attach loan agreement PDF to a loan transaction. |
| **Document Versions** | Version history of documents (e.g., updated loan contract). | Track changes to group bylaws or loan terms. |
| **Digital Signatures (Simplified)** | Records signature of document by a participant using PIN, biometric, or cryptographic key. Supports eIDAS levels (SES, AdES, QES). | USSD user can “sign” a loan agreement using their PIN. Signature stored immutably. |
| **Document Access Log** | Logs every view, download, or share of a document (GDPR compliance). | Audit who accessed a user’s KYC document. |
| **Retention Policies** | Configurable retention per document type (e.g., KYC documents: 5 years, transaction receipts: 7 years). Automated deletion after retention period, respecting legal holds. | Comply with data protection laws. |
| **Legal Hold** | Ability to mark specific records or documents for indefinite retention during litigation or investigation. | Freeze a group’s transaction history during a dispute. |
## 11. Streaming & Real‑time Events
| Component | Description | USSD Justification |
|-----------|-------------|---------------------|
| **Event Streams** | Kafka‑compatible topics (e.g., `ledger.transactions`, `ledger.balances`, `ledger.approvals`). Each stream has partitions, retention, and delivery guarantees (at‑least‑once). | Real‑time notifications: when a contribution is made, update the group’s dashboard and send SMS to members. |
| **Mutation Log (CDC)** | Captures every insert/update/delete on core tables (change data capture). Stores old/new data, changed fields, transaction ID. | Replicate ledger changes to a search index (Elasticsearch) or data warehouse for analytics. |
| **Webhook Subscriptions** | Subscribers (e.g., USSD session manager, external fraud detection) register to receive filtered events via HTTP POST. Supports retry and dead‑letter queue. | Notify an external loyalty system when a user makes a payment. |
| **Materialised View Refresh** | Tracks the last processed mutation ID for each materialised view; supports incremental refresh. | Keep real‑time dashboards (e.g., group contribution totals) updated without full refresh. |
## 12. Peer Caching & Performance
| Component | Description | USSD Justification |
|-----------|-------------|---------------------|
| **Read Replicas** | Multiple PostgreSQL read replicas to offload query traffic. Replicas can have slight lag (eventual consistency). | USSD balance checks and history queries go to replicas, reducing load on the primary. |
| **Cache Regions** | Defines cacheable entity types (e.g., `account_balance`, `user_profile`, `product_catalogue`) with LRU/LFU eviction, TTL, and max size. | In‑memory cache (Redis or PostgreSQL cache table) for sub‑second USSD responses. |
| **Content‑Addressable Cache** | Cache entries are keyed by SHA‑256 of content. Supports versioning and staleness detection. | Invalidate cache when a transaction updates a balance – the new content hash differs. |
| **Connection Pooling** | PgBouncer or built‑in pooling to handle thousands of concurrent USSD sessions efficiently. | Handle peak load during group meeting hours. |
## 13. Archival & Data Lifecycle
| Component | Description | USSD Justification |
|-----------|-------------|---------------------|
| **Archival Policies** | Define when data moves from hot (primary database) to warm (read replica) to cold (object storage) to glacier (deep archive). Configurable per table and tenant. | Old transactions (>2 years) are moved to cheap S3 Glacier storage. Keeps hot database size manageable. |
| **Archive Jobs** | Automated jobs that scan partitions, compress data (e.g., Parquet), upload to external storage (S3, GCS), and verify checksums. | Daily archival of completed transactions older than 365 days. |
| **Archive Manifest** | Catalog of archived records: source table, record ID, archive location, content hash, retention expiry, legal hold flag. | Ability to search archived records and restore on demand (e.g., for regulatory audit). |
| **Legal Hold Override** | Archival and deletion jobs skip records under legal hold. | During a dispute, preserve all related transactions. |
| **GDPR Erasure Requests** | Process to anonymise or delete personal data after retention period, respecting legal holds. | User requests account deletion – anonymise PII but keep financial transaction history for regulatory retention. |
## 14. Observability & Health Checks
| Component | Description | USSD Justification |
|-----------|-------------|---------------------|
| **Health Checks** | Predefined checks: database connectivity, replication lag, disk space, long‑running queries, hash chain integrity. | Monitor the ledger’s health. Alert if replication lag > 10 seconds or hash chain broken. |
| **Service Level Objectives (SLOs)** | Define SLOs for transaction latency (p95 < 200ms), availability (>99.9%), error rate (<0.1%). Burn rate alerts. | Ensure USSD users experience fast responses. Alert when error budget is depleting. |
| **Alerts & Incidents** | Firing alerts with severity (critical/high/medium/low). Incidents track detection, response, resolution, and post‑mortem. | Page on‑call engineer when the ledger is unhealthy. |
| **Metrics Collection** | Time‑series metrics: transaction throughput, latency percentiles, balance snapshot refresh time, idempotency key hit rate. Export to Prometheus. | Grafana dashboards for operations team. |
| **Audit Trail for Administrative Actions** | Separate immutable audit table recording all configuration changes (e.g., new application created, role assigned, fee structure updated). | Compliance: know who changed the loan interest rate and when. |
## 15. Financial Reporting & Accounting (Simplified)
| Component | Description | USSD Justification |
|-----------|-------------|---------------------|
| **Chart of Accounts (COA)** | Hierarchical GL accounts (asset, liability, equity, income, expense) with LTREE path. Each value container can be mapped to a COA account. | Produce balance sheet and income statement for the entire platform or per application. |
| **Period‑End Balances** | Snapshot of opening balance, period debits/credits, closing balance per COA account for a fiscal period (month, quarter, year). | Run monthly financial close for savings groups or micro‑loan portfolio. |
| **Trial Balance** | Lists all accounts with debit/credit balances at a point in time. Automatically checks if debits = credits. | Auditor’s first step in reviewing the ledger. |
| **Fiscal Periods** | Defines months, quarters, years with open/closed status. Closing a period prevents further changes and runs accruals. | Ensure no transactions are posted to a closed accounting period. |
| **Multi‑Currency Support** | Exchange rate table (spot, average, closing) with bitemporal validity. Currency conversion function. | USSD apps can operate in local currency (e.g., ZWL) while ledger uses a stable currency (USD). |
| **Tax Calculation (VAT/GST)** | Tax rates per jurisdiction, product category, and validity period. Automatically compute tax on e‑commerce sales or repair services. | E‑commerce app needs to collect VAT. Tax transaction records are stored immutably for reporting. |
| **Bad Debt Provision (IFRS 9 Simplified)** | Aging buckets (current, 30‑60 days, 60‑90 days, 90+ days) with configurable loss rates. Calculates expected credit loss for micro‑loans. | Automatically provision for potential loan defaults. Compliant with local financial regulations. |
---
## Final Notes
This combined list contains **only components that are directly relevant** to a USSD‑based immutable ledger supporting savings groups, micro‑loans, marketplaces, transport, health, and e‑commerce. The following features from the original systems have been **excluded** because they do not fit the USSD context:
- Device diagnostics, repair orders, spare parts inventory (insureLedger)
- Insurance‑specific: claims, underwriting, IFRS 17 premium earning, claim reserves
- Complex capital adequacy: Basel III LCR/NSFR, RWA, capital tiers
- Physical device digital twins (beyond simple product catalogue)
- Blockchain anchoring (optional, but not mandatory for USSD)
- Advanced post‑quantum cryptography
- Complex peer‑to‑peer replication (multi‑master)
- Full eIDAS signature levels (simplified to PIN/biometric)
  All remaining components are **implementable in PostgreSQL** using the patterns demonstrated in the provided SQL files. The USSD kernel’s Core schema will be fully immutable; the App schema will handle versioned configurations and audit‑logged mutable settings.

ussd-immutable-ledger-kernel/
├── database/
│   ├── migrations/
│   │   ├── 0001_baseline/
│   │   │   ├── up/
│   │   │   │   ├── 001_create_schemas.sql
│   │   │   │   ├── 002_core_extensions.sql
│   │   │   │   ├── 003_core_account_registry.sql
│   │   │   │   ├── 004_core_transaction_log.sql
│   │   │   │   ├── 005_core_movement_legs.sql
│   │   │   │   ├── 006_core_movement_postings.sql
│   │   │   │   ├── 007_core_blocks_merkle.sql
│   │   │   │   ├── 008_core_entity_sequences.sql
│   │   │   │   ├── 009_core_agent_relationships.sql
│   │   │   │   ├── 010_core_virtual_accounts.sql
│   │   │   │   ├── 011_core_transaction_sagas.sql
│   │   │   │   ├── 012_core_transaction_operations.sql
│   │   │   │   ├── 013_core_rejection_log.sql
│   │   │   │   ├── 014_core_settlement_instructions.sql
│   │   │   │   ├── 015_core_liquidity_positions.sql
│   │   │   │   ├── 016_core_reconciliation_runs.sql
│   │   │   │   ├── 017_core_reconciliation_items.sql
│   │   │   │   ├── 018_core_suspense_items.sql
│   │   │   │   ├── 019_core_suspense_resolutions.sql
│   │   │   │   ├── 020_core_control_batches.sql
│   │   │   │   ├── 021_core_batch_jobs.sql
│   │   │   │   ├── 022_core_document_registry.sql
│   │   │   │   ├── 023_core_document_versions.sql
│   │   │   │   ├── 024_core_digital_signatures.sql
│   │   │   │   ├── 025_core_archive_manifest.sql
│   │   │   │   ├── 026_core_chart_of_accounts.sql
│   │   │   │   ├── 027_core_period_end_balances.sql
│   │   │   │   ├── 028_core_exchange_rates.sql
│   │   │   │   ├── 029_core_bad_debt_provision.sql
│   │   │   │   ├── 030_core_integrity_triggers.sql
│   │   │   │   ├── 031_app_registry.sql
│   │   │   │   ├── 032_app_account_membership.sql
│   │   │   │   ├── 033_app_roles_permissions.sql
│   │   │   │   ├── 034_app_user_role_assignments.sql
│   │   │   │   ├── 035_app_entitlement_limits.sql
│   │   │   │   ├── 036_app_validation_rules.sql
│   │   │   │   ├── 037_app_hooks_registry.sql
│   │   │   │   ├── 038_app_business_calendar.sql
│   │   │   │   ├── 039_app_fiscal_periods.sql
│   │   │   │   ├── 040_app_cutoff_times.sql
│   │   │   │   ├── 041_app_tax_rates.sql
│   │   │   │   ├── 042_app_retention_policies.sql
│   │   │   │   ├── 043_app_legal_hold.sql
│   │   │   │   ├── 044_app_matching_rules.sql
│   │   │   │   ├── 045_app_configuration_store.sql
│   │   │   │   ├── 046_app_feature_flags.sql
│   │   │   │   ├── 047_ussd_session_state.sql
│   │   │   │   ├── 048_ussd_shortcode_routing.sql
│   │   │   │   ├── 049_ussd_menu_configurations.sql
│   │   │   │   ├── 050_ussd_pending_transactions.sql
│   │   │   │   ├── 051_ussd_device_fingerprints.sql
│   │   │   │   ├── 052_security_rls_policies.sql
│   │   │   │   ├── 053_security_audit_tables.sql
│   │   │   │   ├── 054_indexes_constraints.sql
│   │   │   │   └── 055_seed_data.sql
│   │   │   └── down/
│   │   │       └── 0001_baseline_rollback.sql
│   │   ├── 0002_partitioning_setup/
│   │   │   ├── up/
│   │   │   │   ├── 001_create_partition_schemes.sql
│   │   │   │   └── 002_setup_hypertables.sql
│   │   │   └── down/
│   │   ├── 0003_archival_policies/
│   │   │   ├── up/
│   │   │   │   └── 001_archival_configuration.sql
│   │   │   └── down/
│   │   └── README.md
│   │
│   ├── schema/
│   │   ├── core/
│   │   │   ├── tables/
│   │   │   │   ├── 000_account_registry.sql
│   │   │   │   ├── 001_transaction_types.sql
│   │   │   │   ├── 002_transaction_log.sql
│   │   │   │   ├── 003_movement_legs.sql
│   │   │   │   ├── 004_movement_postings.sql
│   │   │   │   ├── 005_blocks.sql
│   │   │   │   ├── 006_entity_sequences.sql
│   │   │   │   ├── 007_agent_relationships.sql
│   │   │   │   ├── 008_virtual_accounts.sql
│   │   │   │   ├── 009_transaction_sagas.sql
│   │   │   │   ├── 010_transaction_operations.sql
│   │   │   │   ├── 011_rejection_log.sql
│   │   │   │   ├── 012_settlement_instructions.sql
│   │   │   │   ├── 013_liquidity_positions.sql
│   │   │   │   ├── 014_reconciliation_runs.sql
│   │   │   │   ├── 015_reconciliation_items.sql
│   │   │   │   ├── 016_suspense_items.sql
│   │   │   │   ├── 017_suspense_resolutions.sql
│   │   │   │   ├── 018_control_batches.sql
│   │   │   │   ├── 019_batch_jobs.sql
│   │   │   │   ├── 020_document_registry.sql
│   │   │   │   ├── 021_document_versions.sql
│   │   │   │   ├── 022_digital_signatures.sql
│   │   │   │   ├── 023_archive_manifest.sql
│   │   │   │   ├── 024_chart_of_accounts.sql
│   │   │   │   ├── 025_period_end_balances.sql
│   │   │   │   ├── 026_exchange_rates.sql
│   │   │   │   ├── 027_bad_debt_provision.sql
│   │   │   │   ├── 028_idempotency_keys.sql
│   │   │   │   ├── 029_audit_trail.sql
│   │   │   │   └── Add more...
│   │   │   ├── functions/
│   │   │   │   ├── cryptographic/
│   │   │   │   │   ├── 000_hash_chain_compute.sql
│   │   │   │   │   ├── 001_merkle_root_calculate.sql
│   │   │   │   │   ├── 002_integrity_verify.sql
│   │   │   │   │   └── 003_proof_generate.sql
│   │   │   │   ├── transaction/
│   │   │   │   │   ├── 000_submit_transaction.sql
│   │   │   │   │   ├── 001_validate_payload.sql
│   │   │   │   │   ├── 002_get_balance_at_time.sql
│   │   │   │   │   └── 003_get_transaction_history.sql
│   │   │   │   └── maintenance/
│   │   │   │       ├── 000_refresh_materialized_views.sql
│   │   │   │       ├── 001_partition_maintenance.sql
│   │   │   │       └── 002_health_checks.sql
│   │   │   ├── triggers/
│   │   │   │   ├── 000_immutability_enforcement.sql
│   │   │   │   ├── 001_hash_chain_automation.sql
│   │   │   │   └── 002_audit_log_capture.sql
│   │   │   ├── policies/
│   │   │   │   └── 000_row_level_security_core.sql
│   │   │   ├── views/
│   │   │   │   ├── 000_account_state_snapshot.sql
│   │   │   │   ├── 001_trial_balance.sql
│   │   │   │   └── 002_entity_streams.sql
│   │   │   └── indexes/
│   │   │       ├── 000_transaction_log_indexes.sql
│   │   │       ├── 001_account_registry_indexes.sql
│   │   │       └── 002_partitioning_indexes.sql
│   │   │
│   │   ├── applications/
│   │   │   ├── (Business Logic Applications)
│   │   │
│   │   └── ussd_gateway/
│   │       ├── tables/
│   │       │   ├── 000_session_state.sql
│   │       │   ├── 001_shortcode_routing.sql
│   │       │   ├── 002_menu_configurations.sql
│   │       │   ├── 003_pending_transactions.sql
│   │       │   └── 004_device_fingerprints.sql
│   │       ├── functions/
│   │       │   ├── session/
│   │       │   │   ├── 000_create_session.sql
│   │       │   │   ├── 001_update_session_context.sql
│   │       │   │   ├── 002_resume_session.sql
│   │       │   │   └── 003_cleanup_expired_sessions.sql
│   │       │   ├── routing/
│   │       │   │   ├── 000_resolve_shortcode.sql
│   │       │   │   └── 001_route_to_application.sql
│   │       │   └── security/
│   │       │       ├── 000_verify_device_fingerprint.sql
│   │       │       ├── 001_check_velocity_limits.sql
│   │       │       └── 002_detect_sim_swap.sql
│   │       └── indexes/
│   │           └── 000_session_state_indexes.sql
│   │
│   ├── partitions/
│   │   ├── templates/
│   │   │   ├── 000_monthly_partition_template.sql
│   │   │   └── 001_application_list_template.sql
│   │   ├── maintenance/
│   │   │   ├── 000_create_future_partitions.sql
│   │   │   ├── 001_detach_old_partitions.sql
│   │   │   └── 002_archive_cold_partitions.sql
│   │   └── hypertables/
│   │       └── 000_timescale_setup.sql
│   │
│   ├── replication/
│   │   ├── logical/
│   │   │   ├── 000_publication_setup.sql
│   │   │   └── 001_subscription_config.sql
│   │   └── physical/
│   │       ├── 000_wal_archiving.sql
│   │       └── 001_streaming_replication.sql
│   │
│   ├── security/
│   │   ├── rls/
│   │   │   ├── 000_core_transaction_access.sql
│   │   │   ├── 001_core_account_access.sql
│   │   │   └── 002_app_configuration_access.sql
│   │   ├── encryption/
│   │   │   ├── 000_pii_field_encryption.sql
│   │   │   └── 001_key_rotation_procedures.sql
│   │   └── audit/
│   │       ├── 000_audit_trigger_functions.sql
│   │       ├── 001_audit_table_definitions.sql
│   │       └── 002_document_access_log.sql
│   │
│   ├── jobs/
│   │   ├── background_workers/
│   │   │   ├── 000_merkle_tree_computation.sql
│   │   │   ├── 001_integrity_verification_scheduler.sql
│   │   │   ├── 002_materialized_view_refresh.sql
│   │   │   └── 003_idempotency_key_cleanup.sql
│   │   └── cron/
│   │       ├── 000_eod_processing.sql
│   │       ├── 001_reconciliation_runs.sql
│   │       └── 002_archival_execution.sql
│   │
│   └── utils/
│       ├── extensions/
│       │   ├── 000_pg_crypto_setup.sql
│       │   ├── 001_uuid_ossp_setup.sql
│       │   ├── 002_pg_trgm_setup.sql
│       │   └── 003_timescaledb_setup.sql
│       ├── helpers/
│       │   ├── 000_json_validation.sql
│       │   ├── 001_error_handling.sql
│       │   └── 002_logging_utilities.sql
│       └── seed/
│           ├── 000_system_accounts.sql
│           ├── 001_default_transaction_types.sql
│           └── 002_root_application.sql
│
├── config/
│   ├── postgresql/
│   │   ├── postgresql.conf.immutable_ledger
│   │   ├── pg_hba.conf.template
│   │   └── pgbouncer/
│   │       ├── pgbouncer.ini.template
│   │       └── userlist.txt.template
│   ├── partitioning/
│   │   ├── partition_strategy.yaml
│   │   └── retention_policies.yaml
│   └── monitoring/
│       ├── prometheus_alerts.yml
│       └── grafana_dashboards/
│           ├── core_ledger_health.json
│           └── app_performance.json
│
├── procedures/
│   ├── disaster_recovery/
│   │   ├── point_in_time_recovery.sql
│   │   ├── hash_chain_rebuild.sql
│   │   └── snapshot_restore.sql
│   ├── compliance/
│   │   ├── gdpr_anonymization.sql
│   │   ├── legal_hold_application.sql
│   │   └── regulatory_reporting_exports.sql
│   └── maintenance/
│       ├── reindex_partitioned_tables.sql
│       ├── vacuum_strategy.sql
│       └── connection_pool_tuning.sql
│
├── tests/
│   ├── integrity/
│   │   ├── hash_chain_validation.sql
│   │   ├── merkle_inclusion_tests.sql
│   │   └── immutability_violation_attempts.sql
│   ├── performance/
│   │   ├── concurrency_load_tests.sql
│   │   ├── partition_pruning_tests.sql
│   │   └── materialized_view_refresh_benchmarks.sql
│   └── security/
│       ├── rls_policy_tests.sql
│       ├── encryption_roundtrip_tests.sql
│       └── sim_swap_detection_tests.sql
│
└── docs/
├── schema_documentation/
│   ├── core_schema_erd.md
│   ├── app_schema_erd.md
│   └── ussd_integration_schema.md
├── runbooks/
│   ├── partition_management.md
│   ├── integrity_verification.md
│   └── incident_response/
│       ├── hash_mismatch_response.md
│       └── settlement_failure_response.md
└── api/
├── core_ledger_api_spec.md
└── app_schema_api_spec.md