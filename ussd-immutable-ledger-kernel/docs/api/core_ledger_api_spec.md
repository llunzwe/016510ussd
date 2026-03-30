# Core Ledger API Specification

## Overview

The Core Ledger API provides programmatic access to the immutable USSD ledger entries, hash chain verification, and balance operations.

---

## Compliance

### ISO Standards Mapping

| ISO Standard | Requirement | Implementation |
|--------------|-------------|----------------|
| **ISO 27001:2022** | A.8.1 - User endpoint devices | API authentication and authorization controls |
| **ISO 27001:2022** | A.8.5 - Secure authentication | Bearer token authentication with rotation |
| **ISO 27001:2022** | A.8.9 - Management of authentication information | API key lifecycle management |
| **ISO 27001:2022** | A.8.11 - Data masking | PII masking in API responses |
| **ISO 20022** | Financial messaging standards | Transaction formats compatible with ISO 20022 |
| **ISO 8583** | Card transaction messaging | Entry fields map to ISO 8583 data elements |

### Regulatory Compliance

| Regulation | API Compliance |
|------------|----------------|
| **PCI DSS 4.0** | No cardholder data in API responses; tokenized references only |
| **GDPR Article 25** | Data protection by design - request validation, response filtering |
| **SOX Section 404** | API access logging for financial controls audit |
| **PSD2** | Strong Customer Authentication (SCA) for sensitive operations |

---

## Security Considerations

### API Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│                      API SECURITY LAYERS                         │
├─────────────────────────────────────────────────────────────────┤
│ 1. Transport Layer                                               │
│    - TLS 1.3 mandatory (TLS 1.2 minimum)                        │
│    - Certificate pinning for mobile clients                      │
│    - HSTS headers enforced                                       │
├─────────────────────────────────────────────────────────────────┤
│ 2. Authentication Layer                                          │
│    - Bearer tokens (JWT with RS256)                              │
│    - Token expiration: 1 hour                                    │
│    - Refresh tokens: 30 days                                     │
│    - API keys for service-to-service                             │
├─────────────────────────────────────────────────────────────────┤
│ 3. Authorization Layer                                           │
│    - RBAC (Role-Based Access Control)                            │
│    - Resource-level permissions                                  │
│    - Rate limiting per client/endpoint                           │
├─────────────────────────────────────────────────────────────────┤
│ 4. Input Validation                                              │
│    - JSON Schema validation                                      │
│    - SQL injection prevention (parameterized queries)            │
│    - XSS prevention (output encoding)                            │
│    - Request size limits                                         │
├─────────────────────────────────────────────────────────────────┤
│ 5. Audit Logging                                                 │
│    - All API calls logged with request ID                        │
│    - Sensitive fields masked in logs                             │
│    - Log integrity protected (signed)                            │
└─────────────────────────────────────────────────────────────────┘
```

### Authentication

All requests require an API key passed in the `Authorization` header.

```
Authorization: Bearer {api_key}
X-Request-ID: {uuid}  # Required for idempotency
X-Client-Version: {version}  # Client application version
```

### Security Headers

All API responses include:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Cache-Control: no-store, no-cache, must-revalidate
```

### Threat Mitigation

| Threat | Mitigation |
|--------|------------|
| Replay attacks | Request ID uniqueness + timestamp validation |
| Token theft | Short expiration + refresh token rotation |
| API abuse | Rate limiting + abuse detection |
| Data exfiltration | Field-level filtering based on permissions |
| Injection attacks | Parameterized queries + input validation |

---

## Audit Requirements

### Required Audit Events

| Event | Logged Fields | Retention |
|-------|---------------|-----------|
| Entry creation | Request ID, client ID, entry UUID, hash | 7 years |
| Balance query | Request ID, client ID, account ID, timestamp | 3 years |
| Verification request | Request ID, client ID, verification type | 7 years |
| Failed authentication | Client IP, user agent, timestamp | 1 year |
| Rate limit exceeded | Client ID, endpoint, timestamp | 90 days |

### Audit Log Format

```json
{
  "timestamp": "2025-03-30T15:30:00Z",
  "request_id": "req-550e8400-e29b-41d4-a716-446655440000",
  "client_id": "client-001",
  "endpoint": "POST /ledger/entries",
  "ip_address": "203.0.113.42",
  "user_agent": "USSD-Client/1.2.3",
  "response_status": 201,
  "entry_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "processing_time_ms": 45,
  "signature": "sha256=abc123..."
}
```

### Compliance Endpoints

```http
# Export audit trail for compliance
GET /ledger/audit/export?start_date=2025-01-01&end_date=2025-03-30
Authorization: Bearer {admin_api_key}

# Response
{
  "export_id": "EXP-550e8400",
  "format": "JSON",
  "record_count": 150000,
  "download_url": "/downloads/audit-export-550e8400.json.gz",
  "expires_at": "2025-03-31T15:30:00Z",
  "integrity_hash": "sha256:abc123..."
}
```

---

## Data Protection Notes

### Request/Response Data Classification

| Field | Request Classification | Response Classification |
|-------|----------------------|------------------------|
| entry_uuid | Public | Public |
| transaction_ref | Internal | Internal |
| account_id | Internal | Internal (filtered by permissions) |
| msisdn | Sensitive | Masked (e.g., +123****890) |
| amount | Financial | Financial |
| metadata | Variable | Filtered (sensitive keys removed) |
| entry_hash | System | System |

### Data Minimization

API responses follow data minimization principles:

```javascript
// Request
{
  "account_id": "ACC-123456789",
  "include_metadata": false  // Default: false
}

// Response (metadata excluded by default)
{
  "account_id": "ACC-123456789",
  "balance": "1250.00",
  // metadata not included unless explicitly requested
}
```

### Cross-Border Considerations

- **Data residency**: API gateway routes to appropriate regional instance
- **Encryption**: All cross-border API calls use end-to-end encryption
- **Logging**: Audit logs stored in data subject's jurisdiction

---

## Base URL

```
Production: https://api.ledger.company.com/v1
Staging:    https://staging-api.ledger.company.com/v1
Sandbox:    https://sandbox-api.ledger.company.com/v1
```

## API Endpoints

### 1. Create Ledger Entry

Create a new immutable ledger entry.

```http
POST /ledger/entries
Content-Type: application/json
Authorization: Bearer {api_key}
X-Request-ID: {uuid}
```

#### Request Body

```json
{
  "transaction_ref": "TXN-2025-001-12345",
  "entry_type": "DEBIT",
  "amount": "150.00",
  "currency_code": "USD",
  "account_id": "ACC-123456789",
  "session_id": "USSD-SESSION-abc123",
  "msisdn": "+1234567890",
  "metadata": {
    "merchant_id": "MERCH-001",
    "product_code": "AIRTIME-10USD",
    "channel": "USSD",
    "device_info": "Nokia 3310"
  },
  "idempotency_key": "idem-abc123-def456"
}
```

#### Response

**201 Created**
```json
{
  "entry_id": 123456789,
  "entry_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "transaction_ref": "TXN-2025-001-12345",
  "entry_type": "DEBIT",
  "amount": "150.00",
  "currency_code": "USD",
  "account_id": "ACC-123456789",
  "status": "CONFIRMED",
  "created_at": "2025-03-30T15:30:00Z",
  "entry_hash": "a1b2c3d4e5f6...",
  "previous_entry_id": 123456788,
  "chain_hash": "f6e5d4c3b2a1...",
  "links": {
    "self": "/ledger/entries/550e8400-e29b-41d4-a716-446655440000",
    "account": "/accounts/ACC-123456789",
    "session": "/sessions/USSD-SESSION-abc123"
  }
}
```

**400 Bad Request**
```json
{
  "error": {
    "code": "INVALID_ENTRY_TYPE",
    "message": "Entry type must be one of: DEBIT, CREDIT, ADJUSTMENT, REVERSAL",
    "details": {
      "field": "entry_type",
      "provided": "INVALID"
    }
  },
  "request_id": "req-abc123"
}
```

**409 Conflict** (Duplicate transaction_ref)
```json
{
  "error": {
    "code": "DUPLICATE_TRANSACTION",
    "message": "Transaction reference already exists",
    "details": {
      "transaction_ref": "TXN-2025-001-12345",
      "existing_entry_uuid": "550e8400-e29b-41d4-a716-446655440000"
    }
  }
}
```

### 2. Get Ledger Entry

Retrieve a specific ledger entry by UUID.

```http
GET /ledger/entries/{entry_uuid}
Authorization: Bearer {api_key}
```

#### Response

**200 OK**
```json
{
  "entry_id": 123456789,
  "entry_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "transaction_ref": "TXN-2025-001-12345",
  "entry_type": "DEBIT",
  "amount": "150.00",
  "currency_code": "USD",
  "account_id": "ACC-123456789",
  "session_id": "USSD-SESSION-abc123",
  "msisdn": "+123****890",
  "metadata": {
    "merchant_id": "MERCH-001",
    "product_code": "AIRTIME-10USD"
  },
  "created_at": "2025-03-30T15:30:00Z",
  "created_by": "service-ussd-gateway",
  "entry_hash": "a1b2c3d4e5f6...",
  "previous_entry_id": 123456788,
  "chain_hash": "f6e5d4c3b2a1...",
  "verification_status": "VERIFIED"
}
```

**404 Not Found**
```json
{
  "error": {
    "code": "ENTRY_NOT_FOUND",
    "message": "Ledger entry not found",
    "details": {
      "entry_uuid": "550e8400-e29b-41d4-a716-446655440000"
    }
  }
}
```

### 3. Query Ledger Entries

Query ledger entries with filtering and pagination.

```http
GET /ledger/entries?account_id={account_id}&start_date={iso_date}&end_date={iso_date}&entry_type={type}&cursor={cursor}&limit={limit}
Authorization: Bearer {api_key}
```

#### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| account_id | string | Filter by account |
| session_id | string | Filter by session |
| msisdn | string | Filter by phone number (hashed) |
| start_date | ISO8601 | Start of date range |
| end_date | ISO8601 | End of date range |
| entry_type | enum | DEBIT, CREDIT, ADJUSTMENT, REVERSAL |
| min_amount | decimal | Minimum amount |
| max_amount | decimal | Maximum amount |
| cursor | string | Pagination cursor |
| limit | integer | Max results (default: 50, max: 1000) |

#### Response

**200 OK**
```json
{
  "data": [
    {
      "entry_id": 123456789,
      "entry_uuid": "550e8400-e29b-41d4-a716-446655440000",
      "transaction_ref": "TXN-2025-001-12345",
      "entry_type": "DEBIT",
      "amount": "150.00",
      "currency_code": "USD",
      "account_id": "ACC-123456789",
      "created_at": "2025-03-30T15:30:00Z"
    }
  ],
  "pagination": {
    "total_count": 150,
    "returned_count": 50,
    "has_more": true,
    "next_cursor": "eyJsYXN0X2lkIjoxMjM0NTZ9",
    "previous_cursor": null
  },
  "meta": {
    "query_time_ms": 45,
    "partition_scanned": ["ledger_entries_2025_03"]
  }
}
```

### 4. Get Account Balance

Retrieve current balance for an account.

```http
GET /ledger/accounts/{account_id}/balance
Authorization: Bearer {api_key}
```

#### Response

**200 OK**
```json
{
  "account_id": "ACC-123456789",
  "balances": [
    {
      "currency_code": "USD",
      "available_balance": "1250.00",
      "pending_balance": "150.00",
      "hold_balance": "0.00",
      "total_balance": "1400.00"
    },
    {
      "currency_code": "EUR",
      "available_balance": "500.00",
      "pending_balance": "0.00",
      "hold_balance": "0.00",
      "total_balance": "500.00"
    }
  ],
  "last_updated": "2025-03-30T15:30:00Z",
  "last_entry_id": 123456789,
  "balance_hash": "a1b2c3d4e5f6..."
}
```

### 5. Verify Entry Integrity

Verify the cryptographic integrity of a specific entry.

```http
POST /ledger/entries/{entry_uuid}/verify
Content-Type: application/json
Authorization: Bearer {api_key}
```

#### Request Body

```json
{
  "verify_chain": true,
  "depth": 10  // Number of previous entries to verify
}
```

#### Response

**200 OK**
```json
{
  "entry_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "verification_status": "VALID",
  "entry_hash_valid": true,
  "chain_integrity": true,
  "chain_verified_depth": 10,
  "verified_at": "2025-03-30T15:35:00Z",
  "verification_proof": {
    "entry_hash": "a1b2c3d4e5f6...",
    "previous_hash": "b2c3d4e5f6a1...",
    "chain_root": "c3d4e5f6a1b2..."
  }
}
```

**200 OK** (Verification Failed)
```json
{
  "entry_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "verification_status": "INVALID",
  "entry_hash_valid": false,
  "chain_integrity": false,
  "mismatch_details": {
    "expected_hash": "a1b2c3d4e5f6...",
    "actual_hash": "x1y2z3w4v5u6...",
    "mismatch_type": "ENTRY_HASH_MISMATCH"
  },
  "alert_id": "ALT-2025-001"
}
```

### 6. Batch Create Entries

Create multiple ledger entries in a single atomic operation.

```http
POST /ledger/entries/batch
Content-Type: application/json
Authorization: Bearer {api_key}
X-Request-ID: {uuid}
```

#### Request Body

```json
{
  "entries": [
    {
      "transaction_ref": "TXN-2025-001-12345",
      "entry_type": "DEBIT",
      "amount": "150.00",
      "currency_code": "USD",
      "account_id": "ACC-123456789",
      "metadata": {"purpose": "airtime_purchase"}
    },
    {
      "transaction_ref": "TXN-2025-001-12346",
      "entry_type": "CREDIT",
      "amount": "150.00",
      "currency_code": "USD",
      "account_id": "ACC-987654321",
      "metadata": {"purpose": "airtime_sale"}
    }
  ],
  "atomic": true,
  "idempotency_key": "batch-abc123"
}
```

#### Response

**201 Created**
```json
{
  "batch_id": "BATCH-550e8400-e29b-41d4-a716-446655440000",
  "status": "COMPLETED",
  "entries_created": 2,
  "entries": [
    {
      "entry_uuid": "660e8400-e29b-41d4-a716-446655440001",
      "transaction_ref": "TXN-2025-001-12345",
      "status": "CONFIRMED",
      "entry_hash": "b2c3d4e5f6a1..."
    },
    {
      "entry_uuid": "770e8400-e29b-41d4-a716-446655440002",
      "transaction_ref": "TXN-2025-001-12346",
      "status": "CONFIRMED",
      "entry_hash": "c3d4e5f6a1b2..."
    }
  ],
  "batch_hash": "d4e5f6a1b2c3...",
  "created_at": "2025-03-30T15:30:00Z"
}
```

### 7. Get Hash Chain Info

Retrieve hash chain metadata and statistics.

```http
GET /ledger/chain/info
Authorization: Bearer {api_key}
```

#### Response

**200 OK**
```json
{
  "chain_status": "HEALTHY",
  "total_entries": 123456789,
  "genesis_entry_id": 1,
  "last_entry_id": 123456789,
  "chain_length": 123456789,
  "last_verified_entry_id": 123456780,
  "verification_status": {
    "last_full_verification": "2025-03-30T00:00:00Z",
    "last_incremental_verification": "2025-03-30T15:00:00Z",
    "verification_health": "CURRENT"
  },
  "hash_algorithm": "SHA-256",
  "chain_root_hash": "a1b2c3d4e5f6789012345678901234567890abcd..."
}
```

### 8. Trigger Verification

Initiate on-demand hash chain verification.

```http
POST /ledger/verify
Content-Type: application/json
Authorization: Bearer {api_key}
```

#### Request Body

```json
{
  "verification_type": "INCREMENTAL",
  "start_entry_id": 123456700,
  "end_entry_id": 123456789,
  "callback_url": "https://webhook.company.com/verification-complete"
}
```

#### Response

**202 Accepted**
```json
{
  "verification_id": "VERIFY-550e8400-e29b-41d4-a716-446655440000",
  "status": "QUEUED",
  "verification_type": "INCREMENTAL",
  "estimated_completion": "2025-03-30T15:35:00Z",
  "progress_url": "/ledger/verify/VERIFY-550e8400-e29b-41d4-a716-446655440000"
}
```

---

## Webhooks

### Entry Created Webhook

```json
{
  "event_type": "ledger.entry.created",
  "event_id": "evt-550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-03-30T15:30:00Z",
  "data": {
    "entry_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "entry_type": "DEBIT",
    "amount": "150.00",
    "currency_code": "USD",
    "account_id": "ACC-123456789",
    "transaction_ref": "TXN-2025-001-12345",
    "created_at": "2025-03-30T15:30:00Z"
  }
}
```

### Integrity Alert Webhook

```json
{
  "event_type": "ledger.integrity.alert",
  "event_id": "evt-660e8400-e29b-41d4-a716-446655440001",
  "timestamp": "2025-03-30T15:35:00Z",
  "severity": "CRITICAL",
  "data": {
    "alert_id": "ALT-2025-001",
    "alert_type": "HASH_MISMATCH",
    "entry_id": 123456789,
    "entry_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "details": {
      "expected_hash": "a1b2c3d4e5f6...",
      "actual_hash": "x1y2z3w4v5u6...",
      "mismatch_type": "ENTRY_HASH_MISMATCH"
    }
  }
}
```

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| INVALID_ENTRY_TYPE | 400 | Entry type not in allowed enum |
| INVALID_AMOUNT | 400 | Amount format or value invalid |
| INVALID_CURRENCY | 400 | Currency code not supported |
| MISSING_REQUIRED_FIELD | 400 | Required field not provided |
| INVALID_DATE_RANGE | 400 | Date range exceeds maximum |
| ENTRY_NOT_FOUND | 404 | Entry UUID does not exist |
| ACCOUNT_NOT_FOUND | 404 | Account ID does not exist |
| DUPLICATE_TRANSACTION | 409 | Transaction reference already exists |
| HASH_MISMATCH | 409 | Computed hash does not match stored |
| RATE_LIMIT_EXCEEDED | 429 | Too many requests |
| INTERNAL_ERROR | 500 | Unexpected server error |
| VERIFICATION_IN_PROGRESS | 503 | Verification already running |

---

## Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| POST /ledger/entries | 1000 | 1 minute |
| GET /ledger/entries/{id} | 10000 | 1 minute |
| GET /ledger/entries | 500 | 1 minute |
| POST /ledger/verify | 10 | 1 hour |
| Batch operations | 100 | 1 minute |

---

## TODOs

- [ ] Implement GraphQL endpoint for flexible queries
- [ ] Add bulk export API for regulatory reporting
- [ ] Create WebSocket API for real-time entry streaming
- [ ] Implement API request signing for enhanced security
- [ ] Add API versioning strategy documentation
- [ ] Create SDK libraries (Python, Node.js, Java)
- [ ] Implement API response caching layer
- [ ] Add API usage analytics dashboard
- [ ] Design API rate limit bypass for emergency ops
- [ ] Create API changelog and deprecation policy
