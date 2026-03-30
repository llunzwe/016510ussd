# Application Schema API Specification

## Overview

The Application Schema API provides endpoints for account management, USSD session handling, and settlement operations.

---

## Compliance

### ISO Standards Mapping

| ISO Standard | Requirement | Implementation |
|--------------|-------------|----------------|
| **ISO 27001:2022** | A.5.18 - Access rights | Account status controls API access |
| **ISO 27001:2022** | A.8.2 - Privileged access rights | Settlement operations require elevated permissions |
| **ISO 27001:2022** | A.8.3 - Information access restriction | Data filtering based on service provider |
| **ISO 27001:2022** | A.8.5 - Secure authentication | Multi-factor auth for sensitive operations |
| **ISO 20022** | Account management | Account structures compatible with ISO 20022 |
| **ISO 8583** | Session management | Session tracking for transaction correlation |

### Regulatory Compliance

| Regulation | API Compliance |
|------------|----------------|
| **GDPR Article 7** | Consent management for account creation |
| **PCI DSS 4.0** | No sensitive authentication data in APIs |
| **PSD2** | Strong Customer Authentication (SCA) |
| **KYC/AML** | Identity verification status tracking |
| **SOX Section 404** | Settlement controls and audit trails |

---

## Security Considerations

### API Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│                    APPLICATION API SECURITY                      │
├─────────────────────────────────────────────────────────────────┤
│ 1. Authentication                                                │
│    - OAuth 2.0 + PKCE for mobile/SPA clients                     │
│    - API keys for service-to-service                             │
│    - Session tokens for USSD gateway                             │
├─────────────────────────────────────────────────────────────────┤
│ 2. Authorization                                                 │
│    - Service provider isolation (tenant-based)                   │
│    - Account-level permissions                                   │
│    - Settlement operation approvals                              │
├─────────────────────────────────────────────────────────────────┤
│ 3. Input Protection                                              │
│    - KYC data validation                                         │
│    - Phone number format validation (E.164)                      │
│    - SQL injection prevention                                    │
│    - File upload restrictions (KYC documents)                    │
├─────────────────────────────────────────────────────────────────┤
│ 4. Session Security                                              │
│    - Session timeout enforcement (30 seconds)                    │
│    - Device fingerprinting                                       │
│    - Location anomaly detection                                  │
├─────────────────────────────────────────────────────────────────┤
│ 5. Audit and Monitoring                                          │
│    - All account changes logged                                  │
│    - Settlement operations require justification                 │
│    - Failed authentication attempts tracked                      │
└─────────────────────────────────────────────────────────────────┘
```

### Role-Based Access Control

| Role | Permissions |
|------|-------------|
| `account:read` | View account details and balances |
| `account:write` | Create and modify accounts |
| `account:admin` | Freeze/close accounts, status changes |
| `session:read` | View session history |
| `session:write` | Create and manage sessions |
| `settlement:read` | View settlement batches |
| `settlement:write` | Create and close batches |
| `settlement:admin` | Approve payments, corrections |
| `provider:admin` | Manage service provider settings |

### Sensitive Operations

| Operation | Additional Security |
|-----------|---------------------|
| Account closure | MFA + manager approval |
| Batch close | Dual-control (two approvers) |
| Payment initiation | MFA + amount limits |
| Provider configuration | Admin-only + audit log |
| KYC data access | Explicit consent check |

---

## Audit Requirements

### Required Audit Events

| Event | Logged Data | Retention |
|-------|-------------|-----------|
| Account created | Account ID, MSISDN (hashed), KYC status | 7 years |
| Account status changed | Previous/new status, reason, approver | 7 years |
| Session created | Session ID, MSISDN (hashed), IP, device | 90 days |
| Settlement batch closed | Batch ID, totals, closed by | 7 years |
| Payment initiated | Batch ID, amount, approver | 7 years |
| Failed login attempts | Client ID, IP, timestamp | 1 year |

### Audit Endpoints

```http
# Account audit trail
GET /accounts/{account_id}/audit
Authorization: Bearer {api_key}

# Response
{
  "account_id": "ACC-123456789",
  "events": [
    {
      "event_type": "STATUS_CHANGED",
      "timestamp": "2025-03-30T15:30:00Z",
      "previous_status": "ACTIVE",
      "new_status": "FROZEN",
      "reason": "SUSPICIOUS_ACTIVITY",
      "performed_by": "admin@company.com"
    }
  ]
}
```

### Compliance Reporting

```http
# Export settlement data for regulatory reporting
GET /settlements/export?start_date=2025-01-01&end_date=2025-03-30&format=ISO20022
Authorization: Bearer {admin_api_key}
```

---

## Data Protection Notes

### Personal Data Handling

| Field | Collection | Storage | Retention |
|-------|------------|---------|-----------|
| MSISDN | Required | Tokenized | Account lifetime |
| KYC data | Required | Encrypted | Account lifetime + 7 years |
| Session IP | Automatic | 90 days | 90 days |
| Device info | Automatic | 90 days | 90 days |
| Location | Optional | 90 days | 90 days |

### Consent Management

```json
// Account creation with consent
{
  "account_type": "WALLET",
  "msisdn": "+1234567890",
  "consents": {
    "terms_of_service": true,
    "privacy_policy": true,
    "marketing": false,
    "data_processing": true
  },
  "consent_timestamp": "2025-03-30T15:30:00Z",
  "consent_version": "2025-03-01"
}
```

### Data Subject Rights

| Right | API Endpoint |
|-------|--------------|
| Right to Access | `GET /accounts/{id}/export` |
| Right to Rectification | `PATCH /accounts/{id}/kyc` |
| Right to Erasure | `POST /accounts/{id}/close` |
| Right to Portability | `GET /accounts/{id}/export?format=ISO20022` |
| Right to Restrict | `POST /accounts/{id}/freeze` |

---

## Base URL

```
Production: https://api.ussd.company.com/v1
Staging:    https://staging-api.ussd.company.com/v1
Sandbox:    https://sandbox-api.ussd.company.com/v1
```

## Authentication

```
Authorization: Bearer {api_key}
X-Client-Id: {client_id}
X-Request-ID: {uuid}
```

## Account Management APIs

### 1. Create Account

```http
POST /accounts
Content-Type: application/json
Authorization: Bearer {api_key}
X-Request-ID: {uuid}
```

#### Request Body

```json
{
  "account_type": "WALLET",
  "msisdn": "+1234567890",
  "currency_code": "USD",
  "service_provider_id": "PROVIDER-001",
  "kyc_data": {
    "first_name": "John",
    "last_name": "Doe",
    "id_type": "PASSPORT",
    "id_number": "P123456789",
    "date_of_birth": "1990-01-15",
    "address": {
      "street": "123 Main St",
      "city": "New York",
      "country": "US"
    }
  },
  "consents": {
    "terms_of_service": true,
    "privacy_policy": true,
    "data_processing": true
  },
  "metadata": {
    "source": "USSD_ONBOARDING",
    "referral_code": "REF123"
  }
}
```

#### Response

**201 Created**
```json
{
  "account_id": "ACC-550e8400-e29b-41d4-a716-446655440000",
  "account_type": "WALLET",
  "msisdn": "+1234567890",
  "currency_code": "USD",
  "status": "ACTIVE",
  "service_provider_id": "PROVIDER-001",
  "kyc_status": "PENDING_VERIFICATION",
  "balances": [
    {
      "currency_code": "USD",
      "available_balance": "0.00",
      "pending_balance": "0.00",
      "hold_balance": "0.00"
    }
  ],
  "created_at": "2025-03-30T15:30:00Z",
  "links": {
    "self": "/accounts/ACC-550e8400-e29b-41d4-a716-446655440000",
    "ledger_entries": "/ledger/entries?account_id=ACC-550e8400-e29b-41d4-a716-446655440000"
  }
}
```

**409 Conflict** (MSISDN already registered)
```json
{
  "error": {
    "code": "DUPLICATE_MSISDN",
    "message": "An account with this phone number already exists",
    "details": {
      "msisdn": "+1234567890",
      "existing_account_id": "ACC-existing-id"
    }
  }
}
```

### 2. Get Account

```http
GET /accounts/{account_id}
Authorization: Bearer {api_key}
```

#### Response

**200 OK**
```json
{
  "account_id": "ACC-550e8400-e29b-41d4-a716-446655440000",
  "account_type": "WALLET",
  "msisdn": "+123****890",
  "status": "ACTIVE",
  "service_provider_id": "PROVIDER-001",
  "currency_code": "USD",
  "kyc_status": "VERIFIED",
  "kyc_verified_at": "2025-03-30T15:35:00Z",
  "balances": [
    {
      "currency_code": "USD",
      "available_balance": "1250.00",
      "pending_balance": "150.00",
      "hold_balance": "0.00",
      "last_updated": "2025-03-30T15:30:00Z"
    }
  ],
  "limits": {
    "daily_transaction_limit": "5000.00",
    "monthly_transaction_limit": "50000.00",
    "single_transaction_limit": "2000.00",
    "remaining_daily": "3750.00"
  },
  "opened_at": "2025-03-30T15:30:00Z",
  "last_activity_at": "2025-03-30T15:30:00Z"
}
```

### 3. Update Account Status

```http
PATCH /accounts/{account_id}/status
Content-Type: application/json
Authorization: Bearer {api_key}
```

#### Request Body

```json
{
  "status": "FROZEN",
  "reason": "SUSPICIOUS_ACTIVITY",
  "reference_id": "CASE-2025-001",
  "notes": "Multiple failed PIN attempts detected",
  "mfa_token": "123456"
}
```

#### Response

**200 OK**
```json
{
  "account_id": "ACC-550e8400-e29b-41d4-a716-446655440000",
  "previous_status": "ACTIVE",
  "current_status": "FROZEN",
  "status_changed_at": "2025-03-30T15:40:00Z",
  "changed_by": "admin@company.com",
  "reason": "SUSPICIOUS_ACTIVITY",
  "effective_immediately": true
}
```

### 4. List Accounts

```http
GET /accounts?service_provider_id={provider_id}&status={status}&cursor={cursor}&limit={limit}
Authorization: Bearer {api_key}
```

#### Response

**200 OK**
```json
{
  "data": [
    {
      "account_id": "ACC-550e8400-e29b-41d4-a716-446655440000",
      "msisdn": "+123****890",
      "status": "ACTIVE",
      "account_type": "WALLET",
      "available_balance": "1250.00",
      "currency_code": "USD"
    }
  ],
  "pagination": {
    "total_count": 15000,
    "returned_count": 50,
    "has_more": true,
    "next_cursor": "eyJsYXN0X2lkIjoiQUNDLjU1MGU4NDAwIn0="
  }
}
```

---

## USSD Session APIs

### 5. Create USSD Session

```http
POST /sessions
Content-Type: application/json
Authorization: Bearer {api_key}
```

#### Request Body

```json
{
  "msisdn": "+1234567890",
  "ussd_code": "*123#",
  "account_id": "ACC-550e8400-e29b-41d4-a716-446655440000",
  "network_operator": "MNO-001",
  "session_context": {
    "device_type": "FEATURE_PHONE",
    "language": "en",
    "location": "US-NYC"
  }
}
```

#### Response

**201 Created**
```json
{
  "session_id": "SESS-550e8400-e29b-41d4-a716-446655440000",
  "msisdn": "+123****890",
  "ussd_code": "*123#",
  "session_status": "ACTIVE",
  "started_at": "2025-03-30T15:30:00Z",
  "expires_at": "2025-03-30T15:30:30Z",
  "current_state": "MENU_MAIN",
  "session_context": {
    "device_type": "FEATURE_PHONE",
    "language": "en"
  },
  "menu": {
    "text": "Welcome to USSD Banking\n1. Check Balance\n2. Send Money\n3. Buy Airtime\n4. Transaction History",
    "options": [
      {"key": "1", "action": "BALANCE_INQUIRY"},
      {"key": "2", "action": "TRANSFER_MENU"},
      {"key": "3", "action": "AIRTIME_PURCHASE"},
      {"key": "4", "action": "TRANSACTION_HISTORY"}
    ]
  }
}
```

### 6. Process USSD Input

```http
POST /sessions/{session_id}/input
Content-Type: application/json
Authorization: Bearer {api_key}
```

#### Request Body

```json
{
  "user_input": "2",
  "input_type": "MENU_SELECTION"
}
```

#### Response

**200 OK**
```json
{
  "session_id": "SESS-550e8400-e29b-41d4-a716-446655440000",
  "session_status": "ACTIVE",
  "current_state": "TRANSFER_INPUT_AMOUNT",
  "previous_state": "MENU_MAIN",
  "response": {
    "text": "Send Money\nEnter recipient phone number:",
    "input_type": "NUMERIC",
    "expected_format": "PHONE_NUMBER"
  },
  "session_context": {
    "pending_action": "TRANSFER",
    "step": 1,
    "total_steps": 4
  }
}
```

### 7. Get Session Status

```http
GET /sessions/{session_id}
Authorization: Bearer {api_key}
```

#### Response

**200 OK**
```json
{
  "session_id": "SESS-550e8400-e29b-41d4-a716-446655440000",
  "msisdn": "+123****890",
  "session_status": "COMPLETED",
  "started_at": "2025-03-30T15:30:00Z",
  "ended_at": "2025-03-30T15:30:45Z",
  "duration_seconds": 45,
  "transaction_completed": true,
  "final_state": "RECEIPT_DISPLAY",
  "transactions": [
    {
      "transaction_id": "TXN-550e8400-e29b-41d4-a716-446655440000",
      "transaction_type": "TRANSFER",
      "amount": "100.00",
      "currency": "USD",
      "status": "COMPLETED",
      "ledger_entry_uuid": "LED-550e8400-e29b-41d4-a716-446655440000"
    }
  ],
  "state_history": [
    {
      "state": "MENU_MAIN",
      "entered_at": "2025-03-30T15:30:00Z",
      "exited_at": "2025-03-30T15:30:05Z"
    },
    {
      "state": "TRANSFER_INPUT_AMOUNT",
      "entered_at": "2025-03-30T15:30:05Z",
      "exited_at": "2025-03-30T15:30:15Z"
    }
  ]
}
```

### 8. Terminate Session

```http
POST /sessions/{session_id}/terminate
Content-Type: application/json
Authorization: Bearer {api_key}
```

#### Request Body

```json
{
  "reason": "USER_CANCELLED",
  "force": false
}
```

#### Response

**200 OK**
```json
{
  "session_id": "SESS-550e8400-e29b-41d4-a716-446655440000",
  "previous_status": "ACTIVE",
  "current_status": "COMPLETED",
  "termination_reason": "USER_CANCELLED",
  "terminated_at": "2025-03-30T15:35:00Z"
}
```

---

## Settlement APIs

### 9. Create Settlement Batch

```http
POST /settlements/batches
Content-Type: application/json
Authorization: Bearer {api_key}
```

#### Request Body

```json
{
  "service_provider_id": "PROVIDER-001",
  "batch_type": "DAILY",
  "batch_date": "2025-03-30",
  "auto_close": true,
  "close_at": "2025-03-30T23:59:59Z"
}
```

#### Response

**201 Created**
```json
{
  "batch_id": "BATCH-550e8400-e29b-41d4-a716-446655440000",
  "service_provider_id": "PROVIDER-001",
  "batch_type": "DAILY",
  "status": "OPEN",
  "batch_date": "2025-03-30",
  "opened_at": "2025-03-30T00:00:00Z",
  "scheduled_close_at": "2025-03-30T23:59:59Z",
  "total_amount": "0.00",
  "entry_count": 0,
  "auto_close_enabled": true
}
```

### 10. Close Settlement Batch

```http
POST /settlements/batches/{batch_id}/close
Content-Type: application/json
Authorization: Bearer {api_key}
```

#### Request Body

```json
{
  "force": false,
  "note": "End of day settlement",
  "mfa_token": "123456"
}
```

#### Response

**200 OK**
```json
{
  "batch_id": "BATCH-550e8400-e29b-41d4-a716-446655440000",
  "previous_status": "OPEN",
  "current_status": "CLOSED",
  "closed_at": "2025-03-30T23:59:59Z",
  "final_totals": {
    "total_amount": "15000.00",
    "entry_count": 150,
    "currency_code": "USD"
  },
  "summary_by_type": {
    "DEBIT": "10000.00",
    "CREDIT": "5000.00"
  },
  "reconciliation_status": "VERIFIED"
}
```

### 11. Get Settlement Batch

```http
GET /settlements/batches/{batch_id}
Authorization: Bearer {api_key}
```

#### Response

**200 OK**
```json
{
  "batch_id": "BATCH-550e8400-e29b-41d4-a716-446655440000",
  "service_provider_id": "PROVIDER-001",
  "service_provider_name": "Mobile Money Provider A",
  "batch_type": "DAILY",
  "status": "CLOSED",
  "batch_date": "2025-03-30",
  "opened_at": "2025-03-30T00:00:00Z",
  "closed_at": "2025-03-30T23:59:59Z",
  "total_amount": "15000.00",
  "entry_count": 150,
  "payment_status": "PENDING",
  "entries": {
    "data": [
      {
        "settlement_entry_id": "SE-550e8400",
        "ledger_entry_uuid": "LED-550e8400",
        "amount": "100.00",
        "entry_type": "DEBIT",
        "included_at": "2025-03-30T12:30:00Z"
      }
    ],
    "pagination": {
      "total_count": 150,
      "has_more": true,
      "next_cursor": "eyJsYXN0X2lkIjoxMjN9"
    }
  }
}
```

### 12. List Settlement Batches

```http
GET /settlements/batches?service_provider_id={provider_id}&status={status}&start_date={date}&end_date={date}
Authorization: Bearer {api_key}
```

#### Response

**200 OK**
```json
{
  "data": [
    {
      "batch_id": "BATCH-550e8400-e29b-41d4-a716-446655440000",
      "service_provider_id": "PROVIDER-001",
      "batch_type": "DAILY",
      "status": "SETTLED",
      "batch_date": "2025-03-30",
      "total_amount": "15000.00",
      "entry_count": 150,
      "payment_status": "COMPLETED",
      "settled_at": "2025-03-31T02:00:00Z"
    }
  ],
  "summary": {
    "total_batches": 30,
    "total_amount": "450000.00",
    "by_status": {
      "OPEN": 1,
      "CLOSED": 4,
      "SETTLED": 25
    }
  },
  "pagination": {
    "total_count": 30,
    "returned_count": 10,
    "has_more": true
  }
}
```

### 13. Initiate Settlement Payment

```http
POST /settlements/batches/{batch_id}/pay
Content-Type: application/json
Authorization: Bearer {api_key}
```

#### Request Body

```json
{
  "payment_method": "BANK_TRANSFER",
  "reference": "SETTLEMENT-MAR30-001",
  "callback_url": "https://webhook.company.com/settlement-complete",
  "mfa_token": "123456",
  "approver_note": "Approved for payment after reconciliation"
}
```

#### Response

**202 Accepted**
```json
{
  "batch_id": "BATCH-550e8400-e29b-41d4-a716-446655440000",
  "payment_status": "PROCESSING",
  "payment_initiated_at": "2025-03-31T02:00:00Z",
  "estimated_completion": "2025-03-31T06:00:00Z",
  "payment_reference": "PAY-550e8400-e29b-41d4-a716-446655440000",
  "track_url": "/settlements/payments/PAY-550e8400-e29b-41d4-a716-446655440000",
  "approver": "finance.admin@company.com"
}
```

---

## Service Provider APIs

### 14. Register Service Provider

```http
POST /service-providers
Content-Type: application/json
Authorization: Bearer {api_key}
```

#### Request Body

```json
{
  "provider_name": "Mobile Money Provider A",
  "provider_code": "MMPA",
  "settlement_schedule": "T+1",
  "settlement_accounts": [
    {
      "account_type": "BANK",
      "bank_name": "Bank of America",
      "account_number": "****1234",
      "routing_number": "021000322",
      "currency_code": "USD"
    }
  ],
  "api_config": {
    "webhook_url": "https://provider-a.com/webhooks",
    "notification_preferences": ["EMAIL", "WEBHOOK"]
  }
}
```

#### Response

**201 Created**
```json
{
  "provider_id": "PROVIDER-550e8400-e29b-41d4-a716-446655440000",
  "provider_name": "Mobile Money Provider A",
  "provider_code": "MMPA",
  "status": "ACTIVE",
  "settlement_schedule": "T+1",
  "created_at": "2025-03-30T15:30:00Z",
  "api_credentials": {
    "client_id": "client-550e8400",
    "client_secret": "secret-xxxxxxxxxxxx",  # Only shown once
    "webhook_secret": "whsec-xxxxxxxxxxxx"   # Only shown once
  }
}
```

### 15. Get Service Provider

```http
GET /service-providers/{provider_id}
Authorization: Bearer {api_key}
```

#### Response

**200 OK**
```json
{
  "provider_id": "PROVIDER-550e8400-e29b-41d4-a716-446655440000",
  "provider_name": "Mobile Money Provider A",
  "provider_code": "MMPA",
  "status": "ACTIVE",
  "settlement_schedule": "T+1",
  "settlement_accounts": [
    {
      "account_id": "ACC-1234",
      "account_type": "BANK",
      "bank_name": "Bank of America",
      "currency_code": "USD"
    }
  ],
  "statistics": {
    "total_accounts": 15000,
    "total_transactions_30d": 450000,
    "total_volume_30d": "2500000.00",
    "average_settlement_amount": "15000.00"
  },
  "created_at": "2025-03-30T15:30:00Z"
}
```

---

## Webhook Events

### Account Events

```json
{
  "event_type": "account.created",
  "event_id": "evt-550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-03-30T15:30:00Z",
  "data": {
    "account_id": "ACC-550e8400-e29b-41d4-a716-446655440000",
    "msisdn": "+123****890",
    "account_type": "WALLET",
    "status": "ACTIVE"
  }
}
```

### Session Events

```json
{
  "event_type": "session.completed",
  "event_id": "evt-660e8400-e29b-41d4-a716-446655440001",
  "timestamp": "2025-03-30T15:30:45Z",
  "data": {
    "session_id": "SESS-550e8400-e29b-41d4-a716-446655440000",
    "msisdn": "+123****890",
    "transaction_completed": true,
    "transaction_id": "TXN-550e8400-e29b-41d4-a716-446655440000",
    "amount": "100.00",
    "currency": "USD"
  }
}
```

### Settlement Events

```json
{
  "event_type": "settlement.batch.closed",
  "event_id": "evt-770e8400-e29b-41d4-a716-446655440002",
  "timestamp": "2025-03-30T23:59:59Z",
  "data": {
    "batch_id": "BATCH-550e8400-e29b-41d4-a716-446655440000",
    "service_provider_id": "PROVIDER-001",
    "total_amount": "15000.00",
    "entry_count": 150,
    "status": "CLOSED"
  }
}
```

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| INVALID_ACCOUNT_TYPE | 400 | Account type not supported |
| DUPLICATE_MSISDN | 409 | MSISDN already registered |
| INVALID_KYC_DATA | 400 | KYC validation failed |
| ACCOUNT_FROZEN | 403 | Account status prevents operation |
| SESSION_EXPIRED | 410 | USSD session has expired |
| INVALID_SESSION_STATE | 409 | Operation not valid in current state |
| BATCH_ALREADY_CLOSED | 409 | Settlement batch is already closed |
| BATCH_CLOSE_ERROR | 422 | Error closing batch (entries pending) |
| PROVIDER_NOT_FOUND | 404 | Service provider does not exist |
| INVALID_SETTLEMENT_SCHEDULE | 400 | Settlement schedule not supported |
| PAYMENT_FAILED | 502 | Settlement payment processor error |
| MFA_REQUIRED | 403 | Multi-factor authentication required |
| INSUFFICIENT_PRIVILEGES | 403 | User lacks required permissions |

---

## TODOs

- [ ] Implement bulk account onboarding API
- [ ] Add USSD session simulation endpoint for testing
- [ ] Create settlement forecasting API
- [ ] Implement provider self-service portal APIs
- [ ] Add real-time session monitoring endpoints
- [ ] Create reconciliation report APIs
- [ ] Implement multi-currency settlement support
- [ ] Add dispute management API endpoints
- [ ] Create compliance reporting APIs
- [ ] Implement API key rotation endpoints
