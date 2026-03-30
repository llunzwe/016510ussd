# USSD Gateway Database Schema - Compliance Documentation

## Overview

This directory contains the PostgreSQL database schema for the USSD Gateway component of the Immutable Ledger Kernel. All files have been enhanced with comprehensive compliance annotations following enterprise security standards and regulatory requirements.

---

## Compliance Standards Implemented

### 1. ISO/IEC 27001:2022 - Information Security Management System (ISMS)

| Control | Description | Files |
|---------|-------------|-------|
| A.5.1 | Information security policies | All session management files |
| A.8.1 | User endpoint security | Device fingerprinting, session binding |
| A.8.5 | Secure authentication | PIN/OTP, auth levels, verification |
| A.8.6 | Capacity management | Global rate limiting |
| A.8.7 | Malware protection | Input validation |
| A.8.8 | Technical vulnerability management | Secure routing |
| A.8.10 | Information deletion | Cleanup procedures |
| A.8.11 | Session timeout management | Multi-layer timeout architecture |
| A.8.12 | Audit logging | Hash chains, event tables |
| A.8.15 | Logging | Navigation history, transaction logs |
| A.8.16 | Monitoring activities | Anomaly detection, metrics |
| A.8.22 | Web filtering | Endpoint whitelist validation |
| A.8.23 | Web application security | SSRF prevention |

### 2. ISO/IEC 27018:2019 - PII Protection in Cloud Services

| Requirement | Implementation |
|-------------|----------------|
| MSISDN Encryption | Column-level AES-256-GCM |
| Context Encryption | Encrypted JSONB session data |
| Identifier Hashing | SHA-256 for IMEI/IMSI |
| Geolocation Limiting | Cell tower precision only |
| Pseudonymization | Analytics data anonymization |
| Right to Erasure | Anonymization support |

### 3. ISO/IEC 27035-2:2023 - Incident Management

| Feature | Description |
|---------|-------------|
| SIM Swap Detection | Multi-source correlation |
| Fraud Pattern Detection | Behavioral anomaly detection |
| Automated Response | Risk-based action matrix |
| Evidence Preservation | Audit trail integrity |
| Escalation Procedures | Severity-based notification |

### 4. ISO 31000:2018 - Risk Management

| Component | Risk Control |
|-----------|--------------|
| Trust Scoring | 0.0-1.0 device trust algorithm |
| Velocity Limits | Rate limiting per dimension |
| Risk Flags | Anomaly categorization |
| Risk-Based Timeouts | Dynamic session duration |
| Progressive Penalties | Escalating violation response |

### 5. PCI DSS v4.0 (Payment Card Industry)

| Requirement | Implementation |
|-------------|----------------|
| Req 3 | Cardholder data protection |
| Req 4 | Encrypted transmission |
| Req 8.1.8 | Session timeout (15 min max) |
| Req 10 | Access logging |
| Req 11.4 | Intrusion detection |
| mTLS | Service-to-service auth |

### 6. GDPR (General Data Protection Regulation)

| Article | Compliance Measure |
|---------|-------------------|
| Article 5(1)(a) | Lawful basis documentation |
| Article 5(1)(b) | Purpose limitation |
| Article 5(1)(c) | Data minimization |
| Article 5(1)(e) | Storage limitation |
| Article 32 | Security of processing |
| Article 17 | Right to erasure support |

### 7. GSMA IR.71 - SIM Swap Detection

| Requirement | Implementation |
|-------------|----------------|
| Multi-source Detection | Operator API, HLR, Device FP, Behavioral |
| 72-hour Window | Critical monitoring period |
| Device Correlation | Fingerprint change detection |
| Verification Workflow | Enhanced post-swap verification |

---

## File Structure

```
ussd_gateway/
├── TABLES/
│   ├── 000_session_state.sql          # Session management with encryption
│   ├── 001_shortcode_routing.sql      # Routing with SSRF prevention
│   ├── 002_menu_configurations.sql    # Menu security controls
│   ├── 003_pending_transactions.sql   # Transaction integrity
│   └── 004_device_fingerprints.sql    # Privacy-preserving fingerprints
├── FUNCTIONS/
│   ├── session/
│   │   ├── 000_create_session.sql     # Session creation with security checks
│   │   ├── 001_update_session_context.sql  # State machine with audit
│   │   ├── 002_resume_session.sql     # Secure session recovery
│   │   └── 003_cleanup_expired_sessions.sql # GDPR-compliant cleanup
│   ├── routing/
│   │   ├── 000_resolve_shortcode.sql  # Secure routing resolution
│   │   └── 001_route_to_application.sql # Secure inter-service comms
│   └── security/
│       ├── 000_verify_device_fingerprint.sql # Privacy-preserving verification
│       ├── 001_check_velocity_limits.sql     # Fraud prevention
│       └── 002_detect_sim_swap.sql           # Incident management
├── INDEXES/
│   └── 000_session_state_indexes.sql  # Performance & security indexes
└── COMPLIANCE_README.md               # This file
```

---

## Security Features by Category

### Session Management Security

| Feature | Standard | Implementation |
|---------|----------|----------------|
| Multi-layer Timeouts | ISO 27001 A.8.11 | Network + Application + Absolute |
| Hash Chain | ISO 27001 A.8.12 | SHA-256 linked list for integrity |
| Concurrent Session Control | ISO 27001 A.8.11 | Max 3 sessions per MSISDN |
| Context Encryption | ISO 27018 | AES-256-GCM with KMS |
| Device Binding | ISO 27001 A.8.1 | Fingerprint-session linkage |

### PII Protection

| Data Element | Protection Method | Standard |
|--------------|-------------------|----------|
| MSISDN | Column encryption + masking | ISO 27018 |
| IMEI/IMSI | SHA-256 hashing | ISO 27018 |
| Location | Cell tower precision only | GDPR |
| Session Context | AES-256-GCM encryption | ISO 27018 |
| Device Components | Encrypted BLOB storage | ISO 27018 |

### Fraud Detection

| Control | Description | Standard |
|---------|-------------|----------|
| Velocity Limits | Per-MSISDN, IP, App, Global | ISO 31000 |
| SIM Swap Detection | Multi-source correlation | ISO 27035-2 |
| Device Fingerprinting | Trust score algorithm | ISO 27001 A.8.1 |
| Behavioral Biometrics | Navigation pattern analysis | ISO 31000 |
| Risk Scoring | Transaction risk assessment | ISO 31000 |

---

## Enterprise PostgreSQL Coding Practices

### Security Definer Functions
All functions use `SECURITY DEFINER` with restricted execution roles:
- `ussd_gateway_role` - Standard gateway operations
- `ussd_security_role` - Security functions
- `ussd_cleanup_role` - Data cleanup operations
- `ussd_support_role` - Administrative functions

### Input Validation
- E.164 MSISDN format validation: `^\+[1-9][0-9]{7,14}$`
- Shortcode format validation: `^\*[0-9]+([*][0-9#*]*)?#$`
- Operator code validation: MCC+MNC format
- Context key whitelist validation

### Concurrency Control
- `SELECT FOR UPDATE` for session row locking
- Advisory locks for MSISDN-level operations
- Optimistic locking with version columns

### Audit Trail
- Immutable hash chains (`session_hash`, `previous_session_hash`)
- Event tables with severity classification
- Timestamp consistency using `NOW()` (database clock)

---

## Deployment Checklist

### Pre-Deployment

- [ ] Review and customize encryption key management (KMS integration)
- [ ] Configure session timeout values per environment
- [ ] Set up pg_cron for cleanup job scheduling
- [ ] Configure rate limiting thresholds
- [ ] Enable required PostgreSQL extensions:
  - `pgcrypto` (gen_random_uuid, encryption)
  - `pg_cron` (scheduled cleanup)
  - `pg_stat_statements` (query monitoring)

### Security Configuration

- [ ] Create database roles with minimal privileges
- [ ] Configure SSL/TLS for database connections
- [ ] Set up row-level security policies if needed
- [ ] Configure audit logging (pgAudit)
- [ ] Set up monitoring and alerting

### Compliance Verification

- [ ] Verify MSISDN encryption in transit and at rest
- [ ] Confirm IMEI/IMSI hashing implementation
- [ ] Test SIM swap detection workflows
- [ ] Validate velocity limit enforcement
- [ ] Review data retention policies

---

## Maintenance

### Regular Tasks

| Task | Frequency | Standard |
|------|-----------|----------|
| Index maintenance | Weekly | ISO 27001 A.12.3 |
| Audit log review | Daily | ISO 27001 A.8.15 |
| Encryption key rotation | Quarterly | ISO 27018 |
| Access review | Quarterly | ISO 27001 A.9.2 |
| Vulnerability scan | Monthly | ISO 27001 A.8.8 |

### Monitoring

- Session timeout rates
- Velocity limit violations
- SIM swap detection events
- Device fingerprint anomalies
- Database performance metrics

---

## Incident Response

### SIM Swap Detection Response

| Risk Level | Automatic Actions | Timeline |
|------------|-------------------|----------|
| CRITICAL | Block high-value TX, alert security | Immediate |
| HIGH | Reduce limits, 24h verification | Within 1 hour |
| MEDIUM | Additional verification, monitoring | Within 24 hours |
| LOW | Log, notify user | Within 24 hours |

### Velocity Violation Response

| Violation Count | Response |
|-----------------|----------|
| 1st | Warning, log only |
| 2nd | Temporary delay |
| 3rd | 1-hour block |
| 4th+ | 24-hour block, fraud investigation |

---

## Contact & Support

For compliance questions or security issues:
- Security Team: security@example.com
- Compliance Officer: compliance@example.com
- Database Administrators: dba@example.com

---

## Document History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-03-30 | Initial compliance enhancement | System |

---

## Legal Notice

This schema implements security controls for compliance with international standards. However, compliance is a shared responsibility:

1. **Infrastructure Security**: Ensure network, OS, and hardware security
2. **Application Security**: Implement secure coding practices in applications
3. **Operational Security**: Follow secure deployment and operations procedures
4. **Personnel Security**: Train staff on security policies and procedures

Organizations must conduct regular security audits and penetration testing to verify the effectiveness of these controls.
