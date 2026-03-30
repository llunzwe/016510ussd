-- =============================================================================
-- USSD KERNEL CORE SCHEMA - TRANSACTION TYPES
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    001_transaction_types.sql
-- SCHEMA:      ussd_core
-- TABLE:       transaction_types
-- DESCRIPTION: Master reference for all transaction classifications including
--              business rules, validation schemas, and workflow configurations.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.5.9 Information asset inventory - Transaction types classified
├── A.5.13 Classification of information - Risk-based type categorization
└── A.8.1 User endpoint devices - Transaction origination controls

ISO/IEC 27040:2024 (Storage Security)
├── Immutable audit trail per transaction type
├── Type-specific retention policies enforced
└── WORM storage for high-value transaction types

ISO/IEC 27031:2025 (Business Continuity ICT Readiness)
├── Critical transaction types prioritized for recovery
├── Failover procedures per transaction category
└── RTO/RPO defined by transaction criticality

SOX Compliance (if applicable)
├── Financial transaction types require dual authorization
├── Immutable audit trail for all financial transactions
└── Change management for transaction type modifications

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. REFERENCE DATA MANAGEMENT
   - Immutable reference data with versioning
   - Type codes use descriptive, stable identifiers
   - Soft delete via valid_to timestamp

2. JSON SCHEMA VALIDATION
   - payload_schema uses JSON Schema format
   - Schema versioning tracked separately
   - Validation enforced at application and database level

3. WORKFLOW CONFIGURATION
   - approval_workflow stored as JSONB for flexibility
   - Required approvals configurable per type
   - Escalation rules embedded in workflow config

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

AUTHORIZATION LEVELS:
- Level 1: Standard transactions (self-approved)
- Level 2: Supervisor approval required
- Level 3: Manager approval required
- Level 4: Multi-signature required
- Level 5: Board/exco approval required

VALIDATION RULES:
- JSON Schema validation on payload
- Amount limits per transaction type
- Frequency limits (daily/weekly/monthly)
- Time-of-day restrictions
- Geographic restrictions

CHANGE CONTROL:
- Transaction types are versioned (valid_from/valid_to)
- Changes require CAB approval
- Audit trail for all type modifications
- Emergency change procedures documented

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXING:
- PRIMARY KEY: type_id (UUID)
- UNIQUE: type_code (natural key lookup)
- PARTIAL: valid_to IS NULL (active types only)

CACHING:
- Transaction types cached in application layer
- Cache invalidated on type updates
- Redis/Memcached recommended for distributed systems

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- TYPE_CREATED: New transaction type defined
- TYPE_MODIFIED: Versioned update to type
- TYPE_DEPRECATED: Type marked for retirement
- TYPE_ACCESSED: Schema retrieval for validation

CHANGE MANAGEMENT:
- All type changes logged to audit_trail
- Approval workflow for modifications
- Impact assessment required
================================================================================
*/

-- -----------------------------------------------------------------------------
-- TODO[PRIMARY_KEY]: Define transaction types primary key
-- -----------------------------------------------------------------------------
-- type_id UUID PRIMARY KEY DEFAULT uuid_generate_v4()
-- type_code VARCHAR(50) UNIQUE NOT NULL - Natural key for references

-- -----------------------------------------------------------------------------
-- TODO[INDEXES]: Define lookup indexes
-- -----------------------------------------------------------------------------
-- CREATE UNIQUE INDEX idx_transaction_types_code_active
--     ON ussd_core.transaction_types(type_code) WHERE valid_to IS NULL;
--
-- CREATE INDEX idx_transaction_types_category
--     ON ussd_core.transaction_types(category, valid_to IS NULL);

-- -----------------------------------------------------------------------------
-- TODO[CONSTRAINTS]: Business rule constraints
-- -----------------------------------------------------------------------------
-- CHECK (risk_level IN ('low', 'medium', 'high', 'critical'))
-- CHECK (requires_approval IN (true, false))
-- CHECK (max_amount > 0 OR max_amount IS NULL)

-- -----------------------------------------------------------------------------
-- TABLE STRUCTURE (Reference)
-- -----------------------------------------------------------------------------
/*
CREATE TABLE ussd_core.transaction_types (
    -- Primary identifier
    type_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Natural key (immutable once assigned)
    type_code VARCHAR(50) UNIQUE NOT NULL,
    type_name VARCHAR(100) NOT NULL,
    
    -- Classification
    category VARCHAR(50) NOT NULL,  -- payment, transfer, fee, adjustment, etc.
    subcategory VARCHAR(50),        -- More specific classification
    
    -- Risk and compliance
    risk_level VARCHAR(20) DEFAULT 'low' 
        CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    compliance_flags VARCHAR(50)[] DEFAULT '{}',  -- AML, KYC, etc.
    
    -- Validation schema
    payload_schema JSONB NOT NULL,  -- JSON Schema for validation
    schema_version INTEGER DEFAULT 1,
    
    -- Business rules
    requires_approval BOOLEAN DEFAULT false,
    approval_workflow JSONB,        -- Workflow configuration
    min_amount NUMERIC(20, 8),
    max_amount NUMERIC(20, 8),
    daily_limit NUMERIC(20, 8),
    
    -- Processing configuration
    processor_module VARCHAR(100),  -- Handler function/module
    priority INTEGER DEFAULT 100,   -- Processing priority (lower = higher)
    
    -- Accounting impact
    accounting_impact JSONB,        -- COA entries generated
    
    -- Notifications
    notification_config JSONB,      -- Alert triggers
    
    -- Versioning
    valid_from TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    valid_to TIMESTAMPTZ,
    superseded_by UUID REFERENCES ussd_core.transaction_types(type_id),
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT ussd_core.precise_now(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL
);
*/

-- -----------------------------------------------------------------------------
-- INITIAL DATA: Core transaction types
-- -----------------------------------------------------------------------------
/*
INSERT INTO ussd_core.transaction_types (type_code, type_name, category, payload_schema) VALUES
    ('P2P_TRANSFER', 'Peer-to-Peer Transfer', 'payment', '{...}'),
    ('MERCHANT_PAY', 'Merchant Payment', 'payment', '{...}'),
    ('AIRTIME_PURCHASE', 'Airtime Purchase', 'purchase', '{...}'),
    ('BILL_PAYMENT', 'Bill Payment', 'payment', '{...}'),
    ('CASH_IN', 'Cash Deposit', 'deposit', '{...}'),
    ('CASH_OUT', 'Cash Withdrawal', 'withdrawal', '{...}'),
    ('FEE_CHARGE', 'Transaction Fee', 'fee', '{...}'),
    ('ADJUSTMENT', 'Account Adjustment', 'adjustment', '{...}');
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
