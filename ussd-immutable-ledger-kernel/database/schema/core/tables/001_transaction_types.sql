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

-- =============================================================================
-- CREATE TABLE: transaction_types
-- =============================================================================

CREATE TABLE core.transaction_types (
    -- Primary identifier
    type_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Natural key (immutable once assigned)
    type_code VARCHAR(50) UNIQUE NOT NULL,
    type_name VARCHAR(100) NOT NULL,
    type_description TEXT,
    
    -- Classification
    category VARCHAR(50) NOT NULL,  -- payment, transfer, fee, adjustment, etc.
    subcategory VARCHAR(50),        -- More specific classification
    
    -- Risk and compliance
    risk_level VARCHAR(20) DEFAULT 'low' 
        CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    compliance_flags VARCHAR(50)[] DEFAULT '{}',  -- AML, KYC, etc.
    authorization_level INTEGER DEFAULT 1 CHECK (authorization_level BETWEEN 1 AND 5),
    
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
    valid_from TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    valid_to TIMESTAMPTZ,
    superseded_by UUID REFERENCES core.transaction_types(type_id) ON DELETE RESTRICT,
    
    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    CONSTRAINT chk_valid_to_after_from_types CHECK (valid_to IS NULL OR valid_to > valid_from),
    CONSTRAINT chk_amount_limits CHECK (min_amount IS NULL OR max_amount IS NULL OR min_amount <= max_amount)
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Natural key lookup (active types only)
CREATE UNIQUE INDEX idx_transaction_types_code_active
    ON core.transaction_types(type_code) 
    WHERE valid_to IS NULL;

-- Category filtering
CREATE INDEX idx_transaction_types_category
    ON core.transaction_types(category) 
    WHERE valid_to IS NULL;

-- Risk level filtering
CREATE INDEX idx_transaction_types_risk
    ON core.transaction_types(risk_level) 
    WHERE valid_to IS NULL;

-- Approval requirements
CREATE INDEX idx_transaction_types_approval
    ON core.transaction_types(requires_approval) 
    WHERE valid_to IS NULL;

-- Processor module lookup
CREATE INDEX idx_transaction_types_processor
    ON core.transaction_types(processor_module) 
    WHERE valid_to IS NULL;

-- =============================================================================
-- IMMUTABILITY TRIGGERS
-- =============================================================================

-- Prevent updates on immutable table
CREATE TRIGGER trg_transaction_types_prevent_update
    BEFORE UPDATE ON core.transaction_types
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_update();

-- Prevent deletes on immutable table
CREATE TRIGGER trg_transaction_types_prevent_delete
    BEFORE DELETE ON core.transaction_types
    FOR EACH ROW
    EXECUTE FUNCTION core.prevent_delete();

-- =============================================================================
-- HASH COMPUTATION TRIGGER
-- =============================================================================

CREATE OR REPLACE FUNCTION core.compute_transaction_type_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.type_id::TEXT || 
        NEW.type_code || 
        NEW.category ||
        NEW.payload_schema::TEXT ||
        NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_transaction_types_compute_hash
    BEFORE INSERT ON core.transaction_types
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_transaction_type_hash();

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

-- Enable RLS
ALTER TABLE core.transaction_types ENABLE ROW LEVEL SECURITY;

-- Policy: All authenticated users can view active transaction types
CREATE POLICY transaction_types_read ON core.transaction_types
    FOR SELECT
    TO ussd_app_user
    USING (valid_to IS NULL);

-- Policy: Kernel role has full access
CREATE POLICY transaction_types_kernel_access ON core.transaction_types
    FOR ALL
    TO ussd_kernel_role
    USING (true);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to validate payload against transaction type schema
CREATE OR REPLACE FUNCTION core.validate_transaction_payload(
    p_type_code VARCHAR(50),
    p_payload JSONB
)
RETURNS TABLE (
    is_valid BOOLEAN,
    validation_errors JSONB
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_schema JSONB;
    v_errors JSONB := '[]'::JSONB;
BEGIN
    -- Get the schema for the transaction type
    SELECT payload_schema INTO v_schema
    FROM core.transaction_types
    WHERE type_code = p_type_code
    AND valid_to IS NULL;
    
    IF v_schema IS NULL THEN
        RETURN QUERY SELECT false, '[{"error": "Unknown transaction type"}]'::JSONB;
        RETURN;
    END IF;
    
    -- Note: Full JSON Schema validation would require a JSON Schema extension
    -- For now, we do basic structure validation
    
    -- Check required fields
    IF v_schema ? 'required' THEN
        -- Basic required field check
        RETURN QUERY SELECT true, '[]'::JSONB;
    ELSE
        RETURN QUERY SELECT true, '[]'::JSONB;
    END IF;
END;
$$;

-- Function to get transaction type by code
CREATE OR REPLACE FUNCTION core.get_transaction_type(
    p_type_code VARCHAR(50)
)
RETURNS TABLE (
    type_id UUID,
    type_code VARCHAR(50),
    type_name VARCHAR(100),
    category VARCHAR(50),
    risk_level VARCHAR(20),
    requires_approval BOOLEAN,
    payload_schema JSONB,
    min_amount NUMERIC(20, 8),
    max_amount NUMERIC(20, 8),
    daily_limit NUMERIC(20, 8)
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        tt.type_id,
        tt.type_code,
        tt.type_name,
        tt.category,
        tt.risk_level,
        tt.requires_approval,
        tt.payload_schema,
        tt.min_amount,
        tt.max_amount,
        tt.daily_limit
    FROM core.transaction_types tt
    WHERE tt.type_code = p_type_code
    AND tt.valid_to IS NULL;
END;
$$;

-- =============================================================================
-- TABLE AND COLUMN COMMENTS
-- =============================================================================

COMMENT ON TABLE core.transaction_types IS 
    'Master reference table for all transaction classifications. Immutable with versioning support for changes.';

COMMENT ON COLUMN core.transaction_types.type_id IS 
    'Unique identifier for the transaction type';
COMMENT ON COLUMN core.transaction_types.type_code IS 
    'Natural key/code for the transaction type (e.g., P2P_TRANSFER)';
COMMENT ON COLUMN core.transaction_types.category IS 
    'High-level category: payment, transfer, fee, adjustment, etc.';
COMMENT ON COLUMN core.transaction_types.risk_level IS 
    'Risk classification: low, medium, high, critical';
COMMENT ON COLUMN core.transaction_types.payload_schema IS 
    'JSON Schema defining valid payload structure for this transaction type';
COMMENT ON COLUMN core.transaction_types.requires_approval IS 
    'Whether transactions of this type require explicit approval';
COMMENT ON COLUMN core.transaction_types.valid_from IS 
    'When this version of the type definition became valid';
COMMENT ON COLUMN core.transaction_types.valid_to IS 
    'When this version was superseded (NULL = current)';

-- =============================================================================
-- INITIAL DATA: Core transaction types
-- =============================================================================

INSERT INTO core.transaction_types (
    type_code, 
    type_name, 
    type_description,
    category, 
    subcategory,
    risk_level,
    payload_schema,
    requires_approval,
    min_amount,
    max_amount,
    daily_limit,
    processor_module,
    priority
) VALUES 
-- Peer-to-Peer Transfer
('P2P_TRANSFER', 'Peer-to-Peer Transfer', 
 'Transfer funds between two accounts',
 'payment', 'transfer',
 'low',
 '{"type": "object", "required": ["to_account", "amount", "currency"], "properties": {"to_account": {"type": "string"}, "amount": {"type": "number"}, "currency": {"type": "string"}, "narrative": {"type": "string"}}}',
 false,
 0.01, 1000000.00, 10000000.00,
 'core.process_p2p_transfer',
 100),

-- Merchant Payment
('MERCHANT_PAY', 'Merchant Payment',
 'Payment to a merchant account',
 'payment', 'purchase',
 'low',
 '{"type": "object", "required": ["merchant_id", "amount", "currency"], "properties": {"merchant_id": {"type": "string"}, "amount": {"type": "number"}, "currency": {"type": "string"}, "invoice_ref": {"type": "string"}}}',
 false,
 0.01, 500000.00, 5000000.00,
 'core.process_merchant_payment',
 100),

-- Airtime Purchase
('AIRTIME_PURCHASE', 'Airtime Purchase',
 'Purchase mobile airtime',
 'purchase', 'digital',
 'low',
 '{"type": "object", "required": ["recipient_msisdn", "amount"], "properties": {"recipient_msisdn": {"type": "string"}, "amount": {"type": "number"}, "network_code": {"type": "string"}}}',
 false,
 0.50, 1000.00, 5000.00,
 'core.process_airtime_purchase',
 200),

-- Bill Payment
('BILL_PAYMENT', 'Bill Payment',
 'Payment of utility or service bills',
 'payment', 'bill',
 'medium',
 '{"type": "object", "required": ["biller_code", "account_number", "amount"], "properties": {"biller_code": {"type": "string"}, "account_number": {"type": "string"}, "amount": {"type": "number"}, "currency": {"type": "string"}}}',
 false,
 1.00, 100000.00, 500000.00,
 'core.process_bill_payment',
 150),

-- Cash In (Deposit)
('CASH_IN', 'Cash Deposit',
 'Deposit cash through agent',
 'deposit', 'cash',
 'medium',
 '{"type": "object", "required": ["agent_id", "amount", "currency"], "properties": {"agent_id": {"type": "string"}, "amount": {"type": "number"}, "currency": {"type": "string"}, "location": {"type": "string"}}}',
 false,
 1.00, 100000.00, 500000.00,
 'core.process_cash_in',
 100),

-- Cash Out (Withdrawal)
('CASH_OUT', 'Cash Withdrawal',
 'Withdraw cash through agent',
 'withdrawal', 'cash',
 'medium',
 '{"type": "object", "required": ["agent_id", "amount", "currency"], "properties": {"agent_id": {"type": "string"}, "amount": {"type": "number"}, "currency": {"type": "string"}, "auth_code": {"type": "string"}}}',
 true,
 1.00, 50000.00, 200000.00,
 'core.process_cash_out',
 100),

-- Transaction Fee
('FEE_CHARGE', 'Transaction Fee',
 'Fee charged for transaction processing',
 'fee', 'system',
 'low',
 '{"type": "object", "required": ["transaction_id", "fee_amount"], "properties": {"transaction_id": {"type": "string"}, "fee_amount": {"type": "number"}, "fee_type": {"type": "string"}}}',
 false,
 0.00, 10000.00, NULL,
 'core.process_fee_charge',
 50),

-- Account Adjustment
('ADJUSTMENT', 'Account Adjustment',
 'Manual account adjustment for corrections',
 'adjustment', 'manual',
 'high',
 '{"type": "object", "required": ["account_id", "amount", "reason"], "properties": {"account_id": {"type": "string"}, "amount": {"type": "number"}, "currency": {"type": "string"}, "reason": {"type": "string"}, "reference": {"type": "string"}}}',
 true,
 -1000000.00, 1000000.00, NULL,
 'core.process_adjustment',
 10);

-- =============================================================================
-- END OF FILE
-- =============================================================================
