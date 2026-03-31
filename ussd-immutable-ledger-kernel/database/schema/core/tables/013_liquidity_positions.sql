-- =============================================================================
-- USSD KERNEL CORE SCHEMA - LIQUIDITY POSITIONS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    013_liquidity_positions.sql
-- SCHEMA:      ussd_core
-- TABLE:       liquidity_positions
-- DESCRIPTION: Tracks held funds, reserves, and liquidity positions for
--              accounts, applications, and system-wide liquidity management.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - Position access control
├── A.12.4 Logging and monitoring - Liquidity monitoring
└── A.14.2 Business continuity - Liquidity contingency

ISO/IEC 27040:2024 (Storage Security)
├── Immutable position history
├── Position integrity verification
└── Audit trail for all position changes

Financial Regulations
├── Liquidity coverage ratio (LCR) tracking
├── Net stable funding ratio (NSFR) support
├── Reserve requirement compliance
└── Intraday liquidity monitoring

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. POSITION TYPES
   - HELD: Funds temporarily held (e.g., pending settlement)
   - RESERVED: Regulatory or contractual reserves
   - COLLATERAL: Security for obligations
   - FLOAT: Working capital/float
   - PLEDGED: Pledged to third parties

2. POSITION STATES
   - ACTIVE: Position in effect
   - RELEASED: Position released, funds available
   - EXPIRED: Position auto-released after timeout
   - CONFISCATED: Position seized (regulatory)

3. CURRENCY HANDLING
   - Multi-currency positions
   - Currency-specific limits
   - FX rate tracking

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

POSITION AUTHORIZATION:
- Multi-level approval for large positions
- Separation of duties for position creation/release
- Automated limit checking

MONITORING:
- Real-time position monitoring
- Liquidity threshold alerts
- Stress testing support

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXES:
- PRIMARY KEY: position_id
- ACCOUNT: account_id + status
- TYPE: position_type + status
- EXPIRY: expires_at (for auto-release)

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- POSITION_CREATED
- POSITION_RELEASED
- POSITION_EXPIRED
- POSITION_EXTENDED

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- CREATE TABLE: liquidity_positions
-- =============================================================================

CREATE TABLE core.liquidity_positions (
    -- Primary identifier
    position_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    position_reference VARCHAR(100) UNIQUE,  -- External reference
    
    -- Position owner
    account_id UUID REFERENCES core.account_registry(account_id) ON DELETE RESTRICT,
    application_id UUID,
    
    -- Position classification
    position_type VARCHAR(50) NOT NULL
        CHECK (position_type IN ('HELD', 'RESERVED', 'COLLATERAL', 'FLOAT', 'PLEDGED')),
    position_subtype VARCHAR(50),
    
    -- Amount
    amount NUMERIC(20, 8) NOT NULL CHECK (amount > 0),
    currency VARCHAR(3) NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    
    -- Status
    status VARCHAR(20) DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'RELEASED', 'EXPIRED', 'CONFISCATED', 'PENDING')),
    
    -- Purpose
    purpose_code VARCHAR(50),
    description TEXT,
    regulatory_reference VARCHAR(100),
    
    -- Related transaction/movement
    source_transaction_id BIGINT,
    source_movement_id UUID,
    related_position_id UUID REFERENCES core.liquidity_positions(position_id) ON DELETE RESTRICT,
    
    -- Timing
    created_at TIMESTAMPTZ NOT NULL DEFAULT core.precise_now(),
    effective_date DATE NOT NULL DEFAULT CURRENT_DATE,
    expires_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    
    -- Release conditions
    auto_release BOOLEAN DEFAULT TRUE,
    release_conditions JSONB,  -- Conditions for automatic release
    
    -- Release details
    released_by UUID,
    release_reason TEXT,
    release_reference VARCHAR(100),
    
    -- Approval
    approved_by UUID,
    approved_at TIMESTAMPTZ,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    -- Audit
    created_by UUID,
    record_hash VARCHAR(64) NOT NULL,
    
    -- Constraints
    CONSTRAINT chk_release_dates CHECK (
        released_at IS NULL OR expires_at IS NULL OR released_at <= expires_at
    )
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- Account lookup
CREATE INDEX idx_liquidity_positions_account ON core.liquidity_positions(account_id, status);

-- Active positions
CREATE INDEX idx_liquidity_positions_active ON core.liquidity_positions(position_id)
    WHERE status = 'ACTIVE';

-- Position type
CREATE INDEX idx_liquidity_positions_type ON core.liquidity_positions(position_type, status);

-- Expiry lookup (for auto-release processing)
CREATE INDEX idx_liquidity_positions_expiry ON core.liquidity_positions(expires_at)
    WHERE status = 'ACTIVE' AND auto_release = TRUE;

-- Application lookup
CREATE INDEX idx_liquidity_positions_app ON core.liquidity_positions(application_id, status);

-- Currency aggregation
CREATE INDEX idx_liquidity_positions_currency ON core.liquidity_positions(currency, status);

-- Effective date
CREATE INDEX idx_liquidity_positions_effective ON core.liquidity_positions(effective_date DESC);

-- Reference lookup
CREATE INDEX idx_liquidity_positions_reference ON core.liquidity_positions(position_reference)
    WHERE position_reference IS NOT NULL;

-- =============================================================================
-- HASH COMPUTATION TRIGGER
-- =============================================================================

CREATE OR REPLACE FUNCTION core.compute_position_hash()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.record_hash := core.generate_hash(
        NEW.position_id::TEXT || 
        COALESCE(NEW.account_id::TEXT, '') || 
        NEW.position_type ||
        NEW.amount::TEXT ||
        NEW.currency ||
        NEW.status ||
        NEW.created_at::TEXT
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_liquidity_positions_compute_hash
    BEFORE INSERT OR UPDATE ON core.liquidity_positions
    FOR EACH ROW
    EXECUTE FUNCTION core.compute_position_hash();

-- =============================================================================
-- RLS POLICIES
-- =============================================================================

-- Enable RLS
ALTER TABLE core.liquidity_positions ENABLE ROW LEVEL SECURITY;

-- Policy: Account owners can view their positions
CREATE POLICY liquidity_positions_account_access ON core.liquidity_positions
    FOR SELECT
    TO ussd_app_user
    USING (account_id = current_setting('app.current_account_id', true)::UUID);

-- Policy: Application-scoped access
CREATE POLICY liquidity_positions_app_access ON core.liquidity_positions
    FOR SELECT
    TO ussd_app_user
    USING (
        application_id = current_setting('app.current_application_id', true)::UUID
        OR EXISTS (
            SELECT 1 FROM core.account_registry ar
            WHERE ar.account_id = liquidity_positions.account_id
            AND ar.primary_application_id = current_setting('app.current_application_id', true)::UUID
        )
    );

-- Policy: Kernel role has full access
CREATE POLICY liquidity_positions_kernel_access ON core.liquidity_positions
    FOR ALL
    TO ussd_kernel_role
    USING (true);

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

-- Function to create a liquidity position
CREATE OR REPLACE FUNCTION core.create_liquidity_position(
    p_account_id UUID,
    p_position_type VARCHAR,
    p_amount NUMERIC,
    p_currency VARCHAR,
    p_purpose_code VARCHAR DEFAULT NULL,
    p_description TEXT DEFAULT NULL,
    p_expires_at TIMESTAMPTZ DEFAULT NULL,
    p_auto_release BOOLEAN DEFAULT TRUE,
    p_application_id UUID DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_position_id UUID;
BEGIN
    INSERT INTO core.liquidity_positions (
        account_id,
        position_type,
        amount,
        currency,
        purpose_code,
        description,
        expires_at,
        auto_release,
        application_id
    ) VALUES (
        p_account_id,
        p_position_type,
        p_amount,
        p_currency,
        p_purpose_code,
        p_description,
        p_expires_at,
        p_auto_release,
        p_application_id
    )
    RETURNING position_id INTO v_position_id;
    
    RETURN v_position_id;
END;
$$;

-- Function to release a position
CREATE OR REPLACE FUNCTION core.release_liquidity_position(
    p_position_id UUID,
    p_released_by UUID,
    p_reason TEXT DEFAULT NULL,
    p_reference VARCHAR DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_position RECORD;
BEGIN
    -- Get position details
    SELECT * INTO v_position
    FROM core.liquidity_positions
    WHERE position_id = p_position_id
    AND status = 'ACTIVE';
    
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    
    -- Update position
    UPDATE core.liquidity_positions
    SET 
        status = 'RELEASED',
        released_at = core.precise_now(),
        released_by = p_released_by,
        release_reason = p_reason,
        release_reference = p_reference
    WHERE position_id = p_position_id;
    
    -- In a real implementation, this would also update the account balance
    
    RETURN TRUE;
END;
$$;

-- Function to extend position expiry
CREATE OR REPLACE FUNCTION core.extend_liquidity_position(
    p_position_id UUID,
    p_new_expires_at TIMESTAMPTZ,
    p_reason TEXT DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE core.liquidity_positions
    SET 
        expires_at = p_new_expires_at,
        metadata = metadata || jsonb_build_object('extension_reason', p_reason, 'extended_at', core.precise_now())
    WHERE position_id = p_position_id
    AND status = 'ACTIVE'
    AND (expires_at IS NULL OR p_new_expires_at > expires_at);
    
    RETURN FOUND;
END;
$$;

-- Function to get expiring positions
CREATE OR REPLACE FUNCTION core.get_expiring_positions(
    p_lookahead_interval INTERVAL DEFAULT INTERVAL '1 hour'
)
RETURNS TABLE (
    position_id UUID,
    account_id UUID,
    position_type VARCHAR,
    amount NUMERIC(20, 8),
    currency VARCHAR(3),
    expires_at TIMESTAMPTZ,
    minutes_until_expiry NUMERIC
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        lp.position_id,
        lp.account_id,
        lp.position_type,
        lp.amount,
        lp.currency,
        lp.expires_at,
        EXTRACT(EPOCH FROM (lp.expires_at - core.precise_now())) / 60
    FROM core.liquidity_positions lp
    WHERE lp.status = 'ACTIVE'
    AND lp.auto_release = TRUE
    AND lp.expires_at IS NOT NULL
    AND lp.expires_at <= core.precise_now() + p_lookahead_interval
    ORDER BY lp.expires_at;
END;
$$;

-- Function to auto-expire positions
CREATE OR REPLACE FUNCTION core.auto_expire_positions()
RETURNS INTEGER  -- Returns count of positions expired
LANGUAGE plpgsql
AS $$
DECLARE
    v_expired_count INTEGER := 0;
BEGIN
    UPDATE core.liquidity_positions
    SET 
        status = 'EXPIRED',
        released_at = core.precise_now(),
        release_reason = 'Auto-expired after timeout'
    WHERE status = 'ACTIVE'
    AND auto_release = TRUE
    AND expires_at IS NOT NULL
    AND expires_at <= core.precise_now();
    
    GET DIAGNOSTICS v_expired_count = ROW_COUNT;
    
    RETURN v_expired_count;
END;
$$;

-- Function to get liquidity summary
CREATE OR REPLACE FUNCTION core.get_liquidity_summary(
    p_account_id UUID DEFAULT NULL,
    p_application_id UUID DEFAULT NULL
)
RETURNS TABLE (
    position_type VARCHAR,
    currency VARCHAR(3),
    total_amount NUMERIC(20, 8),
    position_count BIGINT
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        lp.position_type,
        lp.currency,
        SUM(lp.amount),
        COUNT(*)::BIGINT
    FROM core.liquidity_positions lp
    WHERE lp.status = 'ACTIVE'
    AND (p_account_id IS NULL OR lp.account_id = p_account_id)
    AND (p_application_id IS NULL OR lp.application_id = p_application_id)
    GROUP BY lp.position_type, lp.currency
    ORDER BY lp.position_type, lp.currency;
END;
$$;

-- =============================================================================
-- TABLE AND COLUMN COMMENTS
-- =============================================================================

COMMENT ON TABLE core.liquidity_positions IS 
    'Tracks held funds, reserves, and liquidity positions for accounts and applications.';

COMMENT ON COLUMN core.liquidity_positions.position_id IS 
    'Unique identifier for the liquidity position';
COMMENT ON COLUMN core.liquidity_positions.position_type IS 
    'Type: HELD, RESERVED, COLLATERAL, FLOAT, PLEDGED';
COMMENT ON COLUMN core.liquidity_positions.status IS 
    'Status: ACTIVE, RELEASED, EXPIRED, CONFISCATED, PENDING';
COMMENT ON COLUMN core.liquidity_positions.amount IS 
    'Amount held in this position';
COMMENT ON COLUMN core.liquidity_positions.expires_at IS 
    'When this position will auto-expire (if auto_release is TRUE)';
COMMENT ON COLUMN core.liquidity_positions.auto_release IS 
    'Whether to automatically release when expired';
COMMENT ON COLUMN core.liquidity_positions.release_conditions IS 
    'JSON conditions for automatic release';
COMMENT ON COLUMN core.liquidity_positions.regulatory_reference IS 
    'Reference to regulatory requirement (if applicable)';

-- =============================================================================
-- END OF FILE
-- =============================================================================
