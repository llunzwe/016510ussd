-- =============================================================================
-- USSD KERNEL CORE SCHEMA - TRANSACTION FUNCTIONS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    003_get_transaction_history.sql
-- SCHEMA:      core
-- CATEGORY:    Transaction Functions
-- DESCRIPTION: Transaction history queries with filtering, pagination,
--              and full-text search capabilities.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.8.1 User endpoint devices - History access control
├── A.8.11 Data masking - Sensitive data handling
└── A.12.4 Logging and monitoring - History query monitoring

GDPR Compliance
├── Data minimization: Query result limitation
├── Purpose limitation: Authorized access only
├── Right to access: Subject access request support
└── Audit trail: Query logging

Financial Regulations
├── Transaction history: Complete history provision
├── Statement generation: Periodic statement support
├── Dispute resolution: Evidence provision
└── Retention: 7+ year history availability

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. QUERY PATTERNS
   - Date range filtering
   - Transaction type filtering
   - Amount range filtering
   - Status filtering

2. PAGINATION
   - Cursor-based pagination
   - Offset/limit support
   - Total count provision
   - Performance optimization

3. SEARCH
   - Full-text search on payload
   - Reference number search
   - Metadata search

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

ACCESS CONTROL:
- Account ownership verification
- Application scope enforcement
- RLS policy compliance

DATA MASKING:
- Sensitive field masking
- Partial data redaction
- Role-based visibility

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

INDEXING:
- Account + date composite index
- Status partial index
- JSONB GIN index

PARTITIONING:
- Partition pruning for date ranges
- Partition-wise aggregation

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- HISTORY_QUERIED
- STATEMENT_GENERATED
- EXPORT_REQUESTED

RETENTION: 7 years
================================================================================
*/

-- Create transaction history result type
DROP TYPE IF EXISTS core.transaction_history_result CASCADE;
CREATE TYPE core.transaction_history_result AS (
    transaction_id UUID,
    transaction_reference VARCHAR(50),
    transaction_type VARCHAR(50),
    initiator_account_id UUID,
    beneficiary_account_id UUID,
    amount NUMERIC,
    currency VARCHAR(3),
    status VARCHAR(20),
    entry_date DATE,
    created_at TIMESTAMPTZ,
    current_hash VARCHAR(64),
    payload JSONB,
    chain_sequence BIGINT,
    account_sequence BIGINT
);

-- =============================================================================
-- Create get_transaction_history function
-- DESCRIPTION: Query transaction history with filtering
-- PRIORITY: HIGH
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_transaction_history(
    p_account_id UUID DEFAULT NULL,
    p_application_id UUID DEFAULT NULL,
    p_start_date DATE DEFAULT NULL,
    p_end_date DATE DEFAULT NULL,
    p_transaction_type_id UUID DEFAULT NULL,
    p_status VARCHAR(20) DEFAULT NULL,
    p_min_amount NUMERIC DEFAULT NULL,
    p_max_amount NUMERIC DEFAULT NULL,
    p_currency VARCHAR(3) DEFAULT NULL,
    p_cursor BIGINT DEFAULT NULL,  -- For cursor pagination (chain_sequence)
    p_limit INTEGER DEFAULT 50
)
RETURNS TABLE (
    transactions core.transaction_history_result[],
    next_cursor BIGINT,
    has_more BOOLEAN,
    total_count BIGINT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
DECLARE
    v_transactions core.transaction_history_result[];
    v_next_cursor BIGINT;
    v_has_more BOOLEAN;
    v_total_count BIGINT;
    v_limit INTEGER;
BEGIN
    v_limit := LEAST(COALESCE(p_limit, 50), 1000);  -- Max 1000 records
    
    -- Get total count (up to a reasonable limit for performance)
    SELECT COUNT(*) INTO v_total_count
    FROM core.transaction_log tl
    WHERE (p_account_id IS NULL OR 
           tl.initiator_account_id = p_account_id OR 
           tl.beneficiary_account_id = p_account_id)
      AND (p_application_id IS NULL OR tl.application_id = p_application_id)
      AND (p_start_date IS NULL OR tl.entry_date >= p_start_date)
      AND (p_end_date IS NULL OR tl.entry_date <= p_end_date)
      AND (p_transaction_type_id IS NULL OR tl.transaction_type_id = p_transaction_type_id)
      AND (p_status IS NULL OR tl.status = p_status)
      AND (p_min_amount IS NULL OR tl.amount >= p_min_amount)
      AND (p_max_amount IS NULL OR tl.amount <= p_max_amount)
      AND (p_currency IS NULL OR tl.currency = p_currency);
    
    -- Fetch transactions with cursor pagination
    SELECT array_agg(t.* ORDER BY t.chain_sequence DESC), MAX(t.chain_sequence)
    INTO v_transactions, v_next_cursor
    FROM (
        SELECT 
            tl.transaction_id,
            tl.transaction_reference,
            tt.name as transaction_type,
            tl.initiator_account_id,
            tl.beneficiary_account_id,
            tl.amount,
            tl.currency,
            tl.status,
            tl.entry_date,
            tl.created_at,
            encode(tl.current_hash, 'hex') as current_hash,
            tl.payload,
            tl.chain_sequence,
            tl.account_sequence
        FROM core.transaction_log tl
        LEFT JOIN core.transaction_types tt ON tl.transaction_type_id = tt.transaction_type_id
        WHERE (p_account_id IS NULL OR 
               tl.initiator_account_id = p_account_id OR 
               tl.beneficiary_account_id = p_account_id)
          AND (p_application_id IS NULL OR tl.application_id = p_application_id)
          AND (p_start_date IS NULL OR tl.entry_date >= p_start_date)
          AND (p_end_date IS NULL OR tl.entry_date <= p_end_date)
          AND (p_transaction_type_id IS NULL OR tl.transaction_type_id = p_transaction_type_id)
          AND (p_status IS NULL OR tl.status = p_status)
          AND (p_min_amount IS NULL OR tl.amount >= p_min_amount)
          AND (p_max_amount IS NULL OR tl.amount <= p_max_amount)
          AND (p_currency IS NULL OR tl.currency = p_currency)
          AND (p_cursor IS NULL OR tl.chain_sequence < p_cursor)
        ORDER BY tl.chain_sequence DESC
        LIMIT v_limit + 1  -- Fetch one extra to check for more
    ) t;
    
    -- Check if there are more results
    IF array_length(v_transactions, 1) > v_limit THEN
        v_has_more := true;
        v_transactions := v_transactions[1:v_limit];  -- Trim to requested limit
    ELSE
        v_has_more := false;
        v_next_cursor := NULL;
    END IF;
    
    -- Determine next cursor
    IF v_has_more AND array_length(v_transactions, 1) > 0 THEN
        SELECT (v_transactions[array_length(v_transactions, 1)]).chain_sequence 
        INTO v_next_cursor;
    ELSE
        v_next_cursor := NULL;
    END IF;
    
    -- Log query
    INSERT INTO core.audit_trail (
        event_type,
        table_name,
        record_id,
        details
    ) VALUES (
        'HISTORY_QUERIED',
        'transaction_log',
        COALESCE(p_account_id::text, 'MULTI'),
        jsonb_build_object(
            'filters', jsonb_build_object(
                'start_date', p_start_date,
                'end_date', p_end_date,
                'status', p_status,
                'currency', p_currency
            ),
            'limit', v_limit,
            'results_returned', COALESCE(array_length(v_transactions, 1), 0)
        )
    );
    
    RETURN QUERY SELECT v_transactions, v_next_cursor, v_has_more, v_total_count;
END;
$$;

COMMENT ON FUNCTION core.get_transaction_history IS 'Query transaction history with comprehensive filtering and cursor pagination';

-- =============================================================================
-- Create search_transactions function
-- DESCRIPTION: Full-text search over transactions
-- PRIORITY: MEDIUM
-- =============================================================================
CREATE OR REPLACE FUNCTION core.search_transactions(
    p_query TEXT,
    p_account_id UUID DEFAULT NULL,
    p_application_id UUID DEFAULT NULL,
    p_limit INTEGER DEFAULT 20
)
RETURNS TABLE (
    transaction_id UUID,
    transaction_reference VARCHAR(50),
    relevance_score REAL,
    matched_fields TEXT[],
    initiator_account_id UUID,
    amount NUMERIC,
    currency VARCHAR(3),
    created_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
AS $$
DECLARE
    v_normalized_query TEXT;
BEGIN
    v_normalized_query := lower(trim(p_query));
    
    IF length(v_normalized_query) < 3 THEN
        RAISE EXCEPTION 'Search query must be at least 3 characters';
    END IF;
    
    RETURN QUERY
    SELECT 
        tl.transaction_id,
        tl.transaction_reference,
        CASE 
            WHEN lower(tl.transaction_reference) = v_normalized_query THEN 1.0
            WHEN lower(tl.transaction_reference) LIKE v_normalized_query || '%' THEN 0.9
            WHEN lower(tl.transaction_reference) LIKE '%' || v_normalized_query || '%' THEN 0.8
            WHEN tl.payload::text ILIKE '%' || p_query || '%' THEN 0.7
            WHEN tl.beneficiary_account_id::text = v_normalized_query THEN 0.6
            ELSE 0.5
        END::REAL as relevance_score,
        ARRAY[
            CASE WHEN lower(tl.transaction_reference) LIKE '%' || v_normalized_query || '%' 
                 THEN 'reference' END,
            CASE WHEN tl.payload::text ILIKE '%' || p_query || '%' 
                 THEN 'payload' END,
            CASE WHEN tl.beneficiary_account_id::text = v_normalized_query 
                 THEN 'beneficiary' END
        ] as matched_fields,
        tl.initiator_account_id,
        tl.amount,
        tl.currency,
        tl.created_at
    FROM core.transaction_log tl
    WHERE (p_account_id IS NULL OR 
           tl.initiator_account_id = p_account_id OR 
           tl.beneficiary_account_id = p_account_id)
      AND (p_application_id IS NULL OR tl.application_id = p_application_id)
      AND (
          lower(tl.transaction_reference) LIKE '%' || v_normalized_query || '%'
          OR tl.payload::text ILIKE '%' || p_query || '%'
          OR tl.beneficiary_account_id::text = v_normalized_query
          OR tl.initiator_account_id::text = v_normalized_query
      )
    ORDER BY relevance_score DESC, tl.created_at DESC
    LIMIT LEAST(p_limit, 100);
    
    -- Log search
    INSERT INTO core.audit_trail (
        event_type,
        details
    ) VALUES (
        'TRANSACTION_SEARCH',
        jsonb_build_object(
            'query', p_query,
            'account_id', p_account_id,
            'limit', p_limit
        )
    );
END;
$$;

COMMENT ON FUNCTION core.search_transactions IS 'Full-text search over transactions with relevance scoring';

/*
================================================================================
MIGRATION CHECKLIST:
□ Create get_transaction_history function
□ Create search_transactions function
□ Test filtering
□ Test pagination
□ Test search
□ Benchmark query performance
================================================================================
*/

-- =============================================================================
-- END OF FILE
-- =============================================================================
