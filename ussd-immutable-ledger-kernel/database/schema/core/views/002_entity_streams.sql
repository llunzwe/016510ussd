-- =============================================================================
-- USSD KERNEL CORE SCHEMA - VIEWS
-- Enterprise-Grade Immutable Ledger System
-- =============================================================================
-- FILENAME:    002_entity_streams.sql
-- SCHEMA:      core
-- CATEGORY:    Views - Entity Streams
-- DESCRIPTION: Event stream views for Change Data Capture (CDC),
--              audit streaming, and real-time analytics.
-- =============================================================================

/*
================================================================================
COMPLIANCE FRAMEWORK
================================================================================

ISO/IEC 27001:2022 (Information Security Management Systems)
├── A.12.4 Logging and monitoring - Event streaming
├── A.16.1 Management of information security incidents - Real-time detection
└── A.18.1 Compliance - Audit stream support

ISO/IEC 27031:2025 (Business Continuity ICT Readiness)
├── Event sourcing: Complete event history
├── Stream replication: Cross-site replication
└── Recovery: Event-based recovery

================================================================================
ENTERPRISE POSTGRESQL CODING PRACTICES
================================================================================

1. STREAM FORMAT
   - Event type classification
   - Event payload structure
   - Timestamp ordering
   - Sequence numbers

2. STREAM TYPES
   - Transaction stream
   - Account change stream
   - Audit event stream
   - Error event stream

3. CONSUMPTION
   - CDC connectors
   - Event sourcing
   - Real-time analytics
   - Audit archiving

================================================================================
SECURITY IMPLEMENTATION NOTES
================================================================================

STREAM SECURITY:
- Access control on streams
- Sensitive data masking
- Audit logging of access

================================================================================
PERFORMANCE OPTIMIZATION ANNOTATIONS
================================================================================

STREAM OPTIMIZATION:
- Logical decoding slots
   - Partitioned consumption
   - Batch processing

================================================================================
AUDIT AND LOGGING REQUIREMENTS
================================================================================

AUDIT EVENTS:
- STREAM_ACCESSED
- EVENT_CONSUMED
- REPLICATION_LAG_ALERT

RETENTION: 7 years
================================================================================
*/

-- =============================================================================
-- VIEW: Transaction stream
-- DESCRIPTION: Real-time transaction event stream for CDC
-- PRIORITY: HIGH
-- =============================================================================
CREATE OR REPLACE VIEW core.transaction_stream AS
SELECT 
    -- Event metadata
    'TRANSACTION' AS event_type,
    'INSERT' AS change_type,
    tl.transaction_id AS entity_id,
    tl.transaction_uuid,
    
    -- Sequence information
    tl.chain_sequence AS global_sequence,
    tl.account_sequence AS entity_sequence,
    
    -- Event timestamp
    tl.committed_at AS event_timestamp,
    EXTRACT(EPOCH FROM tl.committed_at) * 1000000 AS event_micros,
    
    -- Transaction details
    tl.idempotency_key,
    tl.previous_hash,
    tl.transaction_hash,
    tl.status,
    
    -- Actor information
    tl.initiator_account_id,
    tl.on_behalf_of_account_id,
    tl.beneficiary_account_id,
    
    -- Financial details
    tl.amount,
    tl.currency,
    
    -- Classification
    tt.type_code AS transaction_type,
    tt.type_name AS transaction_type_name,
    tl.application_id,
    
    -- Block information
    tl.block_id,
    tl.block_sequence,
    
    -- Payload (selective fields for streaming)
    jsonb_build_object(
        'payload_type', tl.payload->>'type',
        'payload_reference', tl.payload->>'reference',
        'payload_description', tl.payload->>'description'
    ) AS payload_summary,
    
    -- LSN for CDC (would come from pg_current_wal_lsn in real implementation)
    NULL::pg_lsn AS wal_lsn,
    
    -- Event envelope
    jsonb_build_object(
        'event_id', gen_random_uuid(),
        'event_type', 'TRANSACTION_CREATED',
        'source', 'transaction_log',
        'timestamp', NOW(),
        'schema_version', '1.0'
    ) AS event_envelope

FROM core.transaction_log tl
LEFT JOIN core.transaction_types tt ON tl.transaction_type_id = tt.type_id;

-- =============================================================================
-- VIEW: Account change stream
-- DESCRIPTION: Stream of account-related changes
-- =============================================================================
CREATE OR REPLACE VIEW core.account_change_stream AS
-- Account registry changes
SELECT 
    'ACCOUNT_REGISTRY' AS event_type,
    'INSERT' AS change_type,
    ar.account_id::TEXT AS entity_id,
    ar.account_id AS entity_uuid,
    0 AS global_sequence,
    0 AS entity_sequence,
    ar.created_at AS event_timestamp,
    EXTRACT(EPOCH FROM ar.created_at) * 1000000 AS event_micros,
    NULL AS idempotency_key,
    ar.record_hash AS previous_hash,
    ar.record_hash AS entity_hash,
    ar.status,
    ar.account_id AS initiator_account_id,
    NULL::UUID AS on_behalf_of_account_id,
    NULL::UUID AS beneficiary_account_id,
    NULL::NUMERIC AS amount,
    NULL::VARCHAR(3) AS currency,
    ar.account_type AS entity_type,
    NULL::TEXT AS type_name,
    ar.primary_application_id AS application_id,
    NULL::UUID AS block_id,
    NULL::INTEGER AS block_sequence,
    jsonb_build_object(
        'account_type', ar.account_type,
        'display_name', ar.display_name,
        'status', ar.status,
        'parent_account_id', ar.parent_account_id
    ) AS payload_summary,
    NULL::pg_lsn AS wal_lsn,
    jsonb_build_object(
        'event_id', gen_random_uuid(),
        'event_type', 'ACCOUNT_CREATED',
        'source', 'account_registry',
        'timestamp', NOW(),
        'schema_version', '1.0'
    ) AS event_envelope
FROM core.account_registry ar

UNION ALL

-- Movement postings (account balance changes)
SELECT 
    'MOVEMENT_POSTING' AS event_type,
    'INSERT' AS change_type,
    mp.posting_id::TEXT AS entity_id,
    mp.posting_id AS entity_uuid,
    mp.transaction_id AS global_sequence,
    0 AS entity_sequence,
    mp.posted_at AS event_timestamp,
    EXTRACT(EPOCH FROM mp.posted_at) * 1000000 AS event_micros,
    NULL AS idempotency_key,
    NULL AS previous_hash,
    mp.posting_hash AS entity_hash,
    'POSTED'::VARCHAR(20) AS status,
    mp.account_id AS initiator_account_id,
    NULL::UUID AS on_behalf_of_account_id,
    NULL::UUID AS beneficiary_account_id,
    mp.amount,
    mp.currency,
    mp.coa_code AS entity_type,
    mp.direction AS type_name,
    NULL::UUID AS application_id,
    NULL::UUID AS block_id,
    NULL::INTEGER AS block_sequence,
    jsonb_build_object(
        'transaction_id', mp.transaction_id,
        'leg_id', mp.leg_id,
        'direction', mp.direction,
        'running_balance', mp.running_balance,
        'coa_code', mp.coa_code
    ) AS payload_summary,
    NULL::pg_lsn AS wal_lsn,
    jsonb_build_object(
        'event_id', gen_random_uuid(),
        'event_type', 'BALANCE_CHANGED',
        'source', 'movement_postings',
        'timestamp', NOW(),
        'schema_version', '1.0'
    ) AS event_envelope
FROM core.movement_postings mp;

-- =============================================================================
-- VIEW: Audit event stream
-- DESCRIPTION: Comprehensive audit stream combining all auditable events
-- =============================================================================
CREATE OR REPLACE VIEW core.audit_event_stream AS
SELECT 
    'AUDIT_EVENT' AS event_type,
    at.event_id::TEXT AS entity_id,
    at.event_id AS entity_uuid,
    at.event_timestamp AS event_timestamp,
    EXTRACT(EPOCH FROM at.event_timestamp) * 1000000 AS event_micros,
    at.event_type AS audit_event_type,
    at.event_description,
    at.actor_account_id,
    at.actor_session_id,
    at.actor_ip_address,
    at.severity,
    at.compliance_flag,
    at.metadata AS event_metadata,
    at.table_name AS affected_table,
    at.record_id AS affected_record_id,
    jsonb_build_object(
        'event_id', at.event_id,
        'event_type', at.event_type,
        'severity', at.severity,
        'compliance_flag', at.compliance_flag,
        'source', 'audit_trail',
        'timestamp', NOW(),
        'schema_version', '1.0'
    ) AS event_envelope
FROM core.audit_trail at
ORDER BY at.event_timestamp DESC;

-- =============================================================================
-- VIEW: Error event stream
-- DESCRIPTION: Stream of error events and failures
-- =============================================================================
CREATE OR REPLACE VIEW core.error_event_stream AS
-- Transaction failures
SELECT 
    'ERROR_EVENT' AS event_type,
    'TRANSACTION_FAILURE' AS error_category,
    tl.transaction_id::TEXT AS entity_id,
    tl.transaction_id AS entity_uuid,
    tl.committed_at AS event_timestamp,
    EXTRACT(EPOCH FROM tl.committed_at) * 1000000 AS event_micros,
    tl.rejection_code AS error_code,
    tl.rejection_reason AS error_message,
    tl.initiator_account_id AS affected_account_id,
    tl.application_id,
    tl.status AS transaction_status,
    jsonb_build_object(
        'transaction_uuid', tl.transaction_uuid,
        'idempotency_key', tl.idempotency_key,
        'transaction_type_id', tl.transaction_type_id,
        'amount', tl.amount,
        'currency', tl.currency
    ) AS context,
    jsonb_build_object(
        'event_id', gen_random_uuid(),
        'event_type', 'TRANSACTION_FAILED',
        'severity', 'ERROR',
        'source', 'transaction_log',
        'timestamp', NOW(),
        'schema_version', '1.0'
    ) AS event_envelope
FROM core.transaction_log tl
WHERE tl.status = 'failed'

UNION ALL

-- Rejection log entries
SELECT 
    'ERROR_EVENT' AS event_type,
    'REJECTION' AS error_category,
    rl.rejection_id::TEXT AS entity_id,
    rl.rejection_id AS entity_uuid,
    rl.rejected_at AS event_timestamp,
    EXTRACT(EPOCH FROM rl.rejected_at) * 1000000 AS event_micros,
    rl.rejection_code AS error_code,
    rl.rejection_reason AS error_message,
    rl.initiator_account_id AS affected_account_id,
    rl.application_id,
    rl.status AS transaction_status,
    jsonb_build_object(
        'transaction_reference', rl.transaction_reference,
        'rejection_stage', rl.rejection_stage,
        'validation_errors', rl.validation_errors
    ) AS context,
    jsonb_build_object(
        'event_id', gen_random_uuid(),
        'event_type', 'TRANSACTION_REJECTED',
        'severity', 'WARNING',
        'source', 'rejection_log',
        'timestamp', NOW(),
        'schema_version', '1.0'
    ) AS event_envelope
FROM core.rejection_log rl;

-- =============================================================================
-- VIEW: Block stream
-- DESCRIPTION: Stream of block sealing events
-- =============================================================================
CREATE OR REPLACE VIEW core.block_stream AS
SELECT 
    'BLOCK_EVENT' AS event_type,
    b.block_id::TEXT AS entity_id,
    b.block_id AS entity_uuid,
    b.chain_sequence AS block_number,
    b.status AS block_status,
    b.opened_at,
    b.sealed_at,
    b.anchored_at,
    b.transaction_count,
    b.merkle_root,
    b.block_hash,
    b.previous_block_hash,
    b.anchor_type,
    b.anchor_tx_id,
    b.total_amount,
    b.currencies,
    b.unique_accounts,
    jsonb_build_object(
        'min_transaction_id', b.min_transaction_id,
        'max_transaction_id', b.max_transaction_id,
        'merkle_tree_depth', b.merkle_tree_depth
    ) AS block_metadata,
    jsonb_build_object(
        'event_id', gen_random_uuid(),
        'event_type', CASE 
            WHEN b.status = 'OPEN' THEN 'BLOCK_OPENED'
            WHEN b.status = 'SEALED' THEN 'BLOCK_SEALED'
            WHEN b.status = 'ANCHORED' THEN 'BLOCK_ANCHORED'
        END,
        'source', 'blocks',
        'timestamp', NOW(),
        'schema_version', '1.0'
    ) AS event_envelope
FROM core.blocks b
ORDER BY b.chain_sequence DESC;

-- =============================================================================
-- FUNCTION: Get events since sequence
-- Description: Returns events after a given sequence number for CDC
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_events_since(
    p_last_sequence BIGINT,
    p_limit INTEGER DEFAULT 1000
)
RETURNS TABLE (
    sequence_number BIGINT,
    event_type TEXT,
    entity_id TEXT,
    event_timestamp TIMESTAMPTZ,
    event_data JSONB
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        tl.chain_sequence AS sequence_number,
        'TRANSACTION'::TEXT AS event_type,
        tl.transaction_id::TEXT AS entity_id,
        tl.committed_at AS event_timestamp,
        jsonb_build_object(
            'transaction_uuid', tl.transaction_uuid,
            'transaction_hash', tl.transaction_hash,
            'initiator_account_id', tl.initiator_account_id,
            'status', tl.status,
            'amount', tl.amount,
            'currency', tl.currency
        ) AS event_data
    FROM core.transaction_log tl
    WHERE tl.chain_sequence > p_last_sequence
    ORDER BY tl.chain_sequence
    LIMIT p_limit;
END;
$$;

-- =============================================================================
-- FUNCTION: Get stream watermark
-- Description: Returns the current high watermark for stream consumption
-- =============================================================================
CREATE OR REPLACE FUNCTION core.get_stream_watermark()
RETURNS TABLE (
    max_transaction_sequence BIGINT,
    max_block_sequence BIGINT,
    max_audit_event_id BIGINT,
    watermark_timestamp TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        (SELECT MAX(chain_sequence) FROM core.transaction_log),
        (SELECT MAX(chain_sequence) FROM core.blocks),
        (SELECT MAX(event_id) FROM core.audit_trail),
        NOW() AS watermark_timestamp;
END;
$$;

-- =============================================================================
-- FUNCTION: Export events for archival
-- Description: Formats events for export to external systems
-- =============================================================================
CREATE OR REPLACE FUNCTION core.export_events_for_archival(
    p_start_time TIMESTAMPTZ,
    p_end_time TIMESTAMPTZ
)
RETURNS TABLE (
    export_format JSONB
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        jsonb_build_object(
            'header', jsonb_build_object(
                'export_id', gen_random_uuid(),
                'start_time', p_start_time,
                'end_time', p_end_time,
                'generated_at', NOW()
            ),
            'transactions', (
                SELECT jsonb_agg(jsonb_build_object(
                    'transaction_id', transaction_id,
                    'transaction_uuid', transaction_uuid,
                    'committed_at', committed_at,
                    'transaction_hash', transaction_hash,
                    'initiator_account_id', initiator_account_id,
                    'amount', amount,
                    'currency', currency
                ))
                FROM core.transaction_log
                WHERE committed_at BETWEEN p_start_time AND p_end_time
            ),
            'audit_events', (
                SELECT jsonb_agg(jsonb_build_object(
                    'event_id', event_id,
                    'event_type', event_type,
                    'event_timestamp', event_timestamp,
                    'severity', severity
                ))
                FROM core.audit_trail
                WHERE event_timestamp BETWEEN p_start_time AND p_end_time
            )
        ) AS export_format;
END;
$$;

-- =============================================================================
-- MIGRATION CHECKLIST:
-- □ Create transaction_stream view
-- □ Create account_change_stream view
-- □ Create audit_event_stream view
-- □ Set up logical replication
-- □ Test CDC consumption
-- □ Benchmark stream performance
================================================================================

-- =============================================================================
-- END OF FILE
-- =============================================================================
