-- =============================================================================
-- LOGICAL DECODING
-- Change data capture and event streaming infrastructure
-- =============================================================================

-- =============================================================================
-- LOGICAL DECODING SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS logical_decoding;

COMMENT ON SCHEMA logical_decoding IS 'Logical decoding and change data capture configuration';

-- =============================================================================
-- SLOT REGISTRY
-- =============================================================================
CREATE TABLE IF NOT EXISTS logical_decoding.slot_registry (
    id SERIAL PRIMARY KEY,
    slot_name VARCHAR(128) NOT NULL UNIQUE,
    plugin VARCHAR(50) NOT NULL DEFAULT 'pgoutput',
    database VARCHAR(63) NOT NULL,
    
    -- Purpose
    purpose VARCHAR(100) NOT NULL, -- CDC, REPLICATION, AUDIT, ETL
    consumer_name VARCHAR(100), -- Application consuming the slot
    consumer_type VARCHAR(50), -- KAFKA, APP, ANALYTICS, etc.
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_confirmed_flush_lsn pg_lsn,
    last_confirmed_at TIMESTAMPTZ,
    
    -- Lag monitoring
    current_lag_bytes BIGINT,
    lag_threshold_bytes BIGINT DEFAULT 104857600, -- 100MB
    lag_alert_sent_at TIMESTAMPTZ,
    
    -- Retention
    retain_bytes BIGINT DEFAULT 1073741824, -- 1GB default retention
    max_lag_minutes INTEGER DEFAULT 60,
    
    -- Metadata
    description TEXT,
    created_by VARCHAR(100) DEFAULT current_user
);

CREATE INDEX IF NOT EXISTS idx_slot_registry_purpose 
ON logical_decoding.slot_registry(purpose);

CREATE INDEX IF NOT EXISTS idx_slot_registry_consumer 
ON logical_decoding.slot_registry(consumer_name);

-- =============================================================================
-- CHANGE EVENT LOG
-- =============================================================================
CREATE TABLE IF NOT EXISTS logical_decoding.change_events (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL DEFAULT gen_random_uuid(),
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Source
    slot_name VARCHAR(128) NOT NULL,
    lsn pg_lsn NOT NULL,
    xid BIGINT,
    
    -- Change details
    schema_name VARCHAR(63) NOT NULL,
    table_name VARCHAR(63) NOT NULL,
    operation VARCHAR(10) NOT NULL, -- INSERT, UPDATE, DELETE, TRUNCATE
    
    -- Data
    old_data JSONB,
    new_data JSONB,
    changed_fields TEXT[],
    
    -- Processing
    processed BOOLEAN DEFAULT FALSE,
    processed_at TIMESTAMPTZ,
    processor_name VARCHAR(100),
    processing_duration_ms INTEGER,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_change_events_slot 
ON logical_decoding.change_events(slot_name, lsn);

CREATE INDEX IF NOT EXISTS idx_change_events_unprocessed 
ON logical_decoding.change_events(processed) 
WHERE processed = FALSE;

CREATE INDEX IF NOT EXISTS idx_change_events_table 
ON logical_decoding.change_events(schema_name, table_name, received_at);

-- =============================================================================
-- CONSUMER REGISTRY
-- =============================================================================
CREATE TABLE IF NOT EXISTS logical_decoding.consumer_registry (
    id SERIAL PRIMARY KEY,
    consumer_name VARCHAR(100) NOT NULL UNIQUE,
    consumer_type VARCHAR(50) NOT NULL, -- KAFKA_CONNECT, DEBEZIUM, CUSTOM_APP
    
    -- Connection
    slot_name VARCHAR(128) REFERENCES logical_decoding.slot_registry(slot_name),
    output_plugin VARCHAR(50) DEFAULT 'pgoutput',
    
    -- Filter settings
    included_schemas TEXT[],
    excluded_schemas TEXT[] DEFAULT ARRAY['pg_catalog', 'information_schema', 'logical_decoding', 'replication'],
    included_tables TEXT[],
    excluded_tables TEXT[],
    included_operations TEXT[] DEFAULT ARRAY['INSERT', 'UPDATE', 'DELETE'],
    
    -- Processing
    batch_size INTEGER DEFAULT 1000,
    poll_interval_ms INTEGER DEFAULT 1000,
    max_retries INTEGER DEFAULT 3,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    last_poll_at TIMESTAMPTZ,
    last_error_at TIMESTAMPTZ,
    last_error_message TEXT,
    total_events_processed BIGINT DEFAULT 0,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================================================
-- DEFAULT SLOTS
-- =============================================================================
INSERT INTO logical_decoding.slot_registry (
    slot_name, plugin, database, purpose, consumer_name, consumer_type, description
) VALUES 
(
    'cdc_kafka_slot',
    'pgoutput',
    'ledger_production',
    'CDC',
    'kafka-connect',
    'KAFKA',
    'Slot for Kafka Connect CDC streaming'
),
(
    'audit_stream_slot',
    'wal2json',
    'ledger_production',
    'AUDIT',
    'audit-processor',
    'APP',
    'Slot for real-time audit log processing'
),
(
    'analytics_etl_slot',
    'pgoutput',
    'ledger_production',
    'ETL',
    'analytics-loader',
    'ANALYTICS',
    'Slot for analytics ETL pipeline'
),
(
    'replica_slot',
    'pgoutput',
    'ledger_production',
    'REPLICATION',
    'logical-replica',
    'REPLICATION',
    'Slot for logical replication to replica'
)
ON CONFLICT (slot_name) DO UPDATE SET
    purpose = EXCLUDED.purpose,
    consumer_name = EXCLUDED.consumer_name;

-- =============================================================================
-- DEFAULT CONSUMERS
-- =============================================================================
INSERT INTO logical_decoding.consumer_registry (
    consumer_name, consumer_type, slot_name, included_schemas, included_tables
) VALUES 
(
    'kafka-connect',
    'KAFKA_CONNECT',
    'cdc_kafka_slot',
    ARRAY['ledger', 'reference'],
    NULL -- All tables in included schemas
),
(
    'audit-processor',
    'CUSTOM_APP',
    'audit_stream_slot',
    ARRAY['audit'],
    NULL
),
(
    'analytics-loader',
    'CUSTOM_APP',
    'analytics_etl_slot',
    ARRAY['ledger'],
    ARRAY['ledger.transactions', 'ledger.ledger_entries', 'ledger.balances']
)
ON CONFLICT (consumer_name) DO UPDATE SET
    slot_name = EXCLUDED.slot_name,
    included_schemas = EXCLUDED.included_schemas;

-- =============================================================================
-- FUNCTION: Create replication slot
-- =============================================================================
CREATE OR REPLACE FUNCTION logical_decoding.create_slot(
    p_slot_name VARCHAR,
    p_plugin VARCHAR DEFAULT 'pgoutput',
    p_temporary BOOLEAN DEFAULT FALSE
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_result RECORD;
BEGIN
    IF p_temporary THEN
        EXECUTE format(
            'SELECT * FROM pg_create_logical_replication_slot(%L, %L, true)',
            p_slot_name, p_plugin
        ) INTO v_result;
    ELSE
        EXECUTE format(
            'SELECT * FROM pg_create_logical_replication_slot(%L, %L, false)',
            p_slot_name, p_plugin
        ) INTO v_result;
    END IF;
    
    RETURN format('SUCCESS: Created slot %s with plugin %s (LSN: %s)',
                  p_slot_name, p_plugin, v_result.lsn);
EXCEPTION WHEN OTHERS THEN
    RETURN format('ERROR: %s', SQLERRM);
END;
$$;

-- =============================================================================
-- FUNCTION: Drop replication slot
-- =============================================================================
CREATE OR REPLACE FUNCTION logical_decoding.drop_slot(
    p_slot_name VARCHAR,
    p_force BOOLEAN DEFAULT FALSE
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    EXECUTE format(
        'SELECT pg_drop_replication_slot(%L)',
        p_slot_name
    );
    
    -- Update registry
    UPDATE logical_decoding.slot_registry
    SET is_active = FALSE
    WHERE slot_name = p_slot_name;
    
    RETURN format('SUCCESS: Dropped slot %s', p_slot_name);
EXCEPTION WHEN OTHERS THEN
    IF p_force THEN
        RETURN format('WARNING: Slot %s may not exist: %s', p_slot_name, SQLERRM);
    END IF;
    RETURN format('ERROR: %s', SQLERRM);
END;
$$;

-- =============================================================================
-- FUNCTION: Get slot status
-- =============================================================================
CREATE OR REPLACE FUNCTION logical_decoding.get_slot_status()
RETURNS TABLE(
    slot_name TEXT,
    plugin TEXT,
    slot_type TEXT,
    database TEXT,
    active BOOLEAN,
    restart_lsn TEXT,
    confirmed_flush_lsn TEXT,
    pg_current_wal_lsn TEXT,
    lag_bytes BIGINT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        s.slot_name::TEXT,
        s.plugin::TEXT,
        s.slot_type::TEXT,
        s.database::TEXT,
        s.active,
        s.restart_lsn::TEXT,
        s.confirmed_flush_lsn::TEXT,
        pg_current_wal_lsn()::TEXT,
        (pg_current_wal_lsn() - s.confirmed_flush_lsn)::BIGINT as lag_bytes
    FROM pg_replication_slots s
    WHERE s.slot_type = 'logical';
END;
$$;

-- =============================================================================
-- FUNCTION: Update slot flush position
-- =============================================================================
CREATE OR REPLACE FUNCTION logical_decoding.confirm_flush(
    p_slot_name VARCHAR,
    p_lsn pg_lsn
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE logical_decoding.slot_registry
    SET last_confirmed_flush_lsn = p_lsn,
        last_confirmed_at = NOW()
    WHERE slot_name = p_slot_name;
    
    RETURN format('SUCCESS: Confirmed flush at %s for slot %s', p_lsn, p_slot_name);
END;
$$;

-- =============================================================================
-- FUNCTION: Decode changes from slot
-- =============================================================================
CREATE OR REPLACE FUNCTION logical_decoding.decode_changes(
    p_slot_name VARCHAR,
    p_start_lsn pg_lsn DEFAULT NULL,
    p_count INTEGER DEFAULT 100
)
RETURNS TABLE(
    lsn pg_lsn,
    xid BIGINT,
    data TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_start_lsn pg_lsn;
BEGIN
    -- Get last confirmed LSN if not provided
    IF p_start_lsn IS NULL THEN
        SELECT last_confirmed_flush_lsn INTO v_start_lsn
        FROM logical_decoding.slot_registry
        WHERE slot_name = p_slot_name;
    ELSE
        v_start_lsn := p_start_lsn;
    END IF;
    
    RETURN QUERY
    SELECT 
        lsn::pg_lsn,
        xid,
        data::TEXT
    FROM pg_logical_slot_get_changes(
        p_slot_name,
        v_start_lsn,
        p_count
    );
END;
$$;

-- =============================================================================
-- FUNCTION: Peek changes without advancing
-- =============================================================================
CREATE OR REPLACE FUNCTION logical_decoding.peek_changes(
    p_slot_name VARCHAR,
    p_count INTEGER DEFAULT 100
)
RETURNS TABLE(
    lsn pg_lsn,
    xid BIGINT,
    data TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_confirmed_lsn pg_lsn;
BEGIN
    SELECT last_confirmed_flush_lsn INTO v_confirmed_lsn
    FROM logical_decoding.slot_registry
    WHERE slot_name = p_slot_name;
    
    RETURN QUERY
    SELECT 
        lsn::pg_lsn,
        xid,
        data::TEXT
    FROM pg_logical_slot_peek_changes(
        p_slot_name,
        v_confirmed_lsn,
        p_count
    );
END;
$$;

-- =============================================================================
-- FUNCTION: Log change event
-- =============================================================================
CREATE OR REPLACE FUNCTION logical_decoding.log_change_event(
    p_slot_name VARCHAR,
    p_lsn pg_lsn,
    p_xid BIGINT,
    p_schema_name VARCHAR,
    p_table_name VARCHAR,
    p_operation VARCHAR,
    p_old_data JSONB DEFAULT NULL,
    p_new_data JSONB DEFAULT NULL
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_event_id BIGINT;
    v_changed_fields TEXT[];
BEGIN
    -- Determine changed fields for UPDATE
    IF p_operation = 'UPDATE' AND p_old_data IS NOT NULL AND p_new_data IS NOT NULL THEN
        SELECT array_agg(key)
        INTO v_changed_fields
        FROM jsonb_each_text(p_new_data)
        WHERE p_old_data->key IS DISTINCT FROM p_new_data->key;
    END IF;
    
    INSERT INTO logical_decoding.change_events (
        slot_name, lsn, xid, schema_name, table_name, operation,
        old_data, new_data, changed_fields
    ) VALUES (
        p_slot_name, p_lsn, p_xid, p_schema_name, p_table_name, p_operation,
        p_old_data, p_new_data, v_changed_fields
    )
    RETURNING id INTO v_event_id;
    
    RETURN v_event_id;
END;
$$;

-- =============================================================================
-- FUNCTION: Mark events as processed
-- =============================================================================
CREATE OR REPLACE FUNCTION logical_decoding.mark_processed(
    p_event_ids BIGINT[],
    p_processor_name VARCHAR,
    p_duration_ms INTEGER DEFAULT NULL
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER;
BEGIN
    UPDATE logical_decoding.change_events
    SET processed = TRUE,
        processed_at = NOW(),
        processor_name = p_processor_name,
        processing_duration_ms = p_duration_ms
    WHERE id = ANY(p_event_ids);
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    
    -- Update consumer stats
    UPDATE logical_decoding.consumer_registry
    SET total_events_processed = total_events_processed + v_count,
        last_poll_at = NOW()
    WHERE consumer_name = p_processor_name;
    
    RETURN v_count;
END;
$$;

-- =============================================================================
-- FUNCTION: Get unprocessed events
-- =============================================================================
CREATE OR REPLACE FUNCTION logical_decoding.get_unprocessed_events(
    p_slot_name VARCHAR DEFAULT NULL,
    p_limit INTEGER DEFAULT 1000
)
RETURNS TABLE(
    id BIGINT,
    event_id UUID,
    slot_name VARCHAR,
    lsn pg_lsn,
    schema_name VARCHAR,
    table_name VARCHAR,
    operation VARCHAR,
    new_data JSONB,
    retry_count INTEGER
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ce.id,
        ce.event_id,
        ce.slot_name::VARCHAR(128),
        ce.lsn,
        ce.schema_name::VARCHAR(63),
        ce.table_name::VARCHAR(63),
        ce.operation::VARCHAR(10),
        ce.new_data,
        ce.retry_count
    FROM logical_decoding.change_events ce
    WHERE ce.processed = FALSE
      AND (p_slot_name IS NULL OR ce.slot_name = p_slot_name)
    ORDER BY ce.lsn, ce.id
    LIMIT p_limit;
END;
$$;

-- =============================================================================
-- FUNCTION: Clean old processed events
-- =============================================================================
CREATE OR REPLACE FUNCTION logical_decoding.cleanup_old_events(
    p_older_than_days INTEGER DEFAULT 7
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER;
BEGIN
    DELETE FROM logical_decoding.change_events
    WHERE processed = TRUE
      AND processed_at < NOW() - (p_older_than_days || ' days')::INTERVAL;
    
    GET DIAGNOSTICS v_count = ROW_COUNT;
    
    RETURN v_count;
END;
$$;

-- =============================================================================
-- VIEW: Slot health overview
-- =============================================================================
CREATE OR REPLACE VIEW logical_decoding.slot_health AS
SELECT 
    sr.slot_name,
    sr.plugin,
    sr.purpose,
    sr.consumer_name,
    sr.is_active as config_active,
    s.active as slot_active,
    sr.current_lag_bytes,
    sr.lag_threshold_bytes,
    CASE 
        WHEN sr.current_lag_bytes > sr.lag_threshold_bytes THEN 'LAGGING'
        WHEN NOT s.active THEN 'INACTIVE'
        ELSE 'HEALTHY'
    END as health_status,
    s.restart_lsn::TEXT as restart_lsn,
    s.confirmed_flush_lsn::TEXT as confirmed_flush_lsn,
    sr.last_confirmed_at,
    pg_size_pretty(sr.current_lag_bytes) as lag_pretty,
    (pg_current_wal_lsn() - s.confirmed_flush_lsn)::BIGINT as actual_lag_bytes
FROM logical_decoding.slot_registry sr
LEFT JOIN pg_replication_slots s ON s.slot_name = sr.slot_name
WHERE sr.is_active = TRUE;

-- =============================================================================
-- VIEW: Consumer statistics
-- =============================================================================
CREATE OR REPLACE VIEW logical_decoding.consumer_stats AS
SELECT 
    cr.consumer_name,
    cr.consumer_type,
    cr.slot_name,
    cr.is_active,
    cr.batch_size,
    cr.total_events_processed,
    cr.last_poll_at,
    cr.last_error_at,
    COUNT(ce.id) FILTER (WHERE ce.processed = FALSE) as pending_events,
    MAX(ce.received_at) FILTER (WHERE ce.processed = FALSE) as oldest_pending_event,
    array_to_string(cr.included_schemas, ', ') as schemas
FROM logical_decoding.consumer_registry cr
LEFT JOIN logical_decoding.change_events ce ON ce.slot_name = cr.slot_name
GROUP BY cr.id, cr.consumer_name, cr.consumer_type, cr.slot_name, 
         cr.is_active, cr.batch_size, cr.total_events_processed,
         cr.last_poll_at, cr.last_error_at;

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA logical_decoding TO replication_admin, cdc_consumer;
GRANT SELECT ON ALL TABLES IN SCHEMA logical_decoding TO replication_admin, cdc_consumer;
GRANT INSERT, UPDATE ON logical_decoding.change_events TO cdc_consumer;
GRANT INSERT, UPDATE ON logical_decoding.slot_registry TO replication_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA logical_decoding TO replication_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA logical_decoding TO replication_admin;
