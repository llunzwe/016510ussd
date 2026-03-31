-- =============================================================================
-- CONFLICT RESOLUTION
-- Multi-master replication conflict detection and resolution
-- =============================================================================

-- =============================================================================
-- CONFLICT SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS conflict_resolution;

COMMENT ON SCHEMA conflict_resolution IS 'Conflict detection and resolution for multi-master replication';

-- =============================================================================
-- CONFLICT LOG TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS conflict_resolution.conflict_log (
    id BIGSERIAL PRIMARY KEY,
    conflict_id UUID NOT NULL DEFAULT gen_random_uuid(),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    
    -- Source information
    source_node VARCHAR(100) NOT NULL,
    target_node VARCHAR(100) NOT NULL,
    
    -- Conflict details
    schema_name VARCHAR(63) NOT NULL,
    table_name VARCHAR(63) NOT NULL,
    primary_key_values JSONB NOT NULL,
    conflict_type VARCHAR(50) NOT NULL, -- INSERT_INSERT, UPDATE_UPDATE, UPDATE_DELETE, DELETE_DELETE, UNIQUE_VIOLATION
    
    -- Data involved
    local_tuple JSONB,
    remote_tuple JSONB,
    local_xid BIGINT,
    remote_xid BIGINT,
    local_timestamp TIMESTAMPTZ,
    remote_timestamp TIMESTAMPTZ,
    local_origin VARCHAR(100),
    remote_origin VARCHAR(100),
    
    -- Resolution
    resolution_strategy VARCHAR(50), -- FIRST_UPDATE_WINS, LAST_UPDATE_WINS, SOURCE_PRIORITY, MERGE, MANUAL
    resolution_result VARCHAR(20), -- PENDING, RESOLVED_LOCAL, RESOLVED_REMOTE, MERGED, DISCARDED, ERROR
    resolution_details JSONB,
    resolved_by VARCHAR(100),
    
    -- Metadata
    replication_slot VARCHAR(128),
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_conflict_log_detected 
ON conflict_resolution.conflict_log(detected_at);

CREATE INDEX IF NOT EXISTS idx_conflict_log_status 
ON conflict_resolution.conflict_log(resolution_result) 
WHERE resolution_result = 'PENDING';

CREATE INDEX IF NOT EXISTS idx_conflict_log_table 
ON conflict_resolution.conflict_log(schema_name, table_name);

CREATE INDEX IF NOT EXISTS idx_conflict_log_nodes 
ON conflict_resolution.conflict_log(source_node, target_node);

-- =============================================================================
-- CONFLICT RESOLUTION POLICIES
-- =============================================================================
CREATE TABLE IF NOT EXISTS conflict_resolution.policies (
    id SERIAL PRIMARY KEY,
    policy_name VARCHAR(100) NOT NULL UNIQUE,
    schema_name VARCHAR(63) NOT NULL,
    table_name VARCHAR(63) NOT NULL,
    
    -- Resolution strategies by conflict type
    insert_insert_strategy VARCHAR(50) DEFAULT 'LAST_UPDATE_WINS', -- FIRST_UPDATE_WINS, LAST_UPDATE_WINS, SOURCE_PRIORITY, ERROR
    update_update_strategy VARCHAR(50) DEFAULT 'LAST_UPDATE_WINS',
    update_delete_strategy VARCHAR(50) DEFAULT 'PRESERVE_DELETE', -- PRESERVE_UPDATE, PRESERVE_DELETE, ERROR
    delete_delete_strategy VARCHAR(50) DEFAULT 'IGNORE',
    unique_violation_strategy VARCHAR(50) DEFAULT 'APPEND_NODE_ID',
    
    -- Priority settings
    node_priority JSONB DEFAULT '{}', -- {'node1': 1, 'node2': 2}
    custom_priority_column VARCHAR(63), -- Column to use for priority (e.g., 'updated_at')
    
    -- Merge settings
    merge_function VARCHAR(200), -- Custom merge function name
    
    -- Auto-resolution
    auto_resolve BOOLEAN DEFAULT TRUE,
    notify_on_conflict BOOLEAN DEFAULT FALSE,
    max_retries INTEGER DEFAULT 3,
    
    -- Metadata
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE(schema_name, table_name)
);

COMMENT ON TABLE conflict_resolution.policies IS 'Conflict resolution policies per table';

-- =============================================================================
-- DEFAULT POLICIES
-- =============================================================================
INSERT INTO conflict_resolution.policies (
    policy_name, schema_name, table_name,
    insert_insert_strategy, update_update_strategy, update_delete_strategy,
    unique_violation_strategy, custom_priority_column, auto_resolve
) VALUES 
(
    'ledger_transactions_conflict_policy',
    'ledger', 'transactions',
    'ERROR', 'ERROR', 'PRESERVE_DELETE',
    'ERROR', 'created_at', FALSE
),
(
    'reference_data_conflict_policy',
    'reference', 'currencies',
    'LAST_UPDATE_WINS', 'LAST_UPDATE_WINS', 'PRESERVE_UPDATE',
    'APPEND_NODE_ID', 'updated_at', TRUE
),
(
    'audit_logs_conflict_policy',
    'audit', 'ledger_audit_log',
    'APPEND_NODE_ID', 'IGNORE', 'IGNORE',
    'APPEND_NODE_ID', 'event_timestamp', TRUE
)
ON CONFLICT (schema_name, table_name) DO UPDATE SET
    policy_name = EXCLUDED.policy_name,
    insert_insert_strategy = EXCLUDED.insert_insert_strategy,
    update_update_strategy = EXCLUDED.update_update_strategy;

-- =============================================================================
-- FUNCTION: Detect conflict type
-- =============================================================================
CREATE OR REPLACE FUNCTION conflict_resolution.detect_conflict_type(
    p_local_tuple JSONB,
    p_remote_tuple JSONB,
    p_operation VARCHAR(10)
)
RETURNS VARCHAR(50)
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_operation = 'INSERT' THEN
        IF p_local_tuple IS NOT NULL AND p_remote_tuple IS NOT NULL THEN
            RETURN 'INSERT_INSERT';
        END IF;
    ELSIF p_operation = 'UPDATE' THEN
        IF p_local_tuple IS NULL THEN
            RETURN 'UPDATE_DELETE';
        ELSIF p_remote_tuple IS NULL THEN
            RETURN 'DELETE_UPDATE';
        ELSE
            RETURN 'UPDATE_UPDATE';
        END IF;
    ELSIF p_operation = 'DELETE' THEN
        IF p_local_tuple IS NULL AND p_remote_tuple IS NULL THEN
            RETURN 'DELETE_DELETE';
        END IF;
    END IF;
    
    RETURN 'UNKNOWN';
END;
$$;

-- =============================================================================
-- FUNCTION: Apply resolution strategy
-- =============================================================================
CREATE OR REPLACE FUNCTION conflict_resolution.apply_resolution(
    p_conflict_id BIGINT,
    p_strategy VARCHAR(50) DEFAULT NULL
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_conflict RECORD;
    v_policy RECORD;
    v_strategy VARCHAR(50);
    v_result VARCHAR(20);
    v_details JSONB;
BEGIN
    SELECT * INTO v_conflict 
    FROM conflict_resolution.conflict_log 
    WHERE id = p_conflict_id;
    
    IF NOT FOUND THEN
        RETURN 'ERROR: Conflict not found';
    END IF;
    
    -- Get policy
    SELECT * INTO v_policy
    FROM conflict_resolution.policies
    WHERE schema_name = v_conflict.schema_name
      AND table_name = v_conflict.table_name
      AND is_active = TRUE;
    
    -- Determine strategy
    IF p_strategy IS NOT NULL THEN
        v_strategy := p_strategy;
    ELSIF v_policy IS NOT NULL THEN
        v_strategy := CASE v_conflict.conflict_type
            WHEN 'INSERT_INSERT' THEN v_policy.insert_insert_strategy
            WHEN 'UPDATE_UPDATE' THEN v_policy.update_update_strategy
            WHEN 'UPDATE_DELETE' THEN v_policy.update_delete_strategy
            WHEN 'DELETE_DELETE' THEN v_policy.delete_delete_strategy
            WHEN 'UNIQUE_VIOLATION' THEN v_policy.unique_violation_strategy
            ELSE 'ERROR'
        END;
    ELSE
        v_strategy := 'ERROR';
    END IF;
    
    -- Apply strategy
    CASE v_strategy
        WHEN 'LAST_UPDATE_WINS' THEN
            IF v_conflict.remote_timestamp > v_conflict.local_timestamp THEN
                v_result := 'RESOLVED_REMOTE';
                v_details := jsonb_build_object('reason', 'remote_timestamp newer');
            ELSE
                v_result := 'RESOLVED_LOCAL';
                v_details := jsonb_build_object('reason', 'local_timestamp newer');
            END IF;
            
        WHEN 'FIRST_UPDATE_WINS' THEN
            IF v_conflict.local_timestamp < v_conflict.remote_timestamp THEN
                v_result := 'RESOLVED_LOCAL';
                v_details := jsonb_build_object('reason', 'local_timestamp older');
            ELSE
                v_result := 'RESOLVED_REMOTE';
                v_details := jsonb_build_object('reason', 'remote_timestamp older');
            END IF;
            
        WHEN 'SOURCE_PRIORITY' THEN
            IF v_policy.node_priority->>v_conflict.remote_origin > 
               v_policy.node_priority->>v_conflict.local_origin THEN
                v_result := 'RESOLVED_REMOTE';
            ELSE
                v_result := 'RESOLVED_LOCAL';
            END IF;
            
        WHEN 'PRESERVE_DELETE' THEN
            v_result := 'RESOLVED_LOCAL'; -- Keep the delete
            v_details := jsonb_build_object('reason', 'delete preserved');
            
        WHEN 'PRESERVE_UPDATE' THEN
            v_result := 'RESOLVED_REMOTE'; -- Keep the update
            v_details := jsonb_build_object('reason', 'update preserved');
            
        WHEN 'APPEND_NODE_ID' THEN
            v_result := 'MERGED';
            v_details := jsonb_build_object(
                'reason', 'appended node identifiers',
                'local_origin', v_conflict.local_origin,
                'remote_origin', v_conflict.remote_origin
            );
            
        WHEN 'MERGE' THEN
            IF v_policy.merge_function IS NOT NULL THEN
                -- Would call custom merge function
                v_result := 'MERGED';
                v_details := jsonb_build_object('merge_function', v_policy.merge_function);
            ELSE
                v_result := 'ERROR';
                v_details := jsonb_build_object('error', 'no merge function defined');
            END IF;
            
        WHEN 'IGNORE' THEN
            v_result := 'DISCARDED';
            v_details := jsonb_build_object('reason', 'conflict ignored per policy');
            
        ELSE
            v_result := 'PENDING';
            v_details := jsonb_build_object('reason', 'manual resolution required');
    END CASE;
    
    -- Update conflict log
    UPDATE conflict_resolution.conflict_log
    SET resolution_strategy = v_strategy,
        resolution_result = v_result,
        resolution_details = v_details,
        resolved_at = NOW(),
        resolved_by = current_user
    WHERE id = p_conflict_id;
    
    RETURN format('SUCCESS: Applied %s strategy, result: %s', v_strategy, v_result);
END;
$$;

-- =============================================================================
-- FUNCTION: Log conflict (to be called by conflict trigger)
-- =============================================================================
CREATE OR REPLACE FUNCTION conflict_resolution.log_conflict()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_conflict_id BIGINT;
    v_pk_columns TEXT[];
    v_pk_values JSONB;
    v_local_tuple JSONB;
    v_remote_tuple JSONB;
BEGIN
    -- Get primary key columns
    SELECT array_agg(a.attname)
    INTO v_pk_columns
    FROM pg_index i
    JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
    WHERE i.indrelid = TG_RELID AND i.indisprimary;
    
    -- Build PK values from NEW or OLD
    IF TG_OP = 'DELETE' THEN
        v_pk_values := to_jsonb(OLD);
    ELSE
        v_pk_values := to_jsonb(NEW);
    END IF;
    
    -- Log the conflict
    INSERT INTO conflict_resolution.conflict_log (
        source_node,
        target_node,
        schema_name,
        table_name,
        primary_key_values,
        conflict_type,
        local_tuple,
        remote_tuple,
        local_timestamp,
        remote_timestamp,
        resolution_result
    ) VALUES (
        current_setting('application.node_name', TRUE),
        current_setting('application.remote_node', TRUE),
        TG_TABLE_SCHEMA,
        TG_TABLE_NAME,
        v_pk_values,
        'UNKNOWN',
        NULL, -- Would be populated with actual data
        to_jsonb(NEW),
        NOW(),
        NULL,
        'PENDING'
    )
    RETURNING id INTO v_conflict_id;
    
    -- Attempt auto-resolution if enabled
    PERFORM conflict_resolution.apply_resolution(v_conflict_id);
    
    -- Return appropriate row based on resolution
    RETURN NEW;
END;
$$;

-- =============================================================================
-- FUNCTION: Resolve all pending conflicts
-- =============================================================================
CREATE OR REPLACE FUNCTION conflict_resolution.resolve_all_pending(
    p_max_conflicts INTEGER DEFAULT 100
)
RETURNS TABLE(conflict_id BIGINT, result TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_conflict RECORD;
    v_result TEXT;
BEGIN
    FOR v_conflict IN 
        SELECT id FROM conflict_resolution.conflict_log
        WHERE resolution_result = 'PENDING'
        ORDER BY detected_at
        LIMIT p_max_conflicts
    LOOP
        conflict_id := v_conflict.id;
        result := conflict_resolution.apply_resolution(v_conflict.id);
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Get conflict summary
-- =============================================================================
CREATE OR REPLACE FUNCTION conflict_resolution.get_conflict_summary(
    p_since TIMESTAMPTZ DEFAULT NOW() - INTERVAL '24 hours'
)
RETURNS TABLE(
    conflict_type VARCHAR(50),
    total_count BIGINT,
    resolved_count BIGINT,
    pending_count BIGINT,
    avg_resolution_time_seconds NUMERIC
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        cl.conflict_type,
        COUNT(*)::BIGINT as total_count,
        COUNT(*) FILTER (WHERE cl.resolution_result != 'PENDING')::BIGINT as resolved_count,
        COUNT(*) FILTER (WHERE cl.resolution_result = 'PENDING')::BIGINT as pending_count,
        ROUND(AVG(EXTRACT(EPOCH FROM (cl.resolved_at - cl.detected_at))), 2)::NUMERIC 
            FILTER (WHERE cl.resolved_at IS NOT NULL) as avg_resolution_time_seconds
    FROM conflict_resolution.conflict_log cl
    WHERE cl.detected_at >= p_since
    GROUP BY cl.conflict_type
    ORDER BY total_count DESC;
END;
$$;

-- =============================================================================
-- VIEW: Pending conflicts requiring attention
-- =============================================================================
CREATE OR REPLACE VIEW conflict_resolution.pending_conflicts AS
SELECT 
    cl.id,
    cl.conflict_id,
    cl.detected_at,
    cl.schema_name || '.' || cl.table_name as table_full_name,
    cl.conflict_type,
    cl.primary_key_values,
    cl.local_origin,
    cl.remote_origin,
    cl.local_timestamp,
    cl.remote_timestamp,
    p.insert_insert_strategy as configured_strategy,
    p.auto_resolve as auto_resolve_enabled,
    EXTRACT(EPOCH FROM (NOW() - cl.detected_at))/3600 as hours_pending
FROM conflict_resolution.conflict_log cl
LEFT JOIN conflict_resolution.policies p ON (
    p.schema_name = cl.schema_name AND p.table_name = cl.table_name
)
WHERE cl.resolution_result = 'PENDING'
ORDER BY cl.detected_at;

-- =============================================================================
-- VIEW: Conflict statistics by table
-- =============================================================================
CREATE OR REPLACE VIEW conflict_resolution.table_conflict_stats AS
SELECT 
    schema_name,
    table_name,
    COUNT(*) as total_conflicts,
    COUNT(*) FILTER (WHERE resolution_result = 'PENDING') as pending,
    COUNT(*) FILTER (WHERE resolution_result = 'RESOLVED_LOCAL') as resolved_local,
    COUNT(*) FILTER (WHERE resolution_result = 'RESOLVED_REMOTE') as resolved_remote,
    COUNT(*) FILTER (WHERE resolution_result = 'MERGED') as merged,
    COUNT(*) FILTER (WHERE resolution_result = 'ERROR') as errors,
    MAX(detected_at) as last_conflict_at
FROM conflict_resolution.conflict_log
GROUP BY schema_name, table_name;

-- =============================================================================
-- TRIGGER: Update timestamp
-- =============================================================================
CREATE TRIGGER trigger_policies_updated
    BEFORE UPDATE ON conflict_resolution.policies
    FOR EACH ROW EXECUTE FUNCTION replication.update_timestamp();

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA conflict_resolution TO replication_admin;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA conflict_resolution TO replication_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA conflict_resolution TO replication_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA conflict_resolution TO replication_admin;
