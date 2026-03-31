-- =============================================================================
-- DATA LIFECYCLE MANAGEMENT
-- Comprehensive data lifecycle policies and automation
-- =============================================================================

-- =============================================================================
-- LIFECYCLE SCHEMA
-- =============================================================================
CREATE SCHEMA IF NOT EXISTS data_lifecycle;

COMMENT ON SCHEMA data_lifecycle IS 'Schema for data lifecycle management policies';

-- =============================================================================
-- LIFECYCLE POLICY DEFINITIONS
-- =============================================================================
CREATE TABLE IF NOT EXISTS data_lifecycle.policies (
    id SERIAL PRIMARY KEY,
    policy_name VARCHAR(100) NOT NULL UNIQUE,
    schema_name VARCHAR(63) NOT NULL,
    table_name VARCHAR(63) NOT NULL,
    
    -- Lifecycle stages
    hot_retention_days INTEGER NOT NULL DEFAULT 7,      -- Recent data, fast access
    warm_retention_days INTEGER NOT NULL DEFAULT 30,    -- Compressed, slower access
    cold_retention_days INTEGER NOT NULL DEFAULT 90,    -- Archived, restore required
    frozen_retention_years INTEGER NOT NULL DEFAULT 7,  -- Long-term compliance
    
    -- Actions
    compress_after_days INTEGER DEFAULT 7,
    archive_after_days INTEGER DEFAULT 30,
    delete_after_days INTEGER, -- NULL = never delete (compliance)
    
    -- Policy settings
    require_encryption BOOLEAN DEFAULT TRUE,
    require_integrity_check BOOLEAN DEFAULT TRUE,
    legal_hold_enabled BOOLEAN DEFAULT FALSE,
    compliance_framework VARCHAR(50), -- SOX, GDPR, PCI-DSS, etc.
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by VARCHAR(100) DEFAULT current_user,
    
    UNIQUE(schema_name, table_name)
);

COMMENT ON TABLE data_lifecycle.policies IS 'Data lifecycle policies per table';

-- =============================================================================
-- LIFECYCLE STATE TRACKING
-- =============================================================================
CREATE TABLE IF NOT EXISTS data_lifecycle.object_states (
    id BIGSERIAL PRIMARY KEY,
    policy_id INTEGER NOT NULL REFERENCES data_lifecycle.policies(id),
    object_type VARCHAR(50) NOT NULL, -- TABLE, PARTITION, ROW
    schema_name VARCHAR(63) NOT NULL,
    object_name VARCHAR(128) NOT NULL,
    range_from TIMESTAMPTZ,
    range_to TIMESTAMPTZ,
    
    -- Current state
    current_state VARCHAR(20) NOT NULL DEFAULT 'HOT', -- HOT, WARM, COLD, FROZEN, DELETED
    previous_state VARCHAR(20),
    state_changed_at TIMESTAMPTZ DEFAULT NOW(),
    
    -- Metadata
    row_count BIGINT,
    size_bytes BIGINT,
    compressed_size_bytes BIGINT,
    compression_ratio NUMERIC(5,2),
    checksum VARCHAR(64),
    encryption_key_id VARCHAR(100),
    
    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lifecycle_state_policy 
ON data_lifecycle.object_states(policy_id, current_state);

CREATE INDEX IF NOT EXISTS idx_lifecycle_state_object 
ON data_lifecycle.object_states(schema_name, object_name);

CREATE INDEX IF NOT EXISTS idx_lifecycle_state_transition 
ON data_lifecycle.object_states(current_state, state_changed_at);

-- =============================================================================
-- LIFECYCLE TRANSITION LOG
-- =============================================================================
CREATE TABLE IF NOT EXISTS data_lifecycle.transition_log (
    id BIGSERIAL PRIMARY KEY,
    object_state_id BIGINT NOT NULL REFERENCES data_lifecycle.object_states(id),
    transition_type VARCHAR(50) NOT NULL, -- COMPRESS, ARCHIVE, RESTORE, DELETE, etc.
    from_state VARCHAR(20),
    to_state VARCHAR(20),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER,
    rows_affected BIGINT,
    size_bytes_affected BIGINT,
    status VARCHAR(20) DEFAULT 'RUNNING', -- RUNNING, SUCCESS, FAILED, ROLLED_BACK
    error_message TEXT,
    initiated_by VARCHAR(100) DEFAULT current_user,
    metadata JSONB
);

-- =============================================================================
-- DEFAULT POLICIES
-- =============================================================================
INSERT INTO data_lifecycle.policies (
    policy_name, schema_name, table_name,
    hot_retention_days, warm_retention_days, cold_retention_days, frozen_retention_years,
    compress_after_days, archive_after_days, delete_after_days,
    require_encryption, require_integrity_check, compliance_framework
) VALUES
    ('ledger_transactions', 'ledger', 'transactions',
     7, 30, 90, 7, 7, 30, NULL, TRUE, TRUE, 'SOX'),
    ('ledger_entries', 'ledger', 'ledger_entries',
     7, 30, 90, 7, 7, 30, NULL, TRUE, TRUE, 'SOX'),
    ('audit_general', 'audit', 'ledger_audit_log',
     7, 90, 365, 7, 30, 90, NULL, TRUE, TRUE, 'SOX'),
    ('audit_transaction', 'audit', 'transaction_audit_log',
     7, 90, 365, 7, 30, 90, NULL, TRUE, TRUE, 'PCI-DSS'),
    ('access_logs', 'audit', 'access_audit_log',
     7, 30, 90, 2, 7, 30, 365, TRUE, FALSE, NULL)
ON CONFLICT (schema_name, table_name) DO UPDATE SET
    policy_name = EXCLUDED.policy_name,
    hot_retention_days = EXCLUDED.hot_retention_days,
    archive_after_days = EXCLUDED.archive_after_days;

-- =============================================================================
-- FUNCTION: Initialize lifecycle tracking for existing partitions
-- =============================================================================
CREATE OR REPLACE FUNCTION data_lifecycle.init_tracking()
RETURNS TABLE(policy_name TEXT, objects_tracked INTEGER)
LANGUAGE plpgsql
AS $$
DECLARE
    v_policy RECORD;
    v_count INTEGER;
BEGIN
    FOR v_policy IN SELECT * FROM data_lifecycle.policies WHERE is_active = TRUE LOOP
        policy_name := v_policy.policy_name;
        
        -- Track existing partitions
        INSERT INTO data_lifecycle.object_states (
            policy_id, object_type, schema_name, object_name,
            range_from, range_to, current_state
        )
        SELECT 
            v_policy.id,
            'PARTITION',
            pm.partition_schema,
            pm.partition_name,
            pm.range_from,
            pm.range_to,
            CASE 
                WHEN pm.range_to > NOW() THEN 'HOT'
                WHEN pm.range_to > NOW() - (v_policy.warm_retention_days || ' days')::INTERVAL THEN 'WARM'
                WHEN pm.range_to > NOW() - (v_policy.cold_retention_days || ' days')::INTERVAL THEN 'COLD'
                ELSE 'FROZEN'
            END
        FROM partition_mgmt.partition_metadata pm
        WHERE pm.parent_schema = v_policy.schema_name
          AND pm.parent_table = v_policy.table_name
        ON CONFLICT DO NOTHING;
        
        GET DIAGNOSTICS v_count = ROW_COUNT;
        objects_tracked := v_count;
        
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Evaluate and transition objects based on policy
-- =============================================================================
CREATE OR REPLACE FUNCTION data_lifecycle.evaluate_transitions()
RETURNS TABLE(object_name TEXT, current_state TEXT, recommended_action TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_policy RECORD;
    v_object RECORD;
    v_age_days INTEGER;
    v_recommended TEXT;
BEGIN
    FOR v_policy IN SELECT * FROM data_lifecycle.policies WHERE is_active = TRUE LOOP
        FOR v_object IN 
            SELECT * FROM data_lifecycle.object_states 
            WHERE policy_id = v_policy.id
              AND current_state != 'DELETED'
        LOOP
            object_name := v_object.schema_name || '.' || v_object.object_name;
            current_state := v_object.current_state;
            v_age_days := EXTRACT(DAY FROM NOW() - v_object.range_to)::INTEGER;
            
            -- Determine recommended action
            IF v_object.current_state = 'HOT' AND v_age_days >= v_policy.compress_after_days THEN
                v_recommended := 'TRANSITION_TO_WARM';
            ELSIF v_object.current_state = 'WARM' AND v_age_days >= v_policy.archive_after_days THEN
                v_recommended := 'TRANSITION_TO_COLD';
            ELSIF v_object.current_state = 'COLD' AND v_age_days >= (v_policy.frozen_retention_years * 365) THEN
                IF v_policy.delete_after_days IS NULL THEN
                    v_recommended := 'TRANSITION_TO_FROZEN';
                ELSE
                    v_recommended := 'DELETE';
                END IF;
            ELSIF v_object.current_state = 'FROZEN' AND v_policy.delete_after_days IS NOT NULL 
                  AND v_age_days >= v_policy.delete_after_days THEN
                v_recommended := 'DELETE';
            ELSE
                v_recommended := 'NO_ACTION';
            END IF;
            
            recommended_action := v_recommended;
            RETURN NEXT;
        END LOOP;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Transition object to WARM state (compression)
-- =============================================================================
CREATE OR REPLACE FUNCTION data_lifecycle.transition_to_warm(
    p_object_state_id BIGINT
)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    v_object data_lifecycle.object_states%ROWTYPE;
    v_start_time TIMESTAMPTZ;
    v_log_id BIGINT;
    v_original_size BIGINT;
    v_compressed_size BIGINT;
BEGIN
    SELECT * INTO v_object FROM data_lifecycle.object_states WHERE id = p_object_state_id;
    
    IF NOT FOUND THEN
        RETURN 'ERROR: Object state not found';
    END IF;
    
    IF v_object.current_state != 'HOT' THEN
        RETURN format('ERROR: Cannot transition from %s to WARM', v_object.current_state);
    END IF;
    
    v_start_time := clock_timestamp();
    
    -- Log transition
    INSERT INTO data_lifecycle.transition_log (
        object_state_id, transition_type, from_state, to_state
    ) VALUES (
        p_object_state_id, 'COMPRESS', v_object.current_state, 'WARM'
    ) RETURNING id INTO v_log_id;
    
    BEGIN
        -- Get original size
        EXECUTE format('
            SELECT pg_total_relation_size(%L)
        ', v_object.schema_name || '.' || v_object.object_name) INTO v_original_size;
        
        -- In PostgreSQL 14+, use built-in compression
        -- For older versions, this would involve table rewrites
        EXECUTE format('
            ALTER TABLE %I.%I SET (compression = ''zstd'')
        ', v_object.schema_name, v_object.object_name);
        
        -- Get new size
        EXECUTE format('
            SELECT pg_total_relation_size(%L)
        ', v_object.schema_name || '.' || v_object.object_name) INTO v_compressed_size;
        
        -- Update object state
        UPDATE data_lifecycle.object_states
        SET current_state = 'WARM',
            previous_state = v_object.current_state,
            state_changed_at = NOW(),
            size_bytes = v_original_size,
            compressed_size_bytes = v_compressed_size,
            compression_ratio = CASE WHEN v_original_size > 0 
                THEN ROUND(((v_original_size - v_compressed_size)::NUMERIC / v_original_size) * 100, 2)
                ELSE 0 
            END
        WHERE id = p_object_state_id;
        
        -- Update log
        UPDATE data_lifecycle.transition_log
        SET completed_at = NOW(),
            status = 'SUCCESS',
            duration_ms = EXTRACT(MILLISECOND FROM clock_timestamp() - v_start_time)::INTEGER,
            rows_affected = v_object.row_count,
            size_bytes_affected = v_original_size
        WHERE id = v_log_id;
        
        RETURN format('SUCCESS: Transitioned %s to WARM (compression ratio: %s%%)',
            v_object.object_name,
            ROUND(((v_original_size - v_compressed_size)::NUMERIC / v_original_size) * 100, 2));
            
    EXCEPTION WHEN OTHERS THEN
        UPDATE data_lifecycle.transition_log
        SET completed_at = NOW(),
            status = 'FAILED',
            error_message = SQLERRM
        WHERE id = v_log_id;
        
        RETURN 'ERROR: ' || SQLERRM;
    END;
END;
$$;

-- =============================================================================
-- FUNCTION: Execute all pending transitions
-- =============================================================================
CREATE OR REPLACE FUNCTION data_lifecycle.execute_pending_transitions()
RETURNS TABLE(object_name TEXT, action TEXT, result TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_transition RECORD;
BEGIN
    FOR v_transition IN 
        SELECT * FROM data_lifecycle.evaluate_transitions()
        WHERE recommended_action != 'NO_ACTION'
    LOOP
        object_name := v_transition.object_name;
        action := v_transition.recommended_action;
        
        CASE v_transition.recommended_action
            WHEN 'TRANSITION_TO_WARM' THEN
                result := 'Scheduled for compression';
            WHEN 'TRANSITION_TO_COLD' THEN
                result := 'Scheduled for archival';
            WHEN 'TRANSITION_TO_FROZEN' THEN
                result := 'Scheduled for deep freeze';
            WHEN 'DELETE' THEN
                result := 'Scheduled for deletion';
            ELSE
                result := 'Unknown action';
        END CASE;
        
        RETURN NEXT;
    END LOOP;
    
    RETURN;
END;
$$;

-- =============================================================================
-- FUNCTION: Calculate storage statistics
-- =============================================================================
CREATE OR REPLACE FUNCTION data_lifecycle.calculate_storage_stats()
RETURNS TABLE(
    state VARCHAR(20),
    object_count BIGINT,
    total_size_bytes BIGINT,
    total_compressed_size BIGINT,
    avg_compression_ratio NUMERIC
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        os.current_state::VARCHAR(20),
        COUNT(*)::BIGINT as object_count,
        COALESCE(SUM(os.size_bytes), 0)::BIGINT as total_size_bytes,
        COALESCE(SUM(os.compressed_size_bytes), 0)::BIGINT as total_compressed_size,
        ROUND(AVG(os.compression_ratio), 2)::NUMERIC as avg_compression_ratio
    FROM data_lifecycle.object_states os
    WHERE os.current_state != 'DELETED'
    GROUP BY os.current_state
    ORDER BY 
        CASE os.current_state
            WHEN 'HOT' THEN 1
            WHEN 'WARM' THEN 2
            WHEN 'COLD' THEN 3
            WHEN 'FROZEN' THEN 4
            ELSE 5
        END;
END;
$$;

-- =============================================================================
-- VIEW: Lifecycle compliance report
-- =============================================================================
CREATE OR REPLACE VIEW data_lifecycle.compliance_report AS
SELECT 
    p.policy_name,
    p.schema_name || '.' || p.table_name as table_full_name,
    p.compliance_framework,
    p.hot_retention_days,
    p.warm_retention_days,
    p.cold_retention_days,
    p.frozen_retention_years,
    p.delete_after_days,
    COUNT(os.id) FILTER (WHERE os.current_state = 'HOT') as hot_partitions,
    COUNT(os.id) FILTER (WHERE os.current_state = 'WARM') as warm_partitions,
    COUNT(os.id) FILTER (WHERE os.current_state = 'COLD') as cold_partitions,
    COUNT(os.id) FILTER (WHERE os.current_state = 'FROZEN') as frozen_partitions,
    pg_size_pretty(SUM(os.size_bytes)) as total_size,
    p.legal_hold_enabled,
    CASE 
        WHEN p.legal_hold_enabled THEN 'LEGAL_HOLD_ACTIVE'
        ELSE 'NORMAL'
    END as compliance_status
FROM data_lifecycle.policies p
LEFT JOIN data_lifecycle.object_states os ON os.policy_id = p.id
WHERE p.is_active = TRUE
GROUP BY p.id, p.policy_name, p.schema_name, p.table_name, p.compliance_framework;

-- =============================================================================
-- TRIGGER: Update timestamps
-- =============================================================================
CREATE OR REPLACE FUNCTION data_lifecycle.update_timestamps()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_policies_updated
    BEFORE UPDATE ON data_lifecycle.policies
    FOR EACH ROW EXECUTE FUNCTION data_lifecycle.update_timestamps();

CREATE TRIGGER trigger_object_states_updated
    BEFORE UPDATE ON data_lifecycle.object_states
    FOR EACH ROW EXECUTE FUNCTION data_lifecycle.update_timestamps();

-- =============================================================================
-- GRANTS
-- =============================================================================
GRANT USAGE ON SCHEMA data_lifecycle TO lifecycle_admin;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA data_lifecycle TO lifecycle_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA data_lifecycle TO lifecycle_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA data_lifecycle TO lifecycle_admin;
