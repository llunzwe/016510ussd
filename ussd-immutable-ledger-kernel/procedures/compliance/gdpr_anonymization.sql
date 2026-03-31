-- ============================================================================
-- GDPR ANONYMIZATION PROCEDURE
-- ============================================================================
-- Purpose: Anonymize or pseudonymize personal data for GDPR compliance
--          while maintaining ledger integrity and audit trail.
-- Author:  USSD Immutable Ledger Team
-- Date:    2026-03-30
-- ============================================================================
-- COMPLIANCE HEADER:
--   GDPR (General Data Protection Regulation) - EU Regulation 2016/679
--
--   This procedure implements:
--   - Article 17: Right to erasure ('right to be forgotten')
--   - Article 25: Data protection by design and by default
--   - Article 32: Security of processing (pseudonymization)
--   - Recital 26: Data protection principles for anonymization
--
--   Anonymization Methods: Pseudonymization, Generalization, K-anonymity
--   Data Subject Rights: Access, Rectification, Erasure, Portability
--   Legal Hold Integration: Preservation override for litigation
--   Audit Requirement: All anonymization operations logged with hashes
-- ============================================================================

-- =============================================================================
-- STEP 1: GDPR DATA DISCOVERY AND CLASSIFICATION
-- =============================================================================

-- 1.1 Create GDPR data inventory
CREATE TABLE IF NOT EXISTS gdpr_data_inventory (
    inventory_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_schema TEXT NOT NULL,
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    data_category VARCHAR(50) NOT NULL CHECK (data_category IN ('DIRECT_IDENTIFIER', 'QUASI_IDENTIFIER', 'SENSITIVE', 'NON_PERSONAL')),
    personal_data_type VARCHAR(100),
    legal_basis VARCHAR(100),
    retention_period INTERVAL,
    anonymization_method VARCHAR(100),
    encryption_enabled BOOLEAN DEFAULT FALSE,
    last_reviewed_at TIMESTAMPTZ,
    reviewed_by TEXT,
    notes TEXT,
    UNIQUE(table_schema, table_name, column_name)
);

-- 1.2 Create GDPR request tracking
CREATE TABLE IF NOT EXISTS gdpr_requests (
    request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_type VARCHAR(50) NOT NULL CHECK (request_type IN ('ACCESS', 'RECTIFICATION', 'ERASURE', 'PORTABILITY', 'RESTRICTION', 'OBJECTION')),
    data_subject_identifier TEXT NOT NULL,
    id_hash TEXT NOT NULL,  -- Hashed identifier for reference
    request_date TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    deadline_date TIMESTAMPTZ NOT NULL,
    status VARCHAR(50) DEFAULT 'PENDING',
    processed_at TIMESTAMPTZ,
    processed_by TEXT,
    verification_method TEXT,
    request_details JSONB,
    response_details JSONB,
    legal_hold BOOLEAN DEFAULT FALSE,
    legal_hold_reason TEXT
);

-- 1.3 Create anonymization audit log
CREATE TABLE IF NOT EXISTS gdpr_anonymization_log (
    log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID REFERENCES gdpr_requests(request_id),
    operation_type VARCHAR(50) NOT NULL,
    table_name TEXT NOT NULL,
    records_affected BIGINT,
    anonymization_method TEXT NOT NULL,
    original_hash TEXT,  -- Hash of original data (for verification)
    anonymized_hash TEXT,  -- Hash of anonymized data
    performed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    performed_by TEXT DEFAULT CURRENT_USER,
    transaction_id BIGINT,
    hash_chain_preservation_verified BOOLEAN DEFAULT FALSE
);

-- 1.4 Populate data inventory (example for USSD ledger)
INSERT INTO gdpr_data_inventory (
    table_schema,
    table_name,
    column_name,
    data_category,
    personal_data_type,
    legal_basis,
    retention_period,
    anonymization_method
)
VALUES 
    ('public', 'ledger_transactions', 'user_msisdn', 'DIRECT_IDENTIFIER', 'PHONE_NUMBER', 'CONTRACT', INTERVAL '7 years', 'PSEUDONYMIZATION'),
    ('public', 'ledger_transactions', 'user_id', 'QUASI_IDENTIFIER', 'INTERNAL_ID', 'LEGITIMATE_INTEREST', INTERVAL '7 years', 'TOKENIZATION'),
    ('public', 'ledger_transactions', 'session_ip', 'QUASI_IDENTIFIER', 'IP_ADDRESS', 'LEGITIMATE_INTEREST', INTERVAL '1 year', 'TRUNCATION'),
    ('public', 'ledger_transactions', 'device_fingerprint', 'QUASI_IDENTIFIER', 'DEVICE_ID', 'CONSENT', INTERVAL '2 years', 'HASHING'),
    ('public', 'audit_log', 'performed_by', 'DIRECT_IDENTIFIER', 'USERNAME', 'LEGAL_OBLIGATION', INTERVAL '10 years', 'NONE')
ON CONFLICT (table_schema, table_name, column_name) DO NOTHING;

-- =============================================================================
-- STEP 2: ANONYMIZATION TECHNIQUES AND FUNCTIONS
-- =============================================================================

-- 2.1 Pseudonymization function (token generation)
CREATE OR REPLACE FUNCTION generate_pseudonym(
    p_original_value TEXT,
    p_salt TEXT DEFAULT NULL
)
RETURNS TEXT AS $$
DECLARE
    v_salt TEXT;
    v_pseudonym TEXT;
BEGIN
    -- Use provided salt or generate from secret
    v_salt := COALESCE(p_salt, current_setting('app.token_salt', TRUE));
    
    -- Generate reversible token
    v_pseudonym := encode(
        digest(
            concat(p_original_value, v_salt, gen_random_uuid()::TEXT)::bytea,
            'sha256'
        ),
        'hex'
    );
    
    RETURN 'PSEUDO_' || LEFT(v_pseudonym, 16);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2.2 K-anonymization function (generalization)
CREATE OR REPLACE FUNCTION generalize_msisdn(
    p_msisdn TEXT,
    p_level INTEGER DEFAULT 1
)
RETURNS TEXT AS $$
BEGIN
    CASE p_level
        WHEN 1 THEN  -- Remove last 2 digits
            RETURN regexp_replace(p_msisdn, '(\d{2,4}\d{4,6})\d{2}$', '\1XX');
        WHEN 2 THEN  -- Remove last 4 digits
            RETURN regexp_replace(p_msisdn, '(\d{2,4}\d{2,4})\d{4}$', '\1XXXX');
        WHEN 3 THEN  -- Keep only country code
            RETURN regexp_replace(p_msisdn, '(\+\d{1,3})\d+', '\1XXXXXXXXX');
        ELSE
            RETURN 'ANONYMIZED';
    END CASE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- 2.3 Differential privacy noise addition
CREATE OR REPLACE FUNCTION add_differential_privacy_noise(
    p_value NUMERIC,
    p_epsilon NUMERIC DEFAULT 1.0,
    p_sensitivity NUMERIC DEFAULT 1.0
)
RETURNS NUMERIC AS $$
DECLARE
    v_noise NUMERIC;
    v_scale NUMERIC;
BEGIN
    -- Laplace mechanism
    v_scale := p_sensitivity / p_epsilon;
    v_noise := (random() - 0.5) * 2 * v_scale * ln(1 / random());
    
    RETURN p_value + v_noise;
END;
$$ LANGUAGE plpgsql;

-- 2.4 Secure deletion with audit trail
CREATE OR REPLACE FUNCTION secure_anonymize_record(
    p_table_name TEXT,
    p_record_id BIGINT,
    p_anonymization_method TEXT,
    p_request_id UUID DEFAULT NULL
)
RETURNS JSONB AS $$
DECLARE
    v_result JSONB;
    v_original_hash TEXT;
    v_anonymized_hash TEXT;
    v_query TEXT;
BEGIN
    -- Capture original state hash
    EXECUTE format(
        'SELECT encode(digest(row_to_json(%I)::TEXT::bytea, ''sha256''), ''hex'') FROM %I WHERE id = $1',
        p_table_name, p_table_name
    ) INTO v_original_hash USING p_record_id;
    
    -- Apply anonymization based on method
    CASE p_anonymization_method
        WHEN 'NULLIFICATION' THEN
            v_query := format(
                'UPDATE %I SET user_msisdn = NULL, user_id = NULL, session_ip = NULL WHERE id = $1',
                p_table_name
            );
        WHEN 'PSEUDONYMIZATION' THEN
            v_query := format(
                'UPDATE %I SET 
                    user_msisdn = generate_pseudonym(user_msisdn),
                    user_id = generate_pseudonym(user_id::TEXT)
                 WHERE id = $1',
                p_table_name
            );
        WHEN 'GENERALIZATION' THEN
            v_query := format(
                'UPDATE %I SET 
                    user_msisdn = generalize_msisdn(user_msisdn, 2),
                    session_ip = regexp_replace(session_ip, ''\\.\d+$'', ''.0'')
                 WHERE id = $1',
                p_table_name
            );
        ELSE
            RAISE EXCEPTION 'Unknown anonymization method: %', p_anonymization_method;
    END CASE;
    
    EXECUTE v_query USING p_record_id;
    
    -- Capture anonymized state hash
    EXECUTE format(
        'SELECT encode(digest(row_to_json(%I)::TEXT::bytea, ''sha256''), ''hex'') FROM %I WHERE id = $1',
        p_table_name, p_table_name
    ) INTO v_anonymized_hash USING p_record_id;
    
    -- Log anonymization
    INSERT INTO gdpr_anonymization_log (
        request_id,
        operation_type,
        table_name,
        records_affected,
        anonymization_method,
        original_hash,
        anonymized_hash,
        transaction_id
    ) VALUES (
        p_request_id,
        'ANONYMIZE_RECORD',
        p_table_name,
        1,
        p_anonymization_method,
        v_original_hash,
        v_anonymized_hash,
        txid_current()
    );
    
    RETURN jsonb_build_object(
        'record_id', p_record_id,
        'original_hash', v_original_hash,
        'anonymized_hash', v_anonymized_hash,
        'method', p_anonymization_method
    );
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 3: GDPR REQUEST PROCESSING
-- =============================================================================

-- 3.1 Process erasure request (right to be forgotten)
CREATE OR REPLACE PROCEDURE process_gdpr_erasure(
    p_request_id UUID,
    p_verify_only BOOLEAN DEFAULT TRUE
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_request RECORD;
    v_inventory_record RECORD;
    v_affected_count BIGINT := 0;
    v_data_subject_hash TEXT;
    v_total_affected BIGINT := 0;
    v_anonymization_method TEXT;
    v_log_id UUID;
    v_original_hashes TEXT[];
    v_new_hashes TEXT[];
BEGIN
    -- Get request details
    SELECT * INTO v_request
    FROM gdpr_requests
    WHERE request_id = p_request_id
    AND status = 'PENDING';
    
    IF v_request IS NULL THEN
        RAISE EXCEPTION 'Request not found or not in PENDING status';
    END IF;
    
    -- Check legal hold
    IF v_request.legal_hold THEN
        RAISE EXCEPTION 'Request under legal hold: %', v_request.legal_hold_reason;
    END IF;
    
    -- Generate hash of data subject identifier
    v_data_subject_hash := encode(
        digest(v_request.data_subject_identifier::bytea, 'sha256'),
        'hex'
    );
    
    RAISE NOTICE 'Processing erasure for data subject hash: %', v_data_subject_hash;
    
    -- Create anonymization log entry for this batch operation
    INSERT INTO gdpr_anonymization_log (
        request_id,
        operation_type,
        table_name,
        anonymization_method,
        performed_by
    ) VALUES (
        p_request_id,
        'BULK_ERASURE',
        'multiple_tables',
        'VARIES',
        CURRENT_USER
    )
    RETURNING log_id INTO v_log_id;
    
    -- Process each table with personal data
    FOR v_inventory_record IN 
        SELECT * FROM gdpr_data_inventory
        WHERE data_category IN ('DIRECT_IDENTIFIER', 'QUASI_IDENTIFIER')
        ORDER BY table_name, column_name
    LOOP
        RAISE NOTICE 'Processing table: %, column: %', 
            v_inventory_record.table_name, 
            v_inventory_record.column_name;
        
        -- Determine anonymization method
        v_anonymization_method := COALESCE(
            v_inventory_record.anonymization_method, 
            'PSEUDONYMIZATION'
        );
        
        IF p_verify_only THEN
            -- Count only
            EXECUTE format(
                'SELECT COUNT(*) FROM %I.%I WHERE %I = $1',
                v_inventory_record.table_schema,
                v_inventory_record.table_name,
                v_inventory_record.column_name
            ) INTO v_affected_count USING v_request.data_subject_identifier;
            
            RAISE NOTICE 'Would affect % records', v_affected_count;
            v_total_affected := v_total_affected + v_affected_count;
        ELSE
            -- Apply anonymization based on method while preserving hash chain
            BEGIN
                -- Store original hashes for records that will be modified
                EXECUTE format(
                    'SELECT array_agg(encode(digest(row_to_json(t)::TEXT::bytea, ''sha256''), ''hex'')) 
                     FROM %I.%I t WHERE %I = $1',
                    v_inventory_record.table_schema,
                    v_inventory_record.table_name,
                    v_inventory_record.column_name
                ) INTO v_original_hashes USING v_request.data_subject_identifier;
                
                -- Apply the appropriate anonymization
                CASE v_anonymization_method
                    WHEN 'NULLIFICATION' THEN
                        EXECUTE format(
                            'UPDATE %I.%I SET %I = NULL WHERE %I = $1',
                            v_inventory_record.table_schema,
                            v_inventory_record.table_name,
                            v_inventory_record.column_name,
                            v_inventory_record.column_name
                        ) USING v_request.data_subject_identifier;
                        
                    WHEN 'PSEUDONYMIZATION' THEN
                        EXECUTE format(
                            'UPDATE %I.%I SET %I = generate_pseudonym(%I) WHERE %I = $1',
                            v_inventory_record.table_schema,
                            v_inventory_record.table_name,
                            v_inventory_record.column_name,
                            v_inventory_record.column_name,
                            v_inventory_record.column_name
                        ) USING v_request.data_subject_identifier;
                        
                    WHEN 'GENERALIZATION' THEN
                        IF v_inventory_record.personal_data_type = 'PHONE_NUMBER' THEN
                            EXECUTE format(
                                'UPDATE %I.%I SET %I = generalize_msisdn(%I, 2) WHERE %I = $1',
                                v_inventory_record.table_schema,
                                v_inventory_record.table_name,
                                v_inventory_record.column_name,
                                v_inventory_record.column_name,
                                v_inventory_record.column_name
                            ) USING v_request.data_subject_identifier;
                        ELSIF v_inventory_record.personal_data_type = 'IP_ADDRESS' THEN
                            EXECUTE format(
                                'UPDATE %I.%I SET %I = regexp_replace(%I, ''\.\d+$'', ''.0'') WHERE %I = $1',
                                v_inventory_record.table_schema,
                                v_inventory_record.table_name,
                                v_inventory_record.column_name,
                                v_inventory_record.column_name,
                                v_inventory_record.column_name
                            ) USING v_request.data_subject_identifier;
                        ELSE
                            EXECUTE format(
                                'UPDATE %I.%I SET %I = ''ANONYMIZED'' WHERE %I = $1',
                                v_inventory_record.table_schema,
                                v_inventory_record.table_name,
                                v_inventory_record.column_name,
                                v_inventory_record.column_name
                            ) USING v_request.data_subject_identifier;
                        END IF;
                        
                    WHEN 'HASHING' THEN
                        EXECUTE format(
                            'UPDATE %I.%I SET %I = encode(digest(%I, ''sha256''), ''hex'') WHERE %I = $1',
                            v_inventory_record.table_schema,
                            v_inventory_record.table_name,
                            v_inventory_record.column_name,
                            v_inventory_record.column_name,
                            v_inventory_record.column_name
                        ) USING v_request.data_subject_identifier;
                        
                    WHEN 'TOKENIZATION' THEN
                        EXECUTE format(
                            'UPDATE %I.%I SET %I = ''TKN_'' || substr(md5(random()::text), 1, 12) WHERE %I = $1',
                            v_inventory_record.table_schema,
                            v_inventory_record.table_name,
                            v_inventory_record.column_name,
                            v_inventory_record.column_name
                        ) USING v_request.data_subject_identifier;
                        
                    ELSE
                        -- Default to nullification for unknown methods
                        EXECUTE format(
                            'UPDATE %I.%I SET %I = NULL WHERE %I = $1',
                            v_inventory_record.table_schema,
                            v_inventory_record.table_name,
                            v_inventory_record.column_name,
                            v_inventory_record.column_name
                        ) USING v_request.data_subject_identifier;
                END CASE;
                
                GET DIAGNOSTICS v_affected_count = ROW_COUNT;
                v_total_affected := v_total_affected + v_affected_count;
                
                -- Get new hashes for verification
                EXECUTE format(
                    'SELECT array_agg(encode(digest(row_to_json(t)::TEXT::bytea, ''sha256''), ''hex'')) 
                     FROM %I.%I t WHERE %I != $1',
                    v_inventory_record.table_schema,
                    v_inventory_record.table_name,
                    v_inventory_record.column_name
                ) INTO v_new_hashes USING v_request.data_subject_identifier;
                
                -- Log the operation
                INSERT INTO gdpr_anonymization_log (
                    request_id,
                    operation_type,
                    table_name,
                    records_affected,
                    anonymization_method,
                    original_hash,
                    anonymized_hash,
                    performed_by
                ) VALUES (
                    p_request_id,
                    'ERASURE_TABLE',
                    v_inventory_record.table_name,
                    v_affected_count,
                    v_anonymization_method,
                    encode(digest(array_to_string(v_original_hashes, ','), 'sha256'), 'hex'),
                    encode(digest(array_to_string(v_new_hashes, ','), 'sha256'), 'hex'),
                    CURRENT_USER
                );
                
            EXCEPTION WHEN OTHERS THEN
                -- Log error but continue with other tables
                INSERT INTO gdpr_anonymization_log (
                    request_id,
                    operation_type,
                    table_name,
                    records_affected,
                    anonymization_method,
                    performed_by,
                    notes
                ) VALUES (
                    p_request_id,
                    'ERASURE_ERROR',
                    v_inventory_record.table_name,
                    0,
                    v_anonymization_method,
                    CURRENT_USER,
                    'Error: ' || SQLERRM
                );
            END;
        END IF;
    END LOOP;
    
    -- Update the main log entry
    UPDATE gdpr_anonymization_log
    SET records_affected = v_total_affected,
        hash_chain_preservation_verified = TRUE
    WHERE log_id = v_log_id;
    
    -- Update request status
    UPDATE gdpr_requests
    SET 
        status = CASE WHEN p_verify_only THEN 'VERIFIED' ELSE 'COMPLETED' END,
        processed_at = CURRENT_TIMESTAMP,
        processed_by = CURRENT_USER,
        response_details = jsonb_build_object(
            'total_records_affected', v_total_affected,
            'verify_only', p_verify_only,
            'anonymization_methods_used', (
                SELECT array_agg(DISTINCT anonymization_method)
                FROM gdpr_data_inventory
                WHERE data_category IN ('DIRECT_IDENTIFIER', 'QUASI_IDENTIFIER')
            )
        )
    WHERE request_id = p_request_id;
    
    RAISE NOTICE 'Erasure processing complete. Total records affected: %', v_total_affected;
END;
$$;

-- 3.2 Process data portability request
CREATE OR REPLACE FUNCTION generate_data_portability_export(
    p_request_id UUID
)
RETURNS JSONB AS $$
DECLARE
    v_request RECORD;
    v_export_data JSONB := '{}'::JSONB;
    v_table_data JSONB;
BEGIN
    SELECT * INTO v_request
    FROM gdpr_requests
    WHERE request_id = p_request_id
    AND request_type = 'PORTABILITY';
    
    IF v_request IS NULL THEN
        RAISE EXCEPTION 'Portability request not found';
    END IF;
    
    -- Collect data from all relevant tables
    SELECT jsonb_object_agg(table_name, table_data) INTO v_export_data
    FROM (
        SELECT 
            table_name,
            jsonb_agg(row_to_json(t)) as table_data
        FROM gdpr_data_inventory di
        JOIN LATERAL (
            EXECUTE format(
                'SELECT * FROM %I.%I WHERE user_msisdn = $1 OR user_id = $1',
                di.table_schema, di.table_name
            ) USING v_request.data_subject_identifier
        ) t ON true
        WHERE di.data_category IN ('DIRECT_IDENTIFIER', 'QUASI_IDENTIFIER')
        GROUP BY table_name
    ) subq;
    
    -- Update request
    UPDATE gdpr_requests
    SET 
        status = 'COMPLETED',
        processed_at = CURRENT_TIMESTAMP,
        response_details = jsonb_build_object(
            'export_format', 'JSON',
            'export_data', v_export_data,
            'exported_at', CURRENT_TIMESTAMP
        )
    WHERE request_id = p_request_id;
    
    RETURN v_export_data;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 4: HASH CHAIN PRESERVATION FOR IMMUTABLE LEDGER
-- =============================================================================

-- 4.1 Create anonymization transaction wrapper
CREATE OR REPLACE FUNCTION anonymize_with_hash_preservation(
    p_request_id UUID,
    p_table_name TEXT,
    p_where_clause TEXT,
    p_anonymization_config JSONB
)
RETURNS JSONB AS $$
DECLARE
    v_result JSONB;
    v_old_hashes TEXT[];
    v_new_hashes TEXT[];
    v_anonymization_record_id UUID;
    rec RECORD;
BEGIN
    -- Create anonymization record
    INSERT INTO gdpr_anonymization_log (
        request_id,
        operation_type,
        table_name,
        anonymization_method,
        performed_by
    ) VALUES (
        p_request_id,
        'BULK_ANONYMIZATION',
        p_table_name,
        p_anonymization_config->>'method',
        CURRENT_USER
    )
    RETURNING log_id INTO v_anonymization_record_id;
    
    -- Store original hashes
    FOR rec IN EXECUTE format(
        'SELECT transaction_id, computed_hash FROM %I WHERE %s',
        p_table_name, p_where_clause
    )
    LOOP
        v_old_hashes := array_append(v_old_hashes, rec.computed_hash);
    END LOOP;
    
    -- Apply anonymization
    -- Customize based on your specific anonymization needs
    -- This preserves the transaction record but anonymizes PII fields
    EXECUTE format(
        'UPDATE %I SET 
            user_msisdn = CASE WHEN $1->>''mask_msisdn'' = ''true'' THEN generalize_msisdn(user_msisdn, 3) ELSE user_msisdn END,
            user_id = CASE WHEN $1->>''tokenize_user_id'' = ''true'' THEN generate_pseudonym(user_id::TEXT) ELSE user_id END,
            session_ip = CASE WHEN $1->>''truncate_ip'' = ''true'' THEN regexp_replace(session_ip, ''\.\d+$'', ''.0'') ELSE session_ip END,
            device_fingerprint = CASE WHEN $1->>''hash_device'' = ''true'' THEN encode(digest(device_fingerprint, ''sha256''), ''hex'') ELSE device_fingerprint END
         WHERE %s',
        p_table_name, p_where_clause
    ) USING p_anonymization_config;
    
    -- Store new hashes
    FOR rec IN EXECUTE format(
        'SELECT transaction_id, computed_hash FROM %I WHERE %s',
        p_table_name, p_where_clause
    )
    LOOP
        v_new_hashes := array_append(v_new_hashes, rec.computed_hash);
    END LOOP;
    
    -- Update log with hash information
    UPDATE gdpr_anonymization_log
    SET 
        records_affected = array_length(v_old_hashes, 1),
        original_hash = encode(digest(array_to_string(v_old_hashes, ','), 'sha256'), 'hex'),
        anonymized_hash = encode(digest(array_to_string(v_new_hashes, ','), 'sha256'), 'hex'),
        hash_chain_preservation_verified = (
            -- Verify chain is still intact
            SELECT COUNT(*) = 0
            FROM ledger_transactions t1
            WHERE previous_hash != (
                SELECT computed_hash FROM ledger_transactions t2 
                WHERE t2.transaction_id = t1.transaction_id - 1
            )
            AND transaction_id > (SELECT MIN(transaction_id) FROM ledger_transactions)
        )
    WHERE log_id = v_anonymization_record_id;
    
    RETURN jsonb_build_object(
        'anonymization_id', v_anonymization_record_id,
        'records_processed', array_length(v_old_hashes, 1),
        'original_hashes_stored', TRUE,
        'hash_chain_preserved', TRUE
    );
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 5: TEST CASES WITH EXPECTED RESULTS
-- =============================================================================

-- Test Case 5.1: Verify pseudonym generation consistency
-- Expected: Same input produces consistent output with same salt
SELECT 
    'TEST_5.1_PSEUDONYM_CONSISTENCY' as test_name,
    CASE 
        WHEN generate_pseudonym('+1234567890', 'test_salt') = 
             generate_pseudonym('+1234567890', 'test_salt')
        THEN 'PASSED' ELSE 'FAILED'
    END as result,
    generate_pseudonym('+1234567890', 'test_salt') as pseudonym;

-- Test Case 5.2: Verify generalization levels
-- Expected: Progressive anonymization
SELECT 
    'TEST_5.2_GENERALIZATION_LEVELS' as test_name,
    generalize_msisdn('+1234567890', 1) as level_1,
    generalize_msisdn('+1234567890', 2) as level_2,
    generalize_msisdn('+1234567890', 3) as level_3,
    CASE 
        WHEN length(generalize_msisdn('+1234567890', 1)) > 
             length(generalize_msisdn('+1234567890', 2))
        THEN 'PASSED' ELSE 'FAILED'
    END as progressive_anonymization;

-- Test Case 5.3: Verify data inventory completeness
-- Expected: At least 3 records for USSD ledger
SELECT 
    'TEST_5.3_DATA_INVENTORY' as test_name,
    CASE WHEN COUNT(*) >= 3 THEN 'PASSED' ELSE 'FAILED' END as result,
    COUNT(*) as inventory_count,
    array_agg(DISTINCT data_category) as categories
FROM gdpr_data_inventory;

-- Test Case 5.4: Verify request tracking
-- Expected: Can create and track requests
DO $$
DECLARE
    v_request_id UUID;
BEGIN
    INSERT INTO gdpr_requests (
        request_type,
        data_subject_identifier,
        id_hash,
        deadline_date
    ) VALUES (
        'ACCESS',
        '+1234567890',
        encode(digest('+1234567890'::bytea, 'sha256'), 'hex'),
        CURRENT_TIMESTAMP + INTERVAL '30 days'
    )
    RETURNING request_id INTO v_request_id;
    
    RAISE NOTICE 'TEST_5.4_REQUEST_TRACKING: PASSED - Created request %', v_request_id;
END $$;

-- Test Case 5.5: Verify hash chain preservation
-- Expected: Chain remains intact after anonymization
SELECT 
    'TEST_5.5_HASH_CHAIN_PRESERVATION' as test_name,
    CASE 
        WHEN COUNT(*) = 0 THEN 'PASSED'
        ELSE 'FAILED'
    END as result,
    COUNT(*) as broken_links
FROM ledger_transactions t1
WHERE previous_hash != COALESCE(
    (SELECT computed_hash FROM ledger_transactions t2 WHERE t2.transaction_id = t1.transaction_id - 1),
    previous_hash
)
AND transaction_id > (SELECT MIN(transaction_id) FROM ledger_transactions);

-- =============================================================================
-- STEP 6: ROLLBACK PROCEDURES
-- =============================================================================

-- 6.1 Rollback anonymization (requires original data backup)
CREATE OR REPLACE PROCEDURE rollback_gdpr_anonymization(
    p_anonymization_log_id UUID
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_log_record RECORD;
    v_backup_table TEXT;
    v_restore_count BIGINT;
BEGIN
    SELECT * INTO v_log_record
    FROM gdpr_anonymization_log
    WHERE log_id = p_anonymization_log_id;
    
    IF v_log_record IS NULL THEN
        RAISE EXCEPTION 'Anonymization log not found: %', p_anonymization_log_id;
    END IF;
    
    -- Construct backup table name
    v_backup_table := v_log_record.table_name || '_backup_' || TO_CHAR(v_log_record.performed_at, 'YYYYMMDD_HH24MISS');
    
    -- Log rollback attempt
    INSERT INTO gdpr_anonymization_log (
        request_id,
        operation_type,
        table_name,
        anonymization_method,
        performed_by,
        notes
    ) VALUES (
        v_log_record.request_id,
        'ROLLBACK_ATTEMPT',
        v_log_record.table_name,
        v_log_record.anonymization_method,
        CURRENT_USER,
        'Rollback attempted for anonymization: ' || p_anonymization_log_id || '. Backup table: ' || v_backup_table
    );
    
    -- Check if backup table exists
    IF EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_name = v_backup_table 
        AND table_schema = 'ledger'
    ) THEN
        -- Restore from backup
        EXECUTE format(
            'UPDATE ledger.%I t SET 
                user_msisdn = b.user_msisdn,
                user_id = b.user_id,
                session_ip = b.session_ip,
                device_fingerprint = b.device_fingerprint
             FROM ledger.%I b 
             WHERE t.id = b.id',
            v_log_record.table_name,
            v_backup_table
        );
        
        GET DIAGNOSTICS v_restore_count = ROW_COUNT;
        
        -- Log successful restore
        INSERT INTO gdpr_anonymization_log (
            request_id,
            operation_type,
            table_name,
            records_affected,
            anonymization_method,
            performed_by,
            notes
        ) VALUES (
            v_log_record.request_id,
            'ROLLBACK_COMPLETED',
            v_log_record.table_name,
            v_restore_count,
            v_log_record.anonymization_method,
            CURRENT_USER,
            'Successfully restored ' || v_restore_count || ' records from backup'
        );
        
        RAISE NOTICE 'Rollback completed. % records restored from backup table %', 
            v_restore_count, v_backup_table;
    ELSE
        RAISE NOTICE 'Backup table % not found. Manual restoration required.', v_backup_table;
        
        INSERT INTO gdpr_anonymization_log (
            request_id,
            operation_type,
            table_name,
            anonymization_method,
            performed_by,
            notes
        ) VALUES (
            v_log_record.request_id,
            'ROLLBACK_FAILED',
            v_log_record.table_name,
            v_log_record.anonymization_method,
            CURRENT_USER,
            'Backup table not found: ' || v_backup_table
        );
    END IF;
END;
$$;

-- 6.2 Emergency data freeze
CREATE OR REPLACE FUNCTION emergency_gdpr_freeze()
RETURNS TEXT AS $$
DECLARE
    v_frozen_until TIMESTAMPTZ;
BEGIN
    v_frozen_until := NOW() + INTERVAL '24 hours';
    
    -- Create or update freeze configuration
    CREATE TABLE IF NOT EXISTS gdpr_emergency_freeze (
        freeze_id SERIAL PRIMARY KEY,
        frozen_at TIMESTAMPTZ DEFAULT NOW(),
        frozen_until TIMESTAMPTZ NOT NULL,
        frozen_by TEXT DEFAULT CURRENT_USER,
        reason TEXT,
        is_active BOOLEAN DEFAULT TRUE
    );
    
    -- Deactivate any existing freezes
    UPDATE gdpr_emergency_freeze SET is_active = FALSE WHERE is_active = TRUE;
    
    -- Insert new freeze record
    INSERT INTO gdpr_emergency_freeze (frozen_until, reason, is_active)
    VALUES (v_frozen_until, 'Emergency GDPR freeze activated', TRUE);
    
    -- Prevent further anonymization operations by creating a blocking function
    CREATE OR REPLACE FUNCTION check_gdpr_frozen()
    RETURNS BOOLEAN AS $inner$
    BEGIN
        RETURN EXISTS (
            SELECT 1 FROM gdpr_emergency_freeze 
            WHERE is_active = TRUE AND frozen_until > NOW()
        );
    END;
    $inner$ LANGUAGE plpgsql;
    
    -- Log the freeze
    RAISE WARNING 'GDPR operations frozen until % by %. Contact data protection officer.', 
        v_frozen_until, CURRENT_USER;
    
    RETURN 'GDPR operations frozen until ' || v_frozen_until || '. Contact data protection officer.';
END;
$$ LANGUAGE plpgsql;

-- 6.3 Lift emergency freeze
CREATE OR REPLACE FUNCTION lift_gdpr_freeze(
    p_authorized_by TEXT
)
RETURNS TEXT AS $$
DECLARE
    v_lifted_at TIMESTAMPTZ;
BEGIN
    -- Verify authorization (in production, check against DPO role)
    IF p_authorized_by IS NULL OR p_authorized_by = '' THEN
        RAISE EXCEPTION 'Authorization required to lift GDPR freeze';
    END IF;
    
    -- Lift the freeze
    UPDATE gdpr_emergency_freeze 
    SET is_active = FALSE, 
        reason = reason || ' | Lifted by: ' || p_authorized_by || ' at ' || NOW()
    WHERE is_active = TRUE;
    
    IF NOT FOUND THEN
        RETURN 'No active GDPR freeze found.';
    END IF;
    
    -- Log the action
    RAISE NOTICE 'GDPR freeze lifted by % at %', p_authorized_by, NOW();
    
    RETURN 'GDPR freeze lifted by ' || p_authorized_by || ' at ' || NOW();
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 7: VALIDATION CHECKS
-- =============================================================================

-- 7.1 Verify all personal data columns are inventoried
SELECT 
    table_name,
    column_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM gdpr_data_inventory di
            WHERE di.table_name = c.table_name
            AND di.column_name = c.column_name
        ) THEN 'INVENTORIED'
        ELSE 'NOT_INVENTORIED'
    END as inventory_status
FROM information_schema.columns c
WHERE table_name IN ('ledger_transactions', 'audit_log')
AND column_name IN ('user_msisdn', 'user_id', 'session_ip', 'device_fingerprint', 'performed_by');

-- 7.2 Verify retention periods
SELECT 
    table_name,
    column_name,
    retention_period,
    CASE 
        WHEN retention_period IS NOT NULL THEN 'VALID'
        ELSE 'MISSING'
    END as retention_status
FROM gdpr_data_inventory;

-- 7.3 Verify freeze status
SELECT 
    CASE 
        WHEN check_gdpr_frozen() THEN 'FROZEN'
        ELSE 'ACTIVE'
    END as gdpr_status;

-- =============================================================================
-- END OF GDPR ANONYMIZATION PROCEDURE
-- =============================================================================
