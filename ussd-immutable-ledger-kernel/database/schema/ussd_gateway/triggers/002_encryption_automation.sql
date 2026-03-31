-- ============================================================================
-- USSD Gateway - Encryption Automation Triggers
-- Automatic encryption/decryption of sensitive data (MSISDN, PII)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Trigger Function: ussd.tf_encrypt_msisdn
-- Description: Automatically encrypts MSISDN before storage
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.tf_encrypt_msisdn()
RETURNS TRIGGER AS $$
DECLARE
    v_encryption_key TEXT;
BEGIN
    -- Get encryption key from session
    BEGIN
        v_encryption_key := current_setting('app.encryption_key', true);
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'Encryption key not set in app.encryption_key';
    END;
    
    -- Encrypt MSISDN if provided and not already encrypted
    IF NEW.msisdn_plaintext IS NOT NULL AND NEW.msisdn_plaintext != '' THEN
        NEW.msisdn_encrypted := pgp_sym_encrypt(
            NEW.msisdn_plaintext,
            v_encryption_key,
            'cipher-algo=aes256, compress-algo=0'
        );
        NEW.msisdn_hash := encode(digest(NEW.msisdn_plaintext, 'sha256'), 'hex');
        NEW.msisdn_plaintext := NULL;  -- Clear plaintext
    END IF;
    
    -- Handle direct MSISDN field (alternative column name)
    IF NEW.msISDN IS NOT NULL AND NEW.msISDN != '' THEN
        NEW.msisdn_encrypted := pgp_sym_encrypt(
            NEW.msISDN,
            v_encryption_key,
            'cipher-algo=aes256, compress-algo=0'
        );
        NEW.msisdn_hash := encode(digest(NEW.msISDN, 'sha256'), 'hex');
        NEW.msISDN := NULL;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.tf_encrypt_msisdn IS 
'Automatically encrypts MSISDN fields before storage';

-- ----------------------------------------------------------------------------
-- Trigger Function: ussd.tf_encrypt_sensitive_fields
-- Description: Encrypts various PII fields automatically
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.tf_encrypt_sensitive_fields()
RETURNS TRIGGER AS $$
DECLARE
    v_encryption_key TEXT;
BEGIN
    v_encryption_key := current_setting('app.encryption_key', true);
    
    -- Encrypt IMEI if present
    IF NEW.imei_plaintext IS NOT NULL THEN
        NEW.imei_encrypted := pgp_sym_encrypt(
            NEW.imei_plaintext, v_encryption_key
        );
        NEW.imei_hash := encode(digest(NEW.imei_plaintext, 'sha256'), 'hex');
        NEW.imei_plaintext := NULL;
    END IF;
    
    -- Encrypt IMSI if present
    IF NEW.imsi_plaintext IS NOT NULL THEN
        NEW.imsi_encrypted := pgp_sym_encrypt(
            NEW.imsi_plaintext, v_encryption_key
        );
        NEW.imsi_hash := encode(digest(NEW.imsi_plaintext, 'sha256'), 'hex');
        NEW.imsi_plaintext := NULL;
    END IF;
    
    -- Encrypt account numbers
    IF NEW.account_number_plaintext IS NOT NULL THEN
        NEW.account_number_encrypted := pgp_sym_encrypt(
            NEW.account_number_plaintext, v_encryption_key
        );
        NEW.account_number_hash := encode(digest(NEW.account_number_plaintext, 'sha256'), 'hex');
        NEW.account_number_plaintext := NULL;
    END IF;
    
    -- Encrypt PIN (one-way hash, not reversible encryption)
    IF NEW.pin_plaintext IS NOT NULL AND NEW.pin_plaintext != '' THEN
        NEW.pin_hash := crypt(NEW.pin_plaintext, gen_salt('bf', 10));
        NEW.pin_plaintext := NULL;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.tf_encrypt_sensitive_fields IS 
'Encrypts multiple PII fields before storage';

-- ----------------------------------------------------------------------------
-- Trigger: sessions_encrypt_msisdn
-- Description: MSISDN encryption trigger for sessions table
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS sessions_encrypt_msisdn ON ussd.sessions;
CREATE TRIGGER sessions_encrypt_msisdn
    BEFORE INSERT OR UPDATE ON ussd.sessions
    FOR EACH ROW
    WHEN (NEW.msisdn_plaintext IS NOT NULL OR NEW.msISDN IS NOT NULL)
    EXECUTE FUNCTION ussd.tf_encrypt_msisdn();

COMMENT ON TRIGGER sessions_encrypt_msisdn ON ussd.sessions IS 
'Encrypts MSISDN in sessions table';

-- ----------------------------------------------------------------------------
-- Trigger: user_profiles_encrypt_fields
-- Description: PII encryption trigger for user profiles
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS user_profiles_encrypt_fields ON ussd.user_profiles;
CREATE TRIGGER user_profiles_encrypt_fields
    BEFORE INSERT OR UPDATE ON ussd.user_profiles
    FOR EACH ROW
    EXECUTE FUNCTION ussd.tf_encrypt_sensitive_fields();

COMMENT ON TRIGGER user_profiles_encrypt_fields ON ussd.user_profiles IS 
'Encrypts sensitive fields in user profiles';

-- ----------------------------------------------------------------------------
-- Trigger Function: ussd.tf_audit_encryption_access
-- Description: Audits access to encrypted data
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.tf_audit_encryption_access()
RETURNS TRIGGER AS $$
BEGIN
    -- Log decryption access for sensitive fields
    IF TG_OP = 'SELECT' THEN
        INSERT INTO ussd.encryption_access_logs (
            table_name,
            operation,
            accessed_by,
            accessed_at,
            query_text
        ) VALUES (
            TG_TABLE_NAME,
            'DECRYPTION_ACCESS',
            current_user,
            NOW(),
            current_query()
        );
    END IF;
    
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ----------------------------------------------------------------------------
-- Trigger: sessions_audit_access
-- Description: Audit access to session data
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS sessions_audit_access ON ussd.sessions;
CREATE TRIGGER sessions_audit_access
    BEFORE SELECT ON ussd.sessions
    FOR EACH STATEMENT
    EXECUTE FUNCTION ussd.tf_audit_encryption_access();

-- ----------------------------------------------------------------------------
-- Trigger Function: ussd.tf_secure_pin_update
-- Description: Secures PIN updates with validation
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.tf_secure_pin_update()
RETURNS TRIGGER AS $$
DECLARE
    v_pin_strength INTEGER;
BEGIN
    -- Validate PIN complexity if changing
    IF NEW.pin_plaintext IS NOT NULL AND NEW.pin_plaintext != '' THEN
        -- Check length
        IF LENGTH(NEW.pin_plaintext) < 4 THEN
            RAISE EXCEPTION 'PIN must be at least 4 digits';
        END IF;
        
        -- Check for sequential digits
        IF NEW.pin_plaintext ~ '^(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210|0000|1111|2222|3333|4444|5555|6666|7777|8888|9999)$' THEN
            RAISE EXCEPTION 'PIN cannot be sequential or repeated digits';
        END IF;
        
        -- Hash the PIN (actual encryption happens in encrypt trigger)
        NEW.pin_hash := crypt(NEW.pin_plaintext, gen_salt('bf', 10));
        NEW.pin_plaintext := NULL;
        NEW.pin_changed_at := NOW();
        NEW.pin_attempts := 0;  -- Reset attempts on PIN change
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.tf_secure_pin_update IS 
'Validates and secures PIN updates';

-- ----------------------------------------------------------------------------
-- Trigger: user_profiles_secure_pin
-- Description: PIN security validation trigger
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS user_profiles_secure_pin ON ussd.user_profiles;
CREATE TRIGGER user_profiles_secure_pin
    BEFORE INSERT OR UPDATE OF pin_plaintext ON ussd.user_profiles
    FOR EACH ROW
    EXECUTE FUNCTION ussd.tf_secure_pin_update();

COMMENT ON TRIGGER user_profiles_secure_pin ON ussd.user_profiles IS 
'Secures PIN updates with validation';

-- ----------------------------------------------------------------------------
-- Trigger Function: ussd.tf_encrypt_audit_logs
-- Description: Encrypts sensitive data in audit logs
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.tf_encrypt_audit_logs()
RETURNS TRIGGER AS $$
DECLARE
    v_encryption_key TEXT;
BEGIN
    v_encryption_key := current_setting('app.encryption_key', true);
    
    -- Encrypt any PII in details JSONB
    IF NEW.details ? 'msisdn' THEN
        NEW.details := jsonb_set(
            NEW.details,
            '{msisdn}',
            to_jsonb(pgp_sym_encrypt(NEW.details->>'msisdn', v_encryption_key))
        );
    END IF;
    
    IF NEW.details ? 'account_number' THEN
        NEW.details := jsonb_set(
            NEW.details,
            '{account_number}',
            to_jsonb(pgp_sym_encrypt(NEW.details->>'account_number', v_encryption_key))
        );
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.tf_encrypt_audit_logs IS 
'Encrypts PII in audit log details';

-- ----------------------------------------------------------------------------
-- Trigger: audit_logs_encrypt_details
-- Description: Encryption for audit log entries
-- ----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS audit_logs_encrypt_details ON ussd.audit_logs;
CREATE TRIGGER audit_logs_encrypt_details
    BEFORE INSERT ON ussd.audit_logs
    FOR EACH ROW
    WHEN (NEW.details ? 'msisdn' OR NEW.details ? 'account_number')
    EXECUTE FUNCTION ussd.tf_encrypt_audit_logs();

COMMENT ON TRIGGER audit_logs_encrypt_details ON ussd.audit_logs IS 
'Encrypts sensitive fields in audit logs';

-- ----------------------------------------------------------------------------
-- Function: ussd.rotate_encryption_key
-- Description: Re-encrypts data with new encryption key
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.rotate_encryption_key(
    p_old_key TEXT,
    p_new_key TEXT,
    p_batch_size INTEGER DEFAULT 100
) RETURNS TABLE (
    table_name TEXT,
    records_processed INTEGER
) AS $$
DECLARE
    v_count INTEGER;
    v_record RECORD;
    v_decrypted TEXT;
BEGIN
    -- Rotate sessions table MSISDN
    v_count := 0;
    FOR v_record IN 
        SELECT id, msisdn_encrypted 
        FROM ussd.sessions 
        WHERE msisdn_encrypted IS NOT NULL
        LIMIT p_batch_size
    LOOP
        BEGIN
            v_decrypted := pgp_sym_decrypt(v_record.msisdn_encrypted, p_old_key);
            UPDATE ussd.sessions 
            SET msisdn_encrypted = pgp_sym_encrypt(v_decrypted, p_new_key)
            WHERE id = v_record.id;
            v_count := v_count + 1;
        EXCEPTION WHEN OTHERS THEN
            -- Log failed rotation
            RAISE WARNING 'Failed to rotate encryption for session %: %', v_record.id, SQLERRM;
        END;
    END LOOP;
    
    RETURN QUERY SELECT 'ussd.sessions'::TEXT, v_count;
    
    -- Note: In production, this would continue for all encrypted tables
    -- with proper batching and transaction management
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.rotate_encryption_key IS 
'Rotates encryption key for stored data (use with caution)';

-- ----------------------------------------------------------------------------
-- Function: ussd.decrypt_msisdn_safe
-- Description: Safely decrypts MSISDN with audit logging
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.decrypt_msisdn_safe(
    p_encrypted_msisdn BYTEA,
    p_reason TEXT DEFAULT 'General access'
) RETURNS VARCHAR(20) AS $$
DECLARE
    v_decrypted VARCHAR(20);
    v_encryption_key TEXT;
BEGIN
    v_encryption_key := current_setting('app.encryption_key', true);
    
    -- Decrypt
    v_decrypted := pgp_sym_decrypt(p_encrypted_msisdn, v_encryption_key);
    
    -- Log access
    INSERT INTO ussd.encryption_access_logs (
        table_name,
        operation,
        accessed_by,
        reason,
        accessed_at
    ) VALUES (
        'ussd.sessions',
        'DECRYPT_MSISDN',
        current_user,
        p_reason,
        NOW()
    );
    
    RETURN v_decrypted;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.decrypt_msisdn_safe IS 
'Safely decrypts MSISDN with audit logging';
