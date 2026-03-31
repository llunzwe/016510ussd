-- ============================================================================
-- USSD Gateway - Transaction Orchestrator Functions
-- Handles PIN/OTP flow, transaction validation, and ledger integration
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Function: ussd.initiate_transaction
-- Description: Initiates a new financial transaction from USSD session
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.initiate_transaction(
    p_session_id VARCHAR(100),
    p_transaction_type VARCHAR(50),
    p_amount DECIMAL(18,2),
    p_currency_code CHAR(3) DEFAULT 'USD',
    p_destination_account VARCHAR(100) DEFAULT NULL,
    p_description TEXT DEFAULT NULL,
    p_metadata JSONB DEFAULT '{}'
) RETURNS TABLE (
    success BOOLEAN,
    transaction_id UUID,
    status VARCHAR(20),
    requires_pin BOOLEAN,
    requires_otp BOOLEAN,
    message TEXT
) AS $$
DECLARE
    v_session RECORD;
    v_transaction_id UUID;
    v_msisdn VARCHAR(20);
    v_pin_required BOOLEAN := FALSE;
    v_otp_required BOOLEAN := FALSE;
    v_transaction_limit DECIMAL(18,2);
    v_daily_total DECIMAL(18,2);
BEGIN
    -- Get session with decrypted MSISDN
    SELECT * INTO v_session FROM ussd.get_session(p_session_id);
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::UUID, 'FAILED'::VARCHAR(20), FALSE, FALSE, 
            'Session not found or expired'::TEXT;
        RETURN;
    END IF;
    
    v_msisdn := v_session.msisdn;
    
    -- Check transaction limits
    SELECT daily_limit INTO v_transaction_limit
    FROM ussd.transaction_limits
    WHERE transaction_type = p_transaction_type
      AND is_active = TRUE;
    
    -- Get daily total for this MSISDN and transaction type
    SELECT COALESCE(SUM(amount), 0) INTO v_daily_total
    FROM ussd.transactions t
    JOIN ussd.sessions s ON t.session_id = s.id
    WHERE t.transaction_type = p_transaction_type
      AND pgp_sym_decrypt(s.msisdn_encrypted, current_setting('app.encryption_key', true)) = v_msisdn
      AND t.created_at >= CURRENT_DATE
      AND t.status IN ('COMPLETED', 'PENDING');
    
    IF v_daily_total + p_amount > COALESCE(v_transaction_limit, 10000) THEN
        RETURN QUERY SELECT FALSE, NULL::UUID, 'LIMIT_EXCEEDED'::VARCHAR(20), FALSE, FALSE,
            'Daily transaction limit exceeded'::TEXT;
        RETURN;
    END IF;
    
    -- Determine authentication requirements based on amount
    IF p_amount >= 100 THEN
        v_pin_required := TRUE;
    END IF;
    
    IF p_amount >= 1000 THEN
        v_otp_required := TRUE;
    END IF;
    
    -- Check for suspicious patterns (velocity check)
    IF EXISTS (
        SELECT 1 FROM ussd.transactions t
        JOIN ussd.sessions s ON t.session_id = s.id
        WHERE pgp_sym_decrypt(s.msisdn_encrypted, current_setting('app.encryption_key', true)) = v_msisdn
          AND t.created_at >= NOW() - INTERVAL '5 minutes'
          AND t.status IN ('PENDING', 'COMPLETED')
        HAVING COUNT(*) > 5
    ) THEN
        v_otp_required := TRUE;
    END IF;
    
    -- Create transaction record
    INSERT INTO ussd.transactions (
        session_id,
        transaction_type,
        amount,
        currency_code,
        destination_account,
        description,
        status,
        requires_pin,
        requires_otp,
        pin_verified,
        otp_verified,
        metadata,
        created_at,
        expires_at
    ) VALUES (
        v_session.id,
        p_transaction_type,
        p_amount,
        p_currency_code,
        p_destination_account,
        p_description,
        'PENDING_AUTH',
        v_pin_required,
        v_otp_required,
        NOT v_pin_required,
        NOT v_otp_required,
        p_metadata,
        NOW(),
        NOW() + INTERVAL '10 minutes'
    )
    RETURNING id INTO v_transaction_id;
    
    -- Update session with transaction reference
    PERFORM ussd.update_session_state(
        p_session_id,
        'AWAITING_AUTH',
        v_session.menu_path,
        v_session.session_data || jsonb_build_object(
            'pending_transaction_id', v_transaction_id,
            'requires_pin', v_pin_required,
            'requires_otp', v_otp_required
        ),
        v_transaction_id
    );
    
    -- Generate OTP if required
    IF v_otp_required THEN
        PERFORM ussd.generate_otp(v_transaction_id, v_msisdn, 'SMS');
    END IF;
    
    RETURN QUERY SELECT 
        TRUE,
        v_transaction_id,
        'PENDING_AUTH'::VARCHAR(20),
        v_pin_required,
        v_otp_required,
        CASE 
            WHEN v_pin_required AND v_otp_required THEN 'Please enter PIN and check SMS for OTP'
            WHEN v_pin_required THEN 'Please enter your PIN'
            WHEN v_otp_required THEN 'Please check SMS for OTP'
            ELSE 'Processing transaction'
        END::TEXT;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.initiate_transaction IS 'Initiates a financial transaction with PIN/OTP requirements';

-- ----------------------------------------------------------------------------
-- Function: ussd.verify_pin
-- Description: Verifies user PIN for transaction authentication
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.verify_pin(
    p_session_id VARCHAR(100),
    p_pin VARCHAR(10),
    p_transaction_id UUID DEFAULT NULL
) RETURNS TABLE (
    success BOOLEAN,
    transaction_id UUID,
    status VARCHAR(20),
    remaining_attempts INTEGER,
    message TEXT
) AS $$
DECLARE
    v_session RECORD;
    v_transaction RECORD;
    v_msisdn VARCHAR(20);
    v_stored_hash VARCHAR(255);
    v_attempts INTEGER;
    v_max_attempts INTEGER := 3;
BEGIN
    -- Get session
    SELECT * INTO v_session FROM ussd.get_session(p_session_id);
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::UUID, 'FAILED'::VARCHAR(20), 0, 
            'Session expired'::TEXT;
        RETURN;
    END IF;
    
    v_msisdn := v_session.msisdn;
    
    -- Get PIN hash from user profile
    SELECT pin_hash, pin_attempts INTO v_stored_hash, v_attempts
    FROM ussd.user_profiles
    WHERE msisdn_hash = encode(digest(v_msisdn, 'sha256'), 'hex');
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, NULL::UUID, 'FAILED'::VARCHAR(20), 0,
            'User profile not found'::TEXT;
        RETURN;
    END IF;
    
    -- Check if account is locked
    IF v_attempts >= v_max_attempts THEN
        RETURN QUERY SELECT FALSE, NULL::UUID, 'LOCKED'::VARCHAR(20), 0,
            'Account locked due to too many failed attempts'::TEXT;
        RETURN;
    END IF;
    
    -- Verify PIN
    IF crypt(p_pin, v_stored_hash) = v_stored_hash THEN
        -- PIN verified - reset attempts
        UPDATE ussd.user_profiles 
        SET pin_attempts = 0, last_pin_verified_at = NOW()
        WHERE msisdn_hash = encode(digest(v_msisdn, 'sha256'), 'hex');
        
        -- Update transaction if provided
        IF p_transaction_id IS NOT NULL THEN
            UPDATE ussd.transactions 
            SET pin_verified = TRUE,
                verified_at = NOW()
            WHERE id = p_transaction_id
              AND status = 'PENDING_AUTH'
            RETURNING * INTO v_transaction;
            
            -- Check if OTP also required
            IF v_transaction.requires_otp AND NOT v_transaction.otp_verified THEN
                RETURN QUERY SELECT 
                    TRUE,
                    p_transaction_id,
                    'PENDING_OTP'::VARCHAR(20),
                    v_max_attempts - v_attempts,
                    'PIN verified. Please enter OTP'::TEXT;
                RETURN;
            END IF;
            
            -- Complete transaction if no OTP required
            RETURN QUERY SELECT * FROM ussd.complete_transaction(p_transaction_id);
        ELSE
            RETURN QUERY SELECT 
                TRUE,
                NULL::UUID,
                'VERIFIED'::VARCHAR(20),
                v_max_attempts,
                'PIN verified successfully'::TEXT;
        END IF;
    ELSE
        -- Failed PIN - increment attempts
        UPDATE ussd.user_profiles 
        SET pin_attempts = pin_attempts + 1
        WHERE msisdn_hash = encode(digest(v_msisdn, 'sha256'), 'hex');
        
        RETURN QUERY SELECT 
            FALSE,
            p_transaction_id,
            'FAILED'::VARCHAR(20),
            v_max_attempts - (v_attempts + 1),
            'Invalid PIN'::TEXT;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.verify_pin IS 'Verifies user PIN for transaction authentication';

-- ----------------------------------------------------------------------------
-- Function: ussd.generate_otp
-- Description: Generates and sends OTP for transaction verification
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.generate_otp(
    p_transaction_id UUID,
    p_msisdn VARCHAR(20),
    p_delivery_method VARCHAR(20) DEFAULT 'SMS'
) RETURNS TABLE (
    success BOOLEAN,
    otp_reference VARCHAR(50),
    expires_at TIMESTAMPTZ,
    message TEXT
) AS $$
DECLARE
    v_otp_code VARCHAR(10);
    v_otp_hash VARCHAR(255);
    v_reference VARCHAR(50);
    v_expiry TIMESTAMPTZ;
BEGIN
    -- Generate 6-digit OTP
    v_otp_code := LPAD(floor(random() * 1000000)::TEXT, 6, '0');
    v_otp_hash := crypt(v_otp_code, gen_salt('bf'));
    v_reference := 'OTP-' || encode(gen_random_bytes(8), 'hex');
    v_expiry := NOW() + INTERVAL '5 minutes';
    
    -- Store OTP record
    INSERT INTO ussd.otp_records (
        transaction_id,
        otp_hash,
        reference,
        delivery_method,
        expires_at,
        created_at
    ) VALUES (
        p_transaction_id,
        v_otp_hash,
        v_reference,
        p_delivery_method,
        v_expiry,
        NOW()
    );
    
    -- Queue OTP for delivery (actual delivery handled by worker)
    INSERT INTO ussd.otp_delivery_queue (
        reference,
        msisdn_encrypted,
        delivery_method,
        status,
        created_at
    ) VALUES (
        v_reference,
        pgp_sym_encrypt(p_msisdn, current_setting('app.encryption_key', true)),
        p_delivery_method,
        'PENDING',
        NOW()
    );
    
    RETURN QUERY SELECT 
        TRUE,
        v_reference,
        v_expiry,
        'OTP sent successfully'::TEXT;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.generate_otp IS 'Generates and queues OTP for delivery';

-- ----------------------------------------------------------------------------
-- Function: ussd.verify_otp
-- Description: Verifies OTP code for transaction
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.verify_otp(
    p_session_id VARCHAR(100),
    p_otp_code VARCHAR(10),
    p_transaction_id UUID
) RETURNS TABLE (
    success BOOLEAN,
    transaction_id UUID,
    status VARCHAR(20),
    remaining_attempts INTEGER,
    message TEXT
) AS $$
DECLARE
    v_otp_record RECORD;
    v_transaction RECORD;
    v_max_attempts INTEGER := 3;
BEGIN
    -- Get active OTP record
    SELECT * INTO v_otp_record
    FROM ussd.otp_records
    WHERE transaction_id = p_transaction_id
      AND verified = FALSE
      AND expires_at > NOW()
    ORDER BY created_at DESC
    LIMIT 1;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, p_transaction_id, 'EXPIRED'::VARCHAR(20), 0,
            'OTP expired or not found'::TEXT;
        RETURN;
    END IF;
    
    -- Check attempts
    IF v_otp_record.attempts >= v_max_attempts THEN
        RETURN QUERY SELECT FALSE, p_transaction_id, 'MAX_ATTEMPTS'::VARCHAR(20), 0,
            'Maximum OTP attempts exceeded'::TEXT;
        RETURN;
    END IF;
    
    -- Verify OTP
    IF crypt(p_otp_code, v_otp_record.otp_hash) = v_otp_record.otp_hash THEN
        -- Mark OTP as verified
        UPDATE ussd.otp_records 
        SET verified = TRUE, verified_at = NOW()
        WHERE id = v_otp_record.id;
        
        -- Update transaction
        UPDATE ussd.transactions 
        SET otp_verified = TRUE,
            verified_at = COALESCE(verified_at, NOW())
        WHERE id = p_transaction_id
          AND status = 'PENDING_AUTH'
        RETURNING * INTO v_transaction;
        
        -- Check if PIN also required
        IF v_transaction.requires_pin AND NOT v_transaction.pin_verified THEN
            RETURN QUERY SELECT 
                TRUE,
                p_transaction_id,
                'PENDING_PIN'::VARCHAR(20),
                v_max_attempts - v_otp_record.attempts,
                'OTP verified. Please enter PIN'::TEXT;
            RETURN;
        END IF;
        
        -- Complete transaction
        RETURN QUERY SELECT * FROM ussd.complete_transaction(p_transaction_id);
    ELSE
        -- Increment attempts
        UPDATE ussd.otp_records 
        SET attempts = attempts + 1
        WHERE id = v_otp_record.id;
        
        RETURN QUERY SELECT 
            FALSE,
            p_transaction_id,
            'INVALID'::VARCHAR(20),
            v_max_attempts - (v_otp_record.attempts + 1),
            'Invalid OTP code'::TEXT;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.verify_otp IS 'Verifies OTP code for transaction authentication';

-- ----------------------------------------------------------------------------
-- Function: ussd.complete_transaction
-- Description: Completes transaction and creates ledger entry
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.complete_transaction(
    p_transaction_id UUID
) RETURNS TABLE (
    success BOOLEAN,
    transaction_id UUID,
    status VARCHAR(20),
    remaining_attempts INTEGER,
    message TEXT
) AS $$
DECLARE
    v_transaction RECORD;
    v_session RECORD;
    v_ledger_entry_id UUID;
BEGIN
    -- Get transaction
    SELECT * INTO v_transaction
    FROM ussd.transactions
    WHERE id = p_transaction_id;
    
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, p_transaction_id, 'NOT_FOUND'::VARCHAR(20), 0,
            'Transaction not found'::TEXT;
        RETURN;
    END IF;
    
    -- Verify authentication complete
    IF v_transaction.requires_pin AND NOT v_transaction.pin_verified THEN
        RETURN QUERY SELECT FALSE, p_transaction_id, 'PENDING_PIN'::VARCHAR(20), 0,
            'PIN verification required'::TEXT;
        RETURN;
    END IF;
    
    IF v_transaction.requires_otp AND NOT v_transaction.otp_verified THEN
        RETURN QUERY SELECT FALSE, p_transaction_id, 'PENDING_OTP'::VARCHAR(20), 0,
            'OTP verification required'::TEXT;
        RETURN;
    END IF;
    
    -- Create ledger entry (immutable record)
    INSERT INTO ussd.ledger_entries (
        transaction_id,
        entry_type,
        amount,
        currency_code,
        status,
        metadata,
        created_at
    ) VALUES (
        p_transaction_id,
        v_transaction.transaction_type,
        v_transaction.amount,
        v_transaction.currency_code,
        'COMMITTED',
        v_transaction.metadata || jsonb_build_object(
            'destination_account', v_transaction.destination_account,
            'description', v_transaction.description
        ),
        NOW()
    )
    RETURNING id INTO v_ledger_entry_id;
    
    -- Update transaction status
    UPDATE ussd.transactions 
    SET 
        status = 'COMPLETED',
        completed_at = NOW(),
        ledger_entry_id = v_ledger_entry_id
    WHERE id = p_transaction_id;
    
    -- Clear from session
    SELECT * INTO v_session
    FROM ussd.sessions
    WHERE id = v_transaction.session_id;
    
    IF FOUND THEN
        PERFORM ussd.update_session_state(
            v_session.session_id,
            'TRANSACTION_COMPLETE',
            v_session.menu_path,
            v_session.session_data - 'pending_transaction_id' - 'requires_pin' - 'requires_otp'
        );
    END IF;
    
    RETURN QUERY SELECT 
        TRUE,
        p_transaction_id,
        'COMPLETED'::VARCHAR(20),
        0,
        'Transaction completed successfully'::TEXT;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.complete_transaction IS 'Completes transaction and creates immutable ledger entry';

-- ----------------------------------------------------------------------------
-- Function: ussd.cancel_transaction
-- Description: Cancels pending transaction
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.cancel_transaction(
    p_session_id VARCHAR(100),
    p_transaction_id UUID,
    p_reason TEXT DEFAULT 'User cancelled'
) RETURNS TABLE (
    success BOOLEAN,
    transaction_id UUID,
    status VARCHAR(20),
    message TEXT
) AS $$
DECLARE
    v_updated INTEGER;
BEGIN
    UPDATE ussd.transactions 
    SET 
        status = 'CANCELLED',
        cancelled_at = NOW(),
        cancellation_reason = p_reason
    WHERE id = p_transaction_id
      AND status IN ('PENDING', 'PENDING_AUTH');
    
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    
    IF v_updated > 0 THEN
        RETURN QUERY SELECT 
            TRUE,
            p_transaction_id,
            'CANCELLED'::VARCHAR(20),
            'Transaction cancelled'::TEXT;
    ELSE
        RETURN QUERY SELECT 
            FALSE,
            p_transaction_id,
            'NOT_CANCELLABLE'::VARCHAR(20),
            'Transaction cannot be cancelled'::TEXT;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.cancel_transaction IS 'Cancels a pending transaction';

-- ----------------------------------------------------------------------------
-- Function: ussd.get_transaction_history
-- Description: Retrieves transaction history for a session/user
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION ussd.get_transaction_history(
    p_session_id VARCHAR(100),
    p_limit INTEGER DEFAULT 10,
    p_offset INTEGER DEFAULT 0
) RETURNS TABLE (
    transaction_id UUID,
    transaction_type VARCHAR(50),
    amount DECIMAL(18,2),
    currency_code CHAR(3),
    status VARCHAR(20),
    created_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
) AS $$
DECLARE
    v_session RECORD;
    v_msisdn_hash VARCHAR(64);
BEGIN
    -- Get session for MSISDN hash
    SELECT s.*, encode(digest(
        pgp_sym_decrypt(s.msisdn_encrypted, current_setting('app.encryption_key', true)), 
        'sha256'
    ), 'hex') as msisdn_hash
    INTO v_session
    FROM ussd.sessions s
    WHERE s.session_id = p_session_id;
    
    IF NOT FOUND THEN
        RETURN;
    END IF;
    
    RETURN QUERY
    SELECT 
        t.id,
        t.transaction_type,
        t.amount,
        t.currency_code,
        t.status,
        t.created_at,
        t.completed_at
    FROM ussd.transactions t
    JOIN ussd.sessions s ON t.session_id = s.id
    WHERE s.msisdn_hash = v_session.msisdn_hash
    ORDER BY t.created_at DESC
    LIMIT p_limit OFFSET p_offset;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION ussd.get_transaction_history IS 'Retrieves transaction history for user';
