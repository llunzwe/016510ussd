-- ============================================================================
-- USSD Session Indexes
-- ============================================================================

-- Session state lookups
CREATE INDEX IF NOT EXISTS idx_session_external ON ussd.session_state(external_session_id);
CREATE INDEX IF NOT EXISTS idx_session_msisdn ON ussd.session_state(msisdn_hash);
CREATE INDEX IF NOT EXISTS idx_session_active ON ussd.session_state(is_active, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_session_app ON ussd.session_state(application_id, is_active);

-- Timeout monitoring
CREATE INDEX IF NOT EXISTS idx_session_timeout ON ussd.session_state(
    is_active, 
    network_timeout_at
) WHERE is_active = TRUE;

-- Menu state
CREATE INDEX IF NOT EXISTS idx_session_menu ON ussd.session_state(menu_state, is_active);
