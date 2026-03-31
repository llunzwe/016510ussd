-- ============================================================================
-- USSD Security Indexes
-- ============================================================================

-- Device fingerprint lookups
CREATE INDEX IF NOT EXISTS idx_device_fingerprint ON ussd.device_fingerprints(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_device_msisdn ON ussd.device_fingerprints(msisdn_hash);
CREATE INDEX IF NOT EXISTS idx_device_risk ON ussd.device_fingerprints(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_device_trust ON ussd.device_fingerprints(trust_level, last_seen_at DESC);

-- Pending transactions
CREATE INDEX IF NOT EXISTS idx_pending_session ON ussd.pending_transactions(session_id);
CREATE INDEX IF NOT EXISTS idx_pending_status ON ussd.pending_transactions(status, created_at);
CREATE INDEX IF NOT EXISTS idx_pending_expiry ON ussd.pending_transactions(expires_at) 
    WHERE status IN ('PENDING', 'VERIFYING');

-- SIM swap monitoring
CREATE INDEX IF NOT EXISTS idx_sim_swap_monitor ON ussd.sim_swap_monitoring(
    msisdn_hash, 
    swap_detected_at DESC
);
