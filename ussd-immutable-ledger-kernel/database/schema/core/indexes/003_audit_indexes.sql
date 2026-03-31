-- ============================================================================
-- Audit and Compliance Indexes
-- ============================================================================

-- Audit trail queries
CREATE INDEX IF NOT EXISTS idx_audit_table ON core.audit_trail(table_name, changed_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_record ON core.audit_trail(record_id, changed_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_action ON core.audit_trail(action, changed_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_user ON core.audit_trail(changed_by, changed_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_transaction ON core.audit_trail(transaction_id);

CREATE INDEX IF NOT EXISTS idx_audit_severity ON core.audit_trail(severity, changed_at DESC);

-- Hash chain verification
CREATE INDEX IF NOT EXISTS idx_audit_hash ON core.audit_trail(record_hash);

-- Suspense items
CREATE INDEX IF NOT EXISTS idx_suspense_status ON core.suspense_items(status, created_at);

CREATE INDEX IF NOT EXISTS idx_suspense_age ON core.suspense_items(aging_days DESC);

-- Idempotency keys
CREATE UNIQUE INDEX IF NOT EXISTS idx_idempotency_hash ON core.idempotency_keys(key_hash);

CREATE INDEX IF NOT EXISTS idx_idempotency_expires ON core.idempotency_keys(expires_at);

-- Archive manifest
CREATE INDEX IF NOT EXISTS idx_archive_status ON core.archive_manifest(status, created_at);

CREATE INDEX IF NOT EXISTS idx_archive_destruction ON core.archive_manifest(scheduled_destruction_date);
