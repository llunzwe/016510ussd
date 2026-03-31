-- ============================================================================
-- App Schema - Configuration Indexes
-- ============================================================================

-- Configuration store
CREATE INDEX IF NOT EXISTS idx_config_app_key ON app.configuration_store(application_id, config_key, is_current);
CREATE INDEX IF NOT EXISTS idx_config_current ON app.configuration_store(is_current, valid_from DESC);

-- Feature flags
CREATE INDEX IF NOT EXISTS idx_flags_app ON app.feature_flags(application_id, feature_name, is_current);
CREATE INDEX IF NOT EXISTS idx_flags_enabled ON app.feature_flags(enabled, rollout_percentage);

-- Business calendar
CREATE INDEX IF NOT EXISTS idx_calendar_date ON app.business_calendar(calendar_date, is_business_day);
CREATE INDEX IF NOT EXISTS idx_calendar_app ON app.business_calendar(application_id, calendar_date);

-- Fiscal periods
CREATE INDEX IF NOT EXISTS idx_fiscal_current ON app.fiscal_periods(is_current, period_start);
CREATE INDEX IF NOT EXISTS idx_fiscal_app ON app.fiscal_periods(application_id, period_start);

-- Retention policies
CREATE INDEX IF NOT EXISTS idx_retention_app ON app.retention_policies(application_id, policy_type);

-- AI schema indexes
CREATE INDEX IF NOT EXISTS idx_model_registry_app ON app.model_registry(application_id, deployment_status);
CREATE INDEX IF NOT EXISTS idx_model_registry_risk ON app.model_registry(risk_level, bias_audit_completed);
CREATE INDEX IF NOT EXISTS idx_inference_log_model ON app.inference_log(model_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_inference_log_session ON app.inference_log(session_id);
