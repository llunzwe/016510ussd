-- ============================================================================
-- App Schema - Configuration Views
-- ============================================================================

-- View: Configuration history
CREATE OR REPLACE VIEW app.v_config_history AS
SELECT 
    config_id,
    application_id,
    config_key,
    config_value,
    previous_value,
    valid_from,
    valid_to,
    is_current,
    changed_by,
    change_reason
FROM app.configuration_store
ORDER BY config_key, valid_from DESC;

COMMENT ON VIEW app.v_config_history IS 'Full configuration change history';

-- View: Business calendar lookup
CREATE OR REPLACE VIEW app.v_business_calendar AS
SELECT 
    calendar_date,
    is_business_day,
    day_of_week,
    fiscal_year,
    fiscal_quarter,
    fiscal_period,
    is_holiday,
    holiday_name,
    country_code
FROM app.business_calendar
WHERE calendar_date >= CURRENT_DATE - interval '1 year'
AND calendar_date <= CURRENT_DATE + interval '1 year';

COMMENT ON VIEW app.v_business_calendar IS 'Business calendar with fiscal periods';

-- View: Fiscal periods overview
CREATE OR REPLACE VIEW app.v_fiscal_periods AS
SELECT 
    fiscal_period_id,
    application_id,
    period_name,
    period_start,
    period_end,
    is_current,
    is_closed,
    closed_at,
    closed_by,
    EXTRACT(DAY FROM (period_end - period_start)) + 1 AS days_in_period
FROM app.fiscal_periods
ORDER BY period_start DESC;

COMMENT ON VIEW app.v_fiscal_periods IS 'Fiscal periods with calculated metadata';

-- View: AI model status
CREATE OR REPLACE VIEW app.v_model_status AS
SELECT 
    model_id,
    model_name,
    model_version,
    model_type,
    risk_level,
    deployment_status,
    bias_audit_completed,
    eu_ai_act_compliant,
    inference_count,
    avg_latency_ms,
    last_inference_at,
    application_id,
    created_at
FROM app.model_registry
ORDER BY created_at DESC;

COMMENT ON VIEW app.v_model_status IS 'AI model deployment status';
