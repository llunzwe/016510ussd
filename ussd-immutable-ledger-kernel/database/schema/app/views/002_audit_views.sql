/**
 * =============================================================================
 * USSD IMMUTABLE LEDGER KERNEL - VIEW: AUDIT VIEWS
 * =============================================================================
 * 
 * Feature:      CORE-APP-VIEW-006
 * Description:  Audit trail views with change tracking, compliance reporting,
 *               and security event monitoring. Supports SOC 2, ISO 27001,
 *               and GDPR audit requirements.
 * 
 * Version:      1.0.0
 * Author:       Eng. llunzwe
 * Created:      2026-03-30
 * Last Modified: 2026-03-30
 * 
 * =============================================================================
 * COMPLIANCE & CERTIFICATIONS
 * =============================================================================
 * 
 * ISO/IEC 27001:2022 (ISMS)
 *   - Control A.5.35: Independent review
 *   - Control A.8.15: Logging
 *   - Control A.8.16: Monitoring activities
 * 
 * ISO/IEC 27018:2019 (PII Protection)
 *   - Section 10: Access to PII audit logs
 * 
 * GDPR (General Data Protection Regulation)
 *   - Article 30: Records of processing
 *   - Article 33: Personal data breach notification
 * 
 * SOC 2 Type II
 *   - CC7.2: System monitoring
 *   - CC4.1: Board oversight
 * 
 * =============================================================================
 * DEPENDENCIES
 * =============================================================================
 * 
 *   - core.t_audit_trail
 *   - app.t_application_registry
 *   - app.t_account_membership
 *   - app.model_registry
 *   - app.inference_log
 *   - app.t_user_role_assignments
 * 
 * =============================================================================
 */

-- =============================================================================
-- COMPLIANCE STANDARDS
-- =============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework
-- ISO/IEC 27018:2019 - PII Protection
-- GDPR - Data Protection
-- SOC 2 Type II - Security Controls
-- =============================================================================

-- =============================================================================
-- VIEW: Application Audit Trail
 * ISO 27001 A.8.15: Security event logging
-- =============================================================================

CREATE OR REPLACE VIEW app.v_application_audit AS
SELECT 
    at.audit_id,
    at.table_name,
    at.record_id,
    at.action,
    at.action_type,
    
    -- Change tracking
    at.old_values,
    at.new_values,
    
    -- Change summary (computed)
    CASE 
        WHEN at.old_values IS NOT NULL AND at.new_values IS NOT NULL THEN
            (
                SELECT jsonb_object_agg(key, jsonb_build_object('from', ov.value, 'to', nv.value))
                FROM jsonb_each(at.old_values) ov
                INNER JOIN jsonb_each(at.new_values) nv ON ov.key = nv.key
                WHERE ov.value IS DISTINCT FROM nv.value
            )
        ELSE NULL
    END as changed_fields,
    
    -- Actor information
    at.performed_by,
    performer.email as performed_by_email,
    performer.display_name as performed_by_name,
    
    -- Context
    at.ip_address,
    at.user_agent,
    at.session_id,
    at.correlation_id,
    
    -- Application context
    at.app_id,
    ar.app_code,
    ar.app_name,
    
    -- Timestamps
    at.performed_at,
    at.recorded_at,
    
    -- Result and severity
    at.result,
    at.severity,
    
    -- Compliance metadata
    at.compliance_frameworks,
    at.retention_until,
    
    -- Verification
    at.ledger_hash,
    at.chain_verified,
    
    -- Classification
    CASE 
        WHEN at.table_name LIKE '%model_registry%' OR at.table_name LIKE '%inference%' THEN 'ai_governance'
        WHEN at.table_name LIKE '%role%' OR at.table_name LIKE '%permission%' THEN 'access_control'
        WHEN at.table_name LIKE '%user%' OR at.table_name LIKE '%membership%' THEN 'user_management'
        WHEN at.severity IN ('critical', 'high') THEN 'security'
        ELSE 'general'
    END as audit_category,
    
    -- Data sensitivity
    CASE 
        WHEN at.table_name LIKE '%model_registry%' THEN 'confidential'
        WHEN at.table_name LIKE '%inference%' THEN 'restricted'
        WHEN at.severity = 'critical' THEN 'restricted'
        ELSE 'internal'
    END as data_classification

FROM core.t_audit_trail at
LEFT JOIN core.t_user_identity performer ON at.performed_by = performer.user_identity_id
LEFT JOIN app.t_application_registry ar ON at.app_id = ar.app_id
WHERE at.table_name LIKE 'app.%' 
   OR at.table_name LIKE 'core.t_audit%'
ORDER BY at.performed_at DESC;

COMMENT ON VIEW app.v_application_audit IS 
    'Application audit trail with change tracking. ' ||
    'ISO 27001 A.8.15: Security event logging. Feature: CORE-APP-VIEW-006';

-- =============================================================================
-- VIEW: Security Events
-- ISO 27001: Security monitoring
-- =============================================================================

CREATE OR REPLACE VIEW app.v_security_events AS
SELECT 
    at.audit_id,
    at.performed_at,
    at.action,
    at.action_type,
    at.table_name,
    at.record_id,
    
    -- Severity classification
    at.severity,
    CASE at.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END as severity_level,
    
    -- Event categorization
    CASE at.action
        WHEN 'AUTH_FAILURE' THEN 'authentication'
        WHEN 'PERMISSION_DENIED' THEN 'authorization'
        WHEN 'BREAK_GLASS_ACCESS' THEN 'emergency_access'
        WHEN 'API_KEY_ROTATE' THEN 'credential_management'
        WHEN 'OWNERSHIP_TRANSFER' THEN 'access_change'
        WHEN 'ROLE_REVOKE' THEN 'access_change'
        WHEN 'HIGH_RISK_INFERENCE' THEN 'ai_governance'
        WHEN 'MODEL_APPROVED_PRODUCTION' THEN 'ai_governance'
        WHEN 'QUOTA_EXCEEDED' THEN 'resource_abuse'
        WHEN 'SUSPEND' THEN 'account_action'
        WHEN 'ARCHIVE' THEN 'account_action'
        ELSE 'other'
    END as event_category,
    
    -- Actor
    at.performed_by,
    performer.email as actor_email,
    at.ip_address,
    at.user_agent,
    
    -- Details
    at.new_values,
    at.details,
    
    -- Response
    at.result,
    
    -- Alert status
    CASE 
        WHEN at.action IN ('AUTH_FAILURE', 'PERMISSION_DENIED') 
         AND at.performed_at > NOW() - INTERVAL '5 minutes'
        THEN 'investigating'
        WHEN at.severity = 'critical' AND at.performed_at > NOW() - INTERVAL '1 hour'
        THEN 'open'
        ELSE 'closed'
    END as alert_status,
    
    -- Application context
    at.app_id,
    ar.app_code

FROM core.t_audit_trail at
LEFT JOIN core.t_user_identity performer ON at.performed_by = performer.user_identity_id
LEFT JOIN app.t_application_registry ar ON at.app_id = ar.app_id
WHERE at.severity IN ('critical', 'high', 'medium')
   OR at.action IN (
       'AUTH_FAILURE',
       'PERMISSION_DENIED',
       'BREAK_GLASS_ACCESS',
       'OWNERSHIP_TRANSFER',
       'HIGH_RISK_INFERENCE',
       'QUOTA_EXCEEDED'
   )
ORDER BY 
    CASE at.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END,
    at.performed_at DESC;

COMMENT ON VIEW app.v_security_events IS 
    'Security events for monitoring and incident response. ' ||
    'ISO 27001: Security monitoring.';

-- =============================================================================
-- VIEW: AI Governance Audit
-- EU AI Act Article 12: Record-keeping for high-risk AI
-- =============================================================================

CREATE OR REPLACE VIEW app.v_ai_governance_audit AS
SELECT 
    -- Inference record
    il.id as inference_id,
    il.request_id,
    il.correlation_id,
    
    -- Model context
    il.model_id,
    mr.name as model_name,
    mr.version as model_version,
    mr.type as model_type,
    mr.risk_level as model_risk_level,
    mr.human_oversight_required,
    
    -- Application context
    il.user_id,
    ui.email as user_email,
    ui.display_name as user_name,
    
    -- Inference details
    il.inference_type,
    il.status as inference_status,
    il.confidence_score,
    il.confidence_threshold,
    
    -- Latency metrics
    il.latency_ms,
    il.preprocessing_latency_ms,
    il.inference_latency_ms,
    il.postprocessing_latency_ms,
    
    -- Token usage
    il.tokens_input,
    il.tokens_output,
    il.compute_units,
    il.cost_estimate_usd,
    
    -- PII handling
    il.contains_pii,
    il.pii_types_detected,
    il.pii_redaction_applied,
    il.data_classification,
    
    -- Compliance
    il.compliance_frameworks,
    il.legal_hold,
    il.retention_until,
    
    -- Integrity verification
    il.input_hash,
    il.output_hash,
    il.ledger_hash,
    il.record_signature,
    il.ledger_sequence,
    il.previous_hash,
    
    -- Chain verification status
    CASE 
        WHEN il.previous_hash IS NULL THEN 'genesis'
        WHEN EXISTS (
            SELECT 1 FROM app.inference_log prev 
            WHERE prev.ledger_hash = il.previous_hash
        ) THEN 'verified'
        ELSE 'broken_chain'
    END as chain_status,
    
    -- Error details
    il.error_code,
    il.error_message,
    il.retry_count,
    
    -- Session context
    il.session_id,
    il.ip_address,
    il.user_agent_hash,
    il.timezone,
    
    -- Billing
    il.billing_tag,
    
    -- Timestamps
    il.request_timestamp,
    il.created_at,
    il.partition_date

FROM app.inference_log il
INNER JOIN app.model_registry mr ON il.model_id = mr.id
LEFT JOIN core.t_user_identity ui ON il.user_id = ui.user_identity_id
WHERE il.deleted_at IS NULL
ORDER BY il.request_timestamp DESC;

COMMENT ON VIEW app.v_ai_governance_audit IS 
    'AI inference audit trail for EU AI Act compliance. ' ||
    'Article 12: Record-keeping for high-risk AI systems.';

-- =============================================================================
-- VIEW: Data Access Audit
 * GDPR Article 30: Records of processing
-- =============================================================================

CREATE OR REPLACE VIEW app.v_data_access_audit AS
SELECT 
    at.audit_id,
    at.performed_at,
    
    -- Data subject (if applicable)
    CASE 
        WHEN at.table_name LIKE '%user%' THEN at.record_id
        WHEN at.new_values ? 'user_identity_id' THEN (at.new_values->>'user_identity_id')::UUID
        ELSE NULL
    END as data_subject_id,
    
    -- Processing activity
    at.action as processing_activity,
    at.table_name as data_category,
    
    -- Legal basis (mapped from action)
    CASE at.action
        WHEN 'CREATE' THEN 'consent'  -- Or legitimate_interest
        WHEN 'UPDATE' THEN 'legitimate_interest'
        WHEN 'DELETE' THEN 'consent_withdrawal'
        WHEN 'ACCESS' THEN 'legitimate_interest'
        ELSE 'legitimate_interest'
    END as legal_basis,
    
    -- Data recipients
    at.app_id,
    ar.app_name,
    
    -- Controller information
    'USSD Immutable Ledger' as controller_name,
    at.performed_by as processor_id,
    
    -- Retention
    at.retention_until,
    
    -- Transfer information
    NULL::TEXT as third_country_transfers,
    
    -- Safeguards
    at.ledger_hash as integrity_hash,
    at.chain_verified as integrity_verified,
    
    -- DPO contact (placeholder)
    'dpo@example.com' as dpo_contact

FROM core.t_audit_trail at
LEFT JOIN app.t_application_registry ar ON at.app_id = ar.app_id
WHERE at.table_name IN (
    'app.t_account_membership',
    'app.t_user_role_assignments',
    'core.t_user_identity'
)
ORDER BY at.performed_at DESC;

COMMENT ON VIEW app.v_data_access_audit IS 
    'Data access audit for GDPR Article 30 compliance. ' ||
    'Records of processing activities.';

-- =============================================================================
-- VIEW: Role Change History
-- ISO 27001 A.9.2.5: Review of access rights
-- =============================================================================

CREATE OR REPLACE VIEW app.v_role_change_history AS
SELECT 
    at.audit_id,
    at.performed_at,
    
    -- Role information
    at.record_id as assignment_id,
    COALESCE(
        at.new_values->>'role_id',
        at.old_values->>'role_id'
    )::UUID as role_id,
    rp.role_name,
    rp.role_code,
    
    -- Membership information
    COALESCE(
        at.new_values->>'membership_id',
        at.old_values->>'membership_id'
    )::UUID as membership_id,
    am.user_identity_id,
    ui.email as user_email,
    ui.display_name as user_name,
    
    -- Application
    am.app_id,
    ar.app_code,
    
    -- Change type
    CASE at.action
        WHEN 'CREATE' THEN 'role_assigned'
        WHEN 'REVOKE' THEN 'role_revoked'
        WHEN 'UPDATE' THEN 'role_modified'
        ELSE at.action
    END as change_type,
    
    -- Assignment details
    at.new_values->>'assignment_type' as assignment_type,
    (at.new_values->>'valid_from')::TIMESTAMPTZ as valid_from,
    (at.new_values->>'valid_until')::TIMESTAMPTZ as valid_until,
    (at.new_values->>'is_break_glass')::BOOLEAN as is_break_glass,
    
    -- Actor
    at.performed_by,
    performer.email as performed_by_email,
    
    -- Justification
    at.new_values->>'justification' as justification,
    at.new_values->>'business_reason' as business_reason,
    
    -- Temporal validity at time of change
    CASE 
        WHEN (at.new_values->>'valid_from')::TIMESTAMPTZ <= at.performed_at
         AND ((at.new_values->>'valid_until')::TIMESTAMPTZ IS NULL 
              OR (at.new_values->>'valid_until')::TIMESTAMPTZ > at.performed_at)
        THEN TRUE
        ELSE FALSE
    END as was_immediately_active

FROM core.t_audit_trail at
LEFT JOIN app.t_roles_permissions rp ON 
    COALESCE(at.new_values->>'role_id', at.old_values->>'role_id')::UUID = rp.role_id
LEFT JOIN app.t_account_membership am ON 
    COALESCE(at.new_values->>'membership_id', at.old_values->>'membership_id')::UUID = am.membership_id
LEFT JOIN core.t_user_identity ui ON am.user_identity_id = ui.user_identity_id
LEFT JOIN app.t_application_registry ar ON am.app_id = ar.app_id
LEFT JOIN core.t_user_identity performer ON at.performed_by = performer.user_identity_id
WHERE at.table_name = 'app.t_user_role_assignments'
  AND at.action IN ('CREATE', 'REVOKE', 'UPDATE', 'STATUS_CHANGE')
ORDER BY at.performed_at DESC;

COMMENT ON VIEW app.v_role_change_history IS 
    'Historical record of all role changes. ' ||
    'ISO 27001 A.9.2.5: Review of access rights.';

-- =============================================================================
-- VIEW: Compliance Dashboard
-- Executive summary for compliance reporting
-- =============================================================================

CREATE OR REPLACE VIEW app.v_compliance_dashboard AS
WITH audit_stats AS (
    SELECT 
        DATE_TRUNC('day', performed_at) as audit_date,
        COUNT(*) as total_events,
        COUNT(*) FILTER (WHERE severity = 'critical') as critical_events,
        COUNT(*) FILTER (WHERE severity = 'high') as high_events,
        COUNT(*) FILTER (WHERE action IN ('AUTH_FAILURE', 'PERMISSION_DENIED')) as access_denials,
        COUNT(*) FILTER (WHERE action = 'BREAK_GLASS_ACCESS') as break_glass_uses,
        COUNT(DISTINCT performed_by) as unique_actors,
        COUNT(DISTINCT app_id) as active_apps
    FROM core.t_audit_trail
    WHERE performed_at > NOW() - INTERVAL '30 days'
    GROUP BY DATE_TRUNC('day', performed_at)
),
ai_stats AS (
    SELECT 
        DATE_TRUNC('day', created_at) as inference_date,
        COUNT(*) as total_inferences,
        COUNT(*) FILTER (WHERE risk_level = 'high') as high_risk_inferences,
        COUNT(*) FILTER (WHERE contains_pii = TRUE) as pii_inferences,
        COUNT(*) FILTER (WHERE status != 'success') as failed_inferences,
        AVG(latency_ms) FILTER (WHERE status = 'success') as avg_latency_ms,
        SUM(cost_estimate_usd) as total_cost
    FROM app.inference_log il
    INNER JOIN app.model_registry mr ON il.model_id = mr.id
    WHERE il.created_at > NOW() - INTERVAL '30 days'
    GROUP BY DATE_TRUNC('day', created_at)
)

SELECT 
    COALESCE(a.audit_date, ai.inference_date) as report_date,
    
    -- Audit metrics
    COALESCE(a.total_events, 0) as audit_events,
    COALESCE(a.critical_events, 0) as critical_events,
    COALESCE(a.high_events, 0) as high_events,
    COALESCE(a.access_denials, 0) as access_denials,
    COALESCE(a.break_glass_uses, 0) as break_glass_uses,
    COALESCE(a.unique_actors, 0) as unique_users,
    COALESCE(a.active_apps, 0) as active_applications,
    
    -- AI metrics
    COALESCE(ai.total_inferences, 0) as ai_inferences,
    COALESCE(ai.high_risk_inferences, 0) as high_risk_inferences,
    COALESCE(ai.pii_inferences, 0) as pii_inferences,
    COALESCE(ai.failed_inferences, 0) as failed_inferences,
    ROUND(COALESCE(ai.avg_latency_ms, 0)::NUMERIC, 2) as avg_inference_latency_ms,
    ROUND(COALESCE(ai.total_cost, 0)::NUMERIC, 6) as total_inference_cost,
    
    -- Compliance scores (0-100)
    CASE 
        WHEN a.critical_events > 0 THEN GREATEST(0, 100 - (a.critical_events * 10))
        ELSE 100
    END as security_score,
    
    CASE 
        WHEN ai.total_inferences > 0 
        THEN ROUND(((ai.total_inferences - ai.pii_inferences)::NUMERIC / ai.total_inferences) * 100, 2)
        ELSE 100
    END as pii_compliance_score,
    
    -- Status
    CASE 
        WHEN a.critical_events > 5 OR ai.failed_inferences > ai.total_inferences * 0.1
        THEN 'critical'
        WHEN a.high_events > 10 OR ai.pii_inferences > ai.total_inferences * 0.05
        THEN 'warning'
        ELSE 'healthy'
    END as compliance_status,
    
    -- Report metadata
    NOW() as generated_at,
    'automated' as report_type

FROM audit_stats a
FULL OUTER JOIN ai_stats ai ON a.audit_date = ai.inference_date
ORDER BY COALESCE(a.audit_date, ai.inference_date) DESC;

COMMENT ON VIEW app.v_compliance_dashboard IS 
    'Compliance dashboard with security and AI governance metrics. ' ||
    'Supports SOC 2, ISO 27001, and EU AI Act reporting.';

-- =============================================================================
-- VIEW: Audit Retention Status
 * GDPR: Data retention management
-- =============================================================================

CREATE OR REPLACE VIEW app.v_audit_retention_status AS
SELECT 
    -- Audit record info
    at.audit_id,
    at.table_name,
    at.action,
    at.performed_at,
    
    -- Retention policy
    at.retention_until,
    at.compliance_frameworks,
    
    -- Days until expiry
    CASE 
        WHEN at.retention_until IS NOT NULL 
        THEN (at.retention_until - CURRENT_DATE)
        ELSE NULL
    END as days_until_expiry,
    
    -- Retention status
    CASE 
        WHEN at.retention_until IS NULL THEN 'indefinite'
        WHEN at.retention_until < CURRENT_DATE THEN 'expired'
        WHEN at.retention_until < CURRENT_DATE + INTERVAL '30 days' THEN 'expiring_soon'
        ELSE 'active'
    END as retention_status,
    
    -- Can purge
    CASE 
        WHEN at.legal_hold = TRUE THEN FALSE
        WHEN at.retention_until IS NULL THEN FALSE
        WHEN at.retention_until < CURRENT_DATE THEN TRUE
        ELSE FALSE
    END as can_purge,
    
    -- Legal hold
    at.legal_hold,
    
    -- Data classification
    CASE 
        WHEN at.table_name LIKE '%inference%' THEN 'restricted'
        WHEN at.severity IN ('critical', 'high') THEN 'confidential'
        ELSE 'internal'
    END as data_classification,
    
    -- Recommended action
    CASE 
        WHEN at.legal_hold = TRUE THEN 'retain_legal_hold'
        WHEN at.retention_until IS NULL THEN 'review_retention_policy'
        WHEN at.retention_until < CURRENT_DATE - INTERVAL '90 days' THEN 'purge_eligible'
        WHEN at.retention_until < CURRENT_DATE THEN 'ready_for_purge'
        WHEN at.retention_until < CURRENT_DATE + INTERVAL '30 days' THEN 'notify_expiry'
        ELSE 'retain'
    END as recommended_action

FROM core.t_audit_trail at
WHERE at.performed_at < NOW() - INTERVAL '1 year'  -- Focus on older records
ORDER BY at.retention_until NULLS LAST;

COMMENT ON VIEW app.v_audit_retention_status IS 
    'Audit record retention status for GDPR compliance. ' ||
    'Identifies records eligible for purging.';

-- =============================================================================
-- VIEW: Chain of Custody
 * Immutable ledger verification
-- =============================================================================

CREATE OR REPLACE VIEW app.v_chain_of_custody AS
WITH ordered_records AS (
    SELECT 
        audit_id,
        table_name,
        record_id,
        action,
        performed_at,
        performed_by,
        ledger_hash,
        previous_hash,
        ledger_sequence,
        ROW_NUMBER() OVER (ORDER BY ledger_sequence) as row_num
    FROM core.t_audit_trail
    WHERE ledger_sequence IS NOT NULL
    ORDER BY ledger_sequence
)

SELECT 
    or1.audit_id,
    or1.table_name,
    or1.record_id,
    or1.action,
    or1.performed_at,
    or1.performed_by,
    or1.ledger_sequence,
    or1.ledger_hash,
    or1.previous_hash,
    
    -- Verify chain link
    CASE 
        WHEN or1.row_num = 1 AND or1.previous_hash IS NULL THEN 'genesis'
        WHEN or1.previous_hash = or2.ledger_hash THEN 'verified'
        WHEN or1.previous_hash IS NULL THEN 'orphaned'
        ELSE 'broken'
    END as link_status,
    
    -- Hash verification
    CASE 
        WHEN or1.ledger_hash = encode(
            digest(
                or1.table_name || or1.record_id::TEXT || or1.action || or1.performed_at::TEXT,
                'sha256'
            ),
            'hex'
        ) THEN 'hash_verified'
        ELSE 'hash_mismatch'
    END as hash_verification,
    
    -- Gap detection
    CASE 
        WHEN or1.row_num > 1 AND or1.ledger_sequence != or2.ledger_sequence + 1 THEN 'sequence_gap'
        ELSE 'sequence_ok'
    END as sequence_status

FROM ordered_records or1
LEFT JOIN ordered_records or2 ON or1.row_num = or2.row_num + 1
ORDER BY or1.ledger_sequence;

COMMENT ON VIEW app.v_chain_of_custody IS 
    'Audit trail chain of custody verification. ' ||
    'Immutable ledger integrity validation.';

-- =============================================================================
-- GRANTS
-- =============================================================================
-- Note: Actual grants depend on role setup
-- GRANT SELECT ON app.v_application_audit TO app_auditor;
-- GRANT SELECT ON app.v_security_events TO app_security;

-- =============================================================================
-- IMPLEMENTATION NOTES
-- =============================================================================
-- 1. All audit views reference core.t_audit_trail for central logging
-- 2. Chain verification uses cryptographic hash comparison
-- 3. Retention views support automated purging workflows
-- 4. AI governance view joins to model_registry for risk context
-- 5. Consider partitioning audit_trail by date for performance
-- =============================================================================
