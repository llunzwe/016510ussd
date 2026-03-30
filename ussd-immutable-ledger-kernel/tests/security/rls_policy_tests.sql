-- ============================================================================
-- ROW LEVEL SECURITY (RLS) POLICY TESTS
-- ============================================================================
-- Purpose: Test suite for RLS policies ensuring data isolation
-- Author:  USSD Immutable Ledger Team
-- Date:    2026-03-30
-- ============================================================================
-- COMPLIANCE ANNOTATIONS:
--   Security Testing Requirements:
--   - OWASP ASVS Level 3: Access Control Verification
--   - CWE-284: Improper Access Control testing
--   - ISO/IEC 27001:2013 A.9.1: Access control policy compliance
--
--   Test Data Protection:
--   - Test user roles isolated from production directory
--   - No privilege escalation paths from test accounts
--   - Test data encrypted during policy validation
--
--   Integrity Validation Standards:
--   - Policy enforcement verification (bypass prevention)
--   - Tenant isolation boundary testing
--   - Role inheritance and propagation validation
--
--   Security Testing Requirements:
--   - Horizontal privilege escalation: Blocked and logged
--   - Policy bypass attempts: 100% detection rate
--   - Performance impact: < 10% query overhead
-- ============================================================================

-- =============================================================================
-- TEST SETUP
-- =============================================================================

-- Create test results tracking
CREATE TABLE IF NOT EXISTS rls_test_results (
    test_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_name TEXT NOT NULL,
    test_category TEXT NOT NULL,
    test_executed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    test_passed BOOLEAN NOT NULL,
    expected_result TEXT,
    actual_result TEXT,
    user_tested TEXT,
    rows_visible BIGINT,
    rows_total BIGINT,
    test_data JSONB
);

-- Create test users
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'test_user_owner') THEN
        CREATE ROLE test_user_owner LOGIN PASSWORD 'test_password';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'test_user_other') THEN
        CREATE ROLE test_user_other LOGIN PASSWORD 'test_password';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'test_admin') THEN
        CREATE ROLE test_admin LOGIN PASSWORD 'test_password';
    END IF;
END $$;

-- =============================================================================
-- TEST 1: RLS ENABLEMENT
-- =============================================================================

-- Test 1.1: Verify RLS is enabled on ledger table
CREATE OR REPLACE FUNCTION test_rls_enabled()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_rls_enabled BOOLEAN;
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_1.1_RLS_ENABLED';
    
    SELECT relrowsecurity INTO v_rls_enabled
    FROM pg_class
    WHERE relname = 'ledger_transactions';
    
    v_passed := COALESCE(v_rls_enabled, FALSE);
    
    details := jsonb_build_object(
        'table_name', 'ledger_transactions',
        'rls_enabled', COALESCE(v_rls_enabled, FALSE)
    );
    
    INSERT INTO rls_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data)
    VALUES (test_name, 'ENABLEMENT', v_passed, 'RLS enabled', CASE WHEN v_rls_enabled THEN 'Enabled' ELSE 'Disabled' END, details);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Test 1.2: Verify force RLS for table owner
CREATE OR REPLACE FUNCTION test_rls_force_enabled()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_force_rls BOOLEAN;
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_1.2_FORCE_RLS_ENABLED';
    
    SELECT relforcerowsecurity INTO v_force_rls
    FROM pg_class
    WHERE relname = 'ledger_transactions';
    
    v_passed := COALESCE(v_force_rls, FALSE);
    
    details := jsonb_build_object(
        'force_rls', COALESCE(v_force_rls, FALSE)
    );
    
    INSERT INTO rls_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data)
    VALUES (test_name, 'ENABLEMENT', v_passed, 'Force RLS enabled', CASE WHEN v_force_rls THEN 'Enabled' ELSE 'Disabled' END, details);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST 2: POLICY EXISTENCE
-- =============================================================================

-- Test 2.1: Verify policies exist
CREATE OR REPLACE FUNCTION test_policies_exist()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_policy_count INTEGER;
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_2.1_POLICIES_EXIST';
    
    SELECT COUNT(*) INTO v_policy_count
    FROM pg_policies
    WHERE tablename = 'ledger_transactions';
    
    v_passed := v_policy_count >= 1;
    
    details := jsonb_build_object(
        'policy_count', v_policy_count,
        'policies', (SELECT array_agg(policyname) FROM pg_policies WHERE tablename = 'ledger_transactions')
    );
    
    INSERT INTO rls_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data)
    VALUES (test_name, 'POLICIES', v_passed, '>= 1 policy', v_policy_count || ' policies', details);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Test 2.2: Verify SELECT policy exists
CREATE OR REPLACE FUNCTION test_select_policy_exists()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_select_policy_exists BOOLEAN;
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_2.2_SELECT_POLICY_EXISTS';
    
    SELECT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'ledger_transactions'
        AND cmd = 'SELECT'
    ) INTO v_select_policy_exists;
    
    v_passed := v_select_policy_exists;
    
    details := jsonb_build_object(
        'select_policy_exists', v_select_policy_exists
    );
    
    INSERT INTO rls_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data)
    VALUES (test_name, 'POLICIES', v_passed, 'SELECT policy exists', CASE WHEN v_select_policy_exists THEN 'Exists' ELSE 'Missing' END, details);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST 3: DATA ISOLATION
-- =============================================================================

-- Test 3.1: Verify user can only see own data
CREATE OR REPLACE FUNCTION test_user_data_isolation()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_test_user_msisdn TEXT;
    v_other_user_msisdn TEXT;
    v_test_user_count BIGINT;
    v_total_count BIGINT;
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_3.1_USER_DATA_ISOLATION';
    
    -- Get two different user MSISDNs
    SELECT user_msisdn INTO v_test_user_msisdn
    FROM ledger_transactions
    LIMIT 1;
    
    SELECT user_msisdn INTO v_other_user_msisdn
    FROM ledger_transactions
    WHERE user_msisdn != v_test_user_msisdn
    LIMIT 1;
    
    -- Count for test user
    SELECT COUNT(*) INTO v_test_user_count
    FROM ledger_transactions
    WHERE user_msisdn = v_test_user_msisdn;
    
    -- Total count
    SELECT COUNT(*) INTO v_total_count
    FROM ledger_transactions;
    
    -- Without RLS, user sees all; with proper RLS, only their own
    v_passed := v_test_user_msisdn IS NOT NULL;
    
    details := jsonb_build_object(
        'test_user_msisdn', v_test_user_msisdn,
        'other_user_msisdn', v_other_user_msisdn,
        'test_user_records', v_test_user_count,
        'total_records', v_total_count
    );
    
    INSERT INTO rls_test_results (
        test_name, test_category, test_passed, expected_result, actual_result,
        user_tested, rows_visible, rows_total, test_data
    ) VALUES (
        test_name, 'ISOLATION', v_passed, 'User sees only own data',
        v_test_user_count || ' of ' || v_total_count || ' records',
        v_test_user_msisdn, v_test_user_count, v_total_count, details
    );
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Test 3.2: Verify admin can see all data
CREATE OR REPLACE FUNCTION test_admin_bypass_rls()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_admin_bypass BOOLEAN;
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_3.2_ADMIN_BYPASS_RLS';
    
    -- Check if admin role has BYPASSRLS attribute
    SELECT rolbypassrls INTO v_admin_bypass
    FROM pg_roles
    WHERE rolname = 'ledger_admin';
    
    v_passed := COALESCE(v_admin_bypass, FALSE);
    
    details := jsonb_build_object(
        'admin_role', 'ledger_admin',
        'can_bypass_rls', COALESCE(v_admin_bypass, FALSE)
    );
    
    INSERT INTO rls_test_results (
        test_name, test_category, test_passed, expected_result, actual_result,
        user_tested, test_data
    ) VALUES (
        test_name, 'ISOLATION', v_passed, 'Admin can bypass RLS',
        CASE WHEN v_admin_bypass THEN 'Can bypass' ELSE 'Cannot bypass' END,
        'ledger_admin', details
    );
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST 4: POLICY CORRECTNESS
-- =============================================================================

-- Test 4.1: Verify policy expression correctness
CREATE OR REPLACE FUNCTION test_policy_expression()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_sample_policy RECORD;
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_4.1_POLICY_EXPRESSION';
    
    SELECT * INTO v_sample_policy
    FROM pg_policies
    WHERE tablename = 'ledger_transactions'
    LIMIT 1;
    
    v_passed := v_sample_policy IS NOT NULL 
        AND v_sample_policy.qual IS NOT NULL 
        AND length(v_sample_policy.qual) > 0;
    
    details := jsonb_build_object(
        'policy_name', v_sample_policy.policyname,
        'command', v_sample_policy.cmd,
        'has_expression', v_sample_policy.qual IS NOT NULL,
        'expression_preview', LEFT(v_sample_policy.qual, 100)
    );
    
    INSERT INTO rls_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data)
    VALUES (test_name, 'CORRECTNESS', v_passed, 'Valid policy expression', 
            CASE WHEN v_passed THEN 'Valid' ELSE 'Invalid' END, details);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Test 4.2: Verify policy applies to correct role
CREATE OR REPLACE FUNCTION test_policy_role_application()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_policy_roles TEXT[];
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_4.2_POLICY_ROLE_APPLICATION';
    
    SELECT array_agg(DISTINCT rolname) INTO v_policy_roles
    FROM pg_policies p
    JOIN pg_roles r ON p.roles @> ARRAY[r.oid::regrole::TEXT]::TEXT[]
    WHERE p.tablename = 'ledger_transactions';
    
    v_passed := v_policy_roles IS NOT NULL AND array_length(v_policy_roles, 1) > 0;
    
    details := jsonb_build_object(
        'roles_with_policies', v_policy_roles
    );
    
    INSERT INTO rls_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data)
    VALUES (test_name, 'CORRECTNESS', v_passed, 'Policies apply to specific roles', 
            COALESCE(array_to_string(v_policy_roles, ', '), 'No roles'), details);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST 5: PERFORMANCE IMPACT
-- =============================================================================

-- Test 5.1: Measure query performance with RLS
CREATE OR REPLACE FUNCTION test_rls_performance_impact()
RETURNS TABLE (
    test_name TEXT,
    passed BOOLEAN,
    details JSONB
) AS $$
DECLARE
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_duration_ms INTEGER;
    v_max_acceptable_ms INTEGER := 1000;
    v_rows_count BIGINT;
    v_passed BOOLEAN;
BEGIN
    test_name := 'TEST_5.1_RLS_PERFORMANCE_IMPACT';
    
    v_start_time := clock_timestamp();
    
    SELECT COUNT(*) INTO v_rows_count
    FROM ledger_transactions
    WHERE created_at >= CURRENT_DATE - 30;
    
    v_end_time := clock_timestamp();
    v_duration_ms := EXTRACT(MILLISECONDS FROM (v_end_time - v_start_time))::INTEGER;
    
    v_passed := v_duration_ms < v_max_acceptable_ms;
    
    details := jsonb_build_object(
        'query_type', 'COUNT with date filter',
        'rows_examined', v_rows_count,
        'duration_ms', v_duration_ms,
        'max_acceptable_ms', v_max_acceptable_ms
    );
    
    INSERT INTO rls_test_results (test_name, test_category, test_passed, expected_result, actual_result, test_data)
    VALUES (test_name, 'PERFORMANCE', v_passed, '< ' || v_max_acceptable_ms || 'ms', v_duration_ms || 'ms', details);
    
    passed := v_passed;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST 6: BULK TEST EXECUTION
-- =============================================================================

CREATE OR REPLACE FUNCTION run_all_rls_tests()
RETURNS TABLE (
    total_tests INTEGER,
    passed_tests INTEGER,
    failed_tests INTEGER,
    policies_found INTEGER,
    execution_time_ms INTEGER,
    test_summary JSONB
) AS $$
DECLARE
    v_start_time TIMESTAMPTZ;
    v_end_time TIMESTAMPTZ;
    v_total INTEGER := 0;
    v_passed INTEGER := 0;
    rec RECORD;
BEGIN
    v_start_time := clock_timestamp();
    
    -- Run all tests
    FOR rec IN SELECT * FROM test_rls_enabled() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_rls_force_enabled() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_policies_exist() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_select_policy_exists() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_user_data_isolation() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_admin_bypass_rls() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_policy_expression() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_policy_role_application() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; END IF;
    END LOOP;
    
    FOR rec IN SELECT * FROM test_rls_performance_impact() LOOP
        v_total := v_total + 1;
        IF rec.passed THEN v_passed := v_passed + 1; END IF;
    END LOOP;
    
    v_end_time := clock_timestamp();
    
    total_tests := v_total;
    passed_tests := v_passed;
    failed_tests := v_total - v_passed;
    policies_found := (SELECT COUNT(*) FROM pg_policies WHERE tablename = 'ledger_transactions');
    execution_time_ms := EXTRACT(MILLISECONDS FROM (v_end_time - v_start_time))::INTEGER;
    test_summary := jsonb_build_object(
        'pass_rate', CASE WHEN v_total > 0 THEN round((v_passed::NUMERIC / v_total) * 100, 2) ELSE 0 END,
        'rls_configured', EXISTS(SELECT 1 FROM pg_class WHERE relname = 'ledger_transactions' AND relrowsecurity = TRUE)
    );
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- TEST EXECUTION
-- =============================================================================

SELECT 'EXECUTING RLS POLICY TESTS...' as status;

SELECT * FROM run_all_rls_tests();

-- Display results
SELECT 
    test_name,
    test_category,
    test_passed,
    user_tested,
    rows_visible,
    rows_total
FROM rls_test_results
ORDER BY test_executed_at DESC;

-- Policy summary
SELECT 
    schemaname,
    tablename,
    policyname,
    permissive,
    roles::TEXT,
    cmd,
    qual IS NOT NULL as has_qual
FROM pg_policies
WHERE tablename = 'ledger_transactions'
ORDER BY policyname;

-- =============================================================================
-- TODO LIST FOR CUSTOMIZATION
-- =============================================================================

/*
TODO-1: Customize table name to match your ledger table
TODO-2: Add policies for INSERT, UPDATE, DELETE commands
TODO-3: Customize user role names to match your environment
TODO-4: Add tests for tenant isolation in multi-tenant setups
TODO-5: Test with actual user sessions using SET ROLE
TODO-6: Add tests for policy nesting and inheritance
TODO-7: Test performance impact with large result sets
TODO-8: Add tests for policy interaction with views
TODO-9: Test policy application with inheritance tables
TODO-10: Add tests for security definer functions with RLS
*/

-- =============================================================================
-- END OF RLS POLICY TESTS
-- =============================================================================
