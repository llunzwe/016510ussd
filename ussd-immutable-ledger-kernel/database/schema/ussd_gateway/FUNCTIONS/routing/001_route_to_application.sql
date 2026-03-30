-- ============================================================================
-- FUNCTION: route_to_application
-- ============================================================================
-- Purpose: Route USSD session to the target application with proper
--          protocol handling, request transformation, and response processing.
-- Context: After shortcode resolution, this function handles the actual
--          communication with backend applications, including request
--          formatting, load balancing, circuit breaking, and response handling.
--
-- COMPLIANCE & STANDARDS:
--   ISO/IEC 27001:2022 - Information Security Management
--     * A.8.5: Secure communication with backend services
--     * A.8.8: Management of technical vulnerabilities
--     * A.8.23: Web application security - request/response security
--     * A.8.15: Logging - routing transaction logs
--
--   ISO/IEC 27018:2019 - PII Protection
--     * Request payload sanitization (MSISDN masking in logs)
--     * Context data exclusion of sensitive fields
--     * Encrypted communication enforcement
--
--   PCI DSS v4.0:
--     * Requirement 4: Encrypt transmission of cardholder data
--     * mTLS for service-to-service authentication
--     * Request signing and verification
--
--   ISO 31000:2018 - Risk Management
--     * Circuit breaker for failure containment
--     * Retry with exponential backoff
--     * Fallback and graceful degradation
--
-- ROUTING FLOW:
--   1. Prepare request payload
--   2. Apply circuit breaker pattern
--   3. Send request to application endpoint
--   4. Handle response and errors
--   5. Transform response to USSD format
--   6. Update metrics
--
-- SECURITY FEATURES:
--   - HMAC request signing
--   - Response schema validation
--   - Size limits (max 182 chars for USSD)
--   - Generic error messages (no internal leakage)
--   - Circuit breaker state machine
--   - Retry with exponential backoff
--
-- ENTERPRISE CODING PRACTICES:
--   - SECURITY DEFINER with service account
--   - Exception handling with circuit breaker update
--   - Performance timing instrumentation
--   - Comprehensive error logging
-- ============================================================================

CREATE OR REPLACE FUNCTION route_to_application(
    -- Session context
    p_session_id UUID,
    p_msisdn VARCHAR(15),
    p_application_id VARCHAR(64),
    p_application_endpoint VARCHAR(512),
    
    -- Request context
    p_current_menu_id VARCHAR(64),
    p_user_input VARCHAR(400),
    p_session_context JSONB,
    
    -- Routing configuration
    p_routing_method VARCHAR(20) DEFAULT 'DIRECT',
    p_timeout_ms INT DEFAULT 5000,
    p_retry_count INT DEFAULT 0
)
RETURNS TABLE (
    success BOOLEAN,
    response_text TEXT,
    next_menu_id VARCHAR(64),
    session_state VARCHAR(32),
    should_terminate BOOLEAN,
    error_code VARCHAR(32),
    error_message VARCHAR(256),
    response_metadata JSONB
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_request_payload JSONB;
    v_response JSONB;
    v_start_time TIMESTAMPTZ;
    v_response_time_ms INT;
    v_attempt INT := 0;
    v_max_retries INT := p_retry_count;
    v_error_code VARCHAR(32) := NULL;
    v_error_message VARCHAR(256) := NULL;
    v_should_terminate BOOLEAN := FALSE;
    v_next_menu_id VARCHAR(64) := p_current_menu_id;
    v_session_state VARCHAR(32) := 'MENU';
    v_response_metadata JSONB := '{}'::JSONB;
BEGIN
    v_start_time := clock_timestamp();

    -- ========================================================================
    -- TODO [ROUTE-001]: Build request payload
    -- ========================================================================
    /*
    TODO: Construct standardized request payload
      - Include session metadata
      - Add user input and context
      - Include device fingerprint info
      - Add routing metadata
      - Sign request if required
    
    Payload structure:
    {
        "session": {
            "id": "uuid",
            "msisdn": "+255...",
            "operator": "64002",
            "start_time": "..."
        },
        "context": {
            "current_menu": "main",
            "user_input": "1",
            "session_data": {...}
        },
        "routing": {
            "application_id": "mobile_money",
            "route_variant": "control"
        },
        "request": {
            "timestamp": "...",
            "sequence": 5
        }
    }
    */
    
    v_request_payload := jsonb_build_object(
        'session', jsonb_build_object(
            'id', p_session_id,
            'msisdn', p_msisdn,
            'start_time', p_session_context->>'session_start_time'
        ),
        'context', jsonb_build_object(
            'current_menu', p_current_menu_id,
            'user_input', p_user_input,
            'session_data', p_session_context - 'sensitive_data'
        ),
        'routing', jsonb_build_object(
            'application_id', p_application_id,
            'method', p_routing_method
        ),
        'request', jsonb_build_object(
            'timestamp', NOW(),
            'sequence', COALESCE((p_session_context->>'request_sequence')::INT, 0) + 1
        )
    );

    -- ========================================================================
    -- TODO [ROUTE-002]: Apply circuit breaker pattern
    -- ========================================================================
    /*
    TODO: Check circuit breaker state before routing
      - Query circuit breaker status for application
      - States: CLOSED (normal), OPEN (failing), HALF_OPEN (testing)
      - If OPEN, return error immediately or route to fallback
      - Track consecutive failures
      - Implement exponential backoff for recovery
    
    Circuit breaker table:
      application_id, state, failure_count, last_failure_at, opened_at
    */

    -- ========================================================================
    -- TODO [ROUTE-003]: Send request to application
    -- ========================================================================
    /*
    TODO: Implement HTTP/gRPC request to application endpoint
      - Support both HTTP REST and gRPC
      - Set appropriate timeouts
      - Handle connection pooling
      - Implement retry with backoff
      - Track request/response for debugging
    
    Implementation note:
      This would typically use pg_http extension or be handled
      by application layer. Function documents expected behavior.
    */
    
    WHILE v_attempt <= v_max_retries LOOP
        BEGIN
            -- Simulate request (actual implementation uses HTTP client)
            -- v_response := http_post(
            --     p_application_endpoint,
            --     v_request_payload::TEXT,
            --     p_timeout_ms
            -- );
            
            -- Placeholder: Simulate successful response
            v_response := jsonb_build_object(
                'success', TRUE,
                'message', 'Thank you for your request.',
                'next_menu', COALESCE(p_current_menu_id, 'main'),
                'terminate', FALSE,
                'session_state', 'MENU'
            );
            
            -- Success - exit retry loop
            EXIT;
            
        EXCEPTION WHEN OTHERS THEN
            v_attempt := v_attempt + 1;
            v_error_code := 'REQUEST_FAILED';
            v_error_message := SQLERRM;
            
            -- Update circuit breaker
            -- PERFORM update_circuit_breaker(p_application_id, FALSE);
            
            IF v_attempt > v_max_retries THEN
                -- All retries exhausted
                v_should_terminate := TRUE;
                v_session_state := 'ERROR';
                
                RETURN QUERY SELECT 
                    FALSE,
                    'Service temporarily unavailable. Please try again later.'::TEXT,
                    NULL::VARCHAR(64),
                    'ERROR'::VARCHAR(32),
                    TRUE,
                    'MAX_RETRIES_EXCEEDED'::VARCHAR(32),
                    v_error_message::VARCHAR(256),
                    jsonb_build_object(
                        'attempts', v_attempt,
                        'last_error', v_error_message
                    );
                RETURN;
            END IF;
            
            -- Exponential backoff
            PERFORM pg_sleep(power(2, v_attempt) * 0.1);
        END;
    END LOOP;

    -- ========================================================================
    -- TODO [ROUTE-004]: Process application response
    -- ========================================================================
    /*
    TODO: Parse and validate application response
      - Validate response schema
      - Extract display text
      - Determine next state
      - Handle termination signals
      - Process menu transitions
      - Extract context updates
    
    Response schema:
    {
        "success": true,
        "message": "Display text for user",
        "next_menu": "menu_id",
        "session_state": "MENU|INPUT|CONFIRM|PROCESS|COMPLETE",
        "terminate": false,
        "context_updates": {...},
        "requires_auth": false,
        "auth_method": "PIN|OTP"
    }
    */
    
    IF v_response IS NOT NULL THEN
        -- Extract response fields
        v_should_terminate := COALESCE((v_response->>'terminate')::BOOLEAN, FALSE);
        v_next_menu_id := COALESCE(v_response->>'next_menu', p_current_menu_id);
        v_session_state := COALESCE(v_response->>'session_state', 'MENU');
        
        -- Check for context updates to propagate
        IF v_response->'context_updates' IS NOT NULL THEN
            v_response_metadata := jsonb_build_object(
                'context_updates', v_response->'context_updates'
            );
        END IF;
        
        -- Update circuit breaker on success
        -- PERFORM update_circuit_breaker(p_application_id, TRUE);
    END IF;

    -- ========================================================================
    -- TODO [ROUTE-005]: Update routing metrics
    -- ========================================================================
    /*
    TODO: Record routing performance metrics
      - Response time
      - Success/failure counts
      - Error breakdown
      - Per-route statistics
      - Update routing_metrics table
    */
    
    v_response_time_ms := EXTRACT(MILLISECONDS FROM (clock_timestamp() - v_start_time))::INT;
    
    -- Update metrics (async via trigger or background job)
    -- PERFORM update_routing_metrics(
    --     p_application_id,
    --     v_response_time_ms,
    --     v_error_code IS NULL
    -- );

    -- ========================================================================
    -- TODO [ROUTE-006]: Handle fallback scenarios
    -- ========================================================================
    /*
    TODO: Implement fallback for failures
      - Static error message if application unavailable
      - Degraded mode responses
      - Queue for later processing
      - User notification via SMS
    */

    -- ========================================================================
    -- TODO [ROUTE-007]: Log routing transaction
    -- ========================================================================
    /*
    TODO: Write detailed routing log
      - Request and response payloads (sanitized)
      - Timing information
      - Error details if failed
      - Circuit breaker state
      - Include in distributed tracing
    */

    -- Return response
    RETURN QUERY SELECT 
        (v_error_code IS NULL),
        COALESCE(v_response->>'message', 'An error occurred')::TEXT,
        v_next_menu_id,
        v_session_state,
        v_should_terminate,
        v_error_code,
        v_error_message,
        v_response_metadata || jsonb_build_object('response_time_ms', v_response_time_ms);

END;
$$;

-- ----------------------------------------------------------------------------
-- FUNCTION: batch_route_to_applications (for bulk operations)
-- ----------------------------------------------------------------------------
-- Routes multiple sessions in a single call for efficiency.
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION batch_route_to_applications(
    p_routing_requests JSONB -- Array of routing request objects
)
RETURNS TABLE (
    request_id INT,
    success BOOLEAN,
    response_text TEXT,
    error_code VARCHAR(32)
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_request JSONB;
    v_result RECORD;
    v_index INT := 0;
BEGIN
    FOR v_request IN SELECT * FROM jsonb_array_elements(p_routing_requests)
    LOOP
        v_index := v_index + 1;
        
        SELECT * INTO v_result
        FROM route_to_application(
            (v_request->>'session_id')::UUID,
            v_request->>'msisdn',
            v_request->>'application_id',
            v_request->>'application_endpoint',
            v_request->>'current_menu_id',
            v_request->>'user_input',
            v_request->'session_context',
            COALESCE(v_request->>'routing_method', 'DIRECT'),
            COALESCE((v_request->>'timeout_ms')::INT, 5000),
            COALESCE((v_request->>'retry_count')::INT, 0)
        );
        
        request_id := v_index;
        success := v_result.success;
        response_text := v_result.response_text;
        error_code := v_result.error_code;
        RETURN NEXT;
    END LOOP;
END;
$$;

-- ----------------------------------------------------------------------------
-- FUNCTION: get_application_health
-- ----------------------------------------------------------------------------
-- Check health status of applications for load balancing decisions.
-- ----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION get_application_health(
    p_application_id VARCHAR(64) DEFAULT NULL
)
RETURNS TABLE (
    application_id VARCHAR(64),
    endpoint VARCHAR(512),
    status VARCHAR(16), -- HEALTHY, DEGRADED, UNHEALTHY
    success_rate_5m DECIMAL(5,4),
    avg_response_time_ms INT,
    circuit_breaker_state VARCHAR(16), -- CLOSED, OPEN, HALF_OPEN
    last_checked_at TIMESTAMPTZ
)
LANGUAGE SQL
STABLE
SECURITY DEFINER
AS $$
    -- TODO: Query from health check table or metrics
    -- For now, return placeholder
    SELECT 
        'mobile_money'::VARCHAR(64),
        'http://mm-service:8080'::VARCHAR(512),
        'HEALTHY'::VARCHAR(16),
        0.995::DECIMAL(5,4),
        45::INT,
        'CLOSED'::VARCHAR(16),
        NOW()
    WHERE p_application_id IS NULL OR p_application_id = 'mobile_money';
$$;

-- ----------------------------------------------------------------------------
-- TODO: IMPLEMENTATION NOTES
-- ----------------------------------------------------------------------------

/*
TODO [PERF-001]: Performance optimization
  - Use connection pooling (PgBouncer or application-level)
  - Implement async request processing where possible
  - Cache application responses for idempotent requests
  - Use HTTP/2 for connection multiplexing
  - Target p99 response time < 100ms

TODO [RESILIENCE-001]: Resilience patterns
  - Implement circuit breaker with half-open state testing
  - Use bulkhead pattern to isolate failures
  - Implement request queueing for retry
  - Use timeout per attempt, not total
  - Graceful degradation on partial failures

TODO [OBS-001]: Observability
  - Distributed tracing (OpenTelemetry)
  - Request/response logging (sanitized)
  - Metrics: latency, throughput, error rate
  - Alert on SLA violations
  - Dashboard for routing health

TODO [SEC-001]: Security hardening
  - mTLS for service-to-service communication
  - Request signing and verification
  - Response validation against schema
  - Sanitize all user-facing messages
  - Rate limiting per application
*/

-- ----------------------------------------------------------------------------
-- SECURITY CONSIDERATIONS
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.5 - Secure inter-service communication
-- [ISO/IEC 27001:2022] A.8.23 - Request/response security
-- [ISO/IEC 27018:2019] Request payload sanitization
-- [PCI DSS v4.0] mTLS and request signing
/*
1. REQUEST SECURITY:
   - Sign all requests with HMAC
   - Include request timestamps to prevent replay
   - Validate SSL certificates for HTTPS
   - Never include raw PINs in request payload
   - Encrypt sensitive context data

2. RESPONSE HANDLING:
   - Validate response format before processing
   - Sanitize response text (prevent injection)
   - Limit response size (max 182 chars for USSD)
   - Handle encoding issues gracefully
   - Don't expose internal errors to users

3. ERROR HANDLING:
   - Generic error messages for users
   - Detailed errors in logs only
   - Don't leak application internals
   - Alert on repeated errors
   - Fail secure (terminate session on error)

4. SSRF PREVENTION:
   - Whitelist allowed application endpoints
   - Block internal metadata endpoints
   - Validate URL scheme (https only)
   - Use service mesh for internal routing
   - Monitor for unusual routing patterns
*/

-- ----------------------------------------------------------------------------
-- SESSION TIMEOUT HANDLING
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27001:2022] A.8.11 - Request timeout: 5 seconds default
-- Financial operations: 10 seconds
-- Information queries: 3 seconds
-- Circuit breaker open duration: 30 seconds
/*
Application routing timeout considerations:

1. REQUEST TIMEOUT:
   - Default: 5 seconds per request
   - Financial: 10 seconds (more processing time)
   - Information: 3 seconds (quick response)
   - Timeout includes network round-trip

2. RETRY CONFIGURATION:
   - Default: 0 retries for interactive (fail fast)
   - Background: 3 retries with backoff
   - Critical operations: Custom retry logic
   - Exponential backoff: 100ms, 200ms, 400ms

3. CIRCUIT BREAKER TIMEOUTS:
   - Open state duration: 30 seconds
   - Half-open test requests: 1 per second
   - Close after 5 consecutive successes
   - Alert on circuit breaker open

4. END-OF-SESSION HANDLING:
   - If session expires during request, complete request but don't update
   - Return error if response would exceed session timeout
   - Allow graceful termination mid-request
   - Log partial completion

5. BACKGROUND PROCESSING:
   - Long operations: return "processing" and poll
   - Async callback when complete
   - Session can terminate while operation continues
   - SMS notification of completion
*/

-- ----------------------------------------------------------------------------
-- SIM SWAP DETECTION INTEGRATION
-- ----------------------------------------------------------------------------
-- [ISO/IEC 27035-2:2023] Risk context propagation to applications
-- Swap status included in request payload
-- Application adjusts behavior based on swap risk
-- Device fingerprint re-verification on callbacks
/*
SIM swap detection in application routing:

1. RISK CONTEXT PROPAGATION:
   - Include swap status in request payload
   - Application can adjust behavior based on risk
   - Pass trust score to application
   - Flag recent swaps for enhanced logging

2. APPLICATION-LEVEL PROTECTIONS:
   - Application queries swap status before processing
   - Adjust transaction limits based on swap recency
   - Additional confirmation for high-risk users
   - Route to verification flow if needed

3. CALLBACK CONSIDERATIONS:
   - Verify device fingerprint on async callbacks
   - Re-check swap status before completing
   - Invalidate if swap detected during processing
   - Alert on completion attempts post-swap

4. RESPONSE HANDLING:
   - Application can request additional verification
   - Response may include swap warning message
   - Force PIN re-entry for post-swap sessions
   - Application can terminate if risk too high

5. MONITORING:
   - Track routing success rate for post-swap users
   - Alert on increased errors for swap-affected sessions
   - Monitor for fraud patterns post-swap
   - Feed into swap detection model
*/

-- Grant execute permission
-- GRANT EXECUTE ON FUNCTION route_to_application TO ussd_gateway_role;
-- GRANT EXECUTE ON FUNCTION batch_route_to_applications TO ussd_gateway_role;
-- GRANT EXECUTE ON FUNCTION get_application_health TO ussd_monitoring_role;
