#!/bin/bash
# =============================================================================
# USSD Immutable Ledger Kernel - Deployment Verification Script
# =============================================================================
# DESCRIPTION: Automated verification that all migrations have been applied
#              correctly and the system is ready for production.
# 
# USAGE: ./verify_deployment.sh [database_name] [username]
# DEFAULT: ./verify_deployment.sh ussd_kernel postgres
# =============================================================================

set -e  # Exit on error

# Configuration
DB_NAME="${1:-ussd_kernel}"
DB_USER="${2:-postgres}"
LOG_FILE="deployment_verify_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_section() {
    echo "" | tee -a "$LOG_FILE"
    echo "================================================================================" | tee -a "$LOG_FILE"
    echo "$1" | tee -a "$LOG_FILE"
    echo "================================================================================" | tee -a "$LOG_FILE"
}

# Initialize log
echo "USSD Immutable Ledger Kernel - Deployment Verification" > "$LOG_FILE"
echo "Started: $(date)" >> "$LOG_FILE"
echo "Database: $DB_NAME" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

log_section "DEPLOYMENT VERIFICATION START"
log_info "Target Database: $DB_NAME"
log_info "Log File: $LOG_FILE"

# =============================================================================
# CHECK 1: Database Connectivity
# =============================================================================
log_section "CHECK 1: Database Connectivity"

if psql -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1" > /dev/null 2>&1; then
    log_info "✅ Database connection successful"
else
    log_error "❌ Cannot connect to database $DB_NAME"
    exit 1
fi

# =============================================================================
# CHECK 2: Required Extensions
# =============================================================================
log_section "CHECK 2: Required Extensions"

REQUIRED_EXTENSIONS=("uuid-ossp" "pgcrypto" "ltree")
OPTIONAL_EXTENSIONS=("timescaledb")

for ext in "${REQUIRED_EXTENSIONS[@]}"; do
    if psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT 1 FROM pg_extension WHERE extname = '$ext'" | grep -q 1; then
        log_info "✅ Extension installed: $ext"
    else
        log_error "❌ Required extension missing: $ext"
        log_info "   Install with: CREATE EXTENSION IF NOT EXISTS $ext;"
    fi
done

for ext in "${OPTIONAL_EXTENSIONS[@]}"; do
    if psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT 1 FROM pg_extension WHERE extname = '$ext'" | grep -q 1; then
        log_info "✅ Optional extension installed: $ext"
    else
        log_warn "⚠️  Optional extension not installed: $ext"
    fi
done

# =============================================================================
# CHECK 3: Schema Existence
# =============================================================================
log_section "CHECK 3: Schema Existence"

REQUIRED_SCHEMAS=("core" "app" "ussd_gateway")

for schema in "${REQUIRED_SCHEMAS[@]}"; do
    if psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT 1 FROM information_schema.schemata WHERE schema_name = '$schema'" | grep -q 1; then
        log_info "✅ Schema exists: $schema"
    else
        log_error "❌ Schema missing: $schema"
    fi
done

# =============================================================================
# CHECK 4: Core Tables
# =============================================================================
log_section "CHECK 4: Core Tables"

REQUIRED_CORE_TABLES=(
    "transaction_log"
    "account_registry"
    "blocks"
    "merkle_nodes"
    "merkle_proofs"
    "audit_trail"
    "transaction_types"
    "signing_keys"
    "security_audit_log"
)

for table in "${REQUIRED_CORE_TABLES[@]}"; do
    if psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT 1 FROM information_schema.tables WHERE table_schema = 'core' AND table_name = '$table'" | grep -q 1; then
        log_info "✅ Table exists: core.$table"
    else
        log_error "❌ Table missing: core.$table"
    fi
done

# =============================================================================
# CHECK 5: Immutability Triggers
# =============================================================================
log_section "CHECK 5: Immutability Enforcement"

IMMUTABLE_TABLES=("transaction_log" "blocks" "merkle_nodes" "audit_trail")
TRIGGER_ISSUES=0

for table in "${IMMUTABLE_TABLES[@]}"; do
    UPDATE_TRIGGERS=$(psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM pg_trigger t JOIN pg_class c ON t.tgrelid = c.oid JOIN pg_namespace n ON c.relnamespace = n.oid WHERE n.nspname = 'core' AND c.relname = '$table' AND t.tgname LIKE '%prevent_update%';" | tr -d ' ')
    DELETE_TRIGGERS=$(psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM pg_trigger t JOIN pg_class c ON t.tgrelid = c.oid JOIN pg_namespace n ON c.relnamespace = n.oid WHERE n.nspname = 'core' AND c.relname = '$table' AND t.tgname LIKE '%prevent_delete%';" | tr -d ' ')
    
    if [ "$UPDATE_TRIGGERS" -gt 0 ] && [ "$DELETE_TRIGGERS" -gt 0 ]; then
        log_info "✅ Immutability protected: core.$table ($UPDATE_TRIGGERS update, $DELETE_TRIGGERS delete triggers)"
    else
        log_error "❌ Immutability NOT protected: core.$table"
        TRIGGER_ISSUES=$((TRIGGER_ISSUES + 1))
    fi
done

if [ $TRIGGER_ISSUES -eq 0 ]; then
    log_info "✅ All core tables have immutability protection"
else
    log_warn "⚠️  $TRIGGER_ISSUES table(s) missing immutability protection"
fi

# =============================================================================
# CHECK 6: Hash Chain Columns
# =============================================================================
log_section "CHECK 6: Hash Chain Columns"

if psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT 1 FROM information_schema.columns WHERE table_schema = 'core' AND table_name = 'transaction_log' AND column_name = 'previous_hash'" | grep -q 1; then
    log_info "✅ Hash chain columns present in transaction_log"
else
    log_error "❌ Hash chain columns missing from transaction_log"
fi

if psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT 1 FROM information_schema.columns WHERE table_schema = 'core' AND table_name = 'blocks' AND column_name = 'merkle_root'" | grep -q 1; then
    log_info "✅ Merkle root column present in blocks"
else
    log_error "❌ Merkle root column missing from blocks"
fi

# =============================================================================
# CHECK 7: Row Level Security
# =============================================================================
log_section "CHECK 7: Row Level Security"

RLS_TABLES=$(psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid WHERE n.nspname IN ('core', 'app') AND c.relkind = 'r' AND c.relrowsecurity = TRUE;" | tr -d ' ')

if [ "$RLS_TABLES" -gt 0 ]; then
    log_info "✅ RLS enabled on $RLS_TABLES table(s)"
else
    log_warn "⚠️  No tables found with RLS enabled"
fi

# =============================================================================
# CHECK 8: TimescaleDB Hypertables (if extension exists)
# =============================================================================
log_section "CHECK 8: TimescaleDB Configuration"

if psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'" | grep -q 1; then
    log_info "TimescaleDB extension detected"
    
    HYPERTABLES=$(psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM timescaledb_information.hypertables;" | tr -d ' ')
    log_info "✅ $HYPERTABLES hypertable(s) configured"
    
    COMPRESSION=$(psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM timescaledb_information.compression_settings;" | tr -d ' ')
    log_info "✅ $COMPRESSION compression policy(ies) active"
else
    log_warn "⚠️  TimescaleDB not installed - large tables may have performance issues"
fi

# =============================================================================
# CHECK 9: Critical Functions
# =============================================================================
log_section "CHECK 9: Critical Functions"

CRITICAL_FUNCTIONS=(
    "core.prevent_update"
    "core.prevent_delete"
    "core.calculate_record_hash"
    "core.verify_immutability_enforcement"
    "core.emergency_verify_hash_chain"
    "core.emergency_system_status"
)

for func in "${CRITICAL_FUNCTIONS[@]}"; do
    SCHEMA=$(echo "$func" | cut -d'.' -f1)
    NAME=$(echo "$func" | cut -d'.' -f2)
    
    if psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT 1 FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid WHERE n.nspname = '$SCHEMA' AND p.proname = '$NAME'" | grep -q 1; then
        log_info "✅ Function exists: $func"
    else
        log_error "❌ Function missing: $func"
    fi
done

# =============================================================================
# CHECK 10: Run Immutability Verification
# =============================================================================
log_section "CHECK 10: Immutability Verification"

echo "Running database immutability checks..." | tee -a "$LOG_FILE"

psql -U "$DB_USER" -d "$DB_NAME" <<EOF >> "$LOG_FILE" 2>&1
SELECT * FROM core.final_immutability_check();
EOF

if [ $? -eq 0 ]; then
    log_info "✅ Immutability verification completed"
else
    log_error "❌ Immutability verification failed"
fi

# =============================================================================
# CHECK 11: Security Audit Log
# =============================================================================
log_section "CHECK 11: Security Audit Log"

SECURITY_EVENTS=$(psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM core.security_audit_log WHERE severity IN ('HIGH', 'CRITICAL') AND event_timestamp > NOW() - INTERVAL '24 hours';" | tr -d ' ')

if [ "$SECURITY_EVENTS" -eq 0 ]; then
    log_info "✅ No HIGH/CRITICAL security events in last 24 hours"
else
    log_warn "⚠️  $SECURITY_EVENTS HIGH/CRITICAL security event(s) in last 24 hours"
    log_info "   Review with: SELECT * FROM core.security_audit_log WHERE severity IN ('HIGH', 'CRITICAL') ORDER BY event_timestamp DESC LIMIT 10;"
fi

# =============================================================================
# CHECK 12: Transaction Statistics
# =============================================================================
log_section "CHECK 12: Transaction Statistics"

TXN_COUNT=$(psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM core.transaction_log;" | tr -d ' ')
BLOCK_COUNT=$(psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM core.blocks;" | tr -d ' ')
PENDING_TXN=$(psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM core.transaction_log WHERE status = 'pending';" | tr -d ' ')
FAILED_TXN=$(psql -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM core.transaction_log WHERE status = 'failed';" | tr -d ' ')

log_info "Total transactions: $TXN_COUNT"
log_info "Total blocks: $BLOCK_COUNT"
log_info "Pending transactions: $PENDING_TXN"

if [ "$FAILED_TXN" -gt 0 ]; then
    log_warn "⚠️  Failed transactions: $FAILED_TXN"
else
    log_info "Failed transactions: 0"
fi

# =============================================================================
# FINAL SUMMARY
# =============================================================================
log_section "VERIFICATION SUMMARY"

log_info "Verification completed at $(date)"
log_info "Full log saved to: $LOG_FILE"

echo "" | tee -a "$LOG_FILE"
echo "================================================================================" | tee -a "$LOG_FILE"
echo "NEXT STEPS:" | tee -a "$LOG_FILE"
echo "================================================================================" | tee -a "$LOG_FILE"
echo "1. Review any ERROR or WARN messages above" | tee -a "$LOG_FILE"
echo "2. Run integration tests:" | tee -a "$LOG_FILE"
echo "   psql -d $DB_NAME -f tests/integration/001_immutability_tests.sql" | tee -a "$LOG_FILE"
echo "   psql -d $DB_NAME -f tests/integration/002_integrity_verification_tests.sql" | tee -a "$LOG_FILE"
echo "3. Verify hash chain:" | tee -a "$LOG_FILE"
echo "   psql -d $DB_NAME -c \"SELECT * FROM core.emergency_verify_hash_chain() LIMIT 10;\"" | tee -a "$LOG_FILE"
echo "4. Check system status:" | tee -a "$LOG_FILE"
echo "   psql -d $DB_NAME -c \"SELECT core.emergency_system_status();\"" | tee -a "$LOG_FILE"
echo "================================================================================" | tee -a "$LOG_FILE"

log_info "✅ Deployment verification complete"
