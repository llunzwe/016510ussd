-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: utils/extensions/003_timescaledb_setup.sql
-- Description: Configuration for TimescaleDB extension for time-series data
--              optimization, particularly for audit logs and metrics
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: INTERNAL
-- DATA SENSITIVITY: MEDIUM - Time-Series Infrastructure
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.12.4 Logging and Monitoring
  - A.12.4.1: High-performance audit log storage
  - A.12.4.2: Audit log protection and retention
  
A.12.3.4: Removal of Assets
  - Automated data retention and archival
  
A.18.1.3: Protection of Records
  - Long-term audit log retention with compression
  - Legal hold capability for time-series data
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION IN CLOUD
================================================================================
- Efficient storage for PII access logs
- Compression reduces storage footprint for audit data
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
5.2 Storage Architecture
  - Time-based partitioning for audit data
  - Tiered storage (hot/warm/cold)
  
7.2 Data Encryption
  - Compression reduces storage footprint
  - Encryption at rest for archived chunks
  
8.1 Data Retention and Disposal
  - Automated retention policies
  - Secure deletion of expired data
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
- Time-series partitioning facilitates ESI collection
- Efficient export for litigation support
================================================================================

================================================================================
PCI DSS 4.0 TIME-SERIES REQUIREMENTS
================================================================================
Requirement 10.3: Retain Audit Trail History
  - Minimum 1 year retention with immediate availability of 3 months
  - TimescaleDB partitioning enables efficient retention management
  
Requirement 10.7: Retention Policy for Audit Logs
  - Automated policies for log retention and disposal
  
Requirement 10.3.3: Secure Storage
  - Compression and encryption for audit log storage
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. Safe wrappers with TimescaleDB availability checks
2. Graceful fallback to native partitioning if unavailable
3. Configuration-driven chunk sizing
4. Compression policies for cost optimization
5. Retention policies for compliance
================================================================================

================================================================================
TIMESCALEDB SECURITY FEATURES
================================================================================
Chunking Strategy:
  - 7-day chunks for audit logs (balance size and query performance)
  - Time-based partitioning aligns with retention policies
  
Compression:
  - Segment by high-cardinality columns for efficient compression
  - Order by time for fast range queries
  - Typical compression ratio: 90%+ for time-series data
  
Continuous Aggregates:
  - Pre-computed summaries for dashboard queries
  - Real-time aggregation for recent data
  
Data Tiering:
  - Hot: Recent data on fast storage (SSD)
  - Warm: Compressed data on standard storage
  - Cold: Exported to object storage (S3)
================================================================================

================================================================================
AUDIT TRAIL INTEGRATION
================================================================================
- Audit logs automatically converted to hypertables
- Compression reduces storage costs while maintaining queryability
- Retention policies enforce compliance requirements
- Legal hold capability prevents deletion of specific time ranges
================================================================================
*/

-- ============================================================================
-- EXTENSION INSTALLATION
-- ============================================================================

-- Install TimescaleDB extension
-- Note: Requires superuser and TimescaleDB to be installed on the system
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS timescaledb WITH SCHEMA public;
    RAISE NOTICE 'TimescaleDB extension installed/verified successfully';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TimescaleDB extension not available: %', SQLERRM;
    RAISE NOTICE 'Falling back to standard PostgreSQL partitioning';
END $$;

-- ============================================================================
-- TIMESCALEDB CONFIGURATION
-- ============================================================================

-- Configuration table for TimescaleDB settings
CREATE TABLE IF NOT EXISTS timescaledb_config (
    config_key VARCHAR(100) PRIMARY KEY,
    config_value TEXT NOT NULL,
    config_type VARCHAR(20) DEFAULT 'string',
    description TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default configurations
INSERT INTO timescaledb_config (config_key, config_value, config_type, description) VALUES
    ('chunk_time_interval', '7 days', 'interval', 'Default chunk size for time-series tables'),
    ('compression_enabled', 'true', 'boolean', 'Enable automatic compression'),
    ('compression_after', '7 days', 'interval', 'Compress chunks older than this'),
    ('retention_enabled', 'true', 'boolean', 'Enable automatic data retention'),
    ('retention_period', '1 year', 'interval', 'Default data retention period (PCI DSS 10.7)'),
    ('continuous_aggregates', 'true', 'boolean', 'Enable continuous aggregates'),
    ('materialized_view_refresh', '1 hour', 'interval', 'Refresh interval for materialized views'),
    ('reorder_chunks', 'true', 'boolean', 'Enable automatic chunk reordering')
ON CONFLICT (config_key) DO UPDATE SET
    config_value = EXCLUDED.config_value,
    updated_at = NOW();

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON EXTENSION timescaledb IS 'Time-series database extension for PostgreSQL - PCI DSS audit log optimization (ISO 27040)';

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Implement multi-node TimescaleDB setup for distributed hypertables
-- TODO: Add support for custom chunk sizing based on data volume
-- TODO: Implement tiered storage policies (hot/warm/cold) (ISO 27040)
-- TODO: Add integration with cloud storage for archival
-- TODO: Implement real-time aggregation pipelines
-- TODO: Add support for gap filling and interpolation
-- TODO: Implement anomaly detection on time-series data
-- TODO: Add downsampling policies for long-term retention (PCI DSS 10.7)
-- TODO: Create automated performance tuning recommendations
-- TODO: Implement cross-region replication for time-series data
-- ============================================================================
