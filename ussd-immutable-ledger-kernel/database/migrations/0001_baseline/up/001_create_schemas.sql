-- ============================================================================
-- COMPLIANCE STANDARDS
-- ============================================================================
-- ISO/IEC 27001:2022 - ISMS Framework (Schema isolation for security domains)
-- ISO/IEC 27017:2015 - Cloud Security Controls (Multi-tenant schema separation)
-- ISO/IEC 27018:2019 - PII Protection in Public Clouds (Schema-level PII isolation)
-- ISO/IEC 27040:2024 - Storage Security (Immutable Storage)
-- ISO/IEC 27031:2025 - ICT Readiness for Business Continuity (Schema redundancy)
-- ============================================================================
-- CODING PRACTICES ENFORCED:
-- - Schema-based isolation of security domains
-- - Principle of least privilege via schema ownership
-- - Explicit search_path configuration
-- - Audit logging schema separation
-- ============================================================================
-- =============================================================================
-- MIGRATION: 001_create_schemas.sql
-- DESCRIPTION: Initialize database schemas for the USSD Immutable Ledger Kernel
-- SCHEMAS: core, app, ussd, security, audit, archive
-- DEPENDENCIES: None (baseline migration)
-- =============================================================================

/*
================================================================================
REFERENCE DOCUMENTATION:
- Section: 1. Identity & Multi-Tenancy / Core Immutable Ledger
- Feature: Database Schema Architecture
- Source: adkjfnwr.md (Kernel Core Schema, Kernel App Schema)

BUSINESS CONTEXT:
This migration establishes the foundational schema structure for a USSD-focused
immutable ledger supporting savings groups, micro-loans, marketplaces, transport,
health, and e-commerce applications.

SCHEMA ORGANIZATION:
- core:    Immutable transaction log, account registry, cryptographic proofs
- app:     Application registry, roles, config, hooks, audit logs
- ussd:    USSD-specific session management, routing, device tracking
- security: Row-level security policies, encryption metadata
- audit:   Comprehensive audit logging for compliance
- archive: Data archival manifests and cold storage references
================================================================================
*/

-- =============================================================================
-- TODO: Create core schema
-- DESCRIPTION: Immutable ledger foundation - append-only tables
-- PRIORITY: CRITICAL
-- SECURITY: Contains PII - access restricted to security definer functions
-- ============================================================================
-- TODO: [SCHEMA-001] Create 'core' schema with proper ownership
-- INSTRUCTIONS:
--   - Create schema 'core' owned by ledger_admin role
--   - Set default character encoding to UTF-8
--   - Configure schema-specific search_path
--   - SECURITY DEFINER: All access through controlled functions only
-- COMPLIANCE: ISO/IEC 27040 (Immutable Storage)
-- IMPLEMENTATION:
--   CREATE SCHEMA IF NOT EXISTS core AUTHORIZATION ledger_admin;
--   COMMENT ON SCHEMA core IS 'Immutable transaction ledger - append-only, cryptographically verified';

-- TODO: [SCHEMA-002] Set core schema permissions
-- INSTRUCTIONS:
--   - Grant USAGE to application roles
--   - Restrict CREATE privileges to admin only
--   - Document: Core tables are INSERT-only via triggers
--   - RLS POLICY: Enable row-level security on all core tables

-- =============================================================================
-- TODO: Create app schema
-- DESCRIPTION: Application registry and configuration (hybrid immutable/mutable)
-- PRIORITY: CRITICAL
-- SECURITY: Contains application credentials - encrypt sensitive fields
-- ============================================================================
-- TODO: [SCHEMA-003] Create 'app' schema
-- INSTRUCTIONS:
--   - Create schema 'app' for multi-tenancy and application configuration
--   - Supports both immutable versioned data and mutable audited settings
--   - ERROR HANDLING: Use BEGIN/EXCEPTION blocks for DDL operations
-- COMPLIANCE: ISO/IEC 27018 (PII Protection)
-- IMPLEMENTATION:
--   CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION ledger_admin;
--   COMMENT ON SCHEMA app IS 'Application registry, RBAC, configuration, hooks - versioned & audited';

-- =============================================================================
-- TODO: Create ussd schema
-- DESCRIPTION: USSD-specific session and routing management
-- PRIORITY: HIGH
-- SECURITY: Session data retention per privacy policy
-- ============================================================================
-- TODO: [SCHEMA-004] Create 'ussd' schema
-- INSTRUCTIONS:
--   - Create schema 'ussd' for session state, menu configurations, routing
--   - Links to core transaction log via application_id references
--   - TRANSACTION ISOLATION: READ COMMITTED for session tables
-- COMPLIANCE: ISO/IEC 27031 (Business Continuity)
-- IMPLEMENTATION:
--   CREATE SCHEMA IF NOT EXISTS ussd AUTHORIZATION ledger_admin;
--   COMMENT ON SCHEMA ussd IS 'USSD session management, shortcode routing, menu configurations';

-- =============================================================================
-- TODO: Create security schema
-- DESCRIPTION: RLS policies and encryption metadata
-- PRIORITY: HIGH
-- SECURITY: Contains encryption key references (keys in external KMS)
-- ============================================================================
-- TODO: [SCHEMA-005] Create 'security' schema
-- INSTRUCTIONS:
--   - Store Row-Level Security (RLS) policy definitions
--   - Encryption key references (actual keys in external KMS/HSM)
--   - Access control matrices
--   - NAMING CONVENTION: security_<object> for all objects
-- COMPLIANCE: ISO/IEC 27001 (Access Control), ISO/IEC 27017 (Cloud Security)
-- IMPLEMENTATION:
--   CREATE SCHEMA IF NOT EXISTS security AUTHORIZATION ledger_admin;
--   COMMENT ON SCHEMA security IS 'RLS policies, encryption metadata, access control';

-- =============================================================================
-- TODO: Create audit schema
-- DESCRIPTION: Comprehensive audit logging
-- PRIORITY: HIGH
-- SECURITY: Append-only audit trail, tamper-evident hashing
-- ============================================================================
-- TODO: [SCHEMA-006] Create 'audit' schema
-- INSTRUCTIONS:
--   - Global audit log for all schema changes
--   - Separate from core immutability - this tracks administrative actions
--   - GDPR-compliant access logging
--   - AUDIT LOGGING: All DDL and DML logged with session info
-- COMPLIANCE: ISO/IEC 27001 (Audit Logging)
-- IMPLEMENTATION:
--   CREATE SCHEMA IF NOT EXISTS audit AUTHORIZATION ledger_admin;
--   COMMENT ON SCHEMA audit IS 'Administrative audit trail, access logs, compliance records';

-- =============================================================================
-- TODO: Create archive schema
-- DESCRIPTION: Cold storage manifest and archival tracking
-- PRIORITY: MEDIUM
-- SECURITY: Legal hold tracking, retention policy enforcement
-- ============================================================================
-- TODO: [SCHEMA-007] Create 'archive' schema
-- INSTRUCTIONS:
--   - Catalog of records moved to cold storage (S3 Glacier, etc.)
--   - Content hashes for integrity verification of archived data
--   - Legal hold tracking
--   - SEARCH PATH: Set to core, app for foreign key validation
-- COMPLIANCE: ISO/IEC 27040 (Storage Security)
-- IMPLEMENTATION:
--   CREATE SCHEMA IF NOT EXISTS archive AUTHORIZATION ledger_admin;
--   COMMENT ON SCHEMA archive IS 'Archive manifests, cold storage references, legal hold tracking';

-- =============================================================================
-- TODO: Schema-wide configuration
-- DESCRIPTION: Set default parameters and extensions
-- PRIORITY: MEDIUM
-- ============================================================================
-- TODO: [SCHEMA-008] Configure schema search paths
-- INSTRUCTIONS:
--   ALTER DATABASE current_database() SET search_path TO core, app, ussd, public;
-- SECURITY NOTE: Explicit search_path prevents schema injection attacks

-- TODO: [SCHEMA-009] Document schema dependencies
-- INSTRUCTIONS:
--   - core: No dependencies (foundation)
--   - app:  References core for application_id foreign keys
--   - ussd: References core (transactions) and app (applications)
--   - security: References all schemas for RLS policies
--   - audit:  References all schemas for change tracking
--   - archive: References core for archived records

/*
================================================================================
MIGRATION CHECKLIST:
□ Create core schema (immutable ledger foundation)
□ Create app schema (application registry & config)
□ Create ussd schema (session/routing)
□ Create security schema (RLS & encryption)
□ Create audit schema (compliance logging)
□ Create archive schema (cold storage)
□ Set proper ownership and permissions
□ Configure search paths
□ Add schema comments
□ Verify no circular dependencies
================================================================================
*/
