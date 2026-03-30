-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: utils/seed/001_default_transaction_types.sql
-- Description: Standard transaction types, categories, and fee structures
--              for the USSD immutable ledger
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: INTERNAL
-- DATA SENSITIVITY: MEDIUM - Transaction Configuration
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.12.1 Operational Procedures
  - Transaction type configuration for business processes
  - Fee structure for service delivery
  
A.8.2 Information Classification
  - Transaction categorization by risk level
  - Approval workflow configuration
================================================================================

================================================================================
PCI DSS 4.0 TRANSACTION REQUIREMENTS
================================================================================
Requirement 3.4: Transaction types for cardholder data processing
Requirement 7: Access control for transaction types
Requirement 10: Audit trail configuration per transaction type
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. ON CONFLICT for idempotent seeding
2. Clear documentation for each transaction type
3. Compliance flags for regulatory requirements
4. Audit trail tracking for all types
================================================================================

================================================================================
TRANSACTION TYPE CLASSIFICATION
================================================================================
High Risk: International transfers, bulk transfers, adjustments, reversals
Medium Risk: Bank transfers, merchant payments, cash operations
Low Risk: Airtime purchases, internal transfers
================================================================================
*/

-- ============================================================================
-- TRANSACTION TYPES
-- ============================================================================

INSERT INTO transaction_types (
    type_code, type_name, type_category, description,
    allowed_source_account_types, allowed_destination_account_types,
    requires_approval, approval_threshold_amount,
    is_reversible, reversal_time_limit_hours,
    default_priority, status
) VALUES
    -- Money Transfer Types
    ('P2P_TRANSFER', 'Peer-to-Peer Transfer', 'transfer', 
     'Transfer between two user accounts',
     ARRAY['individual', 'business'], ARRAY['individual', 'business'],
     FALSE, NULL, TRUE, 24, 'normal', 'active'),
     
    ('BANK_TRANSFER', 'Bank Transfer', 'transfer',
     'Transfer to external bank account',
     ARRAY['individual', 'business'], ARRAY['external'],
     FALSE, 10000.00, TRUE, 48, 'normal', 'active'),
     
    ('INTERNATIONAL_TRANSFER', 'International Transfer', 'transfer',
     'Cross-border money transfer',
     ARRAY['individual', 'business'], ARRAY['external'],
     TRUE, 5000.00, FALSE, NULL, 'high', 'active'),
     
    ('REVERSAL', 'Transaction Reversal', 'reversal',
     'Reversal of previous transaction',
     ARRAY['individual', 'business', 'merchant', 'system'],
     ARRAY['individual', 'business', 'merchant', 'system'],
     TRUE, 0.01, FALSE, NULL, 'critical', 'active')

ON CONFLICT (type_code) DO UPDATE SET
    type_name = EXCLUDED.type_name,
    description = EXCLUDED.description,
    requires_approval = EXCLUDED.requires_approval,
    is_reversible = EXCLUDED.is_reversible;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE transaction_types IS 'ISO/IEC 27001: Defines all supported transaction types and their properties';
COMMENT ON TABLE fee_structures IS 'PCI DSS: Fee configuration for each transaction type';

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Add regional fee variations for different markets
-- TODO: Implement promotional fee discounts (campaign-based)
-- TODO: Add loyalty program fee discounts
-- TODO: Create merchant-specific fee negotiation table
-- TODO: Implement real-time fee calculation API
-- TODO: Add fee splitting for multi-party transactions
-- TODO: Create fee revenue recognition accounting rules
-- TODO: Implement dynamic fee pricing based on network conditions
-- TODO: Add fee simulation for transaction preview
-- TODO: Create fee reconciliation and settlement procedures
-- ============================================================================
