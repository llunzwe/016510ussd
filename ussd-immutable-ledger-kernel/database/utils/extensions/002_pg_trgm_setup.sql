-- ============================================================================
-- COMPLIANCE HEADER: ISO/IEC 27001:2022 | ISO/IEC 27018:2019 | ISO/IEC 27040:2024
--                    ISO/IEC 27050-3:2020 | PCI DSS 4.0
-- ============================================================================
-- File: utils/extensions/002_pg_trgm_setup.sql
-- Description: Configuration for trigram similarity search and fuzzy text
--              matching capabilities
-- Version: 1.0.0
-- Author: USSD Immutable Ledger Team
-- Last Modified: 2026-03-30
-- ============================================================================
-- SECURITY CLASSIFICATION: INTERNAL
-- DATA SENSITIVITY: LOW - Text Search Utilities
-- ============================================================================

/*
================================================================================
ISO/IEC 27001:2022 COMPLIANCE MAPPING
================================================================================
A.12.5.1: Installation of Software on Operational Systems
  - Extension installation with security review
  
A.14.2.8: System Security Testing
  - Fuzzy matching for data quality validation
  - Duplicate detection for data integrity

A.18.1.3: Protection of Records
  - Text search for compliance document discovery
  - Audit log searching and analysis
================================================================================

================================================================================
ISO/IEC 27018:2019 PII PROTECTION
================================================================================
- Fuzzy matching for PII detection in unstructured data
- Similarity search for duplicate PII identification
- Text analysis for data classification
================================================================================

================================================================================
ISO/IEC 27040:2024 STORAGE SECURITY COMPLIANCE
================================================================================
- Trigram indexes optimize audit log searches
- Efficient text search for compliance queries
================================================================================

================================================================================
ISO/IEC 27050-3:2020 ELECTRONIC DISCOVERY COMPLIANCE
================================================================================
- Fuzzy text matching for ESI identification
- Similarity search for duplicate detection in discovery
================================================================================

================================================================================
PCI DSS 4.0 REFERENCE
================================================================================
Requirement 3.4: Token matching for cardholder data
Requirement 10: Audit log text search capabilities
================================================================================

================================================================================
SECURITY CONSIDERATIONS
================================================================================
Performance:
  - Trigram indexes can be large (approximately 3x text size)
  - Use selective indexing for large tables
  - Consider pg_bigm extension for CJK (Chinese/Japanese/Korean) text

Privacy:
  - Fuzzy matching may reveal similar records
  - Implement RLS when searching sensitive data
  - Log sensitive searches for compliance

DoS Prevention:
  - Set appropriate similarity thresholds
  - Limit search result sizes
  - Implement query timeouts
================================================================================

================================================================================
ENTERPRISE POSTGRESQL CODING STANDARDS
================================================================================
1. Create GIN indexes for similarity searches
2. Set appropriate similarity thresholds per use case
3. Use strict_word_similarity for more precise matching
4. Document security considerations for fuzzy matching
5. Implement search result limits
================================================================================
*/

-- ============================================================================
-- EXTENSION INSTALLATION
-- ============================================================================

-- Install pg_trgm extension for trigram similarity
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

-- Verify installation
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'
    ) THEN
        RAISE EXCEPTION 'pg_trgm extension installation failed';
    END IF;
    RAISE NOTICE 'pg_trgm extension installed successfully';
END $$;

-- ============================================================================
-- CONFIGURATION
-- ============================================================================

-- Set pg_trgm configuration parameters
-- Similarity threshold (0.0 to 1.0, default 0.3)
ALTER DATABASE CURRENT SET pg_trgm.similarity_threshold = 0.3;

-- Word similarity threshold
ALTER DATABASE CURRENT SET pg_trgm.word_similarity_threshold = 0.6;

-- Strict word similarity threshold
ALTER DATABASE CURRENT SET pg_trgm.strict_word_similarity_threshold = 0.5;

-- ============================================================================
-- SIMILARITY FUNCTIONS
-- ============================================================================

-- Function to calculate similarity between two strings
-- ISO/IEC 27018: PII matching for duplicate detection
CREATE OR REPLACE FUNCTION text_similarity(
    text1 TEXT,
    text2 TEXT
)
RETURNS REAL AS $$
BEGIN
    RETURN similarity(text1, text2);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON EXTENSION pg_trgm IS 'Text similarity measurement and index searching based on trigrams (ISO 27001, PCI DSS audit search)';
COMMENT ON FUNCTION text_similarity IS 'Calculate trigram similarity between two strings (0.0 to 1.0) - ISO 27018 PII matching';

-- ============================================================================
-- TODOs (Security Enhancements)
-- ============================================================================
-- TODO: Add support for phonetic matching (soundex, metaphone)
-- TODO: Implement Levenshtein distance calculations
-- TODO: Add support for n-gram tokenization with n > 3
-- TODO: Implement custom trigram dictionaries for domain-specific terms
-- TODO: Add machine learning-based similarity scoring integration
-- TODO: Implement query expansion for better recall
-- TODO: Add support for multilingual fuzzy matching
-- TODO: Create automated index recommendation system
-- TODO: Implement real-time spell checking API
-- TODO: Add support for context-aware similarity (sentence-level)
-- ============================================================================
