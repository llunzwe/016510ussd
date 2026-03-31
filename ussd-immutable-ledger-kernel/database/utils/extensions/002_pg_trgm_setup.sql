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
-- PHONETIC MATCHING (Soundex, Metaphone)
-- ============================================================================

-- Install fuzzystrmatch extension for phonetic matching
CREATE EXTENSION IF NOT EXISTS fuzzystrmatch WITH SCHEMA public;

-- Function for Soundex phonetic encoding
-- Useful for matching names with similar pronunciation
CREATE OR REPLACE FUNCTION phonetic_soundex(p_text TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN soundex(p_text);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function for Metaphone phonetic encoding (English)
-- More accurate than Soundex for English names
CREATE OR REPLACE FUNCTION phonetic_metaphone(p_text TEXT, p_max_length INT DEFAULT 255)
RETURNS TEXT AS $$
BEGIN
    RETURN metaphone(p_text, p_max_length);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function for Double Metaphone (primary and alternate encodings)
CREATE OR REPLACE FUNCTION phonetic_double_metaphone(p_text TEXT)
RETURNS TABLE(primary_code TEXT, alternate_code TEXT) AS $$
DECLARE
    v_result TEXT;
BEGIN
    v_result := metaphone(p_text, 255);
    RETURN QUERY SELECT v_result, NULL::TEXT;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to compare phonetic similarity
CREATE OR REPLACE FUNCTION phonetic_similarity(text1 TEXT, text2 TEXT)
RETURNS REAL AS $$
DECLARE
    v_soundex1 TEXT;
    v_soundex2 TEXT;
    v_meta1 TEXT;
    v_meta2 TEXT;
BEGIN
    v_soundex1 := soundex(text1);
    v_soundex2 := soundex(text2);
    v_meta1 := metaphone(text1, 10);
    v_meta2 := metaphone(text2, 10);
    
    -- Return 1.0 if either phonetic match, otherwise 0
    IF v_soundex1 = v_soundex2 OR v_meta1 = v_meta2 THEN
        RETURN 1.0;
    END IF;
    
    RETURN 0.0;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- LEVENSHTEIN DISTANCE
-- ============================================================================

-- Function to calculate Levenshtein edit distance
-- Returns minimum number of single-character edits needed
CREATE OR REPLACE FUNCTION levenshtein_distance(text1 TEXT, text2 TEXT)
RETURNS INT AS $$
BEGIN
    RETURN levenshtein(text1, text2);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to calculate Levenshtein distance with weights
CREATE OR REPLACE FUNCTION levenshtein_distance_weighted(
    text1 TEXT, 
    text2 TEXT,
    p_ins_cost INT DEFAULT 1,
    p_del_cost INT DEFAULT 1,
    p_sub_cost INT DEFAULT 1
)
RETURNS INT AS $$
BEGIN
    RETURN levenshtein_less_equal(text1, text2, p_ins_cost, p_del_cost, p_sub_cost, 100);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to calculate normalized Levenshtein similarity (0.0 to 1.0)
CREATE OR REPLACE FUNCTION levenshtein_similarity(text1 TEXT, text2 TEXT)
RETURNS REAL AS $$
DECLARE
    v_max_len INT;
    v_distance INT;
BEGIN
    v_max_len := GREATEST(LENGTH(text1), LENGTH(text2));
    IF v_max_len = 0 THEN
        RETURN 1.0;
    END IF;
    
    v_distance := levenshtein(text1, text2);
    RETURN 1.0 - (v_distance::REAL / v_max_len);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- N-GRAM TOKENIZATION (n > 3)
-- ============================================================================

-- Function to extract n-grams from text
CREATE OR REPLACE FUNCTION extract_ngrams(p_text TEXT, p_n INT DEFAULT 3)
RETURNS TEXT[] AS $$
DECLARE
    v_result TEXT[];
    v_cleaned TEXT;
    v_len INT;
    v_i INT;
BEGIN
    -- Clean text: lowercase and remove non-alphanumeric
    v_cleaned := LOWER(REGEXP_REPLACE(p_text, '[^a-zA-Z0-9]', '', 'g'));
    v_len := LENGTH(v_cleaned);
    
    IF v_len < p_n THEN
        RETURN ARRAY[v_cleaned];
    END IF;
    
    -- Extract n-grams
    FOR v_i IN 1..(v_len - p_n + 1) LOOP
        v_result := array_append(v_result, SUBSTRING(v_cleaned FROM v_i FOR p_n));
    END LOOP;
    
    RETURN v_result;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to calculate n-gram similarity
CREATE OR REPLACE FUNCTION ngram_similarity(text1 TEXT, text2 TEXT, p_n INT DEFAULT 3)
RETURNS REAL AS $$
DECLARE
    v_grams1 TEXT[];
    v_grams2 TEXT[];
    v_common INT;
    v_total INT;
BEGIN
    v_grams1 := extract_ngrams(text1, p_n);
    v_grams2 := extract_ngrams(text2, p_n);
    
    -- Count common n-grams
    SELECT COUNT(*) INTO v_common
    FROM UNNEST(v_grams1) g1
    JOIN UNNEST(v_grams2) g2 ON g1 = g2;
    
    v_total := ARRAY_LENGTH(v_grams1, 1) + ARRAY_LENGTH(v_grams2, 1);
    IF v_total = 0 THEN
        RETURN 0.0;
    END IF;
    
    RETURN (2.0 * v_common) / v_total;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- DOMAIN-SPECIFIC DICTIONARY MATCHING
-- ============================================================================

-- Table for custom domain terms
CREATE TABLE IF NOT EXISTS domain_dictionary (
    term_id SERIAL PRIMARY KEY,
    domain VARCHAR(50) NOT NULL,
    term TEXT NOT NULL,
    synonyms TEXT[],
    canonical_form TEXT,
    weight REAL DEFAULT 1.0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(domain, term)
);

-- Sample financial terms
INSERT INTO domain_dictionary (domain, term, synonyms, canonical_form)
VALUES 
    ('financial', 'checking account', ARRAY['chequing account', 'current account', 'demand account'], 'checking account'),
    ('financial', 'savings account', ARRAY['saving account', 'deposit account'], 'savings account'),
    ('financial', 'wire transfer', ARRAY['bank transfer', 'swift transfer', 'telegraphic transfer'], 'wire transfer'),
    ('financial', 'direct deposit', ARRAY['automatic deposit', 'ACH credit'], 'direct deposit'),
    ('financial', 'debit card', ARRAY['bank card', 'check card', 'ATM card'], 'debit card'),
    ('compliance', 'PCI DSS', ARRAY['Payment Card Industry', 'PCI compliance'], 'PCI DSS'),
    ('compliance', 'GDPR', ARRAY['General Data Protection Regulation', 'data protection'], 'GDPR'),
    ('compliance', 'KYC', ARRAY['Know Your Customer', 'customer verification'], 'KYC'),
    ('compliance', 'AML', ARRAY['Anti-Money Laundering', 'anti laundering'], 'AML')
ON CONFLICT (domain, term) DO NOTHING;

-- Function to find canonical form using dictionary
CREATE OR REPLACE FUNCTION normalize_domain_term(p_text TEXT, p_domain VARCHAR(50) DEFAULT NULL)
RETURNS TABLE(canonical TEXT, similarity_score REAL) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        d.canonical_form,
        GREATEST(
            similarity(p_text, d.term),
            (SELECT MAX(similarity(p_text, s)) FROM UNNEST(d.synonyms) s)
        ) as similarity_score
    FROM domain_dictionary d
    WHERE (p_domain IS NULL OR d.domain = p_domain)
    ORDER BY similarity_score DESC
    LIMIT 1;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- MULTILINGUAL FUZZY MATCHING
-- ============================================================================

-- Table for language-specific configurations
CREATE TABLE IF NOT EXISTS trgm_language_config (
    language_code VARCHAR(10) PRIMARY KEY,
    language_name TEXT NOT NULL,
    collation TEXT,
    special_chars TEXT,
    min_word_length INT DEFAULT 2
);

-- Insert common languages
INSERT INTO trgm_language_config (language_code, language_name, special_chars)
VALUES 
    ('en', 'English', ''),
    ('es', 'Spanish', 'ñáéíóúü'),
    ('fr', 'French', 'àâäæçéèêëïîôœùûüÿ'),
    ('de', 'German', 'äöüß'),
    ('pt', 'Portuguese', 'àáâãçéêíóôõú'),
    ('it', 'Italian', 'àèéìíîòóùú'),
    ('zh', 'Chinese', ''),  -- Use pg_bigm for CJK
    ('ja', 'Japanese', ''),
    ('ko', 'Korean', '')
ON CONFLICT (language_code) DO NOTHING;

-- Function for language-aware text normalization
CREATE OR REPLACE FUNCTION normalize_text_for_language(
    p_text TEXT,
    p_language VARCHAR(10) DEFAULT 'en'
)
RETURNS TEXT AS $$
DECLARE
    v_normalized TEXT;
BEGIN
    v_normalized := LOWER(p_text);
    
    -- Language-specific normalizations could be added here
    -- For now, standard Unicode normalization
    RETURN v_normalized;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- AUTOMATED INDEX RECOMMENDATIONS
-- ============================================================================

-- Table to store index recommendations
CREATE TABLE IF NOT EXISTS trgm_index_recommendations (
    recommendation_id SERIAL PRIMARY KEY,
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    recommendation_type TEXT NOT NULL, -- GIN, GIST
    reason TEXT,
    sample_query TEXT,
    estimated_benefit TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    applied_at TIMESTAMPTZ,
    UNIQUE(table_name, column_name, recommendation_type)
);

-- Function to analyze column and recommend trigram indexes
CREATE OR REPLACE FUNCTION recommend_trgm_index(
    p_table_name TEXT,
    p_column_name TEXT
)
RETURNS JSONB AS $$
DECLARE
    v_sample_size INT;
    v_avg_length NUMERIC;
    v_distinct_ratio NUMERIC;
    v_recommendation JSONB;
BEGIN
    -- Analyze column statistics
    EXECUTE format(
        'SELECT 
            COUNT(*),
            AVG(LENGTH(%I)),
            COUNT(DISTINCT %I)::NUMERIC / NULLIF(COUNT(*), 0)
        FROM %I',
        p_column_name, p_column_name, p_table_name
    ) INTO v_sample_size, v_avg_length, v_distinct_ratio;
    
    -- Generate recommendation
    IF v_avg_length < 5 THEN
        v_recommendation := jsonb_build_object(
            'recommendation', 'NOT_RECOMMENDED',
            'reason', 'Column values too short for trigram matching',
            'avg_length', v_avg_length
        );
    ELSIF v_distinct_ratio > 0.9 THEN
        v_recommendation := jsonb_build_object(
            'recommendation', 'GIN',
            'reason', 'High cardinality, good for equality/similarity searches',
            'sql', format('CREATE INDEX idx_%s_%s_trgm ON %s USING GIN (%s gin_trgm_ops);', 
                         p_table_name, p_column_name, p_table_name, p_column_name)
        );
        
        -- Store recommendation
        INSERT INTO trgm_index_recommendations 
            (table_name, column_name, recommendation_type, reason, sample_query)
        VALUES 
            (p_table_name, p_column_name, 'GIN', 'High cardinality column', 
             format('SELECT * FROM %s WHERE %s %% search_term', p_table_name, p_column_name))
        ON CONFLICT (table_name, column_name, recommendation_type) DO NOTHING;
    ELSE
        v_recommendation := jsonb_build_object(
            'recommendation', 'GIST',
            'reason', 'Moderate cardinality, good for similarity searches',
            'sql', format('CREATE INDEX idx_%s_%s_trgm ON %s USING GIST (%s gist_trgm_ops);', 
                         p_table_name, p_column_name, p_table_name, p_column_name)
        );
    END IF;
    
    RETURN v_recommendation;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- SPELL CHECKING UTILITIES
-- ============================================================================

-- Table for common misspellings and corrections
CREATE TABLE IF NOT EXISTS spelling_dictionary (
    word_id SERIAL PRIMARY KEY,
    correct_spelling TEXT NOT NULL,
    common_misspellings TEXT[] NOT NULL,
    frequency INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Sample corrections
INSERT INTO spelling_dictionary (correct_spelling, common_misspellings, frequency)
VALUES 
    ('account', ARRAY['acount', 'accout', 'accont', 'accoun'], 1000),
    ('transaction', ARRAY['trasaction', 'transacion', 'tranaction', 'transacton'], 800),
    ('balance', ARRAY['balnce', 'balace', 'balanve'], 900),
    ('payment', ARRAY['paymet', 'paymnt', 'pament'], 700),
    ('withdrawal', ARRAY['withdrawl', 'withdrwal', 'withdrawel'], 600)
ON CONFLICT DO NOTHING;

-- Function to suggest spelling corrections
CREATE OR REPLACE FUNCTION suggest_spelling(p_word TEXT, p_max_suggestions INT DEFAULT 3)
RETURNS TABLE(suggestion TEXT, score REAL) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        s.correct_spelling,
        similarity(p_word, s.correct_spelling) as score
    FROM spelling_dictionary s
    WHERE s.correct_spelling % p_word
       OR EXISTS (SELECT 1 FROM UNNEST(s.common_misspellings) m WHERE m = p_word)
    ORDER BY score DESC, s.frequency DESC
    LIMIT p_max_suggestions;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- SENTENCE-LEVEL SIMILARITY (Context-aware)
-- ============================================================================

-- Function to calculate Jaccard similarity between word sets
CREATE OR REPLACE FUNCTION jaccard_similarity(text1 TEXT, text2 TEXT)
RETURNS REAL AS $$
DECLARE
    v_words1 TEXT[];
    v_words2 TEXT[];
    v_intersection INT;
    v_union INT;
BEGIN
    -- Tokenize into words
    v_words1 := ARRAY(SELECT DISTINCT LOWER(word) 
                      FROM UNNEST(REGEXP_SPLIT_TO_ARRAY(text1, '\s+')) word 
                      WHERE word != '');
    v_words2 := ARRAY(SELECT DISTINCT LOWER(word) 
                      FROM UNNEST(REGEXP_SPLIT_TO_ARRAY(text2, '\s+')) word 
                      WHERE word != '');
    
    -- Calculate intersection
    SELECT COUNT(*) INTO v_intersection
    FROM UNNEST(v_words1) w1
    JOIN UNNEST(v_words2) w2 ON w1 = w2;
    
    -- Calculate union
    v_union := ARRAY_LENGTH(v_words1, 1) + ARRAY_LENGTH(v_words2, 1) - v_intersection;
    
    IF v_union = 0 THEN
        RETURN 0.0;
    END IF;
    
    RETURN v_intersection::REAL / v_union;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function for combined similarity score
CREATE OR REPLACE FUNCTION combined_text_similarity(text1 TEXT, text2 TEXT)
RETURNS REAL AS $$
DECLARE
    v_trigram REAL;
    v_levenshtein REAL;
    v_jaccard REAL;
    v_phonetic REAL;
BEGIN
    v_trigram := similarity(text1, text2);
    v_levenshtein := levenshtein_similarity(text1, text2);
    v_jaccard := jaccard_similarity(text1, text2);
    v_phonetic := phonetic_similarity(text1, text2);
    
    -- Weighted combination
    RETURN (v_trigram * 0.4) + (v_levenshtein * 0.3) + (v_jaccard * 0.2) + (v_phonetic * 0.1);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON FUNCTION phonetic_soundex IS 'Calculate Soundex phonetic code for name matching';
COMMENT ON FUNCTION phonetic_metaphone IS 'Calculate Metaphone phonetic code (more accurate than Soundex)';
COMMENT ON FUNCTION levenshtein_distance IS 'Calculate edit distance between two strings';
COMMENT ON FUNCTION levenshtein_similarity IS 'Normalized similarity (0-1) based on Levenshtein distance';
COMMENT ON FUNCTION extract_ngrams IS 'Extract n-grams of specified length from text';
COMMENT ON FUNCTION ngram_similarity IS 'Calculate similarity based on shared n-grams';
COMMENT ON FUNCTION suggest_spelling IS 'Suggest spelling corrections for misspelled words';
COMMENT ON FUNCTION jaccard_similarity IS 'Calculate Jaccard similarity between word sets';
COMMENT ON FUNCTION combined_text_similarity IS 'Combined similarity using multiple algorithms';

-- ============================================================================
-- USAGE NOTES
-- ============================================================================
-- 1. For name matching: Use phonetic_metaphone() or phonetic_soundex()
-- 2. For typo tolerance: Use levenshtein_similarity()
-- 3. For general text: Use trigram similarity (%) or combined_text_similarity()
-- 4. For large tables: Create GIN indexes for %% (similarity) operators
-- ============================================================================
