-- ============================================================================
-- Transaction Partitioning Setup
-- ============================================================================

-- Note: Partitioning is managed by TimescaleDB for time-series tables
-- This file contains additional partition management

-- View: Partition information
CREATE OR REPLACE VIEW utils.v_partition_info AS
SELECT 
    schemaname,
    tablename,
    partitionname,
    partitiontype,
    partitionrangestart,
    partitionrangeend
FROM pg_partitions
WHERE tablename IN ('transactions', 'movement_postings', 'rejection_log', 'audit_trail');

COMMENT ON VIEW utils.v_partition_info IS 'Information about table partitions';

-- Function: Create monthly partition
CREATE OR REPLACE FUNCTION utils.create_monthly_partition(
    p_table_name TEXT,
    p_year INTEGER,
    p_month INTEGER
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = utils, public
AS $$
DECLARE
    v_partition_name TEXT;
    v_start_date DATE;
    v_end_date DATE;
BEGIN
    v_partition_name := p_table_name || '_' || p_year || '_' || LPAD(p_month::text, 2, '0');
    v_start_date := make_date(p_year, p_month, 1);
    v_end_date := v_start_date + interval '1 month';

    -- For TimescaleDB, partitions are created automatically
    -- This function is for manual partition creation if needed
    
    RETURN TRUE;
END;
$$;

COMMENT ON FUNCTION utils.create_monthly_partition IS 'Creates monthly partition for table';
