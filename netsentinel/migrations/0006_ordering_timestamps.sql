-- Agents write several rows per transaction, where now() is constant. "Latest" lookups need real
-- ordering, so these timestamps use clock_timestamp().
ALTER TABLE risk_assessments ALTER COLUMN created_at SET DEFAULT clock_timestamp();
ALTER TABLE investigations ALTER COLUMN created_at SET DEFAULT clock_timestamp();
ALTER TABLE response_actions ALTER COLUMN proposed_at SET DEFAULT clock_timestamp();
