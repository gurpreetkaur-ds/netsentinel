-- Flow end time (observed_at + Flow Duration), set at ingest. Per-source window features (model v2)
-- look back over flows that *ended* in the last 60 s, which is what had been received by then.
ALTER TABLE flow_events ADD COLUMN ended_at timestamptz;
CREATE INDEX flow_events_src_ended ON flow_events (src_ip, ended_at) WHERE ended_at IS NOT NULL;
