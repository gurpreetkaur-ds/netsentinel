-- VERIFIED TELEMETRY: flow 5-tuple as reported by the sensor (validated on ingest, never model input).
ALTER TABLE flow_events
    ADD COLUMN src_ip   inet,
    ADD COLUMN dst_ip   inet,
    ADD COLUMN src_port integer CHECK (src_port BETWEEN 0 AND 65535),
    ADD COLUMN dst_port integer CHECK (dst_port BETWEEN 0 AND 65535),
    ADD COLUMN protocol smallint CHECK (protocol BETWEEN 0 AND 255);
CREATE INDEX flow_events_src_received ON flow_events (src_ip, received_at);

-- Cases: the orchestrator's correlation of attack detections (same source + family within a window).
CREATE TABLE cases (
    case_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    correlation_key  text NOT NULL,
    src_ip           inet,
    family           text,
    status           text NOT NULL DEFAULT 'open'
                         CHECK (status IN ('open', 'investigating', 'investigated', 'assessed', 'ticketed', 'closed')),
    first_seen       timestamptz NOT NULL,
    last_seen        timestamptz NOT NULL,
    flow_count       integer NOT NULL DEFAULT 0,
    max_p_attack     double precision NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (last_seen >= first_seen)
);
-- at most one case accumulating flows per correlation key
CREATE UNIQUE INDEX cases_one_open_per_key ON cases (correlation_key) WHERE status = 'open';
CREATE INDEX cases_status ON cases (status, updated_at);

CREATE TABLE case_events (
    case_id   uuid NOT NULL REFERENCES cases (case_id),
    event_id  uuid NOT NULL REFERENCES detections (event_id),
    PRIMARY KEY (event_id),                -- a flow belongs to exactly one case
    UNIQUE (case_id, event_id)
);

CREATE TABLE case_history (
    id        bigserial PRIMARY KEY,
    case_id   uuid NOT NULL REFERENCES cases (case_id),
    status    text NOT NULL,
    actor     text NOT NULL,
    detail    jsonb NOT NULL DEFAULT '{}'::jsonb,
    at        timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER case_history_append_only BEFORE UPDATE OR DELETE ON case_history
    FOR EACH ROW EXECUTE FUNCTION append_only();

-- Investigation Agent output. Each section keeps its provenance label; rows are append-only.
CREATE TABLE investigations (
    investigation_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id           uuid NOT NULL REFERENCES cases (case_id),
    telemetry         jsonb NOT NULL,   -- VERIFIED TELEMETRY (computed from the database)
    model_output      jsonb NOT NULL,   -- MODEL OUTPUT (detections, copied verbatim)
    analysis          jsonb,            -- LLM ANALYSIS
    recommendations   jsonb,            -- RECOMMENDATION (investigative next steps only)
    llm_status        text NOT NULL CHECK (llm_status IN ('ok', 'unavailable', 'invalid_output', 'guard_rejected')),
    guard_findings    jsonb NOT NULL DEFAULT '[]'::jsonb,
    llm_model         text,
    evidence_sha256   text NOT NULL,
    duration_ms       integer,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX investigations_case ON investigations (case_id, created_at DESC);
CREATE TRIGGER investigations_append_only BEFORE UPDATE OR DELETE ON investigations
    FOR EACH ROW EXECUTE FUNCTION append_only();

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
