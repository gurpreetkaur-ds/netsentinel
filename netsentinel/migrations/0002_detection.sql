-- Model registry. A model scores traffic only once a human approved it and it was activated.
CREATE TABLE models (
    model_id        text PRIMARY KEY CHECK (model_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    artifact_path   text NOT NULL,
    sha256          text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    schema_version  text NOT NULL,
    features        text[] NOT NULL,
    metrics         jsonb NOT NULL DEFAULT '{}'::jsonb,
    status          text NOT NULL DEFAULT 'candidate'
                        CHECK (status IN ('candidate', 'approved', 'active', 'retired', 'rejected')),
    registered_by   text NOT NULL,
    registered_at   timestamptz NOT NULL DEFAULT now(),
    approved_by     text,
    approved_at     timestamptz,
    activated_at    timestamptz,
    CHECK (status NOT IN ('approved', 'active') OR approved_by IS NOT NULL)
);
CREATE UNIQUE INDEX models_one_active ON models ((true)) WHERE status = 'active';

CREATE FUNCTION models_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'models rows cannot be deleted; retire instead';
    END IF;
    IF NEW.sha256 <> OLD.sha256 OR NEW.artifact_path <> OLD.artifact_path OR NEW.features <> OLD.features
       OR NEW.schema_version <> OLD.schema_version THEN
        RAISE EXCEPTION 'a registered model artifact is immutable; register a new model_id';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER models_guard BEFORE UPDATE OR DELETE ON models FOR EACH ROW EXECUTE FUNCTION models_guard();

CREATE TABLE model_events (
    id        bigserial PRIMARY KEY,
    model_id  text NOT NULL REFERENCES models (model_id),
    event     text NOT NULL CHECK (event IN ('registered', 'approved', 'rejected', 'activated', 'retired', 'check_failed')),
    actor     text NOT NULL,
    detail    jsonb NOT NULL DEFAULT '{}'::jsonb,
    at        timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER model_events_append_only BEFORE UPDATE OR DELETE ON model_events
    FOR EACH ROW EXECUTE FUNCTION append_only();

-- Steps 2-4 outcome on the ingested event.
ALTER TABLE flow_events ADD COLUMN reject_reason text,
    ADD CONSTRAINT flow_events_reject_reason CHECK ((status = 'rejected') = (reject_reason IS NOT NULL));

-- Step 6 output: one detection per scored flow. MODEL OUTPUT, never edited by agents or the LLM.
CREATE TABLE detections (
    event_id           uuid PRIMARY KEY REFERENCES flow_events (event_id),
    model_id           text NOT NULL REFERENCES models (model_id),
    p_attack           double precision NOT NULL CHECK (p_attack BETWEEN 0 AND 1),
    threshold          double precision NOT NULL,
    is_attack          boolean NOT NULL,
    family             text,
    family_confidence  double precision,
    attack_type        text,
    type_confidence    double precision,
    missing_features   smallint NOT NULL,
    scored_at          timestamptz NOT NULL DEFAULT now(),
    CHECK (is_attack OR (family IS NULL AND attack_type IS NULL))
);
CREATE INDEX detections_attacks ON detections (scored_at) WHERE is_attack;
CREATE TRIGGER detections_append_only BEFORE UPDATE OR DELETE ON detections
    FOR EACH ROW EXECUTE FUNCTION append_only();

-- Step 7: event bus. Topics are append-only logs; each consumer tracks its own position.
CREATE TABLE bus_messages (
    id          bigserial PRIMARY KEY,
    topic       text NOT NULL CHECK (topic ~ '^[a-z]+(\.[a-z_]+)+$'),
    payload     jsonb NOT NULL,
    producer    text NOT NULL,
    -- Writer's transaction id: consumers only read messages whose transaction, and every older
    -- one, has finished, so a slow-committing writer's lower id is never skipped.
    txid        xid8 NOT NULL DEFAULT pg_current_xact_id(),
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX bus_messages_topic_id ON bus_messages (topic, id);
CREATE TRIGGER bus_messages_append_only BEFORE UPDATE OR DELETE ON bus_messages
    FOR EACH ROW EXECUTE FUNCTION append_only();

CREATE TABLE bus_offsets (
    consumer    text NOT NULL,
    topic       text NOT NULL,
    last_id     bigint NOT NULL DEFAULT 0,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (consumer, topic)
);

CREATE TABLE agent_heartbeats (
    agent       text PRIMARY KEY,
    status      text NOT NULL CHECK (status IN ('ok', 'degraded', 'stopped')),
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb,
    at          timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
