-- API keys: only a SHA-256 digest of each key is stored. The plaintext is generated on the
-- client's own machine and never reaches the server's disk, database or logs.
CREATE TABLE api_keys (
    key_id          text PRIMARY KEY CHECK (key_id ~ '^[0-9a-f]{12}$'),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    key_sha256      bytea NOT NULL UNIQUE CHECK (octet_length(key_sha256) = 32),
    scopes          text[] NOT NULL CHECK (cardinality(scopes) > 0
                        AND scopes <@ ARRAY['ingest:write', 'events:read']::text[]),
    created_at      timestamptz NOT NULL DEFAULT now(),
    created_by      text NOT NULL,
    expires_at      timestamptz,
    last_used_at    timestamptz,
    revoked_at      timestamptz,
    revoked_reason  text,
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
);

-- A key's identity and digest can never be changed, and a revocation can never be undone.
CREATE FUNCTION api_keys_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'api_keys rows cannot be deleted; revoke instead';
    END IF;
    IF NEW.key_id <> OLD.key_id OR NEW.key_sha256 <> OLD.key_sha256
       OR NEW.created_at <> OLD.created_at OR NEW.created_by <> OLD.created_by THEN
        RAISE EXCEPTION 'api_keys identity columns are immutable';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
       OR NEW.revoked_reason IS DISTINCT FROM OLD.revoked_reason) THEN
        RAISE EXCEPTION 'a revoked api key cannot be re-enabled';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER api_keys_guard BEFORE UPDATE OR DELETE ON api_keys
    FOR EACH ROW EXECUTE FUNCTION api_keys_guard();

-- Append-only audit trail of key lifecycle and authentication failures on known keys.
CREATE TABLE api_key_events (
    id          bigserial PRIMARY KEY,
    key_id      text NOT NULL REFERENCES api_keys (key_id),
    event       text NOT NULL CHECK (event IN ('registered', 'revoked', 'auth_failed')),
    actor       text NOT NULL,
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb,
    at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX api_key_events_key_at ON api_key_events (key_id, at DESC);

CREATE FUNCTION append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END $$;
CREATE TRIGGER api_key_events_append_only BEFORE UPDATE OR DELETE ON api_key_events
    FOR EACH ROW EXECUTE FUNCTION append_only();

-- Step 1 (INGEST) of the pipeline: raw flow records as received, before validation.
CREATE TABLE flow_events (
    event_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id         uuid NOT NULL,
    key_id           text NOT NULL REFERENCES api_keys (key_id),
    source           text NOT NULL CHECK (source IN ('cicflowmeter', 'zeek', 'netflow')),
    client_event_id  text CHECK (length(client_event_id) BETWEEN 1 AND 128),
    observed_at      timestamptz,
    flow             jsonb NOT NULL CHECK (jsonb_typeof(flow) = 'object'),
    status           text NOT NULL DEFAULT 'received'
                         CHECK (status IN ('received', 'validated', 'rejected', 'scored')),
    received_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (key_id, client_event_id)
);
CREATE INDEX flow_events_status_received ON flow_events (status, received_at);
CREATE INDEX flow_events_batch ON flow_events (batch_id);

-- Nothing is readable by other database roles.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
