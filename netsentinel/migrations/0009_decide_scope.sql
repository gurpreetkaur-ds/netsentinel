-- 'actions:decide': may approve/reject/complete response actions and close tickets from the dashboard.
-- Granted explicitly per key (netsentinel keys grant); signing in to the dashboard still needs only events:read.
ALTER TABLE api_keys DROP CONSTRAINT api_keys_scopes_check,
    ADD CONSTRAINT api_keys_scopes_check CHECK (cardinality(scopes) > 0
        AND scopes <@ ARRAY['ingest:write', 'events:read', 'actions:decide']::text[]);
ALTER TABLE api_key_events DROP CONSTRAINT api_key_events_event_check,
    ADD CONSTRAINT api_key_events_event_check CHECK (event IN ('registered', 'revoked', 'auth_failed', 'scope_granted'));
