-- SOC workflow: manual tickets, a validated ticket lifecycle, comments, attachments, SLA policies,
-- a general audit log, the AI Security Agent's runs/findings/recommendations, and simulated
-- execution records for approved response actions.

-- ── API key scope for analysts who may edit tickets but not approve response actions ──────────
ALTER TABLE api_keys DROP CONSTRAINT api_keys_scopes_check,
    ADD CONSTRAINT api_keys_scopes_check CHECK (cardinality(scopes) > 0
        AND scopes <@ ARRAY['ingest:write', 'events:read', 'tickets:write', 'actions:decide']::text[]);

-- ── SLA policies (per severity) ───────────────────────────────────────────────────────────────
CREATE TABLE sla_policies (
    severity         text PRIMARY KEY CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    priority         text NOT NULL UNIQUE CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
    ack_minutes      integer NOT NULL CHECK (ack_minutes > 0),
    resolve_minutes  integer NOT NULL CHECK (resolve_minutes >= ack_minutes)
);
-- resolve times match the Ticket Agent's original P1 1 h, P2 4 h, P3 24 h, P4 72 h
INSERT INTO sla_policies VALUES ('critical', 'P1', 15, 60), ('high', 'P2', 30, 240),
                                ('medium', 'P3', 120, 1440), ('low', 'P4', 480, 4320);

-- ── tickets: manual tickets and the full lifecycle ────────────────────────────────────────────
ALTER TABLE tickets DROP CONSTRAINT tickets_status_check;
UPDATE tickets SET status = 'open' WHERE status = 'new';
ALTER TABLE tickets
    ALTER COLUMN case_id DROP NOT NULL,
    ALTER COLUMN status SET DEFAULT 'open',
    ADD CONSTRAINT tickets_status_check CHECK (status IN ('open', 'acknowledged', 'investigating', 'in_progress',
                                                          'awaiting_approval', 'resolved', 'closed')),
    ADD COLUMN origin           text NOT NULL DEFAULT 'detection' CHECK (origin IN ('detection', 'alert', 'manual')),
    ADD COLUMN created_by       text NOT NULL DEFAULT 'agent:ticket',
    ADD COLUMN description      text NOT NULL DEFAULT '' CHECK (length(description) <= 5000),
    ADD COLUMN category         text NOT NULL DEFAULT 'Other' CHECK (length(category) BETWEEN 1 AND 40),
    ADD COLUMN source_ip        inet,
    ADD COLUMN dest_ip          inet,
    ADD COLUMN affected_asset   text CHECK (length(affected_asset) <= 200),
    ADD COLUMN evidence_notes   text NOT NULL DEFAULT '' CHECK (length(evidence_notes) <= 10000),
    ADD COLUMN tags             text[] NOT NULL DEFAULT '{}' CHECK (cardinality(tags) <= 20),
    ADD COLUMN ack_due_at       timestamptz,
    ADD COLUMN acknowledged_at  timestamptz,
    ADD COLUMN severity_locked  boolean NOT NULL DEFAULT false,
    ADD COLUMN escalated        boolean NOT NULL DEFAULT false,
    ADD COLUMN closure_reason   text CHECK (closure_reason IN ('remediated', 'false_positive', 'duplicate', 'benign',
                                                               'risk_accepted', 'no_action_needed', 'other')),
    ADD COLUMN duplicate_of     text REFERENCES tickets (ticket_id),
    ADD COLUMN reopen_count     integer NOT NULL DEFAULT 0 CHECK (reopen_count >= 0),
    ADD COLUMN ai_status        text NOT NULL DEFAULT 'none'
                                    CHECK (ai_status IN ('none', 'queued', 'running', 'completed', 'failed'));

-- Backfill detection tickets from their cases. Closed legacy tickets get closure reason 'other'.
UPDATE tickets t SET category = coalesce(c.family, 'Unnamed'), source_ip = c.src_ip
FROM cases c WHERE c.case_id = t.case_id;
UPDATE tickets SET dest_ip = (summary #>> '{VERIFIED TELEMETRY,destinations,top,0,ip}')::inet
WHERE summary #>> '{VERIFIED TELEMETRY,destinations,top,0,ip}' ~ '^[0-9.]+$';
UPDATE tickets SET closure_reason = 'other' WHERE status = 'closed';
-- constraints only after the backfill, so existing rows satisfy them
ALTER TABLE tickets
    ADD CONSTRAINT tickets_closed_has_reason CHECK (status <> 'closed' OR closure_reason IS NOT NULL),
    ADD CONSTRAINT tickets_title_length CHECK (length(title) BETWEEN 1 AND 300);
UPDATE tickets t SET ack_due_at = t.created_at + make_interval(mins => p.ack_minutes)
FROM sla_policies p WHERE p.severity = t.severity;

CREATE INDEX tickets_status_updated ON tickets (status, updated_at DESC);
CREATE INDEX tickets_assignee ON tickets (assignee) WHERE assignee IS NOT NULL;
CREATE INDEX tickets_source_ip ON tickets (source_ip);
CREATE INDEX tickets_created ON tickets (created_at DESC);

-- The lifecycle, enforced here so no client (dashboard, CLI, agent) can skip it:
--   open → acknowledged → investigating → in_progress → resolved → closed
--   awaiting_approval can be entered from any active state and left to any active state but 'open'
--   any active state → resolved, or → closed with a closure reason (false positive, duplicate, …)
--   resolved → investigating (reopen; counted) or closed.  closed is final.
CREATE FUNCTION ticket_transition_ok(old_s text, new_s text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT old_s = new_s
        OR (old_s IN ('open', 'acknowledged', 'investigating', 'in_progress', 'awaiting_approval')
            AND new_s IN ('investigating', 'in_progress', 'awaiting_approval', 'resolved', 'closed'))
        OR (old_s = 'open' AND new_s = 'acknowledged')
        OR (old_s = 'resolved' AND new_s IN ('investigating', 'closed'))
$$;

CREATE FUNCTION tickets_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'tickets cannot be deleted; close them instead';
    END IF;
    IF NEW.ticket_id <> OLD.ticket_id OR NEW.created_at <> OLD.created_at OR NEW.origin <> OLD.origin
       OR NEW.created_by <> OLD.created_by THEN
        RAISE EXCEPTION 'ticket identity columns are immutable';
    END IF;
    IF OLD.case_id IS NOT NULL AND NEW.case_id IS DISTINCT FROM OLD.case_id THEN
        RAISE EXCEPTION 'a ticket cannot be moved to another case';
    END IF;
    IF NOT ticket_transition_ok(OLD.status, NEW.status) THEN
        RAISE EXCEPTION 'invalid ticket transition % -> %', OLD.status, NEW.status USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'resolved' AND NEW.status = 'investigating' THEN
        NEW.reopen_count := OLD.reopen_count + 1;
    END IF;
    IF OLD.status = 'open' AND NEW.status <> 'open' AND NEW.acknowledged_at IS NULL THEN
        NEW.acknowledged_at := now();
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER tickets_guard BEFORE UPDATE OR DELETE ON tickets FOR EACH ROW EXECUTE FUNCTION tickets_guard();

-- ── comments and internal notes (append-only, threaded) ───────────────────────────────────────
CREATE TABLE ticket_comments (
    comment_id  bigserial PRIMARY KEY,
    ticket_id   text NOT NULL REFERENCES tickets (ticket_id),
    parent_id   bigint REFERENCES ticket_comments (comment_id),
    author      text NOT NULL,
    kind        text NOT NULL CHECK (kind IN ('comment', 'internal_note')),
    body        text NOT NULL CHECK (length(body) BETWEEN 1 AND 5000),
    ai_drafted  boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX ticket_comments_ticket ON ticket_comments (ticket_id, comment_id);
CREATE TRIGGER ticket_comments_append_only BEFORE UPDATE OR DELETE ON ticket_comments
    FOR EACH ROW EXECUTE FUNCTION append_only();

-- ── attachments: evidence files, kept in the database (services have read-only filesystems) ──
CREATE TABLE ticket_attachments (
    attachment_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id      text NOT NULL REFERENCES tickets (ticket_id),
    filename       text NOT NULL CHECK (filename ~ '^[A-Za-z0-9._ ()-]{1,120}$' AND filename !~ '^\.'),
    content_type   text NOT NULL,
    size_bytes     integer NOT NULL CHECK (size_bytes BETWEEN 1 AND 5242880),
    sha256         text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    data           bytea NOT NULL,
    uploaded_by    text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (octet_length(data) = size_bytes)
);
CREATE INDEX ticket_attachments_ticket ON ticket_attachments (ticket_id, created_at);
CREATE TRIGGER ticket_attachments_append_only BEFORE UPDATE OR DELETE ON ticket_attachments
    FOR EACH ROW EXECUTE FUNCTION append_only();

-- ── audit log: every state-changing request from the dashboard, with the acting identity ─────
CREATE TABLE audit_log (
    id           bigserial PRIMARY KEY,
    at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    actor        text NOT NULL,
    action       text NOT NULL,
    object_type  text NOT NULL,
    object_id    text NOT NULL,
    client       text,
    detail       jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_log_object ON audit_log (object_type, object_id, id);
CREATE INDEX audit_log_at ON audit_log (at DESC);
CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION append_only();

-- ── AI Security Agent ─────────────────────────────────────────────────────────────────────────
CREATE TABLE ai_runs (
    run_id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id  uuid NOT NULL,
    ticket_id        text REFERENCES tickets (ticket_id),
    requested_by     text NOT NULL CHECK (requested_by !~ '^agent:'),
    kind             text NOT NULL CHECK (kind IN ('investigate', 'question')),
    prompt           text NOT NULL CHECK (length(prompt) BETWEEN 1 AND 2000),
    status           text NOT NULL DEFAULT 'queued'
                         CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    result           jsonb,
    guard_findings   jsonb NOT NULL DEFAULT '[]'::jsonb,
    error            text,
    model            text,
    tool_calls       integer NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    started_at       timestamptz,
    finished_at      timestamptz,
    CHECK ((status = 'completed') = (result IS NOT NULL))
);
CREATE INDEX ai_runs_queue ON ai_runs (created_at) WHERE status = 'queued';
CREATE INDEX ai_runs_ticket ON ai_runs (ticket_id, created_at DESC);
CREATE INDEX ai_runs_conversation ON ai_runs (conversation_id, created_at);
CREATE INDEX ai_runs_requester ON ai_runs (requested_by, created_at DESC);

-- progress stream for the browser: status changes, tool calls and results, the final answer
CREATE TABLE ai_run_events (
    id      bigserial PRIMARY KEY,
    run_id  uuid NOT NULL REFERENCES ai_runs (run_id),
    at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    kind    text NOT NULL CHECK (kind IN ('status', 'tool_call', 'tool_result', 'note', 'error', 'final')),
    data    jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX ai_run_events_run ON ai_run_events (run_id, id);
CREATE TRIGGER ai_run_events_append_only BEFORE UPDATE OR DELETE ON ai_run_events
    FOR EACH ROW EXECUTE FUNCTION append_only();

CREATE TABLE ai_findings (
    finding_id     bigserial PRIMARY KEY,
    run_id         uuid NOT NULL REFERENCES ai_runs (run_id),
    ticket_id      text REFERENCES tickets (ticket_id),
    category       text NOT NULL CHECK (category IN ('confirmed', 'hypothesis', 'unknown')),
    severity       text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    confidence     text NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    statement      text NOT NULL,
    evidence_refs  jsonb NOT NULL DEFAULT '[]'::jsonb,
    supported      boolean NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX ai_findings_run ON ai_findings (run_id);
CREATE TRIGGER ai_findings_append_only BEFORE UPDATE OR DELETE ON ai_findings
    FOR EACH ROW EXECUTE FUNCTION append_only();

CREATE TABLE ai_recommendations (
    rec_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id         uuid NOT NULL REFERENCES ai_runs (run_id),
    ticket_id      text REFERENCES tickets (ticket_id),
    kind           text NOT NULL CHECK (kind IN ('next_step', 'severity_change', 'escalation', 'comment_draft',
                                                 'resolution_draft', 'remediation', 'command')),
    title          text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    body           jsonb NOT NULL DEFAULT '{}'::jsonb,
    rationale      text NOT NULL DEFAULT '',
    confidence     text NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    evidence_refs  jsonb NOT NULL DEFAULT '[]'::jsonb,
    priority       smallint NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 5),
    status         text NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed', 'accepted', 'rejected', 'dismissed')),
    decided_by     text CHECK (decided_by !~ '^agent:'),
    decided_at     timestamptz,
    decision_note  text,
    created_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((status = 'proposed') = (decided_by IS NULL))
);
CREATE INDEX ai_recommendations_ticket ON ai_recommendations (ticket_id, created_at DESC);
CREATE INDEX ai_recommendations_run ON ai_recommendations (run_id);

CREATE FUNCTION ai_recommendations_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'recommendations cannot be deleted';
    END IF;
    IF NEW.kind <> OLD.kind OR NEW.body <> OLD.body OR NEW.title <> OLD.title
       OR NEW.ticket_id IS DISTINCT FROM OLD.ticket_id OR NEW.run_id <> OLD.run_id THEN
        RAISE EXCEPTION 'a recommendation cannot be altered';
    END IF;
    IF NOT (OLD.status = 'proposed' AND NEW.status IN ('accepted', 'rejected', 'dismissed')) THEN
        RAISE EXCEPTION 'invalid recommendation transition % -> %', OLD.status, NEW.status;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER ai_recommendations_guard BEFORE UPDATE OR DELETE ON ai_recommendations
    FOR EACH ROW EXECUTE FUNCTION ai_recommendations_guard();

-- ── response actions: ticket-level proposals (manual tickets, AI agent), cancellation ─────────
ALTER TABLE response_actions
    ALTER COLUMN case_id DROP NOT NULL,
    ALTER COLUMN assessment_id DROP NOT NULL,
    ADD COLUMN ticket_id    text REFERENCES tickets (ticket_id),
    ADD COLUMN proposed_by  text NOT NULL DEFAULT 'agent:response',
    ADD COLUMN run_id       uuid REFERENCES ai_runs (run_id),
    ADD CONSTRAINT response_actions_has_subject CHECK (case_id IS NOT NULL OR ticket_id IS NOT NULL),
    DROP CONSTRAINT response_actions_status_check,
    ADD CONSTRAINT response_actions_status_check CHECK (status IN ('proposed', 'approved', 'rejected', 'completed',
                                                                   'cancelled'));
CREATE INDEX response_actions_ticket ON response_actions (ticket_id) WHERE ticket_id IS NOT NULL;

CREATE OR REPLACE FUNCTION response_actions_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'response actions cannot be deleted';
    END IF;
    IF NEW.action_type <> OLD.action_type OR NEW.target <> OLD.target OR NEW.params <> OLD.params
       OR NEW.case_id IS DISTINCT FROM OLD.case_id OR NEW.ticket_id IS DISTINCT FROM OLD.ticket_id
       OR NEW.proposed_by <> OLD.proposed_by THEN
        RAISE EXCEPTION 'a proposed action cannot be altered; propose a new one';
    END IF;
    IF NOT ((OLD.status = 'proposed' AND NEW.status IN ('approved', 'rejected', 'cancelled'))
            OR (OLD.status = 'approved' AND NEW.status IN ('completed', 'cancelled'))) THEN
        RAISE EXCEPTION 'invalid response action transition % -> %', OLD.status, NEW.status;
    END IF;
    RETURN NEW;
END $$;

-- Execution records. No integration with a firewall/EDR/IdP is configured, so every execution is a
-- simulation (dry run): it validates and records what *would* be sent, and changes nothing.
CREATE TABLE action_executions (
    execution_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id            uuid NOT NULL REFERENCES response_actions (action_id),
    mode                 text NOT NULL CHECK (mode IN ('simulation', 'live')),
    outcome              text NOT NULL CHECK (outcome IN ('simulated', 'succeeded', 'failed')),
    requested_by         text NOT NULL CHECK (requested_by !~ '^agent:'),
    approved_by          text NOT NULL,
    target               text NOT NULL,
    params               jsonb NOT NULL,
    result               jsonb NOT NULL DEFAULT '{}'::jsonb,
    started_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    finished_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    verification         text NOT NULL DEFAULT 'unverified' CHECK (verification IN ('unverified', 'verified', 'failed')),
    verified_by          text CHECK (verified_by !~ '^agent:'),
    verified_at          timestamptz,
    verification_note    text,
    CHECK (mode = 'live' OR outcome = 'simulated'),
    CHECK ((verification = 'unverified') = (verified_by IS NULL))
);
CREATE INDEX action_executions_action ON action_executions (action_id, started_at);

CREATE FUNCTION action_executions_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'execution records cannot be deleted';
    END IF;
    IF (NEW.action_id, NEW.mode, NEW.outcome, NEW.requested_by, NEW.approved_by, NEW.target, NEW.params, NEW.result,
        NEW.started_at, NEW.finished_at)
       IS DISTINCT FROM (OLD.action_id, OLD.mode, OLD.outcome, OLD.requested_by, OLD.approved_by, OLD.target, OLD.params,
                         OLD.result, OLD.started_at, OLD.finished_at) THEN
        RAISE EXCEPTION 'execution records are immutable; only verification can be recorded';
    END IF;
    IF OLD.verification <> 'unverified' THEN
        RAISE EXCEPTION 'verification is already recorded';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER action_executions_guard BEFORE UPDATE OR DELETE ON action_executions
    FOR EACH ROW EXECUTE FUNCTION action_executions_guard();

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
